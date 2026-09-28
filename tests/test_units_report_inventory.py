"""Unit tests for the report's file-inventory walk."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from containre import report

pytestmark = pytest.mark.unit

SECRET = b"HOST SECRET"
SECRET_DIGEST = hashlib.sha256(SECRET).hexdigest()


# -- the walk that report.py used before it was rewritten, kept as an oracle ----

def _legacy_sha256_file(path: Path, *, max_bytes: int) -> str | None:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _legacy_file_inventory(base: Path, *, max_files: int, hash_limit: int) -> dict[str, Any]:
    if not base.exists() or not base.is_dir():
        return {"base": str(base), "exists": False, "files": [], "count": 0, "total_bytes": 0,
                "truncated": False}
    base_real = os.path.realpath(base)
    prefix = base_real + os.sep
    files = [
        path for path in sorted(base.rglob("*"))
        if not path.is_symlink() and path.is_file()
        and os.path.realpath(path).startswith(prefix)
    ]
    rows = []
    total_bytes = 0
    for path in files[:max_files]:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_bytes += size
        rows.append({
            "path": path.relative_to(base).as_posix(),
            "size": size,
            "sha256": _legacy_sha256_file(path, max_bytes=hash_limit),
        })
    if len(files) > max_files:
        for path in files[max_files:]:
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass
    return {
        "base": str(base),
        "exists": True,
        "files": rows,
        "count": len(files),
        "total_bytes": total_bytes,
        "truncated": len(files) > max_files,
    }


# -- helpers --------------------------------------------------------------------

def _write(path: Path, data: bytes | str = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, str):
        data = data.encode()
    path.write_bytes(data)
    return path


def _tricky_tree(root: Path, outside: Path) -> None:
    """Names that sort differently as strings and as path components, symlinks
    in and out of the tree, special files, and files over the hash limit."""
    for rel in ["a/z.txt", "a-b/c.txt", "a.txt", "a/b/c/deep.txt", "B", "_x", "é.txt",
                "empty-file", "sub dir/with space.txt", "z/1/2/3/4/5/leaf"]:
        _write(root / rel, rel * 3)
    _write(root / "big.bin", b"0" * 4096)
    (root / "empty-dir").mkdir()
    for i in range(12):
        _write(root / "many" / f"f{i:02d}", str(i) * i)
    os.mkfifo(root / "a" / "fifo")
    _write(outside / "secret.txt", SECRET)
    (outside / "dir").mkdir(exist_ok=True)
    _write(outside / "dir" / "inner.txt", SECRET)
    (root / "link-out-file").symlink_to(outside / "secret.txt")
    (root / "link-out-dir").symlink_to(outside / "dir")
    (root / "link-in-file").symlink_to(root / "a.txt")
    (root / "link-in-dir").symlink_to(root / "a")
    (root / "a" / "link-parent").symlink_to("..")
    (root / "dangling").symlink_to(root / "nowhere")


# -- the rewritten walk gives the old walk's output ------------------------------

@pytest.mark.parametrize("max_files", [5, 500])
def test_file_inventory_matches_the_previous_walk(tmp_path, max_files):
    root = tmp_path / "tree"
    _tricky_tree(root, tmp_path / "outside")

    new = report._file_inventory(root, max_files=max_files, hash_limit=1024)
    old = _legacy_file_inventory(root, max_files=max_files, hash_limit=1024)

    assert new == old
    assert json.dumps(new) == json.dumps(old)  # key order too, so report.json is identical
    assert new["truncated"] is (max_files < new["count"])
    assert SECRET_DIGEST not in {row["sha256"] for row in new["files"]}
    if max_files == 500:
        rows = {row["path"]: row for row in new["files"]}
        assert rows["big.bin"]["sha256"] is None                  # over the hash limit
        assert {"a/fifo", "link-in-file", "dangling"}.isdisjoint(rows)
        assert not any(path.startswith(("link-", "a/link-parent")) for path in rows)


def test_file_inventory_matches_the_previous_walk_through_a_symlinked_base(tmp_path):
    root = tmp_path / "tree"
    _tricky_tree(root, tmp_path / "outside")
    alias = tmp_path / "alias"
    alias.symlink_to(root)

    kwargs = {"max_files": 500, "hash_limit": 1024}
    assert report._file_inventory(alias, **kwargs) == _legacy_file_inventory(alias, **kwargs)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads unreadable directories")
def test_file_inventory_matches_the_previous_walk_with_an_unreadable_dir(tmp_path):
    root = tmp_path / "tree"
    _write(root / "ok.txt")
    _write(root / "locked" / "hidden.txt")
    (root / "locked").chmod(0)
    try:
        kwargs = {"max_files": 500, "hash_limit": 1024}
        new = report._file_inventory(root, **kwargs)
        assert new == _legacy_file_inventory(root, **kwargs)
        assert [row["path"] for row in new["files"]] == ["ok.txt"]
    finally:
        (root / "locked").chmod(0o755)


@pytest.mark.skipif(os.geteuid() == 0, reason="root searches unsearchable directories")
def test_file_inventory_skips_a_listable_but_unsearchable_dir(tmp_path):
    # The previous walk raised PermissionError here and took the whole report
    # down; entries that cannot be stat'ed are now left out instead.
    root = tmp_path / "tree"
    _write(root / "ok.txt")
    _write(root / "noexec" / "unstattable.txt")
    (root / "noexec").chmod(0o444)
    try:
        with pytest.raises(PermissionError):
            _legacy_file_inventory(root, max_files=500, hash_limit=1024)
        inv = report._file_inventory(root)
        assert [row["path"] for row in inv["files"]] == ["ok.txt"] and inv["count"] == 1
    finally:
        (root / "noexec").chmod(0o755)


def test_missing_work_mount_matches_the_previous_walk(tmp_path):
    kwargs = {"max_files": 500, "hash_limit": 1024}
    for base in (tmp_path / "missing", _write(tmp_path / "a-file")):
        assert report._file_inventory(base, **kwargs) == _legacy_file_inventory(base, **kwargs)


# -- the walk never reads through a swapped entry --------------------------------

def test_hash_refuses_a_file_swapped_for_a_symlink(tmp_path):
    real = _write(tmp_path / "tree" / "f.txt", "listed")
    secret = _write(tmp_path / "secret.txt", SECRET)
    listed = os.lstat(real)
    real.unlink()
    real.symlink_to(secret)

    assert report._sha256_file(str(real), listed) is None


def test_hash_refuses_a_file_whose_parent_was_swapped(tmp_path):
    tree = tmp_path / "tree"
    listed_file = _write(tree / "d" / "f.txt", "listed")
    listed = os.lstat(listed_file)
    _write(tmp_path / "outside" / "f.txt", SECRET)
    (tree / "d").rename(tree / "d-moved")
    (tree / "d").symlink_to(tmp_path / "outside")

    assert report._sha256_file(str(tree / "d" / "f.txt"), listed) is None
    # The same inode, reached through its new name, still hashes.
    assert report._sha256_file(str(tree / "d-moved" / "f.txt"), listed) == \
        hashlib.sha256(b"listed").hexdigest()


def test_listing_refuses_a_directory_swapped_mid_walk(tmp_path):
    tree = tmp_path / "tree"
    _write(tree / "d" / "f.txt", "listed")
    listed = os.lstat(tree / "d")
    _write(tmp_path / "outside" / "secret.txt", SECRET)
    (tree / "d").rename(tree / "d-moved")
    (tree / "d").symlink_to(tmp_path / "outside")

    assert report._list_dir(str(tree / "d"), (listed.st_dev, listed.st_ino)) == []
    assert [row[0] for row in report._list_dir(str(tree / "d-moved"),
                                               (listed.st_dev, listed.st_ino))] == ["f.txt"]


def test_walk_handles_a_tree_deeper_than_the_recursion_limit(tmp_path):
    depth = 150
    _write(tmp_path / "tree" / Path(*["d"] * depth) / "leaf.txt")
    old_limit = sys.getrecursionlimit()
    # Headroom for the frames already on the stack, far less than the depth.
    sys.setrecursionlimit(len(inspect.stack()) + 50)
    try:
        inv = report._file_inventory(tmp_path / "tree")
    finally:
        sys.setrecursionlimit(old_limit)
    assert [row["path"] for row in inv["files"]] == ["d/" * depth + "leaf.txt"]
