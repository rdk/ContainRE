"""Unit tests for the work-file inventory: its walk and report.work_inventory."""
from __future__ import annotations

import hashlib
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

from containre import policy as P
from containre import report
from containre.report import markdown, summarize_run_dir

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


def _run(tmp_path: Path, *, work: Path, report_policy: dict | None = None,
         assertions: list[dict] | None = None) -> Path:
    run = tmp_path / "run"
    run.mkdir()
    policy: dict[str, Any] = {"specimen": {"path": "/bin/true"},
                              "files": {"work_mount": str(work)}}
    if report_policy is not None or assertions:
        policy["report"] = dict(report_policy or {})
        if assertions:
            policy["report"]["assertions"] = assertions
    (run / "policy.yaml").write_text(yaml.safe_dump(policy))
    (run / "meta.json").write_text(json.dumps({"run_id": "run", "status": "finished",
                                               "exit_code": 0}))
    (run / "events.jsonl").write_text("")
    return run


def _shared_mount(tmp_path: Path) -> Path:
    """A work mount shared by several runs, each working in jobs/<id>."""
    work = tmp_path / "work"
    _write(work / "jobs" / "j1" / "out" / "result.txt", "mine")
    _write(work / "jobs" / "j1" / "in.txt", "input")
    _write(work / "jobs" / "j2" / "out" / "result.txt", "someone else's")
    _write(work / "runs" / "j2" / "events.jsonl", "{}")
    _write(work / "driver.py", "# shared")
    return work


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


@pytest.mark.parametrize("report_policy", [None, {}, {"work_inventory": "all"}])
def test_unscoped_summary_has_the_historical_work_files_shape(tmp_path, report_policy):
    work = _shared_mount(tmp_path)
    run = _run(tmp_path, work=work, report_policy=report_policy)
    expected = _legacy_file_inventory(work, max_files=500, hash_limit=report.DEFAULT_HASH_LIMIT)

    summary = summarize_run_dir(run)

    assert json.dumps(summary["work_files"]) == json.dumps(expected)
    assert "| Work files | 5 |" in markdown(summary)


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


# -- report.work_inventory: none ---------------------------------------------------

def test_work_inventory_none_skips_the_walk(tmp_path, monkeypatch):
    work = _shared_mount(tmp_path)
    run = _run(tmp_path, work=work, report_policy={"work_inventory": "none"}, assertions=[
        {"id": "no-egress", "subject": "network.real_allowed_remote_endpoint_event_count",
         "op": "eq", "value": 0},
        {"id": "no-archives", "subject": "work_files.names", "op": "none_match",
         "value": ["*.zip"]},
        {"id": "empty", "subject": "work_files.count", "op": "eq", "value": 0},
    ])

    def no_walk(*args, **kwargs):
        raise AssertionError("the work mount was walked")

    monkeypatch.setattr(report, "_walk_files", no_walk)
    summary = summarize_run_dir(run)

    assert summary["work_files"] == {
        "base": str(work), "exists": True, "skipped": "policy",
        "files": [], "count": 0, "total_bytes": 0, "truncated": False,
    }
    results = {row["id"]: row for row in summary["assertions"]["results"]}
    assert results["no-egress"]["status"] == "passed"
    # An inventory that was never taken must not satisfy a negative assertion.
    for aid in ("no-archives", "empty"):
        assert results[aid]["status"] == "error"
        assert "report.work_inventory is 'none'" in results[aid]["message"]
    assert summary["assertions"]["status"] == "failed"
    rendered = markdown(summary)
    assert "| Work files | skipped |" in rendered
    assert "- not inventoried: report.work_inventory is 'none'" in rendered


def test_work_inventory_none_leaves_artifacts_inventoried(tmp_path):
    work = _shared_mount(tmp_path)
    run = _run(tmp_path, work=work, report_policy={"work_inventory": "none"})
    _write(run / "files" / "captured.bin", "artifact")

    summary = summarize_run_dir(run)

    assert summary["metrics"]["artifacts.names"] == ["captured.bin"]


# -- report.work_inventory: subdir -------------------------------------------------

def test_work_inventory_subdir_lists_only_that_directory(tmp_path, monkeypatch):
    work = _shared_mount(tmp_path)
    run = _run(tmp_path, work=work, report_policy={"work_inventory": {"subdir": "jobs/j1/"}},
               assertions=[{"id": "has-result", "subject": "work_files.names", "op": "contains",
                            "value": "out/result.txt"}])
    listed: list[str] = []
    real_list_dir = report._list_dir

    def spy(path, identity):
        listed.append(path)
        return real_list_dir(path, identity)

    monkeypatch.setattr(report, "_list_dir", spy)
    summary = summarize_run_dir(run)

    inv = summary["work_files"]
    assert inv["base"] == str(work / "jobs" / "j1")
    assert inv["subdir"] == "jobs/j1"
    assert inv["exists"] is True and "skipped" not in inv
    assert [row["path"] for row in inv["files"]] == ["in.txt", "out/result.txt"]
    assert inv["count"] == 2 and inv["total_bytes"] == len("input") + len("mine")
    assert summary["metrics"]["work_files.names"] == ["in.txt", "out/result.txt"]
    assert summary["assertions"]["status"] == "passed"
    assert listed and all(p.startswith(str(work / "jobs" / "j1")) for p in listed)
    assert "Base: `" + str(work / "jobs" / "j1") + "`" in markdown(summary)


def test_work_inventory_subdir_names_match_an_unshared_run(tmp_path):
    shared = _shared_mount(tmp_path)
    own = tmp_path / "own"
    _write(own / "out" / "result.txt", "mine")
    _write(own / "in.txt", "input")
    scoped = report._file_inventory(shared, subdir="jobs/j1")
    alone = report._file_inventory(own)

    assert scoped["files"] == alone["files"]
    assert (scoped["count"], scoped["total_bytes"]) == (alone["count"], alone["total_bytes"])


def test_work_inventory_subdir_excludes_symlink_escapes_inside_it(tmp_path):
    work = _shared_mount(tmp_path)
    mine = work / "jobs" / "j1"
    secret = _write(tmp_path / "host" / "secret.txt", SECRET)
    (mine / "loot").symlink_to(secret)
    (mine / "loot-dir").symlink_to(secret.parent)
    (mine / "peer").symlink_to(work / "jobs" / "j2")
    (mine / "out" / "up").symlink_to("../..")
    run = _run(tmp_path, work=work, report_policy={"work_inventory": {"subdir": "jobs/j1"}})

    summary = summarize_run_dir(run)

    assert summary["metrics"]["work_files.names"] == ["in.txt", "out/result.txt"]
    assert SECRET_DIGEST not in {row["sha256"] for row in summary["work_files"]["files"]}


@pytest.mark.parametrize("linked", ["jobs/j1", "jobs"])
def test_work_inventory_subdir_through_a_symlink_is_rejected(tmp_path, linked):
    work = _shared_mount(tmp_path)
    outside = tmp_path / "host"
    _write(outside / "j1" / "secret.txt", SECRET)
    _write(outside / "secret.txt", SECRET)
    (work / linked).rename(work / f"{linked}-moved")
    (work / linked).symlink_to(outside)
    run = _run(tmp_path, work=work, report_policy={"work_inventory": {"subdir": "jobs/j1"}},
               assertions=[{"id": "no-secret", "subject": "work_files.names",
                            "op": "none_match", "value": ["*secret*"]}])

    summary = summarize_run_dir(run)

    inv = summary["work_files"]
    assert inv["skipped"] == "invalid"
    assert inv["exists"] is False and inv["files"] == [] and inv["count"] == 0
    assert inv["subdir"] == "jobs/j1"
    assert f"symbolic link {linked.split('/')[-1]!r}" in inv["error"]
    result = summary["assertions"]["results"][0]
    assert result["status"] == "error"
    assert "symbolic link" in result["message"]
    assert "- not inventoried: " in markdown(summary)


def test_work_inventory_subdir_that_does_not_exist(tmp_path):
    work = _shared_mount(tmp_path)
    _write(work / "jobs" / "plain-file")
    for subdir in ("jobs/j9", "jobs/plain-file", "jobs/plain-file/below"):
        inv = report._work_inventory(work, {"report": {"work_inventory": {"subdir": subdir}}},
                                     max_files=500)
        assert inv == {"base": str(work / subdir), "subdir": subdir, "exists": False,
                       "files": [], "count": 0, "total_bytes": 0, "truncated": False}


def test_work_inventory_invalid_value_in_a_persisted_policy_walks_nothing(tmp_path, monkeypatch):
    # A run's policy.yaml is validated when the run starts; one edited afterwards
    # must still not widen the walk.
    work = _shared_mount(tmp_path)
    monkeypatch.setattr(report, "_walk_files", lambda *a, **k: pytest.fail("walked"))
    for value in ({"subdir": "../.."}, {"subdir": "/etc"}, "everything"):
        inv = report._work_inventory(work, {"report": {"work_inventory": value}}, max_files=500)
        assert inv["skipped"] == "invalid"
        assert inv["base"] == str(work) and inv["files"] == []
        assert "report.work_inventory" in inv["error"]


# -- policy validation -------------------------------------------------------------

_VALID = ["all", "none", {"subdir": "jobs/j1"}, {"subdir": "."}, {"subdir": "a/..b/c."},
          {"subdir": "trailing/"}]
_INVALID = ["some", 5, None, [], {}, {"subdir": ""}, {"subdir": "/abs"}, {"subdir": ".."},
            {"subdir": "../x"}, {"subdir": "a/../b"}, {"subdir": "a/.."}, {"subdir": "a\0b"},
            {"subdir": 3}, {"subdr": "x"}]


@pytest.mark.parametrize("value", _VALID)
def test_policy_accepts_work_inventory(value):
    assert P.validate({"specimen": {"path": "/bin/true"},
                       "report": {"work_inventory": value}}) == []


@pytest.mark.parametrize("value", _INVALID)
def test_policy_rejects_work_inventory(value):
    errors = P.validate({"specimen": {"path": "/bin/true"}, "report": {"work_inventory": value}})
    assert errors and all("work_inventory" in e for e in errors)


@pytest.mark.parametrize("value", _INVALID)
def test_policy_rejects_work_inventory_without_the_schema(value, monkeypatch):
    # Validation is soft when no contracts directory is installed; the report
    # trusts this field, so the loader checks it in code as well.
    monkeypatch.setattr(P.contracts, "validate", lambda *a, **k: [])
    errors = P.validate({"specimen": {"path": "/bin/true"}, "report": {"work_inventory": value}})
    assert len(errors) == 1 and errors[0].startswith("['report', 'work_inventory']: ")


def test_load_policy_rejects_an_escaping_subdir(tmp_path):
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump({"specimen": {"path": "/bin/true"},
                                    "report": {"work_inventory": {"subdir": "../peer"}}}))
    with pytest.raises(ValueError, match="work_inventory"):
        P.load_policy(path)


def test_work_inventory_scope_normalizes_and_defaults():
    assert P.work_inventory_scope({}) == "all"
    assert P.work_inventory_scope({"report": {"assertions": []}}) == "all"
    assert P.work_inventory_scope({"report": {"work_inventory": "none"}}) == "none"
    assert P.work_inventory_scope(
        {"report": {"work_inventory": {"subdir": "./jobs//j1/"}}}) == {"subdir": "jobs/j1"}


def test_defaults_leave_work_inventory_unset():
    # Absent means "all"; not defaulting it keeps every effective policy.yaml as before.
    assert "work_inventory" not in P.apply_defaults({"specimen": {"path": "/bin/true"}})["report"]
