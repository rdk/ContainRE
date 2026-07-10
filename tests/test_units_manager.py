"""Unit tests for RunManager read-side behavior."""
from __future__ import annotations

import json

import pytest

from containre.api.manager import CapacityError, RunManager

pytestmark = pytest.mark.unit


def _write_meta(root, run_id, status="running"):
    run_dir = root / run_id
    run_dir.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": run_id,
        "status": status,
        "specimen": {"sha256": "0" * 64},
        "created_wall": 1,
    }))


def test_list_marks_active_runs(tmp_path):
    _write_meta(tmp_path, "active-run")
    _write_meta(tmp_path, "finished-run", status="finished")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)
    manager._active["active-run"] = object()

    by_id = {m["run_id"]: m for m in manager.list()}

    assert by_id["active-run"]["active"] is True
    assert by_id["finished-run"]["active"] is False


def test_events_skips_malformed_lines(tmp_path):
    _write_meta(tmp_path, "run")
    (tmp_path / "run" / "events.jsonl").write_text(
        '{"seq": 0, "kind": "proc", "data": {}}\n'
        'this is not json\n'                       # torn/garbage line
        '{"no_seq_field": true}\n'                 # valid json but missing seq
        '{"seq": 2, "kind": "net", "data": {}}\n'
    )
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    res = manager.events("run")

    assert [e["seq"] for e in res["events"]] == [0, 2]   # bad lines skipped, good ones kept
    assert res["next_seq"] == 3


def test_checkpoint_rejects_unsafe_name_without_writing_outside_run(tmp_path):
    _write_meta(tmp_path, "run")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    result = manager.checkpoint("run", "../../outside")

    assert result == {
        "ok": False,
        "name": "checkpoint",
        "reason": "invalid checkpoint name",
    }
    assert not (tmp_path / "outside.json").exists()
    assert not (tmp_path / "run" / "checkpoints").exists()


def test_restore_rejects_unsafe_name(tmp_path):
    _write_meta(tmp_path, "run")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    result = manager.restore("run", "../checkpoint")

    assert result == {
        "ok": False,
        "name": "checkpoint",
        "reason": "invalid checkpoint name",
    }


def test_memory_rejects_unsafe_snapshot_id(tmp_path):
    _write_meta(tmp_path, "run")
    (tmp_path / "run" / "snapshots").mkdir()
    (tmp_path / "secret.bin").write_text("outside")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    assert manager.memory("run", "../../secret") is None


def test_start_counts_runs_in_startup_toward_capacity(tmp_path):
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)
    manager._starting = 1

    with pytest.raises(CapacityError):
        manager.start({})


def test_reap_marks_unfinalized_run_as_error(tmp_path):
    _write_meta(tmp_path, "run")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)
    handle = object()
    manager._active["run"] = handle
    manager.runtime.wait = lambda received: 7

    manager._reap("run", handle)

    meta = json.loads((tmp_path / "run" / "meta.json").read_text())
    assert meta["status"] == "error"
    assert meta["exit_code"] == 7
    assert meta["error"] == "runtime exited before finalizing run"
    assert "run" not in manager._active
