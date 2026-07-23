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


def test_detections_and_snapshots_scan_past_the_kind_filter(tmp_path):
    _write_meta(tmp_path, "run")
    lines = [{"seq": i, "kind": "proc", "data": {"op": "noop"}} for i in range(10)]
    lines.append({"seq": 10, "kind": "mem", "data": {"op": "snapshot", "snapshot_id": "snap-a"}})
    lines.append({"seq": 11, "kind": "detection", "data": {"id": "decoy-access", "severity": "critical"}})
    (tmp_path / "run" / "events.jsonl").write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    # A tiny per-kind limit must still find the detection/snapshot past the 10
    # preceding proc events - i.e. the cap counts the requested kind, not total.
    assert [e["seq"] for e in manager.events("run", limit=1, kind="detection")["events"]] == [11]
    assert [e["seq"] for e in manager.detections("run")] == [11]
    assert [e["data"]["snapshot_id"] for e in manager.snapshots("run")] == ["snap-a"]


def test_memory_returns_none_for_corrupt_snapshot(tmp_path):
    _write_meta(tmp_path, "run")
    snap_dir = tmp_path / "run" / "snapshots"
    snap_dir.mkdir()
    (snap_dir / "snap-bad.bin").write_bytes(b"not-a-json-header\x00\x01")  # unparseable header
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    assert manager.memory("run", "snap-bad") is None   # 404, not a 500


def test_memory_returns_none_for_region_without_base(tmp_path):
    import json as _json
    _write_meta(tmp_path, "run")
    snap_dir = tmp_path / "run" / "snapshots"
    snap_dir.mkdir()
    # valid JSON header, but the region lacks a "base" key -> int(region["base"]) would raise
    header = _json.dumps({"pid": 1, "regions": [{"dumped": 4}]}).encode()
    (snap_dir / "snap-nb.bin").write_bytes(header + b"\ndata")
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    assert manager.memory("run", "snap-nb") is None   # 404, not a 500


def test_events_skips_malformed_lines(tmp_path):
    _write_meta(tmp_path, "run")
    (tmp_path / "run" / "events.jsonl").write_text(
        '{"seq": 0, "kind": "proc", "data": {}}\n'
        'this is not json\n'                       # torn/garbage line
        '{"no_seq_field": true}\n'                 # valid json but missing seq
        '{"seq": "abc", "kind": "net", "data": {}}\n'  # valid json, non-numeric seq
        '{"seq": null, "kind": "net", "data": {}}\n'   # valid json, null seq
        '{"seq": 2, "kind": "net", "data": {}}\n'
    )
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    res = manager.events("run")   # must not raise on the non-numeric/null seq lines

    assert [e["seq"] for e in res["events"]] == [0, 2]   # bad lines skipped, good ones kept
    assert res["next_seq"] == 3


def test_snapshots_tolerate_mem_event_without_data_key(tmp_path):
    _write_meta(tmp_path, "run")
    (tmp_path / "run" / "events.jsonl").write_text(
        '{"seq": 0, "kind": "mem"}\n'                                      # forged: no data key
        '{"seq": 1, "kind": "mem", "data": {"op": "snapshot", "snapshot_id": "snap-a"}}\n'
    )
    manager = RunManager(runs_root=tmp_path, max_concurrent=1)

    snaps = manager.snapshots("run")   # must not raise on the data-less mem event

    assert [e["data"]["snapshot_id"] for e in snaps] == ["snap-a"]


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
    manager.runtime.wait = lambda received, timeout=None: 7

    manager._reap("run", handle)

    meta = json.loads((tmp_path / "run" / "meta.json").read_text())
    assert meta["status"] == "error"
    assert meta["exit_code"] == 7
    assert meta["error"] == "runtime exited before finalizing run"
    assert "run" not in manager._active
