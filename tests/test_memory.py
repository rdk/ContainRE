"""Memory-snapshot tests: triggers fire, blobs are written, and events reference them."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.specimen


def _snaps(result):
    return [e for e in result.events()
            if e["kind"] == "mem" and e["data"].get("op") == "snapshot"]


def test_snapshot_blobs_are_written(harness):
    # the dynamic loader maps executable regions at startup -> an mmap+x snapshot
    r = harness("hello")
    snaps = _snaps(r)
    assert snaps, "expected at least one memory snapshot"
    files = list((r.run_dir / "snapshots").glob("*"))
    assert files and all(f.stat().st_size > 0 for f in files)
    assert r.meta["counts"]["snapshots"] == len(snaps)
    # each snapshot event references a stored blob id
    for s in snaps:
        assert s["data"]["snapshot_id"].startswith("snap-")
        assert any(s["data"]["snapshot_id"] in f.name for f in files)


def test_snapshot_triggers_on_connect(harness):
    r = harness("netbeacon")
    assert "connect" in {s["data"]["reason"] for s in _snaps(r)}


def test_snapshot_triggers_on_decoy_only_when_configured(harness):
    # restrict triggers to 'decoy' so we prove that specific trigger fired
    r = harness("filewriter", files={"decoys": ["wallet.dat"]},
                trace={"snapshot_on": ["decoy"]})
    reasons = {s["data"]["reason"] for s in _snaps(r)}
    assert reasons == {"decoy"}


def test_no_snapshots_when_triggers_empty(harness):
    r = harness("hello", trace={"snapshot_on": []})
    assert _snaps(r) == []
    assert r.meta["counts"]["snapshots"] == 0