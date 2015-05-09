"""YARA scanning tests: memory snapshots + dropped-file artifacts."""
from __future__ import annotations

import pytest

from containre.detect import have_yara

pytestmark = pytest.mark.specimen

_RULES = """
rule mem_marker {
    meta:
        severity = "high"
        description = "test memory marker"
        attack = "T1055"
    strings: $a = "YARA_MEM_MARKER_containre"
    condition: $a
}
rule file_marker {
    meta:
        severity = "critical"
        description = "test file marker"
    strings: $a = "EVIL_FILE_MARKER_containre"
    condition: $a
}
"""


def _rules_file(tmp_path):
    p = tmp_path / "rules.yar"
    p.write_text(_RULES)
    return str(p)


def _yara_ids(result):
    return [d["data"]["id"] for d in result.detections() if d["data"]["id"].startswith("yara:")]


def test_yara_no_false_positive_on_benign(harness):
    # YARA is on by default; the built-in rules must not fire on a benign specimen
    assert _yara_ids(harness("hello")) == []


def test_yara_scans_memory_and_dropped_files(harness, tmp_path):
    if not have_yara():
        pytest.skip("yara-python not installed")
    r = harness("yaratarget", files={"decoys": ["wallet.dat"]},
                trace={"snapshot_on": ["decoy"]},
                detect={"yara": True, "yara_rules": [_rules_file(tmp_path)]})
    ids = _yara_ids(r)
    assert "yara:mem_marker" in ids      # matched in a memory snapshot
    assert "yara:file_marker" in ids     # matched in a captured dropped file
    payloads = list((r.run_dir / "files").glob("*payload.bin"))
    assert payloads and b"EVIL_FILE_MARKER" in payloads[0].read_bytes()


def test_yara_can_be_disabled(harness, tmp_path):
    r = harness("yaratarget", files={"decoys": ["wallet.dat"]},
                trace={"snapshot_on": ["decoy"]},
                detect={"yara": False, "yara_rules": [_rules_file(tmp_path)]})
    assert _yara_ids(r) == []
