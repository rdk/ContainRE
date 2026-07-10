"""Unit tests for byte-oriented YARA scanning."""
from __future__ import annotations

import pytest

from containre.detect import YaraScanner, have_yara

pytestmark = pytest.mark.unit

_RULES = """
rule mem_marker {
    meta:
        severity = "high"
        description = "test memory marker"
        attack = "T1055"
    strings: $a = "YARA_MEM_MARKER_containre"
    condition: $a
}
"""


def test_yara_scanner_unit(tmp_path):
    if not have_yara():
        pytest.skip("yara-python not installed")
    rules = tmp_path / "rules.yar"
    rules.write_text(_RULES)
    sc = YaraScanner([str(rules)], use_builtin=False)
    assert sc.enabled()
    hits = sc.scan(b"....YARA_MEM_MARKER_containre....", {"snapshot_id": "snap-1", "seq": None})
    assert hits and hits[0]["id"] == "yara:mem_marker"
    assert hits[0]["severity"] == "high" and hits[0]["attack"] == ["T1055"]
    assert hits[0]["refs"] == {"snapshot_id": "snap-1"}
    assert sc.scan(b"nothing to see", {}) == []


def test_scanner_warns_on_a_missing_rule_file(tmp_path):
    if not have_yara():
        pytest.skip("yara-python not installed")
    sc = YaraScanner([str(tmp_path / "nope.yar")], use_builtin=False)
    assert not sc.enabled()   # nothing compiled
    assert any("not found" in w for w in sc.warnings)


def test_bad_custom_rule_does_not_disable_builtin_or_good_rules(tmp_path):
    if not have_yara():
        pytest.skip("yara-python not installed")
    good = tmp_path / "good.yar"
    good.write_text(_RULES)
    bad = tmp_path / "bad.yar"
    bad.write_text("rule broken { this is not valid yara }")

    sc = YaraScanner([str(good), str(bad)], use_builtin=False)

    assert sc.enabled()   # the good ruleset still compiled despite the broken one
    assert any("failed to compile" in w for w in sc.warnings)
    hits = sc.scan(b"....YARA_MEM_MARKER_containre....", {"snapshot_id": "snap-1"})
    assert hits and hits[0]["id"] == "yara:mem_marker"
