"""Unit tests for the behavioral detectors."""
from __future__ import annotations

import pytest

from containre.detect.detectors import DecoyDetector, InjectionDetector

pytestmark = pytest.mark.unit


def test_injection_detector_fires_on_rwx_mmap():
    det = InjectionDetector()
    out = det.feed({"kind": "mem", "seq": 1, "data": {"op": "map", "region": {"perms": "rwx"}}})
    assert out and out[0]["id"] == "rwx-memory"


def test_injection_detector_ignores_plain_rx_mmap():
    # the dynamic loader maps code as r-x; that must not false-positive.
    det = InjectionDetector()
    assert det.feed({"kind": "mem", "seq": 1, "data": {"op": "map", "region": {"perms": "r-x"}}}) == []


def test_injection_detector_still_fires_on_mprotect_exec():
    det = InjectionDetector()
    out = det.feed({"kind": "mem", "seq": 1, "data": {"op": "protect", "region": {"perms": "r-x"}}})
    assert out and out[0]["id"] == "rwx-memory"


def test_injection_detector_ignores_non_exec():
    det = InjectionDetector()
    assert det.feed({"kind": "mem", "seq": 1, "data": {"op": "map", "region": {"perms": "rw-"}}}) == []


def _file(seq, op, path="/w/wallet.dat", decoy=True):
    return {"kind": "file", "seq": seq, "data": {"op": op, "path": path, "decoy": decoy}}


def test_decoy_detector_flags_open_as_high_and_write_as_critical():
    det = DecoyDetector()
    # op="open" is the ACTUAL decoy-access event the tracer emits (not "read").
    opened = det.feed(_file(1, "open"))
    assert opened and opened[0]["severity"] == "high" and opened[0]["id"] == "decoy-access"
    # a later write to the same decoy still escalates to critical (not deduped away)
    write = det.feed(_file(2, "write"))
    assert write and write[0]["severity"] == "critical"
    # a second open of the same decoy is deduped
    assert det.feed(_file(3, "open")) == []


def test_decoy_detector_flags_truncate_wipe_as_critical():
    # a bare truncate("/work/wallet.dat", 0) wiper must raise a critical detection.
    det = DecoyDetector()
    out = det.feed(_file(1, "truncate"))
    assert out and out[0]["severity"] == "critical" and out[0]["id"] == "decoy-access"


def test_decoy_detector_ignores_non_decoy_and_unrelated_ops():
    det = DecoyDetector()
    assert det.feed(_file(1, "open", decoy=False)) == []
    assert det.feed(_file(2, "mkdir")) == []
