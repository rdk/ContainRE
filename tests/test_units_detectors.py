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


def test_decoy_detector_flags_read_as_high_and_write_as_critical():
    det = DecoyDetector()
    read = det.feed({"kind": "file", "seq": 1, "data": {"op": "read", "path": "/w/wallet.dat", "decoy": True}})
    assert read and read[0]["severity"] == "high" and read[0]["id"] == "decoy-access"
    # a later write to the same decoy still escalates to critical (not deduped away)
    write = det.feed({"kind": "file", "seq": 2, "data": {"op": "write", "path": "/w/wallet.dat", "decoy": True}})
    assert write and write[0]["severity"] == "critical"
    # a second read of the same decoy is deduped
    assert det.feed({"kind": "file", "seq": 3, "data": {"op": "read", "path": "/w/wallet.dat", "decoy": True}}) == []


def test_decoy_detector_ignores_non_decoy_and_unrelated_ops():
    det = DecoyDetector()
    assert det.feed({"kind": "file", "seq": 1, "data": {"op": "read", "path": "/w/x", "decoy": False}}) == []
    assert det.feed({"kind": "file", "seq": 2, "data": {"op": "mkdir", "path": "/w/d", "decoy": True}}) == []
