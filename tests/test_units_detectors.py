"""Unit tests for the behavioral detectors."""
from __future__ import annotations

import pytest

from containre.detect.detectors import DecoyDetector, InjectionDetector

pytestmark = pytest.mark.unit


def test_injection_detector_fires_on_mmap_exec():
    det = InjectionDetector()
    out = det.feed({"kind": "mem", "seq": 1, "data": {"op": "map", "region": {"perms": "rwx"}}})
    assert out and out[0]["id"] == "rwx-memory"


def test_injection_detector_still_fires_on_mprotect_exec():
    det = InjectionDetector()
    out = det.feed({"kind": "mem", "seq": 1, "data": {"op": "protect", "region": {"perms": "r-x"}}})
    assert out and out[0]["id"] == "rwx-memory"


def test_injection_detector_ignores_non_exec():
    det = InjectionDetector()
    assert det.feed({"kind": "mem", "seq": 1, "data": {"op": "map", "region": {"perms": "rw-"}}}) == []
