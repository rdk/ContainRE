"""Unit tests for RunSession recording, detectors, artifacts, and pcap output."""
from __future__ import annotations

import json

import pytest

from containre.tracer.session import RunSession
from containre.model import Event, Kind

pytestmark = pytest.mark.unit


def _session(tmp_path, *, detect=None):
    work = tmp_path / "work"
    work.mkdir()
    policy = {"detect": detect if detect is not None else {"yara": False}}
    return RunSession(tmp_path / "run", policy, str(work)), work


def _events(session: RunSession) -> list[dict]:
    session.store.commit()
    path = session.run_dir / "events.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def test_emit_feeds_detectors_and_updates_verdict(tmp_path):
    session, work = _session(tmp_path)
    try:
        session.emit(Event(Kind.FILE, {
            "op": "write",
            "path": str(work / "wallet.dat"),
            "size": 4,
            "decoy": True,
        }, pid=123))
        events = _events(session)
        detections = [e for e in events if e["kind"] == Kind.DETECTION]
        assert len(detections) == 1
        assert detections[0]["data"]["id"] == "decoy-access"
        assert session.verdict.to_dict()["max_severity"] == "critical"
    finally:
        session.store.close()


def test_capture_artifacts_collects_written_workdir_files(tmp_path):
    session, work = _session(tmp_path)
    payload = work / "payload.bin"
    payload.write_bytes(b"payload bytes")
    try:
        session.emit(Event(Kind.FILE, {"op": "write", "path": str(payload), "size": 13}))
        session.capture_artifacts()
        artifacts = list((session.run_dir / "files").glob("*payload.bin"))
        assert artifacts and artifacts[0].read_bytes() == b"payload bytes"
    finally:
        session.store.close()


def test_capture_artifacts_ignores_paths_outside_workdir(tmp_path):
    session, _ = _session(tmp_path)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    try:
        session.emit(Event(Kind.FILE, {"op": "write", "path": str(outside), "size": 7}))
        session.capture_artifacts()
        assert list((session.run_dir / "files").iterdir()) == []
    finally:
        session.store.close()


def test_write_pcap_skips_empty_flows_and_writes_nonempty_flow(tmp_path):
    session, _ = _session(tmp_path)
    try:
        session.write_pcap({})
        assert not (session.run_dir / "net").exists()

        session.write_pcap({
            (1, 2): {"raddr": "1.2.3.4:80", "chunks": []},
        })
        assert not (session.run_dir / "net" / "capture.pcap").exists()

        session.write_pcap({
            (1, 3): {"raddr": "1.2.3.4:80", "chunks": [("out", b"GET / HTTP/1.0\r\n\r\n")]},
        })
        pcap = session.run_dir / "net" / "capture.pcap"
        assert pcap.exists()
        assert pcap.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"
    finally:
        session.store.close()
