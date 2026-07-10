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


def _decoy_write(work):
    return Event(Kind.FILE, {"op": "write", "path": str(work / "wallet.dat"),
                             "size": 4, "decoy": True}, pid=1)


def test_detect_heuristics_flag_disables_heuristic_detectors(tmp_path):
    session, work = _session(tmp_path, detect={"yara": False, "heuristics": False})
    try:
        session.emit(_decoy_write(work))
        assert [e for e in _events(session) if e["kind"] == Kind.DETECTION] == []
    finally:
        session.store.close()


def test_detect_iocs_flag_disables_egress_detector(tmp_path):
    session, _ = _session(tmp_path, detect={"yara": False, "iocs": False})
    try:
        session.emit(Event(Kind.NET, {"op": "connect", "raddr": "1.2.3.4:80",
                                      "decision": "block"}, pid=1))
        dets = [e for e in _events(session) if e["kind"] == Kind.DETECTION]
        assert not any(d["data"]["id"] == "network-egress" for d in dets)
    finally:
        session.store.close()


def test_attack_tags_off_strips_att_ck_from_detections_and_verdict(tmp_path):
    session, work = _session(tmp_path, detect={"yara": False})  # attack_tags default off
    try:
        session.emit(_decoy_write(work))
        det = [e for e in _events(session) if e["kind"] == Kind.DETECTION][0]
        assert "attack" not in det["data"]
        assert session.verdict.to_dict()["attack"] == []
        assert "decoy-hit" in session.verdict.to_dict()["flags"]  # flags still work
    finally:
        session.store.close()


def test_attack_tags_on_keeps_att_ck_tags(tmp_path):
    session, work = _session(tmp_path, detect={"yara": False, "attack_tags": True})
    try:
        session.emit(_decoy_write(work))
        det = [e for e in _events(session) if e["kind"] == Kind.DETECTION][0]
        assert det["data"]["attack"] == ["T1657"]
        assert session.verdict.to_dict()["attack"] == ["T1657"]
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


def test_write_pcap_handles_more_flows_than_16bit_sport_range(tmp_path):
    session, _ = _session(tmp_path)
    # >25535 flows would push sport 40000+i past 65535 and raise struct.error,
    # crashing run finalization before finalize()/capture_artifacts().
    flows = {(0, i): {"raddr": "1.2.3.4:80", "chunks": [("out", b"x")]}
             for i in range(25600)}
    try:
        session.write_pcap(flows)  # must not raise
        assert (session.run_dir / "net" / "capture.pcap").exists()
    finally:
        session.store.close()


def test_capture_artifacts_refuses_symlink_escaping_workdir(tmp_path):
    session, work = _session(tmp_path)
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"TOP SECRET HOST FILE")
    # specimen recorded a write to work/loot, then replaced it with a symlink to a
    # host file outside the workdir before exiting.
    loot = work / "loot"
    loot.symlink_to(secret)
    try:
        session.emit(Event(Kind.FILE, {"op": "write", "path": str(loot), "size": 4}))
        session.capture_artifacts()
        files = list((session.run_dir / "files").iterdir())
        assert files == [], "symlink escaping workdir must not be captured"
    finally:
        session.store.close()


def test_capture_artifacts_refuses_symlinked_parent_dir(tmp_path):
    session, work = _session(tmp_path)
    secret = tmp_path / "vault"
    secret.mkdir()
    (secret / "key").write_bytes(b"host key material")
    # a parent component under workdir is a symlink pointing outside it.
    (work / "d").symlink_to(secret)
    try:
        session.emit(Event(Kind.FILE, {"op": "write", "path": str(work / "d" / "key"), "size": 4}))
        session.capture_artifacts()
        assert list((session.run_dir / "files").iterdir()) == []
    finally:
        session.store.close()


def test_snapshot_yara_scans_raw_uncompressed_bytes(tmp_path, monkeypatch):
    from containre.tracer import session as sess_mod
    session, _ = _session(tmp_path, detect={"yara": False})
    raw = b'{"pid":1,"regions":[]}\n' + b"MZ\x90\x00 unpacked payload marker"
    monkeypatch.setattr(sess_mod, "capture", lambda pid: (raw, [], 0))

    scanned = {}

    class FakeYara:
        def enabled(self):
            return True

        def scan(self, data, ctx):
            scanned["data"] = data
            return []

    session.yara = FakeYara()
    try:
        session.snapshot(1234, "connect")
        # YARA must see the raw plaintext bytes, not the zstd-compressed blob.
        assert scanned["data"] == raw
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
