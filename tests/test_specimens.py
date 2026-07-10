"""Behavioral tests: run each specimen under the harness and assert on the trace."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.specimen


def _files(result):
    return [e["data"] for e in result.events() if e["kind"] == "file"]


def _nets(result):
    return [e["data"] for e in result.events() if e["kind"] == "net"]


def _procs(result):
    return [e["data"] for e in result.events() if e["kind"] == "proc"]


def _det_ids(result):
    return [d["data"]["id"] for d in result.detections()]


def _console(result):
    p = result.run_dir / "console.log"
    return p.read_text() if p.exists() else ""


def test_hello_is_clean(harness):
    r = harness("hello")
    assert r.status == "finished"
    assert r.exit_code == 0
    assert r.detections() == []          # baseline: nothing alarming
    assert "hello from specimen" in _console(r)


def test_filewriter_file_events(harness):
    r = harness("filewriter", files={"decoys": ["wallet.dat"]})
    assert r.status == "finished" and r.exit_code == 0
    files = _files(r)
    assert any(d["op"] == "write" and d["path"].endswith("output.txt") for d in files)
    assert any(d["op"] == "unlink" and d["path"].endswith("temp.bin") for d in files)


def test_filewriter_decoy_detection(harness):
    # attack_tags defaults off (SPEC §10); opt in to exercise the ATT&CK mapping.
    r = harness("filewriter", files={"decoys": ["wallet.dat"]},
                detect={"attack_tags": True})
    # the decoy write is flagged on the event itself...
    assert any(d["op"] == "write" and d.get("decoy") and d["path"].endswith("wallet.dat")
               for d in _files(r))
    # ...and raised as a critical detection
    assert "decoy-access" in _det_ids(r)
    assert r.meta["verdict"]["max_severity"] == "critical"
    assert "decoy-hit" in r.meta["verdict"]["flags"]
    assert "T1657" in r.meta["verdict"]["attack"]


def test_ransomemu_renames_planted_decoy_only(harness):
    r = harness("ransomemu", files={"decoys": ["documents/report.txt"]})
    assert r.status == "finished" and r.exit_code == 0
    files = _files(r)
    assert any(d["op"] == "rename"
               and d.get("decoy")
               and d["path"].endswith("documents/report.txt")
               and d["newpath"].endswith("documents/report.txt.locked")
               for d in files)
    assert any(d["op"] == "write" and d["path"].endswith("README_RECOVER.txt")
               for d in files)
    assert "decoy-access" in _det_ids(r)
    assert r.meta["verdict"]["max_severity"] == "critical"
    assert "ransom emulator done" in _console(r)


def test_dropper_stub_writes_payload_but_does_not_execute_it(harness):
    r = harness("dropper_stub")
    assert r.status == "finished" and r.exit_code == 0
    files = _files(r)
    assert any(d["op"] == "write" and d["path"].endswith("payload.sh") for d in files)
    assert any(d["op"] == "chmod" and d["path"].endswith("payload.sh") for d in files)
    assert not any(d.get("op") == "exec" and "payload.sh" in " ".join(d.get("argv", []))
                   for d in _procs(r))
    payloads = list((r.run_dir / "files").glob("*payload.sh"))
    assert payloads and b"harmless payload fixture" in payloads[0].read_bytes()


def test_netbeacon_connect_is_blocked(harness):
    r = harness("netbeacon")
    assert r.status == "finished"
    conns = [d for d in _nets(r) if d.get("op") == "connect"]
    assert conns, "expected a connect event"
    assert conns[0]["raddr"].startswith("93.184.216.34")
    assert conns[0]["decision"] == "block"
    assert "returned -1" in _console(r)     # specimen observed the failure
    assert "network-egress" in _det_ids(r)


def test_netbeacon_allowlist_is_not_blocked(harness):
    # Point at a closed local port and allowlist it: the harness must NOT block
    # (decision=allow); the OS then refuses it quickly on its own.
    r = harness("netbeacon", args=["127.0.0.1", "1"],
                network={"posture": "deny", "allow": ["127.0.0.1"]})
    conns = [d for d in _nets(r) if d.get("op") == "connect"]
    assert conns and conns[0]["decision"] == "allow"


def test_ipv6beacon_connect_is_blocked(harness):
    r = harness("ipv6beacon")
    console = _console(r)
    if "ipv6 socket unavailable" in console:
        pytest.skip("IPv6 sockets unavailable on this host")
    assert r.status == "finished" and r.exit_code == 0
    conns = [d for d in _nets(r) if d.get("op") == "connect"]
    assert conns, "expected an IPv6 connect event"
    assert conns[0]["raddr"] == "[2001:db8::42]:443"
    assert conns[0]["decision"] == "block"
    assert "network-egress" in _det_ids(r)
    assert "returned -1" in console


def test_bindshell_stub_records_loopback_bind_without_exec(harness):
    r = harness("bindshell_stub")
    assert r.status == "finished" and r.exit_code == 0
    nets = _nets(r)
    assert any(d.get("op") == "bind"
               and d.get("proto") == "tcp"
               and d.get("laddr", "").startswith("127.0.0.1:")
               for d in nets)
    assert any(d.get("op") == "listen" for d in nets)
    assert not any(d.get("op") == "exec" for d in _procs(r))
    assert "network-egress" not in _det_ids(r)
    assert "without accepting" in _console(r)


def test_rawsock_probe_records_attempt_without_egress(harness):
    r = harness("rawsock_probe")
    assert r.status == "finished" and r.exit_code == 0
    nets = _nets(r)
    assert any(d.get("op") == "socket" for d in nets)
    assert not any(d.get("op") in ("connect", "send") for d in nets)
    assert "network-egress" not in _det_ids(r)
    assert "raw socket" in _console(r)


def test_spawner_tracks_child(harness):
    r = harness("spawner")
    assert r.status == "finished" and r.exit_code == 0
    procs = _procs(r)
    assert any(d["op"] == "clone" for d in procs)
    assert any(d["op"] == "exec" and d.get("path") == "/bin/echo" for d in procs)
    assert "child-ran" in _console(r)


def test_antidebug_is_flagged(harness):
    r = harness("antidebug")
    assert r.status == "finished"
    assert "anti-debug" in _det_ids(r)
    assert "anti-debug" in r.meta["verdict"]["flags"]


def test_sleeper_hits_wallclock_kill(harness):
    r = harness("sleeper", limits={"wallclock_s": 2})
    assert r.status == "killed"
    assert r.meta["kill_reason"] == "timeout"


def test_unpacker_makes_memory_executable(harness):
    r = harness("unpacker")
    assert r.status == "finished" and r.exit_code == 0
    mems = [e["data"] for e in r.events() if e["kind"] == "mem"]
    assert any(d.get("op") == "protect" and "x" in d.get("region", {}).get("perms", "")
               for d in mems)
    assert "rwx-memory" in _det_ids(r)
    assert "stub executed" in _console(r)


def test_snooper_flags_secrets_not_passwd(harness):
    r = harness("snooper")
    assert "sensitive-file-access" in _det_ids(r)
    flagged = [d["data"]["iocs"][0]["value"] for d in r.detections()
               if d["data"]["id"] == "sensitive-file-access"]
    assert any("shadow" in p or "id_rsa" in p for p in flagged)
    assert "/etc/passwd" not in flagged          # world-readable, too common to flag


def test_udpbeacon_send_is_blocked(harness):
    r = harness("udpbeacon")
    sends = [d for d in _nets(r) if d.get("op") == "send"]
    assert sends and sends[0]["decision"] == "block"
    assert sends[0]["raddr"].startswith("8.8.8.8")
    assert "returned -1" in _console(r)


def test_threader_tracks_threads(harness):
    r = harness("threader")
    assert r.status == "finished" and r.exit_code == 0
    clones = [d for d in _procs(r) if d.get("op") == "clone"]
    assert len(clones) >= 3                        # three worker threads
    assert "threads done" in _console(r)


def test_forkbomb_safe_is_bounded(harness):
    r = harness("forkbomb_safe")
    assert r.status == "finished" and r.exit_code == 0
    clones = [d for d in _procs(r) if d.get("op") == "clone"]
    assert 4 <= len(clones) <= 8
    assert "bounded fork fanout complete (4 children)" in _console(r)


def test_l1_class_filter_drops_unselected_kinds(harness):
    # record only 'file' events: the connect attempt is still blocked, but no
    # 'net' events are recorded (trace.l1 gates recording, not enforcement).
    r = harness("filewriter", files={"decoys": ["wallet.dat"]},
                trace={"l1": ["file"], "snapshot_on": []})
    kinds = {e["kind"] for e in r.events()}
    assert "file" in kinds
    assert "net" not in kinds and "proc" not in kinds
    # detections that depend on the recorded class still work
    assert "decoy-access" in _det_ids(r)
