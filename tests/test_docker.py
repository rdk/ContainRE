"""Integration tests for DockerRuntime - the isolated backend.

Skipped automatically when Docker is unavailable or the runner image can't be
built, so the default suite stays green on hosts without Docker.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

import pytest

from containre import policy as P
from containre.control import execute
from containre.runtime import DockerRuntime, docker_available
from containre.runtime.docker import DockerError

pytestmark = [pytest.mark.docker, pytest.mark.specimen]


@pytest.fixture(scope="module")
def docker_runtime():
    if not docker_available():
        pytest.skip("docker daemon not available")
    rt = DockerRuntime()
    try:
        rt.ensure_image()
    except (DockerError, Exception) as exc:  # build/network problems -> skip, don't fail
        pytest.skip(f"could not prepare runner image: {exc}")
    return rt


@pytest.fixture
def docker_runs():
    # container writes as root (DAC_OVERRIDE), so files may be root-owned;
    # use a throwaway dir and best-effort cleanup.
    d = Path(tempfile.mkdtemp(prefix="containre-docker-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


def _run(rt, runs, build_specimen, name, **overrides):
    pol = P.policy_for_binary(build_specimen(name), limits={"wallclock_s": 20}, **overrides)
    return execute(pol, runs_root=runs, runtime=rt, timeout=60)


def test_docker_hello_runs_isolated(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "hello", network={"posture": "deny"})
    assert r.status == "finished"
    assert r.exit_code == 0
    assert r.meta["runtime"] == "docker"
    assert r.meta["image"] == "containre/runner:0.1"
    assert "hello from specimen" in (r.run_dir / "console.log").read_text()


def test_docker_decoy_detected(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "filewriter",
             network={"posture": "deny"}, files={"decoys": ["wallet.dat"]})
    assert r.status == "finished"
    assert "decoy-access" in [d["data"]["id"] for d in r.detections()]
    assert "decoy-hit" in r.meta["verdict"]["flags"]


def test_docker_network_blocked(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "netbeacon", network={"posture": "deny"})
    conns = [e["data"] for e in r.events()
             if e["kind"] == "net" and e["data"].get("op") == "connect"]
    assert conns and conns[0]["decision"] == "block"
    assert "returned -1" in (r.run_dir / "console.log").read_text()
    assert "network-egress" in [d["data"]["id"] for d in r.detections()]


def test_docker_l2_single_step(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "l2demo", network={"posture": "deny"},
             trace={"l2": {"mode": "singlestep", "window": {"max_insns": 2000}}})
    assert r.status == "finished" and r.exit_code == 38
    instrs = [e for e in r.events() if e["kind"] == "instr"]
    assert len(instrs) > 15
    assert any(w["new"] == "0x26"
               for e in instrs for w in e["data"].get("mem_writes", []))


def test_docker_simulated_internet(docker_runtime, docker_runs, build_specimen):
    # the sink runs inside the container; loopback works even under --network none
    r = _run(docker_runtime, docker_runs, build_specimen, "httpbeacon",
             network={"posture": "simulate"})
    assert r.status == "finished" and r.exit_code == 0
    http = [e["data"] for e in r.events()
            if e["kind"] == "net" and e["data"].get("op") == "http"]
    assert http and http[0]["http"]["host"] == "evil.example.com"
    assert "HTTP/1.1 200 OK" in (r.run_dir / "console.log").read_text()


def test_docker_pcap_capture(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "httpbeacon",
             network={"posture": "simulate"})
    pcap = r.run_dir / "net" / "capture.pcap"
    assert pcap.exists()
    data = pcap.read_bytes()
    assert data[:4] == b"\xd4\xc3\xb2\xa1"          # little-endian pcap magic
    assert b"GET /malware/config" in data


def test_docker_tls_mitm_decrypts(docker_runtime, docker_runs, build_specimen):
    r = _run(docker_runtime, docker_runs, build_specimen, "httpsbeacon",
             network={"posture": "simulate", "mitm": True})
    assert r.status == "finished" and r.exit_code == 0
    https = [e["data"] for e in r.events()
             if e["kind"] == "net" and e["data"].get("op") == "http"]
    assert https and https[0]["tls"] is True and https[0]["http"]["path"] == "/gate/beacon"


def test_docker_yara_builtin(docker_runtime, docker_runs, build_specimen):
    # built-in embedded_pe rule matches the dropped fake-PE file, in-container
    r = _run(docker_runtime, docker_runs, build_specimen, "yaratarget",
             network={"posture": "deny"}, files={"decoys": ["wallet.dat"]})
    ids = [d["data"]["id"] for d in r.detections()]
    assert "yara:embedded_pe" in ids


def test_docker_unicorn_region(docker_runtime, docker_runs, build_specimen):
    import subprocess
    binp = build_specimen("l2demo")
    out = subprocess.check_output(["nm", "--print-size", "--defined-only", str(binp)], text=True)
    addr = size = None
    for line in out.splitlines():
        p = line.split()
        if p and p[-1] == "compute":
            addr = int(p[0], 16)
            size = int(p[1], 16) if len(p) == 4 else 0x28
    r = _run(docker_runtime, docker_runs, build_specimen, "l2demo", network={"posture": "deny"},
             trace={"l2": {"mode": "unicorn",
                           "window": {"addr_start": hex(addr), "addr_end": hex(addr + size),
                                      "max_insns": 100}}})
    instrs = [e for e in r.events() if e["kind"] == "instr"]
    assert instrs and all(e["data"]["engine"] == "unicorn" for e in instrs)
    assert any(e["data"].get("reg_deltas", {}).get("rax", {}).get("new") == "0x26"
               for e in instrs)
