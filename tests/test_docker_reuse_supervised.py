"""Docker-backed tests for the generic supervised/reuse-container mechanism.

No domain tooling required: a lightweight image + fake "workloads" (a sleep in
its own session) exercise the host<->container glue — per-exec kill without
touching peers (reuse.kill / list_live / stop_if_idle), the supervisor's sink
readiness, and the workload_only fail-closed path.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from containre.runtime import DockerRuntime, docker_available
from containre.runtime import reuse

pytestmark = [pytest.mark.docker, pytest.mark.specimen]

REPO = Path(__file__).resolve().parents[1]
IMAGE = "containre/runner:0.1"


def _run(argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True, check=check)


@pytest.fixture(autouse=True)
def _require_docker():
    if not docker_available():
        pytest.skip("docker daemon not available")
    if not DockerRuntime().image_present():
        pytest.skip(f"{IMAGE} not built; run the docker specimen tests first")


def _mk(runs_root: Path, run_id: str) -> Path:
    d = runs_root / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _launch_fake_workload(container: str, runs_root: Path, run_id: str) -> None:
    """Start a process in its own session inside the container (pid == pgid, like
    the real runner's driver) and record its pgid at /runs/<run_id>/leader.pgid."""
    py = (
        "import os,subprocess;"
        "p=subprocess.Popen(['sleep','600'],start_new_session=True);"
        f"f=open('/runs/{run_id}/leader.pgid','w');"
        "f.write(str(p.pid));f.flush();os.fsync(f.fileno());f.close()"
    )
    _run(["docker", "exec", "-d", container, "python3", "-c", py])


def _wait_pgid(runs_root: Path, run_id: str) -> int:
    p = runs_root / run_id / "leader.pgid"
    for _ in range(80):
        if p.exists() and p.read_text().strip():
            return int(p.read_text().strip())
        time.sleep(0.1)
    raise AssertionError(f"pgid never recorded for {run_id}")


def _start_container(name: str, runs_root: Path) -> None:
    _run(["docker", "run", "-d", "--name", name,
          "-v", f"{runs_root}:/runs", IMAGE, "sleep", "infinity"])


def test_reuse_kill_stops_one_exec_peer_untouched(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    container = f"containre-test-reuse-{os.getpid()}"
    _start_container(container, runs_root)
    try:
        for rid in ("live", "gone"):
            _mk(runs_root, rid)
            reuse.mark(runs_root / rid, container)
            _launch_fake_workload(container, runs_root, rid)
        live_pgid = _wait_pgid(runs_root, "live")
        gone_pgid = _wait_pgid(runs_root, "gone")
        assert len(reuse.list_live(runs_root, container)) == 2

        assert reuse.kill(runs_root, container, "gone") is True

        assert not reuse._pgid_alive(container, gone_pgid)   # target stopped
        assert reuse._pgid_alive(container, live_pgid)       # peer survives
        assert {e["run_id"] for e in reuse.list_live(runs_root, container)} == {"live"}
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def test_reap_kills_exec_with_dead_owner(tmp_path):
    """reuse.reap stops an exec whose owner process has died; an exec with a live
    owner is left running."""
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    container = f"containre-test-reap-{os.getpid()}"
    _start_container(container, runs_root)
    try:
        # 'live' owned by this (alive) test process; 'orph' by a dead pid.
        _mk(runs_root, "live"); reuse.mark(runs_root / "live", container)
        reuse.mark_owner(runs_root / "live", os.getpid(), reuse.proc_start_token(os.getpid()))
        _launch_fake_workload(container, runs_root, "live")
        dead = subprocess.Popen(["sleep", "0.05"]); dpid = dead.pid; dead.wait()
        _mk(runs_root, "orph"); reuse.mark(runs_root / "orph", container)
        reuse.mark_owner(runs_root / "orph", dpid, "99")
        _launch_fake_workload(container, runs_root, "orph")
        live_pgid = _wait_pgid(runs_root, "live")
        orph_pgid = _wait_pgid(runs_root, "orph")

        assert reuse.reap(runs_root, container) == ["orph"]

        assert not reuse._pgid_alive(container, orph_pgid)   # abandoned exec reaped
        assert reuse._pgid_alive(container, live_pgid)       # live-owner exec survives
        assert {e["run_id"] for e in reuse.list_live(runs_root, container)} == {"live"}
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def test_stop_if_idle_refuses_while_busy(tmp_path):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    container = f"containre-test-idle-{os.getpid()}"
    _start_container(container, runs_root)
    try:
        _mk(runs_root, "busy")
        reuse.mark(runs_root / "busy", container)
        _launch_fake_workload(container, runs_root, "busy")
        _wait_pgid(runs_root, "busy")
        assert reuse.stop_if_idle(runs_root, container) is False   # busy -> refused
        reuse.kill(runs_root, container, "busy")
        assert reuse.stop_if_idle(runs_root, container) is True    # now idle -> stopped
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def test_supervisor_marks_ready_then_unready_on_stop(tmp_path):
    work = tmp_path / "work"
    work.mkdir()
    container = f"containre-test-sup-{os.getpid()}"
    _run(["docker", "run", "-d", "--name", container,
          "-v", f"{work}:/work",
          "-v", f"{REPO / 'containre'}:/opt/containre/containre:ro",
          "-e", "PYTHONPATH=/opt/containre",
          "-e", 'CONTAINRE_SINK_CONFIG={"listen_port":0}',
          "-e", "CONTAINRE_READY_MARKER=/work/.containre-ready",
          "-e", "CONTAINRE_CA_PATH=/work/.containre-ca.pem",
          IMAGE, "python3", "-m", "containre.runtime.supervisor"])
    try:
        marker = work / ".containre-ready"
        for _ in range(80):
            if marker.exists():
                break
            time.sleep(0.25)
        assert marker.exists(), "supervisor never signalled ready"
        _run(["docker", "stop", "-t", "5", container])
        assert not marker.exists(), "marker should be cleared on graceful shutdown"
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def test_workload_only_fails_closed_without_ready_marker(tmp_path):
    work = tmp_path / "work"
    (work / "runs" / "r1").mkdir(parents=True)
    cjob = {
        "run_dir": "/work/runs/r1", "specimen_path": "/bin/true", "args": [],
        "env": {}, "cwd": "/work", "stdin_path": None,
        "policy": {
            "trace": {"tracer": "none"},
            "network": {"posture": "simulate"},
            "limits": {"wallclock_s": 30},
            "runtime": {"workload_only": True, "docker_reuse_supervised": True,
                        "docker_reuse_container": True,
                        "ca_path": "/work/.containre-ca.pem"},
        },
    }
    (work / "runs" / "r1" / "cjob.json").write_text(json.dumps(cjob))
    container = f"containre-test-fc-{os.getpid()}"
    proc = _run(["docker", "run", "--rm", "--name", container,
                 "-v", f"{work}:/work",
                 "-v", f"{REPO / 'containre'}:/opt/containre/containre:ro",
                 "-e", "PYTHONPATH=/opt/containre",
                 IMAGE, "python3", "-m", "containre.tracer.runner",
                 "/work/runs/r1/cjob.json"], check=False)
    assert proc.returncode == 3, f"expected fail-closed exit 3, got {proc.returncode}: {proc.stderr[-400:]}"
    meta = json.loads((work / "runs" / "r1" / "meta.json").read_text())
    assert meta.get("kill_reason") == "services_unavailable"
