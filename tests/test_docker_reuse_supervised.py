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
import threading
import time
from copy import deepcopy
from pathlib import Path

import pytest

from containre.interfaces import Job
from containre.runtime import DockerRuntime, docker_available
from containre.runtime import execution, reuse
from containre.runtime.docker import DockerError

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
    pgid = _wait_pgid(runs_root, run_id)
    token = _run(["docker", "exec", container, "python3", "-c",
                  f"from containre.runtime.execution import start_token; print(start_token({pgid}))"])
    run_dir = runs_root / run_id
    with execution.locked(run_dir):
        execution.write(run_dir, {
            "version": 1, "phase": "running", **reuse.container_identity(container),
            "pgid": pgid, "leader_start": token.stdout.strip(),
        })


def _wait_pgid(runs_root: Path, run_id: str) -> int:
    p = runs_root / run_id / "leader.pgid"
    for _ in range(80):
        if p.exists() and p.read_text().strip():
            return int(p.read_text().strip())
        time.sleep(0.1)
    raise AssertionError(f"pgid never recorded for {run_id}")


def _start_container(name: str, runs_root: Path) -> None:
    _run(["docker", "run", "-d", "--name", name,
          "-v", f"{runs_root}:/runs",
          "-v", f"{REPO / 'containre'}:/opt/containre/containre:ro",
          IMAGE, "sleep", "infinity"])


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


@pytest.mark.parametrize("replace", [False, True])
def test_old_container_generation_cannot_signal_new_peer(tmp_path, replace):
    runs_root = tmp_path / "runs"
    runs_root.mkdir()
    container = f"containre-test-generation-{os.getpid()}"
    _start_container(container, runs_root)
    try:
        _mk(runs_root, "old")
        reuse.mark(runs_root / "old", container)
        _launch_fake_workload(container, runs_root, "old")
        old = execution.read(runs_root / "old")
        if replace:
            _run(["docker", "rm", "-f", container])
            _start_container(container, runs_root)
        else:
            _run(["docker", "restart", "-t", "0", container])
        _mk(runs_root, "peer")
        reuse.mark(runs_root / "peer", container)
        _launch_fake_workload(container, runs_root, "peer")
        peer = execution.read(runs_root / "peer")
        # Deliberately collide the numeric process identity. The container's
        # immutable ID/start generation must reject this stale control first.
        old.update(pgid=peer["pgid"], leader_start=peer["leader_start"])
        with execution.locked(runs_root / "old"):
            execution.write(runs_root / "old", old)
        assert reuse.kill(runs_root, container, "old")
        assert reuse._pgid_alive(container, peer["pgid"])
        assert execution.read(runs_root / "old")["container_id"] == old["container_id"]
    finally:
        _run(["docker", "rm", "-f", container], check=False)


def test_cancel_pending_exec_prevents_delayed_workload_launch(tmp_path, monkeypatch):
    runs_root = tmp_path / "runs"
    work = tmp_path / "work"
    work.mkdir()
    key = f"test-delayed-launch-{os.getpid()}"
    container = f"containre-reuse-{key}"
    rt = DockerRuntime()
    job = Job(run_dir=_mk(runs_root, "pending"), specimen_path="/bin/sh",
              args=["-c", "touch /work/should-not-run"], env={"PATH": "/usr/bin:/bin"},
              cwd=str(work), policy={
                  "specimen": {"container_path": "/bin/sh"}, "trace": {"tracer": "none"},
                  "network": {"posture": "deny", "docker_network": "none"},
                  "runtime": {"docker_reuse_container": True, "docker_reuse_key": key},
              })
    entered, proceed = threading.Event(), threading.Event()
    original = subprocess.Popen
    outcome = []

    def delayed(cmd, *a, **kw):
        if "containre.tracer.runner" in cmd:
            entered.set()
            assert proceed.wait(10)
        return original(cmd, *a, **kw)

    def start():
        try:
            outcome.append(rt.start(job))
        except BaseException as exc:
            outcome.append(exc)

    monkeypatch.setattr(subprocess, "Popen", delayed)
    thread = threading.Thread(target=start)
    thread.start()
    try:
        assert entered.wait(10)
        assert reuse.kill(runs_root, container, "pending")
        proceed.set()
        thread.join(10)
        assert len(outcome) == 1 and not isinstance(outcome[0], BaseException), outcome
        rt.wait(outcome[0], timeout=10)
        assert not (work / "should-not-run").exists()
        assert execution.read(job.run_dir)["phase"] == "stopped"
    finally:
        proceed.set()
        thread.join(10)
        _run(["docker", "rm", "-f", container], check=False)


def test_runtime_repeated_stop_and_wait_leave_peer_alive(tmp_path):
    runs_root = tmp_path / "runs"
    work = tmp_path / "work"
    work.mkdir()
    key = f"test-runtime-stop-{os.getpid()}"
    container = f"containre-reuse-{key}"
    rt = DockerRuntime()
    handles = []
    policy = {
        "specimen": {"container_path": "/bin/sh"},
        "trace": {"tracer": "none"},
        "network": {"posture": "deny", "docker_network": "none"},
        "limits": {"wallclock_s": 60},
        "runtime": {"docker_reuse_container": True, "docker_reuse_key": key},
    }
    try:
        for run_id in ("peer", "target"):
            handle = rt.start(Job(
                run_dir=_mk(runs_root, run_id), specimen_path="/bin/sh",
                args=["-c", "sleep 600"], env={"PATH": "/usr/bin:/bin"},
                cwd=str(work), policy=deepcopy(policy),
            ))
            handles.append(handle)
            assert handle.reuse_exec
        peer, target = handles
        peer_pgid = _wait_pgid(runs_root, "peer")
        target_pgid = _wait_pgid(runs_root, "target")

        rt.stop(target)
        rt.stop(target)
        assert rt.wait(target, timeout=10) is not None
        rt.stop(target)  # a late cancellation after the wait also stays per-exec

        assert not reuse._pgid_alive(container, target_pgid)
        assert reuse._pgid_alive(container, peer_pgid)
        assert {e["run_id"] for e in reuse.list_live(runs_root, container)} == {"peer"}
        assert not (target.run_dir / reuse.MARKER_FILE).exists()
    finally:
        # Removing the test's container also terminates workloads if an assertion
        # above failed, and wait reaps the local Docker client processes.
        _run(["docker", "rm", "-f", container], check=False)
        for handle in handles:
            rt.wait(handle, timeout=10)


def test_service_config_change_refuses_busy_then_recreates_when_idle(tmp_path):
    runs_root = tmp_path / "runs"
    work = tmp_path / "work"
    work.mkdir()
    run_dir = _mk(runs_root, "busy")
    container = f"containre-test-config-{os.getpid()}"
    rt = DockerRuntime()
    before = Job(run_dir=run_dir, specimen_path="/bin/true", cwd=str(work), policy={
        "trace": {"tracer": "none"},
        "network": {"posture": "simulate", "docker_network": "none",
                    "sink": {"listen_port": 0}},
        "runtime": {
            "docker_reuse_container": True, "docker_reuse_supervised": True,
            "supervisor_env": {"SERVICE_MODE": "first"},
            "setup_commands": ['printf "%s" "$SERVICE_MODE" > /work/service-mode'],
            "ready_probe": "test -s /work/service-mode", "ready_timeout_s": 20,
        },
    })
    after = deepcopy(before)
    after.policy["runtime"]["supervisor_env"]["SERVICE_MODE"] = "second"

    def ensure(job):
        config_hash = rt._reuse_config_hash(job, work, work)
        rt._ensure_reuse_container(job, work, work, container, config_hash)
        rt._wait_supervised_ready(work, job.policy, poll_s=0.1)

    try:
        ensure(before)
        assert (work / "service-mode").read_text() == "first"
        reuse.mark(run_dir, container)
        _launch_fake_workload(container, runs_root, "busy")
        pgid = _wait_pgid(runs_root, "busy")

        with pytest.raises(DockerError, match="live exec"):
            ensure(after)
        assert reuse._pgid_alive(container, pgid)
        assert (work / "service-mode").read_text() == "first"

        assert reuse.kill(runs_root, container, "busy")
        ensure(after)
        assert (work / "service-mode").read_text() == "second"
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
        _mk(runs_root, "live")
        reuse.mark(runs_root / "live", container)
        reuse.mark_owner(runs_root / "live", os.getpid(), reuse.proc_start_token(os.getpid()))
        _launch_fake_workload(container, runs_root, "live")
        dead = subprocess.Popen(["sleep", "0.05"])
        dpid = dead.pid
        dead.wait()
        _mk(runs_root, "orph")
        reuse.mark(runs_root / "orph", container)
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
