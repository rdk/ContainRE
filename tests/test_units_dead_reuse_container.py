"""A reuse container that is dead, or dies during bring-up, must fail the run
promptly with the cause, never leave it waiting on a readiness marker that can
no longer appear. No Docker daemon: container state and logs are faked.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

import pytest
from typer.testing import CliRunner

from containre import policy as P
from containre.cli import main as cli
from containre.control import execute
from containre.interfaces import Job
from containre.runtime import docker as dockermod
from containre.runtime import execution, reuse
from containre.runtime.docker import DockerError, DockerRuntime, ReuseContainerDied

pytestmark = pytest.mark.unit

EXITED = {"Status": "exited", "Running": False, "ExitCode": 1,
          "FinishedAt": "2026-09-27T21:34:59Z", "Error": ""}


def _policy(**runtime):
    return {"runtime": {"ready_timeout_s": 600, **runtime}}


def _fake_logs(rt, monkeypatch, text="[reuse-supervisor] setup command failed (rc=1)"):
    monkeypatch.setattr(rt, "_container_log_tail", lambda c: text)


# -- _wait_supervised_ready ---------------------------------------------------

def test_exited_container_fails_the_wait_at_once_with_exit_code_and_logs(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_container_state", lambda c: dict(EXITED))
    _fake_logs(rt, monkeypatch)
    (tmp_path / "setup.log").write_text(
        "setup: libc.so.6: version `GLIBC_ABI_DT_X86_64_PLT' not found (required by /libresolv.so.2)\n")
    policy = _policy(ready_diagnostics=["/work/setup.log", "/work/missing.log",
                                        "/etc/passwd", "/work/../../etc/passwd"])
    started = time.monotonic()
    with pytest.raises(ReuseContainerDied) as info:
        rt._wait_supervised_ready(tmp_path, policy, poll_s=0.05, container="abc123",
                                  name="containre-reuse-prod")
    assert time.monotonic() - started < 2.0          # not the 600 s ready timeout
    err = info.value
    assert err.exit_code == 1 and err.container == "containre-reuse-prod"
    msg = str(err)
    assert "containre-reuse-prod exited before becoming ready (exit code 1" in msg
    assert "setup command failed (rc=1)" in msg      # container log tail
    assert "GLIBC_ABI_DT_X86_64_PLT" in msg          # diagnostic file tail
    assert "/work/setup.log" in msg
    assert "root:" not in msg                        # paths outside /work are ignored
    assert isinstance(err, DockerError)              # existing callers still catch it


def test_vanished_container_fails_the_wait(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_container_state", lambda c: {})
    with pytest.raises(ReuseContainerDied, match="no longer exists"):
        rt._wait_supervised_ready(tmp_path, _policy(), poll_s=0.05, container="abc123")


def test_unreadable_state_is_not_death_and_still_times_out(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_container_state", lambda c: None)   # daemon hiccup
    _fake_logs(rt, monkeypatch, "still starting")
    with pytest.raises(DockerError, match="not ready within 0.3s") as info:
        rt._wait_supervised_ready(tmp_path, _policy(ready_timeout_s=0.3), poll_s=0.05,
                                  container="abc123")
    assert not isinstance(info.value, ReuseContainerDied)
    assert "still starting" in str(info.value)


def test_running_container_waits_for_the_marker(tmp_path, monkeypatch):
    rt = DockerRuntime()
    calls = []

    def state(c):
        calls.append(c)
        if len(calls) == 3:
            (tmp_path / ".containre-ready").write_text("gen")
        return {"Running": True, "Status": "running"}

    monkeypatch.setattr(rt, "_container_state", state)
    rt._wait_supervised_ready(tmp_path, _policy(), poll_s=0.01, container="abc", generation="gen")
    assert len(calls) == 3


def test_cancelled_run_stops_waiting(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_container_state", lambda c: {"Running": True})
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    with execution.locked(run_dir):
        execution.write(run_dir, {"version": 1, "phase": "stopped", "container_name": "c"})
    with pytest.raises(DockerError, match="cancelled"):
        rt._wait_supervised_ready(tmp_path, _policy(), poll_s=0.05, container="abc",
                                  run_dir=run_dir)


def test_container_state_distinguishes_absent_from_unknown(monkeypatch):
    rt = DockerRuntime()

    def fake(rc, out="", err=""):
        return lambda argv, **kw: subprocess.CompletedProcess(argv, rc, out, err)

    monkeypatch.setattr(rt, "_run_ctl", fake(0, json.dumps(EXITED)))
    assert rt._container_state("c")["ExitCode"] == 1
    monkeypatch.setattr(rt, "_run_ctl", fake(1, err="Error: No such object: c"))
    assert rt._container_state("c") == {}
    monkeypatch.setattr(rt, "_run_ctl", fake(1, err="Cannot connect to the Docker daemon"))
    assert rt._container_state("c") is None


# -- _ensure_reuse_container: a stopped container is recreated, not restarted --

def _job(tmp_path):
    policy = {
        "specimen": {"path": "/work/x", "container_path": "/work/x"},
        "trace": {"tracer": "none"},
        "network": {"posture": "simulate", "docker_network": "none"},
        "files": {}, "limits": {},
        "runtime": {"docker_reuse_container": True, "docker_reuse_supervised": True,
                    "workload_only": True, "docker_reuse_key": "prod"},
    }
    return Job(run_dir=Path(tmp_path) / "runs" / "r1", specimen_path="/work/x",
               args=[], env={}, cwd=str(tmp_path), policy=policy)


def test_stopped_reuse_container_is_removed_and_recreated(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_inspect_reuse_container", lambda n: (True, False, "HASH"))
    monkeypatch.setattr(dockermod.reuse, "is_busy",
                        lambda *a: pytest.fail("a stopped container has no live execs"))
    calls = []
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda argv, **k: calls.append(argv)
                        or subprocess.CompletedProcess(argv, 0, "id", ""))
    (tmp_path / ".containre-ready").write_text("stale")
    rt._ensure_reuse_container(_job(tmp_path), tmp_path, tmp_path, "containre-reuse-prod", "HASH")
    verbs = [c[1] for c in calls]
    assert verbs == ["rm", "run"], calls
    assert "start" not in verbs
    assert not (tmp_path / ".containre-ready").exists()


def test_running_matching_container_is_reused_untouched(tmp_path, monkeypatch):
    rt = DockerRuntime()
    monkeypatch.setattr(rt, "_inspect_reuse_container", lambda n: (True, True, "HASH"))
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail("no docker call for a healthy container"))
    rt._ensure_reuse_container(_job(tmp_path), tmp_path, tmp_path, "containre-reuse-prod", "HASH")


# -- _start_reused: failure retires the registration --------------------------

def _prepare_start(tmp_path, monkeypatch, rt):
    job = _job(tmp_path / "work")
    Path(job.cwd).mkdir(parents=True)
    job.run_dir.mkdir(parents=True)
    with execution.locked(job.run_dir):
        execution.write(job.run_dir, {"version": 1, "phase": "reserved",
                                      "container_name": "containre-reuse-prod"})
    monkeypatch.setattr(reuse, "lifecycle", _nolock)
    monkeypatch.setattr(rt, "_ensure_reuse_container", lambda *a: None)
    monkeypatch.setattr(dockermod.subprocess, "Popen",
                        lambda *a, **k: pytest.fail("workload must not launch"))
    _fake_logs(rt, monkeypatch)
    return job


class _nolock:
    def __init__(self, name):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_container_dying_during_bring_up_fails_start_and_retires_the_run(tmp_path, monkeypatch):
    rt = DockerRuntime()
    job = _prepare_start(tmp_path, monkeypatch, rt)
    monkeypatch.setattr(reuse, "container_identity", lambda name: {
        "container_id": "a" * 64, "container_name": name, "image_id": "sha256:x",
        "started_at": "t", "init_start": "1", "boot_id": "b"})
    monkeypatch.setattr(rt, "_container_state", lambda c: dict(EXITED))
    started = time.monotonic()
    with pytest.raises(ReuseContainerDied, match="exit code 1"):
        rt._start_reused(job)
    assert time.monotonic() - started < 5.0
    assert execution.read(job.run_dir)["phase"] == "stopped"
    assert not (job.run_dir / reuse.MARKER_FILE).exists()
    assert reuse.list_live(job.run_dir.parent, "containre-reuse-prod") == []


def test_container_already_dead_at_identity_is_reported_with_cause(tmp_path, monkeypatch):
    rt = DockerRuntime()
    job = _prepare_start(tmp_path, monkeypatch, rt)

    def identity(name):
        raise RuntimeError("reuse container is not running")

    monkeypatch.setattr(reuse, "container_identity", identity)
    monkeypatch.setattr(rt, "_container_state", lambda c: dict(EXITED))
    with pytest.raises(ReuseContainerDied, match="exited right after start"):
        rt._start_reused(job)


# -- orchestrator + CLI surface the failure -----------------------------------

class _DeadStartRuntime:
    name = "docker"
    image = "img"

    def start(self, job):
        raise ReuseContainerDied("reuse container containre-reuse-x exited before becoming "
                                 "ready (exit code 1)", container="containre-reuse-x",
                                 exit_code=1)

    def wait(self, handle, timeout=None):
        raise AssertionError("never launched")

    def stop(self, handle):
        raise AssertionError("never launched")


def test_execute_records_start_failure_as_terminal_error(tmp_path):
    specimen = tmp_path / "sample.bin"
    specimen.write_bytes(b"\x7fELF-test")
    runs = tmp_path / "runs"
    with pytest.raises(ReuseContainerDied):
        execute(P.policy_for_binary(specimen), runs_root=runs, runtime=_DeadStartRuntime(),
                run_id="r1")
    meta = json.loads((runs / "r1" / "meta.json").read_text())
    assert meta["status"] == "error"
    assert "exit code 1" in meta["error"]
    assert meta["stopped_wall"]


def test_cli_reports_start_failure_as_json_and_nonzero(tmp_path, monkeypatch):
    specimen = tmp_path / "sample.bin"
    specimen.write_bytes(b"\x7fELF-test")
    monkeypatch.setattr(cli, "get_runtime", lambda name: _DeadStartRuntime())
    result = CliRunner().invoke(cli.app, ["run", str(specimen), "--runs-root",
                                          str(tmp_path / "runs"), "--json", "--run-id", "r1"])
    assert result.exit_code == 1
    payload = json.loads(result.stdout)
    assert payload["status"] == "error" and payload["run_id"] == "r1"
    assert payload["error_type"] == "ReuseContainerDied"
    assert "exit code 1" in payload["error"]
    assert "Traceback" not in result.output
