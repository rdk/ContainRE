"""Unit tests for run orchestration using fake runtimes."""
from __future__ import annotations

import json

import pytest

from containre import policy as P
from containre.control.orchestrator import default_runs_root, execute
from containre.interfaces import RunHandle

pytestmark = pytest.mark.unit


def test_localruntime_warns_about_missing_isolation(tmp_path, monkeypatch):
    from containre.interfaces import Job
    from containre.runtime import local as local_mod

    monkeypatch.setattr(local_mod, "configure_tls_plaintext", lambda job: None)
    monkeypatch.setattr(local_mod.subprocess, "Popen",
                        lambda *a, **k: type("P", (), {"pid": 4321})())
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    job = Job(run_dir=run_dir, specimen_path="/bin/true", args=[], env={},
              cwd=str(tmp_path), stdin_path=None, policy={})

    with pytest.warns(local_mod.LocalRuntimeIsolationWarning):
        local_mod.LocalRuntime().start(job)


def test_default_runs_root_honors_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTAINRE_RUNS_ROOT", str(tmp_path / "custom"))
    assert default_runs_root() == tmp_path / "custom"
    monkeypatch.delenv("CONTAINRE_RUNS_ROOT")
    assert default_runs_root().name == "runs"  # falls back to the home default


class TimeoutRuntime:
    name = "timeout"

    def __init__(self):
        self.stopped = False
        self.wait_timeout = None

    def start(self, job):
        self.job = job
        return RunHandle(run_dir=job.run_dir, runtime=self.name, pid=123)

    def wait(self, handle, timeout=None):
        self.wait_timeout = timeout
        return None

    def stop(self, handle):
        self.stopped = True


class EarlyExitRuntime:
    name = "early-exit"

    def start(self, job):
        self.job = job
        return RunHandle(run_dir=job.run_dir, runtime=self.name, pid=123)

    def wait(self, handle, timeout=None):
        return 125

    def stop(self, handle):
        raise AssertionError("stop should not be called after runtime exit")


def test_execute_marks_stale_running_run_error_when_runtime_wait_times_out(tmp_path):
    specimen = tmp_path / "sample.bin"
    specimen.write_bytes(b"\x7fELF-test")
    runtime = TimeoutRuntime()

    result = execute(P.policy_for_binary(specimen), runs_root=tmp_path / "runs",
                     runtime=runtime, timeout=0.01)

    assert runtime.stopped is True
    assert runtime.wait_timeout == 0.01
    assert result.status == "error"
    assert result.exit_code is None
    assert "runtime did not finish within 0.01s" == result.meta["error"]
    assert json.loads((result.run_dir / "meta.json").read_text())["status"] == "error"


def test_execute_marks_unfinalized_runtime_exit_error(tmp_path):
    specimen = tmp_path / "sample.bin"
    specimen.write_bytes(b"\x7fELF-test")

    result = execute(P.policy_for_binary(specimen), runs_root=tmp_path / "runs",
                     runtime=EarlyExitRuntime(), timeout=0.01)

    assert result.status == "error"
    assert result.exit_code == 125
    assert result.meta["error"] == "runtime exited before finalizing run"
    assert json.loads((result.run_dir / "meta.json").read_text())["status"] == "error"
