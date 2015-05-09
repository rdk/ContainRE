"""Unit tests for run orchestration using fake runtimes."""
from __future__ import annotations

import json

import pytest

from containre import policy as P
from containre.control.orchestrator import execute
from containre.interfaces import RunHandle

pytestmark = pytest.mark.unit


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
