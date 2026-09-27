"""Docker-backed: a supervised reuse container whose bring-up fails (a setup
command exits 1, so the supervisor exits 1 within a second) must fail the run
promptly with the exit code and the cause, and the next run must recreate the
container instead of restarting the dead one.

Uses its own container name (``containre-test-deadreuse-<pid>``), never a
``containre-reuse-*`` name, so it cannot touch a real node's reuse containers.
"""
from __future__ import annotations

import json
import os
import subprocess
import time

import pytest

from containre.control import execute
from containre.runtime import DockerRuntime, docker_available, execution
from containre.runtime.docker import ReuseContainerDied

pytestmark = [pytest.mark.docker, pytest.mark.specimen]


class _TestRuntime(DockerRuntime):
    def __init__(self, name: str):
        super().__init__()
        self._test_name = name

    def _reuse_container_name(self, policy: dict) -> str:
        return self._test_name


@pytest.fixture(autouse=True)
def _require_docker():
    if not docker_available():
        pytest.skip("docker daemon not available")
    if not DockerRuntime().image_present():
        pytest.skip("containre/runner:0.1 not built; run the docker specimen tests first")


def _inspect(name: str) -> dict:
    proc = subprocess.run(["docker", "inspect", "--format", "{{json .}}", name],
                          capture_output=True, text=True)
    return json.loads(proc.stdout) if proc.returncode == 0 else {}


def _policy(tmp_path, work):
    specimen = tmp_path / "workload.sh"
    specimen.write_text("#!/bin/sh\ntouch /work/workload-ran\n")
    specimen.chmod(0o755)
    return {
        "specimen": {"path": str(specimen), "container_path": "/specimen-src/workload.sh",
                     "args": [], "env": {}},
        "trace": {"tracer": "none"},
        "network": {"posture": "simulate", "docker_network": "none",
                    "sink": {"listen_port": 0}},
        "files": {"work_mount": str(work)},
        "limits": {"wallclock_s": 30},
        "runtime": {
            "docker_reuse_container": True, "docker_reuse_supervised": True,
            "workload_only": True, "docker_reuse_key": "deadtest",
            "docker_user": f"{os.getuid()}:{os.getgid()}",
            "command_shell": "/bin/sh",
            "setup_commands": [
                "echo \"setup: version 'GLIBC_ABI_DT_X86_64_PLT' not found\" > /work/start.log; exit 1"
            ],
            "ready_diagnostics": ["/work/start.log"],
            "ready_timeout_s": 300,
        },
    }


def test_reuse_container_that_exits_at_start_fails_fast_then_is_recreated(tmp_path):
    name = f"containre-test-deadreuse-{os.getpid()}"
    runs = tmp_path / "runs"
    work = tmp_path / "work"
    work.mkdir()
    rt = _TestRuntime(name)
    policy = _policy(tmp_path, work)
    try:
        started = time.monotonic()
        with pytest.raises(ReuseContainerDied) as info:
            execute(policy, runs_root=runs, runtime=rt, run_id="first")
        elapsed = time.monotonic() - started
        assert elapsed < 60, f"took {elapsed:.1f}s; must not wait out ready_timeout_s"
        msg = str(info.value)
        assert info.value.exit_code == 1, msg
        assert "exit code 1" in msg
        assert "setup command failed" in msg              # supervisor's own log line
        assert "GLIBC_ABI_DT_X86_64_PLT" in msg           # /work/start.log tail
        assert not (work / "workload-ran").exists()

        meta = json.loads((runs / "first" / "meta.json").read_text())
        assert meta["status"] == "error" and "exit code 1" in meta["error"]
        assert execution.read(runs / "first")["phase"] == "stopped"

        first = _inspect(name)
        assert first and first["State"]["Running"] is False
        assert first["State"]["ExitCode"] == 1

        with pytest.raises(ReuseContainerDied):
            execute(policy, runs_root=runs, runtime=rt, run_id="second")
        second = _inspect(name)
        assert second and second["Id"] != first["Id"], "dead container was restarted, not recreated"
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
