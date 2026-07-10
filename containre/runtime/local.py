"""LocalRuntime - run the tracer+specimen as a host subprocess.

DEV/TEST ONLY. This backend runs the specimen directly on the host (isolated only
by ptrace-level syscall interception and rlimits), which is *not* safe for real
malware. Use DockerRuntime for untrusted binaries. LocalRuntime exists so the
harness and its test suite can run anywhere, without a container build.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import warnings

from ..control.instrumentation import configure_tls_plaintext
from ..interfaces import Job, RunHandle


class LocalRuntimeIsolationWarning(UserWarning):
    """Raised when a specimen is launched under LocalRuntime, which provides no
    container/cgroup/network-namespace isolation."""


class LocalRuntime:
    name = "local"

    def __init__(self) -> None:
        self._procs: dict[str, subprocess.Popen] = {}

    def _preexec(self, job: Job):
        # LocalRuntime does NOT enforce cpu/mem/pids limits: RLIMIT_AS/NPROC would
        # constrain the Python tracer itself, and RLIMIT_NPROC is a per-*user* cap
        # (already exceeded on a normal desktop, so fork() would EAGAIN). Real
        # resource containment is DockerRuntime's job (cgroups). Here we only put
        # the specimen in its own session so we can kill the whole group cleanly.
        # Wall-clock timeouts are still enforced by the tracer watchdog.
        def apply() -> None:
            os.setsid()

        return apply

    def start(self, job: Job) -> RunHandle:
        # LocalRuntime is the default backend but runs the specimen directly on
        # the host with no container/cgroup/netns isolation - containment then
        # rests entirely on the (evadable) ptrace tracer. Make that loud so an
        # operator does not detonate real malware on the host unaware.
        warnings.warn(
            "LocalRuntime runs the specimen directly on the host with NO "
            "container/cgroup/network isolation - not safe for untrusted malware. "
            "Use the docker runtime (CONTAINRE_RUNTIME=docker / --runtime docker) "
            "for real specimens.",
            LocalRuntimeIsolationWarning,
            stacklevel=2,
        )
        configure_tls_plaintext(job)
        job_file = job.run_dir / "job.json"
        job_file.write_text(json.dumps(job.to_json()))
        proc = subprocess.Popen(
            [sys.executable, "-m", "containre.tracer.runner", str(job_file)],
            preexec_fn=self._preexec(job),
            stdout=subprocess.DEVNULL,
            stderr=open(job.run_dir / "runner.log", "wb"),
        )
        self._procs[str(job.run_dir)] = proc
        return RunHandle(run_dir=job.run_dir, runtime=self.name, pid=proc.pid)

    def wait(self, handle: RunHandle, timeout: float | None = None) -> int | None:
        proc = self._procs.get(str(handle.run_dir))
        if proc is None:
            return None
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self, handle: RunHandle) -> None:
        proc = self._procs.get(str(handle.run_dir))
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def checkpoint(self, handle: RunHandle, name: str = "checkpoint") -> dict:
        # CRIU can't cleanly dump a process under active host ptrace without a
        # containing tree; checkpoint is a DockerRuntime capability.
        return {"ok": False, "name": name,
                "reason": "checkpoint requires the docker runtime (CRIU dumps the container tree)"}

    def restore(self, handle: RunHandle, name: str = "checkpoint") -> dict:
        return {"ok": False, "name": name, "reason": "restore requires the docker runtime"}
