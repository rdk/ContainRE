"""Unit tests for DockerRuntime pure argument-building logic (no daemon needed)."""
from __future__ import annotations

from pathlib import Path

import pytest

from containre.interfaces import RunHandle
from containre.runtime.docker import DockerError, DockerRuntime

pytestmark = pytest.mark.unit


def _rt():
    return DockerRuntime()


class _FakeProc:
    def __init__(self):
        self.terminated = False

    def poll(self):
        return None

    def terminate(self):
        self.terminated = True


def test_stop_reuse_container_terminates_exec_not_shared_container(monkeypatch):
    rt = _rt()
    killed = []
    monkeypatch.setattr("containre.runtime.docker.subprocess.run", lambda *a, **k: killed.append(a))
    fp = _FakeProc()
    rt._procs["/runs/r1"] = fp
    rt.stop(RunHandle(run_dir=Path("/runs/r1"), runtime="docker",
                      container="containre-reuse-default", pid=1))
    assert fp.terminated is True
    assert killed == []   # the shared reuse container must NOT be docker-killed


def test_stop_per_run_container_is_killed(monkeypatch):
    rt = _rt()
    calls = []
    monkeypatch.setattr("containre.runtime.docker.subprocess.run", lambda *a, **k: calls.append(a[0]))
    rt.stop(RunHandle(run_dir=Path("/runs/r2"), runtime="docker", container="containre-r2", pid=1))
    assert calls and list(calls[0][:2]) == ["docker", "kill"]


def test_deny_without_allowlist_is_fully_detached():
    assert _rt()._network_args({"network": {"posture": "deny", "allow": []}}) == ["--network", "none"]


def test_allowlist_with_active_tracer_attaches_bridge():
    args = _rt()._network_args({
        "network": {"posture": "deny", "allow": ["1.2.3.4:443"]},
        "trace": {"tracer": "ptrace"},
    })
    assert args == []  # bridge attached; ptrace enforces the narrow destination policy


def test_allowlist_with_tracer_none_is_rejected():
    # tracer=none => no egress enforcement, so attaching networking would give
    # unrestricted egress. Must be refused rather than silently unenforced.
    with pytest.raises(DockerError):
        _rt()._network_args({
            "network": {"posture": "deny", "allow": ["1.2.3.4:443"]},
            "trace": {"tracer": "none"},
        })


def test_host_network_with_tracer_none_is_rejected():
    with pytest.raises(DockerError):
        _rt()._network_args({
            "network": {"posture": "deny", "allow": ["1.2.3.4:443"], "docker_network": "host"},
            "trace": {"tracer": "none"},
        })


def test_host_network_warns_about_lost_isolation():
    from containre.runtime.docker import HostNetworkingWarning
    with pytest.warns(HostNetworkingWarning):
        args = _rt()._network_args({
            "network": {"posture": "deny", "allow": ["1.2.3.4:443"], "docker_network": "host"},
            "trace": {"tracer": "ptrace"},
        })
    assert args == ["--network", "host"]
