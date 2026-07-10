"""Unit tests for DockerRuntime pure argument-building logic (no daemon needed)."""
from __future__ import annotations

from pathlib import Path

import pytest

from containre.interfaces import RunHandle
from containre.runtime.docker import DockerError, DockerRuntime

pytestmark = pytest.mark.unit


def _rt():
    return DockerRuntime()


def test_stop_kills_the_container_to_actually_stop_the_specimen(monkeypatch):
    # For both per-run and shared reuse containers, stop() must docker-kill the
    # container: reliably stopping the specimen is the safety-critical property.
    for name in ("containre-r2", "containre-reuse-default"):
        calls = []
        monkeypatch.setattr("containre.runtime.docker.subprocess.run",
                            lambda *a, **k: calls.append(a[0]))
        _rt().stop(RunHandle(run_dir=Path("/runs/x"), runtime="docker", container=name, pid=1))
        assert calls and list(calls[0][:3]) == ["docker", "kill", name]


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
