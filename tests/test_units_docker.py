"""Unit tests for DockerRuntime pure argument-building logic (no daemon needed)."""
from __future__ import annotations

import pytest

from containre.runtime.docker import DockerError, DockerRuntime

pytestmark = pytest.mark.unit


def _rt():
    return DockerRuntime()


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
