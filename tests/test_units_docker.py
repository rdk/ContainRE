"""Unit tests for DockerRuntime pure argument-building logic (no daemon needed)."""
from __future__ import annotations

from pathlib import Path

import pytest

from containre.interfaces import RunHandle
from containre.runtime.docker import DevicePassthroughWarning, DockerError, DockerRuntime

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


# -- device passthrough (runtime.docker_devices) -------------------------------

_GPU_DEVICES = ["/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia-uvm"]


def _dev_policy(devices):
    return {"runtime": {"docker_devices": devices}}


def test_no_devices_by_default():
    # A sandbox exposes no host hardware unless a policy asks for it.
    assert _rt()._device_args({}) == []
    assert _rt()._device_args({"runtime": {}}) == []
    assert _rt()._device_args(_dev_policy([])) == []


def test_devices_become_device_flags():
    with pytest.warns(DevicePassthroughWarning):
        args = _rt()._device_args(_dev_policy(_GPU_DEVICES))
    assert args == ["--device", "/dev/nvidiactl",
                    "--device", "/dev/nvidia0",
                    "--device", "/dev/nvidia-uvm"]


def test_device_passthrough_warns_that_it_reduces_isolation():
    # Mirrors the docker_network=host precedent: honoured, but never silent.
    with pytest.warns(DevicePassthroughWarning, match="tracer cannot observe"):
        _rt()._device_args(_dev_policy(["/dev/nvidia0"]))


@pytest.mark.parametrize("bad", [
    "/etc/passwd",              # outside /dev
    "/dev/../etc/passwd",       # traversal
    "/dev/nvidia0:/dev/x:rwm",  # host:container:perms remapping is not supported
    "relative",
    "/dev/",
    "",
])
def test_invalid_device_paths_are_rejected(bad):
    with pytest.raises(DockerError, match="docker_devices"):
        _rt()._device_args(_dev_policy([bad]))


def test_nested_dev_path_is_allowed():
    with pytest.warns(DevicePassthroughWarning):
        assert _rt()._device_args(_dev_policy(["/dev/nvidia-caps/nvidia-cap1"])) == [
            "--device", "/dev/nvidia-caps/nvidia-cap1"]


def test_devices_are_part_of_the_reuse_container_identity(tmp_path):
    # Devices are fixed at container creation, so a GPU-bearing container must
    # never be silently reused for a run that asked for none (or vice versa).
    from containre.interfaces import Job

    def _hash(devices):
        pol = {"runtime": {"docker_reuse_container": True, "docker_devices": devices},
               "trace": {"tracer": "none"}, "network": {"posture": "simulate"}}
        job = Job(run_dir=tmp_path / "runs" / "r1", specimen_path="/bin/true", args=[],
                  env={}, cwd=str(tmp_path), stdin_path=None, policy=pol)
        return _rt()._reuse_config_hash(job, tmp_path, tmp_path)

    with pytest.warns(DevicePassthroughWarning):
        gpu = _hash(_GPU_DEVICES)
        partial = _hash(["/dev/nvidia0"])
    plain = _hash([])
    assert gpu != plain
    assert gpu != partial
