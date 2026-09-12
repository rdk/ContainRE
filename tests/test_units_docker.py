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
    # A dedicated per-run container is stopped wholesale. Shared containers use
    # per-exec cancellation instead (covered in test_units_reuse.py).
    name = "containre-r2"
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


def test_non_string_device_entries_are_coerced_then_validated():
    # A YAML policy can yield non-strings; they must go through the same check.
    with pytest.raises(DockerError, match="docker_devices"):
        _rt()._device_args(_dev_policy([123]))


def test_duplicate_devices_are_passed_through_verbatim():
    # Docker tolerates a repeated --device; silently de-duplicating would hide a
    # policy mistake rather than surface it.
    with pytest.warns(DevicePassthroughWarning):
        args = _rt()._device_args(_dev_policy(["/dev/nvidia0", "/dev/nvidia0"]))
    assert args == ["--device", "/dev/nvidia0", "--device", "/dev/nvidia0"]


def test_devices_appear_in_both_fresh_and_reuse_launch_paths(monkeypatch, tmp_path):
    # The two docker command builders are separate code paths; a device set that
    # reached only one of them would work in tests and fail in production.
    from containre.interfaces import Job

    seen = []

    def _fake_ctl(argv, **kw):
        seen.append(list(argv))
        class R:
            returncode = 0
            stdout = "true containre.config-hash"
            stderr = ""
        return R()

    rt = _rt()
    monkeypatch.setattr(rt, "_run_ctl", _fake_ctl)
    monkeypatch.setattr("containre.runtime.docker.reuse.is_busy", lambda *a, **k: False)
    pol = {"runtime": {"docker_devices": ["/dev/nvidia0"], "docker_reuse_container": True},
           "trace": {"tracer": "none"}, "network": {"posture": "simulate", "docker_network": "none"},
           "files": {}, "limits": {}}
    (tmp_path / "runs").mkdir()
    job = Job(run_dir=tmp_path / "runs" / "r1", specimen_path="/bin/true", args=[], env={},
              cwd=str(tmp_path), stdin_path=None, policy=pol)
    with pytest.warns(DevicePassthroughWarning):
        rt._ensure_reuse_container(job, tmp_path, tmp_path, "containre-reuse-x", "hash")
    run_cmds = [c for c in seen if c[:3] == ["docker", "run", "-d"]]
    assert run_cmds, seen
    assert "--device" in run_cmds[0] and "/dev/nvidia0" in run_cmds[0]


def test_local_runtime_ignores_device_policy():
    # docker_* fields are Docker-only by name; LocalRuntime must not choke on one.
    from containre.runtime.local import LocalRuntime

    assert not hasattr(LocalRuntime(), "_device_args")
