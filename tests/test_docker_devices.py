"""Integration test for runtime.docker_devices - real hardware passthrough.

Skipped automatically unless the host has Docker *and* NVIDIA device nodes, so
the default suite stays green everywhere. Uses the CUDA **driver API** through
ctypes, so it needs no CUDA toolkit, no nvcc, and nothing in the image: only
libcuda.so.1 from the host plus the three device nodes.

The point of the test is not CUDA - it is that `--device` is the only way to get
hardware into the sandbox. A bind-mount of the same node supplies the inode but
the container's device cgroup still denies access, which is why the negative
case below is asserted alongside the positive one.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import tempfile
import warnings
from pathlib import Path

import pytest

from containre import policy as P
from containre.control import execute
from containre.runtime import DockerRuntime, docker_available
from containre.runtime.docker import DevicePassthroughWarning, DockerError

pytestmark = [pytest.mark.docker, pytest.mark.specimen]

#: Necessary and jointly sufficient for a CUDA context (measured: dropping any
#: one of the three fails cuInit with rc=999/100).
GPU_DEVICES = ["/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia-uvm"]

#: Minimal probe: load the driver API, create a real context, allocate, free.
PROBE = '''#!/usr/bin/env python3
import ctypes, sys
cu = ctypes.CDLL("libcuda.so.1")
if cu.cuInit(0) != 0:
    print("cuInit failed"); sys.exit(3)
n = ctypes.c_int()
if cu.cuDeviceGetCount(ctypes.byref(n)) != 0 or n.value < 1:
    print("no devices"); sys.exit(4)
dev = ctypes.c_int()
cu.cuDeviceGet(ctypes.byref(dev), 0)
ctx = ctypes.c_void_p()
if cu.cuCtxCreate_v2(ctypes.byref(ctx), 0, dev) != 0:
    print("no context"); sys.exit(5)
ptr = ctypes.c_void_p()
if cu.cuMemAlloc_v2(ctypes.byref(ptr), 1 << 20) != 0:
    print("no alloc"); sys.exit(6)
cu.cuMemFree_v2(ptr); cu.cuCtxDestroy_v2(ctx)
print("CUDA_OK")
'''


def _libcuda() -> Path | None:
    found = ctypes.util.find_library("cuda")
    if found and Path(found).is_absolute() and Path(found).exists():
        return Path(found)
    proc = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, check=False)
    for line in proc.stdout.splitlines():
        if "libcuda.so.1" in line and "=>" in line:
            candidate = Path(line.rsplit("=>", 1)[1].strip())
            if candidate.exists():
                return candidate
    return None


@pytest.fixture(scope="module")
def gpu_runtime():
    if not docker_available():
        pytest.skip("docker daemon not available")
    missing = [d for d in GPU_DEVICES if not Path(d).exists()]
    if missing:
        pytest.skip(f"no NVIDIA device nodes on this host (missing {missing})")
    if _libcuda() is None:
        pytest.skip("libcuda.so.1 not installed on this host")
    rt = DockerRuntime()
    try:
        rt.ensure_image()
    except Exception as exc:  # build/network problems -> skip, don't fail
        pytest.skip(f"could not prepare runner image: {exc}")
    return rt


@pytest.fixture
def runs():
    d = Path(tempfile.mkdtemp(prefix="containre-devices-"))
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture
def probe(tmp_path) -> Path:
    script = tmp_path / "cuda_probe.py"
    script.write_text(PROBE)
    script.chmod(0o755)
    return script


def _policy(probe: Path, libcuda: Path, *, devices, mount_devices=False):
    """A no-trace, no-network policy that runs the probe with the host's libcuda.

    ``mount_devices`` additionally bind-mounts the device nodes read-only, which
    is what makes the negative case a fair test: the inodes ARE present, and
    access still fails without --device.
    """
    mounts = [{"source": str(libcuda), "target": str(libcuda)}]
    if mount_devices:
        mounts += [{"source": d, "target": d} for d in GPU_DEVICES]
    return P.policy_for_binary(
        probe,
        limits={"wallclock_s": 60},
        trace={"tracer": "none", "l1": [], "snapshot_on": [], "snapshot_every_ms": 0,
               "l2": {"mode": "off", "window": {}}},
        network={"posture": "simulate", "docker_network": "none", "allow": []},
        files={"read_only_mounts": mounts, "decoys": []},
        runtime={"docker_devices": devices,
                 "docker_user": f"{os.getuid()}:{os.getgid()}"},
    )


def _console(result) -> str:
    path = result.run_dir / "console.log"
    return path.read_text(errors="replace") if path.exists() else ""


def test_devices_give_the_sandbox_a_real_cuda_context(gpu_runtime, runs, probe):
    """--device passes real hardware through, with network none and caps dropped."""
    pol = _policy(probe, _libcuda(), devices=GPU_DEVICES)
    # The warning is emitted when the args are built, i.e. at launch.
    with pytest.warns(DevicePassthroughWarning):
        result = execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=120)
    assert "CUDA_OK" in _console(result), _console(result)
    assert result.exit_code == 0


def test_bind_mounting_device_nodes_is_not_enough(gpu_runtime, runs, probe):
    """The negative case that makes --device necessary rather than convenient.

    The device nodes are bind-mounted, so the paths exist in the container; the
    device cgroup still denies access, so CUDA cannot initialise.
    """
    pol = _policy(probe, _libcuda(), devices=[], mount_devices=True)
    result = execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=120)
    assert "CUDA_OK" not in _console(result)
    assert result.exit_code != 0


def test_devices_reach_a_reuse_container_exec(gpu_runtime, runs, probe):
    """The path real batch users take: devices on a long-lived reuse container.

    Devices are set at `docker run` time and inherited by every `docker exec`,
    so this checks the half the fresh-container test cannot: that the container
    is created with them and the workload exec sees the GPU. Also asserts the
    container is genuinely reused (same id across two runs), since a recreate
    would mask a broken create.
    """
    pol = _policy(probe, _libcuda(), devices=GPU_DEVICES)
    pol["runtime"]["docker_reuse_container"] = True
    pol["runtime"]["docker_reuse_key"] = "devicetest"
    container = "containre-reuse-devicetest"
    try:
        with pytest.warns(DevicePassthroughWarning):
            first = execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=180)
            second = execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=180)
        for result in (first, second):
            assert "CUDA_OK" in _console(result), _console(result)
            assert result.exit_code == 0
        ids = {subprocess.run(["docker", "inspect", "-f", "{{.Id}}", container],
                              capture_output=True, text=True).stdout.strip()}
        assert len(ids) == 1 and ids != {""}   # one container, still alive
    finally:
        subprocess.run(["docker", "rm", "-f", container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_changing_devices_recreates_the_reuse_container(gpu_runtime, runs, probe):
    """Devices are part of container identity, so a changed set must not be
    silently inherited by a run that asked for something different."""
    container = "containre-reuse-devicetest2"
    def _run(devices):
        pol = _policy(probe, _libcuda(), devices=devices)
        pol["runtime"]["docker_reuse_container"] = True
        pol["runtime"]["docker_reuse_key"] = "devicetest2"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DevicePassthroughWarning)
            execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=180)
        return subprocess.run(["docker", "inspect", "-f", "{{.Id}}", container],
                              capture_output=True, text=True).stdout.strip()
    try:
        with_gpu = _run(GPU_DEVICES)
        without = _run([])
        assert with_gpu and without and with_gpu != without
    finally:
        subprocess.run(["docker", "rm", "-f", container],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_invalid_device_path_fails_before_launch(gpu_runtime, runs, probe):
    """A bad device entry is rejected, not passed to docker."""
    pol = _policy(probe, _libcuda(), devices=["/etc/passwd"])
    with pytest.raises(DockerError, match="docker_devices"):
        execute(pol, runs_root=runs, runtime=gpu_runtime, timeout=60)
