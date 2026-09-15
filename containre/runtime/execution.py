"""Durable identity and a launch/cancel fence for one reused execution.

This module also runs inside the container and deliberately uses only stdlib.
The record survives cleanup as provenance. Locks and cancelled launch tombstones
must survive retries; never unlink them while the runs root is in use.
"""
from __future__ import annotations

import ctypes
import fcntl
import json
import os
import re
import signal
import sys
import time
from contextlib import contextmanager
from pathlib import Path

RECORD = "execution.json"
PIDFD_SIGNAL_PROCESS_GROUP = 4


def _libc_call(name: str, types: list, *args) -> int:
    # Some standalone CPython builds omit the Linux pidfd wrappers even on a
    # capable host. Use libc's typed wrappers, never architecture-specific
    # syscall numbers. Missing libc support fails the prelaunch probe.
    library = ctypes.CDLL(None, use_errno=True)
    function = getattr(library, name)
    function.argtypes = types
    function.restype = ctypes.c_int
    result = function(*args)
    if result == -1:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return result


def _pidfd_open(pid: int) -> int:
    if hasattr(os, "pidfd_open"):
        return os.pidfd_open(pid)
    return _libc_call("pidfd_open", [ctypes.c_int, ctypes.c_uint], pid, 0)


def _group_signal(fd: int, sig: int) -> None:
    if hasattr(signal, "pidfd_send_signal"):
        signal.pidfd_send_signal(fd, sig, None, PIDFD_SIGNAL_PROCESS_GROUP)
    else:
        _libc_call("pidfd_send_signal",
                   [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint],
                   fd, sig, None, PIDFD_SIGNAL_PROCESS_GROUP)


@contextmanager
def locked(run_dir: Path):
    # Beside run directories: cancellation can fence a launch before its
    # directory exists. Host and container use the same bind-mounted inode.
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", run_dir.name):
        raise ValueError("invalid run id")
    locks = run_dir.parent / ".execution-locks"
    locks.mkdir(parents=True, exist_ok=True)
    with (locks / run_dir.name).open("a") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream, fcntl.LOCK_UN)


def read(run_dir: Path) -> dict:
    value = json.loads((run_dir / RECORD).read_text())
    if not isinstance(value, dict) or value.get("version") != 1:
        raise ValueError("unsupported execution record")
    if value.get("phase") not in {"reserved", "pending", "launching", "running", "stopped"}:
        raise ValueError("invalid execution phase")
    return value


def write(run_dir: Path, value: dict) -> None:
    # Caller holds locked(). fsync ensures the launch intent precedes Popen.
    tmp = run_dir / (RECORD + ".tmp")
    with tmp.open("w") as stream:
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, run_dir / RECORD)
    fd = os.open(run_dir, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def start_token(pid: int) -> str:
    stat = Path(f"/proc/{pid}/stat").read_text()
    fields = stat[stat.rfind(")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("unreadable process identity")
    return fields[19]


def group_members(pgid: int) -> list[int]:
    members = []
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            stat = path.read_text()
        except FileNotFoundError:
            continue
        fields = stat[stat.rfind(")") + 2:].split()
        if len(fields) < 3:
            raise ValueError("unreadable process group")
        if fields[0] != "Z" and fields[2] == str(pgid):
            members.append(int(path.parent.name))
    return members


def require_group_signals() -> None:
    """Check the actual kernel capability before starting any workload.

    PIDFD_SIGNAL_PROCESS_GROUP is available since Linux 6.9. Numeric killpg
    after a host-side identity check would reintroduce the PID reuse race.
    See linux man-pages pidfd_send_signal(2).
    """
    fd = _pidfd_open(os.getpid())
    try:
        try:
            _group_signal(fd, 0)
        except ProcessLookupError:
            pass  # our PID need not be a group leader; the flag was accepted
    finally:
        os.close(fd)


def control(record: dict, *, stop: bool = False, grace_s: float = 5.0) -> str:
    """Inside the recorded container: return gone, alive or unknown.

    A retained zombie leader still anchors surviving children. If the leader
    was reaped while children survive, identity cannot be reconstructed: retain
    tracking. A different leader start token proves the old group was drained
    before its number was reused, and never authorizes signalling the new one.
    """
    fd = None
    try:
        boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if boot_id != record["boot_id"] or start_token(1) != record["init_start"]:
            return "gone"  # this container restarted; old namespace is gone
        pgid = int(record["pgid"])
        if pgid <= 1:
            return "unknown"
        try:
            fd = _pidfd_open(pgid)
        except ProcessLookupError:
            return "unknown" if group_members(pgid) else "gone"
        try:
            token = start_token(pgid)
        except FileNotFoundError:
            return "unknown" if group_members(pgid) else "gone"
        if token != record["leader_start"]:
            return "gone"
        if not group_members(pgid):
            return "gone"
        if not stop:
            return "alive"
        _group_signal(fd, signal.SIGTERM)
        deadline = time.monotonic() + grace_s
        while group_members(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if group_members(pgid):
            _group_signal(fd, signal.SIGKILL)
            deadline = time.monotonic() + 2.0
            while group_members(pgid) and time.monotonic() < deadline:
                time.sleep(0.05)
        return "unknown" if group_members(pgid) else "gone"
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return "unknown"
    finally:
        if fd is not None:
            os.close(fd)


if __name__ == "__main__":
    print(control(json.loads(sys.argv[1]), stop=(sys.argv[2] == "stop")))
