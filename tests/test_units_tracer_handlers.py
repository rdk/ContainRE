"""Unit tests for ptrace tracer helpers and syscall handlers using fakes."""
from __future__ import annotations

import socket
import struct
from types import SimpleNamespace

import pytest

from containre.model import Kind
from containre.tracer import syscalls as sc
from containre.tracer.ptrace_tracer import PtraceTracer

pytestmark = pytest.mark.unit


def _arg(value):
    return SimpleNamespace(value=value)


def _syscall(name, *args):
    return SimpleNamespace(name=name, arguments=[_arg(a) for a in args])


def _sockaddr_in(ip: str, port: int) -> bytes:
    return (
        struct.pack("H", sc.AF_INET)
        + struct.pack("!H", port)
        + socket.inet_aton(ip)
        + b"\x00" * 8
    )


def _sockaddr_in6_v4mapped(ip: str, port: int) -> bytes:
    return (
        struct.pack("H", sc.AF_INET6)
        + struct.pack("!H", port)
        + b"\x00" * 4
        + socket.inet_pton(socket.AF_INET6, "::ffff:" + ip)
        + b"\x00" * 4
    )


def _msghdr(msg_name: int, msg_namelen: int, iov: int = 0, iovlen: int = 0) -> bytes:
    return (
        msg_name.to_bytes(8, "little")
        + msg_namelen.to_bytes(4, "little")
        + b"\x00" * 4
        + iov.to_bytes(8, "little")
        + iovlen.to_bytes(8, "little")
        + b"\x00" * 24
    )


def _iovec(base: int, length: int) -> bytes:
    return base.to_bytes(8, "little") + length.to_bytes(8, "little")


class FakeProcess:
    pid = 4242

    def __init__(self, strings=None, reads=None):
        self.strings = strings or {}
        self.reads = reads or {}
        self.regs = []

    def readCString(self, addr, maxlen=4096):
        return self.strings.get(addr, "")

    def readBytes(self, addr, length):
        data = self.reads[addr]
        return data[:length]

    def setreg(self, reg, value):
        self.regs.append((reg, value))


def _tracer(**policy_overrides):
    events = []
    policy = {
        "network": {"posture": "deny", "allow": []},
        "trace": {"l1": ["net", "file", "proc", "mmap", "signal"], "snapshot_on": ["decoy"]},
    }
    policy.update(policy_overrides)
    tracer = PtraceTracer(
        specimen="/bin/true",
        args=[],
        env={},
        policy=policy,
        decoy_paths=["/work/wallet.dat"],
        sink=events.append,
    )
    return tracer, events


def test_decoy_matching_accepts_absolute_path_and_basename():
    tracer, _ = _tracer()
    assert tracer._is_decoy("/work/wallet.dat")
    assert tracer._is_decoy("wallet.dat")
    assert not tracer._is_decoy("/work/other.txt")


def test_handle_write_emits_file_event_and_decoy_snapshot():
    snapshots = []
    tracer, events = _tracer()
    tracer._snapshot_cb = lambda pid, reason: snapshots.append((pid, reason))
    tracer.fd_paths[(FakeProcess.pid, 7)] = "/work/wallet.dat"

    tracer._handle_write(FakeProcess(), _syscall("write", 7, 0x1000, 9), 9)

    assert len(events) == 1
    assert events[0].kind == Kind.FILE
    assert events[0].data == {"op": "write", "path": "/work/wallet.dat", "size": 9, "decoy": True}
    assert snapshots == [(FakeProcess.pid, "decoy")]


def test_handle_rename_marks_decoy_on_old_or_new_path():
    tracer, events = _tracer()
    proc = FakeProcess(strings={0x10: "wallet.dat", 0x20: "wallet.dat.locked"})

    tracer._handle_rename(proc, _syscall("rename", 0x10, 0x20))

    assert events[0].kind == Kind.FILE
    assert events[0].data["op"] == "rename"
    assert events[0].data["path"].endswith("wallet.dat")
    assert events[0].data["newpath"].endswith("wallet.dat.locked")
    assert events[0].data["decoy"] is True


def test_handle_net_connect_blocks_deny_policy_and_records_original_target():
    tracer, events = _tracer()
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.10", 4444)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "connect",
        "proto": "tcp",
        "raddr": "203.0.113.10:4444",
        "decision": "block",
    }
    assert proc.regs, "blocked connect should rewrite the syscall register"
    assert tracer._pending_block == {proc.pid: sc.ECONNREFUSED}


def test_ipv4_mapped_ipv6_sockaddr_matches_ipv4_allowlist():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["192.0.2.44:53000"]})
    proc = FakeProcess(reads={0x5000: _sockaddr_in6_v4mapped("192.0.2.44", 53000)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 28))

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "connect",
        "proto": "tcp",
        "raddr": "192.0.2.44:53000",
        "decision": "allow",
    }
    assert not proc.regs


def test_handle_net_sendmsg_blocks_destination_in_msghdr():
    tracer, events = _tracer()
    sockaddr = _sockaddr_in("203.0.113.20", 5353)
    proc = FakeProcess(reads={0x5000: _msghdr(0x6000, len(sockaddr)), 0x6000: sockaddr})

    tracer._handle_net_egress(proc, _syscall("sendmsg", 3, 0x5000, 0))

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "send",
        "proto": "tcp",
        "raddr": "203.0.113.20:5353",
        "decision": "block",
    }
    assert proc.regs, "blocked sendmsg should rewrite the syscall register"
    assert tracer._pending_block == {proc.pid: sc.ECONNREFUSED}


def test_capture_socket_writev_records_payload_chunks():
    tracer, events = _tracer()
    tracer.flows[(FakeProcess.pid, 4)] = {"raddr": "203.0.113.30:443", "chunks": []}
    proc = FakeProcess(reads={
        0x7000: _iovec(0x7100, 5),
        0x7010: _iovec(0x7200, 6),
        0x7100: b"hello",
        0x7200: b" world",
    })

    tracer._capture_socket_iovec(proc, _syscall("writev", 4, 0x7000, 2), 11, "out", 1, 2)

    assert events[0].kind == Kind.NET
    assert events[0].data["op"] == "send"
    assert events[0].data["raddr"] == "203.0.113.30:443"
    assert events[0].data["bytes"] == 11
    assert tracer.flows[(FakeProcess.pid, 4)]["chunks"] == [("out", b"hello world")]


def test_capture_socket_recvmsg_records_payload_chunks():
    tracer, events = _tracer()
    tracer.flows[(FakeProcess.pid, 5)] = {"raddr": "203.0.113.40:53000", "chunks": []}
    proc = FakeProcess(reads={
        0x8000: _msghdr(0, 0, 0x8100, 2),
        0x8100: _iovec(0x8200, 3),
        0x8110: _iovec(0x8300, 3),
        0x8200: b"abc",
        0x8300: b"def",
    })

    tracer._capture_socket_msghdr(proc, _syscall("recvmsg", 5, 0x8000, 0), 6, "in", 1)

    assert events[0].kind == Kind.NET
    assert events[0].data["op"] == "recv"
    assert events[0].data["raddr"] == "203.0.113.40:53000"
    assert events[0].data["bytes"] == 6
    assert tracer.flows[(FakeProcess.pid, 5)]["chunks"] == [("in", b"abcdef")]


def test_connect_result_records_success_and_keeps_flow():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["203.0.113.50:443"]})
    tracer.flows[(FakeProcess.pid, 6)] = {"raddr": "203.0.113.50:443", "chunks": []}
    tracer._pending_connect[FakeProcess.pid] = {
        "fd": 6,
        "raddr": "203.0.113.50:443",
        "proto": "tcp",
        "decision": "allow",
        "redirected_to": None,
    }

    tracer._handle_connect_result(FakeProcess(), _syscall("connect", 6, 0x5000, 16), 0)

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "connect_result",
        "proto": "tcp",
        "raddr": "203.0.113.50:443",
        "decision": "allow",
        "ret": 0,
        "success": True,
        "status": "success",
    }
    assert (FakeProcess.pid, 6) in tracer.flows


def test_connect_result_records_pending_and_keeps_flow():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["203.0.113.52:443"]})
    tracer.flows[(FakeProcess.pid, 8)] = {"raddr": "203.0.113.52:443", "chunks": []}
    tracer._pending_connect[FakeProcess.pid] = {
        "fd": 8,
        "raddr": "203.0.113.52:443",
        "proto": "tcp",
        "decision": "allow",
        "redirected_to": None,
    }

    tracer._handle_connect_result(FakeProcess(), _syscall("connect", 8, 0x5000, 16), -115)

    assert events[0].data["op"] == "connect_result"
    assert events[0].data["status"] == "pending"
    assert events[0].data["errno_name"] == "EINPROGRESS"
    assert (FakeProcess.pid, 8) in tracer.flows


def test_connect_result_records_errno_and_drops_failed_flow():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["203.0.113.51:443"]})
    tracer.flows[(FakeProcess.pid, 7)] = {"raddr": "203.0.113.51:443", "chunks": []}
    tracer._pending_connect[FakeProcess.pid] = {
        "fd": 7,
        "raddr": "203.0.113.51:443",
        "proto": "tcp",
        "decision": "allow",
        "redirected_to": None,
    }

    tracer._handle_connect_result(FakeProcess(), _syscall("connect", 7, 0x5000, 16), -111)

    assert events[0].data["op"] == "connect_result"
    assert events[0].data["success"] is False
    assert events[0].data["status"] == "failure"
    assert events[0].data["errno_name"] == "ECONNREFUSED"
    assert (FakeProcess.pid, 7) not in tracer.flows


def test_getsockopt_so_error_records_nonblocking_connect_completion():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["203.0.113.53:443"]})
    tracer.flows[(FakeProcess.pid, 9)] = {"raddr": "203.0.113.53:443", "chunks": []}
    proc = FakeProcess(reads={0x9000: (0).to_bytes(4, "little", signed=True)})

    tracer._handle_getsockopt_result(proc, _syscall("getsockopt", 9, 1, 4, 0x9000, 0x9010), 0)

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "socket_error",
        "proto": "tcp",
        "raddr": "203.0.113.53:443",
        "status": "ok",
        "so_error": 0,
    }
    assert (FakeProcess.pid, 9) in tracer.flows


def test_inherit_process_state_copies_fd_paths_and_flow_targets():
    tracer, _ = _tracer()
    tracer.fd_paths[(100, 3)] = "/work/out.txt"
    tracer.flows[(100, 4)] = {"raddr": "203.0.113.60:443", "chunks": [("out", b"parent")]}

    tracer._inherit_process_state(100, 101)

    assert tracer.fd_paths[(101, 3)] == "/work/out.txt"
    assert tracer.flows[(101, 4)] == {"raddr": "203.0.113.60:443", "chunks": []}


def test_handle_execve_captures_path_and_argv():
    tracer, events = _tracer()
    # argv vector at 0x1000 -> pointers 0x2000, 0x2010, NULL.
    argv = (0x2000).to_bytes(8, "little") + (0x2010).to_bytes(8, "little") + (0).to_bytes(8, "little")
    proc = FakeProcess(
        strings={0x10: "/bin/echo", 0x2000: "echo", 0x2010: "hello"},
        reads={0x1000: argv[:8], 0x1008: argv[8:16], 0x1010: argv[16:24]},
    )

    tracer._handle_execve(proc, _syscall("execve", 0x10, 0x1000, 0))

    assert events[0].kind == Kind.PROC
    assert events[0].data == {"op": "exec", "path": "/bin/echo", "argv": ["echo", "hello"]}
