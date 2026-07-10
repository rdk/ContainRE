"""Unit tests for ptrace tracer helpers and syscall handlers using fakes."""
from __future__ import annotations

import socket
import struct
from types import SimpleNamespace

import pytest

from containre.model import Kind
from containre.tracer import l2 as l2mod
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

    def __init__(self, strings=None, reads=None, regvals=None):
        self.strings = strings or {}
        self.reads = reads or {}
        self.regs = []
        self.writes = {}
        self.regvals = dict(regvals or {})

    def getreg(self, name):
        return self.regvals.get(name, 0)

    def readCString(self, addr, maxlen=4096):
        return self.strings.get(addr, "")

    def readBytes(self, addr, length):
        data = self.reads[addr]
        return data[:length]

    def setreg(self, reg, value):
        self.regs.append((reg, value))
        self.regvals[reg] = value

    def writeBytes(self, addr, data):
        self.writes[addr] = bytes(data)
        return len(data)


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


def test_handle_net_sendmmsg_blocks_destination_in_batch():
    tracer, events = _tracer()
    sockaddr = _sockaddr_in("203.0.113.21", 5354)
    # mmsghdr stride is 64 bytes: msg_hdr (56) + msg_len (4) + pad (4).
    proc = FakeProcess(reads={
        0x5000: _msghdr(0x6000, len(sockaddr)),
        0x6000: sockaddr,
    })

    tracer._handle_net_egress_mmsg(proc, _syscall("sendmmsg", 3, 0x5000, 1, 0))

    assert events[0].kind == Kind.NET
    assert events[0].data == {
        "op": "send",
        "proto": "tcp",
        "raddr": "203.0.113.21:5354",
        "decision": "block",
    }
    assert proc.regs, "blocked sendmmsg should rewrite the syscall register"
    assert tracer._pending_block == {proc.pid: sc.ECONNREFUSED}


def test_handle_net_sendmmsg_blocks_whole_batch_if_any_message_blocked():
    tracer, events = _tracer()
    first = _sockaddr_in("203.0.113.22", 80)
    second = _sockaddr_in("203.0.113.23", 443)
    proc = FakeProcess(reads={
        0x5000: _msghdr(0x6000, len(first)),
        0x5040: _msghdr(0x6100, len(second)),   # second mmsghdr at +64
        0x6000: first,
        0x6100: second,
    })

    tracer._handle_net_egress_mmsg(proc, _syscall("sendmmsg", 3, 0x5000, 2, 0))

    assert [e.data["raddr"] for e in events] == ["203.0.113.22:80", "203.0.113.23:443"]
    assert all(e.data["decision"] == "block" for e in events)
    assert proc.regs, "one blocked message must fail the whole batched syscall closed"


def test_resolve_allow_expands_hostname_and_passes_through_literals(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, 0, 6, "", ("93.184.216.34", 0))])
    resolved = PtraceTracer._resolve_allow(["example.com:80", "1.2.3.4:443"])
    assert "93.184.216.34:80" in resolved   # hostname resolved to its numeric target
    assert "example.com:80" in resolved     # original entry retained
    assert "1.2.3.4:443" in resolved        # IP literal passed through, not re-resolved


def test_hostname_allow_permits_the_resolved_ip(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda *a, **k: [(socket.AF_INET, 0, 6, "", ("93.184.216.34", 0))])
    tracer, _ = _tracer(network={"posture": "deny", "allow": ["example.com:80"]})
    assert tracer._net_decision(sc.AF_INET, "93.184.216.34", "93.184.216.34:80") == "allow"


def test_is_multithreaded_fails_closed_on_missing_task_dir():
    tracer, _ = _tracer()
    assert tracer._is_multithreaded(999999999) is True


def test_simulate_connect_blocks_instead_of_racy_redirect_when_multithreaded():
    tracer, events = _tracer(network={"posture": "simulate", "allow": []})
    tracer.sink_addr = ("127.0.0.1", 9999)
    tracer._is_multithreaded = lambda pid: True   # racy: must block, not redirect
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.9", 443)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert "redirected_to" not in events[-1].data
    assert tracer._pending_block == {proc.pid: sc.ECONNREFUSED}
    assert not proc.writes, "must not rewrite the sockaddr for a multithreaded specimen"


def test_simulate_connect_redirects_to_sink_when_single_threaded():
    tracer, events = _tracer(network={"posture": "simulate", "allow": []})
    tracer.sink_addr = ("127.0.0.1", 9999)
    tracer._is_multithreaded = lambda pid: False  # safe: redirect to the sink
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.9", 443)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert events[-1].data.get("redirected_to") == "127.0.0.1:9999"
    assert proc.writes.get(0x5000), "single-threaded simulate connect should rewrite to the sink"
    assert tracer._pending_block == {}, "a redirected connect must not be blocked"


def test_io_uring_setup_blocked_under_restricting_posture():
    import errno as _errno
    tracer, events = _tracer(network={"posture": "deny", "allow": []})

    tracer._handle_io_uring_setup(FakeProcess(), _syscall("io_uring_setup", 64, 0x1000))

    assert events[0].kind == Kind.SYSCALL
    assert events[0].data == {"name": "io_uring_setup", "phase": "enter", "blocked": True}
    assert tracer._pending_block == {FakeProcess.pid: _errno.ENOSYS}


def test_io_uring_setup_allowed_under_allow_posture():
    tracer, events = _tracer(network={"posture": "allow", "allow": []})
    proc = FakeProcess()

    tracer._handle_io_uring_setup(proc, _syscall("io_uring_setup", 64, 0x1000))

    assert events[0].data["blocked"] is False
    assert not proc.regs
    assert tracer._pending_block == {}


def test_disk_mb_parsed_and_workdir_bytes_short_circuits(tmp_path):
    tracer, _ = _tracer(limits={"disk_mb": 128})
    assert tracer.disk_mb == 128
    # one 1000-byte file per subdirectory so the per-directory limit check can
    # return a PARTIAL sum before walking them all.
    for d in ("d1", "d2", "d3"):
        (tmp_path / d).mkdir()
        (tmp_path / d / "f").write_bytes(b"x" * 1000)
    tracer._workdir = str(tmp_path)

    assert tracer._workdir_bytes(10**9) == 3000   # full sum when under the limit
    partial = tracer._workdir_bytes(500)
    assert 500 < partial < 3000                    # short-circuited: stopped before the full walk


def test_disk_mb_off_by_default():
    tracer, _ = _tracer()
    assert tracer.disk_mb == 0


def test_on_enter_dispatches_sendmmsg_and_io_uring_to_the_egress_gate():
    # The containment fixes only take effect via the _on_enter dispatch table;
    # deleting an `elif name == ...` line would reintroduce the bypass. Drive
    # _on_enter (not the handler methods) so the wiring itself is covered.
    tracer, events = _tracer()
    sockaddr = _sockaddr_in("203.0.113.30", 53)
    proc = FakeProcess(reads={0x5000: _msghdr(0x6000, len(sockaddr)), 0x6000: sockaddr})
    tracer._on_enter(proc, _syscall("sendmmsg", 3, 0x5000, 1, 0))
    assert events and events[-1].data["raddr"] == "203.0.113.30:53"
    assert tracer._pending_block == {proc.pid: sc.ECONNREFUSED}

    tracer2, events2 = _tracer(network={"posture": "deny", "allow": []})
    proc2 = FakeProcess()
    tracer2._on_enter(proc2, _syscall("io_uring_setup", 64, 0x1000))
    assert events2[-1].data == {"name": "io_uring_setup", "phase": "enter", "blocked": True}
    assert tracer2._pending_block == {proc2.pid: __import__("errno").ENOSYS}


def test_l2_gate_egress_at_rip_neutralizes_a_syscall_instruction():
    if not l2mod.have_capstone():
        pytest.skip("capstone not available")
    # The L2 seek gate decodes the instruction at rip and only acts on a real
    # `syscall`; verify the decode->gate path (reverting the call site turns it
    # into a no-op).
    tracer, _ = _tracer(network={"posture": "deny", "allow": []})
    tracer._md = l2mod.make_disassembler()
    sockaddr = _sockaddr_in("203.0.113.5", 443)
    proc = FakeProcess(
        reads={0x1000: b"\x0f\x05" + b"\x90" * 13,   # `syscall` then padding
               0x9000: sockaddr},
        regvals={"rip": 0x1000, "rax": 42, "rsi": 0x9000, "rdx": len(sockaddr)},  # connect
    )

    tracer._l2_gate_egress_at_rip(proc)

    assert proc.regvals["rax"] == (1 << 64) - 1   # blocked connect neutralized

    # a non-syscall instruction at rip must NOT be gated
    proc2 = FakeProcess(reads={0x2000: b"\x90" * 15}, regvals={"rip": 0x2000, "rax": 42})
    tracer._l2_gate_egress_at_rip(proc2)
    assert proc2.regvals["rax"] == 42


def test_seek_to_carries_pending_signal_out_instead_of_dropping_it():
    from ptrace.debugger import ProcessSignal
    tracer, _ = _tracer()
    tracer._md = None   # _l2_gate_egress_at_rip becomes a no-op (no disassembly)

    proc = FakeProcess()
    rips = [0x1000, 0x2000]           # step once, then rip == target
    proc.getreg = lambda name: rips.pop(0) if name == "rip" else 0
    proc.singleStep = lambda: None

    sig = ProcessSignal(20, proc)     # a non-SIGTRAP signal delivered mid-seek
    sig.name = "SIGCHLD"

    class _Dbg:
        def waitProcessEvent(self, pid=None):
            return sig

    tracer.debugger = _Dbg()

    outcome = tracer._seek_to(proc, 0x2000)

    assert outcome == "reached"
    # the signal that arrived on the last step before reaching target must be
    # carried out for re-injection, not silently dropped.
    assert tracer._seek_pending_signal == 20


def test_l2_gate_egress_neutralizes_blocked_connect():
    # a connect single-stepped in an L2 window must be gated: recorded, killed
    # (if configured), and the syscall number invalidated so it never egresses.
    tracer, events = _tracer(kill_on=["egress_violation"])
    sockaddr = _sockaddr_in("203.0.113.77", 443)
    proc = FakeProcess(reads={0x9000: sockaddr},
                       regvals={"rax": 42, "rsi": 0x9000, "rdx": len(sockaddr)})  # 42 = connect

    tracer._l2_gate_egress(proc)

    assert events[-1].data["raddr"] == "203.0.113.77:443"
    assert events[-1].data["decision"] == "block"
    assert events[-1].data["via"] == "l2-singlestep"
    assert proc.regvals["rax"] == (1 << 64) - 1   # invalid syscall nr -> kernel skips it
    assert tracer._kill_requested


def test_l2_gate_egress_leaves_allowlisted_connect_intact():
    tracer, events = _tracer(network={"posture": "deny", "allow": ["203.0.113.88:443"]})
    sockaddr = _sockaddr_in("203.0.113.88", 443)
    proc = FakeProcess(reads={0x9000: sockaddr},
                       regvals={"rax": 42, "rsi": 0x9000, "rdx": len(sockaddr)})

    tracer._l2_gate_egress(proc)

    assert events[-1].data["decision"] == "allow"
    assert proc.regvals["rax"] == 42   # allowed egress is not neutralized


def test_l2_gate_egress_ignores_non_egress_syscall():
    tracer, events = _tracer()
    proc = FakeProcess(regvals={"rax": 1})  # write(2) is nr 1, not an egress syscall

    tracer._l2_gate_egress(proc)

    assert events == []
    assert proc.regvals["rax"] == 1


def test_l2_gate_blocks_io_uring_setup_under_restricting_posture():
    # io_uring_setup (nr 425) must be denied inside an L2 window too, else the
    # specimen creates a ring and egresses via io_uring_enter after the window.
    tracer, events = _tracer(network={"posture": "deny", "allow": []})
    proc = FakeProcess(regvals={"rax": 425})

    tracer._l2_gate_egress(proc)

    assert events[-1].data == {"name": "io_uring_setup", "phase": "enter",
                               "blocked": True, "via": "l2-singlestep"}
    assert proc.regvals["rax"] == (1 << 64) - 1


def test_l2_gate_leaves_io_uring_setup_under_allow_posture():
    tracer, events = _tracer(network={"posture": "allow", "allow": []})
    proc = FakeProcess(regvals={"rax": 425})

    tracer._l2_gate_egress(proc)

    assert events == []
    assert proc.regvals["rax"] == 425


def test_l2_gate_sendmmsg_inspects_beyond_the_first_64_messages():
    # a blocked destination in the 65th batched message must still fail the syscall
    # closed (L2 cap must match the L1/kernel limit, not stop at 64).
    tracer, _ = _tracer(network={"posture": "deny", "allow": []})
    sockaddr = _sockaddr_in("203.0.113.99", 443)
    hdr64 = 0x5000 + 64 * 64   # mmsghdr stride is 64; the 65th entry
    proc = FakeProcess(
        reads={hdr64: _msghdr(0x9000, len(sockaddr)), 0x9000: sockaddr},
        regvals={"rax": 307, "rsi": 0x5000, "rdx": 65},   # sendmmsg, vlen=65
    )

    tracer._l2_gate_egress(proc)

    assert proc.regvals["rax"] == (1 << 64) - 1


def test_kill_on_egress_violation_requests_kill():
    tracer, _ = _tracer(kill_on=["egress_violation"])
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.10", 4444)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert tracer._kill_requested is True
    assert tracer.kill_reason == "egress_violation"


def test_no_kill_when_egress_violation_absent_from_kill_on():
    tracer, _ = _tracer(kill_on=[])
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.10", 4444)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert tracer._kill_requested is False
    assert tracer.kill_reason is None


def test_simulated_egress_does_not_trigger_egress_violation_kill():
    # a simulated (not blocked) egress is contained by design, not a violation.
    tracer, _ = _tracer(network={"posture": "simulate", "allow": []}, kill_on=["egress_violation"])
    tracer.sink_addr = ("127.0.0.1", 9999)
    tracer._is_multithreaded = lambda pid: False
    proc = FakeProcess(reads={0x5000: _sockaddr_in("203.0.113.9", 443)})

    tracer._handle_net_egress(proc, _syscall("connect", 3, 0x5000, 16))

    assert tracer._kill_requested is False


def test_kill_on_decoy_write_requests_kill():
    tracer, _ = _tracer(kill_on=["decoy_write"])
    tracer.fd_paths[(FakeProcess.pid, 7)] = "/work/wallet.dat"

    tracer._handle_write(FakeProcess(), _syscall("write", 7, 0x1000, 9), 9)

    assert tracer._kill_requested is True
    assert tracer.kill_reason == "decoy_write"


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
