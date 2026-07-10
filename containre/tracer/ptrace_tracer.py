"""L1 ptrace tracer: forks the specimen, decodes syscalls into structured events,
and enforces the network policy by blocking egress syscalls in-flight.

This is the always-on "flight recorder" layer. It runs *as the parent* of the
specimen (ptrace requires it), so it lives in a dedicated tracer process (the
LocalRuntime subprocess, or the in-container probe-agent under Docker).
"""
from __future__ import annotations

import os
import sys
import threading
import traceback
import errno as errno_mod
from typing import Callable

from ptrace.debugger import (
    NewProcessEvent,
    ProcessExecution,
    ProcessExit,
    ProcessSignal,
    PtraceDebugger,
)
from ptrace.debugger.child import createChild
from ptrace.func_call import FunctionCallOptions
from ptrace.syscall import RETURN_VALUE_REGISTER, SYSCALL_REGISTER

from ..model import Event, Kind, hx
from . import l2 as l2mod
from . import syscalls as sc
from .l2_engine import L2Engine

_MASK = (1 << 64) - 1

# Event kind -> the trace.l1 class that decides whether it is recorded. Kinds not
# listed (instr, detection, mem snapshots, ...) are always recorded.
_L1_CLASS_FOR_KIND = {"net": "net", "file": "file", "proc": "proc", "signal": "signal"}


def _create_child_fast(argv: list[str], env: dict[str, str] | None) -> int:
    # python-ptrace's default close_fds=True closes every fd from 3 to
    # SC_OPEN_MAX in Python child code before exec. Some hosts set
    # RLIMIT_NOFILE/SC_OPEN_MAX to ~1B, which makes even hello-world specimens
    # appear to hang for minutes before execve. Python fds are non-inheritable
    # by default, and createChild's error pipe is marked close-on-exec, so skip
    # that linear close loop.
    return createChild(argv, no_stdout=False, env=env, close_fds=False)


class PtraceTracer(L2Engine):
    def __init__(self, *, specimen: str, args: list[str], env: dict[str, str],
                 policy: dict, decoy_paths: list[str], sink: Callable[[Event], None],
                 stdin_path: str | None = None, console_path: str | None = None,
                 snapshot_cb: Callable[[int, str], None] | None = None,
                 sink_addr: tuple[str, int] | None = None):
        self.specimen = specimen
        self.args = args
        self.env = env
        self.policy = policy
        self._sink = sink
        self._snapshot_cb = snapshot_cb
        self.stdin_path = stdin_path
        self.console_path = console_path
        self.sink_addr = sink_addr  # (host, port) of the simulated-internet sink

        net = policy.get("network", {})
        self.net_posture: str = net.get("posture", "simulate")
        self.net_allow: set[str] = set(net.get("allow", []))
        trace = policy.get("trace", {})
        self.l1: set[str] = set(trace.get("l1", []))
        self.snapshot_on: set[str] = set(trace.get("snapshot_on", []))
        l2cfg = trace.get("l2", {}) or {}
        self.l2_mode: str = l2cfg.get("mode", "off")
        self.l2_window: dict = l2cfg.get("window", {}) or {}
        self.l2_max_insns: int = int(self.l2_window.get("max_insns", 20000))
        self._l2_opened = False
        self._l2_windows = 0
        self._md = (l2mod.make_disassembler()
                    if self.l2_mode in ("singlestep", "unicorn") and l2mod.have_capstone()
                    else None)
        self.decoys: set[str] = {os.path.abspath(p) for p in decoy_paths}
        limits = policy.get("limits", {})
        self.wallclock_s: int = int(limits.get("wallclock_s", 120))
        self.max_events = 500_000

        self.fd_paths: dict[tuple[int, int], str] = {}
        self.flows: dict[tuple[int, int], dict] = {}   # (pid,fd) -> {raddr, chunks:[(dir,bytes)]}
        self._flow_cap = 65536
        self._chunk_cap = 8192
        self._pending_block: dict[int, int] = {}
        self._pending_connect: dict[int, dict] = {}
        self.root_pid: int | None = None
        self.exit_code: int | None = None
        self.kill_reason: str | None = None
        self.event_count = 0
        self._killed = threading.Event()

    # -- emit ---------------------------------------------------------------
    def emit(self, event: Event) -> None:
        cls = _L1_CLASS_FOR_KIND.get(event.kind)
        if cls is None and event.kind == Kind.MEM and event.data.get("op") in ("map", "protect"):
            cls = "mmap"
        if cls is not None and cls not in self.l1:
            return  # this L1 class is disabled by trace.l1
        self.event_count += 1
        self._sink(event)

    # -- helpers ------------------------------------------------------------
    def _cstr(self, process, addr: int, maxlen: int = 4096) -> str:
        if not addr:
            return ""
        try:
            data = process.readCString(addr, maxlen)
        except Exception:
            return ""
        if isinstance(data, tuple):
            data = data[0]
        if isinstance(data, (bytes, bytearray)):
            return data.decode("utf-8", "replace")
        return str(data)

    def _read_addr(self, process, ptr: int, length: int):
        if not ptr:
            return (-1, None, None)
        length = min(length or 128, 128)
        try:
            raw = process.readBytes(ptr, max(length, 2))
        except Exception:
            return (-1, None, None)
        return sc.parse_sockaddr(raw)

    def _read_msghdr(self, process, ptr: int) -> dict[str, int]:
        if not ptr:
            return {}
        try:
            raw = process.readBytes(ptr, 56)
        except Exception:
            return {}
        return {
            "name_ptr": int.from_bytes(raw[0:8], "little"),
            "name_len": int.from_bytes(raw[8:12], "little"),
            "iov_ptr": int.from_bytes(raw[16:24], "little"),
            "iov_len": int.from_bytes(raw[24:32], "little"),
        }

    def _read_msghdr_addr(self, process, ptr: int):
        hdr = self._read_msghdr(process, ptr)
        name_ptr = hdr.get("name_ptr", 0)
        name_len = hdr.get("name_len", 0)
        if not name_ptr or not name_len:
            return (-1, None, None)
        return self._read_addr(process, name_ptr, name_len)

    # struct mmsghdr on x86-64 = struct msghdr (56 bytes) + unsigned msg_len (4)
    # + 4 padding => a 64-byte stride between successive batched messages.
    _MMSGHDR_STRIDE = 64

    def _read_mmsghdr_addr(self, process, vec_ptr: int, index: int):
        return self._read_msghdr_addr(process, vec_ptr + index * self._MMSGHDR_STRIDE)

    def _read_iovec_data(self, process, iov_ptr: int, iov_len: int, nbytes: int) -> bytes:
        if not iov_ptr or not iov_len or nbytes <= 0:
            return b""
        remaining = min(nbytes, self._chunk_cap)
        chunks: list[bytes] = []
        for idx in range(min(int(iov_len), 1024)):
            if remaining <= 0:
                break
            try:
                raw = process.readBytes(iov_ptr + idx * 16, 16)
            except Exception:
                break
            base = int.from_bytes(raw[0:8], "little")
            length = int.from_bytes(raw[8:16], "little")
            if not base or not length:
                continue
            want = min(length, remaining)
            try:
                data = bytes(process.readBytes(base, want))
            except Exception:
                data = b""
            if data:
                chunks.append(data)
                remaining -= len(data)
        return b"".join(chunks)

    def _read_int(self, process, ptr: int) -> int | None:
        if not ptr:
            return None
        try:
            raw = process.readBytes(ptr, 4)
        except Exception:
            return None
        return int.from_bytes(raw[:4], "little", signed=True)

    def _resolve(self, path: str) -> str:
        if not path:
            return path
        if path.startswith("/"):
            return os.path.normpath(path)
        return os.path.normpath(os.path.join(os.getcwd(), path))

    def _is_decoy(self, path: str) -> bool:
        if not path:
            return False
        ap = self._resolve(path)
        return ap in self.decoys or os.path.basename(ap) in {os.path.basename(d) for d in self.decoys}

    def _net_decision(self, family: int, ip: str | None, target: str | None) -> str:
        if family not in (sc.AF_INET, sc.AF_INET6):
            return "allow"
        if self.net_posture == "allow":
            return "allow"
        if ip and (ip in self.net_allow or (target and target in self.net_allow)):
            return "allow"
        return "simulated" if self.net_posture == "simulate" else "block"

    def _block_at_enter(self, process, errno: int) -> None:
        try:
            process.setreg(SYSCALL_REGISTER, _MASK)  # orig_rax = -1 -> kernel skips syscall
            self._pending_block[process.pid] = errno
        except Exception:
            pass

    def _maybe_snapshot(self, pid: int, reason: str) -> None:
        # The specimen is stopped at a syscall here, so /proc/<pid>/mem is stable.
        if self._snapshot_cb and reason in self.snapshot_on:
            try:
                self._snapshot_cb(pid, reason)
            except Exception:
                # A snapshot failure must never abort the trace; surface it only
                # when debugging (it lands in the run's runner.log).
                if os.environ.get("CONTAINRE_DEBUG"):
                    traceback.print_exc(file=sys.stderr)

    # -- syscall dispatch ---------------------------------------------------
    def _on_enter(self, process, syscall) -> None:
        name = syscall.name
        if name in ("connect", "sendto", "sendmsg"):
            self._handle_net_egress(process, syscall)
        elif name == "sendmmsg":
            self._handle_net_egress_mmsg(process, syscall)
        elif name in ("execve", "execveat"):
            self._handle_execve(process, syscall)

    def _on_exit(self, process, syscall) -> None:
        if process.pid in self._pending_block:
            errno = self._pending_block.pop(process.pid)
            try:
                process.setreg(RETURN_VALUE_REGISTER, (-errno) & _MASK)
            except Exception:
                pass
            return  # already emitted at enter
        name = syscall.name
        result = syscall.result
        if name == "connect":
            self._handle_connect_result(process, syscall, result)
        elif name == "getsockopt":
            self._handle_getsockopt_result(process, syscall, result)
        elif name in sc.FILE_OPEN_SYSCALLS:
            self._handle_open(process, syscall, result)
        elif name in ("write", "pwrite64", "send", "sendto"):
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_buffer(process, syscall, result, "out", 1)
            elif name not in ("send", "sendto"):
                self._handle_write(process, syscall, result)
        elif name in ("writev", "pwritev", "pwritev2"):
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_iovec(process, syscall, result, "out", 1, 2)
        elif name == "sendmsg":
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_msghdr(process, syscall, result, "out", 1)
        elif name in ("read", "recv", "recvfrom"):
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_buffer(process, syscall, result, "in", 1)
            elif name == "recvfrom":
                self._handle_net_other(process, syscall, result)
        elif name in ("readv", "preadv", "preadv2"):
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_iovec(process, syscall, result, "in", 1, 2)
        elif name == "recvmsg":
            if (process.pid, syscall.arguments[0].value) in self.flows:
                self._capture_socket_msghdr(process, syscall, result, "in", 1)
            else:
                self._handle_net_other(process, syscall, result)
        elif name in ("unlink", "unlinkat"):
            self._handle_path1(process, syscall, "unlink")
        elif name in ("rename", "renameat", "renameat2"):
            self._handle_rename(process, syscall)
        elif name in ("mkdir", "mkdirat"):
            self._handle_path1(process, syscall, "mkdir")
        elif name in ("chmod", "fchmodat", "truncate"):
            self._handle_path1(process, syscall, "chmod" if "chmod" in name else "truncate")
        elif name == "close":
            self.fd_paths.pop((process.pid, syscall.arguments[0].value), None)
        elif name in sc.MEM_SYSCALLS:
            self._handle_mem(process, syscall, result)
        elif name in sc.ANTI_DEBUG_SYSCALLS:
            self.emit(Event(Kind.SYSCALL, {"name": name, "phase": "exit",
                                           "ret": str(result)}, pid=process.pid))
        elif name in ("socket", "bind", "listen", "accept", "accept4"):
            self._handle_net_other(process, syscall, result)

    # -- handlers -----------------------------------------------------------
    def _handle_net_egress(self, process, syscall) -> None:
        name = syscall.name
        if name == "connect":
            ptr, ln = syscall.arguments[1].value, syscall.arguments[2].value
        elif name == "sendto":
            ptr, ln = syscall.arguments[4].value, syscall.arguments[5].value
            if not ptr:
                return  # connected UDP: dest already seen at connect()
        else:
            family, ip, target = self._read_msghdr_addr(process, syscall.arguments[1].value)
            if family not in (sc.AF_INET, sc.AF_INET6):
                return
            decision = self._net_decision(family, ip, target)
            self.emit(Event(Kind.NET, {
                "op": "send",
                "proto": sc.proto_name(family),
                "raddr": target,
                "decision": decision,
            }, pid=process.pid))
            if decision in ("block", "simulated"):
                self._block_at_enter(process, sc.ECONNREFUSED)
            return
        family, ip, target = self._read_addr(process, ptr, ln)
        if family not in (sc.AF_INET, sc.AF_INET6):
            return
        decision = self._net_decision(family, ip, target)
        # simulate: redirect the connect to the local sink so it succeeds and the
        # specimen "talks" to our responder instead of failing.
        redirected = None
        if decision == "simulated" and self.sink_addr and name == "connect":
            redirected = self._redirect_connect(process, ptr, family)
        data = {"op": "connect" if name == "connect" else "send",
                "proto": sc.proto_name(family), "raddr": target, "decision": decision}
        if redirected:
            data["redirected_to"] = redirected
        self.emit(Event(Kind.NET, data, pid=process.pid))
        if name == "connect":
            self._maybe_snapshot(process.pid, "connect")
            # register a flow for pcap when the connect will actually proceed
            if decision == "allow" or redirected:
                fd = syscall.arguments[0].value
                self.flows[(process.pid, fd)] = {"raddr": target, "chunks": []}
                self._pending_connect[process.pid] = {
                    "fd": fd,
                    "raddr": target,
                    "proto": sc.proto_name(family),
                    "decision": decision,
                    "redirected_to": redirected,
                }
        if decision in ("block", "simulated") and not redirected:
            self._block_at_enter(process, sc.ECONNREFUSED)

    def _handle_net_egress_mmsg(self, process, syscall) -> None:
        """sendmmsg(fd, msgvec, vlen, flags): each batched message carries its own
        destination sockaddr. A single syscall cannot be partially blocked, so if
        ANY message targets a blocked/simulated INET destination we fail closed and
        drop the whole call with ECONNREFUSED (matching the sendmsg path, which also
        does not redirect to the sink)."""
        vec_ptr = syscall.arguments[1].value
        vlen = syscall.arguments[2].value
        if not vec_ptr or not vlen:
            return
        blocked = False
        for i in range(min(int(vlen), 1024)):
            family, ip, target = self._read_mmsghdr_addr(process, vec_ptr, i)
            if family not in (sc.AF_INET, sc.AF_INET6):
                continue
            decision = self._net_decision(family, ip, target)
            self.emit(Event(Kind.NET, {
                "op": "send",
                "proto": sc.proto_name(family),
                "raddr": target,
                "decision": decision,
            }, pid=process.pid))
            if decision in ("block", "simulated"):
                blocked = True
        if blocked:
            self._block_at_enter(process, sc.ECONNREFUSED)

    def _handle_connect_result(self, process, syscall, result) -> None:
        pending = self._pending_connect.pop(process.pid, None)
        if pending is None:
            return
        ret = int(result) if result is not None else 0
        data = {
            "op": "connect_result",
            "proto": pending.get("proto"),
            "raddr": pending.get("raddr"),
            "decision": pending.get("decision"),
            "ret": ret,
            "success": ret >= 0,
        }
        status = "success"
        if pending.get("redirected_to"):
            data["redirected_to"] = pending["redirected_to"]
        if ret < 0:
            err = -ret
            data["errno"] = err
            data["errno_name"] = errno_mod.errorcode.get(err, str(err))
            # A nonblocking connect may complete later; keep that flow so later
            # send/recv calls can still be attributed. Hard failures cannot carry
            # payload and should not become synthetic pcap flows.
            if err not in {errno_mod.EINPROGRESS, errno_mod.EALREADY}:
                status = "failure"
                self.flows.pop((process.pid, int(pending["fd"])), None)
            else:
                status = "pending"
        data["status"] = status
        self.emit(Event(Kind.NET, data, pid=process.pid))

    def _handle_getsockopt_result(self, process, syscall, result) -> None:
        if result is None or result < 0:
            return
        fd = syscall.arguments[0].value
        flow = self.flows.get((process.pid, fd))
        if flow is None:
            return
        # Linux getsockopt(fd, SOL_SOCKET, SO_ERROR, int*, socklen_t*) reports
        # the completion status for nonblocking connect().
        level = syscall.arguments[1].value
        optname = syscall.arguments[2].value
        if level != 1 or optname != 4:
            return
        so_error = self._read_int(process, syscall.arguments[3].value)
        if so_error is None:
            return
        data = {
            "op": "socket_error",
            "proto": "tcp",
            "raddr": flow["raddr"],
            "status": "ok" if so_error == 0 else "failure",
            "so_error": so_error,
        }
        if so_error:
            data["errno"] = so_error
            data["errno_name"] = errno_mod.errorcode.get(so_error, str(so_error))
            self.flows.pop((process.pid, fd), None)
        self.emit(Event(Kind.NET, data, pid=process.pid))

    def _redirect_connect(self, process, ptr: int, family: int) -> str | None:
        """Rewrite the connect() sockaddr in the specimen's memory to point at the
        local sink (same family), returning the new 'host:port' or None."""
        import socket as _socket
        import struct
        host, port = self.sink_addr
        try:
            if family == sc.AF_INET:
                raw = (struct.pack("<H", sc.AF_INET) + struct.pack("!H", port)
                       + _socket.inet_aton("127.0.0.1") + b"\x00" * 8)
                process.writeBytes(ptr, raw)
                return f"127.0.0.1:{port}"
            if family == sc.AF_INET6:
                raw = (struct.pack("<H", sc.AF_INET6) + struct.pack("!H", port)
                       + b"\x00" * 4 + _socket.inet_pton(_socket.AF_INET6, "::1") + b"\x00" * 4)
                process.writeBytes(ptr, raw)
                return f"[::1]:{port}"
        except Exception:
            return None
        return None

    def _handle_net_other(self, process, syscall, result) -> None:
        name = syscall.name
        op = {"socket": "socket", "bind": "bind", "listen": "listen",
              "accept": "accept", "accept4": "accept",
              "recvfrom": "recv", "recvmsg": "recv"}[name]
        data: dict = {"op": op}
        if name == "bind":
            family, ip, target = self._read_addr(process, syscall.arguments[1].value,
                                                 syscall.arguments[2].value)
            if target:
                data["laddr"] = target
                data["proto"] = sc.proto_name(family)
        self.emit(Event(Kind.NET, data, pid=process.pid))

    def _handle_open(self, process, syscall, result) -> None:
        name = syscall.name
        idx = 0 if name in ("open", "creat") else 1
        path = self._resolve(self._cstr(process, syscall.arguments[idx].value))
        fd = int(result) if (result is not None and result >= 0) else None
        if fd is not None:
            self.fd_paths[(process.pid, fd)] = path
        data: dict = {"op": "open", "path": path}
        if fd is not None:
            data["fd"] = fd
        if self._is_decoy(path):
            data["decoy"] = True
        self.emit(Event(Kind.FILE, data, pid=process.pid))

    def _handle_write(self, process, syscall, result) -> None:
        fd = syscall.arguments[0].value
        path = self.fd_paths.get((process.pid, fd))
        if path is None:
            return  # stdio / socket / pipe - not a tracked file
        written = int(result) if (result is not None and result >= 0) else 0
        data: dict = {"op": "write", "path": path, "size": written}
        decoy = self._is_decoy(path)
        if decoy:
            data["decoy"] = True
        self.emit(Event(Kind.FILE, data, pid=process.pid))
        if decoy:
            self._maybe_snapshot(process.pid, "decoy")

    def _emit_socket_payload(
        self,
        process,
        fd: int,
        result,
        direction: str,
        data: bytes,
    ) -> None:
        flow = self.flows.get((process.pid, fd))
        if flow is None:
            return
        n = int(result) if (result is not None and result > 0) else 0
        if n <= 0:
            if result is None:
                return
            ret = int(result)
            if ret < 0:
                err = -ret
                if err in {errno_mod.EAGAIN, errno_mod.EWOULDBLOCK, errno_mod.EINTR}:
                    return
                status = "error"
            elif direction == "in":
                err = None
                status = "eof"
            else:
                return
            event_data = {
                "op": "send" if direction == "out" else "recv",
                "proto": "tcp",
                "raddr": flow["raddr"],
                "bytes": 0,
                "status": status,
            }
            if ret < 0:
                event_data["errno"] = err
                event_data["errno_name"] = errno_mod.errorcode.get(err, str(err))
            self.emit(Event(Kind.NET, event_data, pid=process.pid))
            return
        if data and sum(len(d) for _, d in flow["chunks"]) < self._flow_cap:
            flow["chunks"].append((direction, data))
        self.emit(Event(Kind.NET, {
            "op": "send" if direction == "out" else "recv", "proto": "tcp",
            "raddr": flow["raddr"], "bytes": n,
            "preview": data[:64].decode("latin1", "replace")}, pid=process.pid))

    def _capture_socket_buffer(self, process, syscall, result, direction: str, buf_arg: int) -> None:
        """Capture bytes sent/received on a connected socket buffer."""
        fd = syscall.arguments[0].value
        flow = self.flows.get((process.pid, fd))
        if flow is None:
            return
        n = int(result) if (result is not None and result > 0) else 0
        if n <= 0:
            return
        data = b""
        try:
            data = bytes(process.readBytes(syscall.arguments[buf_arg].value, min(n, self._chunk_cap)))
        except Exception:
            data = b""
        self._emit_socket_payload(process, fd, result, direction, data)

    def _capture_socket_iovec(
        self,
        process,
        syscall,
        result,
        direction: str,
        iov_arg: int,
        iovcnt_arg: int,
    ) -> None:
        fd = syscall.arguments[0].value
        if (process.pid, fd) not in self.flows:
            return
        n = int(result) if (result is not None and result > 0) else 0
        data = self._read_iovec_data(
            process,
            syscall.arguments[iov_arg].value,
            syscall.arguments[iovcnt_arg].value,
            n,
        )
        self._emit_socket_payload(process, fd, result, direction, data)

    def _capture_socket_msghdr(self, process, syscall, result, direction: str, msghdr_arg: int) -> None:
        fd = syscall.arguments[0].value
        if (process.pid, fd) not in self.flows:
            return
        n = int(result) if (result is not None and result > 0) else 0
        hdr = self._read_msghdr(process, syscall.arguments[msghdr_arg].value)
        data = self._read_iovec_data(process, hdr.get("iov_ptr", 0), hdr.get("iov_len", 0), n)
        self._emit_socket_payload(process, fd, result, direction, data)

    def _handle_path1(self, process, syscall, op: str) -> None:
        name = syscall.name
        idx = 1 if name.endswith("at") else 0
        path = self._resolve(self._cstr(process, syscall.arguments[idx].value))
        data: dict = {"op": op, "path": path}
        if self._is_decoy(path):
            data["decoy"] = True
        self.emit(Event(Kind.FILE, data, pid=process.pid))

    def _handle_rename(self, process, syscall) -> None:
        name = syscall.name
        if name == "rename":
            old, new = syscall.arguments[0].value, syscall.arguments[1].value
        else:  # renameat / renameat2: (olddirfd, old, newdirfd, new)
            old, new = syscall.arguments[1].value, syscall.arguments[3].value
        p_old = self._resolve(self._cstr(process, old))
        p_new = self._resolve(self._cstr(process, new))
        data: dict = {"op": "rename", "path": p_old, "newpath": p_new}
        if self._is_decoy(p_old) or self._is_decoy(p_new):
            data["decoy"] = True
        self.emit(Event(Kind.FILE, data, pid=process.pid))

    def _handle_mem(self, process, syscall, result) -> None:
        name = syscall.name
        if name == "mmap":
            length, prot = syscall.arguments[1].value, syscall.arguments[2].value
            if not (prot & sc.PROT_EXEC):
                return
            base = int(result) if (result is not None and result >= 0) else 0
            self.emit(Event(Kind.MEM, {"op": "map", "region": {
                "base": hx(base), "size": int(length), "perms": sc.perms_from_prot(prot)}},
                pid=process.pid))
            self._maybe_snapshot(process.pid, "mmap+x")
        else:  # mprotect(addr, len, prot)
            addr, length, prot = (syscall.arguments[0].value, syscall.arguments[1].value,
                                  syscall.arguments[2].value)
            if not (prot & sc.PROT_EXEC):
                return
            self.emit(Event(Kind.MEM, {"op": "protect", "addr": hx(addr), "len": int(length),
                                       "region": {"base": hx(addr), "size": int(length),
                                                  "perms": sc.perms_from_prot(prot)}},
                            pid=process.pid))
            self._maybe_snapshot(process.pid, "mmap+x")

    def _handle_execve(self, process, syscall) -> None:
        path = self._cstr(process, syscall.arguments[0].value)
        argv = self._read_argv(process, syscall.arguments[1].value)
        data: dict = {"op": "exec", "path": path}
        if argv:
            data["argv"] = argv
        self.emit(Event(Kind.PROC, data, pid=process.pid))

    def _read_argv(self, process, addr: int, maxargs: int = 64) -> list[str]:
        out: list[str] = []
        if not addr:
            return out
        for i in range(maxargs):
            try:
                raw = process.readBytes(addr + i * 8, 8)
            except Exception:
                break
            ptr = int.from_bytes(raw, "little")
            if ptr == 0:
                break
            out.append(self._cstr(process, ptr, 4096))
        return out

    # -- main loop ----------------------------------------------------------
    def _watchdog(self) -> None:
        if self.wallclock_s <= 0:
            return
        if self._killed.wait(self.wallclock_s):
            return
        self.kill_reason = "timeout"
        if self.root_pid:
            try:
                os.kill(self.root_pid, 9)
            except OSError:
                pass

    def run(self) -> int:
        argv = [self.specimen, *self.args]
        env = dict(self.env) if self.env else None

        # Redirect the specimen's stdio around the fork: the child inherits the
        # redirected fds; we restore ours immediately after so tracer diagnostics
        # don't pollute the specimen's console.log.
        saved: list[tuple[int, int]] = []
        opened: list[int] = []
        if self.stdin_path:
            fd = os.open(self.stdin_path, os.O_RDONLY)
            opened.append(fd)
            saved.append((0, os.dup(0)))
            os.dup2(fd, 0)
        if self.console_path:
            fd = os.open(self.console_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
            opened.append(fd)
            saved.append((1, os.dup(1)))
            saved.append((2, os.dup(2)))
            os.dup2(fd, 1)
            os.dup2(fd, 2)
        try:
            pid = _create_child_fast(argv, env)
        finally:
            for target, backup in saved:
                os.dup2(backup, target)
                os.close(backup)
            for fd in opened:
                os.close(fd)
        self.root_pid = pid

        debugger = PtraceDebugger()
        self.debugger = debugger
        debugger.traceFork()
        debugger.traceExec()
        debugger.traceClone()
        try:
            debugger.enableSysgood()
        except Exception:
            pass
        process = debugger.addProcess(pid, is_attached=True)

        options = FunctionCallOptions(write_types=False, write_argname=False)
        wd = threading.Thread(target=self._watchdog, daemon=True)
        wd.start()

        # The process is stopped at its entry point. For L2 we open the window here
        # (the initial exec doesn't raise a ProcessExecution event - it is consumed
        # by addProcess); the window resumes normal tracing when it closes.
        if self._md is not None and self.l2_mode == "singlestep":
            self._l2_opened = True
            self._single_step_window(process)
        elif self._md is not None and self.l2_mode == "unicorn":
            self._l2_opened = True
            self._unicorn_region(process)
        else:
            process.syscall()
        try:
            while debugger.list:
                try:
                    event = debugger.waitSyscall()
                except ProcessExit as ev:
                    self._on_process_exit(ev)
                    continue
                except ProcessExecution as ev:
                    self._maybe_snapshot(ev.process.pid, "exec")
                    ev.process.syscall_state.clear()
                    ev.process.syscall()
                    continue
                except NewProcessEvent as ev:
                    child = ev.process
                    parent = child.parent
                    if parent is not None:
                        self._inherit_process_state(parent.pid, child.pid)
                    self.emit(Event(Kind.PROC, {"op": "clone", "child_pid": child.pid,
                                                "ppid": parent.pid if parent else None},
                                    pid=parent.pid if parent else None))
                    # Resume BOTH: the child (newly stopped) and the parent (stopped
                    # to report the fork). Forgetting the parent deadlocks the run.
                    child.syscall()
                    if parent is not None:
                        parent.syscall()
                    continue
                except ProcessSignal as ev:
                    self.emit(Event(Kind.SIGNAL, {"signo": ev.signum,
                                                  "name": ev.name or str(ev.signum)},
                                    pid=ev.process.pid))
                    ev.process.syscall(ev.signum)
                    continue

                proc = event.process
                self._step_syscall(proc, options)
                if self.event_count > self.max_events:
                    self.kill_reason = "event_cap"
                    proc.kill(9)
                    break
                proc.syscall()
        finally:
            self._killed.set()
            try:
                debugger.quit()
            except Exception:
                pass
        return self.exit_code if self.exit_code is not None else 0

    def _inherit_process_state(self, parent_pid: int, child_pid: int) -> None:
        for (pid, fd), path in list(self.fd_paths.items()):
            if pid == parent_pid:
                self.fd_paths[(child_pid, fd)] = path
        for (pid, fd), flow in list(self.flows.items()):
            if pid == parent_pid:
                self.flows[(child_pid, fd)] = {"raddr": flow["raddr"], "chunks": []}

    def _step_syscall(self, process, options) -> None:
        state = process.syscall_state
        try:
            syscall = state.event(options)
        except Exception:
            return
        if syscall is None:
            return
        try:
            if syscall.result is None:
                self._on_enter(process, syscall)
            else:
                self._on_exit(process, syscall)
        except Exception:
            # a decode/read hiccup on one syscall must never abort the whole trace
            pass

    def _on_process_exit(self, ev) -> None:
        code = getattr(ev, "exitcode", None)
        signum = getattr(ev, "signum", None)
        data: dict = {"op": "exit"}
        if code is not None:
            data["exit_code"] = code
        if signum:
            data["signal"] = str(signum)
        self.emit(Event(Kind.PROC, data, pid=ev.process.pid))
        if ev.process.pid == self.root_pid:
            self.exit_code = code if code is not None else (-signum if signum else 0)
