"""x86-64 syscall constants and decoding helpers used by the L1 tracer."""
from __future__ import annotations

import socket
import struct
import ipaddress

# errno values we inject when blocking
EPERM = 1
EACCES = 13
ENETUNREACH = 101
ECONNREFUSED = 111

# mmap/mprotect protection bits
PROT_READ = 1
PROT_WRITE = 2
PROT_EXEC = 4

# address families
AF_UNIX = 1
AF_INET = 2
AF_INET6 = 10

AT_FDCWD = -100

# Syscalls that touch the network (subject to the network policy).
NET_SYSCALLS = {
    "socket", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
    "getpeername", "getsockopt",
}
# Egress-initiating syscalls we may block. sendmmsg batches several messages,
# each with its own destination sockaddr, so it is a drop-in for sendmsg and must
# be gated too (recvmmsg is receive-only and never egresses).
NET_EGRESS_SYSCALLS = {"connect", "sendto", "sendmsg", "sendmmsg"}

# x86-64 syscall numbers for the egress-initiating calls. The L2 single-step
# engine sees raw `syscall` instructions rather than python-ptrace's decoded
# names, so it matches on the number in rax.
EGRESS_SYSCALL_NRS = {42: "connect", 44: "sendto", 46: "sendmsg", 307: "sendmmsg"}
IO_URING_SETUP_NR = 425  # ring creation; denied under a restricting posture (also in L2)

FILE_OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
FILE_SYSCALLS = FILE_OPEN_SYSCALLS | {
    "write", "pwrite64", "unlink", "unlinkat", "rename", "renameat",
    "renameat2", "mkdir", "mkdirat", "chmod", "fchmodat", "close", "truncate",
    "writev", "pwritev", "pwritev2", "readv", "preadv", "preadv2",
}
PROC_SYSCALLS = {"execve", "execveat", "clone", "clone3", "fork", "vfork"}
MEM_SYSCALLS = {"mmap", "mprotect"}
ANTI_DEBUG_SYSCALLS = {"ptrace", "process_vm_writev", "process_vm_readv"}


def perms_from_prot(prot: int) -> str:
    return (
        ("r" if prot & PROT_READ else "-")
        + ("w" if prot & PROT_WRITE else "-")
        + ("x" if prot & PROT_EXEC else "-")
    )


def parse_sockaddr(raw: bytes) -> tuple[int, str | None, str | None]:
    """Return (family, ip, 'ip:port') parsed from a raw sockaddr blob."""
    if len(raw) < 2:
        return (-1, None, None)
    family = struct.unpack_from("H", raw, 0)[0]
    try:
        if family == AF_INET and len(raw) >= 8:
            port = struct.unpack_from("!H", raw, 2)[0]
            ip = socket.inet_ntoa(raw[4:8])
            return (family, ip, f"{ip}:{port}")
        if family == AF_INET6 and len(raw) >= 24:
            port = struct.unpack_from("!H", raw, 2)[0]
            ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
            mapped = ipaddress.ip_address(ip).ipv4_mapped
            if mapped is not None:
                ip = str(mapped)
                return (family, ip, f"{ip}:{port}")
            return (family, ip, f"[{ip}]:{port}")
        if family == AF_UNIX:
            path = raw[2:].split(b"\x00", 1)[0].decode("utf-8", "replace")
            return (family, path, f"unix:{path}")
    except (OSError, ValueError):
        pass
    return (family, None, None)


def proto_name(family: int) -> str | None:
    return {AF_INET: "tcp", AF_INET6: "tcp", AF_UNIX: "unix"}.get(family)
