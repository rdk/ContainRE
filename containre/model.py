"""Core event model - mirrors contracts/events.v1.schema.json.

Events are built as plain dataclasses and serialized to the envelope dict the
contract defines. The Store assigns the monotonic ``seq``; producers set
``kind``, ``data``, and identity/timing fields.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

SCHEMA_VERSION = 1


class Kind:
    SYSCALL = "syscall"
    NET = "net"
    FILE = "file"
    MEM = "mem"
    PROC = "proc"
    SIGNAL = "signal"
    INSTR = "instr"
    DETECTION = "detection"
    GATE = "gate"


def mono_ns() -> int:
    return time.monotonic_ns()


def wall_ns() -> int:
    return time.time_ns()


def hx(value: int) -> str:
    """Format an integer as an unsigned 64-bit ``0x`` hex string (contract form)."""
    return hex(value & 0xFFFFFFFFFFFFFFFF)


@dataclass
class Event:
    kind: str
    data: dict
    pid: int | None = None
    tid: int | None = None
    ts_mono: int = field(default_factory=mono_ns)
    ts_wall: int | None = None

    def record(self, seq: int) -> dict:
        rec: dict = {
            "schema_version": SCHEMA_VERSION,
            "seq": seq,
            "ts_mono": self.ts_mono,
            "kind": self.kind,
            "data": self.data,
        }
        if self.ts_wall is not None:
            rec["ts_wall"] = self.ts_wall
        if self.pid is not None:
            rec["pid"] = self.pid
        if self.tid is not None:
            rec["tid"] = self.tid
        return rec

    def summary(self) -> str:
        """Short searchable string indexed alongside the event for quick filtering."""
        d = self.data
        for key in ("path", "raddr", "target", "title", "name"):
            if d.get(key):
                return str(d[key])
        if d.get("dns", {}).get("qname"):
            return d["dns"]["qname"]
        return d.get("op", "")
