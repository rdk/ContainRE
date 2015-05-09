"""Unicorn L2 *region* engine: emulate an isolated code region seeded from the live
process, without touching it (SPEC §5).

We copy the live registers into a Unicorn CPU and lazily page in memory from the
stopped specimen (/proc-backed reads via python-ptrace) whenever the emulation
touches an unmapped address. Emulation runs from ``start`` and stops when execution
leaves the region [start, end), hits a syscall, exceeds ``max_insns``, or errors.
Each emulated instruction is emitted as an ``instr`` event (engine=unicorn), same
shape as the single-step engine.
"""
from __future__ import annotations

from typing import Callable

from ..model import Event, Kind, hx
from . import l2 as l2mod

try:
    from unicorn import (
        UC_ARCH_X86,
        UC_HOOK_CODE,
        UC_HOOK_INSN,
        UC_HOOK_MEM_WRITE,
        UC_HOOK_MEM_UNMAPPED,
        UC_MODE_64,
        Uc,
        UcError,
    )
    from unicorn.x86_const import (
        UC_X86_INS_SYSCALL,
        UC_X86_REG_EFLAGS,
        UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
        UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
        UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RCX,
        UC_X86_REG_RDI, UC_X86_REG_RDX, UC_X86_REG_RIP, UC_X86_REG_RSI,
        UC_X86_REG_RSP,
    )
    _HAVE_UNICORN = True
except ImportError:  # pragma: no cover
    _HAVE_UNICORN = False

_PAGE = 0x1000
_MASK = (1 << 64) - 1

if _HAVE_UNICORN:
    _REG_MAP = {
        "rax": UC_X86_REG_RAX, "rbx": UC_X86_REG_RBX, "rcx": UC_X86_REG_RCX,
        "rdx": UC_X86_REG_RDX, "rsi": UC_X86_REG_RSI, "rdi": UC_X86_REG_RDI,
        "rbp": UC_X86_REG_RBP, "rsp": UC_X86_REG_RSP, "r8": UC_X86_REG_R8,
        "r9": UC_X86_REG_R9, "r10": UC_X86_REG_R10, "r11": UC_X86_REG_R11,
        "r12": UC_X86_REG_R12, "r13": UC_X86_REG_R13, "r14": UC_X86_REG_R14,
        "r15": UC_X86_REG_R15, "rip": UC_X86_REG_RIP, "eflags": UC_X86_REG_EFLAGS,
    }
else:  # pragma: no cover
    _REG_MAP = {}


def have_unicorn() -> bool:
    return _HAVE_UNICORN


def _align_down(x: int) -> int:
    return x & ~(_PAGE - 1)


def run_region(process, start: int, end: int, max_insns: int,
               emit: Callable[[Event], None], md, window_id: str, pid: int | None = None) -> dict:
    """Emulate [start, end) seeded from ``process``. Returns a summary dict."""
    if not _HAVE_UNICORN:
        return {"error": "unicorn not available"}

    uc = Uc(UC_ARCH_X86, UC_MODE_64)
    mapped: set[int] = set()

    def _map_from_live(base: int, length: int) -> None:
        base = _align_down(base)
        length = ((length + (_PAGE - 1)) // _PAGE) * _PAGE
        for off in range(0, length, _PAGE):
            page = base + off
            if page in mapped:
                continue
            try:
                uc.mem_map(page, _PAGE)
            except UcError:
                mapped.add(page)
                continue
            mapped.add(page)
            try:
                data = bytes(process.readBytes(page, _PAGE))
            except Exception:
                data = b""
            if data:
                uc.mem_write(page, data[:_PAGE])

    # Seed registers from the live (stopped) process.
    for name, reg in _REG_MAP.items():
        try:
            uc.reg_write(reg, process.getreg(name))
        except Exception:
            pass

    # Pre-map the code region and a stack window; the rest is lazily paged in.
    _map_from_live(start, max(end - _align_down(start), _PAGE) + _PAGE)
    try:
        rsp = process.getreg("rsp")
        _map_from_live(rsp - 0x4000, 0x8000)
    except Exception:
        pass

    state: dict = {"pending": None, "count": 0, "stop": None}

    def _regs() -> dict:
        return {n: uc.reg_read(r) for n, r in _REG_MAP.items()}

    def _finalize(after: dict) -> None:
        p = state["pending"]
        if p is None:
            return
        data = l2mod.instr_data(p["ip"], p["disasm"], window_id, "unicorn",
                                p["before"], after, p["writes"])
        emit(Event(Kind.INSTR, data, pid=pid))
        state["pending"] = None

    def _hook_code(uc_, address, size, _ud):
        # finalize the previous instruction with the now-current registers
        _finalize(_regs())
        if not (start <= address < end):
            state["stop"] = "region-exit"
            uc_.emu_stop()
            return
        if state["count"] >= max_insns:
            state["stop"] = "max_insns"
            uc_.emu_stop()
            return
        try:
            code = bytes(uc_.mem_read(address, size))
        except UcError:
            code = b""
        insn = next(md.disasm(code, address), None) if code else None
        disasm = f"{insn.mnemonic} {insn.op_str}".strip() if insn else "(bad)"
        state["pending"] = {"ip": address, "disasm": disasm, "before": _regs(), "writes": []}
        state["count"] += 1

    def _hook_write(uc_, _access, address, size, value, _ud):
        p = state["pending"]
        if p is None:
            return
        try:
            old = int.from_bytes(bytes(uc_.mem_read(address, size)), "little")
        except UcError:
            old = 0
        p["writes"].append({"addr": hx(address), "size": size,
                            "old": hx(old), "new": hx(value & _MASK)})

    def _hook_unmapped(uc_, _access, address, size, _value, _ud):
        _map_from_live(address, size + _PAGE)
        return True  # retry the faulting access

    def _hook_syscall(uc_, _ud):
        state["stop"] = "syscall"
        uc_.emu_stop()

    uc.hook_add(UC_HOOK_CODE, _hook_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, _hook_write)
    uc.hook_add(UC_HOOK_MEM_UNMAPPED, _hook_unmapped)
    uc.hook_add(UC_HOOK_INSN, _hook_syscall, None, 1, 0, UC_X86_INS_SYSCALL)

    try:
        uc.emu_start(start, end, count=max_insns)
    except UcError as exc:
        state["stop"] = state["stop"] or f"error:{exc}"
    # finalize the last in-region instruction
    _finalize(_regs())

    final = _regs()
    return {"instrs": state["count"], "stop_reason": state["stop"] or "until",
            "final_regs": {n: hx(v) for n, v in final.items()}}
