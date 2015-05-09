"""L2 instruction-level tracing helpers: Capstone disassembly and x86-64
memory-write operand analysis.

Used by the single-step engine in ptrace_tracer to turn each stepped instruction
into a structured ``instr`` event (contracts/events.v1.schema.json §instr).
"""
from __future__ import annotations

from typing import Callable

from ..model import hx

try:
    from capstone import CS_ARCH_X86, CS_AC_WRITE, CS_MODE_64, CS_OP_MEM, Cs
    _HAVE_CAPSTONE = True
except ImportError:  # pragma: no cover - capstone is a hard dep, but stay defensive
    _HAVE_CAPSTONE = False

_MASK = (1 << 64) - 1

# Registers tracked for reg_deltas (x86-64 user_regs_struct field names).
GP_REGS = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "rip", "eflags",
]

# Syscall numbers we treat as "I/O" for the until_io window bound (x86-64).
IO_SYSCALL_NRS = {
    0, 1, 2, 3, 17, 18, 19, 20, 40, 41, 42, 43, 44, 45, 46, 47, 257,
}


def have_capstone() -> bool:
    return _HAVE_CAPSTONE


def make_disassembler():
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def disasm_one(md, code: bytes, ip: int):
    """Disassemble the single instruction at ``ip`` (or None)."""
    return next(md.disasm(bytes(code), ip), None)


def reg_deltas(before: dict[str, int], after: dict[str, int]) -> dict[str, dict]:
    """Registers that changed, formatted as {name: {old, new}} hex strings."""
    return {n: {"old": hx(before[n]), "new": hx(after[n])}
            for n in before if before.get(n) != after.get(n)}


def instr_data(ip: int, disasm: str, window_id: str, engine: str,
               before: dict[str, int], after: dict[str, int],
               mem_writes: list[dict]) -> dict:
    """Assemble an `instr` event payload shared by both L2 engines."""
    data: dict = {"ip": hx(ip), "disasm": disasm, "window_id": window_id, "engine": engine}
    deltas = reg_deltas(before, after)
    if deltas:
        data["reg_deltas"] = deltas
    if mem_writes:
        data["mem_writes"] = mem_writes
    return data


def mem_write_targets(insn, get_reg: Callable[[str], int], ip: int) -> list[tuple[int, int]]:
    """Return [(effective_address, size), ...] for the instruction's *written*
    memory operands, computing addresses from the pre-step register values."""
    if insn is None or not _HAVE_CAPSTONE:
        return []
    try:
        operands = insn.operands
    except Exception:
        return []
    targets: list[tuple[int, int]] = []
    for op in operands:
        if op.type != CS_OP_MEM or not (op.access & CS_AC_WRITE):
            continue
        m = op.mem
        addr = m.disp
        if m.base != 0:
            name = insn.reg_name(m.base)
            if name == "rip":
                addr += ip + insn.size       # rip-relative is from the next instruction
            elif name:
                addr += get_reg(name)
        if m.index != 0:
            name = insn.reg_name(m.index)
            if name:
                addr += get_reg(name) * m.scale
        targets.append((addr & _MASK, op.size or 8))
    return targets
