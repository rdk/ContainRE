"""L2 instruction-tracing engine as a mixin for PtraceTracer.

Holds the single-step window, the address-seek, and the Unicorn region driver.
The host tracer provides: ``emit``, ``debugger``, ``_md`` (Capstone), ``_killed``,
``l2_window``, ``l2_max_insns``, ``_l2_windows``, and ``_on_process_exit``.
"""
from __future__ import annotations

from signal import SIGTRAP

from ptrace.debugger import ProcessExit, ProcessSignal

from ..model import Event, Kind, hx
from . import l2 as l2mod
from . import unicorn_region


class L2Engine:
    def _safe_getreg(self, process, name: str) -> int:
        try:
            return process.getreg(name)
        except Exception:
            return 0

    def _gpregs(self, process) -> dict[str, int]:
        regs = process.getregs()
        out: dict[str, int] = {}
        for n in l2mod.GP_REGS:
            try:
                out[n] = getattr(regs, n)
            except AttributeError:
                pass
        return out

    def _single_step_window(self, process) -> str:
        """Single-step the specimen for a bounded window, emitting an `instr` event
        per instruction (disasm + register deltas + memory writes). Resumes normal
        syscall tracing when the window closes."""
        window_id = f"w-{self._l2_windows}"
        self._l2_windows += 1
        win = self.l2_window
        max_insns = int(win.get("max_insns", self.l2_max_insns))
        until_io = bool(win.get("until_io", False))
        addr_end = win.get("addr_end")
        addr_end = int(addr_end, 16) if isinstance(addr_end, str) else addr_end

        outcome = "closed"
        steps = 0
        while steps < max_insns and not self._killed.is_set():
            try:
                ip = process.getreg("rip")
                code = bytes(process.readBytes(ip, 15))
            except Exception:
                break
            insn = l2mod.disasm_one(self._md, code, ip)
            disasm = f"{insn.mnemonic} {insn.op_str}".strip() if insn else "(bad)"

            if until_io and insn and insn.mnemonic == "syscall":
                if self._safe_getreg(process, "rax") in l2mod.IO_SYSCALL_NRS:
                    outcome = "until_io"
                    break

            targets = l2mod.mem_write_targets(insn, lambda n: self._safe_getreg(process, n), ip)
            olds: dict[tuple[int, int], bytes] = {}
            for addr, size in targets:
                try:
                    olds[(addr, size)] = bytes(process.readBytes(addr, size))
                except Exception:
                    pass
            before = self._gpregs(process)

            try:
                process.singleStep()
                event = self.debugger.waitProcessEvent(pid=process.pid)
            except Exception:
                outcome = "error"
                break
            if isinstance(event, ProcessExit):
                self._on_process_exit(event)
                return "exited"
            if isinstance(event, ProcessSignal) and event.signum not in (SIGTRAP, SIGTRAP | 0x80):
                self.emit(Event(Kind.SIGNAL, {"signo": event.signum,
                                              "name": event.name or str(event.signum)},
                                pid=process.pid))
                outcome = "signal"
                break
            if not isinstance(event, ProcessSignal):
                outcome = "other"
                break

            after = self._gpregs(process)
            mem_writes = []
            for (addr, size), old in olds.items():
                try:
                    new = bytes(process.readBytes(addr, size))
                except Exception:
                    continue
                if new != old:
                    mem_writes.append({
                        "addr": hx(addr), "size": size,
                        "old": hx(int.from_bytes(old, "little")),
                        "new": hx(int.from_bytes(new, "little")),
                    })
            data = l2mod.instr_data(ip, disasm, window_id, "singlestep",
                                    before, after, mem_writes)
            self.emit(Event(Kind.INSTR, data, pid=process.pid))

            steps += 1
            if addr_end is not None and self._safe_getreg(process, "rip") == addr_end:
                outcome = "addr_end"
                break

        if outcome != "exited":
            try:
                process.syscall_state.clear()
                process.syscall()
            except Exception:
                pass
        return outcome

    def _seek_to(self, process, target: int, cap: int = 500000) -> str:
        """Single-step the live process until rip == target. Returns
        'reached' | 'exited' | 'missed'."""
        for _ in range(cap):
            if self._killed.is_set():
                return "missed"
            try:
                if process.getreg("rip") == target:
                    return "reached"
                process.singleStep()
                event = self.debugger.waitProcessEvent(pid=process.pid)
            except Exception:
                return "missed"
            if isinstance(event, ProcessExit):
                self._on_process_exit(event)
                return "exited"
        return "missed"

    def _unicorn_region(self, process) -> None:
        """Seed a Unicorn emulator from the live process at addr_start and emulate
        the region [addr_start, addr_end) without perturbing the specimen."""
        win = self.l2_window
        start = win.get("addr_start")
        end = win.get("addr_end")
        if not start or not end or not unicorn_region.have_unicorn():
            process.syscall()          # nothing to emulate; fall back to normal tracing
            return
        start = int(start, 16) if isinstance(start, str) else int(start)
        end = int(end, 16) if isinstance(end, str) else int(end)

        seek = self._seek_to(process, start)
        if seek == "exited":
            return
        if seek == "reached":
            window_id = f"u-{self._l2_windows}"
            self._l2_windows += 1
            unicorn_region.run_region(
                process, start, end,
                int(win.get("max_insns", self.l2_max_insns)),
                self.emit, self._md, window_id, pid=process.pid,
            )
        # resume normal syscall tracing from wherever the live process is stopped
        try:
            process.syscall_state.clear()
            process.syscall()
        except Exception:
            pass
