"""L2 instruction-level tracing tests (ptrace single-step + Unicorn region engines)."""
from __future__ import annotations

import subprocess

import pytest

from containre import contracts

pytestmark = pytest.mark.specimen


def _instrs(result):
    return [e for e in result.events() if e["kind"] == "instr"]


def _compute_region(binpath) -> tuple[str, str]:
    """Discover l2demo's compute() [addr, addr+size) from the symbol table."""
    out = subprocess.check_output(
        ["nm", "--print-size", "--defined-only", str(binpath)], text=True)
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[-1] == "compute":
            addr = int(parts[0], 16)
            size = int(parts[1], 16) if len(parts) == 4 else 0x28
            return hex(addr), hex(addr + size)
    raise AssertionError("compute symbol not found in l2demo")


def _l2(harness, name, **window):
    return harness(name, trace={"l2": {"mode": "singlestep", "window": window}})


def test_l2_off_by_default(harness):
    r = harness("l2demo")
    assert _instrs(r) == []                      # no L2 unless requested


def test_l2_single_step_emits_instructions(harness):
    r = _l2(harness, "l2demo", max_insns=2000)
    assert r.status == "finished" and r.exit_code == 38
    instrs = _instrs(r)
    assert len(instrs) > 15                       # a short but real stream
    # disassembly + window id + IPs are present and monotone in a straight run
    for e in instrs:
        d = e["data"]
        assert d["disasm"] and d["window_id"].startswith("w-")
        assert d["ip"].startswith("0x")


def test_l2_captures_register_deltas(harness):
    instrs = _instrs(_l2(harness, "l2demo", max_insns=2000))
    # rip changes every instruction; at least one instruction changes a GP register
    assert any("rip" in e["data"].get("reg_deltas", {}) for e in instrs)
    assert any(set(e["data"].get("reg_deltas", {})) - {"rip", "eflags"} for e in instrs)


def test_l2_captures_memory_writes(harness):
    instrs = _instrs(_l2(harness, "l2demo", max_insns=2000))
    writes = [w for e in instrs for w in e["data"].get("mem_writes", [])]
    assert writes, "expected at least one captured memory write"
    # the arithmetic result 38 (0x26) is written to the stack slot
    assert any(w["new"] == "0x26" for w in writes)
    for w in writes:
        assert w["addr"].startswith("0x") and "old" in w and "new" in w


def test_l2_max_insns_bounds_the_window(harness):
    r = _l2(harness, "hello", max_insns=200)       # stop deep inside loader init
    instrs = _instrs(r)
    assert 0 < len(instrs) <= 200
    # window closed -> normal tracing resumed -> program still completed
    assert r.status == "finished"


def test_l2_until_io_hands_back_to_syscall_tracing(harness):
    r = _l2(harness, "hello", until_io=True, max_insns=1_000_000)
    assert r.status == "finished" and r.exit_code == 0
    assert _instrs(r), "expected instructions stepped up to the first I/O"
    # after the window handed back, the I/O actually happened
    assert "hello from specimen" in (r.run_dir / "console.log").read_text()


def test_l2_events_conform_to_schema(harness):
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    for e in _instrs(_l2(harness, "l2demo", max_insns=2000)):
        errors = contracts.validate(e, "events.v1.schema.json")
        assert not errors, f"instr seq={e['seq']}: {errors}"


# -- Unicorn region engine -------------------------------------------------
def _unicorn(harness, build_specimen, **extra_window):
    start, end = _compute_region(build_specimen("l2demo"))
    window = {"addr_start": start, "addr_end": end, "max_insns": 100, **extra_window}
    return harness("l2demo", trace={"l2": {"mode": "unicorn", "window": window}})


def test_unicorn_region_emulates_isolated_function(harness, build_specimen):
    r = _unicorn(harness, build_specimen)
    instrs = _instrs(r)
    assert instrs, "expected emulated instructions"
    assert all(e["data"]["engine"] == "unicorn" for e in instrs)
    # the emulated arithmetic 5*7+3 reaches 38 (0x26) in rax
    assert any(e["data"].get("reg_deltas", {}).get("rax", {}).get("new") == "0x26"
               for e in instrs)


def test_unicorn_region_captures_memory_writes(harness, build_specimen):
    writes = [w for e in _instrs(_unicorn(harness, build_specimen))
              for w in e["data"].get("mem_writes", [])]
    assert any(w["old"] == "0x23" and w["new"] == "0x26" for w in writes)


def test_unicorn_region_does_not_perturb_live_process(harness, build_specimen):
    # emulation is a side-observation; the real process still runs to completion
    r = _unicorn(harness, build_specimen)
    assert r.status == "finished" and r.exit_code == 38


def test_unicorn_region_conforms_to_schema(harness, build_specimen):
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    for e in _instrs(_unicorn(harness, build_specimen)):
        errors = contracts.validate(e, "events.v1.schema.json")
        assert not errors, f"instr seq={e['seq']}: {errors}"
