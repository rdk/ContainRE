"""Minimal ELF fact extraction for meta.json (arch, linkage, libc, interp, PIE).

Just enough to drive base-image/loader selection and record provenance - not a
full ELF parser.
"""
from __future__ import annotations

import struct
from pathlib import Path

_E_MACHINE = {0x3E: "x86-64", 0xB7: "aarch64", 0x03: "x86", 0x28: "arm"}
_PT_INTERP = 3


def elf_facts(path: str | Path) -> dict:
    facts: dict = {"arch": None, "linkage": "unknown", "libc": "unknown",
                   "interp": None, "pie": None}
    try:
        data = Path(path).read_bytes()
    except OSError:
        return facts
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return facts

    is64 = data[4] == 2
    little = data[5] == 1
    en = "<" if little else ">"
    e_type = struct.unpack_from(en + "H", data, 16)[0]
    e_machine = struct.unpack_from(en + "H", data, 18)[0]
    facts["arch"] = _E_MACHINE.get(e_machine, f"machine-{e_machine}")
    facts["pie"] = e_type == 3  # ET_DYN

    if is64:
        e_phoff = struct.unpack_from(en + "Q", data, 32)[0]
        e_phentsize = struct.unpack_from(en + "H", data, 54)[0]
        e_phnum = struct.unpack_from(en + "H", data, 56)[0]
    else:
        e_phoff = struct.unpack_from(en + "I", data, 28)[0]
        e_phentsize = struct.unpack_from(en + "H", data, 42)[0]
        e_phnum = struct.unpack_from(en + "H", data, 44)[0]

    interp = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        if off + 8 > len(data):
            break
        p_type = struct.unpack_from(en + "I", data, off)[0]
        if p_type != _PT_INTERP:
            continue
        if is64:
            p_offset = struct.unpack_from(en + "Q", data, off + 8)[0]
            p_filesz = struct.unpack_from(en + "Q", data, off + 32)[0]
        else:
            p_offset = struct.unpack_from(en + "I", data, off + 4)[0]
            p_filesz = struct.unpack_from(en + "I", data, off + 16)[0]
        interp = data[p_offset:p_offset + p_filesz].split(b"\x00", 1)[0].decode("utf-8", "replace")
        break

    if interp:
        facts["linkage"] = "dynamic"
        facts["interp"] = interp
        low = interp.lower()
        facts["libc"] = "musl" if "musl" in low else ("glibc" if "ld-linux" in low or "ld.so" in low else "unknown")
    else:
        facts["linkage"] = "static"
        facts["libc"] = "none"
    return facts
