"""Unit tests for the low-level helpers (no ptrace, no subprocess): syscall
decoding, ELF facts, memory-snapshot I/O, L2 operand analysis, the Verdict
accumulator, store queries, and sink protocol detection."""
from __future__ import annotations

import json
import socket
import struct

import pytest

from containre import contracts
from containre.control.elf import elf_facts
from containre.control.verdict import Verdict
from containre.memory import snapshot as snap
from containre.model import Event, Kind
from containre.store import RunStore
from containre.tracer import l2, syscalls as sc


def test_validate_warns_when_contracts_missing(monkeypatch):
    import containre.contracts as c
    monkeypatch.setattr(c, "load_schema", lambda name: None)   # simulate no contracts dir
    c._warned_no_schema = False
    with pytest.warns(RuntimeWarning):
        assert c.validate({"anything": 1}, "policy.v1.schema.json") == []


def test_emitted_net_ops_and_protos_conform():
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    # ops/protos the tracer + sink actually emit under the default simulate posture
    for data in [
        {"op": "connect_result", "proto": "tcp", "decision": "allow", "success": True},
        {"op": "socket_error", "proto": "tcp", "status": "ok"},
        {"op": "h2-grpc-replay", "proto": "h2"},
        {"op": "connect", "proto": "tls"},
    ]:
        ev = {"schema_version": 1, "seq": 0, "ts_mono": 1, "kind": "net", "data": data}
        assert contracts.validate(ev, "events.v1.schema.json") == [], data


def test_queued_meta_with_null_runtime_conforms():
    if contracts.find_contracts_dir() is None:
        pytest.skip("contracts dir not found")
    # exactly what create_run writes before a backend is assigned / docker absent.
    meta = {
        "schema_version": 1,
        "run_id": "20260101T000000Z_x_abc123_0000",
        "status": "queued",
        "specimen": {"path": "/bin/true", "sha256": "0" * 64, "size": 1, "elf": {}},
        "image": None,
        "runtime": None,
        "policy_ref": "policy.yaml",
        "created_wall": 1,
        "host": {"kernel": "test", "docker": None, "criu": None, "containre": "0"},
    }
    assert contracts.validate(meta, "meta.v1.schema.json") == []

pytestmark = pytest.mark.unit


# -- syscalls.parse_sockaddr ----------------------------------------------
def _sa_in(ip: str, port: int) -> bytes:
    return struct.pack("H", sc.AF_INET) + struct.pack("!H", port) + socket.inet_aton(ip) + b"\x00" * 8


def _sa_in6(ip: str, port: int) -> bytes:
    return (struct.pack("H", sc.AF_INET6) + struct.pack("!H", port) + b"\x00" * 4
            + socket.inet_pton(socket.AF_INET6, ip) + b"\x00" * 4)


def test_parse_sockaddr_ipv4():
    fam, ip, target = sc.parse_sockaddr(_sa_in("1.2.3.4", 443))
    assert fam == sc.AF_INET and ip == "1.2.3.4" and target == "1.2.3.4:443"


def test_parse_sockaddr_ipv6():
    fam, ip, target = sc.parse_sockaddr(_sa_in6("2001:db8::1", 80))
    assert fam == sc.AF_INET6 and ip == "2001:db8::1" and target == "[2001:db8::1]:80"


def test_parse_sockaddr_unix():
    raw = struct.pack("H", sc.AF_UNIX) + b"/run/x.sock\x00"
    fam, path, target = sc.parse_sockaddr(raw)
    assert fam == sc.AF_UNIX and path == "/run/x.sock" and target == "unix:/run/x.sock"


def test_parse_sockaddr_garbage():
    assert sc.parse_sockaddr(b"") == (-1, None, None)
    fam, ip, target = sc.parse_sockaddr(struct.pack("H", sc.AF_INET) + b"\x00")  # truncated
    assert ip is None and target is None


def test_perms_and_proto():
    assert sc.perms_from_prot(sc.PROT_READ | sc.PROT_EXEC) == "r-x"
    assert sc.perms_from_prot(sc.PROT_READ | sc.PROT_WRITE) == "rw-"
    assert sc.proto_name(sc.AF_INET) == "tcp" and sc.proto_name(sc.AF_UNIX) == "unix"


# -- elf.elf_facts ---------------------------------------------------------
def test_elf_facts_dynamic(build_specimen):
    facts = elf_facts(build_specimen("hello"))
    assert facts["arch"] == "x86-64"
    assert facts["linkage"] == "dynamic" and facts["libc"] == "glibc"
    assert facts["interp"] and facts["pie"] is True


def test_elf_facts_static(build_specimen):
    facts = elf_facts(build_specimen("l2demo"))  # static, no-PIE, nostdlib
    assert facts["arch"] == "x86-64"
    assert facts["linkage"] == "static" and facts["libc"] == "none"
    assert facts["interp"] is None and facts["pie"] is False


def test_elf_facts_non_elf(tmp_path):
    p = tmp_path / "notelf"
    p.write_bytes(b"this is not an ELF file")
    facts = elf_facts(p)
    assert facts["arch"] is None and facts["linkage"] == "unknown"


def test_elf_facts_survives_truncated_program_header(tmp_path):
    # 72-byte ELF64 claiming one 56-byte PT_INTERP program header at e_phoff=64,
    # but the file is too short to hold it -> used to raise struct.error.
    data = bytearray(72)
    data[0:4] = b"\x7fELF"
    data[4] = 2   # 64-bit
    data[5] = 1   # little-endian
    struct.pack_into("<H", data, 16, 2)     # e_type = ET_EXEC
    struct.pack_into("<H", data, 18, 0x3E)  # e_machine = x86-64
    struct.pack_into("<Q", data, 32, 64)    # e_phoff = 64
    struct.pack_into("<H", data, 54, 56)    # e_phentsize
    struct.pack_into("<H", data, 56, 1)     # e_phnum = 1
    struct.pack_into("<I", data, 64, 3)     # p_type = PT_INTERP (only 8 bytes remain)
    p = tmp_path / "evil.bin"
    p.write_bytes(bytes(data))

    facts = elf_facts(p)   # must not raise

    assert facts["arch"] == "x86-64"
    assert facts["linkage"] in ("static", "dynamic", "unknown")


# -- memory snapshot I/O ---------------------------------------------------
def _blob(tmp_path):
    header = {"pid": 7, "regions": [
        {"base": "0x1000", "size": 0x2000, "perms": "r-x", "path": "", "dumped": 16},
        {"base": "0x4000", "size": 0x1000, "perms": "rw-", "path": "[heap]", "dumped": 8},
    ]}
    body = b"A" * 16 + b"B" * 8
    path = tmp_path / "snap-deadbeef.bin"
    path.write_bytes(json.dumps(header).encode() + b"\n" + body)
    return path, header, body


def test_wide_mem_write_values_are_not_truncated_to_64_bits():
    from containre.model import hx
    old = bytes(16)                       # 16-byte SIMD store, all zero
    new = bytes(8) + b"\x01" + bytes(7)   # differs only in a byte above the low 64 bits
    # hx() masks to 64 bits, rendering both as 0x0 -> a phantom no-op write...
    assert hx(int.from_bytes(old, "little")) == hx(int.from_bytes(new, "little")) == "0x0"
    # ...whereas full-width hex (the fix) distinguishes them.
    assert hex(int.from_bytes(old, "little")) != hex(int.from_bytes(new, "little"))


def test_capture_skips_high_kernel_addresses_without_crashing(monkeypatch):
    import os
    # a [vsyscall]-style region at 0xffffffffff600000 (>= 2**63) must be skipped,
    # not seek()'d (which raised an uncaught OverflowError and dropped the snapshot).
    monkeypatch.setattr(snap, "_read_maps", lambda pid: [
        {"base": "0xffffffffff600000", "size": 0x1000, "perms": "r-xp", "path": "[vsyscall]"},
    ])
    blob, meta, total = snap.capture(os.getpid())
    assert total == 1        # region was seen/counted
    assert meta == []        # but not dumped, and no exception propagated


def test_snapshot_load_and_region_slice(tmp_path):
    path, header, body = _blob(tmp_path)
    h, b = snap.load(path)
    assert h["pid"] == 7 and b == body
    data, region = snap.region_slice(h, b, "0x4000")
    assert data == b"B" * 8 and region["path"] == "[heap]"
    first, r0 = snap.region_slice(h, b, None)          # default = first region
    assert first == b"A" * 16 and r0["base"] == "0x1000"


def test_snapshot_hexdump():
    out = snap.hexdump(b"AB\x00\xff", base=0x1000)
    assert out.startswith("000000001000")
    assert "41 42 00 ff" in out
    assert "AB.." in out            # non-printables become '.'


# -- l2 operand analysis + helpers ----------------------------------------
def test_mem_write_targets_rbp_relative():
    md = l2.make_disassembler()
    code = b"\x48\x89\x45\xf8"                # mov [rbp-8], rax
    insn = l2.disasm_one(md, code, 0x400000)
    targets = l2.mem_write_targets(insn, {"rbp": 0x1000}.get, 0x400000)
    assert targets == [(0x1000 - 8, 8)]


def test_mem_write_targets_rip_relative():
    md = l2.make_disassembler()
    code = b"\x48\x89\x05\x10\x00\x00\x00"    # mov [rip+0x10], rax
    insn = l2.disasm_one(md, code, 0x2000)
    targets = l2.mem_write_targets(insn, lambda n: 0, 0x2000)
    assert targets == [(0x2000 + insn.size + 0x10, 8)]


def test_reg_deltas_and_instr_data():
    before = {"rax": 1, "rip": 0x10, "rbx": 5}
    after = {"rax": 2, "rip": 0x14, "rbx": 5}
    deltas = l2.reg_deltas(before, after)
    assert set(deltas) == {"rax", "rip"} and deltas["rax"] == {"old": "0x1", "new": "0x2"}
    data = l2.instr_data(0x10, "nop", "w-0", "singlestep", before, after, [])
    assert data["ip"] == "0x10" and data["engine"] == "singlestep"
    assert "reg_deltas" in data and "mem_writes" not in data


# -- Verdict ---------------------------------------------------------------
def test_verdict_accumulates_severity_flags_attack():
    v = Verdict()
    v.absorb({"severity": "low", "id": "rwx-memory", "attack": ["T1055"]})
    v.absorb({"severity": "critical", "id": "decoy-access", "attack": ["T1657"]})
    v.absorb({"severity": "medium", "id": "unknown-x"})     # unmapped id passes through
    d = v.to_dict()
    assert d["max_severity"] == "critical"
    assert d["attack"] == ["T1055", "T1657"]
    assert set(d["flags"]) == {"executable-memory", "decoy-hit", "unknown-x"}


# -- RunStore queries ------------------------------------------------------
def test_store_query_and_snapshot(tmp_path):
    with RunStore(tmp_path) as st:
        st.write_event(Event(Kind.NET, {"op": "connect", "raddr": "1.2.3.4:80"}))
        st.write_event(Event(Kind.FILE, {"op": "write", "path": "/x"}))
        st.write_event(Event(Kind.NET, {"op": "socket"}))
        sid = st.add_snapshot(b"blobdata", suffix="bin")
        assert st.query(kind="net") and len(st.query(kind="net")) == 2
        assert len(st.query(op="connect")) == 1
    assert sid.startswith("snap-")
    assert (tmp_path / "snapshots" / f"{sid}.bin").read_bytes() == b"blobdata"


def test_index_self_heals_from_jsonl_on_reopen(tmp_path):
    d = tmp_path / "run"
    with RunStore(d) as st:
        for _ in range(10):
            st.write_event(Event(Kind.PROC, {"op": "noop"}))
    # simulate a crash: 5 more events reached the line-buffered JSONL but the
    # SQLite commit was lost.
    with open(d / "events.jsonl", "a") as fh:
        for seq in range(10, 15):
            fh.write(json.dumps({"schema_version": 1, "seq": seq, "ts_mono": seq,
                                 "kind": "proc", "data": {"op": "noop"}}) + "\n")

    st2 = RunStore(d)   # reopen -> reconcile the index from the log
    try:
        assert len(st2.query(limit=100)) == 15   # index healed to match events.jsonl
        assert st2._seq == 15                     # seq counter continues, no reuse
    finally:
        st2.close()


def test_index_self_heals_when_last_record_exceeds_tail_window(tmp_path):
    d = tmp_path / "run"
    with RunStore(d) as st:
        st.write_event(Event(Kind.PROC, {"op": "noop"}))   # seq 0, committed
    # a lost-commit final record whose single line is > the 64KB tail window
    big = "x" * 70000
    with open(d / "events.jsonl", "a") as fh:
        fh.write(json.dumps({"schema_version": 1, "seq": 1, "ts_mono": 1,
                             "kind": "proc", "data": {"op": "noop", "blob": big}}) + "\n")

    st2 = RunStore(d)   # the tail-read can't parse the huge last line -> must full-scan
    try:
        assert len(st2.query(limit=100)) == 2   # both events indexed, not just seq 0
        assert st2._seq == 2
    finally:
        st2.close()


# -- policy defaults / deep-merge -----------------------------------------
def test_policy_deep_merge_preserves_untouched_defaults():
    from containre import policy as P
    pol = P.policy_for_binary("/bin/true", network={"posture": "deny"})
    assert pol["network"]["posture"] == "deny"      # overridden
    assert pol["network"]["mitm"] is False          # sibling default kept
    assert pol["limits"]["wallclock_s"] == 120       # unrelated default kept
    assert pol["trace"]["l2"]["mode"] == "off"
    assert pol["specimen"]["container_path"] is None
    assert pol["files"]["read_only_mounts"] == []
    assert pol["instrumentation"]["tls_plaintext"]["mode"] == "observe"
    assert pol["runtime"]["command_shell"] == "/bin/sh"
    assert pol["runtime"]["docker_user"] is None


def test_policy_for_binary_nested_override():
    from containre import policy as P
    pol = P.policy_for_binary("/bin/true",
                              trace={"l2": {"mode": "singlestep", "window": {"max_insns": 5}}})
    assert pol["trace"]["l2"]["mode"] == "singlestep"
    assert pol["trace"]["l2"]["window"]["max_insns"] == 5
    assert pol["trace"]["snapshot_on"] == ["connect", "mmap+x", "exec"]  # sibling kept


# -- DockerRuntime command construction (pure, no daemon) -----------------
def test_docker_network_args_by_posture():
    from containre.runtime.docker import DockerRuntime
    rt = DockerRuntime()
    assert rt._network_args({"network": {"posture": "deny"}}) == ["--network", "none"]
    assert rt._network_args({"network": {"posture": "simulate"}}) == ["--network", "none"]
    assert rt._network_args({"network": {"posture": "allow"}}) == []


def test_docker_read_only_mount_args(tmp_path):
    from containre.runtime.docker import DockerRuntime
    source = tmp_path / "suite"
    source.mkdir()
    rt = DockerRuntime()

    args = rt._read_only_mount_args({
        "files": {"read_only_mounts": [{"source": str(source), "target": "/opt/suite"}]},
    })

    assert args == ["-v", f"{source.resolve()}:/opt/suite:ro"]


def test_docker_read_only_mount_rejects_relative_target(tmp_path):
    from containre.runtime.docker import DockerError, DockerRuntime
    source = tmp_path / "suite"
    source.mkdir()
    rt = DockerRuntime()

    with pytest.raises(DockerError):
        rt._read_only_mount_args({
            "files": {"read_only_mounts": [{"source": str(source), "target": "opt/suite"}]},
        })


def test_docker_container_specimen_path_default_and_custom():
    from containre.runtime.docker import DockerRuntime
    rt = DockerRuntime()

    assert rt._container_specimen_path({}) == "/specimen"
    assert rt._container_specimen_path({
        "specimen": {"container_path": "/opt/suite/tool"},
    }) == "/opt/suite/tool"


def test_docker_container_specimen_path_rejects_relative():
    from containre.runtime.docker import DockerError, DockerRuntime
    rt = DockerRuntime()

    with pytest.raises(DockerError):
        rt._container_specimen_path({"specimen": {"container_path": "tool"}})


def test_docker_user_args():
    from containre.runtime.docker import DockerError, DockerRuntime
    rt = DockerRuntime()

    assert rt._docker_user_args({}) == []
    assert rt._docker_user_args({"runtime": {"docker_user": "1000:1000"}}) == ["--user", "1000:1000"]
    with pytest.raises(DockerError):
        rt._docker_user_args({"runtime": {"docker_user": "../1000"}})


# -- CRIU checkpoint: graceful degradation (best-effort) ------------------
def test_local_runtime_checkpoint_unavailable():
    from pathlib import Path
    from containre.interfaces import RunHandle
    from containre.runtime import LocalRuntime
    r = LocalRuntime().checkpoint(RunHandle(run_dir=Path("/x"), runtime="local"))
    assert r["ok"] is False and "docker" in r["reason"]


def test_docker_runtime_checkpoint_degrades_cleanly():
    from pathlib import Path
    from containre.interfaces import RunHandle
    from containre.runtime import DockerRuntime
    rt = DockerRuntime()
    # no container attached -> clear reason, never raises
    no_c = rt.checkpoint(RunHandle(run_dir=Path("/x"), runtime="docker"))
    assert no_c["ok"] is False and "container" in no_c["reason"]
    # with a container but experimental features off (this env) -> structured reason
    with_c = rt.checkpoint(RunHandle(run_dir=Path("/x"), runtime="docker", container="nope"))
    assert with_c["ok"] is False and isinstance(with_c["reason"], str) and with_c["reason"]


# -- BuiltinSink generic (non-HTTP) protocol ------------------------------
@pytest.mark.localnet
def test_builtin_sink_generic_tcp():
    from containre.net import BuiltinSink

    seen = []
    sink = BuiltinSink(on_interaction=seen.append)
    sink.start()
    try:
        c = socket.create_connection(("127.0.0.1", sink.port), timeout=2)
        c.sendall(b"HELO mailserver\r\n")
        banner = c.recv(64)
        c.close()
    finally:
        sink.stop()
    assert b"220 containre-sink ready" in banner
    assert seen and seen[0]["op"] == "recv" and "HELO" in seen[0]["preview"]
