from __future__ import annotations

import ctypes
import json
import shutil
import subprocess
from pathlib import Path

import pytest

from containre.control import instrumentation as inst
from containre.interfaces import Job

pytestmark = pytest.mark.unit


def _job(tmp_path: Path, policy: dict) -> Job:
    run_dir = tmp_path / "run"
    work = run_dir / "work"
    work.mkdir(parents=True)
    (run_dir / "meta.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": "run",
        "status": "queued",
        "specimen": {"sha256": "0" * 64},
        "created_wall": 1,
    }))
    return Job(
        run_dir=run_dir,
        specimen_path="/bin/true",
        args=[],
        env={},
        cwd=str(work),
        policy=policy,
    )


def test_tls_plaintext_configure_observe_injects_env_and_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(inst, "_compile_tls_library", lambda output: output.write_bytes(b"so"))
    job = _job(tmp_path, {
        "instrumentation": {
            "tls_plaintext": {
                "enabled": True,
                "provider": "openssl-preload",
                "mode": "observe",
                "max_bytes_per_record": 1234,
            },
        },
    })

    meta = inst.configure_tls_plaintext(job, visible_workdir="/work")

    assert meta["enabled"] is True
    assert meta["mode"] == "observe"
    assert meta["invasive"] is True
    assert meta["experimental"] is False
    assert job.env["LD_PRELOAD"] == "/work/libcontainre_tls_plaintext_capture.so"
    assert job.env["CONTAINRE_TLS_MODE"] == "observe"
    assert job.env["CONTAINRE_TLS_CAPTURE"] == "/work/tls_plaintext_capture.log"
    assert job.env["CONTAINRE_TLS_CAPTURE_MAX"] == "1234"
    saved = json.loads((job.run_dir / "meta.json").read_text())
    assert saved["instrumentation"]["tls_plaintext"]["invasive"] is True


def test_tls_plaintext_configure_replay_requires_replay_file(tmp_path, monkeypatch):
    monkeypatch.setattr(inst, "_compile_tls_library", lambda output: output.write_bytes(b"so"))
    job = _job(tmp_path, {
        "instrumentation": {
            "tls_plaintext": {
                "enabled": True,
                "mode": "replay",
            },
        },
    })

    with pytest.raises(inst.InstrumentationError, match="requires replay_file"):
        inst.configure_tls_plaintext(job, visible_workdir="/work")


def test_tls_plaintext_configure_replay_copies_transcript_and_preserves_preload(tmp_path, monkeypatch):
    monkeypatch.setattr(inst, "_compile_tls_library", lambda output: output.write_bytes(b"so"))
    replay = tmp_path / "replay.jsonl"
    replay.write_text('{"direction":"in","hex":"6869"}\n')
    job = _job(tmp_path, {
        "instrumentation": {
            "tls_plaintext": {
                "enabled": True,
                "mode": "replay",
                "replay_file": str(replay),
                "output": "/work/custom.jsonl",
                "fake_handshake": True,
                "libssl": "/opt/app/libssl.so.3",
            },
        },
    })
    job.env["LD_PRELOAD"] = "/work/existing.so"

    meta = inst.configure_tls_plaintext(job, visible_workdir="/work")

    assert meta["experimental"] is True
    assert meta["replay_runtime_path"] == "/work/tls_plaintext_replay.jsonl"
    assert (Path(job.cwd) / "tls_plaintext_replay.jsonl").read_text() == replay.read_text()
    assert job.env["LD_PRELOAD"] == "/work/libcontainre_tls_plaintext_capture.so /work/existing.so"
    assert job.env["CONTAINRE_TLS_MODE"] == "replay"
    assert job.env["CONTAINRE_TLS_REPLAY"] == "/work/tls_plaintext_replay.jsonl"
    assert job.env["CONTAINRE_TLS_FAKE_HANDSHAKE"] == "1"
    assert job.env["CONTAINRE_TLS_CAPTURE"] == "/work/custom.jsonl"
    assert job.env["CONTAINRE_TLS_LIBSSL"] == "/opt/app/libssl.so.3"
    assert meta["fake_handshake"] is True


def test_tls_plaintext_replay_shim_serves_scripted_ssl_read_bytes(tmp_path, monkeypatch):
    compiler = shutil.which("cc") or shutil.which("gcc")
    if compiler is None:
        pytest.skip("cc/gcc unavailable")

    source = Path(__file__).resolve().parents[1] / "tools" / "tls_plaintext_capture.c"
    library = tmp_path / "libtls_plaintext_capture.so"
    proc = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-o",
            str(library),
            str(source),
            "-ldl",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr

    replay = tmp_path / "replay.jsonl"
    replay.write_text(
        '{"direction":"out","hex":"736b6970"}\n'
        '{"direction":"in","hex":"68656c6c6f"}\n'
        '20776f726c64\n'
    )
    capture = tmp_path / "capture.jsonl"
    monkeypatch.setenv("CONTAINRE_TLS_MODE", "replay")
    monkeypatch.setenv("CONTAINRE_TLS_REPLAY", str(replay))
    monkeypatch.setenv("CONTAINRE_TLS_CAPTURE", str(capture))
    monkeypatch.setenv("CONTAINRE_TLS_FAKE_HANDSHAKE", "1")

    lib = ctypes.CDLL(str(library))
    lib.SSL_connect.argtypes = [ctypes.c_void_p]
    lib.SSL_connect.restype = ctypes.c_int
    lib.SSL_write.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.SSL_write.restype = ctypes.c_int
    lib.SSL_read.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
    lib.SSL_read.restype = ctypes.c_int
    lib.SSL_get0_alpn_selected.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)),
        ctypes.POINTER(ctypes.c_uint),
    ]
    lib.SSL_get0_alpn_selected.restype = None

    outbound = ctypes.create_string_buffer(b"client")
    assert lib.SSL_connect(None) == 1
    assert lib.SSL_write(None, outbound, 6) == 6
    alpn = ctypes.POINTER(ctypes.c_ubyte)()
    alpn_len = ctypes.c_uint()
    lib.SSL_get0_alpn_selected(None, ctypes.byref(alpn), ctypes.byref(alpn_len))
    assert bytes(alpn[:alpn_len.value]) == b"h2"

    first = ctypes.create_string_buffer(5)
    second = ctypes.create_string_buffer(16)
    assert lib.SSL_read(None, first, 5) == 5
    assert first.raw == b"hello"
    assert lib.SSL_read(None, second, 16) == 6
    assert second.raw[:6] == b" world"
    assert lib.SSL_read(None, second, 16) == 0

    rows = [json.loads(line) for line in capture.read_text().splitlines()]
    assert [row["direction"] for row in rows] == ["out", "in", "in"]
    assert bytes.fromhex(rows[1]["hex"]) == b"hello"
