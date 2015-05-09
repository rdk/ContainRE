"""Runtime instrumentation preparation.

These helpers prepare opt-in invasive instrumentation before a Runtime launches
the tracer. The first implementation is an OpenSSL LD_PRELOAD shim for TLS
plaintext observation and experimental response replay.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from ..interfaces import Job

_REPO = Path(__file__).resolve().parents[2]
_TLS_SOURCE = _REPO / "tools" / "tls_plaintext_capture.c"
_TLS_LIBRARY_NAME = "libcontainre_tls_plaintext_capture.so"
_TLS_REPLAY_NAME = "tls_plaintext_replay.jsonl"


class InstrumentationError(RuntimeError):
    pass


def _tls_config(policy: dict) -> dict:
    instrumentation = policy.get("instrumentation", {})
    if not isinstance(instrumentation, dict):
        return {}
    tls = instrumentation.get("tls_plaintext", {})
    return tls if isinstance(tls, dict) else {}


def _runtime_path(visible_workdir: str, name: str) -> str:
    return f"{visible_workdir.rstrip('/')}/{name}"


def _prepend_ld_preload(env: dict[str, str], library: str) -> None:
    existing = env.get("LD_PRELOAD", "").strip()
    env["LD_PRELOAD"] = f"{library} {existing}".strip()


def _compile_tls_library(output: Path) -> None:
    compiler = shutil.which(os.environ.get("CC", "cc")) or shutil.which("gcc")
    if compiler is None:
        raise InstrumentationError("TLS plaintext instrumentation requires cc or gcc")
    if not _TLS_SOURCE.exists():
        raise InstrumentationError(f"missing TLS plaintext shim source: {_TLS_SOURCE}")
    proc = subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O2",
            "-Wall",
            "-Wextra",
            "-o",
            str(output),
            str(_TLS_SOURCE),
            "-ldl",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        detail = (proc.stdout + proc.stderr)[-4000:]
        raise InstrumentationError(f"failed to build TLS plaintext shim:\n{detail}")


def _copy_replay_file(source: str, workdir: Path) -> Path:
    src = Path(source).expanduser().resolve()
    if not src.exists():
        raise InstrumentationError(f"TLS replay file does not exist: {src}")
    dst = workdir / _TLS_REPLAY_NAME
    if src != dst.resolve():
        shutil.copyfile(src, dst)
    return dst


def _write_instrumentation_meta(run_dir: Path, data: dict) -> None:
    path = run_dir / "meta.json"
    if not path.exists():
        return
    meta = json.loads(path.read_text())
    instrumentation = meta.setdefault("instrumentation", {})
    instrumentation["tls_plaintext"] = data
    path.write_text(json.dumps(meta, indent=2))


def configure_tls_plaintext(job: Job, *, visible_workdir: str | None = None) -> dict:
    """Build and inject the OpenSSL TLS plaintext shim when policy-enabled.

    ``visible_workdir`` is the work directory path as seen by the specimen. For
    Docker this is ``/work``; for LocalRuntime it is the host work directory.
    The function mutates ``job.env`` and returns the metadata row that was
    recorded, or an empty dict when disabled.
    """
    cfg = _tls_config(job.policy)
    if not cfg.get("enabled", False):
        return {}

    provider = str(cfg.get("provider") or "openssl-preload")
    if provider != "openssl-preload":
        raise InstrumentationError(f"unsupported TLS plaintext provider: {provider!r}")
    mode = str(cfg.get("mode") or "observe")
    if mode not in {"observe", "replay"}:
        raise InstrumentationError(f"unsupported TLS plaintext mode: {mode!r}")

    workdir = Path(job.cwd).resolve()
    workdir.mkdir(parents=True, exist_ok=True)
    visible = visible_workdir or str(workdir)
    library_host = workdir / _TLS_LIBRARY_NAME
    _compile_tls_library(library_host)
    library_runtime = _runtime_path(visible, _TLS_LIBRARY_NAME)
    output = str(cfg.get("output") or _runtime_path(visible, "tls_plaintext_capture.log"))
    max_bytes = int(cfg.get("max_bytes_per_record") or 4096)

    replay_runtime = None
    replay_host = None
    if mode == "replay":
        replay_file = cfg.get("replay_file")
        if not replay_file:
            raise InstrumentationError("TLS plaintext replay mode requires replay_file")
        replay_host = _copy_replay_file(str(replay_file), workdir)
        replay_runtime = _runtime_path(visible, replay_host.name)

    _prepend_ld_preload(job.env, library_runtime)
    job.env["CONTAINRE_TLS_CAPTURE"] = output
    job.env["CONTAINRE_TLS_CAPTURE_MAX"] = str(max_bytes)
    job.env["CONTAINRE_TLS_MODE"] = mode
    if replay_runtime:
        job.env["CONTAINRE_TLS_REPLAY"] = replay_runtime
    if bool(cfg.get("fake_handshake", False)):
        job.env["CONTAINRE_TLS_FAKE_HANDSHAKE"] = "1"
    if cfg.get("libssl"):
        job.env["CONTAINRE_TLS_LIBSSL"] = str(cfg["libssl"])

    meta = {
        "enabled": True,
        "provider": provider,
        "mode": mode,
        "invasive": True,
        "experimental": mode == "replay",
        "warning": (
            "OpenSSL LD_PRELOAD instrumentation mutates target process behavior; "
            "replay mode fakes TLS handshake/write/read behavior and is weaker "
            "evidence than protocol-faithful network emulation."
        ),
        "library": str(library_host),
        "library_runtime_path": library_runtime,
        "capture": output,
        "max_bytes_per_record": max_bytes,
    }
    if replay_host:
        meta["replay_file"] = str(replay_host)
        meta["replay_runtime_path"] = replay_runtime
    if cfg.get("libssl"):
        meta["libssl"] = str(cfg["libssl"])
    meta["fake_handshake"] = bool(cfg.get("fake_handshake", False))
    _write_instrumentation_meta(job.run_dir, meta)
    return meta
