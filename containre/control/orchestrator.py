"""Run orchestration: create a run directory from a policy, launch a Runtime, and
collect the result. Shared by the CLI and the control-plane API.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

from .. import __version__
from ..interfaces import Job, Runtime
from ..model import wall_ns
from ..store import RunStore
from .elf import elf_facts

_CANARY = b"CONTAINRE-CANARY do-not-modify - decoy file for behavioral detection\n"
_TERMINAL = {"finished", "killed", "error"}


def default_runs_root() -> Path:
    # SPEC §9 documents the runs root as overridable via CONTAINRE_RUNS_ROOT.
    # Honor it here so the CLI (ls/show/run) and the API/webapp agree on the
    # location instead of splitting between $CONTAINRE_RUNS_ROOT and ~/.containre.
    env = os.environ.get("CONTAINRE_RUNS_ROOT")
    if env:
        return Path(env)
    return Path.home() / ".containre" / "runs"


def _slug(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", text)[:40]


def make_run_id(specimen: Path, sha256: str) -> str:
    # second-granularity stamp + a short random token so two runs of the same
    # specimen within one second don't collide on the run directory.
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return f"{stamp}_{_slug(specimen.name)}_{sha256[:6]}_{uuid.uuid4().hex[:4]}"


def _host_facts() -> dict:
    docker = shutil.which("docker")
    docker_ver = None
    if docker:
        try:
            import subprocess
            docker_ver = subprocess.check_output([docker, "version", "-f", "{{.Server.Version}}"],
                                                 text=True, stderr=subprocess.DEVNULL).strip()
        except Exception:
            docker_ver = "present"
    return {"kernel": platform.release(), "docker": docker_ver,
            "criu": None, "containre": __version__}


def prepare_workdir(run_dir: Path, policy: dict) -> Path:
    files = policy.get("files", {})
    work = files.get("work_mount")
    workdir = Path(work).resolve() if work else (run_dir / "work")
    workdir.mkdir(parents=True, exist_ok=True)
    for decoy in files.get("decoys", []):
        target = workdir / decoy
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(_CANARY)
    return workdir


@dataclass
class RunResult:
    run_dir: Path
    run_id: str
    status: str
    exit_code: int | None
    meta: dict

    def events(self) -> list[dict]:
        path = self.run_dir / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def detections(self) -> list[dict]:
        return [e for e in self.events() if e["kind"] == "detection"]


def create_run(policy: dict, runs_root: Path) -> tuple[Path, Job]:
    spec = policy["specimen"]
    specimen = Path(spec["path"]).resolve()
    if not specimen.exists():
        raise FileNotFoundError(f"specimen not found: {specimen}")
    raw = specimen.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()

    run_id = make_run_id(specimen, sha256)
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "policy.yaml").write_text(yaml.safe_dump(policy, sort_keys=False))

    workdir = prepare_workdir(run_dir, policy)

    store = RunStore(run_dir)
    store.write_meta({
        "schema_version": 1,
        "run_id": run_id,
        "status": "queued",
        "specimen": {"path": str(specimen), "sha256": sha256, "size": len(raw),
                     "elf": elf_facts(specimen)},
        "image": None,
        "runtime": None,
        "policy_ref": "policy.yaml",
        "created_wall": wall_ns(),
        "host": _host_facts(),
    })
    store.close()

    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "HOME": str(workdir)}
    env.update(spec.get("env", {}))
    stdin_path = spec.get("stdin")
    job = Job(
        run_dir=run_dir,
        specimen_path=str(specimen),
        args=list(spec.get("args", [])),
        env=env,
        cwd=str(workdir),
        stdin_path=str(Path(stdin_path).resolve()) if stdin_path else None,
        policy=policy,
    )
    return run_dir, job


def get_runtime(name: str) -> Runtime:
    if name == "local":
        from ..runtime.local import LocalRuntime
        return LocalRuntime()
    if name == "docker":
        from ..runtime.docker import DockerRuntime
        return DockerRuntime()
    raise ValueError(f"unknown runtime: {name!r} (expected 'local' or 'docker')")


def execute(policy: dict, runs_root: Path | None = None, runtime: Runtime | None = None,
            timeout: float | None = None) -> RunResult:
    from ..runtime.local import LocalRuntime

    runs_root = runs_root or default_runs_root()
    runs_root.mkdir(parents=True, exist_ok=True)
    runtime = runtime or LocalRuntime()

    run_dir, job = create_run(policy, runs_root)
    store = RunStore(run_dir)
    store.update_meta(runtime=runtime.name, image=getattr(runtime, "image", None))
    store.close()

    handle = runtime.start(job)
    grace = timeout if timeout is not None else (policy.get("limits", {}).get("wallclock_s", 120) + 30)
    wait_result = runtime.wait(handle, timeout=grace)
    error = None
    if wait_result is None:
        meta = json.loads((run_dir / "meta.json").read_text())
        if meta.get("status") not in _TERMINAL:
            runtime.stop(handle)
            error = f"runtime did not finish within {grace}s"
    else:
        error = "runtime exited before finalizing run"

    meta = json.loads((run_dir / "meta.json").read_text())
    if meta.get("status") not in _TERMINAL and error:
        with RunStore(run_dir) as st:
            st.update_meta(
                status="error",
                exit_code=wait_result,
                stopped_wall=wall_ns(),
                kill_reason=None,
                error=error,
            )

    meta = json.loads((run_dir / "meta.json").read_text())
    return RunResult(run_dir=run_dir, run_id=meta["run_id"], status=meta.get("status", "unknown"),
                     exit_code=meta.get("exit_code"), meta=meta)
