"""Generic lifecycle helpers for supervised reuse containers (domain-agnostic).

A reuse container (``runtime.docker_reuse_container``) may host services via a
supervisor entrypoint and run many concurrent ``workload_only`` execs. These
helpers let ContainRE manage that SAFELY without knowing anything about the
workload's domain:

  - ``list_live(container)``  — runs whose in-container workload is still alive.
  - ``is_busy(container)``    — guards ``_ensure_reuse_container`` from replacing
    a container that still has live execs.
  - ``kill(container, run_id)`` — stop ONE exec's process group (peers and the
    container keep running).
  - ``stop_if_idle(container)`` — stop the whole container iff nothing is live.

Liveness is the workload's leader process group. The in-container runner records
its pgid at ``<run_dir>/leader.pgid`` (``start_new_session`` makes pid == pgid),
so a run is live while that group survives inside the container. An EXTERNAL
orchestrator that knows which runs are abandoned (e.g. a scheduler tracking job
owners) drives ``kill``/``stop_if_idle`` via the ``containre reuse`` CLI —
ContainRE only provides the mechanism, never the policy.
"""
from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path

PGID_FILE = "leader.pgid"
MARKER_FILE = "reuse_container"  # per-run marker: the container this exec runs in
OWNER_FILE = "owner"             # "<pid> <start_token>": the host process that owns this exec
#: A just-launched exec may not have written its pgid yet; treat a recently
#: marked run with no pgid as live so the busy-guard doesn't race a cold start.
PENDING_GRACE_S = 180.0


def _activity_path(runs_root: Path, container: str) -> Path:
    return Path(runs_root) / f".reuse-activity-{container}"


def _touch_activity(runs_root: Path, container: str) -> None:
    _activity_path(runs_root, container).write_text(str(time.time()))


def mark(run_dir: Path, container: str) -> None:
    """Record (host-side) that this run's exec belongs to `container`, and bump
    the container's last-activity stamp (used by the idle reaper)."""
    (Path(run_dir) / MARKER_FILE).write_text(container)
    _touch_activity(Path(run_dir).parent, container)


def clear(run_dir: Path) -> None:
    """Drop the marker (and owner) once the exec is no longer live; bump activity
    so a just-drained container starts its idle countdown from now."""
    container = None
    try:
        container = (Path(run_dir) / MARKER_FILE).read_text().strip()
    except OSError:
        pass
    (Path(run_dir) / MARKER_FILE).unlink(missing_ok=True)
    (Path(run_dir) / OWNER_FILE).unlink(missing_ok=True)
    if container:
        _touch_activity(Path(run_dir).parent, container)


def mark_owner(run_dir: Path, pid: int, start_token: str | None) -> None:
    """Record the host process that OWNS this exec. If it dies, the exec is
    abandoned and `reap` will stop it. The owner is opaque to ContainRE — any
    caller may set one; a run with no owner is simply never owner-reaped."""
    (Path(run_dir) / OWNER_FILE).write_text(f"{int(pid)} {start_token or ''}")


def read_owner(run_dir: Path) -> tuple[int, str | None] | None:
    try:
        pid_s, _, tok = (Path(run_dir) / OWNER_FILE).read_text().strip().partition(" ")
        return int(pid_s), (tok or None)
    except (OSError, ValueError):
        return None


def proc_start_token(pid: int) -> str | None:
    """Process start-time (field 22 of /proc/<pid>/stat) — guards a recorded
    owner pid against PID reuse."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    rparen = stat.rfind(")")
    rest = stat[rparen + 2:].split() if rparen != -1 else []
    return rest[19] if len(rest) >= 20 else None


def owner_alive(pid: int, start_token: str | None) -> bool:
    if pid <= 0:
        return False
    current = proc_start_token(pid)
    if current is None:
        return False
    return not (start_token and current != start_token)


def read_pgid(run_dir: Path) -> int | None:
    try:
        return int((Path(run_dir) / PGID_FILE).read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def _iter_runs(runs_root: Path, container: str):
    for marker in Path(runs_root).glob(f"*/{MARKER_FILE}"):
        try:
            if marker.read_text().strip() == container:
                yield marker.parent, marker
        except OSError:
            continue


def list_live(runs_root: Path, container: str, *, now: float | None = None) -> list[dict]:
    """Runs on `container` whose workload is still alive. A run is live while its
    leader process group survives in the container, or (cold-start window) while
    its marker is fresh and no pgid is recorded yet. Self-cleaning: no separate
    registry to leak; a finished exec drops its own marker."""
    now = time.time() if now is None else now
    live: list[dict] = []
    for run_dir, marker in _iter_runs(runs_root, container):
        pgid = read_pgid(run_dir)
        if pgid is not None:
            if _pgid_alive(container, pgid):
                live.append({"run_id": run_dir.name, "run_dir": str(run_dir), "pgid": pgid})
        elif now - marker.stat().st_mtime < PENDING_GRACE_S:  # cold-start window
            live.append({"run_id": run_dir.name, "run_dir": str(run_dir), "pgid": None})
    return live


def is_busy(runs_root: Path, container: str) -> bool:
    return bool(list_live(runs_root, container))


def kill(runs_root: Path, container: str, run_id: str) -> bool:
    """Stop one exec's process group inside `container`. Idempotent."""
    pgid = read_pgid(Path(runs_root) / run_id)
    return _kill_pgid(container, pgid) if pgid is not None else False


def reap(runs_root: Path, container: str) -> list[str]:
    """Stop every exec whose OWNER process has died (abandoned execs), returning
    only the ids confirmed stopped. Failed kills and pending execs retain their
    tracking for retry. Generic: 'abandoned' == the opaque owner pid is no longer
    a live process. Execs with no recorded owner are left alone."""
    killed: list[str] = []
    for run_dir, _marker in list(_iter_runs(runs_root, container)):
        owner = read_owner(run_dir)
        if owner is None or owner_alive(*owner):
            continue
        pgid = read_pgid(run_dir)
        if pgid is None or not _kill_pgid(container, pgid):
            continue
        clear(run_dir)
        killed.append(run_dir.name)
    return killed


def stop_if_idle(runs_root: Path, container: str, *, idle_s: float = 0.0,
                 now: float | None = None) -> bool:
    """Stop `container` iff it has no live execs AND its last activity is at least
    `idle_s` ago (a grace so it stays warm between campaign waves). Returns True
    if stopped."""
    if is_busy(runs_root, container):
        return False
    if idle_s > 0:
        try:
            last = float(_activity_path(runs_root, container).read_text().strip())
        except (OSError, ValueError):
            last = 0.0
        if (time.time() if now is None else now) - last < idle_s:
            return False
    try:
        proc = subprocess.run(["docker", "stop", container],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=_EXEC_TIMEOUT_S + 15.0)  # stop has its own ~10s grace
    except (subprocess.TimeoutExpired, OSError):
        return False  # daemon wedged; leave the activity stamp so we retry later
    if proc.returncode != 0:
        return False
    _activity_path(runs_root, container).unlink(missing_ok=True)
    return True


# -- in-container process-group primitives ------------------------------------

#: `docker exec`/`stop` control ops are bounded — under a wedged/overloaded
#: docker daemon (or a hung in-container probe) an unbounded call would hang the
#: liveness/kill/idle paths (and the wedged-exec recovery in DockerRuntime.wait,
#: which routes through stop()->_kill_pgid->_exec). A failed control command
#: does not establish that a container is gone.
_EXEC_TIMEOUT_S = 30.0
_EXEC_TIMEDOUT = object()  # sentinel: docker exec did not return in time


def _exec(container: str, argv: list[str], *, timeout: float = _EXEC_TIMEOUT_S):
    try:
        proc = subprocess.run(["docker", "exec", container, *argv],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _EXEC_TIMEDOUT
    except OSError:
        return None
    return proc.stdout if proc.returncode == 0 else None


def _container_stopped(container: str) -> bool:
    """Confirm absence/stopped state; any Docker or parsing error stays unknown.

    A failed inspect/exec can mean a daemon failure or a missing container. A
    successful, exactly filtered listing distinguishes confirmed absence without
    parsing localized error messages or treating a permission failure as absence.
    """
    selector = (
        f"id={container}" if re.fullmatch(r"[0-9a-f]{64}", container)
        else f"name=^/{re.escape(container.removeprefix('/'))}$"
    )
    try:
        proc = subprocess.run(
            ["docker", "container", "ls", "--all", "--no-trunc", "--filter", selector,
             "--format", "{{.ID}} {{.State}}"],
            capture_output=True, text=True, timeout=_EXEC_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    if proc.returncode != 0:
        return False
    lines = proc.stdout.strip().splitlines()
    if not lines:
        return True
    fields = lines[0].split()
    return (
        len(lines) == 1 and len(fields) == 2
        and re.fullmatch(r"[0-9a-f]{64}", fields[0]) is not None
        and fields[1] in {"exited", "dead"}
    )


def _pgid_alive(container: str, pgid: int) -> bool:
    if pgid <= 1:
        return False
    probe = (
        "import glob\n"
        "n=0\n"
        "for p in glob.glob('/proc/[0-9]*/stat'):\n"
        "    try: s=open(p).read()\n"
        "    except OSError: continue\n"
        "    r=s[s.rfind(')')+2:].split()\n"
        "    if len(r)>=3 and r[0]!='Z' and r[2]==str(%d): n+=1\n"
        "print(n)\n" % pgid
    )
    out = _exec(container, ["python3", "-c", probe])
    if out is _EXEC_TIMEDOUT:
        # Probe wedged (daemon hung): assume ALIVE so the busy-guard/idle-reaper
        # never replace or stop a container whose liveness we couldn't read.
        return True
    if isinstance(out, str) and re.fullmatch(r"[0-9]{1,10}", out.strip()):
        return int(out.strip()) > 0
    return not _container_stopped(container)


def _kill_pgid(container: str, pgid: int, *, grace_s: float = 5.0) -> bool:
    """TERM then (after a grace) KILL the process group, verifying it is gone."""
    if pgid <= 1:
        return False
    _exec(container, ["sh", "-c", f"kill -TERM -{pgid} 2>/dev/null || true"])
    deadline = time.monotonic() + grace_s
    while time.monotonic() < deadline:
        if not _pgid_alive(container, pgid):
            return True
        time.sleep(0.25)
    _exec(container, ["sh", "-c", f"kill -KILL -{pgid} 2>/dev/null || true"])
    time.sleep(0.25)
    return not _pgid_alive(container, pgid)
