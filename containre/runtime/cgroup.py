"""Best-effort cgroup v2 resource evidence for Docker runs.

Polling preserves observed events across partial reads, but cannot guarantee
capture of a breach immediately before container teardown. Shared-container
observations are advisory and cannot identify which concurrent job was affected.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

__all__ = ["ResourceSampler", "evaluate", "cgroup_path", "sample"]

_CGROUP_ROOT = Path("/sys/fs/cgroup")

#: Backoff ceiling for *locating* the container, which costs a `docker inspect`.
_POLL_S = 2.0

#: Sampling interval once the cgroup is known. Small reads of cgroup pseudo-files,
#: so this stays short: the counters are only useful if we read them before the
#: container (and its cgroup) disappears.
_SAMPLE_S = 0.25


def _read(path: Path) -> str | None:
    try:
        return path.read_text()
    except (OSError, ValueError):
        return None


def _read_int(path: Path) -> int | None:
    raw = _read(path)
    if raw is None:
        return None
    raw = raw.strip()
    if raw == "max":  # an unset ceiling
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _read_keyed(path: Path) -> dict[str, int]:
    """Parse the ``key value`` line format used by ``*.events`` files."""
    out: dict[str, int] = {}
    raw = _read(path)
    if raw is None:
        return out
    for line in raw.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                out[parts[0]] = int(parts[1])
            except ValueError:
                continue
    return out


def container_id(name_or_id: str) -> str | None:
    """Resolve a container name to its full id (the cgroup is named by id)."""
    try:
        proc = subprocess.run(
            ["docker", "inspect", "--format", "{{.Id}}", name_or_id],
            capture_output=True, text=True, timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    cid = proc.stdout.strip()
    return cid if proc.returncode == 0 and cid else None


def cgroup_path(cid: str) -> Path | None:
    """Locate a container's cgroup v2 directory.

    Docker's two cgroup drivers lay this out differently, and neither is
    guaranteed, so fall back to a recursive search before giving up.
    """
    candidates = [
        _CGROUP_ROOT / "system.slice" / f"docker-{cid}.scope",   # systemd driver
        _CGROUP_ROOT / "docker" / cid,                           # cgroupfs driver
    ]
    for path in candidates:
        if (path / "pids.current").exists():
            return path
    try:
        for path in _CGROUP_ROOT.glob(f"**/*{cid}*/pids.current"):
            return path.parent
    except OSError:
        pass
    return None


def _events_max_of(*dicts_and_key) -> int | None:
    """Largest value for a key across several parsed event files."""
    *dicts, key = dicts_and_key
    present = [d.get(key) for d in dicts if d.get(key) is not None]
    return max(present) if present else None


def _events_max(cg: Path, stem: str) -> int | None:
    """Highest ``max`` across a controller's hierarchical and local event files.

    Retain evidence from either interface; kernel and hierarchy semantics differ.
    These values describe the observed cgroup, not individual processes or jobs.
    """
    values = [
        _read_keyed(cg / f"{stem}.events").get("max"),
        _read_keyed(cg / f"{stem}.events.local").get("max"),
    ]
    present = [v for v in values if v is not None]
    return max(present) if present else None


def sample(cg: Path) -> dict:
    """One reading of a live cgroup. Missing counters are simply absent."""
    mem_events = _read_keyed(cg / "memory.events")
    mem_events_local = _read_keyed(cg / "memory.events.local")
    out: dict[str, object] = {
        "pids_current": _read_int(cg / "pids.current"),
        "pids_peak": _read_int(cg / "pids.peak"),
        "pids_max": _read_int(cg / "pids.max"),
        "pids_events_max": _events_max(cg, "pids"),
        "memory_current": _read_int(cg / "memory.current"),
        "memory_peak": _read_int(cg / "memory.peak"),
        "memory_max": _read_int(cg / "memory.max"),
        "memory_events_max": _events_max(cg, "memory"),
        "memory_oom_kill": _events_max_of(mem_events, mem_events_local, "oom_kill"),
    }
    return {k: v for k, v in out.items() if v is not None}


_EVENT_COUNTERS = ("pids_events_max", "memory_events_max", "memory_oom_kill")
_PEAKS = ("pids_peak", "memory_peak")


class ResourceSampler:
    """Collect observed counters; only dedicated containers have run attribution.

    Reads happen outside the lock. Shutdown seals state before joining, so a
    delayed discovery/read cannot publish after stop() has returned.
    """

    def __init__(self, container: str | None, poll_s: float = _POLL_S,
                 sample_s: float = _SAMPLE_S, *, reuse_exec: bool = False):
        self._container = container
        self._poll_s = poll_s
        self._sample_s = sample_s
        self._reuse_exec = reuse_exec
        self._cg: Path | None = None
        self._last: dict = {}
        self._baseline: dict | None = None
        self._invalid: set[str] = set()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._closed = False
        self._out: dict | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> "ResourceSampler":
        if not self._container or self._thread is not None or self._closed:
            return self
        try:
            thread = threading.Thread(
                target=self._loop, name="containre-resource-sampler", daemon=True,
            )
            thread.start()
            self._thread = thread
        except (RuntimeError, OSError):
            # Runtime launch already succeeded: monitoring must not skip wait/cleanup.
            self._stop.set()
        return self

    def _merge(self, got: dict) -> None:
        # Called under the lock. A missing field must not erase prior evidence.
        if self._baseline is None:
            self._baseline = dict(got)
        for key, value in got.items():
            previous = self._last.get(key)
            if key in _EVENT_COUNTERS and self._reuse_exec:
                if previous is not None and value < previous:
                    self._invalid.add(key)
            elif key in (*_EVENT_COUNTERS, *_PEAKS) and previous is not None:
                value = max(previous, value)
            self._last[key] = value

    def _loop(self) -> None:
        cg = None
        resolve_delay = 0.1
        while not self._stop.is_set():
            delay = self._sample_s
            try:
                if cg is None:
                    cid = container_id(self._container)
                    if cid:
                        cg = cgroup_path(cid)
                    if cg is None:
                        delay = resolve_delay
                        resolve_delay = min(resolve_delay * 2, self._poll_s)
                if cg is not None and not self._stop.is_set():
                    got = sample(cg)
                    with self._lock:
                        if self._closed:
                            return
                        self._cg = cg
                        if got:
                            self._merge(got)
            except Exception:  # noqa: BLE001 - unavailable monitoring is not a breach
                pass
            self._stop.wait(delay)

    def stop(self) -> dict:
        """Seal the collector and return a stable snapshot, including a final read."""
        with self._lock:
            if self._out is not None:
                return dict(self._out)
            self._closed = True
            self._stop.set()
            cg = self._cg
        if self._thread is not None:
            self._thread.join(timeout=self._poll_s + 1)
        final = {}
        if cg is not None:
            try:
                final = sample(cg)
            except Exception:  # noqa: BLE001
                pass
        with self._lock:
            if self._out is None:
                if final:
                    self._merge(final)
                out = dict(self._last)
                if out:
                    out["scope"] = "shared_container" if self._reuse_exec else "dedicated_run"
                if self._reuse_exec:
                    for key in _EVENT_COUNTERS:
                        baseline = (self._baseline or {}).get(key)
                        if key in out and baseline is not None and key not in self._invalid:
                            out[f"{key}_delta"] = out[key] - baseline
                self._out = out
            return dict(self._out)

    def __enter__(self) -> "ResourceSampler":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def _mib(n: object) -> str:
    """Bytes as MiB for a human reading an error message."""
    try:
        return f"{int(n) / (1 << 20):.0f} MiB"
    except (TypeError, ValueError):
        return str(n)


def _counter(resources: dict, name: str) -> int:
    """An observed counter increment, or an absolute count for a dedicated run.

    Shared deltas cover all concurrent activity, not just the current job.
    """
    delta = resources.get(f"{name}_delta")
    if delta is not None:
        return delta
    if resources.get("scope") == "shared_container":
        return 0  # no valid baseline: never charge inherited history
    return resources.get(name) or 0


def evaluate(resources: dict) -> list[dict]:
    """Return the ceilings this run actually hit.

    Each entry carries the ``trigger`` name used by ``policy["kill_on"]``, so a
    caller can decide between recording the breach and failing the run.
    """
    breaches: list[dict] = []

    # A non-zero pids.events:max means at least one fork was denied. There is no
    # benign reading of that: some process asked for a thread and did not get one.
    hits = _counter(resources, "pids_events_max")
    if hits > 0:
        breaches.append({
            "trigger": "pids_exceeded",
            "limit": resources.get("pids_max"),
            "peak": resources.get("pids_peak"),
            "hits": hits,
            "detail": (
                f"pids limit {resources.get('pids_max')} was hit {hits}x "
                f"(peak {resources.get('pids_peak')}); processes could not fork, "
                f"so results from this run are not trustworthy"
            ),
        })

    # For memory, distinguish reclaim pressure (memory.events:max, survivable)
    # from an actual kill (oom_kill), which is not.
    kills = _counter(resources, "memory_oom_kill")
    if kills > 0:
        breaches.append({
            "trigger": "oom",
            "limit": resources.get("memory_max"),
            "peak": resources.get("memory_peak"),
            "hits": kills,
            "detail": (
                f"observed {kills} OOM "
                f"kill(s) (limit {_mib(resources.get('memory_max'))}, "
                f"peak {_mib(resources.get('memory_peak'))}); results from "
                f"this run are not trustworthy"
            ),
        })

    return breaches
