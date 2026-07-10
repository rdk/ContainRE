"""RunManager - the control-plane's view of runs: start them non-blocking, list
active + finished, and read their on-disk artifacts (events, snapshots, memory).

The tracer/runner writes everything to the run directory; the manager only reads
it back (plus a small active-handle table), so live and post-hoc access share one
code path.
"""
from __future__ import annotations

import json
import os
import re
import threading
from pathlib import Path

from ..control import create_run, default_runs_root, get_runtime
from ..model import wall_ns
from ..memory import snapshot as snap
from ..report import summarize_run_dir
from ..store import RunStore
from ..static_analysis import analyze_target, load_static, query_static, write_static


class CapacityError(RuntimeError):
    pass


_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,96}$")
_SAFE_SNAPSHOT_RE = re.compile(r"^snap-[A-Za-z0-9._-]{1,128}$")
_TERMINAL_STATUSES = {"finished", "killed", "error"}


def _default_cap() -> int:
    return max(1, (os.cpu_count() or 2) // 2)


def _safe_name(name: str, default: str = "checkpoint") -> str | None:
    name = name or default
    return name if _SAFE_NAME_RE.fullmatch(name) else None


class RunManager:
    def __init__(self, runs_root: Path | None = None, runtime_name: str = "local",
                 max_concurrent: int | None = None):
        self.runs_root = Path(runs_root) if runs_root else default_runs_root()
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self.runtime_name = runtime_name
        self.runtime = get_runtime(runtime_name)
        self.max_concurrent = max_concurrent or _default_cap()
        self._active: dict[str, object] = {}
        self._starting = 0
        self._lock = threading.Lock()

    # -- lifecycle ----------------------------------------------------------
    def start(self, policy: dict) -> dict:
        with self._lock:
            if len(self._active) + self._starting >= self.max_concurrent:
                raise CapacityError(f"at capacity ({self.max_concurrent} concurrent runs)")
            self._starting += 1
        run_dir = None
        try:
            run_dir, job = create_run(policy, self.runs_root)
            store = RunStore(run_dir)
            store.update_meta(runtime=self.runtime.name, image=getattr(self.runtime, "image", None))
            store.close()
            handle = self.runtime.start(job)
            run_id = run_dir.name
            with self._lock:
                self._active[run_id] = handle
        except Exception as exc:
            if run_dir is not None:
                with RunStore(run_dir) as st:
                    st.update_meta(status="error", stopped_wall=wall_ns(), error=str(exc))
            raise
        finally:
            with self._lock:
                self._starting -= 1
        threading.Thread(target=self._reap, args=(run_id, handle), daemon=True).start()
        return {"run_id": run_id, "run_dir": str(run_dir), "status": "running"}

    def _reap(self, run_id: str, handle) -> None:
        exit_code = None
        wait_error = None
        try:
            try:
                exit_code = self.runtime.wait(handle)
            except Exception as exc:
                wait_error = str(exc)
            self._mark_unfinalized_run(run_id, exit_code, wait_error)
        finally:
            with self._lock:
                self._active.pop(run_id, None)

    def _mark_unfinalized_run(self, run_id: str, exit_code: int | None,
                              wait_error: str | None = None) -> None:
        meta_path = self._run_dir(run_id) / "meta.json"
        if not meta_path.exists():
            return
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, json.JSONDecodeError):
            return
        if meta.get("status") in _TERMINAL_STATUSES:
            return
        patch = {
            "status": "error",
            "stopped_wall": wall_ns(),
            "error": wait_error or "runtime exited before finalizing run",
        }
        if exit_code is not None:
            patch["exit_code"] = exit_code
        with RunStore(self._run_dir(run_id)) as st:
            st.update_meta(**patch)

    def stop(self, run_id: str) -> bool:
        with self._lock:
            handle = self._active.get(run_id)
        if handle is None:
            return False
        self.runtime.stop(handle)
        return True

    # -- reads --------------------------------------------------------------
    def _run_dir(self, run_id: str) -> Path:
        return self.runs_root / run_id

    def get(self, run_id: str) -> dict | None:
        meta = self._run_dir(run_id) / "meta.json"
        if not meta.exists():
            return None
        d = json.loads(meta.read_text())
        with self._lock:
            d["active"] = run_id in self._active
        return d

    def list(self) -> list[dict]:
        out = []
        for meta_path in sorted(self.runs_root.glob("*/meta.json"), reverse=True):
            try:
                d = json.loads(meta_path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            with self._lock:
                d["active"] = meta_path.parent.name in self._active
            out.append(d)
        return out

    def events(self, run_id: str, since: int = 0, limit: int = 1000,
               kind: str | None = None) -> dict:
        path = self._run_dir(run_id) / "events.jsonl"
        events: list[dict] = []
        next_seq = since
        if path.exists():
            with open(path) as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    # Tolerate a torn final line or a garbage/forged line: skip it
                    # rather than 500-ing the whole /events, /detections, /summary
                    # and websocket surface for the run.
                    try:
                        e = json.loads(line)
                        seq = e["seq"]
                    except (json.JSONDecodeError, KeyError, TypeError):
                        continue
                    if not isinstance(seq, int) or isinstance(seq, bool):
                        continue  # forged non-integer seq: the comparison below would raise
                    if seq < since:
                        continue
                    next_seq = seq + 1
                    if kind and e.get("kind") != kind:
                        continue
                    events.append(e)
                    if len(events) >= limit:
                        break
        return {"events": events, "next_seq": next_seq}

    def snapshots(self, run_id: str) -> list[dict]:
        # Filter by kind inside events() so the cap bounds mem events, not total
        # events scanned; otherwise a specimen could bury its snapshots past the
        # 100000th (any-kind) event and hide them from this endpoint.
        return [e for e in self.events(run_id, limit=100000, kind="mem")["events"]
                if (e.get("data") or {}).get("op") == "snapshot"]

    def detections(self, run_id: str) -> list[dict]:
        return self.events(run_id, limit=100000, kind="detection")["events"]

    def summary(self, run_id: str, retry_threshold: int = 3) -> dict | None:
        if not (self._run_dir(run_id) / "meta.json").exists():
            return None
        return summarize_run_dir(self._run_dir(run_id), retry_threshold=retry_threshold)

    def static_analysis(self, run_id: str, *, refresh: bool = False,
                        query: str | None = None) -> dict | None:
        meta = self.get(run_id)
        if meta is None:
            return None
        out_dir = self._run_dir(run_id) / "static"
        cached = out_dir / "static.json"
        if cached.exists() and not refresh:
            return load_static(cached)
        specimen = Path(meta.get("specimen", {}).get("path", ""))
        if not specimen.exists():
            return {
                "schema_version": 1,
                "target": str(specimen),
                "summary": {"files_total": 0, "warnings": 1},
                "files": [],
                "symbols": [],
                "imports": [],
                "exports": [],
                "functions": [],
                "relocations": [],
                "call_edges": [],
                "strings": [],
                "source_refs": [],
                "warnings": [f"specimen not found: {specimen}"],
            }
        data = analyze_target(specimen, query=query)
        write_static(data, out_dir)
        return data

    def static_query(self, run_id: str, symbol: str, *, direction: str = "both",
                     refresh: bool = False, limit: int = 120) -> dict | None:
        data = self.static_analysis(run_id, refresh=refresh, query=symbol)
        if data is None:
            return None
        return query_static(data, symbol, direction=direction, limit=limit)

    def artifacts(self, run_id: str) -> list[dict]:
        d = self._run_dir(run_id) / "files"
        if not d.is_dir():
            return []
        return [{"name": p.name, "size": p.stat().st_size}
                for p in sorted(d.iterdir()) if p.is_file()]

    def artifact_path(self, run_id: str, name: str) -> Path | None:
        base = (self._run_dir(run_id) / "files").resolve()
        try:
            p = (base / name).resolve()
        except (OSError, ValueError):
            return None
        if p != base and base not in p.parents:      # path-traversal guard
            return None
        return p if p.is_file() else None

    def pcap_path(self, run_id: str) -> Path | None:
        p = self._run_dir(run_id) / "net" / "capture.pcap"
        return p if p.is_file() else None

    # -- checkpoint / restore (best-effort) ---------------------------------
    def checkpoint(self, run_id: str, name: str = "checkpoint") -> dict:
        safe = _safe_name(name)
        if safe is None:
            return {"ok": False, "name": "checkpoint", "reason": "invalid checkpoint name"}
        with self._lock:
            handle = self._active.get(run_id)
        if handle is None:
            result = {"ok": False, "name": safe, "reason": "run is not active"}
        elif (fn := getattr(self.runtime, "checkpoint", None)) is None:
            result = {"ok": False, "name": safe, "reason": "runtime does not support checkpoint"}
        else:
            result = fn(handle, safe)
        self._record_checkpoint(run_id, result)
        return result

    def restore(self, run_id: str, name: str = "checkpoint") -> dict:
        safe = _safe_name(name)
        if safe is None:
            return {"ok": False, "name": "checkpoint", "reason": "invalid checkpoint name"}
        with self._lock:
            handle = self._active.get(run_id)
        if handle is None:
            return {"ok": False, "name": safe, "reason": "run is not active"}
        fn = getattr(self.runtime, "restore", None)
        if fn is None:
            return {"ok": False, "name": safe, "reason": "runtime does not support restore"}
        return fn(handle, safe)

    def _record_checkpoint(self, run_id: str, result: dict) -> None:
        safe = _safe_name(str(result.get("name", "checkpoint")))
        if safe is None:
            safe = "checkpoint"
        d = self._run_dir(run_id) / "checkpoints"
        d.mkdir(exist_ok=True)
        (d / f"{safe}.json").write_text(json.dumps(result, indent=2))

    def checkpoints(self, run_id: str) -> list[dict]:
        d = self._run_dir(run_id) / "checkpoints"
        if not d.is_dir():
            return []
        out = []
        for p in sorted(d.glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
        return out

    def memory(self, run_id: str, snapshot_id: str, base: str | None = None) -> dict | None:
        if not _SAFE_SNAPSHOT_RE.fullmatch(snapshot_id):
            return None
        snap_dir = self._run_dir(run_id) / "snapshots"
        matches = [
            p for p in snap_dir.iterdir()
            if p.is_file() and p.name.startswith(f"{snapshot_id}.")
        ] if snap_dir.exists() else []
        if not matches:
            return None
        try:
            header, body = snap.load(matches[0])
            data, region = snap.region_slice(header, body, base)
        except Exception:
            # A snapshot that can't be read (zstd blob on a host without
            # zstandard, or a corrupt/truncated header) must degrade to 404, not
            # crash the endpoint with a 500.
            return None
        base_int = int(region["base"], 16) if region else 0
        return {
            "snapshot_id": snapshot_id,
            "regions": header.get("regions", []),
            "region": region,
            "hexdump": snap.hexdump(data, base=base_int),
        }
