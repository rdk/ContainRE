"""Per-run directory store: events.jsonl + index.sqlite + artifacts + meta.json.

The directory *is* the database (SPEC §9). The append-only ``events.jsonl`` is the
system of record; ``index.sqlite`` is a rebuildable seek/filter index; large blobs
live as separate files. A single RunStore instance is the sole writer for a run.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from pathlib import Path

from ..model import Event

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    seq     INTEGER PRIMARY KEY,
    ts_mono INTEGER,
    pid     INTEGER,
    tid     INTEGER,
    kind    TEXT,
    op      TEXT,
    summary TEXT,
    json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_op   ON events(op);
"""


class RunStore:
    def __init__(self, run_dir: str | Path):
        self.dir = Path(run_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "files").mkdir(exist_ok=True)
        self.events_path = self.dir / "events.jsonl"
        self.meta_path = self.dir / "meta.json"
        self._lock = threading.RLock()
        self._events_fh = open(self.events_path, "a", buffering=1)
        # check_same_thread=False + the lock below: the sink server writes from
        # worker threads while the tracer writes from the main thread.
        self._db = sqlite3.connect(self.dir / "index.sqlite", check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript(_SCHEMA_SQL)
        row = self._db.execute("SELECT COALESCE(MAX(seq), -1) FROM events").fetchone()
        self._seq = int(row[0]) + 1
        self._uncommitted = 0
        self.counts: dict[str, int] = {
            "events": 0, "snapshots": 0, "checkpoints": 0,
            "detections": 0, "artifacts": 0, "net_flows": 0,
        }

    # -- events -------------------------------------------------------------
    def write_event(self, event: Event) -> int:
        with self._lock:
            seq = self._seq
            self._seq += 1
            rec = event.record(seq)
            self._events_fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            op = event.data.get("op") or event.data.get("name")
            self._db.execute(
                "INSERT INTO events(seq, ts_mono, pid, tid, kind, op, summary, json) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (seq, event.ts_mono, event.pid, event.tid, event.kind, op,
                 event.summary(), json.dumps(rec, separators=(",", ":"))),
            )
            self.counts["events"] += 1
            if event.kind == "detection":
                self.counts["detections"] += 1
            elif event.kind == "mem" and event.data.get("op") == "snapshot":
                self.counts["snapshots"] += 1
            self._uncommitted += 1
            if self._uncommitted >= 64:
                self.commit()
            return seq

    def commit(self) -> None:
        with self._lock:
            self._events_fh.flush()
            self._db.commit()
            self._uncommitted = 0

    # -- artifacts ----------------------------------------------------------
    def add_artifact(self, name: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()[:12]
        artifact_id = f"a-{digest}"
        safe = name.replace("/", "_").lstrip(".") or "artifact"
        (self.dir / "files" / f"{artifact_id}_{safe}").write_bytes(data)
        self.counts["artifacts"] += 1
        return artifact_id

    def add_snapshot(self, data: bytes, suffix: str = "bin") -> str:
        (self.dir / "snapshots").mkdir(exist_ok=True)
        digest = hashlib.sha256(data).hexdigest()[:12]
        snapshot_id = f"snap-{digest}"
        (self.dir / "snapshots" / f"{snapshot_id}.{suffix}").write_bytes(data)
        return snapshot_id

    # -- meta ---------------------------------------------------------------
    def read_meta(self) -> dict:
        if self.meta_path.exists():
            return json.loads(self.meta_path.read_text())
        return {}

    def write_meta(self, meta: dict) -> None:
        tmp = self.meta_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, indent=2))
        tmp.replace(self.meta_path)

    def update_meta(self, **patch) -> dict:
        with self._lock:
            meta = self.read_meta()
            meta.update(patch)
            self.write_meta(meta)
            return meta

    # -- queries (post-hoc) -------------------------------------------------
    def query(self, kind: str | None = None, op: str | None = None, limit: int = 1000) -> list[dict]:
        sql = "SELECT json FROM events"
        clauses, params = [], []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if op:
            clauses.append("op = ?")
            params.append(op)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY seq LIMIT ?"
        params.append(limit)
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
        return [json.loads(r[0]) for r in rows]

    def close(self) -> None:
        with self._lock:
            self.commit()
            self._events_fh.close()
            self._db.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
