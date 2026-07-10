"""RunSession - owns the recording side of a run: the store, detectors, YARA,
verdict, and the (thread-safe) event sink that the tracer and net-sink both feed.

Extracted from the runner so ``execute()`` reads as orchestration and the recording
concerns (detection recording, memory snapshots, pcap, artifact capture) live in one
cohesive, testable place.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

from ..control.verdict import Verdict
from ..detect import YaraScanner, default_detectors
from ..memory import blob_suffix, capture
from ..model import Event, Kind, wall_ns
from ..net import PcapWriter
from ..store import RunStore

_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024


class RunSession:
    def __init__(self, run_dir: Path, policy: dict, workdir: str):
        self.run_dir = run_dir
        self.policy = policy
        self.workdir = workdir
        self.store = RunStore(run_dir)
        self.detectors = default_detectors()
        self.verdict = Verdict()
        self.net_flows: set[str] = set()
        self.written_files: set[str] = set()
        detect_cfg = policy.get("detect", {})
        self.yara = (YaraScanner(detect_cfg.get("yara_rules", []))
                     if detect_cfg.get("yara", True) else None)
        # The tracer emits from the main thread; the net-sink from worker threads.
        # A re-entrant lock serializes store writes and detector/verdict state.
        self._lock = threading.RLock()

    # -- event sink ---------------------------------------------------------
    def emit(self, event: Event) -> None:
        with self._lock:
            seq = self.store.write_event(event)
            rec = event.record(seq)
            if event.kind == Kind.NET and event.data.get("raddr"):
                self.net_flows.add(event.data["raddr"])
            if event.kind == Kind.FILE and event.data.get("op") == "write":
                path = event.data.get("path", "")
                if path.startswith(self.workdir + os.sep):
                    self.written_files.add(path)
            if event.kind == Kind.DETECTION:
                return
            for det in self.detectors:
                for d in det.feed(rec):
                    self.record_detection(d, event.pid)

    def record_detection(self, d: dict, pid: int | None = None) -> None:
        with self._lock:
            self.store.write_event(Event(Kind.DETECTION, d, pid=pid))
            self.verdict.absorb(d)

    # -- memory snapshots ---------------------------------------------------
    def snapshot(self, pid: int, reason: str) -> None:
        blob, regions, total = capture(pid)
        snapshot_id = self.store.add_snapshot(blob, suffix=blob_suffix())
        data: dict = {"op": "snapshot", "snapshot_id": snapshot_id,
                      "reason": reason, "region_count": total, "bytes": len(blob)}
        if regions:
            r = regions[0]
            data["region"] = {"base": r["base"], "size": r["size"], "perms": r["perms"]}
        self.emit(Event(Kind.MEM, data, pid=pid))
        if self.yara and self.yara.enabled():
            for d in self.yara.scan(blob, {"snapshot_id": snapshot_id}):
                self.record_detection(d, pid)

    # -- finalization -------------------------------------------------------
    def close_detectors(self) -> None:
        for det in self.detectors:
            for d in det.close():
                self.record_detection(d)

    def write_pcap(self, flows: dict) -> None:
        if not flows:
            return
        netdir = self.run_dir / "net"
        netdir.mkdir(exist_ok=True)
        writer = PcapWriter(str(netdir / "capture.pcap"))
        added = False
        for i, flow in enumerate(flows.values()):
            added = writer.add_flow(flow["raddr"], flow["chunks"], sport=40000 + i) or added
        if added:
            writer.write()

    def capture_artifacts(self) -> None:
        # The specimen (now exited) may have replaced a recorded /work file with a
        # symlink to an arbitrary host file, so re-reading it here would exfiltrate
        # that file into a downloadable artifact. Since the specimen is gone there
        # is no live race: resolve each path and refuse anything whose real
        # location escapes the workdir (this catches a symlinked final component
        # AND symlinked parent dirs). Read the resolved path, whose final component
        # is guaranteed not to be a symlink.
        workdir_real = os.path.realpath(self.workdir)
        prefix = workdir_real + os.sep
        for path in sorted(self.written_files):
            real = os.path.realpath(path)
            if real != workdir_real and not real.startswith(prefix):
                continue
            if not os.path.isfile(real):
                continue
            try:
                data = Path(real).read_bytes()[:_MAX_ARTIFACT_BYTES]
            except OSError:
                continue
            artifact_id = self.store.add_artifact(os.path.basename(path), data)
            if self.yara and self.yara.enabled():
                for d in self.yara.scan(data, {"artifact_id": artifact_id}):
                    self.record_detection(d)

    def finalize(self, status: str, exit_code: int | None, kill_reason: str | None) -> None:
        self.store.counts["net_flows"] = len(self.net_flows)
        self.store.update_meta(
            status=status, exit_code=exit_code, stopped_wall=wall_ns(),
            kill_reason=kill_reason, counts=dict(self.store.counts),
            verdict=self.verdict.to_dict(),
        )
        self.store.close()
