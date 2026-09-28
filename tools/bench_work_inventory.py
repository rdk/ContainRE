"""Time the report's work-file inventory on a large shared work mount.

Builds a synthetic work mount shaped like one that many runs share (each run's
files under jobs/<id>/, its records under runs/<id>/), then times
summarize_run_dir with report.work_inventory set to all, one run's subdir, and
none. This is a benchmark, not a test: the numbers depend on the machine, the
filesystem and the page cache (the tree is freshly written, so the cache is
warm).

    uv run python tools/bench_work_inventory.py                      # 200k files, temp dir
    uv run python tools/bench_work_inventory.py --files 1000000 --root /scratch/inv
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import statistics
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import yaml

from containre.report import summarize_run_dir

FILES_PER_DIR = 50


def _build_run(args: tuple[str, int, int]) -> int:
    """Write one run's files; returns how many. Content depends only on the
    run index, so the tree is the same whatever the worker count."""
    work, index, files = args
    job = Path(work) / "jobs" / f"r{index:05d}"
    written = 0
    for chunk in range((files + FILES_PER_DIR - 1) // FILES_PER_DIR):
        out = job / "out" / f"c{chunk:04d}"
        out.mkdir(parents=True, exist_ok=True)
        for j in range(min(FILES_PER_DIR, files - written)):
            (out / f"f{j:03d}.txt").write_text(f"{index}:{chunk}:{j}\n")
            written += 1
    record = Path(work) / "runs" / f"r{index:05d}"
    record.mkdir(parents=True, exist_ok=True)
    (record / "events.jsonl").write_text("{}\n")
    return written + 1


def _time(run: Path, work: Path, scope: object, repeat: int) -> tuple[float, dict]:
    policy = {"specimen": {"path": "/bin/true"}, "files": {"work_mount": str(work)},
              "report": {"work_inventory": scope}}
    (run / "policy.yaml").write_text(yaml.safe_dump(policy))
    times = []
    summary: dict = {}
    for _ in range(repeat):
        started = time.perf_counter()
        summary = summarize_run_dir(run)
        times.append(time.perf_counter() - started)
    return statistics.median(times), summary["work_files"]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--files", type=int, default=200_000, help="total files in the tree")
    parser.add_argument("--runs", type=int, default=200, help="runs sharing the work mount")
    parser.add_argument("--root", type=Path, help="where to build the tree (default: a temp dir)")
    parser.add_argument("--keep", action="store_true", help="leave the tree in place")
    parser.add_argument("--repeat", type=int, default=3, help="timed repetitions per scope")
    parser.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 1) - 2),
                        help="processes used to build the tree")
    args = parser.parse_args()

    root = args.root or Path(tempfile.mkdtemp(prefix="containre-inventory-bench-"))
    root.mkdir(parents=True, exist_ok=True)
    work = root / "work"
    run = root / "run"
    try:
        per_run = max(1, args.files // args.runs)
        started = time.perf_counter()
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            total = sum(pool.map(_build_run, [(str(work), i, per_run) for i in range(args.runs)],
                                 chunksize=4))
        built_s = time.perf_counter() - started
        run.mkdir(exist_ok=True)
        (run / "meta.json").write_text(json.dumps({"run_id": "bench", "status": "finished"}))
        (run / "events.jsonl").write_text("")
        print(f"tree: {total:,} files, {args.runs} runs, built in {built_s:.1f}s at {work}")

        print(f"{'scope':<22} {'count':>9} {'median s':>10}")
        for label, scope in [
            ("all", "all"),
            ("subdir jobs/r00000", {"subdir": "jobs/r00000"}),
            ("none", "none"),
        ]:
            seconds, inventory = _time(run, work, scope, args.repeat)
            print(f"{label:<22} {inventory['count']:>9,} {seconds:>10.4f}")
    finally:
        if not args.keep:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
