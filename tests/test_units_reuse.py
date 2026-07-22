"""Unit tests for the generic supervised/reuse-container mechanism (no daemon).

Covers reuse.list_live/is_busy liveness (marker + pgid + cold-start window),
the reuse-hash's creation-only semantics (per-exec wallclock must NOT churn
identity), and the busy-guard that refuses to replace a live reuse container.
All docker/in-container calls are monkeypatched.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from containre.interfaces import Job
from containre.runtime import docker as dockermod
from containre.runtime import reuse
from containre.runtime.docker import DockerError, DockerRuntime


# -- reuse.list_live / is_busy -------------------------------------------------

def _run_with_marker(runs_root, run_id, container, *, pgid=None):
    d = runs_root / run_id
    d.mkdir(parents=True)
    reuse.mark(d, container)
    if pgid is not None:
        (d / reuse.PGID_FILE).write_text(str(pgid))
    return d


def test_list_live_counts_only_live_pgids(tmp_path, monkeypatch):
    C = "containre-reuse-prod"
    _run_with_marker(tmp_path, "live", C, pgid=4242)
    _run_with_marker(tmp_path, "dead", C, pgid=777)
    _run_with_marker(tmp_path, "other", "containre-reuse-else", pgid=4242)
    monkeypatch.setattr(reuse, "_pgid_alive", lambda c, p: p == 4242)

    live = reuse.list_live(tmp_path, C)
    assert {e["run_id"] for e in live} == {"live"}      # dead skipped, other container skipped
    assert reuse.is_busy(tmp_path, C) is True


def test_list_live_pending_window(tmp_path, monkeypatch):
    C = "c1"
    _run_with_marker(tmp_path, "pending", C)  # marker, no pgid yet
    monkeypatch.setattr(reuse, "_pgid_alive", lambda c, p: False)
    # Fresh marker -> counted live (cold start).
    assert reuse.is_busy(tmp_path, C) is True
    # Past the grace window -> no longer live.
    assert reuse.list_live(tmp_path, C, now=1e18) == []


def test_clear_marker_drops_liveness(tmp_path, monkeypatch):
    C = "c1"
    d = _run_with_marker(tmp_path, "r", C, pgid=1)
    monkeypatch.setattr(reuse, "_pgid_alive", lambda c, p: True)
    assert reuse.is_busy(tmp_path, C) is True
    reuse.clear(d)
    assert reuse.is_busy(tmp_path, C) is False


# -- owner-death reaping -------------------------------------------------------

def test_owner_alive_self_vs_dead():
    import os
    tok = reuse.proc_start_token(os.getpid())
    assert reuse.owner_alive(os.getpid(), tok) is True
    assert reuse.owner_alive(os.getpid(), "999999999") is False   # PID reuse guard
    assert reuse.owner_alive(2_000_000_000, None) is False        # dead pid


def test_reap_stops_only_dead_owner_execs(tmp_path, monkeypatch):
    C = "c1"
    live_dir = _run_with_marker(tmp_path, "live", C, pgid=1)
    orph_dir = _run_with_marker(tmp_path, "orph", C, pgid=2)
    reuse.mark_owner(live_dir, 100, "t")
    reuse.mark_owner(orph_dir, 200, "t")
    monkeypatch.setattr(reuse, "owner_alive", lambda pid, tok: pid == 100)
    killed = []
    monkeypatch.setattr(reuse, "_kill_pgid", lambda c, p, **k: killed.append((c, p)) or True)

    assert reuse.reap(tmp_path, C) == ["orph"]
    assert killed == [(C, 2)]                       # only the dead-owner exec
    monkeypatch.setattr(reuse, "_pgid_alive", lambda c, p: True)
    assert {e["run_id"] for e in reuse.list_live(tmp_path, C)} == {"live"}  # orph marker cleared


# -- reuse-hash creation-only semantics ---------------------------------------

def _job(tmp_path, *, wallclock=3600, mem_mb=8192, supervised=True):
    policy = {
        "specimen": {"path": "/work/run_batch.py", "container_path": "/work/run_batch.py",
                     "args": [], "env": {}, "cwd": "/work"},
        "trace": {"tracer": "none"},
        "network": {"posture": "simulate", "docker_network": "none"},
        "files": {}, "limits": {"cpu": 8, "mem_mb": mem_mb, "pids": 1024, "wallclock_s": wallclock},
        "runtime": {"docker_reuse_container": True, "docker_reuse_supervised": supervised,
                    "workload_only": True, "docker_reuse_key": "prod", "docker_user": None},
    }
    return Job(run_dir=Path(tmp_path) / "runs" / "r1", specimen_path="/work/run_batch.py",
               args=[], env={}, cwd="/work", policy=policy)


def test_hash_ignores_per_exec_wallclock_but_tracks_creation_config(tmp_path):
    rt = DockerRuntime()
    sp, wd = Path("/work"), Path("/work")
    base = rt._reuse_config_hash(_job(tmp_path, wallclock=3600), sp, wd)
    assert base == rt._reuse_config_hash(_job(tmp_path, wallclock=120), sp, wd)   # per-exec, ignored
    assert base != rt._reuse_config_hash(_job(tmp_path, mem_mb=4096), sp, wd)     # creation config
    assert base != rt._reuse_config_hash(_job(tmp_path, supervised=False), sp, wd)


# -- busy-guard ----------------------------------------------------------------

def test_ensure_reuse_refuses_to_replace_busy_container(tmp_path, monkeypatch):
    rt = DockerRuntime()
    name = "containre-reuse-prod"
    monkeypatch.setattr(rt, "_inspect_reuse_container", lambda n: (True, True, "OLDHASH"))
    monkeypatch.setattr(dockermod.reuse, "is_busy", lambda root, c: True)
    calls = []
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: calls.append(a[0]) or subprocess.CompletedProcess(a[0], 0, "", ""))
    with pytest.raises(DockerError, match="live exec"):
        rt._ensure_reuse_container(_job(tmp_path), Path("/work"), Path("/work"), name, "NEWHASH")
    assert not any(c[:3] == ["docker", "rm", "-f"] for c in calls)


def test_ensure_reuse_replaces_idle_container(tmp_path, monkeypatch):
    rt = DockerRuntime()
    name = "containre-reuse-prod"
    monkeypatch.setattr(rt, "_inspect_reuse_container", lambda n: (True, True, "OLDHASH"))
    monkeypatch.setattr(dockermod.reuse, "is_busy", lambda root, c: False)
    calls = []
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: calls.append(a[0]) or subprocess.CompletedProcess(a[0], 0, "id", ""))
    rt._ensure_reuse_container(_job(tmp_path), Path("/work"), Path("/work"), name, "NEWHASH")
    assert any(c[:3] == ["docker", "rm", "-f"] for c in calls)
