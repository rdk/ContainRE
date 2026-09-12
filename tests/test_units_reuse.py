"""Unit tests for the generic supervised/reuse-container mechanism (no daemon).

Covers reuse.list_live/is_busy liveness (marker + pgid + cold-start window),
the reuse-hash's creation-only semantics (per-exec wallclock must NOT churn
identity), and the busy-guard that refuses to replace a live reuse container.
All docker/in-container calls are monkeypatched.
"""
from __future__ import annotations

import json
import subprocess
from copy import deepcopy
from pathlib import Path

import pytest

from containre.interfaces import Job, RunHandle
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


def test_reap_retains_failed_kill_for_retry(tmp_path, monkeypatch):
    container = "c1"
    run_dir = _run_with_marker(tmp_path, "orphan", container, pgid=4242)
    reuse.mark_owner(run_dir, 200, "start")
    monkeypatch.setattr(reuse, "owner_alive", lambda *a: False)
    monkeypatch.setattr(reuse, "_pgid_alive", lambda *a: True)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: False)

    assert reuse.reap(tmp_path, container) == []
    assert (run_dir / reuse.MARKER_FILE).exists()
    assert reuse.read_owner(run_dir) == (200, "start")
    assert reuse.is_busy(tmp_path, container)
    assert not reuse.stop_if_idle(tmp_path, container)

    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    assert reuse.reap(tmp_path, container) == ["orphan"]
    assert not (run_dir / reuse.MARKER_FILE).exists()
    assert reuse.read_owner(run_dir) is None
    assert not reuse.is_busy(tmp_path, container)


def test_reap_retains_pending_exec_until_pgid_is_available(tmp_path, monkeypatch):
    run_dir = _run_with_marker(tmp_path, "pending", "c1")
    reuse.mark_owner(run_dir, 200, "start")
    monkeypatch.setattr(reuse, "owner_alive", lambda *a: False)
    killed = []
    monkeypatch.setattr(reuse, "_kill_pgid", lambda c, p: killed.append((c, p)) or True)

    assert reuse.reap(tmp_path, "c1") == []
    assert killed == []
    assert reuse.read_owner(run_dir) == (200, "start")
    assert reuse.is_busy(tmp_path, "c1")

    (run_dir / reuse.PGID_FILE).write_text("4242")
    assert reuse.reap(tmp_path, "c1") == ["pending"]
    assert killed == [("c1", 4242)]


# -- per-exec stop must stay per-exec after cleanup ----------------------------

@pytest.mark.parametrize("explicit_mode", [False, True])
def test_repeated_stop_never_kills_shared_container(tmp_path, monkeypatch, explicit_mode):
    run_dir = _run_with_marker(tmp_path, "target", "c1", pgid=4242)
    handle = RunHandle(run_dir=run_dir, runtime="docker", container="c1",
                       reuse_exec=explicit_mode)
    killed = []
    monkeypatch.setattr(reuse, "_kill_pgid", lambda c, p: killed.append((c, p)) or True)
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail(f"unexpected container control: {a[0]}"))
    rt = DockerRuntime()

    rt.stop(handle)
    assert not (run_dir / reuse.MARKER_FILE).exists()
    rt.stop(handle)
    assert killed == [("c1", 4242)]  # no second signal to a stale pgid, either


def test_stop_after_external_cleanup_is_noop(tmp_path, monkeypatch):
    run_dir = _run_with_marker(tmp_path, "target", "c1", pgid=4242)
    handle = RunHandle(run_dir=run_dir, runtime="docker", container="c1", reuse_exec=True)
    reuse.clear(run_dir)  # e.g. an external reaper, before this runtime's first stop
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: pytest.fail("stale pgid signalled"))
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail("shared container killed"))
    DockerRuntime().stop(handle)


def test_legacy_handle_reuse_identity_cannot_be_reset_by_racing_stop(tmp_path, monkeypatch):
    run_dir = _run_with_marker(tmp_path, "target", "c1", pgid=4242)
    handle = RunHandle(run_dir=run_dir, runtime="docker", container="c1")
    rt = DockerRuntime()
    original_exists = Path.exists
    interleaved = False

    def exists_after_other_stop(path):
        nonlocal interleaved
        if path == run_dir / reuse.MARKER_FILE and not interleaved:
            interleaved = True
            rt.stop(handle)  # promotes reuse_exec and removes the marker
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", exists_after_other_stop)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail("shared container killed"))
    rt.stop(handle)
    assert handle.reuse_exec


@pytest.mark.parametrize("pending", [False, True])
def test_stop_retains_tracking_until_confirmed_killed(tmp_path, monkeypatch, pending):
    run_dir = _run_with_marker(tmp_path, "target", "c1", pgid=None if pending else 4242)
    reuse.mark_owner(run_dir, 200, "start")
    handle = RunHandle(run_dir=run_dir, runtime="docker", container="c1", reuse_exec=True)
    monkeypatch.setattr(reuse, "_pgid_alive", lambda *a: True)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: False)
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail("shared container killed"))
    rt = DockerRuntime()

    rt.stop(handle)
    assert reuse.read_owner(run_dir) == (200, "start")
    assert reuse.is_busy(tmp_path, "c1")

    (run_dir / reuse.PGID_FILE).write_text("4242")
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    rt.stop(handle)
    assert not (run_dir / reuse.MARKER_FILE).exists()
    assert reuse.read_owner(run_dir) is None


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


@pytest.mark.parametrize("section, key, value", [
    ("runtime", "supervisor_env", {"SERVICE_MODE": "new"}),
    ("runtime", "setup_commands", ["/bin/true"]),
    ("runtime", "ready_probe", "test -f /work/service-ready"),
    ("runtime", "ca_path", "/work/another-ca.pem"),
    ("runtime", "command_shell", "/bin/bash"),
    ("network", "sink", {"listen_port": 43210}),
    ("network", "mitm", True),
])
def test_supervisor_creation_settings_change_reuse_hash(tmp_path, section, key, value):
    before = _job(tmp_path)
    after = deepcopy(before)
    after.policy[section][key] = value
    rt = DockerRuntime()
    assert rt._reuse_config_hash(before, tmp_path, tmp_path) != rt._reuse_config_hash(
        after, tmp_path, tmp_path)

    # Without a supervisor these are per-exec settings, not shared service config.
    before.policy["runtime"]["docker_reuse_supervised"] = False
    after.policy["runtime"]["docker_reuse_supervised"] = False
    assert rt._reuse_config_hash(before, tmp_path, tmp_path) == rt._reuse_config_hash(
        after, tmp_path, tmp_path)


def test_supervisor_hash_is_independent_of_mapping_order(tmp_path):
    before = _job(tmp_path)
    before.policy["runtime"]["supervisor_env"] = {"FIRST": "1", "SECOND": "2"}
    before.policy["network"]["sink"] = {"listen_port": 1234, "nested": {"x": 1, "y": 2}}
    after = deepcopy(before)
    after.policy["runtime"]["supervisor_env"] = {"SECOND": "2", "FIRST": "1"}
    after.policy["network"]["sink"] = {"nested": {"y": 2, "x": 1}, "listen_port": 1234}
    rt = DockerRuntime()
    assert rt._reuse_config_hash(before, tmp_path, tmp_path) == rt._reuse_config_hash(
        after, tmp_path, tmp_path)


def test_supervisor_hash_preserves_setup_command_order(tmp_path):
    before = _job(tmp_path)
    before.policy["runtime"]["setup_commands"] = ["first", "second"]
    after = deepcopy(before)
    after.policy["runtime"]["setup_commands"].reverse()
    rt = DockerRuntime()
    assert rt._reuse_config_hash(before, tmp_path, tmp_path) != rt._reuse_config_hash(
        after, tmp_path, tmp_path)


def test_supervisor_hash_ignores_per_exec_settings(tmp_path):
    before = _job(tmp_path)
    after = deepcopy(before)
    after.run_dir = before.run_dir.parent / "another-run"
    after.args = ["--different-input"]
    after.env = {"INPUT": "another-input"}
    after.policy["specimen"]["env"] = after.env
    after.policy["runtime"].update(owner_pid=123, owner_token="start", ready_timeout_s=90)
    after.policy["limits"]["wallclock_s"] = 120
    rt = DockerRuntime()
    assert rt._reuse_config_hash(before, tmp_path, tmp_path) == rt._reuse_config_hash(
        after, tmp_path, tmp_path)


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


# -- reuse-exec wait(): tolerate a wedged `docker exec` ------------------------

class _FakeProc:
    """Stand-in for the `docker exec` Popen. poll_rc=None models a WEDGED exec
    (never returns, as observed under shared-container concurrency); an int
    models a normal exit."""
    def __init__(self, poll_rc=None):
        self._rc = poll_rc
        self.killed = False

    def poll(self):
        return self._rc

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        # A wedged exec never returns -> .wait(timeout) times out, exactly as the
        # old proc.wait()-based path would see it (so the fix is what rescues it).
        if self._rc is None:
            raise subprocess.TimeoutExpired(cmd="docker exec", timeout=timeout)
        return self._rc


def _reuse_handle(tmp_path, *, status, exit_code=None, container="c1"):
    run_dir = tmp_path / "runs" / "r1"
    run_dir.mkdir(parents=True)
    reuse.mark(run_dir, container)  # writes MARKER_FILE -> _is_reuse_exec() True
    (run_dir / reuse.PGID_FILE).write_text("4242")
    if status is not None:
        (run_dir / "meta.json").write_text(
            json.dumps({"run_id": "r1", "status": status, "exit_code": exit_code}))
    return RunHandle(run_dir=run_dir, runtime="docker", container=container, pid=1)


def test_wait_reuse_exec_short_circuits_on_terminal_meta(tmp_path, monkeypatch):
    # A wedged `docker exec` (poll never returns) must NOT stall wait(): once the
    # run's meta.json is terminal (the in-container runner finalized), wait()
    # reaps the stray exec and returns its exit code instead of blocking ~grace.
    rt = DockerRuntime()
    rt._REUSE_WAIT_POLL_S = 0.01
    handle = _reuse_handle(tmp_path, status="finished", exit_code=0)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    proc = _FakeProc(poll_rc=None)
    rt._procs[str(handle.run_dir)] = proc
    assert rt.wait(handle, timeout=5.0) == 0
    assert proc.killed is True                                  # stray exec reaped
    assert not (handle.run_dir / reuse.MARKER_FILE).exists()    # marker cleared


def test_wait_reuse_exec_returns_proc_rc_when_exec_exits(tmp_path, monkeypatch):
    # Normal case: the exec returns -> use its rc, don't consult meta.
    rt = DockerRuntime()
    handle = _reuse_handle(tmp_path, status=None)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    rt._procs[str(handle.run_dir)] = _FakeProc(poll_rc=7)
    assert rt.wait(handle, timeout=5.0) == 7
    assert not (handle.run_dir / reuse.MARKER_FILE).exists()


def test_wait_reuse_exec_times_out_when_meta_never_terminal(tmp_path, monkeypatch):
    # Genuine in-container hang (meta stays 'running', exec never returns): wait()
    # still bounds on the grace timeout and returns None (unchanged behavior).
    rt = DockerRuntime()
    rt._REUSE_WAIT_POLL_S = 0.01
    handle = _reuse_handle(tmp_path, status="running")
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: True)
    proc = _FakeProc(poll_rc=None)
    rt._procs[str(handle.run_dir)] = proc
    assert rt.wait(handle, timeout=0.2) is None
    assert proc.killed is True


@pytest.mark.parametrize("finish", ["normal", "terminal-meta", "timeout"])
@pytest.mark.parametrize("kill_succeeds", [False, True])
def test_stop_after_wait_never_kills_peers_or_forgets_failed_cleanup(
    tmp_path, monkeypatch, finish, kill_succeeds,
):
    rt = DockerRuntime()
    rt._REUSE_WAIT_POLL_S = 0.001
    handle = _reuse_handle(tmp_path, status="finished" if finish == "terminal-meta" else None,
                           exit_code=0)
    reuse.mark_owner(handle.run_dir, 200, "start")
    rt._procs[str(handle.run_dir)] = _FakeProc(poll_rc=0 if finish == "normal" else None)
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: kill_succeeds)
    monkeypatch.setattr(dockermod.subprocess, "run",
                        lambda *a, **k: pytest.fail("shared container killed"))

    assert rt.wait(handle, timeout=0.01) == (None if finish == "timeout" else 0)
    rt.stop(handle)  # orchestrator timeout fallback or a late API cancellation
    assert (handle.run_dir / reuse.MARKER_FILE).exists() is not kill_succeeds
    assert (reuse.read_owner(handle.run_dir) is None) is kill_succeeds


def test_wait_supervised_ready(tmp_path):
    rt = DockerRuntime()
    policy = {"runtime": {"ready_timeout_s": 0.4}}
    # No marker -> raise after the timeout (an unhealthy container).
    with pytest.raises(DockerError, match="not ready"):
        rt._wait_supervised_ready(tmp_path, policy, poll_s=0.05)
    # Marker present -> return immediately.
    (tmp_path / ".containre-ready").write_text("1")
    rt._wait_supervised_ready(tmp_path, policy, poll_s=0.05)


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
