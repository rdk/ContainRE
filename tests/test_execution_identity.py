"""Exercise the identity fence, including real kernel process-group control."""
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from containre.control.orchestrator import create_run
from containre.runtime import execution, reuse

pytestmark = pytest.mark.unit


def record(proc):
    return {"version": 1, "phase": "running", "pgid": proc.pid,
            "leader_start": execution.start_token(proc.pid),
            "init_start": execution.start_token(1),
            "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "container_name": "shared", "container_id": "a" * 64}


@pytest.fixture
def peer():
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                            start_new_session=True)
    try:
        yield proc
    finally:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()


def test_stale_leader_token_never_signals_replacement(peer):
    value = record(peer)
    value["leader_start"] += "0"
    assert execution.control(value, stop=True) == "gone"
    assert peer.poll() is None


@pytest.mark.parametrize("field", ["boot_id", "init_start"])
def test_stale_container_generation_never_signals_peer(peer, field):
    value = record(peer)
    value[field] += "-previous"
    assert execution.control(value, stop=True) == "gone"
    assert peer.poll() is None


def test_matching_pidfd_stops_only_target(peer):
    target = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"],
                              start_new_session=True)
    try:
        assert execution.control(record(target), stop=True) == "gone"
        assert target.wait(timeout=5) < 0
        assert peer.poll() is None
    finally:
        if target.poll() is None:
            target.kill()
            target.wait()


def test_exited_unreaped_leader_still_anchors_surviving_children(tmp_path, peer):
    child_pid = tmp_path / "child"
    code = ("import subprocess; from pathlib import Path; "
            "p=subprocess.Popen(['sleep','60']); "
            f"Path({str(child_pid)!r}).write_text(str(p.pid))")
    leader = subprocess.Popen([sys.executable, "-c", code], start_new_session=True)
    value = record(leader)
    try:
        deadline = time.monotonic() + 5
        while os.waitid(os.P_PID, leader.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            assert time.monotonic() < deadline
            time.sleep(0.01)
        assert int(child_pid.read_text()) in execution.group_members(leader.pid)
        assert execution.control(value, stop=True) == "gone"
        assert execution.group_members(leader.pid) == []
        assert peer.poll() is None
    finally:
        os.killpg(leader.pid, signal.SIGKILL)
        leader.wait()


@pytest.mark.parametrize("phase", ["reserved", "pending"])
def test_cancellation_fences_unstarted_execution(tmp_path, monkeypatch, phase):
    run = tmp_path / "run"
    run.mkdir()
    with execution.locked(run):
        execution.write(run, {"version": 1, "phase": phase, "container_name": "shared"})
    monkeypatch.setattr(reuse, "_exec", lambda *a: pytest.fail("unstarted execution signalled"))
    assert reuse.kill(tmp_path, "shared", "run", reserve_cancel=True)
    assert execution.read(run)["phase"] == "stopped"


def test_cancel_before_cli_creation_prevents_delayed_launch(tmp_path):
    assert reuse.kill(tmp_path, "shared", "reserved-id", reserve_cancel=True)
    with pytest.raises(FileExistsError):
        create_run({"specimen": {"path": sys.executable}}, tmp_path, run_id="reserved-id")
    assert execution.read(tmp_path / "reserved-id")["phase"] == "stopped"


@pytest.mark.parametrize("value", ["broken", "{}", '{"version": 1, "phase":"invented"}'])
def test_invalid_existing_record_cannot_authorize_cleanup(tmp_path, monkeypatch, value):
    run = tmp_path / "run"
    run.mkdir()
    (run / execution.RECORD).write_text(value)
    reuse.mark(run, "shared")
    monkeypatch.setattr(reuse, "_exec", lambda *a: pytest.fail("invalid identity signalled"))
    assert not reuse.kill(tmp_path, "shared", "run", reserve_cancel=True)
    assert reuse.is_busy(tmp_path, "shared")
    assert (run / execution.RECORD).read_text() == value


def test_legacy_pgid_is_retained_without_unverified_signal(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    reuse.mark(run, "shared")
    (run / reuse.PGID_FILE).write_text("4242")
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: pytest.fail("legacy PID signalled"))
    assert not reuse.kill(tmp_path, "shared", "run")


def test_cleanup_uses_recorded_container_id_and_retains_actual_provenance(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    value = {"version": 1, "phase": "running", "container_name": "shared",
             "container_id": "a" * 64, "image_id": "sha256:actual", "pgid": 42}
    with execution.locked(run):
        execution.write(run, value)
    calls = []

    def probe(cid, argv):
        calls.append((cid, json.loads(argv[-2])))
        return "gone"

    monkeypatch.setattr(reuse, "_exec", probe)
    assert reuse.kill(tmp_path, "shared", "run", reserve_cancel=True)
    assert calls == [(value["container_id"], value)]
    assert execution.read(run) == {**value, "phase": "stopped"}


@pytest.mark.parametrize("run_id", ["../escaped", "a/b", ".", ".."])
def test_explicit_ids_cannot_escape_runs_root(tmp_path, run_id):
    with pytest.raises(ValueError):
        reuse.kill(tmp_path, "shared", run_id, reserve_cancel=True)
    with pytest.raises(ValueError):
        create_run({"specimen": {"path": sys.executable}}, tmp_path, run_id=run_id)
