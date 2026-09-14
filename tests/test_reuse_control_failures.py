"""Unknown Docker state must not authorize dropping recovery or stopping peers."""

import subprocess

import pytest

from containre.runtime import reuse

pytestmark = pytest.mark.unit

CID = "a" * 64


def response(cmd, code=0, stdout=""):
    return subprocess.CompletedProcess(cmd, code, stdout, "daemon diagnostic")


@pytest.mark.parametrize("output", [None, "", "garbage", "-1", "0\n1", "9" * 5000])
def test_unknown_probe_never_proves_a_running_group_dead(monkeypatch, output):
    monkeypatch.setattr(reuse, "_exec", lambda *args: output)
    monkeypatch.setattr(
        reuse.subprocess, "run", lambda cmd, **kw: response(cmd, stdout=f"{CID} running\n")
    )
    assert reuse._pgid_alive("containre-reuse-test", 4242)


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "oserror", "malformed"])
def test_failed_daemon_query_preserves_reap_tracking(tmp_path, monkeypatch, failure):
    run = tmp_path / "run"
    run.mkdir()
    reuse.mark(run, "containre-reuse-test")
    reuse.mark_owner(run, 123, "old")
    (run / reuse.PGID_FILE).write_text("4242")
    monkeypatch.setattr(reuse, "owner_alive", lambda *a: False)
    monkeypatch.setattr(reuse, "_exec", lambda *a: None)
    monkeypatch.setattr(reuse.time, "sleep", lambda *a: None)
    ticks = iter(range(1000))
    monkeypatch.setattr(reuse.time, "monotonic", lambda: next(ticks))

    def control(cmd, **kw):
        assert 0 < kw["timeout"] <= 45
        if failure == "timeout":
            raise subprocess.TimeoutExpired(cmd, kw["timeout"])
        if failure == "oserror":
            raise OSError("cannot launch control")
        return response(cmd, code=1 if failure == "nonzero" else 0, stdout="unparseable")

    monkeypatch.setattr(reuse.subprocess, "run", control)
    assert reuse.reap(tmp_path, "containre-reuse-test") == []
    assert (run / reuse.MARKER_FILE).exists()
    assert reuse.read_owner(run) == (123, "old")


@pytest.mark.parametrize("listing", ["", f"{CID} exited\n", f"{CID} dead\n"])
def test_confirmed_absent_or_stopped_container_allows_cleanup(monkeypatch, listing):
    calls = []
    monkeypatch.setattr(reuse, "_exec", lambda *args: None)

    def control(cmd, **kw):
        calls.append(cmd)
        assert kw["timeout"] <= 30
        return response(cmd, stdout=listing)

    monkeypatch.setattr(reuse.subprocess, "run", control)
    assert not reuse._pgid_alive("containre-reuse-test", 4242)
    assert calls and "name=^/containre\\-reuse\\-test$" in calls[0]


@pytest.mark.parametrize("code", [1, 125])
def test_idle_stop_failure_is_not_success_and_preserves_activity(tmp_path, monkeypatch, code):
    container = "containre-reuse-test"
    stamp = reuse._activity_path(tmp_path, container)
    stamp.write_text("123")
    monkeypatch.setattr(reuse.subprocess, "run", lambda cmd, **kw: response(cmd, code=code))
    assert not reuse.stop_if_idle(tmp_path, container)
    assert stamp.read_text() == "123"
    monkeypatch.setattr(reuse.subprocess, "run", lambda cmd, **kw: response(cmd))
    assert reuse.stop_if_idle(tmp_path, container)
    assert not stamp.exists()


@pytest.mark.parametrize("operation", ["probe", "stop"])
def test_control_launch_error_is_unknown_and_retryable(tmp_path, monkeypatch, operation):
    def missing(cmd, **kw):
        raise FileNotFoundError("docker unavailable")

    monkeypatch.setattr(reuse.subprocess, "run", missing)
    if operation == "probe":
        assert reuse._pgid_alive("containre-reuse-test", 4242)
    else:
        assert not reuse.stop_if_idle(tmp_path, "containre-reuse-test")


@pytest.mark.parametrize("output,alive", [("0\n", False), ("1\n", True), ("20\n", True)])
def test_explicit_valid_probe_needs_no_daemon_fallback(monkeypatch, output, alive):
    monkeypatch.setattr(reuse, "_exec", lambda *args: output)
    monkeypatch.setattr(reuse.subprocess, "run", lambda *a, **kw: pytest.fail("unnecessary probe"))
    assert reuse._pgid_alive("containre-reuse-test", 4242) is alive


def test_absence_query_accepts_immutable_container_id(monkeypatch):
    def control(cmd, **kw):
        assert f"id={CID}" in cmd
        return response(cmd)

    monkeypatch.setattr(reuse.subprocess, "run", control)
    assert reuse._container_stopped(CID)
