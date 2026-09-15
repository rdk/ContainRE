"""Stale or incomplete tracking must never authorize control of another exec."""
import os
from pathlib import Path

import pytest

from containre.runtime import reuse

pytestmark = pytest.mark.unit


def test_pending_marker_does_not_expire_into_permission_to_retire(tmp_path):
    run = tmp_path / "slow-launch"
    run.mkdir()
    reuse.mark(run, "shared")
    assert reuse.list_live(tmp_path, "shared", now=1e18)


def test_kill_rejects_a_different_container_before_any_signal(tmp_path, monkeypatch):
    run = tmp_path / "target"
    run.mkdir()
    reuse.mark(run, "original")
    (run / reuse.PGID_FILE).write_text("4242")
    calls = []
    monkeypatch.setattr(reuse, "_kill_pgid", lambda *a: calls.append(a) or True)
    assert not reuse.kill(tmp_path, "replacement", "target")
    assert calls == []


def test_unreadable_owner_is_not_evidence_of_death(monkeypatch):
    def denied(self, *a, **kw):
        raise PermissionError("proc unavailable")

    monkeypatch.setattr(Path, "read_text", denied)
    assert reuse.owner_alive(os.getpid(), "original")
