"""Unit tests for the control-plane WebSocket stream (synthetic run dirs, no specimen)."""
from __future__ import annotations

import json

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from containre.api import create_app

pytestmark = pytest.mark.unit


def _terminal_run(runs_root, run_id, n_events):
    run = runs_root / run_id
    run.mkdir(parents=True)
    run.joinpath("meta.json").write_text(json.dumps({
        "schema_version": 1, "run_id": run_id, "status": "finished",
        "specimen": {"sha256": "0" * 64}, "created_wall": 1,
    }))
    with run.joinpath("events.jsonl").open("w") as fh:
        for i in range(n_events):
            fh.write(json.dumps({"seq": i, "kind": "proc", "data": {"op": "noop"}}) + "\n")


def test_websocket_drains_all_events_on_already_terminal_run(tmp_path):
    runs = tmp_path / "runs"
    _terminal_run(runs, "run-600", 600)   # > one 500-event page
    client = TestClient(create_app(runs_root=runs, runtime_name="local"))

    received = 0
    with client.websocket_connect("/api/runs/run-600/stream") as ws:
        try:
            while True:
                msg = ws.receive_json()
                if msg["type"] == "event":
                    received += 1
        except WebSocketDisconnect:
            pass

    assert received == 600   # every buffered event delivered, not just the first page


def test_websocket_reports_unknown_run(tmp_path):
    client = TestClient(create_app(runs_root=tmp_path / "runs", runtime_name="local"))
    with client.websocket_connect("/api/runs/nope/stream") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error"
