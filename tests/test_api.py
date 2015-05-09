"""Control-plane API tests (headless, via FastAPI TestClient - no browser)."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from containre.api import create_app

pytestmark = pytest.mark.specimen


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(runs_root=tmp_path / "runs", runtime_name="local"))


def _wait_finished(client, run_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        meta = client.get(f"/api/runs/{run_id}").json()
        if meta["status"] in ("finished", "killed", "error") and not meta.get("active"):
            return meta
        time.sleep(0.1)
    raise AssertionError(f"run {run_id} did not finish in {timeout}s")


def test_health_and_index(client):
    assert client.get("/api/health").json()["ok"] is True
    idx = client.get("/")
    assert idx.status_code == 200 and "ContainRE" in idx.text


def test_create_run_and_read_back(client, build_specimen):
    binp = str(build_specimen("filewriter"))
    r = client.post("/api/runs", json={"binary": binp, "net": "deny", "decoys": ["wallet.dat"]})
    assert r.status_code == 201
    run_id = r.json()["run_id"]

    meta = _wait_finished(client, run_id)
    assert meta["status"] == "finished"
    assert meta["runtime"] == "local"

    events = client.get(f"/api/runs/{run_id}/events").json()["events"]
    assert any(e["kind"] == "file" for e in events)
    assert any(e["kind"] == "detection" and e["data"]["id"] == "decoy-access" for e in events)

    assert any(m["run_id"] == run_id for m in client.get("/api/runs").json()["runs"])


def test_events_pagination_by_seq(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("hello")),
                                            "net": "deny"}).json()["run_id"]
    _wait_finished(client, run_id)
    first = client.get(f"/api/runs/{run_id}/events", params={"limit": 2}).json()
    assert len(first["events"]) <= 2
    rest = client.get(f"/api/runs/{run_id}/events", params={"since": first["next_seq"]}).json()
    seqs = [e["seq"] for e in first["events"]] + [e["seq"] for e in rest["events"]]
    assert seqs == sorted(seqs) and len(seqs) == len(set(seqs))


def test_snapshots_and_online_memory_view(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("unpacker")),
                                            "net": "deny"}).json()["run_id"]
    _wait_finished(client, run_id)
    snaps = client.get(f"/api/runs/{run_id}/snapshots").json()["snapshots"]
    assert snaps, "expected memory snapshots"
    sid = snaps[0]["data"]["snapshot_id"]
    mem = client.get(f"/api/runs/{run_id}/memory", params={"snapshot": sid}).json()
    assert mem["snapshot_id"] == sid
    assert isinstance(mem["regions"], list) and mem["regions"]
    assert isinstance(mem["hexdump"], str)


def test_websocket_live_stream(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("netbeacon")),
                                            "net": "deny"}).json()["run_id"]
    events = 0
    statuses = []
    with client.websocket_connect(f"/api/runs/{run_id}/stream") as ws:
        for _ in range(1000):
            msg = ws.receive_json()
            if msg["type"] == "event":
                events += 1
            elif msg["type"] == "status":
                statuses.append(msg["status"])
                if msg["status"] in ("finished", "killed") and not msg["active"]:
                    break
    assert events > 0
    assert statuses and statuses[-1] in ("finished", "killed")


def test_capacity_limit(client, build_specimen):
    # cap of 0 active is impossible; use a dedicated client with cap=1 and a slow run
    app_client = TestClient(create_app(runs_root=client.app.state.manager.runs_root,
                                       runtime_name="local", max_concurrent=1))
    slow = str(build_specimen("sleeper"))
    first = app_client.post("/api/runs", json={"binary": slow, "net": "deny", "timeout": 5})
    assert first.status_code == 201
    second = app_client.post("/api/runs", json={"binary": slow, "net": "deny", "timeout": 5})
    assert second.status_code == 429
    app_client.post(f"/api/runs/{first.json()['run_id']}/stop")


def test_detections_endpoint(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("filewriter")),
                                            "net": "deny", "decoys": ["wallet.dat"]}).json()["run_id"]
    _wait_finished(client, run_id)
    dets = client.get(f"/api/runs/{run_id}/detections").json()["detections"]
    assert any(d["data"]["id"] == "decoy-access" for d in dets)


def test_summary_endpoint_exposes_metrics_and_assertions(client, build_specimen):
    policy = {
        "report": {
            "assertions": [
                {
                    "id": "no-remote",
                    "subject": "network.remote_endpoint_event_count",
                    "op": "eq",
                    "value": 0,
                }
            ]
        }
    }
    run_id = client.post("/api/runs", json={
        "binary": str(build_specimen("hello")),
        "net": "deny",
        "policy": policy,
    }).json()["run_id"]
    _wait_finished(client, run_id)

    summary = client.get(f"/api/runs/{run_id}/summary").json()

    assert summary["metrics"]["network.remote_endpoint_event_count"] == 0
    assert summary["assertions"]["status"] == "passed"
    assert summary["assertions"]["results"][0]["id"] == "no-remote"


def test_static_endpoint_and_query(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("netbeacon")),
                                            "net": "deny"}).json()["run_id"]
    _wait_finished(client, run_id)

    static = client.get(f"/api/runs/{run_id}/static").json()
    assert static["summary"]["symbols"] > 0
    assert static["summary"]["call_edges"] > 0

    query = client.get(f"/api/runs/{run_id}/static/query", params={"symbol": "connect"}).json()
    assert query["matches"]
    assert query["callers"]


def test_artifacts_list_and_download(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("filewriter")),
                                            "net": "deny", "decoys": ["wallet.dat"]}).json()["run_id"]
    _wait_finished(client, run_id)
    arts = client.get(f"/api/runs/{run_id}/artifacts").json()["artifacts"]
    names = [a["name"] for a in arts]
    assert any(n.endswith("output.txt") for n in names)
    target = next(n for n in names if n.endswith("output.txt"))
    dl = client.get(f"/api/runs/{run_id}/artifacts/{target}")
    assert dl.status_code == 200 and b"normal-data" in dl.content
    # traversal guard (checked at the manager level; routing rejects most, this the rest)
    assert client.app.state.manager.artifact_path(run_id, "../../../etc/passwd") is None


def test_pcap_endpoint(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("httpbeacon")),
                                            "net": "simulate"}).json()["run_id"]
    _wait_finished(client, run_id)
    r = client.get(f"/api/runs/{run_id}/pcap")
    assert r.status_code == 200
    assert r.content[:4] == b"\xd4\xc3\xb2\xa1"          # little-endian pcap magic
    assert b"GET /malware/config" in r.content


def test_checkpoint_degrades_and_is_recorded(client, build_specimen):
    run_id = client.post("/api/runs", json={"binary": str(build_specimen("hello")),
                                            "net": "deny"}).json()["run_id"]
    _wait_finished(client, run_id)
    # a finished run is not active -> best-effort checkpoint returns a structured
    # (not-ok) result, HTTP 200 (graceful, never a 500)
    r = client.post(f"/api/runs/{run_id}/checkpoint")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False and "not active" in body["reason"]
    # ...and the attempt is recorded + listed
    cps = client.get(f"/api/runs/{run_id}/checkpoints").json()["checkpoints"]
    assert cps and cps[0]["ok"] is False


def test_missing_run_is_404(client):
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/api/runs/nope/events").status_code == 404
    assert client.get("/api/runs/nope/detections").status_code == 404
    assert client.get("/api/runs/nope/pcap").status_code == 404
    assert client.post("/api/runs/nope/checkpoint").status_code == 404
    assert client.get("/api/runs/nope/checkpoints").status_code == 404
