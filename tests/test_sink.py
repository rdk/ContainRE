"""Simulated-internet sink tests: simulate posture redirects egress to the sink
so the specimen 'talks' and its requests are captured."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.specimen


def _nets(result):
    return [e["data"] for e in result.events() if e["kind"] == "net"]


def _det_ids(result):
    return [d["data"]["id"] for d in result.detections()]


def test_deny_blocks_connect(harness):
    r = harness("netbeacon", network={"posture": "deny"})
    conn = [d for d in _nets(r) if d.get("op") == "connect"][0]
    assert conn["decision"] == "block"
    assert "redirected_to" not in conn
    assert "returned -1" in (r.run_dir / "console.log").read_text()


def test_simulate_redirects_connect_to_sink(harness):
    r = harness("netbeacon", network={"posture": "simulate"})
    conn = [d for d in _nets(r) if d.get("op") == "connect"][0]
    assert conn["decision"] == "simulated"
    assert conn["raddr"].startswith("93.184.216.34")       # original target recorded
    assert conn["redirected_to"].startswith("127.0.0.1:")  # sent to the sink instead
    # the specimen sees the connection SUCCEED (returns 0), not fail
    assert "returned 0" in (r.run_dir / "console.log").read_text()


def test_simulate_answers_http_and_captures_request(harness):
    r = harness("httpbeacon", network={"posture": "simulate"})
    assert r.status == "finished" and r.exit_code == 0
    http = [d for d in _nets(r) if d.get("op") == "http"]
    assert http, "expected the sink to record an HTTP request"
    h = http[0]["http"]
    assert h["method"] == "GET"
    assert h["path"] == "/malware/config"
    assert h["host"] == "evil.example.com"
    # the specimen received the canned response
    assert "HTTP/1.1 200 OK" in (r.run_dir / "console.log").read_text()
    # and the request surfaced as an IOC detection
    assert "http-request" in _det_ids(r)
    urls = [ioc["value"] for d in r.detections() if d["data"]["id"] == "http-request"
            for ioc in d["data"].get("iocs", [])]
    assert "http://evil.example.com/malware/config" in urls
