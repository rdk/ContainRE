"""TLS-MITM tests: the sink terminates TLS with a per-SNI cert from its CA, so
HTTPS requests become readable when the sandbox trusts the CA."""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.specimen


def _https(result):
    return [e["data"] for e in result.events()
            if e["kind"] == "net" and e["data"].get("op") == "http"]


def _console(result):
    p = result.run_dir / "console.log"
    return p.read_text() if p.exists() else ""


def test_https_specimen_is_decrypted_with_mitm(harness):
    r = harness("httpsbeacon", network={"posture": "simulate", "mitm": True})
    assert r.status == "finished" and r.exit_code == 0
    https = _https(r)
    assert https, "expected a decrypted HTTPS request"
    assert https[0]["tls"] is True
    assert https[0]["http"]["path"] == "/gate/beacon"
    assert https[0]["http"]["host"] == "secure.evil.example.com"
    assert "HTTP/1.1 200 OK" in _console(r)
    assert "http-request" in [d["data"]["id"] for d in r.detections()]
    assert (r.run_dir / "ca.pem").exists()


def test_https_is_opaque_without_mitm(harness):
    # simulate posture but mitm off: the sink can't speak TLS, so the specimen's
    # handshake fails and nothing is decrypted.
    r = harness("httpsbeacon", network={"posture": "simulate", "mitm": False})
    assert r.exit_code == 2
    assert "handshake failed" in _console(r)
    assert not any(h["http"]["path"] == "/gate/beacon" for h in _https(r))
