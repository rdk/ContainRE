"""Unit/local-loopback tests for built-in network sink and MITM helpers."""
from __future__ import annotations

import socket
import ssl
import time

import pytest

from containre.net import BuiltinSink, MitmCA

pytestmark = [pytest.mark.unit, pytest.mark.localnet]

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def test_mitm_close_removes_temp_key_dir():
    ca = MitmCA()
    d = ca._dir
    assert d.exists()
    ca.close()
    assert not d.exists()   # leaf-key temp dir cleaned up


def test_mitm_context_for_caps_distinct_sni_minting(monkeypatch):
    ca = MitmCA()
    monkeypatch.setattr(ca, "_leaf_context", lambda host: object())  # avoid real keygen
    monkeypatch.setattr(MitmCA, "_MAX_CONTEXTS", 3)

    ctxs = [ca.context_for(f"h{i}.example") for i in range(10)]

    assert len(ca._contexts) == 3   # per-SNI cache is bounded
    # beyond the cap a single shared default context is reused, not newly minted
    assert ctxs[5] is ctxs[9]
    assert ca.context_for("later.example") is ctxs[9]


def test_stop_survives_unstarted_handler_thread():
    import threading
    sink = BuiltinSink(on_interaction=lambda info: None)
    # a handler registered but never started (e.g. start() hit the pids-limit)
    sink._handlers.append(threading.Thread(target=lambda: None))
    sink.stop()  # must not raise RuntimeError on the unstarted thread


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type & 0xFF, flags & 0xFF])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def recv_until(sock: ssl.SSLSocket, needle: bytes, timeout: float = 3.0) -> bytes:
    end = time.monotonic() + timeout
    data = b""
    sock.settimeout(0.2)
    while time.monotonic() < end:
        if needle in data:
            return data
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data += chunk
    return data


def test_builtin_sink_http_standalone():
    seen = []
    sink = BuiltinSink(on_interaction=seen.append)
    sink.start()
    try:
        c = socket.create_connection(("127.0.0.1", sink.port), timeout=2)
        c.sendall(b"GET /x HTTP/1.0\r\nHost: h\r\n\r\n")
        resp = c.recv(200)
        c.close()
    finally:
        sink.stop()
    assert b"HTTP/1.1 200 OK" in resp
    assert seen and seen[0]["op"] == "http" and seen[0]["http"]["path"] == "/x"


def test_builtin_sink_classifies_http_split_across_segments():
    seen = []
    sink = BuiltinSink(on_interaction=seen.append)
    sink.start()
    try:
        c = socket.create_connection(("127.0.0.1", sink.port), timeout=2)
        c.sendall(b"GE")             # partial method in the first segment
        time.sleep(0.05)
        c.sendall(b"T /y HTTP/1.0\r\nHost: h\r\n\r\n")
        resp = c.recv(200)
        c.close()
    finally:
        sink.stop()
    assert b"HTTP/1.1 200 OK" in resp
    # must still be recognised as HTTP (so the URL/host IOC is recorded), not TCP
    assert seen and seen[0]["op"] == "http" and seen[0]["http"]["path"] == "/y"


def test_builtin_sink_can_bind_fixed_loopback_port():
    seen = []
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    sink = BuiltinSink(on_interaction=seen.append, sink_config={"listen_port": port})
    sink.start()
    try:
        assert sink.port == port
        c = socket.create_connection(("127.0.0.1", port), timeout=2)
        c.sendall(b"GET /fixed HTTP/1.0\r\nHost: h\r\n\r\n")
        resp = c.recv(200)
        c.close()
    finally:
        sink.stop()
    assert b"HTTP/1.1 200 OK" in resp
    assert seen and seen[0]["http"]["path"] == "/fixed"


def test_mitm_ca_pem_is_a_ca_cert():
    from cryptography import x509

    ca = MitmCA()
    cert = x509.load_pem_x509_certificate(ca.ca_pem())
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert bc.ca is True


def test_mitm_sink_decrypts_https_and_mints_matching_cert():
    ca = MitmCA()
    seen: list[dict] = []
    sink = BuiltinSink(on_interaction=seen.append, mitm=True, ca=ca)
    sink.start()
    try:
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(cadata=ca.ca_pem().decode())
        cctx.check_hostname = True
        raw = socket.create_connection(("127.0.0.1", sink.port), timeout=3)
        tls = cctx.wrap_socket(raw, server_hostname="secure.evil.example.com")
        tls.sendall(b"GET /gate/beacon HTTP/1.0\r\nHost: secure.evil.example.com\r\n\r\n")
        resp = tls.recv(400)
        sans = [v for typ, v in tls.getpeercert().get("subjectAltName", [])]
        tls.close()
    finally:
        sink.stop()
    assert b"HTTP/1.1 200 OK" in resp
    assert "secure.evil.example.com" in sans
    assert seen and seen[0]["op"] == "http" and seen[0]["tls"] is True
    assert seen[0]["http"]["path"] == "/gate/beacon"


def test_h2_grpc_replay_sink_answers_configured_streaming_method():
    ca = MitmCA()
    seen: list[dict] = []
    sink = BuiltinSink(
        on_interaction=seen.append,
        mitm=True,
        ca=ca,
        sink_config={
            "type": "h2-grpc-replay",
            "streaming_methods": ["StreamProbe"],
            "stream_initial_response_hex": "2200",
            "stream_response_hex": "1200",
            "idle_timeout_s": 2,
            "record_payloads": True,
            "payload_preview_bytes": 1,
            "payload_record_limit": 4,
        },
    )
    sink.start()
    try:
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(cadata=ca.ca_pem().decode())
        cctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection(("127.0.0.1", sink.port), timeout=3)
        tls = cctx.wrap_socket(raw, server_hostname="grpc.example.test")
        assert tls.selected_alpn_protocol() == "h2"
        request = (
            H2_PREFACE
            + h2_frame(0x4, 0, 0)
            + h2_frame(0x4, 0x1, 0)
            + h2_frame(0x1, 0x4, 1, b":path /pkg.Service/StreamProbe application/grpc")
            + h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x01A")
            + h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x01B")
        )
        tls.sendall(request)
        data = recv_until(tls, b"\x00\x00\x00\x00\x02\x12\x00")
        tls.close()
    finally:
        sink.stop()

    assert b"\x00\x00\x00\x00\x02\x22\x00" in data
    assert b"\x00\x00\x00\x00\x02\x12\x00" in data
    assert seen and seen[0]["op"] == "h2-grpc-replay"
    assert seen[0]["grpc"]["methods"] == ["StreamProbe"]
    assert seen[0]["grpc"]["messages"] == 2
    assert seen[0]["grpc"]["payloads"] == [
        {
            "stream_id": 1,
            "method": "StreamProbe",
            "data_frame_index": 1,
            "message_in_frame": 1,
            "compressed": False,
            "length": 1,
            "hex": "41",
            "truncated": False,
        },
        {
            "stream_id": 1,
            "method": "StreamProbe",
            "data_frame_index": 2,
            "message_in_frame": 1,
            "compressed": False,
            "length": 1,
            "hex": "42",
            "truncated": False,
        },
    ]


def test_h2_grpc_replay_sink_can_reject_negative_feature_probe():
    ca = MitmCA()
    seen: list[dict] = []
    sink = BuiltinSink(
        on_interaction=seen.append,
        mitm=True,
        ca=ca,
        sink_config={
            "type": "h2-grpc-replay",
            "unary_methods": ["CheckStatus"],
            "negative_feature_substrings": ["FEAT_ALPHA"],
            "negative_grpc_status": "5",
            "negative_grpc_message": "feature {feature} is not expected to exist in the server",
            "idle_timeout_s": 2,
        },
    )
    sink.start()
    try:
        cctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cctx.load_verify_locations(cadata=ca.ca_pem().decode())
        cctx.set_alpn_protocols(["h2"])
        raw = socket.create_connection(("127.0.0.1", sink.port), timeout=3)
        tls = cctx.wrap_socket(raw, server_hostname="grpc.example.test")
        assert tls.selected_alpn_protocol() == "h2"
        request = (
            H2_PREFACE
            + h2_frame(0x4, 0, 0)
            + h2_frame(0x4, 0x1, 0)
            + h2_frame(0x1, 0x4, 1, b":path /pkg.Service/CheckStatus application/grpc")
            + h2_frame(0x0, 0x1, 1, b"\x00\x00\x00\x00\x0aFEAT_ALPHA")
        )
        tls.sendall(request)
        data = recv_until(tls, b"FEAT_ALPHA")
        tls.close()
    finally:
        sink.stop()

    assert b"grpc-status" in data
    assert b"\x015" in data
    assert b"grpc-message" in data
    assert b"feature FEAT_ALPHA is not expected to exist in the server" in data
    assert seen and seen[0]["op"] == "h2-grpc-replay"
    assert seen[0]["grpc"]["negative_features"] == ["FEAT_ALPHA"]
