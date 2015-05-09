"""HTTP/2 gRPC replay inference tests."""
from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from containre.cli.main import app
from containre.net.h2_grpc_replay import H2_PREFACE, infer_h2_grpc_replay

pytestmark = pytest.mark.unit


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return (
        len(payload).to_bytes(3, "big")
        + bytes([frame_type & 0xFF, flags & 0xFF])
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def write_capture(path) -> None:
    records = [
        {
            "direction": "out",
            "hex": (
                H2_PREFACE
                + h2_frame(0x4, 0, 0)
                + h2_frame(0x1, 0x4, 1, b":path /pkg.Service/CheckStatus application/grpc")
                + h2_frame(0x0, 0x1, 1, b"\x00\x00\x00\x00\x01A")
            ).hex(),
        },
        {
            "direction": "in",
            "hex": (
                h2_frame(0x1, 0x4, 1, b"ok-headers")
                + h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x00")
                + h2_frame(0x1, 0x5, 1, b"ok-trailers")
            ).hex(),
        },
        {
            "direction": "out",
            "hex": (
                H2_PREFACE
                + h2_frame(0x4, 0, 0)
                + h2_frame(0x1, 0x4, 1, b":path /pkg.Service/BeginStreaming application/grpc")
                + h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x01B")
            ).hex(),
        },
        {
            "direction": "in",
            "hex": (
                h2_frame(0x1, 0x4, 1, b"ok-headers")
                + h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x02\x22\x00")
            ).hex(),
        },
        {
            "direction": "out",
            "hex": h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x01C").hex(),
        },
        {
            "direction": "in",
            "hex": h2_frame(0x0, 0, 1, b"\x00\x00\x00\x00\x02\x12\x00").hex(),
        },
    ]
    path.write_text("\n".join(json.dumps(record) for record in records) + "\n")


def test_infer_h2_grpc_replay_from_capture(tmp_path):
    capture = tmp_path / "tls_plaintext_capture.log"
    write_capture(capture)

    result = infer_h2_grpc_replay(capture)

    assert result["connection_count"] == 2
    assert result["warnings"] == []
    assert result["sink"] == {
        "type": "h2-grpc-replay",
        "unary_methods": ["CheckStatus"],
        "streaming_methods": ["BeginStreaming"],
        "unary_response_hex": "",
        "stream_initial_response_hex": "2200",
        "stream_response_hex": "1200",
        "idle_timeout_s": 180,
        "server_pings": True,
    }
    assert result["network"]["docker_network"] == "none"


def test_cli_infer_h2_grpc_replay_outputs_yaml_sink(tmp_path):
    capture = tmp_path / "tls_plaintext_capture.log"
    write_capture(capture)

    runner = CliRunner()
    result = runner.invoke(app, ["infer-h2-grpc-replay", str(capture), "--sink-only"])

    assert result.exit_code == 0
    sink = yaml.safe_load(result.stdout)
    assert sink["type"] == "h2-grpc-replay"
    assert sink["unary_methods"] == ["CheckStatus"]
    assert sink["streaming_methods"] == ["BeginStreaming"]
    assert sink["stream_initial_response_hex"] == "2200"
    assert sink["stream_response_hex"] == "1200"


def test_cli_infer_h2_grpc_replay_outputs_no_trace_offline_fragment(tmp_path):
    capture = tmp_path / "tls_plaintext_capture.log"
    write_capture(capture)

    runner = CliRunner()
    result = runner.invoke(app, [
        "infer-h2-grpc-replay",
        str(capture),
        "--service-host",
        "license.example.test",
        "--service-port",
        "53000",
        "--no-trace",
        "--assert-no-egress",
    ])

    assert result.exit_code == 0
    fragment = yaml.safe_load(result.stdout)
    assert fragment["network"]["docker_network"] == "none"
    assert fragment["network"]["extra_hosts"] == [
        {"host": "license.example.test", "ip": "127.0.0.1"},
    ]
    assert fragment["network"]["sink"]["listen_port"] == 53000
    assert fragment["trace"]["tracer"] == "none"
    assert fragment["trace"]["l1"] == []
    assert fragment["detect"]["yara"] is False
    assert fragment["report"]["assertions"][0]["subject"] == (
        "network.real_allowed_remote_endpoint_event_count"
    )


def test_cli_infer_h2_grpc_replay_no_trace_requires_endpoint(tmp_path):
    capture = tmp_path / "tls_plaintext_capture.log"
    write_capture(capture)

    runner = CliRunner()
    result = runner.invoke(app, ["infer-h2-grpc-replay", str(capture), "--no-trace"])

    assert result.exit_code != 0
    assert "--no-trace requires --service-host and --service-port" in result.output
