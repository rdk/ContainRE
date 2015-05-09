"""Infer experimental HTTP/2 gRPC replay sink policies from plaintext captures."""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_DATA = 0x0
H2_HEADERS = 0x1
H2_RST_STREAM = 0x3
H2_SETTINGS = 0x4
H2_GOAWAY = 0x7
H2_FLAG_END_STREAM = 0x1

_METHOD_RE = re.compile(rb"/[A-Za-z0-9_.]+/([A-Za-z0-9_.$-]+)")


@dataclass
class H2Frame:
    direction: str
    connection: int
    sequence: int
    frame_type: int
    flags: int
    stream_id: int
    payload: bytes


@dataclass
class MethodObservation:
    method: str
    mode: str
    streams: int = 0
    client_messages: int = 0
    server_messages: list[str] = field(default_factory=list)
    server_end_streams: int = 0


def _record_bytes(line: str) -> tuple[str, bytes] | None:
    line = line.strip()
    if not line:
        return None
    direction = ""
    try:
        row = json.loads(line)
    except json.JSONDecodeError:
        return "", bytes.fromhex(line)
    if not isinstance(row, dict):
        return None
    raw_hex = row.get("hex") or row.get("data_hex")
    if not isinstance(raw_hex, str) or not raw_hex:
        return None
    direction = str(row.get("direction") or "")
    return direction, bytes.fromhex(raw_hex)


def _frames_from_capture(path: Path) -> tuple[list[H2Frame], list[str]]:
    frames: list[H2Frame] = []
    warnings: list[str] = []
    connection = 0
    sequence = 0
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        record = _record_bytes(line)
        if record is None:
            continue
        direction, data = record
        if not data:
            continue
        pos = 0
        if data.startswith(H2_PREFACE):
            connection += 1
            pos = len(H2_PREFACE)
        elif direction == "out" and H2_PREFACE in data:
            preface_at = data.index(H2_PREFACE)
            if preface_at:
                warnings.append(f"line {line_no}: skipped {preface_at} byte(s) before HTTP/2 preface")
            connection += 1
            pos = preface_at + len(H2_PREFACE)
        if connection == 0:
            # Inbound server SETTINGS may appear before the next outbound record
            # in some captures; keep them on connection 1 rather than dropping.
            connection = 1

        while pos + 9 <= len(data):
            length = int.from_bytes(data[pos:pos + 3], "big")
            end = pos + 9 + length
            if end > len(data):
                warnings.append(f"line {line_no}: truncated HTTP/2 frame at byte {pos}")
                break
            sequence += 1
            frames.append(H2Frame(
                direction=direction,
                connection=connection,
                sequence=sequence,
                frame_type=data[pos + 3],
                flags=data[pos + 4],
                stream_id=int.from_bytes(data[pos + 5:pos + 9], "big") & 0x7FFFFFFF,
                payload=data[pos + 9:end],
            ))
            pos = end
        if pos != len(data):
            warnings.append(f"line {line_no}: {len(data) - pos} trailing byte(s) not parsed as HTTP/2")
    return frames, warnings


def _method_from_headers(payload: bytes) -> str | None:
    match = _METHOD_RE.search(payload)
    if not match:
        return None
    return match.group(1).decode("latin1", "replace")


def _grpc_payloads(data: bytes) -> list[str]:
    payloads: list[str] = []
    pos = 0
    while pos + 5 <= len(data):
        length = int.from_bytes(data[pos + 1:pos + 5], "big")
        end = pos + 5 + length
        if end > len(data):
            break
        payloads.append(data[pos + 5:end].hex())
        pos = end
    return payloads


def infer_h2_grpc_replay(path: str | Path) -> dict[str, Any]:
    """Infer a generic h2-grpc-replay sink config from JSONL plaintext capture."""
    path = Path(path)
    frames, warnings = _frames_from_capture(path)
    stream_methods: dict[tuple[int, int], str] = {}
    stream_client_messages: Counter[tuple[int, int]] = Counter()
    stream_server_messages: defaultdict[tuple[int, int], list[str]] = defaultdict(list)
    stream_server_end: Counter[tuple[int, int]] = Counter()
    stream_closed_by_client: set[tuple[int, int]] = set()

    for frame in frames:
        key = (frame.connection, frame.stream_id)
        if frame.direction == "out" and frame.frame_type == H2_HEADERS:
            method = _method_from_headers(frame.payload)
            if method:
                stream_methods[key] = method
            if frame.flags & H2_FLAG_END_STREAM:
                stream_closed_by_client.add(key)
        elif frame.direction == "out" and frame.frame_type == H2_DATA:
            if frame.stream_id:
                stream_client_messages[key] += len(_grpc_payloads(frame.payload)) or 1
            if frame.flags & H2_FLAG_END_STREAM:
                stream_closed_by_client.add(key)
        elif frame.direction == "in" and frame.frame_type == H2_DATA:
            stream_server_messages[key].extend(_grpc_payloads(frame.payload))
        elif frame.direction == "in" and frame.frame_type == H2_HEADERS:
            if frame.flags & H2_FLAG_END_STREAM:
                stream_server_end[key] += 1
        elif frame.direction == "in" and frame.frame_type in (H2_RST_STREAM, H2_GOAWAY):
            stream_server_end[key] += 1

    method_rows: dict[str, MethodObservation] = {}
    for key, method in stream_methods.items():
        server_messages = stream_server_messages.get(key, [])
        client_messages = stream_client_messages.get(key, 0)
        is_streaming = (
            client_messages > 1
            or len(server_messages) > 1
            or (server_messages and not stream_server_end.get(key))
            or (key not in stream_closed_by_client and not stream_server_end.get(key))
        )
        mode = "streaming" if is_streaming else "unary"
        row = method_rows.setdefault(method, MethodObservation(method=method, mode=mode))
        if mode == "streaming":
            row.mode = "streaming"
        row.streams += 1
        row.client_messages += client_messages
        row.server_messages.extend(server_messages)
        row.server_end_streams += stream_server_end.get(key, 0)

    observations = [
        {
            "method": row.method,
            "mode": row.mode,
            "streams": row.streams,
            "client_messages": row.client_messages,
            "server_messages": row.server_messages,
            "server_end_streams": row.server_end_streams,
        }
        for row in sorted(method_rows.values(), key=lambda r: r.method)
    ]

    unary_methods = [row["method"] for row in observations if row["mode"] == "unary"]
    streaming_methods = [row["method"] for row in observations if row["mode"] == "streaming"]
    unary_bodies = [
        msg
        for row in observations
        if row["mode"] == "unary"
        for msg in row["server_messages"]
    ]
    streaming_first = [
        row["server_messages"][0]
        for row in observations
        if row["mode"] == "streaming" and row["server_messages"]
    ]
    streaming_later = [
        msg
        for row in observations
        if row["mode"] == "streaming"
        for msg in row["server_messages"][1:]
    ]

    if len(set(unary_bodies)) > 1:
        warnings.append("multiple unary response bodies observed; using the first body")
    if len(set(streaming_first)) > 1:
        warnings.append("multiple streaming initial response bodies observed; using the first body")
    if len(set(streaming_later)) > 1:
        warnings.append("multiple streaming later response bodies observed; using the first later body")

    sink = {
        "type": "h2-grpc-replay",
        "unary_methods": unary_methods,
        "streaming_methods": streaming_methods,
        "unary_response_hex": unary_bodies[0] if unary_bodies else "",
        "stream_initial_response_hex": streaming_first[0] if streaming_first else "",
        "stream_response_hex": streaming_later[0] if streaming_later else "",
        "idle_timeout_s": 180,
        "server_pings": True,
    }
    network_fragment = {
        "posture": "simulate",
        "mitm": True,
        "docker_network": "none",
        "sink": sink,
    }
    return {
        "source": str(path),
        "frame_count": len(frames),
        "connection_count": max((frame.connection for frame in frames), default=0),
        "observed_methods": observations,
        "network": network_fragment,
        "sink": sink,
        "warnings": warnings,
    }
