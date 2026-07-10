"""Simulated-internet sink (SPEC §7).

A NetSink answers the specimen's outbound connections so malware "talks" and
reveals behavior, instead of just failing. The default BuiltinSink is a small
self-contained responder (HTTP + generic TCP) bound to loopback; the tracer
redirects `connect` there in simulate mode. This is the swappable "custom minimal
responder" the spec allows in place of a full INetSim/FakeNet deployment - an
InetSimSink adapter can implement the same NetSink interface later.
"""
from __future__ import annotations

import socket
import ssl
import threading
import time
from typing import Callable, Protocol

_HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH")
_H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
_H2_DATA = 0x0
_H2_HEADERS = 0x1
_H2_RST_STREAM = 0x3
_H2_SETTINGS = 0x4
_H2_PING = 0x6
_H2_GOAWAY = 0x7
_H2_WINDOW_UPDATE = 0x8
_H2_FLAG_ACK = 0x1
_H2_FLAG_END_STREAM = 0x1
_H2_FLAG_END_HEADERS = 0x4
_H2_SETTINGS_MAX_FRAME_SIZE_16K = bytes.fromhex("000500004000")
_H2_SERVER_PING_PAYLOAD = bytes.fromhex("02041010090e0707")
_HPACK_GRPC_OK_HEADERS = bytes.fromhex("885f8b1d75d0620d263d4c4d6564")
_HPACK_GRPC_OK_TRAILERS = bytes.fromhex("40889acac8b21234da8f013040899acac8b5254207317f00")


class NetSink(Protocol):
    port: int

    def start(self) -> None: ...
    def stop(self) -> None: ...


class BuiltinSink:
    """Loopback TCP sink: canned HTTP responses + a generic bander for everything
    else. Reports each interaction via ``on_interaction`` (called from worker
    threads, so the callback must be thread-safe)."""
    name = "builtin"

    def __init__(self, on_interaction: Callable[[dict], None] | None = None,
                 mitm: bool = False, ca=None, sink_config: dict | None = None):
        self.on_interaction = on_interaction
        self.mitm = mitm
        self._tls_ctx = ca.server_context() if (mitm and ca is not None) else None
        self.sink_config = dict(sink_config or {})
        self.sink_type = str(self.sink_config.get("type", "builtin"))
        self._grpc_unary_methods = {
            str(m) for m in self.sink_config.get("unary_methods", []) if str(m)
        }
        self._grpc_streaming_methods = {
            str(m) for m in self.sink_config.get("streaming_methods", []) if str(m)
        }
        self._grpc_unary_response = self._hex_payload("unary_response_hex", "")
        self._grpc_stream_initial_response = self._hex_payload("stream_initial_response_hex", "")
        self._grpc_stream_response = self._hex_payload("stream_response_hex", "")
        self._grpc_idle_timeout_s = float(self.sink_config.get("idle_timeout_s", 30.0))
        self._grpc_send_pings = bool(self.sink_config.get("server_pings", True))
        self._grpc_record_payloads = bool(self.sink_config.get("record_payloads", False))
        self._grpc_payload_preview_bytes = max(
            0, int(self.sink_config.get("payload_preview_bytes", 64))
        )
        self._grpc_payload_record_limit = max(
            0, int(self.sink_config.get("payload_record_limit", 32))
        )
        self._grpc_negative_features = [
            str(feature).encode("latin1", "replace")
            for feature in self.sink_config.get("negative_feature_substrings", [])
            if str(feature)
        ]
        self._grpc_negative_status = str(self.sink_config.get("negative_grpc_status", "5"))
        self._grpc_negative_message = str(
            self.sink_config.get(
                "negative_grpc_message",
                "feature {feature} is not expected to exist in the server",
            )
        )
        self._listen_port = int(self.sink_config.get("listen_port") or 0)
        self.port: int = 0
        self._servers: list[socket.socket] = []
        self._accept_threads: list[threading.Thread] = []
        self._handlers: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()

    def start(self) -> None:
        s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s4.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s4.bind(("127.0.0.1", self._listen_port))
        self.port = s4.getsockname()[1]
        s4.listen(64)
        self._servers.append(s4)
        try:  # same port on IPv6 loopback for redirected AF_INET6 connects
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            s6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            s6.bind(("::1", self.port))
            s6.listen(64)
            self._servers.append(s6)
        except OSError:
            pass
        for srv in self._servers:
            t = threading.Thread(target=self._accept_loop, args=(srv,), daemon=True)
            t.start()
            self._accept_threads.append(t)

    def _accept_loop(self, srv: socket.socket) -> None:
        srv.settimeout(0.3)
        while not self._stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            h = threading.Thread(target=self._handle, args=(conn,), daemon=True)
            # Start the handler BEFORE registering it: if start() fails (e.g. the
            # container hit its --pids-limit), close the accepted conn and keep
            # serving instead of leaving an unstarted thread in _handlers (which
            # would make stop()'s join raise) and leaking the fd.
            try:
                h.start()
            except RuntimeError:
                self._close(conn)
                continue
            with self._lock:
                self._handlers = [t for t in self._handlers if t.is_alive()]  # prune finished
                self._handlers.append(h)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(0.5)
        tls = False
        if self._tls_ctx is not None:
            head = b""
            deadline = time.monotonic() + 3.0
            while time.monotonic() < deadline and not self._stop.is_set():
                try:
                    head = conn.recv(1, socket.MSG_PEEK)
                except socket.timeout:
                    continue
                except OSError:
                    head = b""
                    break
                if head:
                    break
            if head[:1] == b"\x16":  # TLS handshake record -> terminate TLS (MITM)
                try:
                    conn = self._tls_ctx.wrap_socket(conn, server_side=True)
                    tls = True
                except (ssl.SSLError, OSError):
                    self._close(conn)
                    if self.on_interaction:
                        self.on_interaction({"op": "connect", "proto": "tls",
                                             "tls": True, "note": "tls handshake failed"})
                    return
        if self.sink_type == "h2-grpc-replay" and tls:
            info = self._respond_h2_grpc_replay(conn)
            self._close(conn)
            info["tls"] = True
            if self.on_interaction:
                self.on_interaction(info)
            return
        data = b""
        try:
            data = conn.recv(4096)
        except OSError:
            pass
        info = self._respond(conn, data)
        self._close(conn)
        if info is not None and tls:
            info["tls"] = True
        if info and self.on_interaction:
            self.on_interaction(info)

    @staticmethod
    def _close(conn) -> None:
        try:
            conn.close()
        except OSError:
            pass

    def _respond(self, conn: socket.socket, data: bytes) -> dict | None:
        text = data.decode("latin1", "replace")
        method = text.split(" ", 1)[0] if data else ""
        if method in _HTTP_METHODS:
            head = text.split("\r\n")
            path = (head[0].split(" ") + ["/"])[1]
            host = next((ln.split(":", 1)[1].strip() for ln in head[1:]
                         if ln.lower().startswith("host:")), "")
            body = b"CONTAINRE-SINK: simulated response\n"
            resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)) + body
            try:
                conn.sendall(resp)
            except OSError:
                pass
            return {"op": "http", "proto": "tcp", "bytes": len(data),
                    "http": {"method": method, "host": host, "path": path, "status": 200}}
        try:
            conn.sendall(b"220 containre-sink ready\r\n")
        except OSError:
            pass
        if not data:
            return {"op": "accept", "proto": "tcp", "bytes": 0}
        return {"op": "recv", "proto": "tcp", "bytes": len(data),
                "preview": data[:64].decode("latin1", "replace")}

    def _hex_payload(self, key: str, default: str) -> bytes:
        raw = self.sink_config.get(key, default)
        if raw in (None, ""):
            return b""
        if not isinstance(raw, str):
            raise ValueError(f"network.sink.{key} must be a hex string")
        return bytes.fromhex(raw)

    @staticmethod
    def _h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
        return (
            len(payload).to_bytes(3, "big")
            + bytes([frame_type & 0xFF, flags & 0xFF])
            + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
            + payload
        )

    @staticmethod
    def _grpc_message(payload: bytes) -> bytes:
        return b"\x00" + len(payload).to_bytes(4, "big") + payload

    @staticmethod
    def _hpack_int(value: int, prefix_bits: int, first: int = 0) -> bytes:
        max_prefix = (1 << prefix_bits) - 1
        if value < max_prefix:
            return bytes([first | value])
        out = [first | max_prefix]
        value -= max_prefix
        while value >= 128:
            out.append((value & 0x7F) | 0x80)
            value >>= 7
        out.append(value)
        return bytes(out)

    @classmethod
    def _hpack_string(cls, value: str | bytes) -> bytes:
        data = value if isinstance(value, bytes) else value.encode("utf-8")
        return cls._hpack_int(len(data), 7, 0) + data

    @classmethod
    def _hpack_literal_without_indexing(cls, name: str, value: str) -> bytes:
        return b"\x00" + cls._hpack_string(name) + cls._hpack_string(value)

    @staticmethod
    def _grpc_payload_previews(data: bytes, preview_bytes: int) -> list[dict]:
        previews: list[dict] = []
        pos = 0
        while pos + 5 <= len(data):
            compressed = data[pos]
            length = int.from_bytes(data[pos + 1:pos + 5], "big")
            end = pos + 5 + length
            if end > len(data):
                break
            body = data[pos + 5:end]
            preview = body[:preview_bytes] if preview_bytes > 0 else b""
            previews.append({
                "compressed": bool(compressed),
                "length": length,
                "hex": preview.hex(),
                "truncated": len(body) > preview_bytes,
            })
            pos = end
        if previews:
            return previews
        preview = data[:preview_bytes] if preview_bytes > 0 else b""
        return [{
            "compressed": None,
            "length": len(data),
            "hex": preview.hex(),
            "truncated": len(data) > preview_bytes,
            "note": "unparsed raw DATA payload",
        }]

    @staticmethod
    def _ascii_preview(data: bytes, limit: int = 160) -> str:
        text = data[:limit].decode("latin1", "replace")
        return "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)

    def _classify_grpc_method(self, payload: bytes) -> tuple[str, str] | None:
        for method in sorted(self._grpc_streaming_methods, key=len, reverse=True):
            if method.encode() in payload:
                return method, "streaming"
        for method in sorted(self._grpc_unary_methods, key=len, reverse=True):
            if method.encode() in payload:
                return method, "unary"
        if b"application/grpc" in payload or b":path" in payload:
            return self._ascii_preview(payload), "unary"
        return None

    def _negative_feature_for_payload(self, payload: bytes) -> str | None:
        for feature in self._grpc_negative_features:
            if feature in payload:
                return feature.decode("latin1", "replace")
        return None

    def _respond_h2_grpc_replay(self, conn: socket.socket) -> dict:
        """Experimental policy-driven HTTP/2 gRPC responder.

        This intentionally stays below protobuf semantics: policies define method
        names and response body bytes, while the sink supplies valid HTTP/2 and
        gRPC framing. It is useful for offline A/B tests when the goal is to keep
        the specimen talking without contacting the real service.
        """
        info: dict = {
            "op": "h2-grpc-replay",
            "proto": "h2",
            "experimental": True,
            "bytes_in": 0,
            "bytes_out": 0,
            "grpc": {"requests": 0, "messages": 0, "methods": []},
        }
        if self._grpc_record_payloads:
            info["grpc"]["payloads"] = []
        methods: set[str] = set()
        streams: dict[int, dict] = {}
        buf = b""
        saw_preface = False
        sent_tuning_settings = False
        idle_deadline = time.monotonic() + self._grpc_idle_timeout_s
        conn.settimeout(0.5)

        def send(payload: bytes) -> None:
            if not payload:
                return
            conn.sendall(payload)
            info["bytes_out"] += len(payload)

        def send_window_update(stream_id: int, amount: int) -> None:
            if amount <= 0:
                return
            increment = min(amount, 0x7FFFFFFF).to_bytes(4, "big")
            send(self._h2_frame(_H2_WINDOW_UPDATE, 0, stream_id, increment))

        def send_ping() -> None:
            if self._grpc_send_pings:
                send(self._h2_frame(_H2_PING, 0, 0, _H2_SERVER_PING_PAYLOAD))

        def send_headers(stream_id: int) -> None:
            send(self._h2_frame(_H2_HEADERS, _H2_FLAG_END_HEADERS, stream_id,
                                _HPACK_GRPC_OK_HEADERS))

        def send_data(stream_id: int, protobuf_payload: bytes) -> None:
            send(self._h2_frame(_H2_DATA, 0, stream_id,
                                self._grpc_message(protobuf_payload)))

        def send_trailers(stream_id: int, status: str = "0", message: str = "") -> None:
            if status == "0" and not message:
                payload = _HPACK_GRPC_OK_TRAILERS
            else:
                payload = self._hpack_literal_without_indexing("grpc-status", status)
                if message:
                    payload += self._hpack_literal_without_indexing("grpc-message", message)
            send(self._h2_frame(_H2_HEADERS, _H2_FLAG_END_HEADERS | _H2_FLAG_END_STREAM,
                                stream_id, payload))

        def respond_unary(stream_id: int) -> None:
            send_ping()
            send_headers(stream_id)
            send_data(stream_id, self._grpc_unary_response)
            send_trailers(stream_id)
            streams[stream_id]["responded"] = True

        def respond_unary_error(stream_id: int, feature: str) -> None:
            stream = streams[stream_id]
            send_ping()
            if not stream.get("headers_sent"):
                send_headers(stream_id)
                stream["headers_sent"] = True
            message = self._grpc_negative_message.replace("{feature}", feature)
            send_trailers(stream_id, self._grpc_negative_status, message)
            stream["responded"] = True
            info["grpc"].setdefault("negative_features", []).append(feature)

        def respond_stream(stream_id: int, initial: bool) -> None:
            send_ping()
            stream = streams[stream_id]
            if not stream.get("headers_sent"):
                send_headers(stream_id)
                stream["headers_sent"] = True
            payload = self._grpc_stream_initial_response if initial else self._grpc_stream_response
            send_data(stream_id, payload)

        while not self._stop.is_set():
            if time.monotonic() > idle_deadline:
                info["note"] = "idle timeout"
                break
            if not saw_preface:
                while len(buf) < len(_H2_PREFACE) and not self._stop.is_set():
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except OSError as exc:
                        info["note"] = f"recv failed before preface: {exc.__class__.__name__}"
                        return info
                    if not chunk:
                        info["note"] = "closed before preface"
                        return info
                    info["bytes_in"] += len(chunk)
                    buf += chunk
                    idle_deadline = time.monotonic() + self._grpc_idle_timeout_s
                if not buf.startswith(_H2_PREFACE):
                    info["note"] = "missing HTTP/2 client preface"
                    info["preview"] = self._ascii_preview(buf)
                    return info
                buf = buf[len(_H2_PREFACE):]
                saw_preface = True
                send(self._h2_frame(_H2_SETTINGS, 0, 0))

            while len(buf) < 9 and not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                except OSError as exc:
                    info["note"] = f"recv failed: {exc.__class__.__name__}"
                    return info
                if not chunk:
                    info["note"] = "client closed"
                    info["grpc"]["methods"] = sorted(methods)
                    return info
                info["bytes_in"] += len(chunk)
                buf += chunk
                idle_deadline = time.monotonic() + self._grpc_idle_timeout_s
            if len(buf) < 9:
                continue

            length = int.from_bytes(buf[:3], "big")
            frame_len = 9 + length
            while len(buf) < frame_len and not self._stop.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                except OSError as exc:
                    info["note"] = f"recv failed mid-frame: {exc.__class__.__name__}"
                    return info
                if not chunk:
                    info["note"] = "client closed mid-frame"
                    info["grpc"]["methods"] = sorted(methods)
                    return info
                info["bytes_in"] += len(chunk)
                buf += chunk
                idle_deadline = time.monotonic() + self._grpc_idle_timeout_s
            if len(buf) < frame_len:
                continue

            frame = buf[:frame_len]
            buf = buf[frame_len:]
            frame_type = frame[3]
            flags = frame[4]
            stream_id = int.from_bytes(frame[5:9], "big") & 0x7FFFFFFF
            payload = frame[9:]

            if frame_type == _H2_SETTINGS:
                if not (flags & _H2_FLAG_ACK):
                    send(self._h2_frame(_H2_SETTINGS, _H2_FLAG_ACK, 0))
                    if not sent_tuning_settings:
                        send(self._h2_frame(_H2_SETTINGS, 0, 0,
                                            _H2_SETTINGS_MAX_FRAME_SIZE_16K))
                        sent_tuning_settings = True
                continue

            if frame_type == _H2_PING:
                if not (flags & _H2_FLAG_ACK) and len(payload) == 8:
                    send(self._h2_frame(_H2_PING, _H2_FLAG_ACK, 0, payload))
                continue

            if frame_type == _H2_WINDOW_UPDATE:
                continue

            if frame_type == _H2_HEADERS:
                classified = self._classify_grpc_method(payload)
                if classified is not None:
                    method, mode = classified
                    streams[stream_id] = {
                        "method": method,
                        "mode": mode,
                        "responded": False,
                        "headers_sent": False,
                        "messages": 0,
                    }
                    methods.add(method)
                    info["grpc"]["requests"] += 1
                    if flags & _H2_FLAG_END_STREAM:
                        if mode == "streaming":
                            respond_stream(stream_id, initial=True)
                        else:
                            respond_unary(stream_id)
                continue

            if frame_type == _H2_DATA:
                stream = streams.setdefault(stream_id, {
                    "method": f"stream-{stream_id}",
                    "mode": "unary",
                    "responded": False,
                    "headers_sent": False,
                    "messages": 0,
                })
                stream["messages"] += 1
                info["grpc"]["messages"] += 1
                negative_feature = self._negative_feature_for_payload(payload)
                if self._grpc_record_payloads:
                    payloads = info["grpc"].setdefault("payloads", [])
                    room = self._grpc_payload_record_limit - len(payloads)
                    if room > 0:
                        for n, preview in enumerate(
                            self._grpc_payload_previews(
                                payload, self._grpc_payload_preview_bytes
                            )[:room],
                            start=1,
                        ):
                            payloads.append({
                                "stream_id": stream_id,
                                "method": stream.get("method"),
                                "data_frame_index": stream["messages"],
                                "message_in_frame": n,
                                **preview,
                            })
                send_window_update(0, len(payload))
                if negative_feature and not stream.get("responded"):
                    respond_unary_error(stream_id, negative_feature)
                elif stream["mode"] == "streaming":
                    respond_stream(stream_id, initial=stream["messages"] == 1)
                elif not stream.get("responded"):
                    respond_unary(stream_id)
                continue

            if frame_type == _H2_RST_STREAM:
                streams.pop(stream_id, None)
                continue

            if frame_type == _H2_GOAWAY:
                info["note"] = "client sent GOAWAY"
                break

        info["grpc"]["methods"] = sorted(methods)
        return info

    def stop(self, drain_timeout: float = 3.0) -> None:
        self._stop.set()
        for srv in self._servers:
            try:
                srv.close()
            except OSError:
                pass
        # Wait for in-flight handlers so all interactions are reported before the
        # caller finalizes the run (otherwise a late detection races store.close()).
        with self._lock:
            handlers = list(self._handlers)
        for h in handlers:
            try:
                h.join(timeout=drain_timeout)
            except RuntimeError:
                continue  # never-started thread; nothing to join
