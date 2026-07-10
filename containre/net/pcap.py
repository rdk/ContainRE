"""Synthesize a libpcap file from observed TCP flows.

We cannot sniff raw packets without privilege (caps are dropped), so instead we
reconstruct each flow from the payloads the tracer captured at write()/read() and
emit a synthetic but valid TCP session (handshake + data segments + teardown) with
the *real* endpoints. The result opens cleanly in Wireshark/tshark.
"""
from __future__ import annotations

import socket
import struct

LINKTYPE_RAW = 101
_SYN, _ACK, _PSH, _FIN = 0x02, 0x10, 0x08, 0x01


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def ipv4_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
             seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    src, dst = socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    seq &= 0xFFFFFFFF
    ack &= 0xFFFFFFFF
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload))
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    total_len = 20 + len(tcp) + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total_len, 0, 0x4000, 64, 6, 0) + src + dst
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return ip + tcp + payload


def ipv6_tcp(src_ip: str, dst_ip: str, sport: int, dport: int,
             seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    src = socket.inet_pton(socket.AF_INET6, src_ip)
    dst = socket.inet_pton(socket.AF_INET6, dst_ip)
    seq &= 0xFFFFFFFF
    ack &= 0xFFFFFFFF
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, (5 << 4), flags, 65535, 0, 0)
    tcp_len = len(tcp) + len(payload)
    # IPv6 TCP pseudo-header: src, dst, upper-layer length (4), zeros (3), next header (6).
    pseudo = src + dst + struct.pack("!I", tcp_len) + b"\x00\x00\x00" + struct.pack("!B", 6)
    csum = _checksum(pseudo + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", csum) + tcp[18:]
    ipv6 = struct.pack("!IHBB", 0x60000000, tcp_len, 6, 64) + src + dst  # version 6, next=TCP, hop=64
    return ipv6 + tcp + payload


class PcapWriter:
    def __init__(self, path: str, client_ip: str = "10.13.37.2",
                 client_ip6: str = "fd00:1337::2"):
        self.path = path
        self.client_ip = client_ip
        self.client_ip6 = client_ip6
        self._records: list[bytes] = []
        self._ts_us = 0

    def _emit(self, pkt: bytes) -> None:
        self._ts_us += 1000  # +1ms per packet (deterministic timestamps)
        self._records.append(
            struct.pack("<IIII", self._ts_us // 1_000_000, self._ts_us % 1_000_000,
                        len(pkt), len(pkt)) + pkt)

    def add_flow(self, raddr: str, chunks: list[tuple[str, bytes]], sport: int) -> bool:
        """Add one flow (raddr='ip:port' or '[ipv6]:port', chunks=[('out'|'in', bytes)])."""
        if not any(data for _, data in chunks):
            return False
        if raddr.startswith("["):
            host, _, port = raddr[1:].rpartition("]:")
            build, client, af = ipv6_tcp, self.client_ip6, socket.AF_INET6
        else:
            host, _, port = raddr.rpartition(":")
            build, client, af = ipv4_tcp, self.client_ip, socket.AF_INET
        try:
            dport = int(port)
            socket.inet_pton(af, host)
        except (ValueError, OSError):
            return False
        c, s = client, host
        cseq, sseq = 1000, 2000
        self._emit(build(c, s, sport, dport, cseq, 0, _SYN))
        self._emit(build(s, c, dport, sport, sseq, cseq + 1, _SYN | _ACK))
        cseq += 1
        self._emit(build(c, s, sport, dport, cseq, sseq + 1, _ACK))
        sseq += 1
        for direction, data in chunks:
            if not data:
                continue
            if direction == "out":
                self._emit(build(c, s, sport, dport, cseq, sseq, _PSH | _ACK, data))
                cseq += len(data)
            else:
                self._emit(build(s, c, dport, sport, sseq, cseq, _PSH | _ACK, data))
                sseq += len(data)
        self._emit(build(c, s, sport, dport, cseq, sseq, _FIN | _ACK))
        self._emit(build(s, c, dport, sport, sseq, cseq + 1, _FIN | _ACK))
        return True

    def write(self) -> None:
        with open(self.path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
            for rec in self._records:
                f.write(rec)
