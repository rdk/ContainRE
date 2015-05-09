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


class PcapWriter:
    def __init__(self, path: str, client_ip: str = "10.13.37.2"):
        self.path = path
        self.client_ip = client_ip
        self._records: list[bytes] = []
        self._ts_us = 0

    def _emit(self, pkt: bytes) -> None:
        self._ts_us += 1000  # +1ms per packet (deterministic timestamps)
        self._records.append(
            struct.pack("<IIII", self._ts_us // 1_000_000, self._ts_us % 1_000_000,
                        len(pkt), len(pkt)) + pkt)

    def add_flow(self, raddr: str, chunks: list[tuple[str, bytes]], sport: int) -> bool:
        """Add one flow (raddr='ip:port', chunks=[('out'|'in', bytes)]). IPv4 only."""
        if not any(data for _, data in chunks):
            return False
        if raddr.startswith("["):
            return False
        host, _, port = raddr.rpartition(":")
        try:
            dport = int(port)
            socket.inet_aton(host)
        except (ValueError, OSError):
            return False
        c, s = self.client_ip, host
        cseq, sseq = 1000, 2000
        self._emit(ipv4_tcp(c, s, sport, dport, cseq, 0, _SYN))
        self._emit(ipv4_tcp(s, c, dport, sport, sseq, cseq + 1, _SYN | _ACK))
        cseq += 1
        self._emit(ipv4_tcp(c, s, sport, dport, cseq, sseq + 1, _ACK))
        sseq += 1
        for direction, data in chunks:
            if not data:
                continue
            if direction == "out":
                self._emit(ipv4_tcp(c, s, sport, dport, cseq, sseq, _PSH | _ACK, data))
                cseq += len(data)
            else:
                self._emit(ipv4_tcp(s, c, dport, sport, sseq, cseq, _PSH | _ACK, data))
                sseq += len(data)
        self._emit(ipv4_tcp(c, s, sport, dport, cseq, sseq, _FIN | _ACK))
        self._emit(ipv4_tcp(s, c, dport, sport, sseq, cseq + 1, _FIN | _ACK))
        return True

    def write(self) -> None:
        with open(self.path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE_RAW))
            for rec in self._records:
                f.write(rec)
