"""Unit tests for pcap packet construction and pcap file writing."""
from __future__ import annotations

import socket
import struct

import pytest

from containre.net.pcap import PcapWriter, _checksum, ipv4_tcp

pytestmark = pytest.mark.unit


def _walk(data: bytes) -> list[bytes]:
    magic, vmaj, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and vmaj == 2 and linktype == 101
    off, pkts = 24, []
    while off + 16 <= len(data):
        _, _, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
        assert caplen == origlen
        off += 16
        pkts.append(data[off:off + caplen])
        off += caplen
    assert off == len(data)
    return pkts


def test_ipv4_tcp_checksums_are_valid():
    pkt = ipv4_tcp("10.0.0.1", "1.2.3.4", 1234, 80, 100, 200, 0x18, b"hello")
    assert _checksum(pkt[:20]) == 0
    tcp = pkt[20:]
    pseudo = (
        socket.inet_aton("10.0.0.1")
        + socket.inet_aton("1.2.3.4")
        + struct.pack("!BBH", 0, 6, len(tcp))
    )
    assert _checksum(pseudo + tcp) == 0


def test_pcap_writer_roundtrip(tmp_path):
    p = tmp_path / "c.pcap"
    w = PcapWriter(str(p))
    ok = w.add_flow("1.2.3.4:80", [
        ("out", b"GET / HTTP/1.0\r\n\r\n"),
        ("in", b"HTTP/1.1 200 OK"),
    ], sport=40000)
    assert ok
    assert w.add_flow("1.2.3.4:81", [], sport=40001) is False
    assert w.add_flow("[::1]:80", [], sport=40001) is False
    w.write()
    data = p.read_bytes()
    pkts = _walk(data)
    assert len(pkts) == 7
    assert b"GET / HTTP/1.0" in data and b"HTTP/1.1 200 OK" in data
