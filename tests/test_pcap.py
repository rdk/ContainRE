"""pcap reconstruction tests: the PcapWriter format and end-to-end capture."""
from __future__ import annotations

import struct

import pytest

pytestmark = pytest.mark.specimen


def _walk(data: bytes) -> list[bytes]:
    """Parse a pcap: verify the global header and return per-packet payloads."""
    magic, vmaj, _, _, _, _, linktype = struct.unpack("<IHHiIII", data[:24])
    assert magic == 0xA1B2C3D4 and vmaj == 2 and linktype == 101
    off, pkts = 24, []
    while off + 16 <= len(data):
        _, _, caplen, origlen = struct.unpack("<IIII", data[off:off + 16])
        assert caplen == origlen
        off += 16
        pkts.append(data[off:off + caplen])
        off += caplen
    assert off == len(data)          # records are well-formed / no trailing bytes
    return pkts


def test_capture_pcap_end_to_end(harness):
    r = harness("httpbeacon", network={"posture": "simulate"})
    assert r.status == "finished"
    pcap = r.run_dir / "net" / "capture.pcap"
    assert pcap.exists()
    data = pcap.read_bytes()
    _walk(data)                       # valid pcap
    assert b"GET /malware/config" in data      # the request bytes are captured
    assert b"HTTP/1.1 200 OK" in data          # and the sink's response
    # the flow used the ORIGINAL destination, not the redirected sink address
    sends = [e["data"] for e in r.events()
             if e["kind"] == "net" and e["data"].get("op") == "send"]
    assert sends and sends[0]["raddr"].startswith("93.184.216.34")


def test_no_pcap_when_connect_blocked(harness):
    r = harness("netbeacon", network={"posture": "deny"})    # connect blocked -> no flow
    assert not (r.run_dir / "net" / "capture.pcap").exists()
