"""Memory snapshots: capture a stopped specimen's maps + bounded region dumps.

Invoked from the tracer process (which is the ptracer) while the specimen is
stopped at a syscall, so /proc/<pid>/mem is readable and consistent. Blobs are
zstd-compressed when the optional dependency is present, else stored raw.
"""
from __future__ import annotations

import json

CAP_TOTAL = 256 * 1024      # never dump more than this per snapshot
CAP_REGION = 128 * 1024     # ... or more than this from any one region

try:
    import zstandard as _zstd
except ImportError:  # optional extra
    _zstd = None


def _read_maps(pid: int) -> list[dict]:
    regions: list[dict] = []
    try:
        text = open(f"/proc/{pid}/maps").read()
    except OSError:
        return regions
    for line in text.splitlines():
        parts = line.split(maxsplit=5)
        if len(parts) < 5:
            continue
        addr, perms = parts[0], parts[1]
        path = parts[5] if len(parts) > 5 else ""
        start, _, end = addr.partition("-")
        try:
            base, top = int(start, 16), int(end, 16)
        except ValueError:
            continue
        regions.append({"base": hex(base), "size": top - base, "perms": perms, "path": path})
    return regions


def _is_interesting(region: dict) -> bool:
    perms, path = region["perms"], region["path"]
    if "x" in perms:                       # executable code (incl. unpacked/JIT)
        return True
    if path in ("[heap]", "[stack]"):      # dynamic data
        return True
    if path == "" and "w" in perms:        # anonymous writable (injected buffers)
        return True
    return False


def capture(pid: int, cap_total: int = CAP_TOTAL) -> tuple[bytes, list[dict], int]:
    """Return (blob, captured_region_metas, total_region_count).

    The blob is ``<json-header>\\n<concatenated region bytes>``, optionally
    zstd-compressed. The header lists each captured region and its dumped length
    so the blob is self-describing.
    """
    regions = _read_maps(pid)
    captured_meta: list[dict] = []
    chunks: list[bytes] = []
    total = 0
    try:
        mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
    except OSError:
        mem = None

    if mem is not None:
        try:
            for r in regions:
                if total >= cap_total or not _is_interesting(r):
                    continue
                base = int(r["base"], 16)
                n = min(r["size"], CAP_REGION, cap_total - total)
                try:
                    mem.seek(base)
                    data = mem.read(n)
                except (OSError, ValueError):
                    continue
                if not data:
                    continue
                chunks.append(data)
                total += len(data)
                captured_meta.append({**r, "dumped": len(data)})
        finally:
            mem.close()

    header = json.dumps({"pid": pid, "regions": captured_meta}).encode()
    blob = header + b"\n" + b"".join(chunks)
    if _zstd is not None:
        blob = _zstd.ZstdCompressor(level=3).compress(blob)
    return blob, captured_meta, len(regions)


def blob_suffix() -> str:
    return "bin.zst" if _zstd is not None else "bin"


def load(path) -> tuple[dict, bytes]:
    """Read a snapshot blob back into (header, body-bytes)."""
    import pathlib
    raw = pathlib.Path(path).read_bytes()
    if str(path).endswith(".zst"):
        if _zstd is None:
            raise RuntimeError("snapshot is zstd-compressed but zstandard is not installed")
        raw = _zstd.ZstdDecompressor().decompress(raw)
    header_line, _, body = raw.partition(b"\n")
    return json.loads(header_line.decode()), body


def region_slice(header: dict, body: bytes, base: str | None) -> tuple[bytes, dict | None]:
    """Extract the dumped bytes for the region with the given base (or the first)."""
    offset = 0
    for r in header.get("regions", []):
        n = int(r.get("dumped", 0))
        if base is None or r["base"] == base:
            return body[offset:offset + n], r
        offset += n
    return b"", None


def hexdump(data: bytes, base: int = 0, width: int = 16, max_bytes: int = 4096) -> str:
    data = data[:max_bytes]
    lines = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{base + i:012x}  {hexs:<{width * 3}}  {asc}")
    return "\n".join(lines)
