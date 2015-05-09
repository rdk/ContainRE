"""Static binary/source evidence extraction for call-site analysis.

This module intentionally stays conservative: direct calls come from disassembly
only, imports come from ELF symbols/relocations, and source/string references
are reported as references rather than executable proof.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from .control.elf import elf_facts

DEFAULT_MAX_FILES = 256
DEFAULT_MAX_STRINGS_PER_FILE = 2000
DEFAULT_MAX_SOURCE_REFS = 300
TEXT_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".py",
    ".pyi",
    ".sh",
    ".rs",
    ".go",
    ".java",
    ".js",
    ".ts",
    ".s",
    ".S",
    ".asm",
    ".md",
    ".txt",
    ".yaml",
    ".yml",
    ".json",
}

_FUNC_HEADER_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:\s*$")
_CALL_RE = re.compile(
    r"^\s*([0-9a-fA-F]+):\s+(?:[0-9a-fA-F]{2}\s+)+\s*call[q]?\s+"
    r"(?:(0x)?([0-9a-fA-F]+)\s+)?(?:<([^>]+)>)?"
)
_STRING_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+(.*)$")
_SAFE_QUERY_RE = re.compile(r"^[\w:~.$@<>,+\-*/()[\] ]{1,200}$")


class StaticAnalysisError(RuntimeError):
    pass


def _sha256(path: Path, *, max_bytes: int = 256 * 1024 * 1024) -> str | None:
    try:
        if path.stat().st_size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _is_elf(path: Path) -> bool:
    try:
        return path.is_file() and path.read_bytes()[:4] == b"\x7fELF"
    except OSError:
        return False


def _is_text(path: Path) -> bool:
    if path.suffix in TEXT_SUFFIXES:
        return True
    try:
        data = path.read_bytes()[:4096]
    except OSError:
        return False
    return b"\x00" not in data


def _rel(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _run_tool(cmd: list[str], *, input_text: str | None = None) -> tuple[str, str | None]:
    if not shutil.which(cmd[0]):
        return "", f"{cmd[0]} not found"
    try:
        proc = subprocess.run(
            cmd,
            input=input_text,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", str(exc)
    if proc.returncode not in (0, 1):
        return proc.stdout, proc.stderr.strip() or f"exit {proc.returncode}"
    return proc.stdout, None


def _demangle(text: str) -> str:
    if not text or not shutil.which("c++filt"):
        return text
    out, err = _run_tool(["c++filt"], input_text=text)
    return out if not err else text


def normalize_symbol(name: str | None) -> str:
    if not name:
        return ""
    text = str(name)
    text = text.replace("@plt", "")
    text = text.split("@@", 1)[0]
    text = re.sub(r"@GLIBC(?:XX)?_[0-9.]+", "", text)
    return text.strip()


def _symbol_matches(name: str | None, query: str) -> bool:
    if not name:
        return False
    q = normalize_symbol(query).lower()
    n = normalize_symbol(name).lower()
    return q == n or query.lower() in str(name).lower() or q in n


def _readelf_symbols(path: Path, rel_file: str) -> tuple[list[dict[str, Any]], list[str]]:
    stdout, err = _run_tool(["readelf", "-Ws", str(path)])
    warnings = [err] if err else []
    stdout = _demangle(stdout)
    symbols = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or ":" not in line or line.startswith("Num:"):
            continue
        parts = line.split(None, 7)
        if len(parts) < 8 or not parts[0].endswith(":"):
            continue
        try:
            value = int(parts[1], 16)
            size = int(parts[2])
        except ValueError:
            continue
        typ, bind, vis, ndx, name = parts[3], parts[4], parts[5], parts[6], parts[7]
        if not name or name == "0":
            continue
        symbols.append({
            "file": rel_file,
            "name": name,
            "normalized": normalize_symbol(name),
            "address": f"0x{value:x}" if value else None,
            "size": size,
            "type": typ,
            "bind": bind,
            "visibility": vis,
            "section": ndx,
            "defined": ndx != "UND",
        })
    return symbols, warnings


def _readelf_relocations(path: Path, rel_file: str) -> tuple[list[dict[str, Any]], list[str]]:
    stdout, err = _run_tool(["readelf", "-rW", str(path)])
    warnings = [err] if err else []
    stdout = _demangle(stdout)
    relocs = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(("Relocation", "Offset")):
            continue
        parts = line.split(None, 4)
        if len(parts) < 5 or not re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            continue
        symbol = parts[4].split(" + ", 1)[0].strip()
        if not symbol:
            continue
        relocs.append({
            "file": rel_file,
            "offset": f"0x{int(parts[0], 16):x}",
            "type": parts[2],
            "symbol": symbol,
            "normalized": normalize_symbol(symbol),
        })
    return relocs, warnings


def _objdump_calls(path: Path, rel_file: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    stdout, err = _run_tool(["objdump", "-dC", str(path)])
    warnings = [err] if err else []
    functions: dict[tuple[str, str], dict[str, Any]] = {}
    edges = []
    current: dict[str, Any] | None = None
    for raw in stdout.splitlines():
        header = _FUNC_HEADER_RE.match(raw)
        if header:
            current = {
                "file": rel_file,
                "name": header.group(2),
                "normalized": normalize_symbol(header.group(2)),
                "address": f"0x{int(header.group(1), 16):x}",
            }
            functions[(rel_file, current["name"])] = current
            continue
        match = _CALL_RE.match(raw)
        if not match or current is None:
            continue
        target = match.group(4)
        target_addr = match.group(3)
        if not target and not target_addr:
            continue
        edges.append({
            "file": rel_file,
            "from": current["name"],
            "from_normalized": current["normalized"],
            "from_address": current["address"],
            "to": target or f"0x{target_addr}",
            "to_normalized": normalize_symbol(target) if target else f"0x{target_addr}",
            "to_address": f"0x{int(target_addr, 16):x}" if target_addr else None,
            "callsite": f"0x{int(match.group(1), 16):x}",
            "confidence": "confirmed_direct_call" if target else "possible_direct_address_call",
        })
    return list(functions.values()), edges, warnings


def _strings(path: Path, rel_file: str, max_strings: int) -> tuple[list[dict[str, Any]], list[str]]:
    stdout, err = _run_tool(["strings", "-a", "-tx", str(path)])
    warnings = [err] if err else []
    rows = []
    for raw in stdout.splitlines():
        match = _STRING_RE.match(raw)
        if not match:
            continue
        text = match.group(2)
        if len(text) < 4:
            continue
        rows.append({
            "file": rel_file,
            "offset": f"0x{int(match.group(1), 16):x}",
            "value": text[:500],
        })
        if len(rows) >= max_strings:
            break
    if len(rows) >= max_strings:
        warnings.append(f"strings truncated at {max_strings} entries for {rel_file}")
    return rows, warnings


def _source_refs(root: Path, query: str | None, max_refs: int) -> list[dict[str, Any]]:
    if not query or not root.is_dir() or not _SAFE_QUERY_RE.fullmatch(query):
        return []
    refs = []
    needle = query.lower()
    for path in sorted(root.rglob("*")):
        if len(refs) >= max_refs:
            break
        if not path.is_file() or not _is_text(path):
            continue
        try:
            lines = path.read_text(errors="replace").splitlines()
        except OSError:
            continue
        for lineno, line in enumerate(lines, start=1):
            if needle in line.lower():
                refs.append({
                    "file": _rel(path, root),
                    "line": lineno,
                    "text": line.strip()[:500],
                    "confidence": "source_reference",
                })
                if len(refs) >= max_refs:
                    break
    return refs


def _target_files(target: Path, max_files: int) -> tuple[Path, list[Path], bool]:
    target = target.resolve()
    if target.is_file():
        return target.parent, [target], False
    if not target.is_dir():
        raise StaticAnalysisError(f"target not found: {target}")
    files = [p for p in sorted(target.rglob("*")) if p.is_file() and _is_elf(p)]
    truncated = len(files) > max_files
    return target, files[:max_files], truncated


def analyze_target(
    target: str | Path,
    *,
    query: str | None = None,
    max_files: int = DEFAULT_MAX_FILES,
    max_strings_per_file: int = DEFAULT_MAX_STRINGS_PER_FILE,
    max_source_refs: int = DEFAULT_MAX_SOURCE_REFS,
) -> dict[str, Any]:
    """Analyze an ELF file or directory of ELF files and return static evidence."""
    target_path = Path(target)
    root, files, files_truncated = _target_files(target_path, max_files)
    warnings = []
    file_rows = []
    symbols: list[dict[str, Any]] = []
    relocs: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []

    for path in files:
        rel_file = _rel(path, root)
        row = {
            "path": rel_file,
            "absolute_path": str(path),
            "size": path.stat().st_size,
            "sha256": _sha256(path),
            "elf": elf_facts(path),
        }
        sym_rows, sym_warnings = _readelf_symbols(path, rel_file)
        reloc_rows, reloc_warnings = _readelf_relocations(path, rel_file)
        func_rows, edge_rows, edge_warnings = _objdump_calls(path, rel_file)
        string_rows, string_warnings = _strings(path, rel_file, max_strings_per_file)
        warnings.extend([w for w in sym_warnings + reloc_warnings + edge_warnings + string_warnings if w])
        symbols.extend(sym_rows)
        relocs.extend(reloc_rows)
        functions.extend(func_rows)
        edges.extend(edge_rows)
        strings.extend(string_rows)
        row.update({
            "symbols": len(sym_rows),
            "functions": len(func_rows),
            "call_edges": len(edge_rows),
            "strings": len(string_rows),
        })
        file_rows.append(row)

    imports = [s for s in symbols if not s.get("defined")]
    exports = [
        s for s in symbols
        if s.get("defined") and s.get("bind") in {"GLOBAL", "WEAK"} and s.get("type") != "FILE"
    ]
    source_refs = _source_refs(root, query, max_source_refs)
    edge_conf = Counter(edge.get("confidence", "unknown") for edge in edges)
    data = {
        "schema_version": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target": str(target_path.resolve()),
        "root": str(root),
        "query": query,
        "summary": {
            "files_total": len(file_rows),
            "files_truncated": files_truncated,
            "symbols": len(symbols),
            "imports": len(imports),
            "exports": len(exports),
            "functions": len(functions),
            "call_edges": len(edges),
            "strings": len(strings),
            "source_refs": len(source_refs),
            "edge_confidence": dict(sorted(edge_conf.items())),
            "warnings": len(warnings),
        },
        "files": file_rows,
        "symbols": symbols,
        "imports": imports,
        "exports": exports,
        "functions": functions,
        "relocations": relocs,
        "call_edges": edges,
        "strings": strings,
        "source_refs": source_refs,
        "warnings": warnings,
    }
    return data


def load_static(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def query_static(
    data: dict[str, Any],
    symbol: str,
    *,
    direction: str = "both",
    limit: int = 120,
) -> dict[str, Any]:
    """Return caller/callee evidence and a compact graph for a symbol query."""
    if not symbol:
        return {"query": symbol, "matches": [], "callers": [], "callees": [], "nodes": [], "edges": []}
    functions = data.get("functions", []) or []
    symbols = data.get("symbols", []) or []
    edges = data.get("call_edges", []) or []

    matches = []
    seen = set()
    for row in [*functions, *symbols]:
        name = row.get("name")
        if _symbol_matches(name, symbol):
            key = (row.get("file"), name, row.get("address"))
            if key not in seen:
                matches.append({
                    "file": row.get("file"),
                    "name": name,
                    "normalized": normalize_symbol(name),
                    "address": row.get("address"),
                    "type": row.get("type") or "function",
                    "defined": row.get("defined", True),
                })
                seen.add(key)

    target_names = {normalize_symbol(row["name"]) for row in matches if row.get("name")}
    if not target_names:
        target_names = {normalize_symbol(symbol)}

    callers = [
        edge for edge in edges
        if any(_symbol_matches(edge.get("to"), name) for name in target_names)
    ]
    callees = [
        edge for edge in edges
        if any(_symbol_matches(edge.get("from"), name) for name in target_names)
    ]
    if direction == "callers":
        graph_edges = callers[:limit]
    elif direction == "callees":
        graph_edges = callees[:limit]
    else:
        graph_edges = [*callers, *callees][:limit]

    node_map: dict[str, dict[str, Any]] = {}
    for name in target_names:
        if name:
            node_map[name] = {"id": name, "label": name, "role": "query"}
    for edge in graph_edges:
        for key, role in (("from_normalized", "caller"), ("to_normalized", "callee")):
            node_id = edge.get(key) or edge.get("from" if key.startswith("from") else "to")
            if not node_id:
                continue
            node_id = normalize_symbol(node_id)
            node_map.setdefault(node_id, {"id": node_id, "label": node_id, "role": role})

    source_refs = [
        ref for ref in data.get("source_refs", []) or []
        if symbol.lower() in str(ref.get("text", "")).lower()
    ]
    string_refs = [
        ref for ref in data.get("strings", []) or []
        if symbol.lower() in str(ref.get("value", "")).lower()
    ][:limit]
    return {
        "query": symbol,
        "matches": matches[:limit],
        "callers": callers[:limit],
        "callees": callees[:limit],
        "source_refs": source_refs[:limit],
        "string_refs": string_refs[:limit],
        "nodes": list(node_map.values())[:limit],
        "edges": graph_edges,
        "truncated": len(callers) + len(callees) > len(graph_edges),
    }


def write_static(data: dict[str, Any], out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "static.json"
    path.write_text(json.dumps(data, indent=2))
    return path
