"""Post-hoc run summaries for ContainRE event directories."""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any

import yaml

NETWORK_OPS = {
    "socket", "connect", "connect_result", "socket_error", "send", "recv",
    "bind", "listen", "accept",
}
REMOTE_OPS = {"connect", "send", "recv", "accept"}
DNS_PORT = 53
DEFAULT_HASH_LIMIT = 64 * 1024 * 1024
DEFAULT_FILE_SCAN_LIMIT = 500
ASSERTION_FAILURE_SEVERITY = "high"
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text()) if path.exists() else {}


def _read_policy(run_dir: Path) -> dict[str, Any]:
    path = run_dir / "policy.yaml"
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text())
    except (OSError, yaml.YAMLError):
        return {}
    return data if isinstance(data, dict) else {}


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    for line in path.read_text().splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def _endpoint_for(data: dict[str, Any]) -> str:
    return str(data.get("raddr") or data.get("laddr") or "")


def _endpoint_port(endpoint: str) -> int | None:
    if endpoint.startswith("unix:") or endpoint == "-":
        return None
    if endpoint.startswith("["):
        match = re.search(r"\]:(\d+)$", endpoint)
    else:
        match = re.search(r":(\d+)$", endpoint)
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _sha256_file(path: Path, *, max_bytes: int = DEFAULT_HASH_LIMIT) -> str | None:
    try:
        size = path.stat().st_size
        if size > max_bytes:
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _file_inventory(
    base: Path,
    *,
    max_files: int = DEFAULT_FILE_SCAN_LIMIT,
    hash_limit: int = DEFAULT_HASH_LIMIT,
) -> dict[str, Any]:
    if not base.exists() or not base.is_dir():
        return {"base": str(base), "exists": False, "files": [], "count": 0, "total_bytes": 0,
                "truncated": False}
    # The base (e.g. the specimen-controlled /work) may contain symlinks the
    # specimen planted to arbitrary host files; following them would leak those
    # files' size/hash/content into the report. Skip symlinks and anything whose
    # real path escapes the base (this also catches symlinked parent dirs). The
    # specimen has already exited, so there is no live race.
    base_real = os.path.realpath(base)
    prefix = base_real + os.sep
    files = [
        path for path in sorted(base.rglob("*"))
        if not path.is_symlink() and path.is_file()
        and os.path.realpath(path).startswith(prefix)
    ]
    rows = []
    total_bytes = 0
    for path in files[:max_files]:
        try:
            size = path.stat().st_size
        except OSError:
            continue
        total_bytes += size
        rows.append({
            "path": path.relative_to(base).as_posix(),
            "size": size,
            "sha256": _sha256_file(path, max_bytes=hash_limit),
        })
    if len(files) > max_files:
        for path in files[max_files:]:
            try:
                total_bytes += path.stat().st_size
            except OSError:
                pass
    return {
        "base": str(base),
        "exists": True,
        "files": rows,
        "count": len(files),
        "total_bytes": total_bytes,
        "truncated": len(files) > max_files,
    }


def _static_compact(run_dir: Path) -> dict[str, Any]:
    data = _read_json(run_dir / "static" / "static.json")
    if not data:
        return {
            "available": False,
            "summary": {},
            "files": [],
            "symbols": {"names": []},
            "imports": {"names": []},
            "exports": {"names": []},
            "functions": {"names": []},
            "call_edges": [],
        }
    return {
        "available": True,
        "target": data.get("target"),
        "summary": data.get("summary", {}),
        "files": data.get("files", []),
        "symbols": {"names": sorted({row.get("name", "") for row in data.get("symbols", []) if row.get("name")})},
        "imports": {"names": sorted({row.get("name", "") for row in data.get("imports", []) if row.get("name")})},
        "exports": {"names": sorted({row.get("name", "") for row in data.get("exports", []) if row.get("name")})},
        "functions": {
            "names": sorted({row.get("name", "") for row in data.get("functions", []) if row.get("name")})
        },
        "call_edges": [
            {
                "file": edge.get("file"),
                "from": edge.get("from"),
                "to": edge.get("to"),
                "confidence": edge.get("confidence"),
                "callsite": edge.get("callsite"),
            }
            for edge in data.get("call_edges", [])
        ],
        "warnings": data.get("warnings", []),
    }


def _snapshots(run_dir: Path, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        data = event.get("data", {}) or {}
        if event.get("kind") == "mem" and data.get("op") == "snapshot":
            sid = str(data.get("snapshot_id", ""))
            by_id[sid] = {
                "snapshot_id": sid,
                "reason": data.get("reason"),
                "bytes": data.get("bytes"),
                "seq": event.get("seq"),
            }
    snap_dir = run_dir / "snapshots"
    if snap_dir.is_dir():
        for path in sorted(snap_dir.iterdir()):
            if not path.is_file():
                continue
            sid = path.name.split(".", 1)[0]
            row = by_id.setdefault(sid, {"snapshot_id": sid})
            row["file"] = path.name
            row["file_size"] = path.stat().st_size
    return sorted(by_id.values(), key=lambda row: str(row.get("snapshot_id", "")))


def _network_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    remote_rows = [row for row in rows if row["op"] in REMOTE_OPS and row["endpoint"] != "-"]
    blocked_count = 0
    simulated_count = 0
    allowed_or_unclassified_count = 0
    send_bytes = 0
    recv_bytes = 0
    explicit_allow_count = 0
    connect_success_count = 0
    connect_failure_count = 0
    connect_pending_count = 0
    for row in remote_rows:
        decisions = row.get("decisions", {})
        block = int(decisions.get("block", 0))
        simulated = int(decisions.get("simulated", 0))
        blocked_count += block
        simulated_count += simulated
        unblocked = int(row["count"]) - block
        if unblocked > 0:
            allowed_or_unclassified_count += unblocked
        explicit_allow_count += int(decisions.get("allow", 0))
        if row["op"] == "send":
            send_bytes += int(row.get("bytes") or 0)
        elif row["op"] == "recv":
            recv_bytes += int(row.get("bytes") or 0)
    for row in rows:
        if row["op"] != "connect_result" or row["endpoint"] == "-":
            continue
        results = row.get("results", {})
        connect_success_count += int(results.get("success", 0))
        connect_failure_count += int(results.get("failure", 0))
        connect_pending_count += int(results.get("pending", 0))
    dns_block_count = sum(
        int(row.get("decisions", {}).get("block", 0))
        for row in remote_rows
        if _endpoint_port(row["endpoint"]) == DNS_PORT
    )
    return {
        "remote_endpoint_event_count": sum(int(row["count"]) for row in remote_rows),
        "remote_endpoint_count": len({row["endpoint"] for row in remote_rows}),
        "remote_endpoints": sorted({row["endpoint"] for row in remote_rows}),
        "blocked_remote_endpoint_event_count": blocked_count,
        "simulated_remote_endpoint_event_count": simulated_count,
        "real_allowed_remote_endpoint_event_count": explicit_allow_count,
        "allowed_remote_endpoint_event_count": allowed_or_unclassified_count,
        "dns_block_count": dns_block_count,
        "bytes_sent": send_bytes,
        "bytes_received": recv_bytes,
        "connect_success_count": connect_success_count,
        "connect_failure_count": connect_failure_count,
        "connect_pending_count": connect_pending_count,
    }


def _sink_interactions(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if event.get("kind") != "net":
            continue
        data = event.get("data", {}) or {}
        op = str(data.get("op", ""))
        if not op or op in NETWORK_OPS:
            continue
        if not data.get("experimental") and not op.endswith("-replay"):
            continue
        proto = str(data.get("proto", ""))
        key = (op, proto)
        row = rows.setdefault(key, {
            "op": op,
            "proto": proto,
            "count": 0,
            "bytes_in": 0,
            "bytes_out": 0,
            "grpc_requests": 0,
            "grpc_messages": 0,
            "grpc_methods": set(),
            "grpc_negative_features": Counter(),
            "notes": Counter(),
        })
        row["count"] += 1
        row["bytes_in"] += int(data.get("bytes_in") or 0)
        row["bytes_out"] += int(data.get("bytes_out") or 0)
        grpc = data.get("grpc", {}) or {}
        row["grpc_requests"] += int(grpc.get("requests") or 0)
        row["grpc_messages"] += int(grpc.get("messages") or 0)
        row["grpc_methods"].update(str(method) for method in grpc.get("methods", []) if str(method))
        row["grpc_negative_features"].update(
            str(feature) for feature in grpc.get("negative_features", []) if str(feature)
        )
        if data.get("note"):
            row["notes"][str(data["note"])] += 1

    out = []
    for row in rows.values():
        out.append({
            "op": row["op"],
            "proto": row["proto"],
            "count": row["count"],
            "bytes_in": row["bytes_in"],
            "bytes_out": row["bytes_out"],
            "grpc_requests": row["grpc_requests"],
            "grpc_messages": row["grpc_messages"],
            "grpc_methods": sorted(row["grpc_methods"]),
            "grpc_negative_features": dict(sorted(row["grpc_negative_features"].items())),
            "notes": dict(sorted(row["notes"].items())),
        })
    return sorted(out, key=lambda r: (r["op"], r["proto"]))


def _duration_s(meta: dict[str, Any]) -> float | None:
    start = meta.get("started_wall") or meta.get("created_wall")
    stop = meta.get("stopped_wall")
    if not isinstance(start, int) or not isinstance(stop, int) or stop < start:
        return None
    return round((stop - start) / 1_000_000_000, 6)


def _metrics(summary: dict[str, Any]) -> dict[str, Any]:
    counts = summary.get("counts", {}) or {}
    verdict = summary.get("verdict", {}) or {}
    network = _network_metrics(summary.get("network", []))
    sink_interactions = summary.get("network_sink_interactions", [])
    h2_grpc_replay = [row for row in sink_interactions if row.get("op") == "h2-grpc-replay"]
    artifacts = summary.get("artifacts", {})
    work_files = summary.get("work_files", {})
    detections = summary.get("detections", [])
    file_events = summary.get("file_events", [])
    decoy_file_events = [row for row in file_events if row.get("decoy")]
    snapshots = summary.get("snapshots", [])
    static = summary.get("static", {}) or {}
    static_summary = static.get("summary", {}) or {}
    tls_plaintext = (summary.get("instrumentation", {}) or {}).get("tls_plaintext", {}) or {}
    return {
        "status": summary.get("status"),
        "exit_code": summary.get("exit_code"),
        "kill_reason": summary.get("kill_reason"),
        "duration_s": summary.get("duration_s"),
        "events.count": summary.get("event_count", 0),
        "events.by_kind": summary.get("events_by_kind", {}),
        "counts.events": counts.get("events", 0),
        "counts.detections": counts.get("detections", 0),
        "counts.artifacts": counts.get("artifacts", 0),
        "counts.snapshots": counts.get("snapshots", 0),
        "counts.net_flows": counts.get("net_flows", 0),
        "network.remote_endpoint_event_count": network["remote_endpoint_event_count"],
        "network.remote_endpoint_count": network["remote_endpoint_count"],
        "network.remote_endpoints": network["remote_endpoints"],
        "network.blocked_remote_endpoint_event_count": network["blocked_remote_endpoint_event_count"],
        "network.simulated_remote_endpoint_event_count": network["simulated_remote_endpoint_event_count"],
        "network.real_allowed_remote_endpoint_event_count": network["real_allowed_remote_endpoint_event_count"],
        "network.allowed_remote_endpoint_event_count": network["allowed_remote_endpoint_event_count"],
        "network.dns_block_count": network["dns_block_count"],
        "network.bytes_sent": network["bytes_sent"],
        "network.bytes_received": network["bytes_received"],
        "network.connect_success_count": network["connect_success_count"],
        "network.connect_failure_count": network["connect_failure_count"],
        "network.connect_pending_count": network["connect_pending_count"],
        "network.sink_interaction_count": sum(int(row["count"]) for row in sink_interactions),
        "network.h2_grpc_replay_interaction_count": sum(int(row["count"]) for row in h2_grpc_replay),
        "network.h2_grpc_replay_methods": sorted({
            method for row in h2_grpc_replay for method in row.get("grpc_methods", [])
        }),
        "network.h2_grpc_replay_negative_feature_count": sum(
            sum(int(count) for count in (row.get("grpc_negative_features") or {}).values())
            for row in h2_grpc_replay
        ),
        "network.h2_grpc_replay_negative_features": {
            feature: sum(
                int((row.get("grpc_negative_features") or {}).get(feature) or 0)
                for row in h2_grpc_replay
            )
            for feature in sorted({
                feature
                for row in h2_grpc_replay
                for feature in (row.get("grpc_negative_features") or {})
            })
        },
        "network.h2_grpc_replay_messages": sum(int(row.get("grpc_messages") or 0) for row in h2_grpc_replay),
        "network.h2_grpc_replay_bytes_in": sum(int(row.get("bytes_in") or 0) for row in h2_grpc_replay),
        "network.h2_grpc_replay_bytes_out": sum(int(row.get("bytes_out") or 0) for row in h2_grpc_replay),
        "detections.count": len(detections),
        "detections.ids": sorted({
            str(det.get("id") or det.get("title") or "detection")
            for det in detections
        }),
        "detections.max_severity": verdict.get("max_severity", "info"),
        "verdict.flags": verdict.get("flags", []),
        "verdict.attack": verdict.get("attack", []),
        "artifacts.count": artifacts.get("count", 0),
        "artifacts.names": [row["path"] for row in artifacts.get("files", [])],
        "artifacts.total_bytes": artifacts.get("total_bytes", 0),
        "work_files.count": work_files.get("count", 0),
        "work_files.names": [row["path"] for row in work_files.get("files", [])],
        "work_files.total_bytes": work_files.get("total_bytes", 0),
        "file_events.count": sum(int(row["count"]) for row in file_events),
        "file_events.paths": sorted({row["path"] for row in file_events}),
        "file_events.decoy_count": sum(int(row["count"]) for row in decoy_file_events),
        "file_events.decoy_paths": sorted({row["path"] for row in decoy_file_events}),
        "snapshots.count": len(snapshots),
        "snapshots.ids": [row["snapshot_id"] for row in snapshots],
        "static.available": bool(static.get("available")),
        "static.files.count": static_summary.get("files_total", 0),
        "static.symbols.count": static_summary.get("symbols", 0),
        "static.symbols.names": static.get("symbols", {}).get("names", []),
        "static.imports.count": static_summary.get("imports", 0),
        "static.imports.names": static.get("imports", {}).get("names", []),
        "static.exports.count": static_summary.get("exports", 0),
        "static.exports.names": static.get("exports", {}).get("names", []),
        "static.functions.count": static_summary.get("functions", 0),
        "static.functions.names": static.get("functions", {}).get("names", []),
        "static.call_edges.count": static_summary.get("call_edges", 0),
        "static.call_edges": static.get("call_edges", []),
        "instrumentation.tls_plaintext.enabled": bool(tls_plaintext.get("enabled")),
        "instrumentation.tls_plaintext.mode": tls_plaintext.get("mode"),
        "instrumentation.tls_plaintext.invasive": bool(tls_plaintext.get("invasive")),
        "instrumentation.tls_plaintext.experimental": bool(tls_plaintext.get("experimental")),
    }


def _network_rows(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    network: dict[tuple[str, str, str], dict[str, Any]] = {}
    for event in events:
        if event.get("kind") != "net":
            continue
        data = event.get("data", {}) or {}
        op = str(data.get("op", ""))
        if op not in NETWORK_OPS:
            continue
        endpoint = _endpoint_for(data) or "-"
        key = (op, endpoint, str(data.get("proto", "")))
        row = network.setdefault(key, {
            "op": op,
            "endpoint": endpoint,
            "proto": data.get("proto"),
            "count": 0,
            "decisions": Counter(),
            "results": Counter(),
            "errnos": Counter(),
            "bytes": 0,
        })
        row["count"] += 1
        if data.get("decision"):
            row["decisions"][str(data["decision"])] += 1
        if isinstance(data.get("bytes"), int):
            row["bytes"] += data["bytes"]
        status = data.get("status")
        if not status and op == "connect_result":
            status = "success" if data.get("success") else "failure"
        if status:
            row["results"][str(status)] += 1
        if data.get("errno_name"):
            row["errnos"][str(data["errno_name"])] += 1

    rows = []
    for row in network.values():
        out = {
            **{k: v for k, v in row.items() if k != "decisions"},
            "decisions": dict(sorted(row["decisions"].items())),
        }
        results = dict(sorted(row["results"].items()))
        errnos = dict(sorted(row["errnos"].items()))
        out.pop("results", None)
        out.pop("errnos", None)
        if results:
            out["results"] = results
        if errnos:
            out["errnos"] = errnos
        rows.append(out)
    return sorted(rows, key=lambda r: (r["endpoint"], r["op"], r.get("proto") or ""))


def _network_findings(rows: list[dict[str, Any]], retry_threshold: int) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    remote_rows = [r for r in rows if r["op"] in REMOTE_OPS and r["endpoint"] != "-"]
    blocked_remote = [
        r for r in remote_rows
        if r["decisions"] and sum(r["decisions"].values()) == r["decisions"].get("block", 0)
    ]
    if not remote_rows:
        findings.append({
            "id": "no-remote-endpoint-events",
            "severity": "info",
            "title": "No remote endpoint events recorded",
        })
    elif len(blocked_remote) == len(remote_rows):
        findings.append({
            "id": "all-remote-egress-blocked",
            "severity": "info",
            "title": "All remote endpoint attempts were blocked",
        })

    for row in rows:
        if row["op"] != "connect" or row["endpoint"] == "-":
            continue
        if row["count"] >= retry_threshold and row["decisions"].get("block", 0) == row["count"]:
            findings.append({
                "id": "blocked-connect-retry",
                "severity": "medium",
                "title": f"Repeated blocked connects to {row['endpoint']} x{row['count']}",
                "endpoint": row["endpoint"],
                "count": row["count"],
            })
        if _endpoint_port(row["endpoint"]) == DNS_PORT and row["decisions"].get("block", 0):
            findings.append({
                "id": "blocked-dns-port",
                "severity": "medium",
                "title": f"Blocked DNS-port connect attempts to {row['endpoint']}",
                "endpoint": row["endpoint"],
                "count": row["count"],
            })
    return findings


def _get_subject(summary: dict[str, Any], subject: str) -> Any:
    metrics = summary.get("metrics", {})
    if subject in metrics:
        return metrics[subject]
    current: Any = summary
    for part in subject.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, (tuple, set)):
        return list(value)
    return [value]


def _match_value(value: Any, pattern: str, mode: str) -> bool:
    text = str(value)
    if mode == "regex":
        return re.search(pattern, text) is not None
    if mode == "exact":
        return text == pattern
    return fnmatch.fnmatch(text, pattern)


def _evaluate_assertion(actual: Any, op: str, expected: Any, match: str) -> tuple[bool, str]:
    try:
        if op == "contains_edge":
            edges = [edge for edge in _as_list(actual) if isinstance(edge, dict)]
            exp = expected if isinstance(expected, dict) else {}
            want_from = exp.get("from")
            want_to = exp.get("to")
            want_conf = exp.get("confidence")
            def edge_ok(edge: dict[str, Any]) -> bool:
                if want_from and not _match_value(edge.get("from", ""), str(want_from), match):
                    return False
                if want_to and not _match_value(edge.get("to", ""), str(want_to), match):
                    return False
                if want_conf and edge.get("confidence") != want_conf:
                    return False
                return True
            ok = any(edge_ok(edge) for edge in edges)
            return ok, f"expected call edge matching {exp!r}"
        if op == "eq":
            return actual == expected, f"expected {actual!r} == {expected!r}"
        if op == "ne":
            return actual != expected, f"expected {actual!r} != {expected!r}"
        if op in {"gt", "gte", "lt", "lte"}:
            if op == "gt":
                ok = actual > expected
                sign = ">"
            elif op == "gte":
                ok = actual >= expected
                sign = ">="
            elif op == "lt":
                ok = actual < expected
                sign = "<"
            else:
                ok = actual <= expected
                sign = "<="
            return ok, f"expected {actual!r} {sign} {expected!r}"
        if op == "between":
            low, high = expected
            return low <= actual <= high, f"expected {actual!r} between {low!r} and {high!r}"
        if op == "in":
            return actual in _as_list(expected), f"expected {actual!r} in {expected!r}"
        if op == "not_in":
            return actual not in _as_list(expected), f"expected {actual!r} not in {expected!r}"
        if op == "contains":
            ok = str(expected) in actual if isinstance(actual, str) else expected in _as_list(actual)
            return ok, f"expected {actual!r} to contain {expected!r}"
        if op == "not_contains":
            ok = str(expected) not in actual if isinstance(actual, str) else expected not in _as_list(actual)
            return ok, f"expected {actual!r} not to contain {expected!r}"
        if op == "contains_any":
            values = _as_list(expected)
            if isinstance(actual, str):
                ok = any(str(item) in actual for item in values)
            else:
                haystack = _as_list(actual)
                ok = any(item in haystack for item in values)
            return ok, f"expected {actual!r} to contain any of {expected!r}"
        if op == "contains_all":
            values = _as_list(expected)
            if isinstance(actual, str):
                ok = all(str(item) in actual for item in values)
            else:
                haystack = _as_list(actual)
                ok = all(item in haystack for item in values)
            return ok, f"expected {actual!r} to contain all of {expected!r}"
        if op == "exists":
            return actual is not None, "expected subject to exist"
        if op == "not_exists":
            return actual is None, "expected subject not to exist"
        if op == "is_empty":
            return not _as_list(actual), f"expected {actual!r} to be empty"
        if op == "is_not_empty":
            return bool(_as_list(actual)), f"expected {actual!r} not to be empty"
        if op in {"any_match", "none_match", "all_match"}:
            actual_values = [str(item) for item in _as_list(actual)]
            patterns = [str(item) for item in _as_list(expected)]
            matched = [
                value for value in actual_values
                if any(_match_value(value, pattern, match) for pattern in patterns)
            ]
            if op == "any_match":
                return bool(matched), f"expected any of {actual_values!r} to match {patterns!r}"
            if op == "none_match":
                return not matched, f"expected none of {actual_values!r} to match {patterns!r}"
            return len(matched) == len(actual_values), (
                f"expected all of {actual_values!r} to match {patterns!r}"
            )
    except Exception as exc:
        return False, f"assertion evaluation error: {exc}"
    return False, f"unsupported assertion op: {op!r}"


def evaluate_assertions(
    summary: dict[str, Any],
    assertions: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    specs = assertions or []
    results = []
    for idx, spec in enumerate(specs, start=1):
        if not isinstance(spec, dict):
            results.append({
                "id": f"assertion-{idx}",
                "status": "error",
                "severity": ASSERTION_FAILURE_SEVERITY,
                "subject": None,
                "op": None,
                "message": "assertion must be a mapping",
            })
            continue
        aid = str(spec.get("id") or f"assertion-{idx}")
        subject = str(spec.get("subject", ""))
        op = str(spec.get("op", "eq"))
        expected = spec.get("value")
        severity = str(spec.get("severity") or ASSERTION_FAILURE_SEVERITY)
        match = str(spec.get("match") or "glob")
        actual = _get_subject(summary, subject) if subject else None
        ok, message = _evaluate_assertion(actual, op, expected, match)
        results.append({
            "id": aid,
            "title": spec.get("title") or aid,
            "status": "passed" if ok else "failed",
            "severity": severity,
            "subject": subject,
            "op": op,
            "match": match if op in {"any_match", "none_match", "all_match"} else None,
            "expected": expected,
            "actual": actual,
            "message": message,
        })
    failures = [row for row in results if row["status"] != "passed"]
    max_sev = "info"
    for row in failures:
        severity = str(row.get("severity") or ASSERTION_FAILURE_SEVERITY)
        if _SEVERITY_RANK.get(severity, 0) > _SEVERITY_RANK[max_sev]:
            max_sev = severity
    return {
        "configured": bool(specs),
        "status": "failed" if failures else "passed" if specs else "not_configured",
        "passed": sum(1 for row in results if row["status"] == "passed"),
        "failed": len(failures),
        "max_failure_severity": max_sev if failures else None,
        "results": results,
    }


def load_assertions(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    raw = path.read_text()
    data = json.loads(raw) if path.suffix == ".json" else yaml.safe_load(raw)
    if isinstance(data, dict):
        data = data.get("assertions") or data.get("report", {}).get("assertions")
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError("assertions file must contain a list or an assertions: list mapping")
    return data


def policy_assertions(policy: dict[str, Any]) -> list[dict[str, Any]]:
    report = policy.get("report", {})
    if isinstance(report, dict) and isinstance(report.get("assertions"), list):
        return report["assertions"]
    if isinstance(policy.get("assertions"), list):
        return policy["assertions"]
    return []


def summarize_run_dir(
    run_dir: str | Path,
    *,
    retry_threshold: int = 3,
    assertions: list[dict[str, Any]] | None = None,
    include_policy_assertions: bool = True,
    max_files: int = DEFAULT_FILE_SCAN_LIMIT,
) -> dict[str, Any]:
    """Summarize a run directory without modifying it."""
    run_dir = Path(run_dir).resolve()
    meta = _read_json(run_dir / "meta.json")
    policy = _read_policy(run_dir)
    events = _read_events(run_dir / "events.jsonl")

    by_kind = Counter(str(e.get("kind", "")) for e in events)
    network = _network_rows(events)
    detections = [e.get("data", {}) or {} for e in events if e.get("kind") == "detection"]
    files = Counter()
    for event in events:
        if event.get("kind") != "file":
            continue
        data = event.get("data", {}) or {}
        op = str(data.get("op", ""))
        path = str(data.get("path", ""))
        if op and path:
            files[(op, path, bool(data.get("decoy")))] += 1

    work_base = Path(policy.get("files", {}).get("work_mount") or run_dir / "work")
    if not work_base.is_absolute():
        work_base = (run_dir / work_base).resolve()
    summary = {
        "run_dir": str(run_dir),
        "run_id": meta.get("run_id", run_dir.name),
        "status": meta.get("status"),
        "exit_code": meta.get("exit_code"),
        "kill_reason": meta.get("kill_reason"),
        "duration_s": _duration_s(meta),
        "counts": meta.get("counts", {}),
        "verdict": meta.get("verdict", {}),
        "instrumentation": meta.get("instrumentation", {}),
        "event_count": len(events),
        "events_by_kind": dict(sorted(by_kind.items())),
        "network": network,
        "network_sink_interactions": _sink_interactions(events),
        "network_findings": _network_findings(network, retry_threshold),
        "detections": detections,
        "snapshots": _snapshots(run_dir, events),
        "artifacts": _file_inventory(run_dir / "files", max_files=max_files),
        "work_files": _file_inventory(work_base, max_files=max_files),
        "file_events": [
            {"op": op, "path": path, "decoy": decoy, "count": count}
            for (op, path, decoy), count in sorted(files.items())
        ],
        "static": _static_compact(run_dir),
    }
    summary["metrics"] = _metrics(summary)
    assertion_specs = []
    if include_policy_assertions:
        assertion_specs.extend(policy_assertions(policy))
    if assertions:
        assertion_specs.extend(assertions)
    summary["assertions"] = evaluate_assertions(summary, assertion_specs)
    return summary


def markdown(summary: dict[str, Any], *, file_limit: int = 100) -> str:
    metrics = summary.get("metrics", {})
    assertions = summary.get("assertions", {})
    lines = [
        "# ContainRE Run Summary",
        "",
        f"Run: `{summary['run_id']}`",
        f"Directory: `{summary['run_dir']}`",
        f"Status: `{summary.get('status')}`",
        f"Exit code: `{summary.get('exit_code')}`",
    ]
    if summary.get("duration_s") is not None:
        lines.append(f"Duration: `{summary['duration_s']}` seconds")
    if summary.get("kill_reason"):
        lines.append(f"Kill reason: `{summary['kill_reason']}`")
    verdict = summary.get("verdict") or {}
    if verdict:
        lines.append(
            f"Verdict: `{verdict.get('max_severity', 'info')}` "
            f"flags=`{verdict.get('flags', [])}` attack=`{verdict.get('attack', [])}`"
        )
    tls_plaintext = (summary.get("instrumentation", {}) or {}).get("tls_plaintext", {}) or {}
    if tls_plaintext.get("enabled"):
        lines.append(
            "Instrumentation: `tls_plaintext` "
            f"mode=`{tls_plaintext.get('mode')}` invasive=`{tls_plaintext.get('invasive')}` "
            f"experimental=`{tls_plaintext.get('experimental')}`"
        )
    if assertions:
        lines.append(
            f"Assertions: `{assertions.get('status')}` "
            f"({assertions.get('passed', 0)} passed, {assertions.get('failed', 0)} failed)"
        )
    lines += [
        f"Events: **{summary['event_count']}**",
        "",
        "## Key Metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Remote endpoint events | {metrics.get('network.remote_endpoint_event_count', 0)} |",
        f"| Allowed/unblocked remote events | {metrics.get('network.allowed_remote_endpoint_event_count', 0)} |",
        f"| Blocked remote events | {metrics.get('network.blocked_remote_endpoint_event_count', 0)} |",
        f"| Connect successes | {metrics.get('network.connect_success_count', 0)} |",
        f"| Connect pending | {metrics.get('network.connect_pending_count', 0)} |",
        f"| Connect failures | {metrics.get('network.connect_failure_count', 0)} |",
        f"| Simulated sink interactions | {metrics.get('network.sink_interaction_count', 0)} |",
        f"| h2 gRPC replay messages | {metrics.get('network.h2_grpc_replay_messages', 0)} |",
        f"| h2 gRPC negative feature probes | {metrics.get('network.h2_grpc_replay_negative_feature_count', 0)} |",
        f"| Detections | {metrics.get('detections.count', 0)} |",
        f"| Artifacts | {metrics.get('artifacts.count', 0)} |",
        f"| Work files | {metrics.get('work_files.count', 0)} |",
        f"| Snapshots | {metrics.get('snapshots.count', 0)} |",
        f"| Static call edges | {metrics.get('static.call_edges.count', 0)} |",
        "",
        "## Events by Kind",
        "",
    ]
    if summary["events_by_kind"]:
        for kind, count in summary["events_by_kind"].items():
            lines.append(f"- `{kind}`: {count}")
    else:
        lines.append("- none recorded")

    lines += ["", "## Assertions", ""]
    if assertions.get("configured"):
        for row in assertions.get("results", []):
            marker = "PASS" if row["status"] == "passed" else "FAIL"
            lines.append(
                f"- `{marker}` `{row['id']}` {row.get('title') or ''} "
                f"({row.get('subject')} {row.get('op')} {row.get('expected')!r})"
            )
            if row["status"] != "passed":
                lines.append(f"  - actual: `{row.get('actual')}`")
                lines.append(f"  - detail: {row.get('message')}")
    else:
        lines.append("- none configured")

    lines += ["", "## Network Findings", ""]
    if summary["network_findings"]:
        for finding in summary["network_findings"]:
            lines.append(f"- `{finding['severity']}` {finding['title']}")
    else:
        lines.append("- none recorded")

    lines += [
        "",
        "## Network Observations",
        "",
        "| Operation | Endpoint | Protocol | Decisions | Results | Count | Bytes |",
        "|---|---|---|---|---|---:|---:|",
    ]
    if summary["network"]:
        for row in summary["network"]:
            decisions = ", ".join(f"{k}:{v}" for k, v in row["decisions"].items()) or "-"
            results = ", ".join(f"{k}:{v}" for k, v in row.get("results", {}).items()) or "-"
            errnos = ", ".join(f"{k}:{v}" for k, v in row.get("errnos", {}).items()) or "-"
            if errnos != "-":
                results = f"{results}; {errnos}" if results != "-" else errnos
            lines.append(
                f"| `{row['op']}` | `{row['endpoint']}` | `{row.get('proto') or '-'}` | "
                f"{decisions} | {results} | {row['count']} | {row['bytes']} |"
            )
    else:
        lines.append("| - | - | - | - | - | 0 | 0 |")

    lines += [
        "",
        "## Simulated Sink Interactions",
        "",
        "| Operation | Protocol | Count | Bytes In | Bytes Out | gRPC Requests | gRPC Messages | Methods | Negative Features | Notes |",
        "|---|---|---:|---:|---:|---:|---:|---|---|---|",
    ]
    if summary.get("network_sink_interactions"):
        for row in summary["network_sink_interactions"]:
            notes = ", ".join(f"{k}:{v}" for k, v in row.get("notes", {}).items()) or "-"
            methods = ", ".join(row.get("grpc_methods", [])) or "-"
            negative_features = ", ".join(
                f"{k}:{v}" for k, v in (row.get("grpc_negative_features") or {}).items()
            ) or "-"
            lines.append(
                f"| `{row['op']}` | `{row.get('proto') or '-'}` | {row['count']} | "
                f"{row.get('bytes_in', 0)} | {row.get('bytes_out', 0)} | "
                f"{row.get('grpc_requests', 0)} | {row.get('grpc_messages', 0)} | "
                f"`{methods}` | {negative_features} | {notes} |"
            )
    else:
        lines.append("| - | - | 0 | 0 | 0 | 0 | 0 | - | - | - |")

    lines += ["", "## Detections", ""]
    if summary["detections"]:
        for det in summary["detections"]:
            title = det.get("title") or det.get("id") or "detection"
            severity = det.get("severity", "unknown")
            lines.append(f"- `{severity}` {title}")
    else:
        lines.append("- none recorded")

    lines += ["", "## Artifacts", ""]
    artifacts = summary.get("artifacts", {})
    if artifacts.get("files"):
        lines.append(f"Base: `{artifacts.get('base')}`")
        for row in artifacts["files"][:file_limit]:
            digest = f" sha256=`{row['sha256']}`" if row.get("sha256") else ""
            lines.append(f"- `{row['path']}` ({row['size']} bytes){digest}")
        omitted = len(artifacts["files"]) - file_limit
        if omitted > 0:
            lines.append(f"- ... {omitted} more")
        if artifacts.get("truncated"):
            lines.append(f"- inventory truncated at {len(artifacts['files'])} of {artifacts['count']} file(s)")
    else:
        lines.append("- none recorded")

    lines += ["", "## Work Files", ""]
    work_files = summary.get("work_files", {})
    if work_files.get("files"):
        lines.append(f"Base: `{work_files.get('base')}`")
        for row in work_files["files"][:file_limit]:
            digest = f" sha256=`{row['sha256']}`" if row.get("sha256") else ""
            lines.append(f"- `{row['path']}` ({row['size']} bytes){digest}")
        omitted = len(work_files["files"]) - file_limit
        if omitted > 0:
            lines.append(f"- ... {omitted} more")
        if work_files.get("truncated"):
            lines.append(f"- inventory truncated at {len(work_files['files'])} of {work_files['count']} file(s)")
    else:
        lines.append("- none recorded")

    lines += ["", "## Snapshots", ""]
    if summary.get("snapshots"):
        for row in summary["snapshots"][:file_limit]:
            detail = f" reason={row.get('reason')}" if row.get("reason") else ""
            size = row.get("file_size") or row.get("bytes")
            size_text = f" size={size}" if size is not None else ""
            lines.append(f"- `{row['snapshot_id']}`{detail}{size_text}")
        omitted = len(summary["snapshots"]) - file_limit
        if omitted > 0:
            lines.append(f"- ... {omitted} more")
    else:
        lines.append("- none recorded")

    lines += ["", "## File Observations", ""]
    if summary["file_events"]:
        for row in summary["file_events"][:file_limit]:
            decoy = " decoy" if row["decoy"] else ""
            lines.append(f"- `{row['op']}` `{row['path']}` x{row['count']}{decoy}")
        omitted = len(summary["file_events"]) - file_limit
        if omitted > 0:
            lines.append(f"- ... {omitted} more")
    else:
        lines.append("- none recorded")
    return "\n".join(lines) + "\n"
