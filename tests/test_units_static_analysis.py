"""Unit tests for static symbol and call-site analysis."""
from __future__ import annotations

import json

import pytest

from containre.report import evaluate_assertions, summarize_run_dir
from containre.static_analysis import (
    _CALL_RE,
    _symbol_matches,
    analyze_target,
    query_static,
    write_static,
)

pytestmark = pytest.mark.unit


def test_call_re_captures_full_demangled_target_with_nested_brackets():
    line = ("  138e:\te8 01 02 03 04       \tcallq  1234 "
            "<std::vector<int, std::allocator<int> >::push_back(int const&)>")
    m = _CALL_RE.match(line)
    assert m is not None
    assert m.group(4) == "std::vector<int, std::allocator<int> >::push_back(int const&)"


def test_static_analysis_extracts_symbols_and_calls(build_specimen):
    binary = build_specimen("hello")

    data = analyze_target(binary, query="main")

    assert data["summary"]["files_total"] == 1
    assert data["summary"]["symbols"] > 0
    assert data["summary"]["functions"] > 0
    assert any("main" in row["name"] for row in data["symbols"])
    assert data["call_edges"], "expected at least one direct call edge from hello"

    result = query_static(data, "main")
    assert result["matches"]
    assert result["callees"], "main should have at least one direct callee in the test binary"
    assert result["nodes"]
    assert result["edges"]


def test_static_analysis_query_finds_import_callers(build_specimen):
    binary = build_specimen("netbeacon")

    data = analyze_target(binary)
    result = query_static(data, "connect")

    assert result["matches"], "connect should appear as an imported symbol"
    assert result["callers"], "expected a direct call to connect or connect@plt"
    assert any("connect" in edge["to"] for edge in result["callers"])


def test_static_report_metrics_and_contains_edge_assertion(tmp_path, build_specimen):
    binary = build_specimen("netbeacon")
    static = analyze_target(binary)
    run = tmp_path / "run-static"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({
        "run_id": run.name,
        "status": "finished",
        "exit_code": 0,
        "created_wall": 1_000_000_000,
        "stopped_wall": 2_000_000_000,
        "verdict": {"max_severity": "info", "flags": [], "attack": []},
    }))
    (run / "events.jsonl").write_text("")
    write_static(static, run / "static")

    summary = summarize_run_dir(run)

    assert summary["metrics"]["static.available"] is True
    assert summary["metrics"]["static.call_edges.count"] > 0
    result = evaluate_assertions(summary, [{
        "id": "main-calls-connect",
        "subject": "static.call_edges",
        "op": "contains_edge",
        "value": {"from": "*main*", "to": "*connect*"},
    }])
    assert result["status"] == "passed"
