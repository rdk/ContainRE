"""Unit tests for post-hoc run reporting."""
from __future__ import annotations

import json

import pytest
import yaml

from containre.report import evaluate_assertions, load_assertions, markdown, summarize_run_dir

pytestmark = pytest.mark.unit


def _write_run(run_dir, events, *, policy=None, meta=None):
    run_dir.mkdir()
    base_meta = {
        "run_id": run_dir.name,
        "status": "finished",
        "exit_code": 1,
        "created_wall": 1_000_000_000,
        "started_wall": 2_000_000_000,
        "stopped_wall": 4_500_000_000,
        "verdict": {"max_severity": "info", "flags": [], "attack": []},
    }
    if meta:
        base_meta.update(meta)
    (run_dir / "meta.json").write_text(json.dumps(base_meta))
    if policy is not None:
        (run_dir / "policy.yaml").write_text(yaml.safe_dump(policy))
    (run_dir / "events.jsonl").write_text(
        "\n".join(json.dumps(event) for event in events) + "\n"
    )


def test_summary_identifies_blocked_dns_retries(tmp_path):
    run = tmp_path / "run-dns"
    events = []
    for seq in range(4):
        events.append({
            "seq": seq,
            "kind": "net",
            "data": {
                "op": "connect",
                "proto": "tcp",
                "raddr": "8.8.8.8:53",
                "decision": "block",
            },
        })
    events.append({
        "seq": 4,
        "kind": "detection",
        "data": {"severity": "medium", "title": "Network egress attempt"},
    })
    _write_run(run, events)

    summary = summarize_run_dir(run, retry_threshold=3)

    assert summary["network"] == [{
        "op": "connect",
        "endpoint": "8.8.8.8:53",
        "proto": "tcp",
        "count": 4,
        "bytes": 0,
        "decisions": {"block": 4},
    }]
    finding_ids = {finding["id"] for finding in summary["network_findings"]}
    assert "all-remote-egress-blocked" in finding_ids
    assert "blocked-connect-retry" in finding_ids
    assert "blocked-dns-port" in finding_ids
    assert "Repeated blocked connects to 8.8.8.8:53 x4" in markdown(summary)


def test_summary_identifies_no_remote_endpoint_events(tmp_path):
    run = tmp_path / "run-local"
    _write_run(run, [
        {"seq": 0, "kind": "net", "data": {"op": "socket"}},
        {"seq": 1, "kind": "net", "data": {"op": "bind"}},
        {"seq": 2, "kind": "file", "data": {"op": "open", "path": "/work/input"}},
    ])

    summary = summarize_run_dir(run)

    assert summary["network_findings"] == [{
        "id": "no-remote-endpoint-events",
        "severity": "info",
        "title": "No remote endpoint events recorded",
    }]
    assert "No remote endpoint events recorded" in markdown(summary)


def test_summary_reports_connect_result_metrics(tmp_path):
    run = tmp_path / "run-connect-results"
    _write_run(run, [
        {
            "seq": 0,
            "kind": "net",
            "data": {
                "op": "connect",
                "proto": "tcp",
                "raddr": "192.0.2.10:53000",
                "decision": "allow",
            },
        },
        {
            "seq": 1,
            "kind": "net",
            "data": {
                "op": "connect_result",
                "proto": "tcp",
                "raddr": "192.0.2.10:53000",
                "decision": "allow",
                "ret": 0,
                "success": True,
                "status": "success",
            },
        },
        {
            "seq": 2,
            "kind": "net",
            "data": {
                "op": "connect_result",
                "proto": "tcp",
                "raddr": "192.0.2.10:53000",
                "decision": "allow",
                "ret": -115,
                "success": False,
                "status": "pending",
                "errno_name": "EINPROGRESS",
            },
        },
        {
            "seq": 3,
            "kind": "net",
            "data": {
                "op": "connect_result",
                "proto": "tcp",
                "raddr": "192.0.2.10:53000",
                "decision": "allow",
                "ret": -111,
                "success": False,
                "status": "failure",
                "errno_name": "ECONNREFUSED",
            },
        },
        {
            "seq": 4,
            "kind": "net",
            "data": {
                "op": "socket_error",
                "proto": "tcp",
                "raddr": "192.0.2.10:53000",
                "status": "ok",
                "so_error": 0,
            },
        },
    ])

    summary = summarize_run_dir(run)

    assert summary["metrics"]["network.remote_endpoint_event_count"] == 1
    assert summary["metrics"]["network.connect_success_count"] == 1
    assert summary["metrics"]["network.connect_pending_count"] == 1
    assert summary["metrics"]["network.connect_failure_count"] == 1
    result_row = [row for row in summary["network"] if row["op"] == "connect_result"][0]
    assert result_row["results"] == {"failure": 1, "pending": 1, "success": 1}
    assert result_row["errnos"] == {"ECONNREFUSED": 1, "EINPROGRESS": 1}
    socket_error_row = [row for row in summary["network"] if row["op"] == "socket_error"][0]
    assert socket_error_row["results"] == {"ok": 1}
    rendered = markdown(summary)
    assert "Connect successes" in rendered
    assert "Connect pending" in rendered
    assert "ECONNREFUSED:1" in rendered


def test_summary_reports_h2_grpc_replay_sink_metrics(tmp_path):
    run = tmp_path / "run-h2-grpc-replay"
    _write_run(run, [
        {
            "seq": 0,
            "kind": "net",
            "data": {
                "op": "h2-grpc-replay",
                "proto": "h2",
                "experimental": True,
                "bytes_in": 536,
                "bytes_out": 150,
                "grpc": {
                    "requests": 1,
                    "messages": 1,
                    "methods": ["Ping"],
                },
                "note": "client closed",
                "tls": True,
            },
        },
        {
            "seq": 1,
            "kind": "net",
            "data": {
                "op": "h2-grpc-replay",
                "proto": "h2",
                "experimental": True,
                "bytes_in": 886,
                "bytes_out": 337,
                "grpc": {
                    "requests": 1,
                    "messages": 5,
                    "methods": ["StreamData"],
                    "negative_features": ["FEAT_ALPHA", "FEAT_ALPHA"],
                },
                "note": "client closed",
                "tls": True,
            },
        },
    ])

    summary = summarize_run_dir(run)

    assert summary["metrics"]["network.sink_interaction_count"] == 2
    assert summary["metrics"]["network.h2_grpc_replay_interaction_count"] == 2
    assert summary["metrics"]["network.h2_grpc_replay_messages"] == 6
    assert summary["metrics"]["network.h2_grpc_replay_methods"] == ["Ping", "StreamData"]
    assert summary["metrics"]["network.h2_grpc_replay_negative_feature_count"] == 2
    assert summary["metrics"]["network.h2_grpc_replay_negative_features"] == {"FEAT_ALPHA": 2}
    rendered = markdown(summary)
    assert "## Simulated Sink Interactions" in rendered
    assert "`Ping, StreamData`" in rendered
    assert "FEAT_ALPHA:2" in rendered


def test_summary_builds_metrics_and_file_inventories(tmp_path):
    run = tmp_path / "run-files"
    _write_run(run, [
        {"seq": 0, "kind": "file", "data": {"op": "write", "path": str(run / "work/out.txt")}},
        {"seq": 1, "kind": "mem", "data": {"op": "snapshot", "snapshot_id": "snap-abc",
                                           "reason": "exec", "bytes": 12}},
    ])
    (run / "work").mkdir()
    (run / "work" / "out.txt").write_text("payload")
    (run / "files").mkdir()
    (run / "files" / "a-123_output.txt").write_text("artifact")
    (run / "snapshots").mkdir()
    (run / "snapshots" / "snap-abc.bin").write_bytes(b"snapshot")

    summary = summarize_run_dir(run)

    assert summary["duration_s"] == 2.5
    assert summary["metrics"]["artifacts.count"] == 1
    assert summary["metrics"]["artifacts.names"] == ["a-123_output.txt"]
    assert summary["metrics"]["work_files.names"] == ["out.txt"]
    assert summary["metrics"]["snapshots.ids"] == ["snap-abc"]
    rendered = markdown(summary)
    assert "## Key Metrics" in rendered
    assert "## Artifacts" in rendered
    assert "snap-abc" in rendered


def test_file_inventory_excludes_symlinks_escaping_workdir(tmp_path):
    run = tmp_path / "run-symlink"
    secret = tmp_path / "host-secret.txt"
    secret.write_text("HOST SECRET")
    _write_run(run, [
        {"seq": 0, "kind": "file", "data": {"op": "write", "path": str(run / "work/loot")}},
    ])
    (run / "work").mkdir()
    (run / "work" / "real.txt").write_text("ok")
    (run / "work" / "loot").symlink_to(secret)  # specimen-planted symlink to a host file

    # sha256 of the escaping secret, so we can prove its content was never hashed
    import hashlib
    secret_digest = hashlib.sha256(b"HOST SECRET").hexdigest()

    summary = summarize_run_dir(run)
    rows = summary["work_files"]["files"]
    names = summary["metrics"]["work_files.names"]

    assert names == ["real.txt"]                    # only the real file; the symlink is excluded
    assert "loot" not in names
    # the host secret's content must not have been read/hashed into any row
    assert all(row.get("sha256") != secret_digest for row in rows)


def test_summary_tolerates_a_malformed_events_line(tmp_path):
    run = tmp_path / "run-torn"
    _write_run(run, [{"seq": 0, "kind": "proc", "data": {"op": "exit", "exit_code": 0}}])
    # a garbage / torn line appended to events.jsonl must not crash the report.
    with (run / "events.jsonl").open("a") as fh:
        fh.write('{"seq": 1, "kind": "net"  <-- torn\n')
    summary = summarize_run_dir(run)  # must not raise
    assert summary["run_id"] == run.name


def test_summary_builds_decoy_file_event_metrics(tmp_path):
    run = tmp_path / "run-decoys"
    _write_run(run, [
        {
            "seq": 0,
            "kind": "file",
            "data": {"op": "open", "path": "/work/home/.ssh/id_rsa", "decoy": True},
        },
        {
            "seq": 1,
            "kind": "file",
            "data": {"op": "open", "path": "/work/dock.in"},
        },
    ])

    summary = summarize_run_dir(run)

    assert summary["metrics"]["file_events.decoy_count"] == 1
    assert summary["metrics"]["file_events.decoy_paths"] == ["/work/home/.ssh/id_rsa"]


def test_summary_exposes_tls_plaintext_instrumentation_metrics(tmp_path):
    run = tmp_path / "run-instrumentation"
    run.mkdir()
    (run / "meta.json").write_text(json.dumps({
        "schema_version": 1,
        "run_id": "run-instrumentation",
        "status": "finished",
        "specimen": {"sha256": "0" * 64},
        "created_wall": 1,
        "stopped_wall": 2,
        "instrumentation": {
            "tls_plaintext": {
                "enabled": True,
                "mode": "replay",
                "invasive": True,
                "experimental": True,
            },
        },
    }))
    (run / "policy.yaml").write_text("specimen: {path: /bin/true}\n")
    (run / "events.jsonl").write_text("")

    summary = summarize_run_dir(run)

    assert summary["metrics"]["instrumentation.tls_plaintext.enabled"] is True
    assert summary["metrics"]["instrumentation.tls_plaintext.mode"] == "replay"
    assert summary["metrics"]["instrumentation.tls_plaintext.invasive"] is True
    assert summary["metrics"]["instrumentation.tls_plaintext.experimental"] is True
    rendered = markdown(summary)
    assert "Instrumentation: `tls_plaintext` mode=`replay`" in rendered


def test_policy_assertions_are_evaluated_and_reported(tmp_path):
    run = tmp_path / "run-assert"
    policy = {
        "specimen": {"path": "/bin/true"},
        "report": {
            "assertions": [
                {
                    "id": "no-remote",
                    "subject": "network.remote_endpoint_event_count",
                    "op": "eq",
                    "value": 0,
                },
                {
                    "id": "no-output",
                    "subject": "artifacts.names",
                    "op": "none_match",
                    "value": ["*.dat", "*.csv"],
                },
            ],
        },
    }
    _write_run(run, [{"seq": 0, "kind": "net", "data": {"op": "socket"}}], policy=policy)

    summary = summarize_run_dir(run)

    assert summary["assertions"]["status"] == "passed"
    assert summary["assertions"]["passed"] == 2
    rendered = markdown(summary)
    assert "`PASS` `no-remote`" in rendered
    assert "Assertions: `passed`" in rendered


def test_forged_duplicate_seq_lines_are_dropped_and_counted(tmp_path):
    run = tmp_path / "run-forged"
    _write_run(run, [
        {"seq": 0, "kind": "net", "data": {"op": "connect", "raddr": "1.2.3.4:443",
                                           "decision": "allow"}},
        {"seq": 1, "kind": "proc", "data": {"op": "exit", "exit_code": 0}},
    ])
    # specimen forges lines in its own events.jsonl: a duplicate seq (rewrite the
    # allow as a block) and a non-integer seq.
    with (run / "events.jsonl").open("a") as fh:
        fh.write(json.dumps({"seq": 0, "kind": "net",
                             "data": {"op": "connect", "raddr": "1.2.3.4:443",
                                      "decision": "block"}}) + "\n")
        fh.write(json.dumps({"seq": "x", "kind": "net", "data": {"op": "connect"}}) + "\n")

    summary = summarize_run_dir(run)

    assert summary["metrics"]["integrity.suspect_event_lines"] == 2
    # the real (first) allow event survives; the forged block does not overwrite it.
    assert summary["metrics"]["network.real_allowed_remote_endpoint_event_count"] == 1


def test_detections_max_severity_derives_from_events_not_stale_verdict(tmp_path):
    run = tmp_path / "run-killed-early"
    # detection recorded, but the run was hard-killed before finalize wrote the
    # verdict, so meta.verdict.max_severity is a stale 'info'.
    _write_run(run, [
        {"seq": 0, "kind": "detection",
         "data": {"id": "decoy-access", "severity": "critical", "title": "decoy"}},
    ], meta={"verdict": {"max_severity": "info", "flags": [], "attack": []}, "status": "killed"})

    summary = summarize_run_dir(run)

    assert summary["metrics"]["detections.count"] == 1
    assert summary["metrics"]["detections.max_severity"] == "critical"


def test_negative_assertion_on_missing_subject_is_error_not_silent_pass():
    summary = {"metrics": {"artifacts.names": ["exfil.dat"]}}
    result = evaluate_assertions(summary, [
        # 'artifact.names' is a typo for 'artifacts.names'; a none_match gate must
        # not vacuously PASS just because the subject didn't resolve.
        {"id": "typo", "subject": "artifact.names", "op": "none_match", "value": ["*.dat"]},
    ])
    row = result["results"][0]
    assert row["status"] == "error"
    assert result["status"] == "failed"
    assert "did not resolve" in row["message"]


def test_not_exists_still_passes_on_a_genuinely_missing_subject():
    result = evaluate_assertions({"metrics": {}}, [
        {"id": "gone", "subject": "nope.missing", "op": "not_exists"},
    ])
    assert result["results"][0]["status"] == "passed"


def test_assertion_failures_capture_actual_values():
    summary = {
        "metrics": {
            "network.remote_endpoint_event_count": 2,
            "artifacts.names": ["result.dat"],
        },
    }

    result = evaluate_assertions(summary, [
        {
            "id": "no-egress",
            "subject": "network.remote_endpoint_event_count",
            "op": "eq",
            "value": 0,
            "severity": "critical",
        },
        {
            "id": "forbid-outputs",
            "subject": "artifacts.names",
            "op": "none_match",
            "value": ["*.dat"],
        },
    ])

    assert result["status"] == "failed"
    assert result["failed"] == 2
    assert result["max_failure_severity"] == "critical"
    assert result["results"][0]["actual"] == 2


def test_load_assertions_accepts_mapping_or_list(tmp_path):
    mapping = tmp_path / "assertions.yaml"
    mapping.write_text(yaml.safe_dump({
        "assertions": [{"id": "exit", "subject": "exit_code", "op": "ne", "value": 0}]
    }))
    direct = tmp_path / "assertions.json"
    direct.write_text(json.dumps([
        {"id": "no-remote", "subject": "network.remote_endpoint_event_count", "op": "eq", "value": 0}
    ]))

    assert load_assertions(mapping)[0]["id"] == "exit"
    assert load_assertions(direct)[0]["id"] == "no-remote"
