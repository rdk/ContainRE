"""ContainRE command-line interface - a thin client over the orchestrator.

    containre run <policy.yaml | binary> [options]   # record a run (headless)
    containre ls                                      # list runs
    containre show <run_id> [--events] [--kind K]     # inspect a run
    containre watch <run_id>                          # tail a live/finished run
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import typer
import yaml

from .. import policy as P
from ..control import default_runs_root, execute, get_runtime
from ..net.h2_grpc_replay import infer_h2_grpc_replay
from ..report import load_assertions
from ..report import markdown as report_markdown
from ..report import summarize_run_dir
from ..static_analysis import analyze_target
from ..static_analysis import load_static
from ..static_analysis import query_static
from ..static_analysis import write_static

app = typer.Typer(add_completion=False, help="Sandbox + tracer + flight recorder for Linux binaries.")

_SEV_COLOR = {"info": "white", "low": "cyan", "medium": "yellow", "high": "red", "critical": "bright_red"}


def _echo(msg: str, **kw) -> None:
    typer.secho(msg, **kw)


@app.command()
def run(
    target: str = typer.Argument(..., help="A policy file (.yaml/.json) or a specimen binary."),
    args: list[str] = typer.Argument(None, help="Arguments passed to the specimen."),
    net: str = typer.Option(None, "--net", help="Override network posture: deny|simulate|allow."),
    mitm: bool = typer.Option(False, "--mitm", help="TLS interception under --net simulate (decrypt HTTPS)."),
    decoy: list[str] = typer.Option(None, "--decoy", help="Plant a decoy/canary file (repeatable)."),
    ro_mount: list[str] = typer.Option(
        None,
        "--ro-mount",
        help="Read-only Docker bind mount HOST:CONTAINER (repeatable).",
    ),
    container_path: str = typer.Option(
        None,
        "--container-path",
        help="Docker path used to execute the specimen (default: /specimen).",
    ),
    timeout: int = typer.Option(None, "--timeout", help="Wall-clock limit (seconds)."),
    runtime: str = typer.Option("local", "--runtime", help="Execution backend: local|docker."),
    l2: str = typer.Option(None, "--l2", help="L2 instruction tracing: off|singlestep|unicorn."),
    l2_until_io: bool = typer.Option(False, "--l2-until-io", help="singlestep: window stops at the next I/O syscall."),
    l2_max: int = typer.Option(None, "--l2-max", help="Max instructions in the L2 window."),
    l2_region: str = typer.Option(None, "--l2-region", help="unicorn: region to emulate, 'START:END' (hex addrs)."),
    runs_root: Path = typer.Option(None, "--runs-root", help="Where run directories are written."),
    as_json: bool = typer.Option(False, "--json", help="Emit the run summary as JSON."),
) -> None:
    """Execute a specimen under the harness and record a run."""
    target_path = Path(target)
    if target_path.suffix in (".yaml", ".yml", ".json"):
        policy = P.load_policy(target_path)
    else:
        policy = P.policy_for_binary(target_path)
    if args:
        policy["specimen"]["args"] = list(args)
    if net:
        policy["network"]["posture"] = net
        policy["network"]["simulate"] = net == "simulate"
    if mitm:
        policy["network"]["mitm"] = True
    if decoy:
        policy["files"]["decoys"] = list(decoy)
    if ro_mount:
        mounts = []
        for item in ro_mount:
            source, sep, target = item.partition(":")
            if not sep or not source or not target.startswith("/"):
                raise typer.BadParameter("--ro-mount must be HOST:CONTAINER with an absolute container path")
            mounts.append({"source": source, "target": target})
        policy["files"]["read_only_mounts"] = mounts
    if container_path:
        if not container_path.startswith("/") or ":" in container_path:
            raise typer.BadParameter("--container-path must be an absolute container path")
        policy["specimen"]["container_path"] = container_path
    if timeout:
        policy["limits"]["wallclock_s"] = timeout
    if l2:
        policy["trace"]["l2"]["mode"] = l2
    if l2_until_io:
        policy["trace"]["l2"].setdefault("window", {})["until_io"] = True
    if l2_max:
        policy["trace"]["l2"].setdefault("window", {})["max_insns"] = l2_max
    if l2_region:
        start, _, end = l2_region.partition(":")
        w = policy["trace"]["l2"].setdefault("window", {})
        w["addr_start"], w["addr_end"] = start.strip(), end.strip()

    # Validate the EFFECTIVE policy after overrides (mirrors the API's
    # _build_policy), so e.g. `--net bogus` is rejected up front rather than
    # silently persisted and run with fall-through behavior.
    errors = P.validate(policy)
    if errors:
        raise typer.BadParameter("invalid effective policy:\n  " + "\n  ".join(errors))

    result = execute(policy, runs_root=runs_root or default_runs_root(),
                     runtime=get_runtime(runtime))
    meta = result.meta
    verdict = meta.get("verdict", {})
    if as_json:
        typer.echo(json.dumps({"run_id": result.run_id, "run_dir": str(result.run_dir),
                               "status": result.status, "exit_code": result.exit_code,
                               "counts": meta.get("counts"), "verdict": verdict}, indent=2))
        return
    _echo(f"run      {result.run_id}")
    _echo(f"dir      {result.run_dir}")
    _echo(f"status   {result.status}   exit={result.exit_code}"
          + (f"   killed: {meta.get('kill_reason')}" if meta.get("kill_reason") else ""))
    c = meta.get("counts", {})
    _echo(f"events   {c.get('events', 0)}  (detections={c.get('detections', 0)}, "
          f"net_flows={c.get('net_flows', 0)})")
    sev = verdict.get("max_severity", "info")
    _echo(f"verdict  severity={sev}  flags={verdict.get('flags') or '[]'}  "
          f"attack={verdict.get('attack') or '[]'}", fg=_SEV_COLOR.get(sev))
    for det in result.detections():
        d = det["data"]
        _echo(f"  [{d['severity']}] {d['id']}: {d['title']}", fg=_SEV_COLOR.get(d["severity"]))


@app.command("ls")
def list_runs(runs_root: Path = typer.Option(None, "--runs-root")) -> None:
    """List recorded runs."""
    root = runs_root or default_runs_root()
    if not root.exists():
        _echo(f"(no runs under {root})")
        raise typer.Exit()
    rows = []
    for meta_path in sorted(root.glob("*/meta.json")):
        m = json.loads(meta_path.read_text())
        v = m.get("verdict", {})
        rows.append((m.get("run_id", meta_path.parent.name), m.get("status", "?"),
                     str(m.get("exit_code")), v.get("max_severity", "-"),
                     ",".join(v.get("flags", [])) or "-"))
    if not rows:
        _echo(f"(no runs under {root})")
        raise typer.Exit()
    w = max(len(r[0]) for r in rows)
    _echo(f"{'RUN':<{w}}  {'STATUS':<9} {'EXIT':<5} {'SEVERITY':<9} FLAGS")
    for r in rows:
        _echo(f"{r[0]:<{w}}  {r[1]:<9} {r[2]:<5} {r[3]:<9} {r[4]}",
              fg=_SEV_COLOR.get(r[3]))


@app.command()
def show(
    run_id: str = typer.Argument(...),
    runs_root: Path = typer.Option(None, "--runs-root"),
    events: bool = typer.Option(False, "--events", help="Print the event stream."),
    kind: str = typer.Option(None, "--kind", help="Filter events by kind."),
    limit: int = typer.Option(50, "--limit"),
) -> None:
    """Show a run's metadata, detections, and (optionally) events."""
    run_dir = (runs_root or default_runs_root()) / run_id
    if not (run_dir / "meta.json").exists():
        _echo(f"no such run: {run_dir}", fg="red")
        raise typer.Exit(1)
    meta = json.loads((run_dir / "meta.json").read_text())
    typer.echo(json.dumps(meta, indent=2))
    if events:
        events_path = run_dir / "events.jsonl"
        all_events = []
        if events_path.exists():
            for line in events_path.read_text().splitlines():
                if not line.strip():
                    continue
                try:  # tolerate a torn final line / externally-produced run dir
                    all_events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        shown = [e for e in all_events if not kind or e.get("kind") == kind][:limit]
        _echo(f"\n-- events ({len(shown)} shown){' kind=' + kind if kind else ''} --")
        for e in shown:
            _echo(f"  #{e['seq']:>5} {e['kind']:<9} {json.dumps(e['data'])[:140]}")


@app.command()
def summarize(
    target: str = typer.Argument(..., help="Run id under --runs-root, or a run directory path."),
    runs_root: Path = typer.Option(None, "--runs-root"),
    as_json: bool = typer.Option(False, "--json", help="Emit JSON instead of Markdown."),
    assertions: Path = typer.Option(
        None,
        "--assertions",
        help="YAML/JSON assertion file to evaluate in addition to policy report.assertions.",
    ),
    no_policy_assertions: bool = typer.Option(
        False,
        "--no-policy-assertions",
        help="Ignore report.assertions stored in the run policy.",
    ),
    write_report: bool = typer.Option(
        False,
        "--write-report",
        help="Write report.json and report.md into the run directory.",
    ),
    fail_on_assertions: bool = typer.Option(
        False,
        "--fail-on-assertions",
        help="Exit 2 if any configured assertion fails.",
    ),
    retry_threshold: int = typer.Option(3, "--retry-threshold",
                                        help="Repeated blocked-connect threshold."),
    file_limit: int = typer.Option(100, "--file-limit",
                                   help="Maximum file-observation rows in Markdown output."),
) -> None:
    """Summarize an existing run without executing anything."""
    candidate = Path(target)
    run_dir = candidate if (candidate / "meta.json").exists() else (runs_root or default_runs_root()) / target
    if not (run_dir / "meta.json").exists():
        _echo(f"no such run: {run_dir}", fg="red")
        raise typer.Exit(1)
    assertion_specs = load_assertions(assertions) if assertions else None
    summary = summarize_run_dir(
        run_dir,
        retry_threshold=retry_threshold,
        assertions=assertion_specs,
        include_policy_assertions=not no_policy_assertions,
    )
    rendered = report_markdown(summary, file_limit=file_limit)
    if write_report:
        (run_dir / "report.json").write_text(json.dumps(summary, indent=2))
        (run_dir / "report.md").write_text(rendered)
    if as_json:
        typer.echo(json.dumps(summary, indent=2))
    else:
        typer.echo(rendered, nl=False)
    if fail_on_assertions and summary.get("assertions", {}).get("status") == "failed":
        raise typer.Exit(2)


@app.command("infer-h2-grpc-replay")
def infer_h2_grpc_replay_cmd(
    transcript: Path = typer.Argument(..., help="TLS plaintext JSONL capture from OpenSSL observe mode."),
    as_json: bool = typer.Option(False, "--json", help="Emit full inference JSON."),
    sink_only: bool = typer.Option(False, "--sink-only", help="Emit only the network.sink object."),
    service_host: str = typer.Option(
        None,
        "--service-host",
        help="Hostname to map to 127.0.0.1 for offline Docker runs.",
    ),
    service_port: int = typer.Option(
        None,
        "--service-port",
        min=1,
        max=65535,
        help="Original service port; also used as network.sink.listen_port.",
    ),
    no_trace: bool = typer.Option(
        False,
        "--no-trace",
        help="Emit a low-overhead offline fragment with trace.tracer=none and detectors disabled.",
    ),
    assert_no_egress: bool = typer.Option(
        False,
        "--assert-no-egress",
        help="Add a report assertion that no real remote endpoint was allowed.",
    ),
) -> None:
    """Infer an experimental h2-grpc-replay policy fragment from a TLS transcript."""
    if not transcript.exists():
        raise typer.BadParameter(f"transcript not found: {transcript}")
    if no_trace and (not service_host or service_port is None):
        raise typer.BadParameter("--no-trace requires --service-host and --service-port")
    result = infer_h2_grpc_replay(transcript)
    if service_port is not None:
        result["sink"]["listen_port"] = service_port
        result["network"]["sink"]["listen_port"] = service_port
    if service_host:
        result["network"]["extra_hosts"] = [{"host": service_host, "ip": "127.0.0.1"}]
    if no_trace:
        result["low_overhead_offline"] = {
            "trace": {
                "tracer": "none",
                "l1": [],
                "snapshot_on": [],
                "snapshot_every_ms": 0,
                "l2": {"mode": "off", "window": {}},
            },
            "detect": {
                "yara": False,
                "iocs": False,
                "heuristics": False,
                "attack_tags": False,
                "yara_rules": [],
            },
        }
    if assert_no_egress:
        result["report"] = {
            "assertions": [
                {
                    "id": "no-real-allowed-egress",
                    "subject": "network.real_allowed_remote_endpoint_event_count",
                    "op": "eq",
                    "value": 0,
                    "severity": "critical",
                },
            ],
        }
    if as_json:
        typer.echo(json.dumps(result, indent=2))
        return
    if result.get("warnings"):
        for warning in result["warnings"]:
            _echo(f"warning: {warning}", fg="yellow")
    if sink_only:
        fragment = result["sink"]
    else:
        fragment = {"network": result["network"]}
        if no_trace:
            fragment.update(result["low_overhead_offline"])
        if assert_no_egress:
            fragment["report"] = result["report"]
    typer.echo(yaml.safe_dump(fragment, sort_keys=False), nl=False)


def _static_target(target: str, runs_root: Path | None) -> tuple[Path, Path | None]:
    """Resolve TARGET as a path, run directory, or run id.

    Returns (analysis_target, default_out_dir). default_out_dir is set for run
    directories/ids so analysis can be cached under runs/<id>/static.
    """
    candidate = Path(target)
    if candidate.exists():
        if (candidate / "meta.json").exists():
            meta = json.loads((candidate / "meta.json").read_text())
            specimen = Path(meta.get("specimen", {}).get("path", ""))
            return specimen, candidate / "static"
        return candidate, None
    root = runs_root or default_runs_root()
    run_dir = root / target
    if (run_dir / "meta.json").exists():
        meta = json.loads((run_dir / "meta.json").read_text())
        specimen = Path(meta.get("specimen", {}).get("path", ""))
        return specimen, run_dir / "static"
    return candidate, None


def _load_or_analyze_static(
    target: str,
    *,
    runs_root: Path | None,
    refresh: bool,
    query: str | None = None,
    out: Path | None = None,
) -> tuple[dict, Path | None]:
    analysis_target, default_out = _static_target(target, runs_root)
    out_dir = out or default_out
    cached = out_dir / "static.json" if out_dir else None
    if cached and cached.exists() and not refresh:
        data = load_static(cached)
        return data, cached
    if not analysis_target.exists():
        raise typer.BadParameter(f"target not found: {analysis_target}")
    data = analyze_target(analysis_target, query=query)
    path = write_static(data, out_dir) if out_dir else None
    return data, path


@app.command("static")
def static_cmd(
    target: str = typer.Argument(..., help="ELF file, directory, run id, or run directory."),
    runs_root: Path = typer.Option(None, "--runs-root"),
    out: Path = typer.Option(None, "--out", help="Directory for static.json. Run ids default to RUN/static."),
    query: str = typer.Option(None, "--query", help="Also collect source refs for this text."),
    refresh: bool = typer.Option(False, "--refresh", help="Recompute even if cached static.json exists."),
    as_json: bool = typer.Option(False, "--json", help="Emit full JSON evidence."),
) -> None:
    """Extract static symbols, imports, strings, and direct call-site evidence."""
    data, path = _load_or_analyze_static(
        target,
        runs_root=runs_root,
        refresh=refresh,
        query=query,
        out=out,
    )
    if as_json:
        typer.echo(json.dumps(data, indent=2))
        return
    summary = data.get("summary", {})
    _echo(f"target       {data.get('target')}")
    if path:
        _echo(f"static.json  {path}")
    _echo(
        "files        {files_total}  symbols={symbols}  funcs={functions}  "
        "calls={call_edges}  imports={imports}  strings={strings}".format(**summary)
    )
    if summary.get("warnings"):
        _echo(f"warnings     {summary['warnings']}", fg="yellow")
    if query:
        result = query_static(data, query)
        _echo(f"\nquery        {query}")
        _echo(f"matches      {len(result['matches'])}  callers={len(result['callers'])}  "
              f"callees={len(result['callees'])}  strings={len(result['string_refs'])}")


@app.command()
def callers(
    target: str = typer.Argument(..., help="ELF file, directory, run id, or run directory."),
    symbol: str = typer.Argument(..., help="Symbol/name fragment to query."),
    runs_root: Path = typer.Option(None, "--runs-root"),
    refresh: bool = typer.Option(False, "--refresh"),
    as_json: bool = typer.Option(False, "--json"),
    limit: int = typer.Option(80, "--limit"),
) -> None:
    """Show direct static callers for a symbol or name fragment."""
    data, _ = _load_or_analyze_static(
        target,
        runs_root=runs_root,
        refresh=refresh,
        query=symbol,
    )
    result = query_static(data, symbol, direction="callers", limit=limit)
    if as_json:
        typer.echo(json.dumps(result, indent=2))
        return
    _echo(f"callers for {symbol}: {len(result['callers'])}")
    for edge in result["callers"]:
        _echo(
            f"  {edge['file']} {edge['from']} -> {edge['to']} "
            f"at {edge['callsite']} [{edge['confidence']}]"
        )


@app.command()
def callees(
    target: str = typer.Argument(..., help="ELF file, directory, run id, or run directory."),
    symbol: str = typer.Argument(..., help="Symbol/name fragment to query."),
    runs_root: Path = typer.Option(None, "--runs-root"),
    refresh: bool = typer.Option(False, "--refresh"),
    as_json: bool = typer.Option(False, "--json"),
    limit: int = typer.Option(80, "--limit"),
) -> None:
    """Show direct static callees for a symbol or name fragment."""
    data, _ = _load_or_analyze_static(
        target,
        runs_root=runs_root,
        refresh=refresh,
        query=symbol,
    )
    result = query_static(data, symbol, direction="callees", limit=limit)
    if as_json:
        typer.echo(json.dumps(result, indent=2))
        return
    _echo(f"callees from {symbol}: {len(result['callees'])}")
    for edge in result["callees"]:
        _echo(
            f"  {edge['file']} {edge['from']} -> {edge['to']} "
            f"at {edge['callsite']} [{edge['confidence']}]"
        )


@app.command()
def watch(
    run_id: str = typer.Argument(...),
    runs_root: Path = typer.Option(None, "--runs-root"),
    kind: str = typer.Option(None, "--kind"),
) -> None:
    """Tail a run's event stream (works for live and finished runs)."""
    run_dir = (runs_root or default_runs_root()) / run_id
    events_path = run_dir / "events.jsonl"
    meta_path = run_dir / "meta.json"
    if not meta_path.exists():
        _echo(f"no such run: {run_dir}", fg="red")
        raise typer.Exit(1)
    pos = 0
    try:
        while True:
            if events_path.exists():
                with open(events_path) as fh:
                    fh.seek(pos)
                    for line in fh:
                        if not line.endswith("\n"):
                            break
                        pos = fh.tell()
                        e = json.loads(line)
                        if kind and e["kind"] != kind:
                            continue
                        _echo(f"#{e['seq']:>5} {e['kind']:<9} {json.dumps(e['data'])[:140]}")
            status = json.loads(meta_path.read_text()).get("status")
            if status in ("finished", "killed", "error"):
                _echo(f"-- run {status} --", fg="green")
                break
            time.sleep(0.3)
    except KeyboardInterrupt:
        pass


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8787, "--port"),
    runs_root: Path = typer.Option(None, "--runs-root"),
    runtime: str = typer.Option("local", "--runtime", help="Backend for launched runs: local|docker."),
    max_concurrent: int = typer.Option(None, "--max-concurrent"),
) -> None:
    """Start the control-plane API + web dashboard."""
    import uvicorn

    if runs_root:
        os.environ["CONTAINRE_RUNS_ROOT"] = str(runs_root)
    os.environ["CONTAINRE_RUNTIME"] = runtime
    if max_concurrent:
        os.environ["CONTAINRE_MAX_CONCURRENT"] = str(max_concurrent)
    _echo(f"ContainRE control plane → http://{host}:{port}  (runtime={runtime})", fg="green")
    uvicorn.run("containre.api.app:app", host=host, port=port)


if __name__ == "__main__":
    app()
