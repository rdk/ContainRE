# Architecture and Tech Stack

ContainRE is split into a control plane, runtime backend, tracer, network sink,
run store, API, CLI, and web UI. The same run directory is used by both live and
post-hoc workflows.

## Data Flow

```text
CLI / Svelte web UI
        |
        | REST / WebSocket
        v
FastAPI control plane
        |
        | start policy
        v
Runtime backend: local or docker
        |
        | launches tracer + specimen
        v
ptrace tracer + optional NetSink
        |
        | events, snapshots, pcap, artifacts, detections
        v
~/.containre/runs/<run_id>/
        ^
        | optional post-hoc static analyzer writes static/static.json
```

## Main Components

- `containre/cli` - Typer command-line interface.
- `containre/api` - FastAPI application and run manager.
- `containre/control` - run creation, policy application, orchestration, and
  verdict metadata.
- `containre/runtime` - `LocalRuntime` and `DockerRuntime` implementations.
- `containre/tracer` - ptrace-based L1 tracer plus L2 single-step and Unicorn
  region support.
- `containre/net` - simulated-internet sink, TLS helper code, and pcap writer.
- `containre/memory` - memory snapshot capture and loading.
- `containre/detect` - YARA and behavioral detectors.
- `containre/static_analysis.py` - ELF/source static evidence extraction and
  caller/callee graph queries.
- `containre/store` - per-run event, metadata, artifact, snapshot, and SQLite
  index storage.
- `webapp` - Svelte 5 frontend.
- `contracts` - versioned JSON schemas and example payloads.
- `specimens` - small C programs used by examples and tests.

## Runtime Backends

| Backend | Best For | Isolation |
|---|---|---|
| `local` | development, tests, trusted specimens | host process with ptrace interception |
| `docker` | untrusted specimens | locked-down container, cgroups, no real egress by default |

Both backends feed the same tracer and produce the same run-directory format.
The `Runtime` interface is the extension point for stronger isolation backends
such as gVisor or Firecracker later.

## Run Directory

A run is stored under `~/.containre/runs/<run_id>/` by default. Important files:

- `meta.json` - status, specimen hash, runtime, counts, verdict, host facts.
- `policy.yaml` - exact effective policy used for the run.
- `events.jsonl` - ordered structured event stream.
- `index.sqlite` - query/index companion for events and artifacts.
- `snapshots/` - captured memory snapshot blobs.
- `files/` - captured dropped or modified artifacts.
- `net/capture.pcap` - reconstructed packet capture when traffic was observed.
- `checkpoints/` - best-effort checkpoint metadata/images when supported.
- `static/static.json` - optional static symbols, imports, strings, direct
  call edges, and source references.

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3, C specimens, TypeScript |
| Packaging | `uv`, `pyproject.toml` |
| CLI | Typer |
| API | FastAPI, uvicorn |
| Tracing | `python-ptrace`, Linux ptrace, Capstone, Unicorn |
| Static analysis | binutils (`readelf`, `objdump`, `strings`, `c++filt`) |
| Detection | YARA-compatible scanner path plus behavioral detectors |
| Storage | JSONL, SQLite, per-run binary blobs |
| Runtime | local host process or Docker |
| Frontend | Svelte 5, Vite |
| Validation | pytest, ruff, JSON Schema contracts, svelte-check |

## Contracts

The API and stored artifacts use versioned schemas from [contracts](../contracts/).
Within schema major version 1, changes are additive where possible and readers
should tolerate unknown fields.
