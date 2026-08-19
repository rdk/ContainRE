# Features

ContainRE records what a specimen does while keeping the run reproducible and
inspectable after the fact.

## Execution and Containment

- Linux ELF x86-64 specimen support.
- `local` runtime for development and trusted specimens.
- `docker` runtime for untrusted specimens, with container isolation, dropped
  capabilities, cgroup limits, and no real network egress by default.
- Per-run resource policy for CPU, memory, process count, wall-clock timeout,
  disk budget, arguments, environment, stdin, and work directory.
- Docker read-only bind mounts for dependency trees or fixture bundles needed by
  larger installed applications.
- Optional Docker specimen path preservation for launchers that infer install
  roots from their executable path.
- Opt-in host device passthrough (`runtime.docker_devices`) for trusted compute
  workloads that need real hardware, such as a GPU. Off by default, and reported
  as an explicit isolation trade-off — see
  [Device passthrough](batch-helper-services.md#device-passthrough-gpus).

## Tracing

- L1 syscall/event tracing for network, file I/O, process lifecycle, memory map
  changes, signals, anti-debug calls, and selected runtime behavior.
- Opt-in L2 instruction tracing:
  - ptrace single-step for faithful live-process stepping.
  - Unicorn region emulation for isolated function or unpacker analysis.
- Structured events written as JSONL and served through REST/WebSocket APIs.

## Static Analysis

- ELF symbol, import/export, relocation, string, and direct call-site extraction
  from binaries or directories.
- Conservative call graph evidence: only disassembled direct calls are marked as
  confirmed direct calls; source and string hits are kept as references.
- CLI caller/callee queries for symbols or name fragments.
- Per-run `static/static.json` artifacts for reports, APIs, dashboard review,
  and assertion checks.
- Dashboard static tab with searchable symbols, caller/callee lists, and an SVG
  call graph centered on the queried symbol.

## Network Analysis

- Default egress containment.
- `deny`, `simulate`, and `allow` network postures.
- Built-in simulated-internet sink for HTTP(S) and generic TCP behavior.
- Optional TLS MITM under simulated networking.
- Experimental HTTP/2 gRPC replay sink with policy-configured method names and
  protobuf response bodies for offline A/B tests, plus configured non-zero gRPC
  status responses for request payload probes that real services reject.
- `infer-h2-grpc-replay` command that derives an offline replay sink fragment
  from a TLS plaintext capture, including optional fixed-port/no-trace fragments
  for low-overhead offline benchmarks.
- Optional `trace.tracer: none` Docker mode for known workflows where only the
  local emulator and container isolation should remain enabled.
- Optional Docker `--user` selection for containerized workflows that are
  sensitive to UID/GID.
- Opt-in OpenSSL plaintext instrumentation with `observe` and explicitly
  experimental `replay` modes.
- Reconstructed pcap output from observed socket payloads.
- Flow and IOC extraction from network activity.

## Files, Memory, and Artifacts

- Decoy files for ransomware and stealer-style behavior.
- Captured dropped or modified files.
- Policy-triggered memory snapshots.
- Online memory viewer with region selection and hexdump output.
- Best-effort CRIU checkpoint/restore hooks for Docker runs.

## Detection

- YARA over memory snapshots and captured files.
- Behavioral heuristics for decoy access, egress attempts, anti-debug behavior,
  credential access, and executable memory/injection signals.
- Verdict summaries with severity, flags, and optional MITRE ATT&CK tags.

## Interfaces

- CLI for headless runs and post-hoc inspection.
- CLI run summaries that group network endpoints, detections, file activity,
  and repeated blocked-egress patterns.
- Static analysis commands for symbol inventory and caller/callee analysis.
- Post-hoc evidence reports with reusable assertions for no-egress, no-output,
  exit-code, detection, artifact, static call-edge, and work-directory
  expectations.
- FastAPI control-plane API.
- Svelte 5 web UI for live event streams, run details, memory, detections,
  artifacts, pcap downloads, L2 traces, and static call graphs.
- Versioned JSON schemas in [contracts](../contracts/).

## Test Support

- Test runner: `./run_tests.sh` — offline unit tests by default; `--integration`
  adds the specimen/docker group (`--only-integration`, `--all`, `--no-docker`,
  and `--no-build` refine the selection; extra args pass through to pytest).
- Benign and safe suspicious-behavior specimens under [specimens/src](../specimens/src/).
