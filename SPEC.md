# ContainRE - Specification (v0.1)

> **Contain** + **RE**: a sandbox, execution tracer, and flight recorder for
> potentially dangerous Linux binaries, with an interactive web UI for live and
> post-hoc analysis.

Status: implemented v1 design notes. Scope below is **v1** unless marked *Later*.

---

## 1. One-paragraph summary

ContainRE runs an untrusted **Linux ELF x86-64** binary ("the specimen") inside a
locked-down Docker container with **no network egress by default**, and records a
structured, replayable trace of everything it does - syscalls, network attempts,
file I/O, process/thread activity, and memory. It works as a **flight recorder**
(run it, walk away, analyze later) *and* as a **live analysis harness** (attach a
browser and watch live events, stop runs, checkpoint, and inspect captured memory). A
single **Python control plane** owns the containers, tracers, and storage and
exposes one API used by both a **thin CLI** and an **interactive Svelte webapp**
that can drive many specimens at once.

---

## 2. Goals / Non-goals

**Goals**
- Safely execute and observe dangerous binaries; block network by default.
- Emit **structured** event data (not just text logs), usable online and post-hoc.
- Two tracing depths: always-on **syscall/event** level; opt-in **instruction** level.
- First-class **memory inspection**: snapshots, hexdumps, and checkpoints.
- Reproducible headless runs via a **policy file**, plus CLI/API launch overrides.
- Behavioral **detections** (YARA, IOCs, heuristics) layered on raw facts.
- Drive/observe **multiple concurrent runs** from one webapp.

**Non-goals (v1)**
- Windows PE / non-x86-64 targets (*Later*).
- Multi-user accounts / RBAC / remote-internet exposure (*Later*).
- Reversible/record-replay (rr-style) time-travel debugging (*Later*).
- Fully scored auto-triage and automatic MITRE ATT&CK mapping beyond heuristic
  tags (*Later*). Evidence summaries and assertion reports are in scope.
- Embedded Ghidra/rizin; we export open formats for external tools instead.

---

## 3. Locked design decisions

| Area | Decision |
|---|---|
| Specimen | Linux ELF **x86-64** only (v1) |
| Isolation | **Docker** now, behind a swappable `Runtime` interface (gVisor/Firecracker later) |
| Tracing | **Layered**: L1 syscall/net/file always-on; L2 instruction-level opt-in |
| L2 engine | **ptrace single-step** (faithful default) + **Unicorn** region mode; Frida *Later* |
| Network | **Deny by default** + **simulated internet** sink + pcap; allowlist; TLS MITM optional |
| Memory | Snapshot viewer + **CRIU** checkpoint/restore hooks (no rr replay) |
| Storage | Per-run dir: **JSONL events + SQLite index + binary blobs** |
| Backend | **Python control plane** (uv, FastAPI + uvicorn), REST + WebSocket |
| Frontend | **Svelte 5 + TypeScript**, live/post-hoc dashboard |
| CLI | Thin client of the **same API** as the webapp |
| Deploy | **Single-user, localhost, no auth** (v1) |
| Control | **YAML policy file** + launch-time CLI/API overrides |
| Analysis | Facts + Capstone disasm + **behavioral detections** (YARA/IOC/heuristics; ATT&CK tags optional) |
| Filesystem | Provision args/stdin/env/sample files; capture dropped/modified artifacts; **decoy** files |
| Interop | Standalone; export **open formats** (JSONL, pcap, mem dumps, CRIU images, ELF) |
| Sim internet | Built-in loopback `NetSink` behind a swappable interface |
| Base image | Ubuntu runner image with Python tracer dependencies; ELF facts recorded for analysis/runtime selection |
| Schema | **Versioned** event envelope, **additive-only** within a major; JSON Schemas in `contracts/`; readers tolerate unknown fields |
| Concurrency | **Config cap**; `max_concurrent_runs` defaults from host cores/RAM; excess API launches return 429 |
| CRIU | **Best-effort** DockerRuntime hooks with graceful degrade; region snapshots always work |

---

## 4. Architecture

```
                                   host (single user, localhost)
  ┌───────────────────────────────────────────────────────────────────────────┐
  │  Svelte webapp ──REST/WebSocket──┐                                          │
  │  CLI (thin client) ──────────────┤                                          │
  │                                  ▼                                          │
  │                        ┌───────────────────────┐                           │
  │                        │  Control plane (uv)    │  FastAPI + uvicorn        │
  │                        │  - run orchestrator    │                           │
  │                        │  - Runtime driver      │  ← swappable (Docker v1)  │
  │                        │  - trace ingest/store  │                           │
  │                        │  - policy handling     │                           │
  │                        │  - detection engine    │                           │
  │                        └──────────┬────────────┘                           │
  │        control (unix sock/vsock)  │        run store: runs/<id>/            │
  │                                   ▼                                          │
  │   ┌────────────── container/process tree (per specimen) ────────────────┐    │
  │   │  probe-agent / tracer runner                                        │    │
  │   │   ├─ specimen (ptrace'd child)                                      │    │
  │   │   └─ built-in loopback sink for simulate posture                    │    │
  │   │  streams L1/L2 events, snapshots, pcap reconstruction, detections   │    │
  │   └─────────────────────────────────────────────────────────────────────┘    │
  └───────────────────────────────────────────────────────────────────────────┘
```

**Key structural choice - in-container `probe-agent`.** Each container runs a small
supervisor as PID 1 that launches the specimen under `ptrace` *inside the
container's own namespaces*. This avoids fragile cross-namespace ptrace, keeps the
tracer co-located with its target, and streams structured events + memory reads to
the control plane over a unix socket / vsock. The control plane never ptraces
across the boundary; it orchestrates, ingests, stores, and serves.

**Runtime interface (swappable isolation):**
```python
class Runtime(Protocol):
    def start(self, image, policy) -> RunHandle: ...
    def stop(self, h) -> None: ...
    def checkpoint(self, h) -> SnapshotRef: ...   # CRIU-backed
    def restore(self, ref) -> RunHandle: ...
    def netns(self, h) -> NetNsRef: ...           # for pcap/sink wiring
# v1 impl: DockerRuntime; later: GvisorRuntime, FirecrackerRuntime, ...
```

---

## 5. Tracing model

### L1 - always-on (native speed)
- **Mechanism:** `ptrace` in the probe-agent, with `PTRACE_O_TRACESYSGOOD` +
  seccomp-BPF to select syscalls of interest; per-syscall entry/exit records.
- **Captured:** network syscalls (`socket/connect/bind/send*/recv*`), file I/O
  (`open*/read/write/unlink/rename/…` + content deltas), process/thread lifecycle
  (`clone/execve/exit`), mmap/mprotect (esp. `+x`), signals, ptrace/anti-debug
  attempts, time/random sources.
- **"Step to next I/O":** a first-class stop condition - continue the specimen
  until the next syscall in a chosen class, then halt.
- *Later:* optional **eBPF** layer for lower-overhead, whole-host correlation.

### L2 - opt-in instruction level
- **Default engine - ptrace single-step:** `PTRACE_SINGLESTEP` over a chosen
  window (time-bounded, address-range, or "from here until next I/O"). Records
  register deltas and inferred **memory writes** from decoded write operands.
  Faithful (real syscalls/env), least evadable, reuses the L1 tracer. Slow -
  always scoped to a window.
- **Region mode - Unicorn:** seed an emulator from live memory + regs
  and emulate an **isolated function/unpacker** forward, with syscalls hooked. No
  effect on the live process; ideal for algorithm/unpacking analysis. Diverges
  from real OS behavior by design.
- *Later:* **Frida (Stalker)** as an optional plugin engine.

Every L2 record: `{ip, disasm(Capstone), reg_deltas, mem_writes:[{addr,old,new}]}`.

---

## 6. Memory model

- **Maps:** `/proc/<pid>/maps`-style region metadata captured in snapshots.
- **Viewer:** pick a snapshot and region → hexdump/ASCII.
- **Snapshots:** compressed (zstd) region dumps taken **on demand** or on policy
  triggers (e.g. at each `connect`, on `mmap +x`, every *N* ms). Stored as blobs.
- **CRIU checkpoint/restore:** whole-process checkpoint of the specimen; restore to
  re-run from a saved moment or fork alternate paths. **Best-effort**:
  region snapshots (above) always work; if a CRIU dump fails on a given host/sample
  the run surfaces a clear error and continues without it. *Privilege-sensitive* -
  see §12 host requirements.

---

## 7. Network model

- **Default posture:** Docker runs with `--network none`; LocalRuntime enforces
  egress decisions at the ptrace layer. Real egress is denied unless explicitly
  allowed.
- **Simulated internet:** the built-in loopback **sink** answers HTTP(S) and generic
  TCP so the specimen "talks" and reveals behavior. The `NetSink` interface leaves
  room for INetSim/FakeNet-NG adapters later.
- **Capture:** a reconstructed **pcap** per run from observed socket payloads, plus
  structured connection/HTTP event records correlated to syscalls and PIDs.
- **TLS MITM (optional):** transparent proxy with an injected CA to read payloads;
  off by default (detectable/evadable).
- **Real egress:** only via explicit **allowlist** entries in the policy. Every
  attempt - allowed or blocked - is traced.

---

## 8. Filesystem model

- **Inputs:** specimen receives `args`, `stdin`, `env`, and **sample files** dropped
  into a read-write `/work` mount.
- **Trace:** `open/read/write/unlink/rename` with content deltas for created/modified
  files.
- **Artifacts:** dropped and modified files auto-saved to the run dir (overlay diff +
  live capture).
- **Decoys:** optional **canary** files (fake documents, keys, wallets) planted to
  trip ransomware/stealer behavior; access to a decoy is a high-signal event.

---

## 9. Run storage format (`runs/<run_id>/`)

Mirrors the "**directory is the database**" pattern (read-only for the webapp).
Each run is a self-contained directory under the runs root - default
`~/.containre/runs/` (override with `--runs-root` / `CONTAINRE_RUNS_ROOT`):

```
~/.containre/runs/<run_id>/
  meta.json            # specimen hash, image, policy, start/stop, status, verdicts
  policy.yaml          # exact effective policy (reproducibility)
  events.jsonl         # ordered, append-only structured events (schema-versioned)
  index.sqlite         # seek/filter/query index over events + artifacts
  snapshots/*.zst      # memory region dumps
  checkpoints/*        # CRIU images
  instr/<window>.trace # L2 instruction traces
  net/capture.pcap     # full packet capture
  net/flows.jsonl      # structured connection/DNS/HTTP records
  files/               # captured dropped/modified artifacts + decoy hits
  detections.jsonl     # YARA/IOC/heuristic findings (+ optional ATT&CK tags)
  console.log          # specimen stdout/stderr
```

- **Hot (live) path:** events streamed over WebSocket as they happen.
- **Cold (durable) path:** same events appended to `events.jsonl`; `index.sqlite`
  built incrementally for fast seek/query. Large blobs never inlined into the DB.
- **Event envelope:** `{schema_version, seq, ts_mono, ts_wall?, pid?, tid?, kind, data}`
  where currently emitted `kind ∈ {syscall, net, file, mem, proc, signal, instr, detection}`;
  the v1 schema also reserves `gate` for future live-decision events. `data` holds
  the kind-specific payload. Full JSON Schema:
  [`contracts/events.v1.schema.json`](contracts/events.v1.schema.json).
- **Schema versioning:** every event/meta record carries `schema_version`; changes are
  **additive-only within a major** version, breaking changes bump the major. Formal
  JSON Schemas live in [`contracts/`](contracts/README.md) and readers **tolerate
  unknown fields and enum values** (forward-compatible), so old runs stay readable as
  the format grows.

---

## 10. Policy file (per run, YAML)

```yaml
specimen: { path: ./sample.bin, args: ["--foo"], stdin: ./in.txt, env: {LANG: C} }
limits:   { cpu: 1, mem_mb: 512, pids: 128, wallclock_s: 120, disk_mb: 256 }
network:
  posture: deny            # deny | simulate | allow
  simulate: true           # bring up the fake-internet sink
  mitm: false
  allow: []                # e.g. ["1.2.3.4:443", "example.com:80"]
files:
  work_mount: ./work
  decoys: [canary.docx, wallet.dat]
trace:
  l1: [net, file, proc, mmap, signal]
  snapshot_on: [connect, "mmap+x", exec]
  snapshot_every_ms: 0     # 0 = triggers only
  l2: { mode: off }        # off | singlestep | unicorn ; window: {addr|time|until_io}
detect: { yara: true, iocs: true, heuristics: true, attack_tags: false }
kill_on: [egress_violation, oom, timeout, decoy_write]
```

The CLI and webapp can supply launch-time overrides; the effective policy is
persisted to the run dir for reproducibility.

---

## 11. Control-plane API

**REST**
- `POST /api/runs` (`{binary, net, decoys, timeout}` or `{policy}`) → create/start
- `GET /api/runs` · `GET /api/runs/{id}`
- `POST /api/runs/{id}/stop`
- `POST /api/runs/{id}/checkpoint` · `POST /api/runs/{id}/restore`
- `GET /api/runs/{id}/events?since=seq&kind=…`
- `GET /api/runs/{id}/snapshots` · `GET /api/runs/{id}/memory?snapshot=…&base=…`
- `GET /api/runs/{id}/detections`
- `GET /api/runs/{id}/artifacts` · `GET /api/runs/{id}/artifacts/{name}`
- `GET /api/runs/{id}/pcap`

**WebSocket** `/api/runs/{id}/stream` - live event envelopes and status changes.

**Concurrency / backpressure.** The orchestrator enforces `max_concurrent_runs`
(config; default derived from host CPU count). API launches beyond the cap return
HTTP 429; each active Docker run is still bounded by its own cgroup limits. Status
appears in `GET /api/runs` and per-run WebSocket streams.

---

## 12. Webapp (Svelte 5)

- **Overview:** all runs (live + finished), status, resource meters, verdict badges;
  drive **multiple** specimens concurrently.
- **Run detail - live & post-hoc share one UI**, differing only in whether control
  actions are enabled:
  - **Timeline / event stream** with kind filters.
  - **Memory viewer**: snapshots table → region list → hexdump.
  - **Network/artifact access:** decoded HTTP events, reconstructed pcap download,
    dropped-file downloads.
  - **Instruction trace panel:** L2 single-step/Unicorn events when enabled at launch.
  - **Control actions:** stop active run, best-effort checkpoint/restore.
  - **Detections:** YARA/IOC/heuristic findings, decoy hits, optional ATT&CK tags.
  - **Artifacts:** dropped/modified files, downloads, export bundle.
- **Detections and verdicts:** heuristic/YARA findings, decoy hits, and ATT&CK tags
  where available.

---

## 13. Detection layer

Runs on raw facts (pluggable `Detector` interface):
- **YARA** over memory snapshots and dropped files.
- **IOC extraction:** domains, IPs, URLs, mutexes, file paths, crypto constants.
- **Heuristics:** anti-debug/anti-ptrace, code injection (`ptrace`/`process_vm_writev`
  /`mprotect +x`), persistence, self-deletion, decoy access.
- *Optional:* map findings to **MITRE ATT&CK** technique tags.
- Post-hoc evidence summaries with report assertions over run metrics. Fully
  scored triage remains a later layer.

---

## 14. CLI (thin client of the API)

```
containre run <policy.yaml|binary> [--net deny|simulate|allow] [--l2 …] [--headless]
containre watch <run_id>            # live tail of structured events
containre ls | show <run_id> | summarize <run_id>
containre serve                     # start control plane + webapp
```

Headless `run` = pure flight recorder (policy-driven, reproducible). Everything the
CLI does is an API call, so CLI and webapp behavior are identical.

---

## 15. Security & host requirements

- **Threat model (v1):** untrusted binaries that may be actively malicious but not
  assumed to carry kernel 0-days. Docker + `cap-drop` + no-egress network + resource
  cgroups. **The `Runtime` interface exists so gVisor /
  Firecracker can raise this bar** without touching the rest of the system.
- **Control plane binds `127.0.0.1`; no auth (single-user).** The full-remote-control
  API is powerful - keep it local-only until auth lands.
- **Host needs:** Linux, Python dependencies from `pyproject.toml`, and a compiler
  for the example specimens. Docker is needed for DockerRuntime tests/runs. CRIU
  checkpoint/restore is privilege-sensitive and depends on host Docker support.
  eBPF path (*Later*) needs a recent kernel.
- **Caveats to document:** CRIU-in-Docker is finicky; TLS MITM and single-stepping
  are detectable by anti-analysis samples; decoy/simulated-internet realism is
  best-effort.

---

## 16. Proposed repository layout

```
ContainRE/
  pyproject.toml            # uv-managed; console_scripts: containre
  uv.lock
  README.md
  SPEC.md
  containre/                # Python control plane + CLI (one package)
    api/                    # FastAPI app: REST + WebSocket
    control/                # run orchestrator, verdicts, policy
    runtime/                # Runtime interface + DockerRuntime
    tracer/                 # probe-agent, L1 (ptrace/seccomp), L2 (singlestep, unicorn)
    memory/                 # maps-derived snapshots, hexdump, CRIU
    net/                    # sink (sim internet), pcap, mitm
    store/                  # run dir writer, jsonl, sqlite index, blobs
    detect/                 # yara, iocs, heuristics, attack tags
    cli/                    # thin client over the API
  images/                   # Docker runner image
  webapp/                   # Svelte 5 + Vite dashboard
  contracts/                # event schema, run-dir layout, policy schema (versioned)
  tests/
```

---

## 17. Implemented capability map

1. **Flight recorder core:** DockerRuntime, LocalRuntime, L1 ptrace tracer,
   run-dir store (JSONL+SQLite), deny-by-default network, reconstructed pcap, CLI
   `run`/`ls`/`show`/`watch`.
2. **Live webapp:** FastAPI control plane, WebSocket streaming, run list/detail,
   event timeline, memory view, detections, artifacts, pcap, and checkpoint actions.
3. **Memory:** maps-derived snapshots, hexdump viewer, policy-triggered snapshots,
   and best-effort CRIU checkpoint/restore hooks.
4. **Deep trace:** L2 single-step and Unicorn region mode with Capstone disassembly.
5. **Sim internet + detections:** built-in sink, optional TLS MITM, YARA,
   IOC/heuristics, decoys, and dropped-file artifact capture.

---

## 18. Resolved decisions (were open questions)

1. **Sim internet** - ship a built-in sink behind a swappable `NetSink` interface;
   INetSim or FakeNet-NG can replace it later.
2. **Base image** - use a runner image with the Python probe-agent and tracer
   dependencies; inspect the ELF and record static facts for reproducibility.
   *Later:* bring-your-own image + injected probe-agent as an escape hatch.
3. **Schema versioning** - versioned event envelope, **additive-only within a major**,
   JSON Schemas in `contracts/`, forward-compatible readers (§9).
4. **Concurrency** - `max_concurrent_runs` config cap (default from host cores/RAM);
   excess API launches return a structured 429 rather than starting unbounded work.
5. **CRIU** - best-effort DockerRuntime capability with graceful degrade; region
   snapshots always work, checkpoint failures surface an error and don't abort the run
   (§6, §15).

## 19. Remaining open questions (later milestones)

- When to introduce **auth** and networked/multi-user access (currently localhost-only).
- Second `Runtime` backend priority: **gVisor** vs **Firecracker/Kata**.
- Whether **eBPF** L1 and **Frida** L2 land as plugins, and in which milestone.
- Scored **auto-triage** and automatic **MITRE ATT&CK** mapping beyond heuristic
  tags. Post-hoc evidence reports and assertions already ship; scoring is
  *Later*.
```
