# ContainRE Documentation

ContainRE is a sandbox, execution tracer, and flight recorder for Linux ELF
x86-64 binaries. It is built for authorized malware analysis and reverse
engineering on systems you control.

Use this folder as the short-form documentation set:

- [Features](features.md) - what ContainRE can observe, contain, and export.
- [Architecture and Tech Stack](architecture.md) - how the control plane,
  runtimes, tracer, sink, storage, API, and web UI fit together.
- [Tutorials](tutorials.md) - practical workflows ordered by difficulty.
- [TLS Plaintext Capture](tls-plaintext-capture.md) - authorized inspection of
  OpenSSL plaintext with `LD_PRELOAD` during controlled ContainRE runs.
- [Offline Service Emulation](offline-service-emulation.md) - infer and replay
  simple HTTP/2 gRPC service behavior with no outside network access.
- [Batch Runs and Helper Services](batch-helper-services.md) - run large
  offline batches with setup/teardown hooks and optional reusable Docker
  containers.
- [Reporting and Assertions](reporting.md) - evidence summaries and reusable
  pass/fail checks for no-egress, output, exit-code, and detection expectations.

For the full design notes, see [SPEC.md](../SPEC.md). For quick commands and
status, see [README.md](../README.md).

## Safety Model

ContainRE has two runtime backends:

- `local` is fast and useful for tests, development, and trusted specimens. It
  uses ptrace interception on the host and is not a safe backend for real malware.
- `docker` runs the specimen in a locked-down container with no real network
  egress by default. Use this backend for untrusted specimens.

The control-plane API is powerful and unauthenticated. Keep it bound to
`127.0.0.1` unless you add your own access controls around it.

## Fast Start

```bash
uv sync
make -C specimens

uv run containre run specimens/bin/netbeacon --net deny
uv run containre ls
uv run containre show <run_id> --events --kind net
```

To launch the web dashboard:

```bash
uv run containre serve
```

Then open `http://127.0.0.1:8787`.

## Dashboard Preview

The dashboard includes a Static tab for symbol queries, caller/callee review,
and a compact call graph around confirmed direct calls:

![ContainRE dashboard Static tab showing a connect query and call graph](assets/static-call-graph.png)
