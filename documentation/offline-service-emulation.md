# Offline Service Emulation

This workflow is for authorized analysis of a binary that needs a remote service
before it reveals useful behavior. The goal is to run a real-service baseline
once under narrow controls, infer enough protocol behavior, then rerun the binary
with no outside network access.

The current automated path targets gRPC over TLS/HTTP2. It is experimental, but
it is stronger evidence than OpenSSL hook replay because the specimen still uses
its real TLS, ALPN, HTTP/2, and gRPC implementation. Only the remote service is
replaced by ContainRE's local simulated sink.

## When To Use It

Use this when:

- the endpoint is known and you are authorized to contact it;
- the real run can be constrained with `network.allow`;
- the client uses dynamically linked OpenSSL for plaintext capture;
- the protocol is HTTP/2 gRPC with simple success or acknowledgment responses;
- you can compare deterministic or normalized outputs between real and offline
  runs.

Do not treat this as proof that every future server response is benign. It proves
only that the modeled response path was sufficient for the tested behavior.

## Step 1: Capture A Controlled Real Exchange

Run the specimen with a narrow allowlist and OpenSSL plaintext observation.

```yaml
network:
  posture: deny
  allow:
    - "198.51.100.10:443"
  docker_network: bridge

instrumentation:
  tls_plaintext:
    enabled: true
    provider: openssl-preload
    mode: observe
    max_bytes_per_record: 65536
```

Add report assertions for the expected endpoint and decoys:

```yaml
report:
  assertions:
    - id: only-expected-endpoint
      subject: network.remote_endpoints
      op: eq
      value: ["198.51.100.10:443"]
      severity: critical
    - id: no-decoy-access
      subject: file_events.decoy_count
      op: eq
      value: 0
      severity: critical
```

After the run, keep the generated `tls_plaintext_capture.log`.

## Step 2: Infer The Offline gRPC Sink

Use the capture to generate a policy fragment:

```bash
uv run containre infer-h2-grpc-replay /path/to/tls_plaintext_capture.log
```

For low-overhead offline reruns where ptrace tracing is intentionally disabled,
include the original service endpoint:

```bash
uv run containre infer-h2-grpc-replay /path/to/tls_plaintext_capture.log \
  --service-host service.example.internal \
  --service-port 443 \
  --no-trace \
  --assert-no-egress
```

The command emits YAML like:

```yaml
network:
  posture: simulate
  mitm: true
  docker_network: none
  sink:
    type: h2-grpc-replay
    unary_methods:
      - HealthCheck
    streaming_methods:
      - Session
    unary_response_hex: ''
    stream_initial_response_hex: '2200'
    stream_response_hex: '1200'
    idle_timeout_s: 180
    server_pings: true
```

For machine-readable review:

```bash
uv run containre infer-h2-grpc-replay /path/to/tls_plaintext_capture.log --json
```

Review the inferred methods and response bodies before using the fragment. The
hex strings are protobuf message bodies; ContainRE adds gRPC framing, HTTP/2
DATA frames, success headers, and OK trailers.

If the real service rejected a probe for an unknown feature, product, or
capability, model that explicitly instead of returning success for every unary
request. Add bounded payload recording to a diagnostic offline run, identify the
stable byte-substring in the request body, and configure a gRPC error response:

```yaml
network:
  sink:
    type: h2-grpc-replay
    negative_feature_substrings: ["UNKNOWN_FEATURE"]
    negative_grpc_status: "5"
    negative_grpc_message: "feature {feature} is not expected to exist in the server"
```

The sink matches these substrings in inbound gRPC DATA payloads and sends normal
HTTP/2/gRPC framing with the configured non-zero `grpc-status`. Reports aggregate
matches as `grpc_negative_features`, so routine runs can prove the negative path
was exercised without retaining full request payloads.

## Step 3: Rerun Offline

Use the inferred fragment in a second policy. Keep Docker networking disabled
and the real allowlist empty:

```yaml
network:
  posture: simulate
  mitm: true
  docker_network: none
  allow: []
  sink:
    type: h2-grpc-replay
    unary_methods: ["HealthCheck"]
    streaming_methods: ["Session"]
    unary_response_hex: ""
    stream_initial_response_hex: "2200"
    stream_response_hex: "1200"
    idle_timeout_s: 180
    server_pings: true
    negative_feature_substrings: ["UNKNOWN_FEATURE"]
    negative_grpc_status: "5"
    negative_grpc_message: "feature {feature} is not expected to exist in the server"

report:
  assertions:
    - id: no-real-allowed-egress
      subject: network.real_allowed_remote_endpoint_event_count
      op: eq
      value: 0
      severity: critical
    - id: no-decoy-access
      subject: file_events.decoy_count
      op: eq
      value: 0
      severity: critical
```

Run and summarize:

```bash
uv run containre run offline-policy.yaml --runtime docker --json
uv run containre summarize <run-dir> --write-report --fail-on-assertions
```

## Low-Overhead Benchmark Mode

Use this mode only after the offline service behavior is understood and the goal
is to measure application/runtime overhead. It disables ptrace and related
analysis features while keeping Docker isolation and the local service emulator:

```yaml
network:
  posture: simulate
  mitm: true
  docker_network: none
  allow: []
  extra_hosts:
    - { host: service.example.internal, ip: 127.0.0.1 }
  sink:
    type: h2-grpc-replay
    listen_port: 443
    unary_methods: ["HealthCheck"]
    streaming_methods: ["Session"]
    unary_response_hex: ""
    stream_initial_response_hex: "2200"
    stream_response_hex: "1200"
    idle_timeout_s: 180
    server_pings: true

trace:
  tracer: none
  l1: []
  snapshot_on: []
  snapshot_every_ms: 0
  l2: { mode: off, window: {} }

detect:
  yara: false
  iocs: false
  heuristics: false
  attack_tags: false
  yara_rules: []
```

When diagnosing a replay mismatch, optionally record bounded request protobuf
previews from incoming gRPC DATA frames:

```yaml
network:
  sink:
    type: h2-grpc-replay
    record_payloads: true
    payload_preview_bytes: 64
    payload_record_limit: 32
```

This adds `grpc.payloads` to the sink interaction event with the method, stream
id, message length, compressed flag, and a short hex prefix. It is off by
default to avoid storing potentially sensitive request bodies in routine
reports.

In this mode ContainRE does not record syscall-level connect, file, process, or
snapshot evidence. The no-egress claim rests on Docker `--network none`, an empty
allowlist, and the service hostname resolving to loopback where the in-container
sink listens. Reports still show sink interactions and assertions, but they are
not a replacement for full tracing when discovering unknown behavior.

If the application needs local helper services, start them inside the same
isolated container namespace with `runtime.setup_commands`, or use a batch
driver wrapper when the application needs custom orchestration. For repeated
low-overhead runs, `runtime.docker_reuse_container` can keep a keyed no-trace
Docker container alive. See [Batch Runs and Helper Services](batch-helper-services.md).

## Step 4: Interpret The Evidence

For a no-outside-contact claim, check:

- `network.docker_network` was `none`;
- `network.allow` was empty;
- `network.real_allowed_remote_endpoint_event_count` is `0`;
- the report assertion `no-real-allowed-egress` passed;
- in ptrace mode, any remote endpoint rows are `decision=simulated`, not
  `decision=allow`;
- the "Simulated Sink Interactions" section lists the gRPC methods handled by
  the local sink;
- decoy access stayed at `0`;
- outputs match the real baseline exactly or with documented normalization.

For `trace.tracer: none` runs, expect no syscall-level remote endpoint rows.
Confirm the Docker/network policy instead: `docker_network: none`, empty
allowlist, loopback host mapping, and fixed sink `listen_port`.

The generic `Allowed/unblocked remote events` line includes simulated sink
traffic. Do not use that line alone to decide whether real egress occurred.

## Current Limitations

- Method matching is byte-substring based on HTTP/2 header blocks.
- The sink currently has one unary response template and one streaming response
  template for all configured methods.
- It does not decode protobuf schemas. It can return configured non-zero gRPC
  statuses for request payload substrings, but that is still a byte-substring
  rule, not schema-aware protocol logic.
- Request payload previews are bounded hex prefixes; they are for comparing
  message shape, not semantic protobuf decoding.
- It is intended for offline A/B testing, not as a full replacement for a real
  service implementation.

Good follow-up improvements are per-method response templates, optional HPACK
decoding, protobuf schema plugins, optional decoded request/response capture
using user-supplied schemas, Docker user controls, and a first-class A/B command
that runs the real controlled baseline and offline rerun as one workflow.
