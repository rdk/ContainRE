# TLS Plaintext Capture With OpenSSL `LD_PRELOAD`

This tutorial shows how to capture plaintext from a TLS client while the target
runs under ContainRE. It is meant for authorized analysis of binaries and
services you control or have permission to inspect.

The technique observes buffers at the OpenSSL API boundary:

- `SSL_write` / `SSL_write_ex`: client plaintext before TLS encryption.
- `SSL_read` / `SSL_read_ex`: server plaintext after TLS decryption.

It does not decrypt packets, recover TLS session keys, bypass authentication, or
modify the remote service.

## Current ContainRE Support

ContainRE can build and inject the OpenSSL shim from policy:

```yaml
instrumentation:
  tls_plaintext:
    enabled: true
    provider: openssl-preload
    mode: observe
    output: null
    max_bytes_per_record: 65536
    replay_file: null
    libssl: null
```

The runtime compiles `tools/tls_plaintext_capture.c` into the work directory,
prepends it to `LD_PRELOAD`, preserves any existing user `LD_PRELOAD`, sets the
capture environment variables, and records metadata that marks the run as using
invasive instrumentation. Summaries expose metrics such as
`instrumentation.tls_plaintext.enabled`,
`instrumentation.tls_plaintext.mode`, and
`instrumentation.tls_plaintext.experimental`.

Two modes are available:

- `observe`: call through to real OpenSSL, while logging `SSL_read` and
  `SSL_write` plaintext. This is invasive because it injects code, but it
  preserves the real TLS connection.
- `replay`: experimental fallback. It fakes OpenSSL handshake/write success and
  returns scripted bytes from `replay_file` through `SSL_read`. By default,
  replay expects a real local TLS/MITM handshake; set `fake_handshake: true`
  only when you explicitly want to bypass that too. Replay can run with no
  outside network, but it is weaker evidence than protocol-faithful network
  emulation because parts of TLS and socket behavior are being simulated inside
  the target process.

Protocol-specific parsing and keyword scanning are still analysis-side tasks.
The generic report records the instrumentation label and work/artifact files;
analysts should hash the plaintext artifact and document protocol-specific
interpretation in their case notes.

## Applicability

This works when the target:

- Is dynamically linked.
- Uses OpenSSL-compatible `SSL_read` / `SSL_write` calls.
- Allows `LD_PRELOAD`.
- Does not use setuid/setgid execution.
- Does not scrub preload-related environment variables before TLS is used.

It may not see traffic from static binaries, non-OpenSSL TLS stacks, QUIC,
kernel TLS, custom crypto, anti-hooking logic, or child processes that clear the
environment.

## Add Decoys

Decoys help test whether the target reads local sensitive-looking files:

```bash
WORK=/tmp/containre-tls-work
mkdir -p "$WORK/home/.ssh" "$WORK/home/.aws" "$WORK/home/Documents"
printf 'CONTAINRE DECOY PRIVATE KEY\n' > "$WORK/home/.ssh/id_rsa"
printf 'CONTAINRE DECOY AWS CREDENTIALS\n' > "$WORK/home/.aws/credentials"
printf 'CONTAINRE DECOY PASSWORD LIST\n' > "$WORK/home/Documents/passwords.txt"
printf 'CONTAINRE DECOY WALLET\n' > "$WORK/wallet.dat"
```

Point `HOME` at `/work/home` in the policy and list these paths under
`files.decoys`.

## Example Policy

Save this as `/tmp/containre-tls-observe.yaml` and adjust the specimen path,
arguments, read-only mounts, and endpoint.

```yaml
schema_version: 1

specimen:
  path: /path/to/specimen
  args: ["--connect", "service.example.internal"]
  env:
    HOME: /work/home
    USER: containre
    LOGNAME: containre

limits:
  wallclock_s: 180
  mem_mb: 2048
  pids: 256

network:
  posture: deny
  allow:
    - "198.51.100.10:443"
  extra_hosts:
    - { host: service.example.internal, ip: 198.51.100.10 }
  docker_network: bridge

files:
  work_mount: /tmp/containre-tls-work
  decoys:
    - home/.ssh/id_rsa
    - home/.aws/credentials
    - home/Documents/passwords.txt
    - wallet.dat
  read_only_mounts:
    - { source: /opt/app, target: /opt/app }

trace:
  l1: [net, file, proc, mmap, signal]

instrumentation:
  tls_plaintext:
    enabled: true
    provider: openssl-preload
    mode: observe
    output: null
    max_bytes_per_record: 65536
    replay_file: null
    # Optional, only for a private OpenSSL path:
    # libssl: /opt/app/lib/libssl.so.3

report:
  assertions:
    - id: only-expected-endpoint
      subject: network.remote_endpoints
      op: contains
      value: "198.51.100.10:443"
      severity: high
    - id: no-decoy-access
      subject: file_events.decoy_count
      op: eq
      value: 0
      severity: critical
```

Use `network.docker_network: host` only for controlled cases where Docker bridge
networking breaks the specific allowlisted service. Host networking is accepted
only with a non-empty allowlist and a posture other than broad `allow`.

## Experimental Replay Mode

Replay mode is for controlled offline exploration when a protocol-specific
NetSink or TLS MITM cannot satisfy the client. It is not equivalent to observing
a real protocol exchange.

Create a replay file containing either hex lines or JSONL records from a prior
capture. JSONL records are filtered to `direction=in`:

```json
{"direction":"in","hex":"000000040000000000"}
{"direction":"in","hex":"000000040100000000"}
```

Then set `mode: replay` and point `replay_file` at the host-side file:

```yaml
network:
  posture: simulate
  docker_network: none

instrumentation:
  tls_plaintext:
    enabled: true
    provider: openssl-preload
    mode: replay
    replay_file: /tmp/replay.jsonl
    fake_handshake: false
    output: null
    max_bytes_per_record: 65536
```

In replay mode the shim:

- uses the real local TLS handshake by default;
- can return success from `SSL_connect` and `SSL_do_handshake` when
  `fake_handshake: true` is explicitly set;
- logs outbound `SSL_write` buffers but does not send them through real TLS;
- returns scripted bytes from `SSL_read` / `SSL_read_ex` in transcript order;
- reports ALPN `h2` for HTTP/2 replay;
- returns EOF when replay bytes are exhausted.

Use replay to see how the target reacts to alternate server replies while all
outside networking remains disabled. Use a protocol-faithful NetSink whenever
you can; it preserves more real behavior.

## Experimental HTTP/2 gRPC Sink

For clients that use gRPC over TLS, prefer the protocol-level sink over OpenSSL
hook replay when you can describe the expected server behavior. It still uses
`network.posture: simulate` and can run with `docker_network: none`, so the
specimen has no real egress. The sink terminates TLS with the MITM CA, parses
HTTP/2 frames, and sends valid gRPC responses using policy-provided protobuf
body bytes.

To infer a first policy fragment from a capture:

```bash
uv run containre infer-h2-grpc-replay /tmp/containre-tls-work/tls_plaintext_capture.log
```

For a low-overhead offline rerun that maps the service hostname to the local
emulator and disables ptrace-based tracing:

```bash
uv run containre infer-h2-grpc-replay /tmp/containre-tls-work/tls_plaintext_capture.log \
  --service-host service.example.internal \
  --service-port 443 \
  --no-trace \
  --assert-no-egress
```

```yaml
network:
  posture: simulate
  mitm: true
  docker_network: none
  sink:
    type: h2-grpc-replay
    unary_methods: ["HealthCheck"]
    streaming_methods: ["Session"]
    unary_response_hex: ""              # empty protobuf message
    stream_initial_response_hex: "2200" # example payload bytes
    stream_response_hex: "1200"         # example payload bytes
    idle_timeout_s: 180
    server_pings: true
```

The method names are byte-substring matches against HTTP/2 header blocks. The
response hex strings are protobuf message bodies only; ContainRE adds the gRPC
compression byte, length prefix, HTTP/2 DATA frames, success headers, and
`grpc-status: 0` trailers. This mode is experimental evidence: it can answer
known protocol paths for offline comparison, but it does not replace a real
service implementation or prove that unmodeled server replies are safe.

## Run And Summarize

```bash
uv run containre run /tmp/containre-tls-observe.yaml \
  --runtime docker \
  --runs-root /tmp/containre-runs
```

Then:

```bash
uv run containre summarize <run_id> \
  --runs-root /tmp/containre-runs \
  --write-report \
  --fail-on-assertions
```

The plaintext log should be in:

```text
/tmp/containre-tls-work/tls_plaintext_capture.log
```

The run metadata and Markdown summary will label the instrumentation mode as
invasive, and replay mode as experimental. Record the run id, policy, endpoint
allowlist, target hash, plaintext artifact path, and plaintext artifact SHA256
in your analysis notes.

## Inspect Captured Plaintext

Count records by direction:

```bash
python3 - <<'PY'
import json
from collections import Counter
from pathlib import Path

path = Path("/tmp/containre-tls-work/tls_plaintext_capture.log")
rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
print(Counter(row["direction"] for row in rows))
print(Counter(row["api"] for row in rows))
print(sum(row["captured"] for row in rows), "captured bytes")
PY
```

Extract printable strings:

```bash
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("/tmp/containre-tls-work/tls_plaintext_capture.log")
for row in map(json.loads, path.read_text().splitlines()):
    data = bytes.fromhex(row["hex"])
    strings = re.findall(rb"[\x20-\x7e]{4,}", data)
    if strings:
        print(row["direction"], row["api"], row["len"])
        for item in strings:
            print(" ", item.decode("utf-8", "replace"))
PY
```

Inspect only server replies:

```bash
python3 - <<'PY'
import json
import re
from pathlib import Path

path = Path("/tmp/containre-tls-work/tls_plaintext_capture.log")
for index, line in enumerate(path.read_text().splitlines(), 1):
    row = json.loads(line)
    if row["direction"] != "in":
        continue
    data = bytes.fromhex(row["hex"])
    strings = [s.decode("utf-8", "replace") for s in re.findall(rb"[\x20-\x7e]{4,}", data)]
    print(index, row["api"], "len", row["len"], "strings", strings)
PY
```

Search for sensitive markers:

```bash
python3 - <<'PY'
import json
from pathlib import Path

needles = [
    "id_rsa", "PRIVATE KEY", ".ssh", ".aws", "credentials",
    "password", "passwd", "token", "bearer", "authorization",
    "cookie", "wallet", "/home", "/work", "/mnt",
]
blob = b"".join(bytes.fromhex(json.loads(line)["hex"])
                for line in Path("/tmp/containre-tls-work/tls_plaintext_capture.log").read_text().splitlines()
                if line.strip())
lower = blob.lower()
for needle in needles:
    print(f"{needle}: {lower.find(needle.lower().encode())}")
PY
```

For HTTP/2 or gRPC, first split the byte stream into HTTP/2 frames. Header
payloads are HPACK-compressed, and gRPC messages are protobuf records prefixed
by a compression byte and four-byte length.

```bash
python3 - <<'PY'
import json
from pathlib import Path

names = {0: "DATA", 1: "HEADERS", 3: "RST_STREAM", 4: "SETTINGS",
         6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE"}
path = Path("/tmp/containre-tls-work/tls_plaintext_capture.log")
for record_no, line in enumerate(path.read_text().splitlines(), 1):
    row = json.loads(line)
    data = bytes.fromhex(row["hex"])
    pos = 0
    while pos + 9 <= len(data):
        length = int.from_bytes(data[pos:pos + 3], "big")
        frame_type = data[pos + 3]
        flags = data[pos + 4]
        stream_id = int.from_bytes(data[pos + 5:pos + 9], "big") & 0x7fffffff
        payload = data[pos + 9:pos + 9 + length]
        if pos + 9 + length > len(data):
            break
        print(record_no, row["direction"], names.get(frame_type, frame_type),
              f"flags=0x{flags:02x}", "stream", stream_id, "len", length,
              "payload", payload.hex())
        pos += 9 + length
PY
```

## Interpreting Server Replies

Server replies are not automatically safe just because they are inbound. Look
for:

- Protocol success or error status.
- Expected response method names, resource names, or feature names.
- Empty or small acknowledgment messages.
- Redirects, second-stage URLs, commands, scripts, shell fragments, file paths,
  encoded payloads, or tasking instructions.

For gRPC specifically, reassuring replies usually look like:

- HTTP/2 `SETTINGS`, `WINDOW_UPDATE`, and `PING` frames.
- `HEADERS` with status success and `application/grpc`.
- `DATA` frames whose protobuf messages match the expected response schema.
- Trailers with successful gRPC status and no error message.

Suspicious replies include commands, unexpected URLs, collection paths, encoded
payloads unrelated to the protocol, or instructions that cause new unplanned
network destinations.

## Evidence Checklist

For each run, record:

- Target path and SHA256.
- ContainRE run id and run directory.
- Exact policy used.
- Endpoint allowlist and observed endpoints.
- Plaintext artifact path and SHA256.
- Counts by direction and API.
- Inbound server-reply summary.
- Outbound client-request summary.
- Decoy file event count.
- Keyword searches and negative results.
- Remaining limitations.

This workflow gives strong evidence for the specific execution that was
observed. It does not prove all possible target inputs, accounts, dates, or
server responses are benign.
