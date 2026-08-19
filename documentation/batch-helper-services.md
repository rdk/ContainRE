# Batch Runs And Helper Services

Use this pattern when a specimen is an application workflow, not a single short
process: for example a batch driver that prepares inputs, runs several worker
pools, talks to a local helper service, and writes many result files. The goal is
to keep containment and offline service emulation, while avoiding one Docker run
per item.

## Recommended Shape

Prefer one ContainRE run per batch window. The specimen should be a driver script
or binary that:

- reads a batch input file or directory;
- splits work into chunks;
- runs preparation and main processing stages in parallel inside the container;
- writes per-chunk outputs and a manifest;
- exits only when the whole batch window is complete.

This reuses one Docker container for all work inside that batch. It also keeps
application scheduling visible in the driver logs instead of spreading one logical
job across many small ContainRE run directories.

## Local Helper Services

Some applications need a local job server, IPC daemon, cache service, or loopback
service before the main command starts. Put those commands in policy:

```yaml
runtime:
  setup_commands:
    - /opt/app/bin/jobserver start
  teardown_commands:
    - /opt/app/bin/jobserver stop || true
  command_shell: /bin/sh
  command_timeout_s: 30
```

Setup and teardown run inside the same runtime namespace as the specimen. Logs
are written to `setup.log` and `teardown.log` in the run directory. A non-zero
setup command aborts the specimen; teardown failures are logged without replacing
the specimen exit code.

## Reusable Docker Container

For low-overhead offline benchmark runs, a Docker container can be kept alive and
reused across separate ContainRE runs:

```yaml
runtime:
  docker_reuse_container: true
  docker_reuse_key: batch-screen
```

Constraints:

- `trace.tracer` must be `none`;
- stdin is not supported in reuse mode; pass files through the work directory;
- use a stable `files.work_mount` if you want reuse across multiple runs;
- Docker network/mount/limit changes recreate the keyed container;
- stopping a run `docker kill`s the keyed container so the specimen is reliably
  stopped. **Do not run multiple runs on the same `docker_reuse_key`
  concurrently:** stopping (or the wallclock-timeout of) one tears down the
  shared container and therefore every other run sharing that key. Use distinct
  keys for runs you want to stop independently.

The reusable container is named `containre-reuse-<docker_reuse_key>`. Remove it
manually when finished:

```bash
docker rm -f containre-reuse-batch-screen
```

## Device Passthrough (GPUs)

Some batch workloads are not CPU-bound: an MD engine, a trained model, or any
CUDA/ROCm application needs the host's accelerator. Docker's default device
cgroup denies access to hardware, and a bind mount does **not** change that — it
supplies the device inode while access is still refused — so the container must
be given the device explicitly:

```yaml
runtime:
  docker_devices:
    - /dev/nvidiactl
    - /dev/nvidia0
    - /dev/nvidia-uvm
```

Each entry is an absolute `/dev` path, mapped to the same path inside the
container. Nothing else is required: no special image, and no
`nvidia-container-toolkit` — bind-mount the host's user-space driver library
alongside it and the vendor stack resolves normally:

```yaml
files:
  read_only_mounts:
    - { source: /lib/x86_64-linux-gnu/libcuda.so.1, target: /lib/x86_64-linux-gnu/libcuda.so.1 }
    # add libnvidia-ml.so.1 if the workload uses NVML (e.g. via pynvml)
```

This composes with the rest of the containment posture: it works with
`--network none`, all capabilities dropped, `no-new-privileges`, and a non-root
`runtime.docker_user`.

> **It reduces isolation, and ContainRE says so.** Device passthrough grants the
> specimen direct, often DMA-capable hardware access, and the tracer cannot
> observe what happens on the device — so that behaviour is absent from the
> recorded evidence. A `DevicePassthroughWarning` is emitted on every run that
> uses it. Treat it like `network.docker_network: host`: appropriate for trusted
> compute, not for analysing an untrusted binary.

Device entries are part of the reuse container's creation config, so changing
them recreates the keyed container. A container created with GPU access is never
silently reused for a run that asked for none, or vice versa.

## Offline Service Policy

Combine reuse with Docker network isolation and a local service emulator:

```yaml
files:
  work_mount: /analysis/work/batch-screen
  read_only_mounts:
    - { source: /opt/vendor-suite, target: /opt/vendor-suite }

network:
  posture: simulate
  allow: []
  docker_network: none
  extra_hosts:
    - { host: service.example.internal, ip: 127.0.0.1 }
  sink:
    type: h2-grpc-replay
    listen_port: 443
    unary_methods: ["Ping"]
    streaming_methods: ["BeginSession"]
    unary_response_hex: ""
    stream_initial_response_hex: "2200"
    stream_response_hex: "1200"
    idle_timeout_s: 3600
    server_pings: true
    negative_feature_substrings: ["UNKNOWN_FEATURE"]
    negative_grpc_status: "5"
    negative_grpc_message: "feature {feature} is not expected to exist in the server"

trace:
  tracer: none
  l1: []
  snapshot_on: []
  snapshot_every_ms: 0
  l2: { mode: "off", window: {} }
```

In this mode, the no-egress claim comes from Docker `--network none`, an empty
allowlist, and the service hostname resolving to loopback. ContainRE does not
record syscall-level evidence when `trace.tracer: none` is set.

Use `negative_feature_substrings` only after a controlled real-service capture
shows that the service rejects that probe. Returning success for unknown
capability checks can put some clients into a state the real service would never
produce. Reports aggregate these hits in the simulated sink table as negative
features, without requiring full payload capture in routine benchmark runs.

If the application is sensitive to user identity, set the Docker user explicitly:

```yaml
runtime:
  docker_user: "1000:1000"
```

This value is passed to both `docker run` and `docker exec`, including reused
containers.

## Web UI

The dashboard launch form accepts either a binary path or policy JSON. To use the
full batch policy from the UI, paste the JSON form of the policy into the policy
textarea. If a binary path is also supplied, the JSON is treated as an override
for the simple launch controls.

## Benchmarking

Measure three quantities separately:

- application time, from the batch driver's own manifest/logs;
- ContainRE run time, from the run summary `duration_s`;
- Docker/session overhead, from wrapper wall time minus ContainRE duration.

For a rough empty-container baseline:

```bash
/usr/bin/time -f '%e' docker run --rm --network none containre/runner:0.1 /bin/true
```

For a rough reusable-container exec baseline:

```bash
docker exec containre-reuse-batch-screen /bin/true
```

Expected savings are workload-dependent. Reuse removes repeated Docker create
and teardown cost, usually tenths of a second per small run on a warm host. The
larger win is avoiding repeated application helper-service startup, which can be
seconds per tiny run. For large batches the dominant saving usually comes from
running preparation and main work in parallel inside one driver, not from Docker
reuse itself.

## Operational Notes

Do not run multiple ContainRE runs with the same reuse key at the same time when
they bind the same loopback service port or share mutable helper-service state.
Put parallelism inside the batch driver instead, or use distinct reuse keys and
ports per run.

Use full ptrace mode for discovery and suspicious-behavior analysis. Use no-trace
reuse only after the service protocol and output behavior are understood and the
goal is throughput or benchmark comparison.
