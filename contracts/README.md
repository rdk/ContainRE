# ContainRE contracts

Versioned, machine-readable contracts that the control plane, probe-agent, CLI, and
webapp all agree on. These are the **stable surface**: change them deliberately.

| Contract | File | Governs |
|---|---|---|
| **Run policy** | [`policy.v1.schema.json`](policy.v1.schema.json) | The per-run `policy.yaml` (inputs, limits, network, trace, detect, report assertions, kill rules) |
| **Event stream** | [`events.v1.schema.json`](events.v1.schema.json) | Every record in `events.jsonl` and the live WebSocket stream |
| **Run metadata** | [`meta.v1.schema.json`](meta.v1.schema.json) | The per-run `meta.json` (specimen, status, counts, host) |
| **Run directory** | [SPEC.md §9](../SPEC.md#9-run-storage-format-runsrun_id) | On-disk layout of a run directory (default `~/.containre/runs/<run_id>/`) |

Concrete, valid instances live in [`examples/`](examples/).

## Versioning policy

- Every artifact embeds a **major** version: schemas are named `*.vN.schema.json`;
  event and meta records carry an integer `schema_version` field equal to `N`.
- **Additive-only within a major.** New optional fields and new `enum`/`kind` values
  may be added without a major bump. Readers **MUST ignore unknown fields and tolerate
  unknown enum values** (forward compatibility) rather than reject.
- **Breaking changes** (removing/renaming a field, tightening a type, changing
  semantics) require a new major: add `events.v2.schema.json`, bump `schema_version`,
  and keep the old schema for reading historical runs.
- These schemas are **JSON Schema draft 2020-12**. `additionalProperties` is left open
  by design so additive evolution never breaks old readers.

## Conventions

- **Timestamps.** `ts_mono` is a monotonic clock in **nanoseconds** (int), the ordering
  authority within a run. `ts_wall` is optional Unix wall-clock **nanoseconds** (int).
- **Ordering.** `seq` is a per-run, gap-free, strictly increasing integer starting at 0;
  it is the primary key in `index.sqlite` and the resume cursor for the live stream.
- **Identity.** `run_id` is an opaque, filesystem-safe string. Content-addressed
  artifacts (`artifact_id`, `snapshot_id`, `window_id`) are opaque strings scoped to a run.
- **Addresses/bytes.** Memory addresses and byte values are lowercase hex **strings**
  with a `0x` prefix (e.g. `"0x7ffff7a1c000"`) so 64-bit values survive JSON safely.
- **Sizes/counts** are JSON integers.
