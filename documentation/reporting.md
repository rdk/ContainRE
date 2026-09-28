# Reporting And Assertions

ContainRE reports are post-hoc evidence summaries for a completed run directory.
They do not execute specimens and they do not change enforcement. Their job is
to make a run reviewable by humans and checkable by automation.

## Summary Command

```bash
containre summarize RUN_ID --runs-root ~/.containre/runs
containre summarize /path/to/run-dir --json
containre summarize /path/to/run-dir --write-report
```

`--write-report` stores both files in the run directory:

- `report.md` for human review.
- `report.json` for automation and downstream agents.

The report includes lifecycle metadata, verdict flags, key metrics, assertion
results, network observations, detections, artifacts, work files, memory
snapshots, and file-event observations.

## Policy Assertions

Assertions live under `report.assertions` in the run policy. They are evaluated
when the run is summarized and are persisted with the effective policy in
`policy.yaml`, which makes the evidence criteria reproducible.

```yaml
report:
  assertions:
    - id: no-real-egress
      title: No unblocked remote endpoint events
      subject: network.allowed_remote_endpoint_event_count
      op: eq
      value: 0
      severity: critical

    - id: no-result-archives
      title: No archive outputs were captured
      subject: artifacts.names
      op: none_match
      value: ["*.zip", "*.tar", "*.tgz", "*.gz"]
      match: glob
      severity: high
```

Ad hoc assertion files are also supported:

```bash
containre summarize /path/to/run-dir \
  --assertions ./assertions.yaml \
  --fail-on-assertions \
  --write-report
```

`--fail-on-assertions` exits with code `2` if any configured assertion fails.

## Work-File Inventory

The report lists the regular files under `files.work_mount` as `work_files`:
each file's path relative to the inventory `base`, its size, and its SHA-256
for the first 500 files (files over 64 MiB are listed without a hash). `count`
and `total_bytes` cover every file. Symbolic links are never followed, and
neither is anything reached through one.

`report.work_inventory` chooses how much of the work mount is walked:

```yaml
report:
  work_inventory: all                   # default: the whole work mount
  # work_inventory: none                # no walk
  # work_inventory: {subdir: runs/r42}  # only this directory under the work mount
```

| Value | `work_files` |
|---|---|
| `all`, or unset | The whole work mount; `base` is `files.work_mount`. The shape is unchanged from reports without the option. |
| `none` | Nothing is walked. `skipped: policy`, empty `files`, zero `count` and `total_bytes`; `exists` says whether the work mount is a directory. |
| `{subdir: path}` | Only that directory. `base` is the work mount joined with `path`, `subdir` holds the normalized path, and file paths are relative to `base`, so they read the same as in a run that had the directory to itself. `exists` is `false` when the directory is missing or is not a directory. |

A `subdir` must be relative and must not contain a `..` component. Policy
validation rejects anything else before the run starts. Whether it can be
reached without a symbolic link depends on the tree when the report is taken:
if any component of it is a symlink, nothing is walked and `work_files` records
`skipped: invalid` with an `error` naming the link. A malformed value in a
run's persisted `policy.yaml` is handled the same way.

Scope the inventory when several runs share one work mount. A full walk there
lists every run's files, names and hashes included, and its cost grows with the
whole shared tree rather than with the run's own output. Other runs may still
be writing while the report is taken, so the counts and sizes of a shared tree
are a snapshot.

When `work_files.skipped` is set, every assertion whose subject is `work_files`
or starts with `work_files.` reports `error` instead of being evaluated against
the empty inventory. A negative check such as `work_files.names none_match ...`
therefore cannot pass just because nothing was listed, and
`--fail-on-assertions` fails. Under `subdir`, `work_files.*` subjects evaluate
against the scoped inventory. Assertions on other subjects are unaffected.

## Common Subjects

Subjects can reference summary metrics or simple dot paths. Useful metrics:

| Subject | Meaning |
|---|---|
| `status` | Run lifecycle status. |
| `exit_code` | Specimen exit code. |
| `kill_reason` | Reason a killed run was terminated. |
| `duration_s` | Run duration in seconds, when start/stop timestamps exist. |
| `network.remote_endpoint_event_count` | Count of connect/send/recv/accept events with a remote endpoint. |
| `network.allowed_remote_endpoint_event_count` | Remote events that were allowed or not classified as blocked. |
| `network.blocked_remote_endpoint_event_count` | Remote events explicitly blocked by ContainRE. |
| `network.remote_endpoints` | Unique remote endpoint strings. |
| `network.dns_block_count` | Blocked remote events targeting port 53. |
| `detections.count` | Number of detection events. |
| `detections.ids` | Detection identifiers or titles. |
| `detections.max_severity` | Highest severity across the detection events, reconciled with `meta.verdict` (whichever is stronger). |
| `verdict.flags` | Verdict flags. |
| `artifacts.count` | Captured artifact count. |
| `artifacts.names` | Captured artifact relative names. |
| `work_files.count` | Files in the work-file inventory (see `report.work_inventory`). |
| `work_files.names` | Inventory-relative names of the listed work files. |
| `file_events.paths` | File paths observed in file events. |
| `snapshots.count` | Memory snapshot count. |
| `snapshots.ids` | Snapshot identifiers. |
| `static.available` | Whether `static/static.json` exists for the run. |
| `static.symbols.names` | Extracted symbol names. |
| `static.imports.names` | Imported symbol names. |
| `static.functions.names` | Disassembled function names. |
| `static.call_edges` | Confirmed direct call edges extracted from disassembly. |

## Operations

Scalar comparisons: `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `between`, `in`,
`not_in`, `exists`, `not_exists`, `is_empty`, and `is_not_empty`.

Containment checks: `contains`, `not_contains`, `contains_any`, and
`contains_all`.

Pattern matching over strings or lists: `any_match`, `none_match`, and
`all_match`. Pattern assertions use `match: glob` by default. `match: regex` and
`match: exact` are also supported.

Static call-edge checks: `contains_edge`. The expected value is a mapping with
`from`, `to`, and optionally `confidence`. `from` and `to` use the same `match`
modes as pattern assertions.

## Recommended Evidence Gates

No real egress:

```yaml
- id: no-real-egress
  subject: network.allowed_remote_endpoint_event_count
  op: eq
  value: 0
  severity: critical
```

No remote endpoint attempts at all:

```yaml
- id: no-remote-attempts
  subject: network.remote_endpoint_event_count
  op: eq
  value: 0
  severity: high
```

Expected fail-closed behavior:

```yaml
- id: expected-nonzero-exit
  subject: exit_code
  op: ne
  value: 0
  severity: high
```

No captured result artifacts:

```yaml
- id: no-result-artifacts
  subject: artifacts.names
  op: none_match
  value: ["*.csv", "*.json", "*.dat", "*.out", "*.zip"]
  match: glob
  severity: high
```

No suspicious detection flags:

```yaml
- id: no-high-severity
  subject: detections.max_severity
  op: not_in
  value: ["high", "critical"]
  severity: medium
```

Required direct call edge:

```yaml
- id: main-calls-connect
  subject: static.call_edges
  op: contains_edge
  value:
    from: "*main*"
    to: "*connect*"
```

Run `containre static <run_id>` before summarizing if static evidence assertions
are part of the gate.

## Interpretation

Use assertion results as evidence quality checks, not as proof that a specimen is
safe. A passing report means the run satisfied the configured evidence criteria
under the chosen policy, runtime, and environment.

For high-stakes investigations, pair assertions with a written claim matrix:
claim, required evidence, ContainRE metrics/assertions used, result, and
residual uncertainty.
