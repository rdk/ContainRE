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
| `detections.max_severity` | Maximum verdict severity. |
| `verdict.flags` | Verdict flags. |
| `artifacts.count` | Captured artifact count. |
| `artifacts.names` | Captured artifact relative names. |
| `work_files.count` | Files present in the work directory. |
| `work_files.names` | Work-directory relative names. |
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
