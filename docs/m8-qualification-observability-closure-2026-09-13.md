# Khaos M8 Qualification Observability Closure Report

This gate closes the passive observability work required for M8 qualification
diagnosis. It is an offline gate. It does not qualify a Provider or a model.

## Scope and execution boundary

```text
Provider requests: 0
Credential reads/unlocks: 0
Credential writes: 0
P0-P4 qualification: NOT RUN
Real-agent coding tasks: NOT RUN
Browser/full-stack task: NOT RUN
Full benchmark corpus: NOT RUN
M9: NOT RUN
Commits/pushes/PR updates: 0
```

No Provider adapter, credential backend, network path, prompt, decision policy,
tool admission rule, verification authority, or CompletionGate authority was
changed or invoked by this gate. Validation used deterministic local fixtures,
fake messages, and offline parser/trace paths only.

## Repository identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Current HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before this gate | `923caac9ff764425d8d5cab59c3ad3d7b5674db44a700fe55b1a9da5d7986b01` |
| Working-tree identity after implementation | `ea0a821686103516b1acfe6facd187bf20680a10fc82dd9154fdd5117c20ca26` |
| Identity exclusion | `docs/local-security-closure-report.md` and this report |
| Protected report | untracked, unchanged, unstaged |
| Publication | no commit, push, PR, merge, rebase, or force-push |

The repository already contained unrelated dirty changes and prior evaluation
artifacts. They were preserved; no reset, checkout, clean, or overwrite was
performed.

## Observability closure

### O1 — CompletionGate result observability: PASS

`CodingTraceCollector` now records a bounded, typed completion projection for
proposal and gate events:

```text
proposal_reached
proposal_status
gate_reached
gate_status
gate_reason_code
gate_authority
gate_generation
gate_evidence_digest
decision_digest
model_finalized
```

The authority label is emitted only for a `completion_gated` event and is the
literal `CompletionGate`. Statuses such as `COMPLETED`, `NOT_COMPLETE`,
`REJECTED`, `STALE`, `AUTHORITY_INSUFFICIENT`, and `ERROR` are preserved as
typed status values. Missing evidence remains `null`; no synthetic evidence is
invented. Event order and summary reconciliation remain checked separately.

### O2 — Final response parsing observability: PASS

The runtime adapter records final-response metadata without retaining the raw
answer:

```text
observed / present / byte_count
format / safe_digest / digest_version
parse_attempted
json_decode_status
schema_validation_status
typed_parse_status
typed_finding_count / finding_field_count / unknown_field_count
all_required_fields_present / parse_error_code / truncated
```

Response content is transient. When the runtime redactor is available, the
digest is computed from redacted content; otherwise only metadata is digested.
The parser distinguishes empty, non-JSON, fenced JSON, plain JSON, multiple
JSON values, truncated output, schema failure, and typed finding failure.
Raw answer text and parser exception text are not placed in the trace or
qualification result.

### O3 — Repository Intelligence and Context Engine observability: PASS

The existing production Context Engine boundary now exposes only bounded typed
selection metadata:

```text
context_selection_digest
context_digest / requirements_digest
selected_count / evicted_count / compressed_count / truncated_count
selected_repository_paths
automatic_repo_items_selected
tool_acquired_items_selected
non_repository_items_selected
cache_hit / partial
```

Repository context contributes bundle digest, document/symbol/evidence counts,
safe structure paths, truncation reasons, and generation identifiers. Aggregate
Repo Intelligence and Context Engine counters remain available through their
existing snapshots. Paths are normalized to workspace-relative markers; unsafe
absolute, external, or parent-reference paths are not persisted as host paths.

### O4 — Timing observability: PASS

Qualification now captures `started_at` once at run entry and `finished_at` at
terminal payload construction. Elapsed durations continue to use monotonic
clocks. Start and finish are no longer generated from the same timestamp.

## Schema and historical compatibility

```text
Trace schema: v2 (unchanged)
Observability schema: v1
Qualification JSONL record schema: v1, optional observability_schema_version
Historical JSONL read: PASS
Historical artifact rewrite: NO
Historical digest change: NO
```

The typed `CodingMetrics`, `CodingTraceEvent`, and qualification reader reject
unsupported observability shapes and credential-shaped fields. Existing V1
qualification records without `observability_schema_version` remain readable;
the actual historical record at `/tmp/khaos-glm53-p0-p4-v2.AS0MxP/qualification.jsonl`
was read successfully as a legacy record.

Historical artifact checksums remain:

```text
qualification.json  18b0e504dc720083307b1f4c716ee4daed6f0cd88ac637f134cd8fe26f700c3d
qualification.jsonl c767cdd9cd60dcf871d47efaba5f61d6090eb8fc4f3679f49e9c2bee9c70aeab
```

## Deterministic validation

| Check | Result |
| --- | --- |
| Observability metrics, parser, qualification JSONL tests | `49 passed` |
| Context Engine, evaluation Runner, runtime adapter tests | `33 passed` |
| Python compile checks for changed modules | `PASS` |
| `git diff --check` excluding protected report | `PASS` |
| Targeted Pyright for changed observability modules | `0 errors, 0 warnings` |
| Secret canary / raw-response exclusion tests | `PASS` |
| CompletionGate accepted/rejected/stale/authority/error/not-reached matrix | `PASS` |
| Hidden-oracle fixture isolation | `PASS` |
| Historical qualification record compatibility | `PASS` |

The full offline Python suite completed with:

```text
5604 passed, 50 skipped, 3 failed
```

The three failures were reproduced individually and are outside the
observability changes in this gate:

1. `test_s17_manager_cache_lock_serializes_eviction` constructs
   `TaskService(db=None)` while the existing `TaskSupervisionService` contract
   requires a database or repository.
2. `test_privileged_spawn_inventory_is_current` reports the already-modified
   generated inventory as stale relative to the current dirty worktree.
3. `test_audit_projection_is_best_effort_and_preserves_error_boundary` expects
   the pre-existing finalizer behavior to return the exception text, while the
   current dirty implementation returns the exception type without a redactor.

None of these failures was altered or masked here. The first two relevant
source/artifact areas and the finalizer are pre-existing worktree changes; no
observability regression was reproduced. The full suite is therefore not
reported as green.

## Security and authority review

```text
Raw credentials in trace/result artifacts: 0
Provider request/response bodies persisted: 0
Credential authority bypass: NO
Workspace/tool/verification/CompletionGate authority changes: NO
Hidden oracle exposed: NO
Model prompt or evaluation semantic changes: NO
Observer failure can stop AgentLoop: NO
Protected report mutation: NO
```

The observer is best effort at the AgentLoop boundary. A rejected observation
is represented by bounded observer metadata and cannot authorize edits,
verification, completion, or recovery.

## Defect review

```text
BLOCKER Harness defects: 0
HIGH Harness defects: 0
MEDIUM Harness defects: 0
LOW Harness defects: 0
INFO: 3 pre-existing full-suite failures listed above
```

No genuine generalizable BLOCKER or HIGH Harness defect was found in this
offline observability gate, so no unrelated lifecycle, inventory, or finalizer
fix was applied. The only fixes applied were passive telemetry fields,
schema-compatible readers, parser-shape metadata, timing capture, and their
deterministic regression tests.

## Final verdict

```text
Observability Closure: PASS (offline)
Provider Integration: NOT ASSESSED — zero Provider calls by gate design
Real Agent Capability: UNMEASURED
Real Browser Capability: UNMEASURED
Full Corpus Readiness: NOT READY
Current M8 Capability Status: UNMEASURED
Production Readiness: NOT READY
```

`docs/local-security-closure-report.md`: unchanged, untracked, unstaged.

Repository state: `NOT READY` for a green release closure. No commit or push
was performed. The next authorized phase, if requested, must separately run
the Provider smoke and then the bounded real-provider sanity gate; this report
does not provide Provider or model-capability evidence.
