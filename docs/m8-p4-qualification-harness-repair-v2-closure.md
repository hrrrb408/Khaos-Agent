# Khaos P4 Qualification Harness Repair & Benchmark v2 Closure Report

This report covers an offline, uncommitted working-tree repair gate. It does
not reuse the historical real-provider qualification as fresh evidence.

## Repository identity

| Field | Result |
| --- | --- |
| Branch | `codex/m8-coding-evaluation` |
| Exact HEAD | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Working-tree identity before | `NOT_CAPTURED` (not reconstructed retrospectively) |
| Working-tree identity after | `4c213debf805ea722f97c9de940645d48b1a956e4b5b269b63d95e7193d2eb52` |
| Protected report | `docs/local-security-closure-report.md` — metadata unchanged, untracked, unstaged |
| Commit/push/PR/merge | none |

## Scope and credential boundary

```text
Real Provider calls: 0
Real credentials read: 0
Credential session unlocked: NO
GLM-5.3 / GLM-5.3-Flash: NOT RUN
Coding benchmark corpus: NOT RUN
Browser benchmark: NOT RUN
M9: NOT RUN
```

The existing credential architecture was not changed by this gate. All
validation used deterministic fake routers, synthetic secrets, and local
fixtures. No credential CLI, Keychain operation, provider discovery, or
network request was used.

## Historical P4-v1

| Field | Historical value |
| --- | --- |
| Run ID | `m8-qualification-54e131e3e6af42e4b3f14bbfb88e0994` |
| Result | `FAIL` |
| Mechanical cause | `TOOL_BUDGET_EXHAUSTED` |
| Stored failure class | `AGENT_LOOP_FAILURE` |
| Harness integrity | `FAIL` |
| Convergence attribution validity | `INVALID / INCONCLUSIVE` |
| GLM-5.3 model limitation | `UNCONFIRMED` |
| Historical artifact modified | `NO` |

P4-v1 remains historical evidence. It is not rewritten as a model failure and
is not reused for the repaired qualification chain.

## Budget authority audit

| Concern | Authority and terminal semantics |
| --- | --- |
| Model turns | `AgentLoop` / `AgentConfig.max_turns`; existing max-turn terminal semantics remain runtime-owned. |
| Tool calls before | Collector-side `max_tool_calls` could raise into the AgentLoop and collapse the result into a generic failure. |
| Tool calls after | Canonical `ToolBudget` is injected through the evaluation runtime seam into `ToolScheduler`; denial is returned as typed `TOOL_BUDGET_EXHAUSTED`, then propagated by `AgentLoop`. |
| Trace storage | `CodingTraceCollector.max_events` is an observation bound only; overflow records `trace_truncated=true` and increments `dropped_event_count`. |
| Wall-clock timeout | Runner/invoker timeout authority remains the bounded `asyncio.timeout` / scenario timeout path. |
| Benchmark expectation | Scenario limits remain recorded metrics/resource ceilings; P4-v2 correctness does not require a minimum turn or tool count. |
| Collector controls execution | `NO` |

## Typed budget closure

```text
Runtime tool budget: PASS
Typed TOOL_BUDGET_EXHAUSTED: PASS
Normal budget exhaustion collapsed to generic AGENT_LOOP_FAILURE: NO
Collector exception path: REMOVED
```

The runtime budget regression proves that a pre-exhausted canonical budget
still permits the AgentLoop to receive the typed denial and emit a typed
terminal error. The collector no longer enforces its legacy turn/tool values.

## Trace v2

Trace v2 is schema version `2` and retains the legacy fields needed by older
summaries while adding bounded forensic fields.

| Field/contract | Result |
| --- | --- |
| `schema_version` | `PASS` |
| `run_id`, `event_id`, `event_sequence` | `PASS` |
| `turn_id` on model/tool/terminal events | `PASS` |
| Stable `tool_call_id` and result binding | `PASS` |
| Exact `tool_name` | `PASS` |
| Separate `tool_category` | `PASS` |
| Safe argument summary/digest | `PASS` |
| Workspace-relative scope | `PASS` |
| Result count/limit/truncation metadata | `PASS` |
| Safe result identity/digest | `PASS`; raw provider-supplied digest fields are not trusted, and digest input is redacted or type-only. |
| Typed tool error class | `PASS` |
| Pending terminal states | `PASS` (`SUCCESS`, `FAILURE`, `CANCELLED`, `NOT_EXECUTED`, `MISSING_RESULT`) |
| Terminal reason | `PASS` |
| Redaction before persistence/digest | `PASS` |
| Trace capacity overflow | `PASS`; runtime continues with explicit truncation metadata. |
| Summary/event reconciliation | `PASS`; complete traces report `PASS`, mismatches report `OBSERVABILITY_DEFECT`, and truncated traces report `INCOMPLETE`. |

Trace tests cover duplicate streamed model projections, turn reconstruction,
exact tool identity, navigation/search category aggregation, pending and
unbound results, typed failures, result truncation, capacity overflow, and
synthetic secret canaries.

## Tool accounting

```text
tool_calls_by_exact_name: PASS
tool_calls_by_category: PASS
Historical search_files misbucket: FIXED for new Trace v2 observations
Summary/event reconciliation: PASS
```

Historical artifacts are not rewritten. New records preserve exact names such
as `tree_view`, `list_directory`, `file_info`, `search_files`,
`file_search_content`, and `read_file` while separately aggregating categories.

## Qualification evidence

Qualification now has a typed append-only JSONL record (`schema_version: 1`,
`record_type: coding_qualification`) and a derived summary (`qualification_version: 2`).
The record binds the following safe identity fields:

```text
run_id
provider / model / provider_returned_model_id
source HEAD
dirty working-tree identity
suite and scenario version/digest
fixture digest / fixture base revision
user prompt digest
system prompt digest
production tool-schema digest
effective policy digest
execution budgets and timeout
opaque credential_ref identifier
```

```text
Typed JSONL: PASS (deterministic writer/schema tests)
Summary JSON: PASS (derived qualification payload contract)
Schema version: PASS
Run ID binding: PASS
Provider/model binding: PASS
HEAD binding: PASS
Working-tree identity: PASS
Fixture digest: PASS
Prompt digest: PASS
System prompt digest: PASS
Tool-schema digest: PASS
Policy digest: PASS
Budget binding: PASS
Secret-shaped durable fields: rejected/redacted
```

The actual qualification CLI is intentionally not invoked in this gate, so no
live qualification JSONL is claimed.

## P4-v2 benchmark contract

```text
Scenario: p4-readonly-authority
Scenario version: 2
Kind: CODE_REVIEW
Fixture: small synthetic authority/consumer/policy repository with distractor
         source and an oracle-owned hidden directory
Limits: 12 model turns / 24 tool calls / 300 seconds
Natural completion: YES
Minimum turn requirement visible: NO
Minimum tool requirement visible: NO
"do not finish early": REMOVED
Checkpoint prolongation: REMOVED
Termination instruction: CLEAR
Read-only objective: YES
Correctness evaluator: typed required findings + normal completion + no side effects
```

The correctness evaluator checks required authority-definition,
authority-consumer, and enforcement-boundary findings. Turn and tool counts
remain secondary resource metrics, not correctness criteria. The model-facing
fixture does not contain a hidden patch, golden answer, or grading metadata.

## Deterministic P4-v2 acceptance

| Probe | Expected | Result |
| --- | --- | --- |
| Fake Efficient Model | PASS early | `PASS` |
| Fake Normal Model | PASS | `PASS` |
| Fake Over-Explorer | typed budget exhaustion | `TOOL_BUDGET_EXHAUSTED` |
| Fake Wrong Answer | expected failure | `EXPECTED FAIL` |
| Fake Tool Error | typed failure state with preserved call/result identity | `PASS` |
| Early completion accepted | yes | `YES` |
| Collector killed AgentLoop | no | `NO` |
| Trace truncation without runtime failure | pass | `PASS` |
| Hidden oracle directory isolated | pass | `PASS` |

The efficient and normal probes use the production-shaped `RuntimeCodingAgentInvoker`,
`AgentLoop`, read-only ToolScheduler, disposable FixtureManager, and external
`CodingOracle` with deterministic fake model responses. No direct provider-to-
patch shortcut was added.

## Security

```text
Synthetic secret trace canary: PASS
Authorization-shaped canary: PASS
Raw credential persistence in generated artifacts: 0
Output Firewall/security regression: PASS
Credential architecture modified in this gate: NO
Hidden oracle exposed to agent root: NO
Network/real Provider access: 0
Full-suite diagnostic output hygiene: NOT CLEAN (transient inherited environment metadata appeared in one existing failure diagnostic; no value is reproduced or persisted here)
```

The synthetic Trace/JSONL canaries found no raw credential persistence. The
full-suite diagnostic mentioned in the regression section is treated as
transient test output, not as a durable Harness artifact, and no secret value
is reproduced in this report.

The Trace v2 result digest no longer trusts an arbitrary provider-supplied
digest from result metadata. It is derived from redacted safe output metadata,
or from type-only evidence when no redactor is available; a secret is never
used as an identity hash.

## Defect closure

| Defect | Severity | Status | Evidence |
| --- | --- | --- | --- |
| H1 evaluator tool-cap exception escapes AgentLoop | HIGH | `PASS` | Canonical ToolBudget/Scheduler typed denial and AgentLoop regression. |
| H2 trace lacks safe forensic parameters/results/turn IDs | HIGH | `PASS` | Trace v2 fields, pending states, redaction, truncation, and reconciliation tests. |
| H3 qualification identity/JSONL incomplete | HIGH | `PASS` | Typed JSONL record plus HEAD, dirty-tree, fixture, prompt, system, tool, policy, budget, and opaque ref binding. |
| M1 exact tool identities misbucketed | MEDIUM | `PASS` | Exact-name and separate-category metrics. |
| M2 search/result semantics insufficiently observable | MEDIUM | `PASS` | Exact names, safe query/argument digests, result count/limit/truncation metadata. |
| B1 P4 prolongation confound | benchmark defect | `CLOSED` | P4-v2 natural stopping prompt and no visible minimum interaction target. |

No unresolved in-scope deterministic Harness `BLOCKER` or `HIGH` was found
after the repairs. Model weaknesses and future provider/environment failures
remain separate from Harness defects.

## Regression evidence

```text
Targeted Harness / AgentLoop / Trace / JSONL / P4-v2 + security/inventory: PASS (168 passed, 1 skipped)
Security/output-firewall regression: PASS (47 passed, 1 skipped)
Ruff: PASS (canonical host Ruff; virtualenv has no Ruff module)
Pyright touched Harness paths: PASS
Pyright full AgentLoop file: PREEXISTING_DIAGNOSTICS outside this repair
compileall: PASS
git diff --check: PASS
Full Python (initial run): FAIL (5569 passed, 50 skipped, 11 failed)
Go: NOT RUN (untouched)
Rust: NOT RUN (untouched)
```

The final targeted result is the bounded offline gate result above. The one
skipped security test is an existing host/platform skip, not a Provider or
Harness pass claim.

The full Python suite was run once and is not a clean release result. Three
generated-inventory failures caused by the pre-existing dirty working-tree
state were regenerated and their standalone freshness checks passed; the full
suite was not rerun after that regeneration. The remaining eight observed
failures are outside this Harness gate: pre-existing audit import cycles, a
`db=None` lifecycle assumption, a subagent import cycle, and an existing
result-finalizer compatibility assertion. One failing pytest diagnostic also
rendered inherited environment metadata; no value is reproduced or recorded
here, it was not used as a credential artifact, and no Provider or credential
operation was performed.

## Capability state

```text
GLM-5.3 P0-v1: PASS (historical)
GLM-5.3 P1-v1: PASS (historical)
GLM-5.3 P2-v1: PASS (historical)
GLM-5.3 P3-v1: PASS (historical)
GLM-5.3 P4-v1: FAIL / invalid-inconclusive for pure convergence attribution
Fresh qualification under repaired Harness: NOT RUN
Real Coding: NOT EVALUATED
Real Browser: NOT EVALUATED
GLM-5.3 vs GLM-5.3-Flash: NOT RUN
Full Corpus: NOT READY
Production: NOT READY
```

Real Browser classification for this gate:

```text
Real model used: NO
Real browser runtime used: NO
Real app runtime used: NO
Result: NOT RUN / OUT OF SCOPE
```

## Next gate

```text
FRESH GLM-5.3 P0–P4-v2 qualification: READY after this offline gate
Reason: deterministic Harness acceptance and identity/schema closure passed;
        fresh real qualification must restart at P0 and use the current
        working-tree identity.
Full real-provider corpus: NOT READY
```

The next authorized real run must start at P0 and execute P0 → P1 → P2 → P3
→ P4-v2 with a newly captured identity. This report does not authorize that
run.

## Router import-cycle closure follow-up (2026-09-12)

The previously observed production Router import-cycle blocker was repaired in
a separate offline gate by moving the shared `CanonicalWorkspaceId` contract
to the neutral security layer and retaining a planning compatibility
re-export. Cold direct imports, the relevant fresh-process order matrix,
production Router initialization, and qualification bootstrap all pass.

The follow-up made zero real Provider requests, read zero credential material,
and unlocked zero credential sessions. P4-v2 semantics and its frozen fixture
were not changed. The next fresh GLM-5.3 P0–P4-v2 qualification is ready to
start with a new identity; real coding capability and the full corpus remain
unmeasured/not ready.

See the [Router import-cycle closure report](m8-router-import-cycle-closure.md)
for the exact evidence and defect review.

## Final repository state

```text
Protected docs/local-security-closure-report.md: unchanged / untracked / unstaged
Historical P4-v1 artifact: preserved
Current code/docs/tests: uncommitted working-tree changes
Repository publication: not performed
Final: READY TO COMMIT
```

## Qualification observability closure (2026-09-13)

An offline observability gate closed the passive O1-O4 evidence gaps. Typed
CompletionGate status/reason/reached/authority/generation/digest metadata,
final-response parser shape metadata, actual Context Engine selection metadata,
repository bundle counts, and separate wall-clock/monotonic timing are now
covered by deterministic regressions. The change does not alter P4-v2 prompt,
fixture, oracle, budgets, tool admission, AgentLoop behavior, or CompletionGate
authority. Provider calls and credential reads remained zero; the full Python
suite was not green because three pre-existing worktree failures remain. See
the [observability closure report](m8-qualification-observability-closure-2026-09-13.md).
