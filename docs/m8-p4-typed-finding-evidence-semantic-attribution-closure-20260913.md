# M8 P4 Typed-Finding Evidence & Semantic Attribution Closure Report

Date: 2026-09-13

This is an offline, passive observability closure. It does not authorize or
perform a Provider request, credential read/unlock, real-agent qualification,
browser run, full corpus run, or M9 work.

## Gate result

Gap A (typed finding evidence): **CLOSED / PASS**.

Gap B (exact Context Engine selection evidence): **CLOSED / PASS**.

Historical GLM-5.3 and GLM-5.3-Flash P4-v2 artifacts remain historical
`FAIL 0/3` evidence. Their exact candidate finding details were not retained;
the reader now exposes `NOT_AVAILABLE_LEGACY_ARTIFACT` rather than inventing an
empty finding list. No historical artifact was overwritten.

Preserved artifact hashes:

- GLM-5.3 JSON: `3b383c664e8ae78dd614e5603801b3c1f4be0f6df5930ab0093ea4356945e34c`
- GLM-5.3 JSONL: `df88a61bd8468a0fc6f1dc3083f0bcbf0556a0a7258c31972b5d5423814ad681`
- GLM-5.3-Flash JSON: `78ccd01aeb39bb79cec2ded5ca8ef0279ea8c5bb9a72b2c427a6e141f4bac590`
- GLM-5.3-Flash JSONL: `e2fa41b8cb567cfeb6f9d65af9697bb548c482d5d7bfd0304e90b9b57b00c7a8`

## M8 P4 Typed-Finding Evidence & Semantic Attribution Closure Report

Branch: `codex/m8-coding-evaluation`

Current base commit: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`

Working tree state: pre-existing dirty worktree preserved; this gate added
uncommitted passive observability code, regression tests, this report, and
refreshed generated inventories. No commit, push, PR update, merge, rebase, or
clean operation was performed.

Working-tree identity (excluding the protected local report and this report):
`b6bf468407b8059d10729b91b33f913228a3cff71da5c9b5e5dec28159b1c2ab`.

Provider: `NOT RUN BY SCOPE`

Model: `NOT RUN BY SCOPE`

Reasoning configuration: `NOT AVAILABLE; no provider request was made`

Credential Authority: `NOT EXERCISED; no credential read or unlock`

Secret Leakage Check: **PASS** for the new durable projections and offline
qualification artifacts. The projection tests use only synthetic canaries;
raw model responses, credentials, authorization data, repository contents, and
hidden oracle data are not persisted.

Provider Smoke: `NOT RUN BY SCOPE` (this gate is offline and explicitly
forbids Provider execution)

Usage Accounting: `UNAVAILABLE / NOT APPLICABLE` — Provider requests: `0`;
credential materializations: `0`.

Provider Failure Mapping: `NOT EXERCISED LIVE`; existing deterministic typed
provider/runtime boundary tests passed.

## Passive implementation

- Added a bounded `ReviewFinding` projection downstream of the existing typed
  parser. It records ordinal, canonical category, safe workspace-relative
  file marker, bounded concepts, per-finding digest, redaction, and truncation
  metadata only.
- Wired the same canonical parsed findings into Trace v2 observability without
  changing parser or semantic evaluator behavior.
- Added a bounded projection of the exact `ModelContext.selection` already
  used by the model. It records ordered selected/evicted items, source channel,
  item kind, safe path/identity/digest markers, symbol/relation/evidence
  counts, token/byte metadata, and truncation/compression flags only.
- Added explicit legacy sentinels and backward-compatible readers.
- Added reconciliation checks for typed parser count, persisted finding count,
  semantic-review submitted count, event/summary consistency, and context
  projection consistency.
- Refreshed the machine-generated production reachability and privileged-spawn
  inventories to match the current worktree.

## Behavior preservation

| Surface | Changed? |
| --- | --- |
| P4 prompt | NO |
| P4 fixture | NO |
| P4 hidden oracle | NO |
| Parser semantics | NO |
| Evaluator/scorer semantics | NO |
| CompletionGate authority | NO |
| AgentLoop behavior | NO |
| Context selection behavior | NO; the exact existing `ModelContext` is observed |
| Budgets and timeouts | NO |
| Tool allowlist/admission | NO |
| Provider/credential path | NO; not exercised |

## Regression evidence

- Typed finding, P4 qualification, metrics, context, redaction, legacy,
  hidden-oracle, and offline semantic near-miss join tests: `74 passed`.
- Router/import/bootstrap/provider/security regression subset:
  `39 passed, 1 skipped`.
- Production reachability freshness: `PASS` (`357` modules, `3046` edges,
  `0` forbidden, `0` unresolved).
- Privileged-spawn inventory freshness: `PASS`.
- Security inventory freshness: `PASS`.
- Ruff on touched implementation/tests: `PASS`.
- Pyright on touched implementation: `0 errors, 0 warnings, 0 informations`.
- Python compile check: `PASS`.
- `git diff --check`: `PASS`.

The complete Python suite was run before the generated-inventory refresh and
reported `5626 passed, 50 skipped, 4 failed`. The two generated-inventory
failures were then resolved by the official generators and their tests passed
individually. Two unrelated pre-existing worktree failures remain:

1. `python/tests/db/test_lifecycle_concurrency_round6.py::test_s17_manager_cache_lock_serializes_eviction` — current `TaskService(db=None)` / supervision constructor contract.
2. `python/tests/tools/test_result_finalizer_boundary.py::test_audit_projection_is_best_effort_and_preserves_error_boundary` — current unrelated `ToolResultFinalizer` error-text contract.

Neither failure is caused by the typed-finding/context projection, and neither
was changed in this gate.

## Per-task report

Task 1: `NOT RUN` — no live provider task was authorized.

Task 2: `NOT RUN` — no live provider task was authorized.

Task 3: `NOT RUN` — no live provider task was authorized.

Task 4: `NOT RUN` — no live provider task was authorized.

Task 5: `NOT RUN` — no live provider/browser task was authorized.

For all five slots: Result `NOT_RUN`; primary classification `NOT_APPLICABLE`;
turns/tokens/tools/edits/verification/repair/CompletionGate `NOT_AVAILABLE`.

Sanity Summary:

- Success: `0 live tasks`
- Partial: `0`
- Failure: `0`
- Timeout: `0`
- Provider Error: `0`
- Environment Blocked: `0`
- Security Failure: `0`

False Completion Attempts: `0 observed; no live model run`

Human Interventions: `0`

Real Browser:

- Real model used: `NO`
- Real browser runtime used: `NO`
- Real app runtime used: `NO`
- Result: `NOT RUN`

## Attribution and security matrix

Finding projection coverage includes zero/single/multiple/max findings,
bounded concept lists, Unicode/control characters, absolute/parent-escape/
Windows/secret-like/hidden paths, duplicate concepts, redaction, truncation,
and count preservation.

Context projection coverage includes ordered selected items, multiple sources,
history/task/tool channels, evicted and compressed items, late items,
truncation/eviction, symbol/secret-like identifiers, unsafe paths, duplicate
evidence, bounded iterators, and hidden-oracle markers.

Synthetic offline semantic near-miss coverage confirms that candidate safe
metadata can be joined to an oracle held only in test memory; no hidden oracle
identifier or expected answer enters a durable artifact.

Harness Defects:

- BLOCKER: `0`
- HIGH: `0`
- MEDIUM: `0`
- LOW: `0`
- INFO: unrelated residual worktree test failures listed above; not attributed
  to this gate.

Harness Fixes Applied:

- Passive typed-finding projection and Trace v2 wiring.
- Passive exact-context-selection projection and snapshot/event wiring.
- Explicit legacy observability sentinel and reader compatibility.
- Deterministic regression matrix and offline join tests.
- Official generated-inventory refresh required by the current worktree.

Model Limitations Observed: `NONE MEASURABLE; no live model run`

Provider Limitations Observed: `NONE MEASURABLE; no live Provider request`

Benchmark Defects: `NONE OBSERVED`

Environment Defects: `NONE OBSERVED IN THIS OFFLINE GATE`

JSONL Validation: **PASS** for typed schema/reader and append-only metadata
contracts; no new real-provider JSONL was generated.

Hidden Oracle Isolation: **PASS** in deterministic negative and offline join
tests.

CompletionGate: unchanged and remains the only completion authority; no
observer field authorizes execution or completion.

## Readiness verdict

Fresh P4-v2 qualification observability readiness: **READY TO ATTEMPT LATER**.
The fresh qualification itself was intentionally not executed.

Full Corpus Readiness: **NOT READY** — the real-provider corpus has not been
run, and the repository still has the two unrelated full-suite failures above.

Current M8 Capability Status: **UNMEASURED / NO NEW CAPABILITY CLAIM**.

Production Readiness: **NOT READY**.

`docs/local-security-closure-report.md`: **UNCHANGED / untracked / unstaged**;
mode `0644`, size `851` bytes, SHA-256
`85dbfe1ee17475154a0f48a6d308750b252aec75f3b67dd4f2e47f06b25597a1`.

Repository state: **NOT READY**. The implementation is uncommitted and the
working tree contains unrelated pre-existing changes and residual failures.

No commit or push was performed.
