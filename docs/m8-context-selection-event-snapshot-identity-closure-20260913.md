# Khaos — M8 Context Selection Event/Snapshot Identity Closure Report

## Gate result

- Gate: M8 Context Selection Event/Snapshot Identity Closure
- Date: 2026-09-13 (Asia/Shanghai)
- Branch: `codex/m8-coding-evaluation`
- Current base commit: `3c1095ff69b1a5d800d96eb61e8b88a47fceca14`
- Working-tree identity (protected report and this report excluded): `7b7018f39cfde9bf6994645c28f12a27251248c4a4a5a1798ec44bafd5b65a59`
- Working tree: dirty before and after this gate; unrelated user changes preserved
- Commit/push/PR: none

This gate is an offline observability and attribution closure. It does not
authorize a Provider request, credential unlock, real-agent qualification,
browser run, full corpus run, or M9 work.

## Scope and historical boundary

The defect under review was that Context Engine selection events and the final
context metrics snapshot had no shared invocation identity. Reconciliation
could therefore use the last retained event position as a proxy for the final
selection. A rebalance, cache reuse, child-context build, or retained-event
boundary could make the attribution ambiguous or incorrect.

The historical GLM-5.3-Flash qualification artifacts remain unchanged and
invalidated. The historical record remains `HARNESS_INVALIDATED`, with semantic
attribution `INCONCLUSIVE`; it is not reclassified by this gate.

## Implemented contract

The production-shaped Context Engine now attaches a typed
`ContextSelectionIdentity` to every effective context build. The identity has
bounded, validated fields:

- run-local `selection_id`
- positive monotonic `selection_sequence`
- closed `selection_reason` vocabulary: `BUILD`, `INITIAL_BUILD`,
  `REBALANCE`, and `CHILD_CONTEXT`
- 64-character lower-case `selection_digest` for the safe selection
  projection

The invocation identity is deliberately separate from the selection-content
digest. Reusing the same effective content receives a new lifecycle identity
while retaining the same content digest. The identity contains no prompt,
repository contents, credentials, authorization data, or host path.

Context Engine metrics now expose the final identity, initial identity,
selection count, rebalance count, and a bounded identity-only history of at
most 128 entries. Cache hits and real `rebalance_messages()` calls are
recorded as effective lifecycle events; selection behavior itself was not
changed.

`AgentLoop.bind_observability_sink()` connects the Context Engine's passive
observer to the existing evaluation trace. The callback is invoked after the
immutable result exists and cannot participate in tool admission, execution,
approval, verification, repair, or CompletionGate authority. Observer errors
are non-fatal to the agent loop.

`CodingTraceCollector` now records the exact event identity and the explicit
final snapshot pointer. Reconciliation joins by `selection_id`, then checks
sequence, reason, content digest, identity digest, counts, detailed projection
metadata, duplicate IDs, ordering, and bounded history. Missing legacy IDs are
reported as `LEGACY_NO_SELECTION_ID`; they are never inferred from event
position. Trace truncation remains fail-closed/incomplete rather than being
treated as a successful reconciliation.

## Offline verification

The following checks passed:

| Check | Result |
| --- | --- |
| Context identity regression plus Context Engine, metrics, and typed-finding tests | `58 passed` |
| Evaluation suite (`python/tests/evaluation`) | `185 passed` |
| Agent/runtime/runner regression subset | `35 passed` |
| Production-shaped runtime identity assertions | `12 passed` |
| Ruff on changed Context Engine, AgentLoop, metrics, and regression tests | `PASS` |
| Targeted Pyright on identity contract/service/metrics/tests | `0 errors, 0 warnings, 0 informations` |
| Scoped Python source/test compilation | `PASS` |
| `git diff --check` | `PASS` |
| Typed JSONL/schema and hidden-oracle separation coverage in evaluation tests | `PASS` |

The full Python suite was also allowed to reach a terminal result:

```text
5635 passed, 50 skipped, 3 failed
```

The three stable failures are outside this gate's changed authority chain and
were not modified:

1. `test_s17_manager_cache_lock_serializes_eviction`: the existing dirty-tree
   `TaskService(db=None)` path now rejects a missing database in
   `TaskSupervisionService`.
2. `test_generated_inventory_is_fresh_and_fail_closed`: the existing generated
   production-reachability artifact is stale relative to the current dirty
   worktree graph (`--check` reports stale inventory).
3. `test_audit_projection_is_best_effort_and_preserves_error_boundary`: the
   existing security-hardening behavior returns the typed exception name while
   the older test expects the original exception text.

None of these failures imports or exercises the Context Selection identity
implementation. They remain recorded as worktree baseline failures rather
than being hidden or repaired opportunistically.

A full `compileall python` scan also encounters the repository's deliberate
bad-syntax fixture `python/tests/fixtures/intelligence/syntax_error.py`;
scoped compilation of production sources and the changed tests passed.

## Defect review

| Defect | Reproduction | Severity | Affected subsystem | Generalizable | Security impact | Status |
| --- | --- | --- | --- | --- | --- | --- |
| Final context snapshot was reconciled against the last event by position instead of a shared selection identity | Emit an initial selection followed by rebalance/cache/retained events, then compare the final snapshot | `HIGH` | Context Engine observability, Trace v2 metrics reconciliation | Yes | No authority bypass; incorrect attribution could corrupt evaluation evidence | Fixed |
| Legacy context records have no invocation identity | Reconcile a legacy event/snapshot without `selection_id` | `INFO` | Backward-compatible metrics reader | N/A | None | Explicit `LEGACY_NO_SELECTION_ID`; no inference |
| Current dirty worktree has unrelated full-suite failures | Re-run the three exact node IDs listed above | `INFO` for this gate | Supervision, generated inventory, tool result finalizer | No | None established for this gate | Preserved and reported |

The `HIGH` defect fix has deterministic regression coverage in
`python/tests/evaluation/test_context_selection_identity.py`, including
positive lifecycle, same-digest/different-ID behavior, duplicate IDs,
out-of-order sequences, missing final event/ID, digest and count tampering,
legacy compatibility, and snapshot-without-identity cases.

## Security and authority review

- Provider requests: `0`
- Credential reads/unlocks: `0`
- Credential material in trace/report: `0`
- Raw model output, repository content, prompt, oracle, and authorization data
  are not persisted by the new identity projection.
- The observer is passive and bounded; it does not authorize execution or
  completion.
- CompletionGate remains the completion authority; the new fields are
  diagnostic/evaluation evidence only.
- Hidden oracle separation: `PASS` under the existing deterministic
  evaluation tests.
- Network: not used by this gate.
- Browser: not used by this gate.

## Required capability state

- Provider integration: `NOT EXERCISED` (intentionally offline)
- Real provider smoke: `NOT RUN` (not authorized by this gate)
- Real coding capability: `UNMEASURED`
- Real browser capability: `UNMEASURED`
- Context selection event/snapshot reconciliation: `PASS`
- Full corpus readiness: `NOT READY`
- Production readiness: `NOT READY`
- M9: not started

This gate supplies an observability prerequisite for a later fresh
GLM-5.3-Flash qualification. It is not a model-capability result and makes
no competitive claim.

## Repository preservation and delivery state

`docs/local-security-closure-report.md` remains untracked, unchanged,
unstaged, and untouched. Its pre-existing metadata invariant remains
`mode=0644`, `size=851` bytes, `mtime=1787640581`; its content was not read or
hashed by this gate.

The new report and the identity implementation/tests are uncommitted. Because
the worktree contains unrelated user changes and three full-suite baseline
failures, the delivery state is:

```text
Repository state: NOT READY
Commit/push: not performed
```
