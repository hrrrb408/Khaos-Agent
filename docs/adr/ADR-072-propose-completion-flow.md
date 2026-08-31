# ADR-072: Coding `PROPOSE_COMPLETION` Flow

- 状态：已定（M7.1.6）
- 日期：2026-08-27
- 范围：Coding-mode AgentLoop turn finalization

## Context

`StopReason.END_TURN` describes the end of one model turn. It does not prove
that the durable coding task satisfies its GoalSpec. M7.1.4 made a
`CompletionDecision` an immutable passive ledger record and M7.1.5 made its
evaluator deterministic, but neither record nor evaluator is allowed to
project task lifecycle state.

## Decision

### 1. END_TURN requests evaluation, not completion

For an active coding task, the structured router stop reason
`StopReason.END_TURN` is converted into the internal control event
`PROPOSE_COMPLETION`. Assistant text is never inspected for words such as
"done" or "completed". Ordinary non-coding turns retain their existing
semantics.

The turn may receive a durable `turn.completed` event while the linked
`CodingTask` remains non-terminal. Turn lifecycle and task lifecycle are
separate domains.

### 2. The controller owns orchestration only

`CompletionProposalController` performs this bounded sequence:

```text
completion.proposed
  -> owner-scoped GoalSpec read
  -> owner-scoped current task snapshot
  -> typed fact provider
  -> CompletionEvaluator
  -> CompletionDecisionRepository.append
  -> completion.evaluated
```

The controller does not implement evaluator rules, mutate cognitive state,
change `TaskStatus`, or grant any runtime authority. The server generates the
decision identity. The append repository rechecks task, owner, GoalSpec,
cognitive snapshot, status, and workspace binding; a changed snapshot returns
a typed stale result and is not retried with stale facts.

### 3. Completion facts are explicit and conservative

The default fact provider returns an empty typed `CompletionFactBundle`.
Therefore M7.1.5 synthesizes missing required declarations as `UNKNOWN` and
normally records `REPLAN`. Assistant prose, confidence, or a positive
verification claim cannot create a satisfied assessment. Test/development
composition may inject an explicit typed provider, but its result remains a
passive evaluator input and not lifecycle authority.

### 4. Durable events are bounded

`completion.proposed` contains task, turn, attempt, and trigger identity.
`completion.evaluated` contains the typed flow status and, when recorded, the
decision identity, digest, sequence, and outcome. These events contain no
private chain-of-thought or raw tool/test logs; evidence remains a bounded
`CompletionEvidenceRef` owned by its source subsystem.

### 5. No cognitive fabrication and no lifecycle projection

M7.1.6 captures the current durable cognitive state/version. It does not
manufacture a path through `UNDERSTANDING`, `IMPLEMENTING`, `VERIFYING`,
`REVIEWING`, or `COMPLETION_CHECK`. `COMPLETE`, `REPLAN`, `BLOCKED`, and
`FAILED` in the appended decision remain passive semantic results. The
Completion Gate in M7.1.7 must later perform fresh authority and stale checks
before any task-status projection.

## Security consequences

The flow adds no tool capability, approval, workspace access, sandbox
authority, execution lease, delegation authority, Memory visibility, or
Trusted Verification status. GoalSpec, typed facts, and CompletionDecision
remain desired-work/evaluation data. The existing Security Runtime continues
to decide which actions are permitted.

## Deferred

- Completion Gate and `TaskStatus` projection
- trusted verification composition
- Planning integration
- Recovery/Replan execution
- model-based goal or completion interpretation
