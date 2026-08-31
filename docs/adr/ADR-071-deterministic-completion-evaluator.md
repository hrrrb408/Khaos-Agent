# ADR-071: Deterministic CompletionEvaluator

- 状态：已定（M7.1.5）
- 日期：2026-08-26
- 范围：Agent control-plane semantic completion evaluation

## Context

M7.1.4 established `CompletionDecision` as an immutable, append-only record of one
evaluation snapshot.  A decision still needs a deterministic producer, but that producer must
not become a lifecycle authority, a model judge, or a verification/security authority.

## Decision

### 1. Evaluator, Decision, and Gate are separate

`CompletionEvaluator` consumes typed structured facts and returns one
`CompletionDecision`. `CompletionDecision` records the result and owns its canonical digest;
it does not prove completion or change `TaskStatus`. The later Completion Gate owns stale
checks, authority checks, and any lifecycle projection. The M7.1.6 controller supplies the
separate `PROPOSE_COMPLETION`/END_TURN orchestration described by ADR-072.

### 2. GoalSpec owns required semantics

The evaluator reads `required` from the bound `GoalSpec` declarations.  Assessments carry only
their declaration ID, snapshot status, and typed evidence references; a caller cannot supply a
second `required` flag.  An assessment ID not present in the GoalSpec is malformed input and
raises `CompletionEvaluationInputError`.

### 3. Missing required facts are UNKNOWN

Every missing required requirement or acceptance criterion is materialized as an
`UNKNOWN` assessment with no invented evidence and receives a deterministic typed issue.
Missing optional declarations remain omitted and do not block completion.  Optional
`UNSATISFIED`/`UNKNOWN` assessments may be retained, but do not by themselves produce a
completion-blocking issue.

### 4. External constraints are negative-only

`CompletionConstraintCode` contains only `PLAN_INCOMPLETE`, `VERIFICATION_MISSING`,
`VERIFICATION_FAILED`, `EXTERNAL_BLOCKER`, and `UNRECOVERABLE_FAILURE`.  Each constraint maps
to a fixed `CompletionIssueCode` and bounded deterministic summary.  There are no positive
codes such as `VERIFICATION_PASSED`, `TRUSTED`, or `CAN_COMPLETE`.  An `EvidenceRef`, including
one with kind `VERIFICATION_RUN`, remains a reference and never implies trusted or authoritative
evidence.

### 5. Outcome precedence is closed and deterministic

The evaluator retains every generated issue and applies one precedence order:

```text
FAILED > BLOCKED > REPLAN > COMPLETE
```

`FAILED` is selected for an unrecoverable-failure constraint; otherwise `BLOCKED` is selected
for an external blocker; otherwise `REPLAN` is selected for required unsatisfied/unknown facts
or replan constraints; only the absence of those conditions yields `COMPLETE`.

`COMPLETE` means only that no blocking condition was found in this structured input.  It is not
`TaskStatus.COMPLETED`, an authorization to complete, or a permission to execute work.

### 6. Stable normalization and digest ownership

Requirement and criterion assessment output is ordered by declaration ID.  Assessment evidence,
top-level evidence, constraints, and generated issues use stable typed sort keys.  Caller tuple
ordering therefore cannot change the semantic result.  The evaluator does not implement a
second digest: it calls `CompletionDecision.from_parts()`, which remains the sole decision
digest owner.  `decision_id` is intentionally excluded from that semantic digest.

### 7. Pure/no persistence

The evaluator has no database or repository dependency. It does not append a decision, write a
task, publish an event, change cognitive state, or project `TaskStatus`. M7.1.6 owns the control
flow from a completion proposal through evaluation and durable append, while keeping those
lifecycle boundaries unchanged.

### 8. Security non-authority

The evaluator cannot grant tool capabilities, approval, workspace access, sandbox authority,
execution leases, Memory visibility, or Trusted Verification status.  It may only preserve
structured facts or narrow the recorded outcome.  Security Runtime authority remains separate:
the Agent describes desired work, while the Security Runtime decides what work is allowed.

## Consequences

Identical semantic facts produce identical normalized assessments, issues, outcome, and
`decision_digest`, regardless of caller ordering or decision identity.  Completion remains
conservative when required facts are absent, while later evidence owners can feed explicit
negative constraints without introducing caller-controlled completion authority.

## Deferred

- Completion Gate and `TaskStatus` projection
- GoalAssessment persistence and evaluator/repository integration
- Trusted Verification composition
- Planning and Recovery/Replan execution
