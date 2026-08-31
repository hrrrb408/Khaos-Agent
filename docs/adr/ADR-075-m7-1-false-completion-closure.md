# ADR-075: M7.1 False-Completion Closure Matrix

- 状态：已定（M7.1.9）
- 日期：2026-08-27
- 范围：Coding task completion control-plane closure evidence

## Context

M7.1 separates a model turn from a coding-task lifecycle transition.  An
`END_TURN` is a request to evaluate completion; a `CompletionDecision` is an
immutable evaluation record; and only the Completion Gate may project an
independently authorized `COMPLETE` decision onto `TaskStatus.COMPLETED`.
The M7.1.9 work is a closure matrix over that boundary, not a new planning,
recovery-execution, or verification-authority feature.

## Decision

### 1. Successful completion has one production owner

The only successful coding-task lifecycle path is:

```text
model END_TURN
  -> PROPOSE_COMPLETION
  -> immutable CompletionDecision
  -> Completion Gate
  -> independently authorized COMPLETE
  -> fresh owner/snapshot checks in one writer transaction
  -> TaskStatus.COMPLETED
```

`AgentLoop`, assistant prose, the fact provider, `CompletionEvaluator`, and
the passive decision ledger cannot write a successful task completion.  The
generic `TaskManager` and `Database.update_coding_task()` paths reject an
active-to-`completed` transition.  `TaskManager.reflect_gate_completion()` is
only an in-memory projection after the Gate's dedicated SQL has committed.

Other occurrences of the word `completed` belong to separate domains such as
turns, sub-agents, scheduled tasks, tool operations, or verification runs;
they are not coding-task lifecycle authorities.  For the coding-task table,
the dedicated `CompletionGateRepository` SQL is the sole active-to-completed
writer.

### 2. Durable history is not restart authority

Recovery reads the physical task snapshot, canonical GoalSpec, decision
sequence head, and owner-scoped `completion.gated` turn history.  It returns a
typed continuation interpretation and performs no decision append, Gate
attempt, model/router call, planner call, authority replay, or lifecycle
projection.  A successful historical Gate result is not a bearer token.

Terminal physical task status has precedence over all historical decisions.
An old `COMPLETE` decision captured while the task was `RUNNING` is stale when
restart interruption changes the task to `BLOCKED`, so recovery returns
`REEVALUATION_REQUIRED` and never replays the Gate.

### 3. Malformed newer Gate history never falls back

The existing turn-event ledger remains the Gate-history source; no v19 table
is introduced.  `Database.list_completion_gate_history()` reads only the
newest `MAX_COMPLETION_GATE_HISTORY_RECORDS` records (currently `256`) and
never materializes an over-limit payload.  The event decoder validates the
bounded payload and all decision/task bindings.

If a malformed event is present in the bounded history window, recovery
discards every decoded Gate result for that recovery operation.  It does not
fall back from a newer malformed event to an older valid result.  A nonterminal
`COMPLETE` decision therefore resolves conservatively to
`REEVALUATION_REQUIRED`.  If a matching event is outside the bounded tail,
there is no usable current Gate result and the same conservative outcome is
used.  Maintenance retention pruning remains an independent durable-history
retention policy; the fixed read bound protects recovery memory even before
pruning occurs.

### 4. Turn completion and task completion remain independent

`turn.completed` is valid while a coding task remains `RUNNING`, `BLOCKED`, or
otherwise nonterminal.  `REPLAN`, `BLOCKED`, `FAILED`, stale, authority
insufficient, and malformed-history results do not receive a successful task
status projection in this closure.  Existing max-turn, max-budget, abort,
internal-error, and Verify-Fix failure semantics remain separate failure or
cancellation paths.

### 5. Security boundary

The closure matrix does not broaden Tool capability, Approval authority,
Workspace/Sandbox access, execution leases, delegation, Memory visibility, or
Trusted Verification.  Recovery and completion records are evidence of
control-plane state, not permission.  Owner and project predicates remain on
all production reads and writes, and malformed durable history fails closed.

## Closure matrix anchors

The matrix is implemented by the M7.1.1--M7.1.8 regression suites plus the
M7.1.9 additions.  The anchors below identify executable evidence rather than
model claims:

| Case | Required result | Evidence anchor |
| --- | --- | --- |
| A, E | prose/empty facts or Verify-Fix failure cannot complete | `test_completion_gate.py`, `test_completion_flow.py`, `test_task_state_machine.py`, `test_verify_fix_loop.py` |
| B | SATISFIED input with production fail-closed authority remains active | `test_completion_gate.py`, `test_completion_flow.py` |
| C, I | authorized fresh COMPLETE has one successful projection; races have one winner | `test_completion_gate.py` |
| D | latest FAILING observation blocks END_TURN completion | `test_task_state_machine.py`, `test_verify_fix_loop.py` |
| F--H | cognitive/version/status/workspace drift is stale | `test_completion_gate.py` |
| J--N | stale caches and generic completion APIs cannot regress or mint COMPLETED | `test_task_lifecycle_cas.py` |
| O--Q | restart is conservative; durable REPLAN and terminal outcomes recover deterministically | `test_completion_recovery.py` |
| R--S | malformed latest decision/history and newer-malformed Gate history never use an older permissive record | `test_completion_gate.py`, `test_completion_recovery.py` |
| T | owner/project partitioning is fail-closed | `test_completion_gate.py`, `test_completion_recovery.py`, security suites |
| U | turn terminal event is independent from task lifecycle | `test_completion_flow.py`, `test_completion_gate.py` |
| V | max-turn, max-budget, abort, and fatal-error behavior remains unchanged | `test_agent_loop.py`, `test_task_state_machine.py` |

The M7.1.9 recovery tests additionally prove the fixed history read bound and
the rule that an older valid Gate event cannot be used after a newer malformed
event for the same decision.

## Consequences

- No database migration is required; v18 and the existing turn ledger remain
  the durable stores.
- M7.1.9 adds closure evidence and the bounded/malformed-history hardening;
  it does not execute replanning or recovery strategies.
- Planning integration, Recovery/Replan execution, Trusted Verification, and
  the legacy `khaos.coding.verification.pipeline` remain outside this ADR.
