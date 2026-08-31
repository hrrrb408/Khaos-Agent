# ADR-067: Verify-Fix Observation and Terminal-State Semantics

## Status

Accepted — 2026-08-26

## Context

The Verify-Fix strategy previously used one attempt counter and one
`FixAttempt` history for two different facts: a test result had been
observed and an automatic repair had been issued.  That made a final passing
test ambiguous when the repair budget had already been reached.  It also
allowed a normal model `END_TURN` to complete a task after a failing test had
been observed but before the loop had exhausted its repair budget.

## Decision

Verify-Fix records two separate durable-in-process histories:

- `VerificationObservation` records every parseable `test_run` result.
- `RepairAttempt` records only an automatic repair that was actually issued.

`max_fix_attempts` is the maximum number of automatic repairs that may be
issued.  A failing observation is first recorded and may still admit the next
repair while repair budget remains.  Therefore, with a budget of three, the
third failing observation can still be followed by repair three.  Only a
later failing observation after all three repairs have been issued becomes
`EXHAUSTED_FAILURE`.

The latest parseable verification observation is authoritative:

```text
UNKNOWN             no parseable observation
FAILING             latest observation fails and repair budget remains
PASSED              latest observation passes, regardless of history
EXHAUSTED_FAILURE   latest observation fails and no repair remains
```

`should_enter_loop()` is a side-effect-free predicate.  Callers must first
invoke `observe_test_result()` and pass the resulting typed observation to the
predicate/repair path.  `is_loop_exhausted()` reports only the typed terminal
state, never a raw counter comparison.  A typed `NoProgressSignal` is
available for later Recovery/Replan integration, but M7.1.1 does not perform
the state transition itself.

During M7.1.1 finalization, `PASSED` permits completion, `FAILING` and
`EXHAUSTED_FAILURE` fail the task, and `UNKNOWN` preserves legacy behavior.
An assistant final response is not verification evidence.  This amendment
does not add database state, change the legacy `VerificationPipeline`, or
modify Approval, Workspace, Sandbox, or Authority composition.

## Consequences

- Historical failures and repair-budget exhaustion cannot override a later
  passing verification result.
- Reports describe the latest observation and separately count repair issues.
- All parseable test results remain observable even when no repair can be
  issued.
- Full Recovery/Replan behavior remains a later M7 milestone rather than an
  implicit callback hidden in Verify-Fix.

## Verification

- `python/tests/coding/test_verify_fix.py`
- `python/tests/integration/test_verify_fix_loop.py`
- `python/tests/agent/test_task_state_machine.py`
- `python/tests/agent/test_agent_loop.py`
- `python/tests/integration/test_agent_loop.py`
