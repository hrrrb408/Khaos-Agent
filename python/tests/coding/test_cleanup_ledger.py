"""Tests for CleanupLedger v2 — run_step unified abstraction.

Round-17 review §六: verifies the ``action → verify → mark_done`` sequence,
generation tracking (stale DONE invalidation), CancelledError semantics
(record + re-raise, never mark done), and CleanupInvariantError recording
when the postcondition fails.
"""

from __future__ import annotations

import asyncio

import pytest

from khaos.coding.execution.cleanup_ledger import (
    CleanupInvariantError,
    CleanupLedger,
)


@pytest.mark.asyncio
async def test_run_step_success_marks_done_and_returns_true():
    ledger = CleanupLedger()
    called = []

    async def action() -> None:
        called.append("action")

    done = await ledger.run_step("step1", action=action)
    assert done is True
    assert ledger.is_done("step1")
    assert called == ["action"]


@pytest.mark.asyncio
async def test_run_step_skips_already_done_step():
    ledger = CleanupLedger()
    call_count = 0

    async def action() -> None:
        nonlocal call_count
        call_count += 1

    assert await ledger.run_step("step1", action=action) is True
    # Second call must NOT re-run the action.
    assert await ledger.run_step("step1", action=action) is True
    assert call_count == 1


@pytest.mark.asyncio
async def test_run_step_verify_true_marks_done():
    ledger = CleanupLedger()
    verified = []

    async def action() -> None:
        pass

    def verify() -> bool:
        verified.append(True)
        return True

    assert await ledger.run_step("step1", action=action, verify=verify) is True
    assert ledger.is_done("step1")
    assert verified == [True]


@pytest.mark.asyncio
async def test_run_step_verify_false_records_invariant_error():
    ledger = CleanupLedger()

    async def action() -> None:
        pass

    def verify() -> bool:
        return False

    done = await ledger.run_step("step1", action=action, verify=verify)
    assert done is False
    assert not ledger.is_done("step1")
    assert ledger.has_errors()
    assert isinstance(ledger.errors[0], CleanupInvariantError)


@pytest.mark.asyncio
async def test_run_step_verify_raises_records_invariant_error():
    ledger = CleanupLedger()

    async def action() -> None:
        pass

    def verify() -> bool:
        raise RuntimeError("verify exploded")

    done = await ledger.run_step("step1", action=action, verify=verify)
    assert done is False
    assert not ledger.is_done("step1")
    assert isinstance(ledger.errors[0], CleanupInvariantError)
    assert "verify() raised" in str(ledger.errors[0])


@pytest.mark.asyncio
async def test_run_step_action_exception_records_error_and_returns_false():
    ledger = CleanupLedger()

    async def action() -> None:
        raise OSError("boom")

    done = await ledger.run_step("step1", action=action)
    assert done is False
    assert not ledger.is_done("step1")
    assert isinstance(ledger.errors[0], OSError)


@pytest.mark.asyncio
async def test_run_step_cancelled_error_records_and_reraises():
    """Round-17 review §六: CancelledError must NOT mark done — ownership
    release is unproven.  The error is recorded so the caller enters
    QUARANTINED, and the CancelledError is re-raised so the caller's
    cleanup loop can abort."""
    ledger = CleanupLedger()

    async def action() -> None:
        raise asyncio.CancelledError()

    with pytest.raises(asyncio.CancelledError):
        await ledger.run_step("step1", action=action)

    assert not ledger.is_done("step1")
    assert ledger.has_errors()
    assert "cancelled" in str(ledger.errors[0]).lower()


@pytest.mark.asyncio
async def test_run_step_generation_skip_when_same():
    ledger = CleanupLedger()

    async def action() -> None:
        pass

    gen = object()
    assert await ledger.run_step(
        "listener", action=action, resource_generation=gen,
    ) is True
    # Same generation → skip.
    call_count = 0

    async def action2() -> None:
        nonlocal call_count
        call_count += 1

    assert await ledger.run_step(
        "listener", action=action2, resource_generation=gen,
    ) is True
    assert call_count == 0


@pytest.mark.asyncio
async def test_run_step_generation_invalidate_when_changed():
    """Round-17 review §五/§六: the stale DONE bug.  If a step was marked
    done for generation A but the current resource generation is B, the
    prior DONE must be invalidated and the step re-run — the DONE
    referenced a different resource instance (e.g., a reopened listener)."""
    ledger = CleanupLedger()
    gen_a = object()
    gen_b = object()

    async def action1() -> None:
        pass

    assert await ledger.run_step(
        "listener", action=action1, resource_generation=gen_a,
    ) is True
    assert ledger.generation_of("listener") is gen_a

    # New generation → must re-run.
    re_run = []

    async def action2() -> None:
        re_run.append(True)

    assert await ledger.run_step(
        "listener", action=action2, resource_generation=gen_b,
    ) is True
    assert re_run == [True]
    assert ledger.generation_of("listener") is gen_b


@pytest.mark.asyncio
async def test_run_step_retry_after_error_succeeds():
    """A failed step can be retried: the second successful call clears
    the error and marks done."""
    ledger = CleanupLedger()
    attempt = 0

    async def action() -> None:
        nonlocal attempt
        attempt += 1
        if attempt == 1:
            raise RuntimeError("first attempt failed")

    assert await ledger.run_step("step1", action=action) is False
    assert ledger.has_errors()
    # Retry — reset_errors is the caller's responsibility (matches the
    # existing pattern in LSP/Supervisor/BrowserProxy close()).
    ledger.reset_errors()
    assert await ledger.run_step("step1", action=action) is True
    assert not ledger.has_errors()
    assert ledger.is_done("step1")


@pytest.mark.asyncio
async def test_run_step_verify_failure_does_not_clear_on_retry():
    """If verify fails, the step is not done.  A retry with a passing
    verify marks it done and clears the CleanupInvariantError."""
    ledger = CleanupLedger()
    state = {"alive": True}

    async def action() -> None:
        pass

    def verify() -> bool:
        return not state["alive"]

    assert await ledger.run_step("proc", action=action, verify=verify) is False
    assert isinstance(ledger.errors[0], CleanupInvariantError)

    # Simulate the resource actually dying on retry.
    state["alive"] = False
    ledger.reset_errors()
    assert await ledger.run_step("proc", action=action, verify=verify) is True
    assert ledger.is_done("proc")
    assert not ledger.has_errors()


def test_mark_done_with_generation_records_generation():
    ledger = CleanupLedger()
    gen = object()
    ledger.mark_done_with_generation("listener", gen)
    assert ledger.is_done("listener")
    assert ledger.generation_of("listener") is gen


def test_mark_done_with_none_generation_clears_generation():
    ledger = CleanupLedger()
    ledger.mark_done_with_generation("listener", object())
    ledger.mark_done_with_generation("listener", None)
    assert ledger.generation_of("listener") is None


def test_invalidate_removes_completion_and_generation():
    ledger = CleanupLedger()
    ledger.mark_done_with_generation("listener", object())
    ledger.invalidate("listener")
    assert not ledger.is_done("listener")
    assert ledger.generation_of("listener") is None


def test_reset_errors_clears_only_errors_not_completions():
    ledger = CleanupLedger()
    ledger.mark_done("step1")
    ledger.record_error("step2", RuntimeError("boom"))
    ledger.reset_errors()
    assert ledger.is_done("step1")
    assert not ledger.has_errors()


def test_failed_steps_and_errors_in_insertion_order():
    ledger = CleanupLedger()
    ledger.record_error("b", RuntimeError("b"))
    ledger.record_error("a", OSError("a"))
    ledger.record_error("c", ValueError("c"))
    assert ledger.failed_steps == ("b", "a", "c")
    assert tuple(type(e).__name__ for e in ledger.errors) == (
        "RuntimeError", "OSError", "ValueError",
    )


def test_pending_returns_uncompleted_steps():
    ledger = CleanupLedger()
    ledger.mark_done("step1")
    assert ledger.pending(("step1", "step2", "step3")) == ("step2", "step3")


@pytest.mark.asyncio
async def test_run_step_generation_mismatch_then_verify_failure():
    """Combined: stale DONE invalidation + verify failure on the re-run."""
    ledger = CleanupLedger()
    gen_a = object()
    gen_b = object()

    async def action1() -> None:
        pass

    assert await ledger.run_step(
        "listener", action=action1, resource_generation=gen_a,
    ) is True

    async def action2() -> None:
        pass

    def verify() -> bool:
        return False  # new listener is not actually closed

    done = await ledger.run_step(
        "listener",
        action=action2,
        verify=verify,
        resource_generation=gen_b,
    )
    assert done is False
    assert not ledger.is_done("listener")
    assert isinstance(ledger.errors[0], CleanupInvariantError)
