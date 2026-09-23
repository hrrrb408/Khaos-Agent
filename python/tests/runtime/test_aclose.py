"""RuntimeResult lifecycle wiring tests (B1 / CI gap).

B1 regression: ``RuntimeResult`` was previously constructed with positional
arguments, which bound the ``ExecutionService`` object into the ``_closed``
slot — making ``if self._closed: return`` exit immediately and the entire
``aclose()`` body a no-op.  These tests pin the contract that ``aclose()``
actually invokes every component's shutdown, and that ``build_runtime()``
wires the right component into the right field.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from khaos.runtime.factory import RuntimeResult


async def test_runtime_aclose_calls_memory_manager_close():
    memory = MagicMock()
    memory.aclose = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )
    await result.aclose()
    memory.aclose.assert_awaited_once()


async def test_aclose_closes_explicitly_owned_context_intelligence():
    """M8.1: close the composed repository-intelligence owner once."""
    context_intelligence = MagicMock()
    context_intelligence.close = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )
    result.context_intelligence = context_intelligence
    result.owns_context_intelligence = True

    await result.aclose()

    context_intelligence.close.assert_awaited_once()


async def test_aclose_ignores_synthetic_loop_context_attributes():
    """A mock/compatibility loop must not create an implicit close owner."""
    loop = MagicMock()
    loop.context_intelligence.close = AsyncMock()
    result = RuntimeResult(
        loop=loop,
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )

    await result.aclose()

    loop.context_intelligence.close.assert_not_awaited()


async def test_aclose_invokes_office_authority_shutdown():
    """B1: ``office_authority.shutdown`` must actually be reached."""
    office = MagicMock()
    office.shutdown = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )
    await result.aclose()
    office.shutdown.assert_awaited_once()


async def test_aclose_invokes_execution_service_shutdown():
    """B1: ``execution_service.shutdown`` must actually be reached."""
    execution = MagicMock()
    execution.shutdown = AsyncMock()
    scheduler = MagicMock()
    scheduler.aclose = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=scheduler,
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        execution_service=execution,
    )
    await result.aclose()
    execution.shutdown.assert_awaited_once()


async def test_browser_context_close_failure_marks_runtime_failed(monkeypatch):
    """H4: Browser ownership failure participates in quarantine retries."""
    from khaos.exceptions import RuntimeCloseError
    manager = MagicMock()
    manager.close = AsyncMock(side_effect=RuntimeError("browser live"))
    result = RuntimeResult(
        loop=MagicMock(), mode_manager=MagicMock(), task_manager=None,
        skill_generator=None, tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(), new_verify_fix_loop=None,
        runtime_id="runtime-browser",
        browser_manager=manager,
    )

    with pytest.raises(RuntimeCloseError):
        await result.aclose()
    assert result._close_failed is True
    assert result._closed is False
    assert manager.close.await_count == 3


async def test_aclose_is_idempotent():
    """B1: second ``aclose()`` must short-circuit via ``_closed``.

    Critically the short-circuit must read a *real bool* (``_closed=False``
    default), not a truthy component accidentally bound into the slot.
    """
    memory = MagicMock()
    memory.aclose = AsyncMock()
    office = MagicMock()
    office.shutdown = AsyncMock()
    execution = MagicMock()
    execution.shutdown = AsyncMock()
    scheduler = MagicMock()
    scheduler.aclose = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=scheduler,
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        execution_service=execution,
        office_authority=office,
    )
    # Pre-condition: ``_closed`` is a real bool, not a component object.
    assert result._closed is False
    await result.aclose()
    assert result._closed is True
    assert memory.aclose.await_count == 1
    assert office.shutdown.await_count == 1
    assert execution.shutdown.await_count == 1
    # Second call must not re-invoke any shutdown.
    await result.aclose()
    assert memory.aclose.await_count == 1
    assert office.shutdown.await_count == 1
    assert execution.shutdown.await_count == 1


async def test_aclose_shuts_down_office_before_memory_and_execution():
    """B1 ordering: Office mutation fence must close FIRST.

    Otherwise a mutation thread could keep writing to the filesystem after
    the memory manager / execution service have already torn down their
    state.  This pins the ordering called out in the factory docstring.
    """
    order: list[str] = []
    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=lambda: order.append("office"))
    memory = MagicMock()
    memory.aclose = AsyncMock(side_effect=lambda: order.append("memory"))
    execution = MagicMock()
    execution.shutdown = AsyncMock(side_effect=lambda: order.append("execution"))
    scheduler = MagicMock()
    scheduler.aclose = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=scheduler,
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        execution_service=execution,
        office_authority=office,
    )
    await result.aclose()
    assert order == ["office", "memory", "execution"]


async def test_aclose_tolerates_component_shutdown_failures():
    """A failing component must not prevent the others from closing.

    H3: a component failure sets ``_close_failed=True`` and leaves
    ``_closed=False`` so the caller can observe and retry.  Each
    component's shutdown is expected to be idempotent — a retry will
    re-invoke them, and a component that already reached a terminal
    state on the first attempt should ideally not raise again.

    H4: ``aclose`` now retries 3 times and then raises
    ``RuntimeCloseError`` so the production caller is forced to observe
    the failure.  Every component's shutdown IS still called on every
    retry attempt (they're all invoked, just all fail), and the runtime
    is left in a retryable state (``_closed=False``, ``_close_task=None``).
    """
    from khaos.exceptions import RuntimeCloseError

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("office boom"))
    memory = MagicMock()
    memory.aclose = AsyncMock(side_effect=RuntimeError("memory boom"))
    execution = MagicMock()
    execution.shutdown = AsyncMock(side_effect=RuntimeError("exec boom"))
    scheduler = MagicMock()
    scheduler.aclose = AsyncMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=scheduler,
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        execution_service=execution,
        office_authority=office,
    )
    # H4: aclose raises after exhausting retries — every failure is still
    # contained (no uncaught exception), but the caller is now forced to
    # observe the failure.
    with pytest.raises(RuntimeCloseError):
        await result.aclose()
    # Every component's shutdown was called on the first attempt.
    office.shutdown.assert_awaited()
    memory.aclose.assert_awaited()
    execution.shutdown.assert_awaited()
    # H3: a component failure marks the runtime as failed-close, NOT closed.
    assert result._close_failed is True
    assert result._closed is False


async def test_closed_field_is_not_bound_by_positional_construction():
    """B1 regression guard: even if a future caller slips back to positional
    construction, ``_closed`` must never receive a component object.

    ``init=False`` makes this impossible at the dataclass level: ``_closed``
    is not in the generated ``__init__`` signature, so positional args can
    never bind into it.  The init signature must include the eight real
    components plus the optional components (``execution_service``,
    ``office_authority``, ``owns_office_authority``, ``principal_id``,
    ``session_id``, ``runtime_id``) — but NOT ``_closed``, ``_close_task``
    or ``_close_failed``.
    """
    import inspect

    init_params = list(inspect.signature(RuntimeResult.__init__).parameters)
    # ``_closed`` / ``_close_task`` / ``_close_failed`` must NOT be in the
    # init signature — that's the B1 / H3 fix.
    assert "_closed" not in init_params, (
        "_closed must be init=False so positional construction can never "
        "bind a component into it (B1 regression)"
    )
    assert "_closing" not in init_params, (
        "_closing must be init=False (H3 regression)"
    )
    assert "_close_task" not in init_params, (
        "_close_task must be init=False (H3 regression)"
    )
    assert "_close_failed" not in init_params, (
        "_close_failed must be init=False (H3 regression)"
    )
    # The init signature must still accept the real components in order.
    # H5: ``session_id`` + ``runtime_id`` extend the per-session
    # BrowserContext key and must be in the init signature.
    # H2: ``audit_logger`` is stored on RuntimeResult so ``aclose`` can
    # close its file descriptor — added after ``runtime_id``.
    assert init_params == [
        "self",
        "loop",
        "mode_manager",
        "task_manager",
        "skill_generator",
        "tool_scheduler",
        "memory_manager",
        "skill_manager",
        "new_verify_fix_loop",
        "profile",
        "execution_service",
        "browser_manager",
        "cleanup_authority",
        "office_authority",
        "owns_office_authority",
        "credential_broker",
        "owns_credential_broker",
        "principal_id",
        "principal_kind",
        "parent_principal_id",
        "delegation_digest",
        "session_id",
        "runtime_id",
        "audit_logger",
        "owns_audit_logger",
        "planning_coordinator",
    ]


# ───────────────────────── H2: audit logger close ──────────────────────────


async def test_aclose_invokes_audit_logger_close():
    """H2: ``aclose()`` must call ``audit_logger.close()`` so the file
    descriptor is released — without this, configuring a file audit path
    would leak the fd for the process's lifetime.

    The close is best-effort and happens LAST (after every other
    component has shut down) because audit logging may be needed during
    component shutdown.
    """
    audit = MagicMock()
    audit.close = MagicMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        audit_logger=audit,
    )
    await result.aclose()
    audit.close.assert_called_once()


async def test_aclose_audit_logger_close_is_best_effort():
    """H2: a failure in ``audit_logger.close()`` must NOT set
    ``_close_failed=True`` — the audit fd is reclaimed by the OS on
    process exit, so a close failure is not safety-critical.
    """
    audit = MagicMock()
    audit.close = MagicMock(side_effect=RuntimeError("close boom"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        audit_logger=audit,
    )
    # Must not raise — audit close failure is best-effort.
    await result.aclose()
    assert result._closed is True
    assert result._close_failed is False


async def test_aclose_does_not_close_borrowed_audit_logger():
    """H3: a per-turn runtime cannot close the server's shared logger."""
    audit = MagicMock()
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        audit_logger=audit,
        owns_audit_logger=False,
    )

    await result.aclose()

    audit.close.assert_not_called()


# ───────────────────────── H3: orphan-cleanup registry ────────────────────


async def test_orphan_cleanup_registry_retries_failed_runtime():
    """H3: a runtime that fails ``aclose()`` can be registered as an
    orphan and its ``RuntimeCleanupAuthority`` will retry it.

    The retry resets ``_close_failed`` so the orphan gets a fresh
    3-attempt auto-retry cycle (``aclose`` returns immediately when
    ``_close_failed`` is True to prevent concurrent callers from
    re-running the retries — see H4).
    """
    from khaos.exceptions import RuntimeCloseError

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("persistent failure"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )
    with pytest.raises(RuntimeCloseError):
        await result.aclose()
    # Register as orphan — the registry retains the runtime's component
    # references so they are not silently leaked.
    result.cleanup_authority.register(result)
    # Cleanup retries — still fails, so the orphan remains.
    remaining = await result.cleanup_authority.cleanup()
    assert remaining >= 1
    # Now fix the office shutdown and retry — the orphan is removed.
    office.shutdown = AsyncMock()
    remaining = await result.cleanup_authority.cleanup()
    assert remaining == 0
    assert result.quarantined is False


async def test_production_close_registers_failed_runtime_before_raising():
    """H4: the production close helper retains a persistently failed owner."""
    from khaos.exceptions import RuntimeCloseError
    from khaos.runtime.factory import close_runtime_or_register

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("persistent failure"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )
    try:
        with pytest.raises(RuntimeCloseError):
            await close_runtime_or_register(result)
        assert result.cleanup_authority.contains(result)
        assert result.quarantined is True
    finally:
        office.shutdown = AsyncMock()
        await result.cleanup_authority.cleanup()


async def test_production_close_delays_cancellation_until_terminal_or_quarantine():
    """H2: owner cancellation cannot escape before cleanup is retained."""
    import asyncio

    from khaos.runtime.factory import close_runtime_or_register

    started = asyncio.Event()
    release = asyncio.Event()

    async def failing_shutdown():
        started.set()
        await release.wait()
        raise RuntimeError("persistent close failure")

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=failing_shutdown)
    result = RuntimeResult(
        loop=MagicMock(), mode_manager=MagicMock(), task_manager=None,
        skill_generator=None, tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(), new_verify_fix_loop=None,
        office_authority=office,
    )
    owner = asyncio.create_task(close_runtime_or_register(result))
    await started.wait()
    owner.cancel()
    release.set()

    with pytest.raises(asyncio.CancelledError):
        await owner
    assert result._closed or result.quarantined
    assert result.quarantined
    assert result.cleanup_authority.contains(result)

    office.shutdown = AsyncMock()
    await result.cleanup_authority.cleanup()


# ───────────────────────── H4: concurrent aclose lock ──────────────────────


def test_runtime_cleanup_authorities_are_server_isolated():
    from khaos.runtime import RuntimeCleanupAuthority

    first = RuntimeCleanupAuthority()
    second = RuntimeCleanupAuthority()
    runtime = RuntimeResult(
        loop=MagicMock(), mode_manager=MagicMock(), task_manager=None,
        skill_generator=None, tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(), new_verify_fix_loop=None,
        cleanup_authority=first,
    )

    first.register(runtime)

    assert first.contains(runtime)
    assert first.count == 1
    assert not second.contains(runtime)
    assert second.count == 0


async def test_concurrent_aclose_callers_do_not_create_multiple_close_tasks():
    """H4: when two concurrent ``aclose()`` callers race on a failing
    close, only ONE close task is created at a time — the second caller
    waits on the lock and sees the result of the first.

    Without the lock, both callers would resume simultaneously when the
    shared ``_close_task`` failed, each create a new ``_close_task``,
    and run shutdown on the same components multiple times concurrently.
    """
    import asyncio

    from khaos.exceptions import RuntimeCloseError

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("boom"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )
    # Two concurrent aclose() calls.
    with pytest.raises(RuntimeCloseError):
        await asyncio.gather(result.aclose(), result.aclose())
    # Each retry attempt called office.shutdown ONCE (3 attempts total),
    # NOT 6 (which would happen if both callers created separate tasks).
    assert office.shutdown.await_count == 3


# ───────────────────────── P2-1: close false-success ──────────────────────────


async def test_quarantined_runtime_aclose_re_raises_not_silent_success():
    """P2-1 (close false-success): after a terminal close failure the runtime
    enters ``QUARANTINED``.  A later ``aclose()`` from a *different* caller
    must re-raise the same typed error — it must NOT return silently while
    resources are still live.

    Previously a failed first close set ``_close_failed`` and the next
    ``aclose()`` returned at ``if self._close_failed: return``, so caller B
    believed the close succeeded even though the runtime was quarantined.
    """
    from khaos.exceptions import RuntimeCloseError
    from khaos.runtime.lifecycle import CloseState

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("office boom"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )

    # First caller: close fails terminally after 3 retries.
    with pytest.raises(RuntimeCloseError) as exc_info:
        await result.aclose()
    first_error = exc_info.value

    # The runtime is QUARANTINED, not CLOSED.
    assert result.close_state is CloseState.QUARANTINED
    assert result._closed is False
    assert result._close_failed is True
    assert result.close_error is first_error

    # Second caller: must observe the SAME failure, not a silent success.
    with pytest.raises(RuntimeCloseError) as exc_info2:
        await result.aclose()
    assert exc_info2.value is first_error
    # No additional retry attempts ran for the second caller.
    assert office.shutdown.await_count == 3


async def test_clean_close_transitions_to_closed_state():
    """P2-1: a successful close transitions the typed state machine to CLOSED."""
    from khaos.runtime.lifecycle import CloseState

    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )
    assert result.close_state is CloseState.OPEN

    await result.aclose()

    assert result.close_state is CloseState.CLOSED
    assert result.close_error is None


async def test_quarantined_runtime_recovers_after_cleanup_authority_reset():
    """P2-1: the server-scoped ``RuntimeCleanupAuthority`` resets the
    QUARANTINED state so a transiently-failing component can be retried.
    Once it succeeds the runtime reaches CLOSED and is released.
    """
    from khaos.exceptions import RuntimeCloseError
    from khaos.runtime.factory import RuntimeCleanupAuthority
    from khaos.runtime.lifecycle import CloseState

    # First call fails, subsequent calls succeed (simulating a transient
    # component outage that recovers).
    call_count = {"n": 0}

    async def _flaky_shutdown():
        call_count["n"] += 1
        if call_count["n"] < 4:  # fail the first 3 attempts of the first aclose
            raise RuntimeError("transient")

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=_flaky_shutdown)
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
    )

    authority = RuntimeCleanupAuthority()
    with pytest.raises(RuntimeCloseError):
        await result.aclose()
    assert result.close_state is CloseState.QUARANTINED
    authority.register(result)
    assert authority.count == 1

    # The authority resets the quarantine state and retries — now succeeds.
    remaining = await authority.cleanup()
    assert remaining == 0
    assert result.close_state is CloseState.CLOSED
    assert not result.quarantined
    assert authority.count == 0
