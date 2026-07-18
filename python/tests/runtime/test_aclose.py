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
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        execution_service=execution,
    )
    await result.aclose()
    execution.shutdown.assert_awaited_once()


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
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
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
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
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
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
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
        "execution_service",
        "office_authority",
        "owns_office_authority",
        "principal_id",
        "session_id",
            "runtime_id",
            "audit_logger",
            "owns_audit_logger",
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
    orphan and ``cleanup_orphan_runtimes()`` will retry it.

    The retry resets ``_close_failed`` so the orphan gets a fresh
    3-attempt auto-retry cycle (``aclose`` returns immediately when
    ``_close_failed`` is True to prevent concurrent callers from
    re-running the retries — see H4).
    """
    from khaos.runtime.factory import (
        cleanup_orphan_runtimes,
        register_orphan_runtime,
    )
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
    register_orphan_runtime(result)
    # Cleanup retries — still fails, so the orphan remains.
    remaining = await cleanup_orphan_runtimes()
    assert remaining >= 1
    # Now fix the office shutdown and retry — the orphan is removed.
    office.shutdown = AsyncMock()
    remaining = await cleanup_orphan_runtimes()
    assert remaining == 0
    assert result.quarantined is False


async def test_production_close_registers_failed_runtime_before_raising():
    """H4: the production close helper retains a persistently failed owner."""
    from khaos.exceptions import RuntimeCloseError
    from khaos.runtime.factory import (
        _orphan_runtimes,
        close_runtime_or_register,
    )

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
        assert any(item is result for item in _orphan_runtimes)
        assert result.quarantined is True
    finally:
        office.shutdown = AsyncMock()
        from khaos.runtime.factory import cleanup_orphan_runtimes
        await cleanup_orphan_runtimes()


# ───────────────────────── H4: concurrent aclose lock ──────────────────────


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

