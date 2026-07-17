"""RuntimeResult lifecycle wiring tests (B1 / CI gap).

B1 regression: ``RuntimeResult`` was previously constructed with positional
arguments, which bound the ``ExecutionService`` object into the ``_closed``
slot — making ``if self._closed: return`` exit immediately and the entire
``aclose()`` body a no-op.  These tests pin the contract that ``aclose()``
actually invokes every component's shutdown, and that ``build_runtime()``
wires the right component into the right field.
"""

from unittest.mock import AsyncMock, MagicMock

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
    """
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
    # Must not raise — every failure is contained.
    await result.aclose()
    office.shutdown.assert_awaited_once()
    memory.aclose.assert_awaited_once()
    execution.shutdown.assert_awaited_once()
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
    ]



