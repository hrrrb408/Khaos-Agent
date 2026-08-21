"""Contract tests for terminal result ownership."""

from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock

import pytest
from khaos.tools.operation_store import OperationClaim
from khaos.tools.result_finalizer import ToolResultFinalizer
from khaos.tools.scheduler import ToolScheduler
from khaos.tools.scheduler_models import ToolResult


def _result() -> ToolResult:
    return ToolResult(
        tool_call_id="call-1",
        name="read",
        success=True,
        arguments={"path": "README.md"},
    )


@pytest.mark.asyncio
async def test_audit_projection_is_best_effort_and_preserves_error_boundary() -> None:
    writer = MagicMock()
    writer.audit = AsyncMock(return_value=7)
    finalizer = ToolResultFinalizer(
        audit_writer=writer,
        operation_store=MagicMock(),
    )

    assert await finalizer.audit_best_effort(
        "read",
        "README.md",
        "success",
        {"tool_call_id": "call-1"},
        "session-1",
    ) == ""
    writer.audit.assert_awaited_once_with(
        "read",
        "README.md",
        "success",
        {"tool_call_id": "call-1"},
        "session-1",
    )

    writer.audit.side_effect = RuntimeError("audit unavailable")
    assert await finalizer.audit_best_effort(
        "read", "README.md", "error", {}, "session-1"
    ) == "audit unavailable"


@pytest.mark.asyncio
async def test_finish_and_store_publishes_the_finalized_result_once() -> None:
    operation_store = MagicMock()
    operation_store.finish = AsyncMock(return_value=_result())
    operation_store.put_result = AsyncMock()
    finalizer = ToolResultFinalizer(
        audit_writer=MagicMock(),
        operation_store=operation_store,
    )
    claim = OperationClaim(
        operation_id="operation-1",
        owner_token="owner-1",
        effect_id="effect-1",
    )
    call = {"id": "call-1", "name": "read", "arguments": {"path": "README.md"}}
    context = {"principal_id": "principal-1"}

    result = await finalizer.finish_and_store(
        claim,
        _result(),
        terminal_status="completed",
        call=call,
        session_id="session-1",
        tool_context=context,
    )

    assert result == _result()
    operation_store.finish.assert_awaited_once()
    operation_store.put_result.assert_awaited_once_with(
        call,
        session_id="session-1",
        tool_context=context,
        result=result,
    )


def test_scheduler_delegates_terminal_result_ownership() -> None:
    source = inspect.getsource(ToolScheduler)

    assert "self._result_finalizer.audit_best_effort" in source
    assert "self._result_finalizer.finish_and_store" in source
    assert "self._operation_store.finish" not in source
    assert "self._operation_store.put_result" not in source
    assert "async def _audit_best_effort" not in source
