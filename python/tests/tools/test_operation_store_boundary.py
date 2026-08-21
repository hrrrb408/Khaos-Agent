"""Contract tests for durable tool-operation coordination ownership."""

import inspect

from khaos.tools.operation_store import ToolOperationStore
from khaos.tools.result_store import ToolResultStore
from khaos.tools.scheduler import ToolScheduler


class _NoLifecycleDatabase:
    """Database proxy used to prove the store only calls operation ports."""

    def __getattr__(self, name: str):  # pragma: no cover - violation guard
        raise AssertionError(f"unexpected database operation: {name}")


def test_operation_scope_is_bound_to_tool_and_execution_identity() -> None:
    store = ToolOperationStore(
        db=_NoLifecycleDatabase(),
        result_store=ToolResultStore(),
    )
    context = {
        "principal_id": "principal",
        "project_id": "project",
        "task_id": "task",
        "workspace_id": "workspace",
    }

    first = store.scope(
        "operation",
        tool_name="write_file",
        session_id="session",
        tool_context=context,
    )
    second = store.scope(
        "operation",
        tool_name="write_file",
        session_id="other-session",
        tool_context=context,
    )

    assert first
    assert first != second


def test_operation_store_is_the_only_claim_owner() -> None:
    operation_source = inspect.getsource(ToolOperationStore)
    scheduler_source = inspect.getsource(ToolScheduler)

    assert "sqlite3.connect" not in operation_source
    assert ".commit(" not in operation_source
    assert ".close(" not in operation_source
    assert "claim_tool_operation" not in scheduler_source
    assert "complete_tool_operation" not in scheduler_source
    assert "self._operation_events" not in scheduler_source
    assert "self._operation_store.claim" in scheduler_source
