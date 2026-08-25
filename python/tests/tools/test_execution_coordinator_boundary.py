"""Contract tests for the authority-bound invocation coordinator."""

import asyncio
import inspect
from types import SimpleNamespace

import pytest
from khaos.exceptions import PermissionDeniedError
from khaos.tools.execution_coordinator import ToolExecutionCoordinator
from khaos.tools.scheduler import ToolScheduler


class _InvocationBroker:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def invoke(self, name: str, *, mode: str, context: dict, **arguments):
        self.calls.append(
            {"name": name, "mode": mode, "context": context, "arguments": arguments}
        )
        return "handler output"


def test_coordinator_injects_effect_and_process_authority_before_handler() -> None:
    broker = _InvocationBroker()
    process_authority = object()
    coordinator = ToolExecutionCoordinator(
        invocation_broker=broker,
        security_middleware=SimpleNamespace(sandbox=None),
        process_authority=process_authority,
    )

    outcome = asyncio.run(
        coordinator.invoke(
            tool=SimpleNamespace(name="read_file"),
            call={"id": "call", "arguments": {"path": "file.txt"}},
            mode="coding",
            tool_context={"principal_id": "principal"},
            step_authority=None,
            effect_id="effect-1",
            timeout=1.0,
            default_effect_status="not_applied",
            reconciliation_hint="",
        )
    )

    assert outcome.output == "handler output"
    assert outcome.effect_id == "effect-1"
    context = broker.calls[0]["context"]
    assert isinstance(context, dict)
    assert context["process_authority"] is process_authority
    assert context["effect_id"] == "effect-1"


def test_scheduler_delegates_handler_invocation_to_execution_owner() -> None:
    source = inspect.getsource(ToolScheduler)
    assert "self.invocation_broker.invoke" not in source
    assert "self._execution_coordinator.invoke" in source


def test_production_coordinator_rejects_raw_call_without_admission_snapshot() -> None:
    coordinator = ToolExecutionCoordinator(
        invocation_broker=_InvocationBroker(),
        security_middleware=SimpleNamespace(sandbox=None),
        process_authority=object(),
    )

    with pytest.raises(PermissionDeniedError, match="immutable admitted tool call"):
        asyncio.run(
            coordinator.invoke(
                tool=SimpleNamespace(name="read_file"),
                call={"id": "raw", "arguments": {"path": "model.txt"}},
                mode="coding",
                tool_context={"production_runtime": True},
                step_authority=None,
                effect_id="effect-raw",
                timeout=1.0,
                default_effect_status="not_applied",
                reconciliation_hint="",
            )
        )
