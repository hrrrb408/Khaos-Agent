"""Contract tests for bounded approval callback execution."""

import asyncio
import threading
import time

import pytest
from khaos.tools.approval_callback import (
    ApprovalCallbackRunner,
    confirmation_payload,
    normalize_confirmation,
)
from khaos.tools.scheduler_models import PermissionRequest


def _request(*, expires_at: float | None = None) -> PermissionRequest:
    return PermissionRequest(
        tool_call_id="call-1",
        name="terminal",
        arguments={"command": "printf ok"},
        level="ask",
        target="terminal",
        reason="needs approval",
        binding_digest="b" * 64,
        expires_at=expires_at if expires_at is not None else time.time() + 2,
        principal_id="principal",
        session_id="session",
        task_id="task",
        workspace_id="workspace",
    )


def test_confirmation_normalizer_rejects_unknown_fields_and_invalid_types() -> None:
    assert normalize_confirmation({"approved": True, "reason": "ok"}) == {
        "approved": True,
        "reason": "ok",
    }
    assert normalize_confirmation({"approved": "yes"})["approved"] is False
    assert normalize_confirmation({"approved": True, "unexpected": 1})["approved"] is False


def test_confirmation_payload_contains_binding_fields() -> None:
    payload = confirmation_payload(_request())

    assert payload["id"] == "call-1"
    assert payload["principal_id"] == "principal"
    assert payload["binding_digest"] == "b" * 64


@pytest.mark.asyncio
async def test_runner_supports_async_and_sync_callbacks_and_closes() -> None:
    runner = ApprovalCallbackRunner(max_workers=1)
    seen: list[dict[str, object]] = []

    async def async_callback(payload: dict[str, object]) -> bool:
        seen.append(payload)
        return True

    assert await runner.run(_request(), async_callback) == {"approved": True}
    assert seen[0]["session_id"] == "session"
    assert await runner.run(_request(), lambda _payload: {"approved": False}) == {
        "approved": False
    }
    await runner.aclose()
    assert await runner.run(_request(), lambda _payload: True) == {
        "approved": False,
        "reason": "approval_callback_executor_closed",
    }


@pytest.mark.asyncio
async def test_runner_deadline_and_capacity_fail_closed() -> None:
    runner = ApprovalCallbackRunner(max_workers=1)
    release = threading.Event()

    def blocking(_payload: dict[str, object]) -> bool:
        while not release.is_set():
            time.sleep(0.01)
        return True

    first = asyncio.create_task(
        runner.run(_request(expires_at=time.time() + 0.05), blocking)
    )
    await asyncio.sleep(0.01)
    second = await runner.run(_request(), lambda _payload: True)
    assert second == {
        "approved": False,
        "reason": "approval_callback_capacity_exhausted",
    }
    assert await first == {"approved": False, "reason": "approval_callback_timeout"}
    release.set()
    await runner.aclose()
