import asyncio
import time
from dataclasses import replace

import pytest

from khaos.agent.approval import ApprovalBinding, ApprovalBroker
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.grpc_server import TaskService


async def test_task_approval_resolves_waiting_tool_decision():
    broker = ApprovalBroker()
    binding = _binding("call-1")
    digest = await broker.register_tool_approval(binding)
    manager = TaskManager()
    task = await manager.create("protected tool")
    await manager.update_status(task.id, TaskStatus.BLOCKED, pending_approval={
        "tool_call_id": "call-1", "tool_name": "write_file", "target": "x",
        "principal_id": binding.principal_id, "session_id": binding.session_id,
        "binding_digest": digest,
    })
    waiter = asyncio.create_task(
        broker.wait("call-1", timeout=1, binding_digest=digest)
    )
    service = TaskService(manager, broker)
    # The task endpoint performs the same operation as the HTTP approve path.
    await asyncio.sleep(0)
    response = await service.approve(
        task.id,
        principal_id=binding.principal_id,
        session_id=binding.session_id,
        binding_digest=digest,
    )
    decision = await waiter
    assert response["ok"] is True
    assert decision == {"approved": True, "remember": False}
    assert (await manager.get(task.id)).status == TaskStatus.RUNNING


async def test_approval_broker_rejects_cross_session_and_digest_replay():
    broker = ApprovalBroker()
    binding = _binding("call-2")
    digest = await broker.register_tool_approval(binding)
    assert await broker.resolve(
        "call-2", True, principal_id="principal", session_id="other",
        binding_digest=digest,
    ) is False
    assert await broker.resolve(
        "call-2", True, principal_id="principal", session_id="session",
        binding_digest="0" * 64,
    ) is False
    assert await broker.resolve(
        "call-2", True, principal_id="principal", session_id="session",
        binding_digest=digest,
    ) is True
    assert await broker.wait(
        "call-2", timeout=0.1, binding_digest=digest
    ) == {"approved": True, "remember": False}
    assert await broker.resolve(
        "call-2", True, principal_id="principal", session_id="session",
        binding_digest=digest,
    ) is False


async def test_approval_broker_rejects_expired_binding():
    broker = ApprovalBroker()
    binding = _binding("call-3", expires_at=time.time() - 1)
    digest = await broker.register_tool_approval(binding)
    assert await broker.resolve(
        "call-3", True, principal_id="principal", session_id="session",
        binding_digest=digest,
    ) is False


async def test_tool_approval_timeout_is_one_shot():
    broker = ApprovalBroker()
    binding = _binding("call-timeout")
    digest = await broker.register_tool_approval(binding)

    assert await broker.wait(
        "call-timeout", timeout=0.01, binding_digest=digest
    ) == {"approved": False, "remember": False}
    assert await broker.resolve(
        "call-timeout", True, principal_id="principal",
        session_id="session", binding_digest=digest,
    ) is False


async def test_tool_call_id_cannot_be_rebound_across_scope_or_arguments():
    broker = ApprovalBroker()
    binding = _binding("call-rebind")
    await broker.register_tool_approval(binding)

    for mutated in (
        replace(binding, principal_id="other-principal"),
        replace(binding, task_id="other-task"),
        replace(binding, workspace_id="other-workspace"),
        replace(binding, arguments_digest="c" * 64),
        replace(binding, profile_digest="d" * 64),
    ):
        with pytest.raises(PermissionError, match="already bound"):
            await broker.register_tool_approval(mutated)


async def test_operation_approval_is_bound_and_single_use():
    broker = ApprovalBroker()
    binding = {
        "task_id": "task",
        "workspace_id": "workspace",
        "operation": "git.undo",
        "target": "abc",
        "head": "def",
        "diff_hash": "hash",
        "expiry": time.time() + 60,
        "requester": "session",
    }
    await broker.register_operation("operation", binding, binding["expiry"])
    assert await broker.approve_operation("operation", "other") is False
    assert await broker.approve_operation("operation", "session") is True
    assert await broker.consume_operation("operation", binding) is True
    assert await broker.consume_operation("operation", binding) is False


async def test_operation_approval_expiry_and_mismatch_are_consumed():
    broker = ApprovalBroker()
    binding = {
        "requester": "session",
        "task_id": "task",
        "workspace_id": "workspace",
        "operation": "git.undo",
    }
    await broker.register_operation("expired", binding, time.time() - 1)
    assert await broker.approve_operation("expired", "session") is False
    assert await broker.consume_operation("expired", binding) is False

    await broker.register_operation("mismatch", binding, time.time() + 60)
    assert await broker.approve_operation("mismatch", "session") is True
    assert await broker.consume_operation("mismatch", {**binding, "operation": "git.checkout"}) is False
    assert await broker.consume_operation("mismatch", binding) is False


def _binding(
    tool_call_id: str, *, expires_at: float | None = None
) -> ApprovalBinding:
    return ApprovalBinding(
        principal_id="principal",
        session_id="session",
        task_id="task",
        turn_id="turn",
        tool_call_id=tool_call_id,
        tool_name="write_file",
        arguments_digest="a" * 64,
        workspace_id="workspace",
        profile_digest="b" * 64,
        expires_at=expires_at or time.time() + 60,
    )
