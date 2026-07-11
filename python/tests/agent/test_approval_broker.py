import asyncio
import time

from khaos.agent.approval import ApprovalBroker
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.grpc_server import TaskService


async def test_task_approval_resolves_waiting_tool_decision():
    broker = ApprovalBroker()
    manager = TaskManager()
    task = await manager.create("protected tool")
    await manager.update_status(task.id, TaskStatus.BLOCKED, pending_approval={"tool_call_id": "call-1", "tool_name": "write_file", "target": "x"})
    waiter = asyncio.create_task(broker.wait("call-1", timeout=1))
    service = TaskService(manager, broker)
    # The task endpoint performs the same operation as the HTTP approve path.
    await asyncio.sleep(0)
    response = await service.approve(task.id)
    decision = await waiter
    assert response["ok"] is True
    assert decision == {"approved": True, "remember": False}
    assert (await manager.get(task.id)).status == TaskStatus.RUNNING


async def test_approval_broker_rejects_stale_changeset_binding():
    broker = ApprovalBroker()
    await broker.bind("call-2", "changeset:new:apply")
    assert await broker.resolve("call-2", True, approval_key="changeset:old:apply") is False
    assert await broker.resolve("call-2", True, approval_key="changeset:new:apply") is True
    assert await broker.wait("call-2", timeout=0.1) == {"approved": True, "remember": False}


async def test_approval_broker_rejects_expired_binding():
    broker = ApprovalBroker()
    await broker.bind("call-3", "key", expiry=time.time() - 1)
    assert await broker.resolve("call-3", True, approval_key="key") is False


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
    binding = {"requester": "session", "operation": "git.undo"}
    await broker.register_operation("expired", binding, time.time() - 1)
    assert await broker.approve_operation("expired", "session") is False
    assert await broker.consume_operation("expired", binding) is False

    await broker.register_operation("mismatch", binding, time.time() + 60)
    assert await broker.approve_operation("mismatch", "session") is True
    assert await broker.consume_operation("mismatch", {**binding, "operation": "git.checkout"}) is False
    assert await broker.consume_operation("mismatch", binding) is False
