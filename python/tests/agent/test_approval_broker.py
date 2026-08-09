import asyncio
import time
from dataclasses import replace

import pytest

from khaos.agent.approval import ApprovalBinding, ApprovalBroker, StepExecutionAuthority
from khaos.coding.task_manager import TaskManager, TaskStatus
from khaos.grpc_server import TaskService
from khaos.runtime import RequestContext


def _test_ctx(principal_id: str = "principal") -> RequestContext:
    """M4 batch 3.1.16A-4-2: TaskService.approve now enforces that the
    task's owner, the binding's principal, and ctx.principal_id all
    agree.  The binding created by ``_binding`` uses ``principal_id=
    "principal"``, so the ctx and TaskManager must be aligned to the
    same value — otherwise the new cross-principal guard hides the
    task as "not found"."""
    return RequestContext.for_rpc(principal_id)


def test_step_execution_authority_digest_binds_scope_and_receipt():
    authority = StepExecutionAuthority(
        principal_id="principal",
        project_id="project",
        session_id="session",
        task_id="task",
        turn_id="turn",
        step_id="attempt",
        tool_call_id="call",
        tool_name="terminal",
        workspace_id="workspace",
        workspace_generation=3,
        cwd_identity="dev:ino",
        permission_profile_digest="p" * 64,
        environment_keys=("LANG", "PATH"),
        sandbox_backend="LinuxBubblewrapBackend",
        network_authority="n" * 64,
        target="terminal:ls",
        approval_target="terminal:ls",
        arguments_digest="a" * 64,
        authorization_resource_digest="r" * 64,
        authorization_epoch=7,
        policy_digest="d" * 64,
        tool_schema_digest="s" * 64,
        tool_security_digest="t" * 64,
    )
    with_receipt = replace(authority, approval_receipt_digest="b" * 64)
    changed = replace(authority, cwd_identity="dev:other-ino")
    assert authority.scope_digest() == with_receipt.scope_digest()
    assert authority.digest() != with_receipt.digest()
    assert authority.scope_digest() != changed.scope_digest()


async def test_task_approval_resolves_waiting_tool_decision(tmp_path):
    from khaos.db import Database
    db = Database(tmp_path / "approval-broker-test.db")
    await db.connect()
    await db.run_migrations()
    broker = ApprovalBroker()
    binding = _binding("call-1")
    digest = await broker.register_tool_approval(binding)
    manager = TaskManager(db=db, principal_id="principal")
    await manager.load()
    task = await manager.create("protected tool")
    await manager.update_status(task.id, TaskStatus.BLOCKED, pending_approval={
        "tool_call_id": "call-1", "tool_name": "write_file", "target": "x",
        "principal_id": binding.principal_id, "session_id": binding.session_id,
        "binding_digest": digest,
    })
    waiter = asyncio.create_task(
        broker.wait("call-1", timeout=1, binding_digest=digest)
    )
    service = TaskService(db, broker)
    # The task endpoint performs the same operation as the HTTP approve path.
    await asyncio.sleep(0)
    response = await service.approve(
        _test_ctx(),
        task.id,
        principal_id=binding.principal_id,
        session_id=binding.session_id,
        binding_digest=digest,
    )
    decision = await waiter
    assert response["ok"] is True
    assert decision == {"approved": True, "remember": False}
    # C-1-5a: ``service.approve`` operates on the service's internal
    # per-principal TaskManager (a different instance from the setup
    # ``manager``), so verify the transition via the service's manager
    # — the setup manager's in-memory cache is stale.
    service_manager = await service._manager(_test_ctx())
    assert (await service_manager.get(task.id)).status == TaskStatus.RUNNING
    await db.close()


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


async def test_tool_call_id_reuse_isolated_by_server_approval_id():
    broker = ApprovalBroker()
    binding = _binding("call-rebind")
    first = await broker.register_tool_approval(binding)
    same = await broker.register_tool_approval(binding)
    assert same.approval_id == first.approval_id

    for mutated in (
        replace(binding, principal_id="other-principal"),
        replace(binding, task_id="other-task"),
        replace(binding, workspace_id="other-workspace"),
        replace(binding, arguments_digest="c" * 64),
        replace(binding, profile_digest="d" * 64),
    ):
        registration = await broker.register_tool_approval(mutated)
        assert registration.approval_id != first.approval_id
        assert registration != first


async def test_same_model_call_id_can_be_approved_in_two_sessions():
    broker = ApprovalBroker()
    first_binding = _binding("same-model-id")
    second_binding = replace(
        first_binding,
        principal_id="other-principal",
        session_id="other-session",
        task_id="other-task",
        nonce="f" * 64,
    )
    first = await broker.register_tool_approval(first_binding)
    second = await broker.register_tool_approval(second_binding)

    assert first.approval_id != second.approval_id
    assert await broker.resolve(
        "same-model-id",
        True,
        principal_id="principal",
        session_id="session",
        binding_digest=first,
    ) is True
    assert await broker.resolve(
        "same-model-id",
        True,
        principal_id="other-principal",
        session_id="other-session",
        binding_digest=second,
    ) is True


async def test_pending_approval_quotas_are_scoped_and_expired_records_do_not_count():
    broker = ApprovalBroker(max_pending_per_principal_session=2, max_pending_per_turn=1)
    first_binding = _binding("quota-first")
    await broker.register_tool_approval(first_binding)

    with pytest.raises(PermissionError, match="quota exceeded for turn"):
        await broker.register_tool_approval(_binding("quota-second"))

    other_turn = replace(first_binding, tool_call_id="quota-other-turn", turn_id="turn-2")
    await broker.register_tool_approval(other_turn)
    with pytest.raises(PermissionError, match="quota exceeded for principal/session"):
        await broker.register_tool_approval(
            replace(first_binding, tool_call_id="quota-third", turn_id="turn-3")
        )

    other_principal = replace(
        first_binding,
        principal_id="other-principal",
        tool_call_id="quota-other-principal",
    )
    await broker.register_tool_approval(other_principal)

    expired = replace(
        first_binding,
        tool_call_id="quota-expired",
        turn_id="turn-expired",
        expires_at=time.time() - 1,
    )
    expired_broker = ApprovalBroker(max_pending_per_principal_session=1, max_pending_per_turn=1)
    await expired_broker.register_tool_approval(expired)
    await expired_broker.register_tool_approval(
        replace(expired, tool_call_id="quota-after-expired", expires_at=time.time() + 60)
    )


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
