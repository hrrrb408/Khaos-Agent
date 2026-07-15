import asyncio
import time

from khaos.agent.approval import ApprovalBroker
from khaos.db import Database


async def test_approved_operation_survives_restart_and_consumes_once(tmp_path):
    path = tmp_path / "khaos.db"
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    binding = _binding()

    first = ApprovalBroker(db=db)
    await first.register_operation("approval", binding, binding["expiry"])
    assert await first.approve_operation(
        "approval", "session", principal_id="principal"
    )

    await db.close()
    restarted_db = Database(path)
    await restarted_db.connect()
    await restarted_db.run_migrations()
    restarted = ApprovalBroker(db=restarted_db)
    assert await restarted.consume_operation("approval", binding)
    assert not await restarted.consume_operation("approval", binding)

    events = await restarted_db.list_operation_approval_events("approval")
    assert [event["event_type"] for event in events] == [
        "registered", "approved", "consumed", "consume-rejected",
    ]
    await restarted_db.close()


async def test_binding_mismatch_burns_operation_capability(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    binding = _binding()
    broker = ApprovalBroker(db=db)
    await broker.register_operation("approval", binding, binding["expiry"])
    assert await broker.approve_operation(
        "approval", "session", principal_id="principal"
    )

    assert not await broker.consume_operation(
        "approval", {**binding, "workspace_id": "other"}
    )
    assert not await broker.consume_operation("approval", binding)
    await db.close()


async def test_operation_approval_rejects_cross_principal_and_expiry(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    binding = _binding()
    broker = ApprovalBroker(db=db)
    await broker.register_operation("approval", binding, binding["expiry"])

    assert not await broker.approve_operation(
        "approval", "session", principal_id="other"
    )
    assert await broker.approve_operation(
        "approval", "session", principal_id="principal"
    )

    expired = _binding(expiry=time.time() - 1)
    await broker.register_operation("expired", expired, expired["expiry"])
    assert not await broker.approve_operation(
        "expired", "session", principal_id="principal"
    )
    await db.close()


async def test_operation_approval_is_one_shot_across_connections(tmp_path):
    path = tmp_path / "khaos.db"
    first_db = Database(path)
    second_db = Database(path)
    await first_db.connect()
    await first_db.run_migrations()
    await second_db.connect()
    await second_db.run_migrations()
    binding = _binding()
    first = ApprovalBroker(db=first_db)
    second = ApprovalBroker(db=second_db)
    await first.register_operation("approval", binding, binding["expiry"])
    assert await first.approve_operation(
        "approval", "session", principal_id="principal"
    )

    results = await asyncio.gather(
        first.consume_operation("approval", binding),
        second.consume_operation("approval", binding),
    )
    assert sorted(results) == [False, True]
    await first_db.close()
    await second_db.close()


async def test_cancelled_operation_remains_invalid_after_restart(tmp_path):
    path = tmp_path / "khaos.db"
    db = Database(path)
    await db.connect()
    await db.run_migrations()
    binding = _binding()
    broker = ApprovalBroker(db=db)
    await broker.register_operation("approval", binding, binding["expiry"])
    assert await broker.approve_operation(
        "approval", "session", principal_id="principal"
    )
    await broker.cancel_operation("approval")
    await db.close()

    restarted_db = Database(path)
    await restarted_db.connect()
    restarted = ApprovalBroker(db=restarted_db)
    assert not await restarted.consume_operation("approval", binding)
    events = await restarted_db.list_operation_approval_events("approval")
    assert [event["event_type"] for event in events] == [
        "registered", "approved", "cancelled", "consume-rejected",
    ]
    await restarted_db.close()


def _binding(*, expiry: float | None = None) -> dict:
    return {
        "principal_id": "principal",
        "session_id": "session",
        "requester": "session",
        "task_id": "task",
        "workspace_id": "workspace",
        "operation": "git.undo",
        "target": "HEAD~1",
        "head": "a" * 40,
        "diff_hash": "b" * 64,
        "arguments_digest": "c" * 64,
        "profile_digest": "d" * 64,
        "expiry": expiry or time.time() + 60,
    }
