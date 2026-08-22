"""Contract tests for the scheduler and tool-operation SQL owners."""

import pytest
from khaos.db import Database
from khaos.db.repositories.scheduler import SchedulerRepository
from khaos.db.repositories.tool_operations import ToolOperationRepository


async def _open_database(tmp_path):
    database = Database(tmp_path / "khaos.db")
    await database.connect()
    await database.run_migrations()
    return database


async def test_scheduler_repository_enforces_owner_scope_and_cas(tmp_path):
    database = await _open_database(tmp_path)
    repository = SchedulerRepository(database)

    with pytest.raises(ValueError, match="principal_id"):
        await repository.insert_scheduled_task(
            "unowned", "prompt", "pending", {}, project_id="project-a"
        )

    task_id = await repository.insert_scheduled_task(
        "owned",
        "prompt",
        "pending",
        {"interval_seconds": 60},
        principal_id="alice",
        project_id="project-a",
        policy_digest="policy-a",
    )
    assert await repository.get_scheduled_task(
        task_id, principal_id="bob", project_id="project-a"
    ) is None
    rows = await repository.list_scheduled_tasks(
        principal_id="alice", project_id="project-a"
    )
    assert [row["id"] for row in rows] == [task_id]

    assert await repository.claim_scheduled_task(
        task_id,
        execution_id="execution-1",
        started_at="2026-01-01T00:00:00",
        lease_until="2026-01-01T00:01:00",
        expected_version=0,
        expected_principal_id="alice",
        expected_project_id="project-a",
        expected_policy_digest="policy-a",
    ) == 1
    assert await repository.finalize_scheduled_task(
        task_id,
        execution_id="execution-1",
        expected_version=0,
        status="completed",
        last_result="ok",
    ) == 1
    assert await repository.finalize_scheduled_task(
        task_id,
        execution_id="execution-1",
        expected_version=0,
        status="failed",
    ) == 0
    await database.close()


async def test_scheduler_journal_preserves_project_identity(tmp_path):
    database = await _open_database(tmp_path)
    repository = SchedulerRepository(database)
    sequence = await repository.insert_scheduler_journal_entry(
        operation_id="operation-1",
        task_id="task-1",
        operation_type="pause",
        desired_status="paused",
        expected_version=0,
        target_version=1,
        principal_id="alice",
        policy_digest="policy-a",
        project_id="project-a",
    )
    entries = await repository.list_pending_scheduler_journal_entries()
    assert entries == [
        {
            "seq": sequence,
            "operation_id": "operation-1",
            "task_id": "task-1",
            "operation_type": "pause",
            "desired_status": "paused",
            "expected_version": 0,
            "target_version": 1,
            "principal_id": "alice",
            "policy_digest": "policy-a",
            "project_id": "project-a",
            "created_at": entries[0]["created_at"],
        }
    ]
    assert await repository.mark_scheduler_journal_applied("operation-1") == 1
    assert await repository.list_pending_scheduler_journal_entries() == []
    await database.close()


async def test_tool_operation_repository_rejects_scope_and_invalid_effect_id(tmp_path):
    database = await _open_database(tmp_path)
    repository = ToolOperationRepository(database)

    claimed = await repository.claim_tool_operation(
        operation_id="operation-1",
        tool_name="file_write",
        arguments_digest="args-a",
        effect_id="effect-1",
        owner_token="owner-1",
        principal_id="alice",
        project_id="project-a",
    )
    assert claimed["state"] == "claimed"
    conflict = await repository.claim_tool_operation(
        operation_id="operation-1",
        tool_name="file_write",
        arguments_digest="args-a",
        effect_id="effect-2",
        owner_token="owner-2",
        principal_id="bob",
        project_id="project-a",
    )
    assert conflict["state"] == "conflict"
    assert "principal_id" in conflict["conflict_reason"]

    with pytest.raises(ValueError, match="effect_id"):
        await repository.update_tool_operation_effect_id(
            operation_id="operation-1", owner_token="owner-1", effect_id="bad\nvalue"
        )
    assert await repository.complete_tool_operation(
        operation_id="operation-1",
        owner_token="owner-1",
        status="completed",
        effect_status="not_applied",
        result_json="{}",
    ) == 1
    await database.close()
