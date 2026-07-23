"""Tests for the coding task manager."""

from __future__ import annotations

import asyncio

import pytest

from khaos.coding.task_manager import (
    ACTIVE_STATUSES,
    CodingTask,
    TaskManager,
    TaskStatus,
    TransitionResult,
)


# ---------------------------------------------------------------------------
# CodingTask serialization
# ---------------------------------------------------------------------------


def test_coding_task_to_dict_has_expected_keys() -> None:
    task = CodingTask(goal="fix bug")
    data = task.to_dict()
    assert set(data) == {
        "id",
        "goal",
        "status",
        "created_at",
        "updated_at",
        "files_modified",
        "files_viewed",
        "test_results",
        "fix_attempts",
        "error",
    }
    assert data["goal"] == "fix bug"
    assert data["status"] == "pending"
    assert data["fix_attempts"] == 0


def test_to_dict_serialization_is_json_safe() -> None:
    """to_dict output must survive a json round-trip."""
    import json

    task = CodingTask(
        goal="refactor",
        files_modified=["a.py", "b.py"],
        test_results=[{"success": True}],
        fix_attempts=2,
    )
    data = task.to_dict()
    # Should not raise.
    encoded = json.dumps(data)
    decoded = json.loads(encoded)
    assert decoded["goal"] == "refactor"
    assert decoded["files_modified"] == ["a.py", "b.py"]


# ---------------------------------------------------------------------------
# TaskManager lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_task() -> None:
    manager = TaskManager()
    task = await manager.create("implement feature X")

    assert task.status == TaskStatus.PENDING
    assert task.goal == "implement feature X"
    assert task.id  # non-empty id


@pytest.mark.asyncio
async def test_get_returns_created_task() -> None:
    manager = TaskManager()
    created = await manager.create("do thing")
    fetched = await manager.get(created.id)
    assert fetched is created


@pytest.mark.asyncio
async def test_get_unknown_returns_none() -> None:
    manager = TaskManager()
    assert await manager.get("nope") is None


@pytest.mark.asyncio
async def test_update_status_transition() -> None:
    manager = TaskManager()
    task = await manager.create("work")

    await manager.update_status(task.id, TaskStatus.RUNNING)
    assert (await manager.get(task.id)).status == TaskStatus.RUNNING

    # String form is accepted too.
    await manager.update_status(task.id, "fixing", fix_attempts=1)
    refreshed = await manager.get(task.id)
    assert refreshed.status == TaskStatus.FIXING
    assert refreshed.fix_attempts == 1


@pytest.mark.asyncio
async def test_update_status_unknown_task_is_noop() -> None:
    manager = TaskManager()
    # Must not raise.
    await manager.update_status("ghost", TaskStatus.RUNNING)


@pytest.mark.asyncio
async def test_add_test_result() -> None:
    manager = TaskManager()
    task = await manager.create("verify")

    await manager.add_test_result(task.id, {"success": False, "failed": 2})
    await manager.add_test_result(task.id, {"success": True, "passed": 10})

    refreshed = await manager.get(task.id)
    assert len(refreshed.test_results) == 2
    assert refreshed.test_results[0]["failed"] == 2
    assert refreshed.test_results[1]["passed"] == 10


@pytest.mark.asyncio
async def test_add_test_result_caps_history() -> None:
    manager = TaskManager()
    task = await manager.create("many tests")
    for index in range(20):
        await manager.add_test_result(task.id, {"index": index})

    refreshed = await manager.get(task.id)
    # Only the most recent 5 are retained.
    assert len(refreshed.test_results) == 5
    assert refreshed.test_results[-1]["index"] == 19


@pytest.mark.asyncio
async def test_track_file_modified_deduplicates() -> None:
    manager = TaskManager()
    task = await manager.create("edit")

    await manager.track_file_modified(task.id, "a.py")
    await manager.track_file_modified(task.id, "a.py")
    await manager.track_file_modified(task.id, "b.py")

    refreshed = await manager.get(task.id)
    assert refreshed.files_modified == ["a.py", "b.py"]


@pytest.mark.asyncio
async def test_track_file_viewed_deduplicates() -> None:
    manager = TaskManager()
    task = await manager.create("read")

    await manager.track_file_viewed(task.id, "x.py")
    await manager.track_file_viewed(task.id, "x.py")

    assert (await manager.get(task.id)).files_viewed == ["x.py"]


@pytest.mark.asyncio
async def test_list_active_excludes_terminal() -> None:
    manager = TaskManager()
    running = await manager.create("run")
    await manager.update_status(running.id, TaskStatus.RUNNING)

    done = await manager.create("done")
    await manager.update_status(done.id, TaskStatus.COMPLETED)

    failed = await manager.create("fail")
    await manager.update_status(failed.id, TaskStatus.FAILED)

    active = await manager.list_active()
    active_ids = {item["id"] for item in active}
    assert running.id in active_ids
    assert done.id not in active_ids
    assert failed.id not in active_ids


@pytest.mark.asyncio
async def test_list_all_returns_every_task() -> None:
    manager = TaskManager()
    a = await manager.create("a")
    b = await manager.create("b")
    await manager.update_status(b.id, TaskStatus.COMPLETED)

    all_ids = {item["id"] for item in await manager.list_all()}
    assert all_ids == {a.id, b.id}


@pytest.mark.asyncio
async def test_max_active_limit() -> None:
    manager = TaskManager(max_active=2)
    await manager.create("first")
    await manager.create("second")
    with pytest.raises(RuntimeError, match="max active tasks"):
        await manager.create("third")


@pytest.mark.asyncio
async def test_max_active_frees_up_after_completion() -> None:
    manager = TaskManager(max_active=1)
    first = await manager.create("first")
    await manager.update_status(first.id, TaskStatus.COMPLETED)
    # Slot freed → second creation succeeds.
    second = await manager.create("second")
    assert second.status == TaskStatus.PENDING


@pytest.mark.asyncio
async def test_cancel_marks_cancelled() -> None:
    manager = TaskManager()
    task = await manager.create("doomed")
    assert await manager.cancel(task.id) == TransitionResult.UPDATED
    assert (await manager.get(task.id)).status == TaskStatus.CANCELLED
    assert task.id not in {item["id"] for item in await manager.list_active()}


@pytest.mark.asyncio
async def test_task_manager_persists_and_recovers_interrupted_task(tmp_path) -> None:
    from khaos.db import Database

    db = Database(tmp_path / "tasks.db")
    await db.connect()
    await db.run_migrations()
    manager = TaskManager(db=db, principal_id="test-owner")
    task = await manager.create("long work")
    await manager.update_status(task.id, TaskStatus.RUNNING)
    await manager.record_trace(task.id, {"tool_name": "read_file", "arguments": {}, "success": True})
    restored = TaskManager(db=db, principal_id="test-owner")
    await restored.load()
    loaded = await restored.get(task.id)
    assert loaded.status == TaskStatus.BLOCKED
    assert loaded.error == "interrupted by process restart"
    assert loaded.trace[0]["tool_name"] == "read_file"
    await db.close()


@pytest.mark.asyncio
async def test_cancel_unknown_returns_false() -> None:
    manager = TaskManager()
    assert await manager.cancel("ghost") == TransitionResult.NOT_FOUND


def test_task_status_parse_roundtrip() -> None:
    for status in TaskStatus:
        assert TaskStatus.parse(status.value) is status


def test_task_status_parse_invalid_raises() -> None:
    with pytest.raises(ValueError):
        TaskStatus.parse("bogus")


def test_active_statuses_excludes_terminal() -> None:
    for terminal in {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED}:
        assert terminal not in ACTIVE_STATUSES


@pytest.mark.asyncio
async def test_concurrent_access_is_safe() -> None:
    """Parallel create calls must not corrupt internal state."""
    manager = TaskManager(max_active=100)

    async def make(goal: str) -> CodingTask:
        return await manager.create(goal)

    tasks = await asyncio.gather(*(make(f"g{i}") for i in range(20)))
    assert len({t.id for t in tasks}) == 20
    assert len(await manager.list_all()) == 20
