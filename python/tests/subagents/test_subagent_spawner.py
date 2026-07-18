import asyncio

import pytest

from khaos.db import Database
from khaos.exceptions import SubAgentLimitError
from khaos.subagents import SubAgentConfig, SubAgentSpawner, SubAgentTask


async def _spawner(tmp_path, runner=None, max_concurrent=3):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=max_concurrent), db, runner=runner)
    return db, spawner


# M2: the spawner now returns NOTHING for an empty principal_id (defense
# in depth).  Tests that spawn tasks and then wait / collect / stat must
# stamp the tasks with a non-empty principal_id and pass the same value
# to wait_all / collect_results / stats.
_PRINCIPAL = "user1"


async def test_spawn_success_and_persist(tmp_path):
    db, spawner = await _spawner(tmp_path)

    task = await spawner.spawn(
        SubAgentTask("t1", "do work", "ctx", ["read_file"], principal_id=_PRINCIPAL)
    )
    await spawner.wait_all(principal_id=_PRINCIPAL)
    rows = await db.list_subagent_tasks()

    assert task.status == "completed"
    assert task.result == "completed: do work"
    assert rows[0]["status"] == "completed"
    await db.close()


async def test_concurrency_limit(tmp_path):
    async def slow(task):
        await asyncio.sleep(0.05)
        return "ok"

    db, spawner = await _spawner(tmp_path, runner=slow, max_concurrent=1)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))

    with pytest.raises(SubAgentLimitError):
        await spawner.spawn(SubAgentTask("t2", "two", "ctx", [], principal_id=_PRINCIPAL))
    await spawner.wait_all(principal_id=_PRINCIPAL)
    await db.close()


async def test_wait_all_collects_results(tmp_path):
    db, spawner = await _spawner(tmp_path)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
    await spawner.spawn(SubAgentTask("t2", "two", "ctx", [], principal_id=_PRINCIPAL))

    await spawner.wait_all(principal_id=_PRINCIPAL)
    results = await spawner.collect_results(principal_id=_PRINCIPAL)

    assert results == ["completed: one", "completed: two"]
    await db.close()


async def test_cancel_task(tmp_path):
    async def slow(task):
        await asyncio.sleep(1)
        return "ok"

    db, spawner = await _spawner(tmp_path, runner=slow)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))

    await spawner.cancel("t1")

    assert spawner._tasks["t1"].status == "failed"
    assert spawner._tasks["t1"].error == "cancelled"
    await db.close()


async def test_runner_failure_marks_failed(tmp_path):
    async def fail(task):
        raise RuntimeError("boom")

    db, spawner = await _spawner(tmp_path, runner=fail)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
    await spawner.wait_all(principal_id=_PRINCIPAL)

    assert spawner._tasks["t1"].status == "failed"
    assert spawner._tasks["t1"].error == "boom"
    await db.close()


async def test_nested_subagent_rejected(tmp_path):
    db, spawner = await _spawner(tmp_path)

    with pytest.raises(SubAgentLimitError):
        await spawner.spawn(SubAgentTask("t1", "nested", "ctx", [], depth=2))
    await db.close()


async def test_empty_principal_returns_nothing(tmp_path):
    """M2: empty ``principal_id`` returns NOTHING (not all tasks)."""
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
        await spawner.wait_all(principal_id=_PRINCIPAL)

        # Empty principal returns empty stats / tasks / results.
        assert spawner.stats() == {
            "active": 0, "total": 0, "completed": 0, "failed": 0, "pending": 0,
        }
        assert await spawner.collect_results() == []
        assert await spawner.wait_all(principal_id="") == []
    finally:
        await db.close()
