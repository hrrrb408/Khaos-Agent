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


async def test_spawn_success_and_persist(tmp_path):
    db, spawner = await _spawner(tmp_path)

    task = await spawner.spawn(SubAgentTask("t1", "do work", "ctx", ["read_file"]))
    await spawner.wait_all()
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
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))

    with pytest.raises(SubAgentLimitError):
        await spawner.spawn(SubAgentTask("t2", "two", "ctx", []))
    await spawner.wait_all()
    await db.close()


async def test_wait_all_collects_results(tmp_path):
    db, spawner = await _spawner(tmp_path)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))
    await spawner.spawn(SubAgentTask("t2", "two", "ctx", []))

    await spawner.wait_all()
    results = await spawner.collect_results()

    assert results == ["completed: one", "completed: two"]
    await db.close()


async def test_cancel_task(tmp_path):
    async def slow(task):
        await asyncio.sleep(1)
        return "ok"

    db, spawner = await _spawner(tmp_path, runner=slow)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))

    await spawner.cancel("t1")

    assert spawner._tasks["t1"].status == "failed"
    assert spawner._tasks["t1"].error == "cancelled"
    await db.close()


async def test_runner_failure_marks_failed(tmp_path):
    async def fail(task):
        raise RuntimeError("boom")

    db, spawner = await _spawner(tmp_path, runner=fail)
    await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))
    await spawner.wait_all()

    assert spawner._tasks["t1"].status == "failed"
    assert spawner._tasks["t1"].error == "boom"
    await db.close()


async def test_nested_subagent_rejected(tmp_path):
    db, spawner = await _spawner(tmp_path)

    with pytest.raises(SubAgentLimitError):
        await spawner.spawn(SubAgentTask("t1", "nested", "ctx", [], depth=2))
    await db.close()

