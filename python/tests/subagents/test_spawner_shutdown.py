"""H1 regression: detached SubAgent shutdown ownership.

These tests pin the security boundary the M4 lifecycle audit reopened:
``SubAgentService.Spawn`` returns ``running`` while the Spawner keeps the
task on a detached background ``asyncio.Task``.  Server teardown previously
had no authority over those detached tasks and could dismantle Office /
Browser / Audit / DB under a live subagent run.

Covered contracts:

* ``SubAgentSpawner.shutdown`` cancels and awaits every active task.
* ``spawn`` is rejected once shutdown has begun.
* A cancelled ``_run_task`` persists an explicit ``failed/cancelled``
  terminal row instead of leaving the DB stuck at ``running``.
"""

from __future__ import annotations

import asyncio

import pytest

from khaos.db import Database
from khaos.exceptions import SubAgentLimitError
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask


_PRINCIPAL = "user1"


async def _spawner(tmp_path, runner=None, max_concurrent=3):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=max_concurrent), db, runner=runner
    )
    return db, spawner


# ───────────────────── H1: shutdown cancels active tasks ────────────────────


async def test_spawner_shutdown_cancels_active_task(tmp_path):
    """A blocked subagent must be cancelled and awaited by shutdown()."""
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_runner(task: SubAgentTask) -> str:
        started.set()
        await release.wait()
        return "should-not-reach"

    db, spawner = await _spawner(tmp_path, runner=blocking_runner)
    try:
        await spawner.spawn(
            SubAgentTask("t1", "block", "ctx", [], principal_id=_PRINCIPAL)
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)
        assert len(spawner._active_tasks) == 1

        # shutdown() must cancel + await within the bounded timeout, then
        # drop the task from _active_tasks.
        await spawner.shutdown(timeout=2.0)

        assert spawner._active_tasks == {}
        # The DB row must carry an explicit cancelled terminal state.
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
        # Let the runner's never-reached branch stay unreachable cleanly.
        release.set()
    finally:
        await db.close()


async def test_spawner_rejects_spawn_after_shutdown(tmp_path):
    """Once shutdown has begun, further spawn() calls fail closed."""
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.shutdown(timeout=1.0)
        with pytest.raises(SubAgentLimitError, match="shutting down"):
            await spawner.spawn(
                SubAgentTask("t1", "g", "ctx", [], principal_id=_PRINCIPAL)
            )
    finally:
        await db.close()


async def test_spawner_shutdown_is_idempotent_and_handles_empty(tmp_path):
    """shutdown() with no active tasks is a no-op and can be re-invoked."""
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.shutdown(timeout=1.0)
        await spawner.shutdown(timeout=1.0)
        assert spawner._active_tasks == {}
        assert spawner._shutting_down is True
    finally:
        await db.close()


# ─────────── H1: cancelled _run_task persists failed terminal row ───────────


async def test_cancelled_run_task_persists_failed_state(tmp_path):
    """A cancelled ``_run_task`` must write ``failed/cancelled`` to the DB.

    Previously the ``CancelledError`` branch only re-raised, leaving the DB
    row stuck at ``running`` forever even though the runtime had been torn
    down.  This pins the contract that a cancellation is a terminal
    transition visible to any later ``collect`` / ``status`` query.
    """
    started = asyncio.Event()
    release = asyncio.Event()

    async def blocking_runner(task: SubAgentTask) -> str:
        started.set()
        await release.wait()
        return "should-not-reach"

    db, spawner = await _spawner(tmp_path, runner=blocking_runner)
    try:
        task = await spawner.spawn(
            SubAgentTask("t1", "block", "ctx", [], principal_id=_PRINCIPAL)
        )
        await asyncio.wait_for(started.wait(), timeout=2.0)
        active = spawner._active_tasks[task.id]
        # Cancel the in-flight _run_task; its CancelledError branch must
        # persist the failed/cancelled row BEFORE re-raising.
        active.cancel()
        with pytest.raises(asyncio.CancelledError):
            await active
        rows = await db.list_subagent_tasks()
        assert rows[0]["status"] == "failed"
        assert rows[0]["error"] == "cancelled"
        # In-memory task object reflects the same terminal transition.
        assert spawner._tasks[task.id].status == "failed"
        assert spawner._tasks[task.id].error == "cancelled"
        release.set()
    finally:
        await db.close()
