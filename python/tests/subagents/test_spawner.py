"""Tests for Phase 8 SubAgentSpawner enhancements: spawn_batch + stats + nesting.

Existing spawn/cancel/wait_all behaviour is covered by test_subagent_spawner.py.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from khaos.db import Database
from khaos.exceptions import SubAgentLimitError
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask
from khaos.tools.registry import create_builtin_registry


# M2: the spawner now returns NOTHING for an empty principal_id (defense
# in depth).  Tests that spawn tasks and then wait / collect / stat must
# stamp the tasks with a non-empty principal_id and pass the same value
# to wait_all / stats.
_PRINCIPAL = "user1"


async def _spawner(tmp_path, runner=None, max_concurrent=3, registry=None, config=None):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    cfg = config or SubAgentConfig(max_concurrent=max_concurrent)
    spawner = SubAgentSpawner(cfg, db, runner=runner, registry=registry)
    return db, spawner


# ───────────────────────────── spawn_batch ──────────────────────────────


async def test_spawn_batch_all_succeed(tmp_path):
    db, spawner = await _spawner(tmp_path, max_concurrent=3)
    try:
        tasks = [
            SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL),
            SubAgentTask("t2", "two", "ctx", [], principal_id=_PRINCIPAL),
            SubAgentTask("t3", "three", "ctx", [], principal_id=_PRINCIPAL),
        ]
        spawned = await spawner.spawn_batch(tasks)
        await spawner.wait_all(principal_id=_PRINCIPAL)

        assert len(spawned) == 3
        assert all(t.status == "completed" for t in spawned)
    finally:
        await db.close()


async def test_spawn_batch_over_limit_skips_extras(tmp_path):
    """批量超过并发上限时，超出部分被跳过且不抛异常。"""
    db, spawner = await _spawner(tmp_path, max_concurrent=2)
    try:
        tasks = [
            SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL),
            SubAgentTask("t2", "two", "ctx", [], principal_id=_PRINCIPAL),
            SubAgentTask("t3", "three", "ctx", [], principal_id=_PRINCIPAL),
            SubAgentTask("t4", "four", "ctx", [], principal_id=_PRINCIPAL),
        ]
        spawned = await spawner.spawn_batch(tasks)
        await spawner.wait_all(principal_id=_PRINCIPAL)

        # 并发上限 2 → 只有 2 个被 spawn
        assert len(spawned) == 2
        spawned_ids = {t.id for t in spawned}
        assert spawned_ids.issubset({"t1", "t2", "t3", "t4"})
    finally:
        await db.close()


async def test_spawn_batch_empty_returns_empty(tmp_path):
    db, spawner = await _spawner(tmp_path)
    try:
        spawned = await spawner.spawn_batch([])
        assert spawned == []
    finally:
        await db.close()


async def test_spawn_batch_when_concurrency_full(tmp_path):
    """已有 active 任务占满并发，spawn_batch 应跳过全部。"""
    async def slow(task):
        await asyncio.sleep(0.1)
        return "ok"

    db, spawner = await _spawner(tmp_path, runner=slow, max_concurrent=1)
    try:
        await spawner.spawn(SubAgentTask("t1", "running", "ctx", [], principal_id=_PRINCIPAL))
        spawned = await spawner.spawn_batch(
            [SubAgentTask("t2", "queued", "ctx", [], principal_id=_PRINCIPAL)]
        )
        await spawner.wait_all(principal_id=_PRINCIPAL)

        assert spawned == []
    finally:
        await db.close()


# ──────────────────────────────── stats ─────────────────────────────────


async def test_stats_initial(tmp_path):
    db, spawner = await _spawner(tmp_path)
    try:
        stats = spawner.stats()
        assert stats == {"active": 0, "total": 0, "completed": 0, "failed": 0, "pending": 0}
    finally:
        await db.close()


async def test_stats_after_completion(tmp_path):
    db, spawner = await _spawner(tmp_path)
    try:
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
        await spawner.spawn(SubAgentTask("t2", "two", "ctx", [], principal_id=_PRINCIPAL))
        await spawner.wait_all(principal_id=_PRINCIPAL)

        stats = spawner.stats(principal_id=_PRINCIPAL)
        assert stats["total"] == 2
        assert stats["completed"] == 2
        assert stats["active"] == 0
        assert stats["failed"] == 0
        assert stats["pending"] == 0
    finally:
        await db.close()


async def test_stats_counts_failed(tmp_path):
    async def fail(task):
        raise RuntimeError("boom")

    db, spawner = await _spawner(tmp_path, runner=fail)
    try:
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
        await spawner.wait_all(principal_id=_PRINCIPAL)

        stats = spawner.stats(principal_id=_PRINCIPAL)
        assert stats["total"] == 1
        assert stats["failed"] == 1
        assert stats["completed"] == 0
    finally:
        await db.close()


async def test_stats_active_while_running(tmp_path):
    async def slow(task):
        await asyncio.sleep(0.1)
        return "ok"

    db, spawner = await _spawner(tmp_path, runner=slow)
    try:
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", [], principal_id=_PRINCIPAL))
        # 不等待：此刻应有一条 active 任务
        stats = spawner.stats(principal_id=_PRINCIPAL)
        assert stats["active"] == 1
        assert stats["total"] == 1
        await spawner.wait_all(principal_id=_PRINCIPAL)
    finally:
        await db.close()


# ──────────────────────────── nesting rules ─────────────────────────────


async def test_nested_depth2_rejected_by_default(tmp_path):
    """默认 allow_nesting=False：depth=2 必须被拒绝（ADR-002 单层语义）。"""
    db, spawner = await _spawner(tmp_path)
    try:
        with pytest.raises(SubAgentLimitError):
            await spawner.spawn(SubAgentTask("t1", "nested", "ctx", [], depth=2))
    finally:
        await db.close()


async def test_nested_allowed_when_allow_nesting_true(tmp_path):
    """allow_nesting=True + max_spawn_depth=2：depth=2 允许。"""
    config = SubAgentConfig(max_concurrent=3, max_spawn_depth=2, allow_nesting=True)
    db, spawner = await _spawner(tmp_path, config=config)
    try:
        task = await spawner.spawn(
            SubAgentTask("t1", "nested", "ctx", [], depth=2, principal_id=_PRINCIPAL)
        )
        await spawner.wait_all(principal_id=_PRINCIPAL)
        assert task.status == "completed"
    finally:
        await db.close()


async def test_nested_exceeds_max_depth_even_when_allowed(tmp_path):
    """allow_nesting=True 但 depth > max_spawn_depth 仍被拒绝。"""
    config = SubAgentConfig(max_concurrent=3, max_spawn_depth=2, allow_nesting=True)
    db, spawner = await _spawner(tmp_path, config=config)
    try:
        with pytest.raises(SubAgentLimitError):
            await spawner.spawn(SubAgentTask("t1", "deep", "ctx", [], depth=3))
    finally:
        await db.close()


# ────────────────────────── tool validation ─────────────────────────────


async def test_spawn_validates_unknown_tool(tmp_path):
    """传入 registry 后，spawn 校验 task.tools 中工具是否已注册。"""
    registry = create_builtin_registry()
    db, spawner = await _spawner(tmp_path, registry=registry)
    try:
        with pytest.raises(SubAgentLimitError):
            await spawner.spawn(SubAgentTask("t1", "g", "ctx", ["does_not_exist"]))
    finally:
        await db.close()


async def test_spawn_accepts_registered_tools(tmp_path):
    registry = create_builtin_registry()
    db, spawner = await _spawner(tmp_path, registry=registry)
    try:
        task = await spawner.spawn(
            SubAgentTask(
                "t1", "g", "ctx", ["read_file", "search_files"], principal_id=_PRINCIPAL
            )
        )
        await spawner.wait_all(principal_id=_PRINCIPAL)
        assert task.status == "completed"
    finally:
        await db.close()


async def test_spawn_without_registry_skips_validation(tmp_path):
    """未传入 registry 时不做校验（保持向后兼容）。"""
    db, spawner = await _spawner(tmp_path, registry=None)
    try:
        # 即使工具名不存在，也不会报错
        task = await spawner.spawn(
            SubAgentTask("t1", "g", "ctx", ["anything"], principal_id=_PRINCIPAL)
        )
        await spawner.wait_all(principal_id=_PRINCIPAL)
        assert task.status == "completed"
    finally:
        await db.close()


# ────────────────────────── auto task id ────────────────────────────────


async def test_spawn_generates_task_id_when_empty(tmp_path):
    db, spawner = await _spawner(tmp_path)
    try:
        task = SubAgentTask("", "g", "ctx", [], principal_id=_PRINCIPAL)
        await spawner.spawn(task)
        await spawner.wait_all(principal_id=_PRINCIPAL)
        # M3: task IDs are now UUID4 (``task_{uuid.uuid4().hex}``).
        assert task.id.startswith("task_")
        assert task.id != ""
        # UUID4 hex is 32 chars; ``task_`` prefix is 5 chars.
        assert len(task.id) == 5 + 32
    finally:
        await db.close()


# ─────────────────── HIGH-1 (batch 3.1.8): duplicate id rejection ──────


async def test_spawn_rejects_duplicate_id(tmp_path):
    """HIGH-1 (batch 3.1.8): the spawner MUST refuse a task whose id
    already exists in ``_tasks``.  Without this, a caller that supplies
    its own non-unique id would overwrite the existing
    ``_tasks`` / ``_initializing_owners`` entries, re-opening the
    ``max_concurrent`` bypass and the initializing-owner loss.
    """
    db, spawner = await _spawner(tmp_path, max_concurrent=3)
    try:
        # First task with a fixed id — accepted.
        task1 = SubAgentTask(
            "task_fixed_duplicate", "g1", "ctx", [],
            principal_id=_PRINCIPAL,
        )
        await spawner.spawn(task1)
        await spawner.wait_all(principal_id=_PRINCIPAL)
        assert task1.id == "task_fixed_duplicate"

        # Second task with the SAME id — must raise SubAgentLimitError.
        task2 = SubAgentTask(
            "task_fixed_duplicate", "g2", "ctx", [],
            principal_id=_PRINCIPAL,
        )
        with pytest.raises(SubAgentLimitError, match="already exists"):
            await spawner.spawn(task2)

        # The original task is still there (not overwritten).
        assert "task_fixed_duplicate" in spawner._tasks
        assert spawner._tasks["task_fixed_duplicate"] is task1
    finally:
        await db.close()


async def test_two_concurrent_plans_with_same_logical_ids_get_distinct_uuids(
    tmp_path,
):
    """HIGH-1 (batch 3.1.8): two concurrent plans that both declare
    ``task_1`` / ``task_2`` must produce DISTINCT global UUIDs in the
    spawner — otherwise the second reservation overwrites the first
    ``_tasks`` / ``_initializing_owners`` entry, re-opening the
    ``max_concurrent`` bypass and the initializing-owner loss.

    The planner maps each logical id (``task_N`` or any declared id)
    to a fresh ``task_{uuid.uuid4().hex}``; the spawner refuses
    duplicates as defense in depth.  This test verifies the end-to-end
    contract: two plans with identical logical ids can be spawned
    concurrently without collision.
    """
    from khaos.subagents.planner import TaskPlanner

    db, spawner = await _spawner(tmp_path, max_concurrent=10)
    try:
        # Two plans with identical logical ids.
        plan_a = TaskPlanner.from_json(
            json.dumps({
                "description": "plan a",
                "tasks": [
                    {"goal": "a1", "tools": []},
                    {"goal": "a2", "tools": []},
                ],
            })
        )
        plan_b = TaskPlanner.from_json(
            json.dumps({
                "description": "plan b",
                "tasks": [
                    {"goal": "b1", "tools": []},
                    {"goal": "b2", "tools": []},
                ],
            })
        )
        # Both plans have logical ids task_1, task_2 — but the
        # real_ids must be distinct UUIDs.
        ids_a = {t.id for t in plan_a.tasks}
        ids_b = {t.id for t in plan_b.tasks}
        # Within each plan, ids are unique.
        assert len(ids_a) == 2
        assert len(ids_b) == 2
        # Across plans, ids are disjoint (no collision).
        assert ids_a.isdisjoint(ids_b), (
            f"plans share task ids: {ids_a & ids_b}"
        )
        # All ids are fresh UUIDs (not bare task_1 / task_2).
        for tid in ids_a | ids_b:
            assert tid.startswith("task_")
            uuid_hex = tid[len("task_"):]
            assert len(uuid_hex) == 32
            int(uuid_hex, 16)

        # Spawn all tasks from both plans concurrently.  No
        # SubAgentLimitError should be raised (all ids are distinct).
        for task in list(plan_a.tasks) + list(plan_b.tasks):
            task.principal_id = _PRINCIPAL
            await spawner.spawn(task)
        await spawner.wait_all(principal_id=_PRINCIPAL)

        # All four tasks are tracked in the spawner with distinct ids.
        assert len(spawner._tasks) == 4
        all_ids = {t.id for t in spawner._tasks.values()}
        assert all_ids == ids_a | ids_b
    finally:
        await db.close()
