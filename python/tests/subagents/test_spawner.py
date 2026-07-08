"""Tests for Phase 8 SubAgentSpawner enhancements: spawn_batch + stats + nesting.

Existing spawn/cancel/wait_all behaviour is covered by test_subagent_spawner.py.
"""
from __future__ import annotations

import asyncio

import pytest

from khaos.db import Database
from khaos.exceptions import SubAgentLimitError
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask
from khaos.tools.registry import create_builtin_registry


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
            SubAgentTask("t1", "one", "ctx", []),
            SubAgentTask("t2", "two", "ctx", []),
            SubAgentTask("t3", "three", "ctx", []),
        ]
        spawned = await spawner.spawn_batch(tasks)
        await spawner.wait_all()

        assert len(spawned) == 3
        assert all(t.status == "completed" for t in spawned)
    finally:
        await db.close()


async def test_spawn_batch_over_limit_skips_extras(tmp_path):
    """批量超过并发上限时，超出部分被跳过且不抛异常。"""
    db, spawner = await _spawner(tmp_path, max_concurrent=2)
    try:
        tasks = [
            SubAgentTask("t1", "one", "ctx", []),
            SubAgentTask("t2", "two", "ctx", []),
            SubAgentTask("t3", "three", "ctx", []),
            SubAgentTask("t4", "four", "ctx", []),
        ]
        spawned = await spawner.spawn_batch(tasks)
        await spawner.wait_all()

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
        await spawner.spawn(SubAgentTask("t1", "running", "ctx", []))
        spawned = await spawner.spawn_batch([SubAgentTask("t2", "queued", "ctx", [])])
        await spawner.wait_all()

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
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))
        await spawner.spawn(SubAgentTask("t2", "two", "ctx", []))
        await spawner.wait_all()

        stats = spawner.stats()
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
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))
        await spawner.wait_all()

        stats = spawner.stats()
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
        await spawner.spawn(SubAgentTask("t1", "one", "ctx", []))
        # 不等待：此刻应有一条 active 任务
        stats = spawner.stats()
        assert stats["active"] == 1
        assert stats["total"] == 1
        await spawner.wait_all()
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
        task = await spawner.spawn(SubAgentTask("t1", "nested", "ctx", [], depth=2))
        await spawner.wait_all()
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
        task = await spawner.spawn(SubAgentTask("t1", "g", "ctx", ["read_file", "search_files"]))
        await spawner.wait_all()
        assert task.status == "completed"
    finally:
        await db.close()


async def test_spawn_without_registry_skips_validation(tmp_path):
    """未传入 registry 时不做校验（保持向后兼容）。"""
    db, spawner = await _spawner(tmp_path, registry=None)
    try:
        # 即使工具名不存在，也不会报错
        task = await spawner.spawn(SubAgentTask("t1", "g", "ctx", ["anything"]))
        await spawner.wait_all()
        assert task.status == "completed"
    finally:
        await db.close()


# ────────────────────────── auto task id ────────────────────────────────


async def test_spawn_generates_task_id_when_empty(tmp_path):
    db, spawner = await _spawner(tmp_path)
    try:
        task = SubAgentTask("", "g", "ctx", [])
        await spawner.spawn(task)
        await spawner.wait_all()
        assert task.id.startswith("task_")
        assert task.id != ""
    finally:
        await db.close()
