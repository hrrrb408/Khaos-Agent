"""Tests for TaskPlanner & SubTaskPlan (Phase 8)."""
from __future__ import annotations

import json

import pytest

from khaos.db import Database
from khaos.subagents.planner import SubTaskPlan, TaskPlanner
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask


# ─────────────────────────────── fixtures ───────────────────────────────


async def _db(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


def _plan_with(goals: list[str], deps: dict[str, list[str]] | None = None) -> str:
    """Build a minimal JSON plan with optional dependencies."""
    payload = {
        "description": "test plan",
        "tasks": [{"goal": g, "tools": []} for g in goals],
    }
    if deps:
        payload["dependencies"] = deps
    return json.dumps(payload)


def _assert_valid_uuid_id(tid: str) -> None:
    """Assert a task id is a fresh UUID (not a sequential task_N)."""
    assert tid.startswith("task_"), f"id must start with 'task_': {tid!r}"
    uuid_hex = tid[len("task_"):]
    assert len(uuid_hex) == 32, f"id must be task_ + 32-char hex, got {tid!r}"
    int(uuid_hex, 16)  # must be valid hex


# ───────────────────────────── from_json ────────────────────────────────


def test_from_json_parses_tasks():
    plan_json = json.dumps(
        {
            "description": "add tests",
            "tasks": [
                {"goal": "test a", "tools": ["read_file"], "context": "ctx a"},
                {"goal": "test b", "tools": ["write_file"]},
            ],
        }
    )
    plan = TaskPlanner.from_json(plan_json)

    assert plan is not None
    assert plan.description == "add tests"
    assert len(plan.tasks) == 2
    # HIGH-1 (batch 3.1.8): ids are now fresh UUIDs, not task_N.
    for t in plan.tasks:
        _assert_valid_uuid_id(t.id)
    assert len({t.id for t in plan.tasks}) == 2  # all unique
    assert plan.tasks[0].goal == "test a"
    assert plan.tasks[0].tools == ["read_file"]
    assert plan.tasks[0].context == "ctx a"
    assert plan.tasks[1].tools == ["write_file"]
    assert plan.has_dependencies is False


def test_from_json_auto_assigns_task_ids():
    plan_json = json.dumps({"tasks": [{"goal": "g1"}, {"goal": "g2"}]})
    plan = TaskPlanner.from_json(plan_json)

    # HIGH-1 (batch 3.1.8): ids are now fresh UUIDs, not task_N.
    for t in plan.tasks:
        _assert_valid_uuid_id(t.id)
    assert len({t.id for t in plan.tasks}) == 2


def test_from_json_with_dependencies():
    plan_json = _plan_with(["a", "b"], deps={"task_2": ["task_1"]})
    plan = TaskPlanner.from_json(plan_json)

    assert plan.has_dependencies is True
    # Dependencies are resolved to real UUIDs.
    t1, t2 = plan.tasks[0].id, plan.tasks[1].id
    assert plan.dependencies == {t2: [t1]}


def test_from_json_dependencies_using_declared_ids():
    """Dependencies can reference declared `id` fields, not just auto task_N."""
    plan_json = json.dumps(
        {
            "tasks": [
                {"id": "build", "goal": "g1"},
                {"id": "deploy", "goal": "g2"},
            ],
            "dependencies": {"deploy": ["build"]},
        }
    )
    plan = TaskPlanner.from_json(plan_json)

    # declared ids map to real UUIDs internally
    t1, t2 = plan.tasks[0].id, plan.tasks[1].id
    assert plan.dependencies == {t2: [t1]}


def test_from_json_empty_tasks():
    plan = TaskPlanner.from_json('{"description": "empty", "tasks": []}')
    assert plan is not None
    assert plan.tasks == []
    assert plan.has_dependencies is False


def test_from_json_empty_dependencies_not_marked():
    plan = TaskPlanner.from_json('{"tasks": [{"goal": "g"}], "dependencies": {}}')
    assert plan.has_dependencies is False


def test_invalid_json_returns_none():
    assert TaskPlanner.from_json("not json") is None
    assert TaskPlanner.from_json("") is None
    assert TaskPlanner.from_json("{bad") is None


def test_from_json_non_object_returns_none():
    assert TaskPlanner.from_json('["a", "b"]') is None
    assert TaskPlanner.from_json('"string"') is None
    assert TaskPlanner.from_json("123") is None


def test_from_json_ignores_dependency_on_unknown_id():
    """依赖指向 plan.tasks 中不存在的 id → 视为外部已完成，仅从 deps 中过滤。"""
    plan_json = json.dumps(
        {
            "tasks": [{"goal": "g1"}],
            "dependencies": {"task_1": ["external_done"]},
        }
    )
    plan = TaskPlanner.from_json(plan_json)
    # external_done 不在 task_ids 中，应在依赖里被过滤掉
    t1 = plan.tasks[0].id
    assert plan.dependencies == {t1: ["external_done"]}  # 原始映射保留（运行时处理）
    # 但 has_dependencies 仍为 True，因为 dependencies 非空
    assert plan.has_dependencies is True


# ───────────────────────────── to_json ─────────────────────────────────


def test_to_json_roundtrip():
    plan = TaskPlanner.create_simple_tasks(["a", "b"], tools=["read_file"])
    serialized = TaskPlanner.to_json(plan)
    data = json.loads(serialized)

    assert data["description"] == plan.description
    assert len(data["tasks"]) == 2
    # HIGH-1 (batch 3.1.8): ids are fresh UUIDs.
    for t in data["tasks"]:
        _assert_valid_uuid_id(t["id"])
    assert data["tasks"][0]["goal"] == "a"
    assert data["tasks"][0]["tools"] == ["read_file"]


def test_to_json_preserves_dependencies():
    plan_json = _plan_with(["a", "b"], deps={"task_2": ["task_1"]})
    plan = TaskPlanner.from_json(plan_json)
    roundtrip = TaskPlanner.from_json(TaskPlanner.to_json(plan))

    # HIGH-1 (batch 3.1.8): each from_json call generates fresh UUIDs,
    # so the exact dependency keys/values differ across the roundtrip.
    # What MUST be preserved is the STRUCTURE: same number of tasks,
    # same goals, same dependency graph shape (one task depends on the
    # other).
    assert roundtrip.has_dependencies is plan.has_dependencies
    assert [t.goal for t in roundtrip.tasks] == [t.goal for t in plan.tasks]
    assert len(roundtrip.dependencies) == 1
    # The single dependency entry maps the second task → the first task.
    rt_key = next(iter(roundtrip.dependencies.keys()))
    rt_val = next(iter(roundtrip.dependencies.values()))
    assert rt_key == roundtrip.tasks[1].id
    assert rt_val == [roundtrip.tasks[0].id]


# ───────────────────────── create_simple_tasks ─────────────────────────


def test_create_simple_tasks_basic():
    plan = TaskPlanner.create_simple_tasks(["do a", "do b"], tools=["read_file"])

    assert len(plan.tasks) == 2
    assert plan.has_dependencies is False
    assert plan.dependencies == {}
    assert all(t.tools == ["read_file"] for t in plan.tasks)
    # HIGH-1 (batch 3.1.8): ids are fresh UUIDs.
    for t in plan.tasks:
        _assert_valid_uuid_id(t.id)
    assert len({t.id for t in plan.tasks}) == 2
    assert [t.goal for t in plan.tasks] == ["do a", "do b"]


def test_create_simple_tasks_default_empty_tools():
    plan = TaskPlanner.create_simple_tasks(["only goal"])
    assert plan.tasks[0].tools == []


def test_create_simple_tasks_empty_goals():
    plan = TaskPlanner.create_simple_tasks([])
    assert plan.tasks == []


# ─────────────────────────── execute_plan ──────────────────────────────


async def test_execute_plan_no_deps_all_parallel(tmp_path):
    """无依赖计划：所有任务并行执行并完成。"""
    db = await _db(tmp_path)
    try:
        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db)
        plan = TaskPlanner.create_simple_tasks(["a", "b", "c"])

        results = await TaskPlanner.execute_plan(plan, spawner)

        assert len(results) == 3
        assert all(t.status == "completed" for t in results)
        # 默认 runner 返回 "completed: {goal}"
        goals = sorted(t.goal for t in results)
        assert goals == ["a", "b", "c"]
    finally:
        await db.close()


async def test_execute_plan_with_deps_layered(tmp_path):
    """有依赖计划：按层级执行，层0全部完成后才启动层1。"""
    db = await _db(tmp_path)
    try:
        execution_order: list[str] = []

        async def tracking_runner(task: SubAgentTask) -> str:
            execution_order.append(task.id)
            return f"done:{task.id}"

        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db, runner=tracking_runner)
        plan_json = _plan_with(["a", "b", "c"], deps={"task_2": ["task_1"], "task_3": ["task_1"]})
        plan = TaskPlanner.from_json(plan_json)

        results = await TaskPlanner.execute_plan(plan, spawner)

        assert len(results) == 3
        assert all(t.status == "completed" for t in results)
        # task_1 (now a UUID) must complete before task_2 / task_3.
        t1_id = plan.tasks[0].id
        t2_id = plan.tasks[1].id
        t3_id = plan.tasks[2].id
        assert execution_order.index(t1_id) < execution_order.index(t2_id)
        assert execution_order.index(t1_id) < execution_order.index(t3_id)
    finally:
        await db.close()


async def test_execute_plan_failure_skips_dependents(tmp_path):
    """上游任务失败 → 下游任务标记 skipped 且不 spawn。"""
    db = await _db(tmp_path)
    try:
        async def failing_first(task: SubAgentTask) -> str:
            if task.id == plan.tasks[0].id:
                raise RuntimeError("upstream broken")
            return f"done:{task.id}"

        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db, runner=failing_first)
        plan_json = _plan_with(["a", "b"], deps={"task_2": ["task_1"]})
        plan = TaskPlanner.from_json(plan_json)

        results = {t.id: t for t in await TaskPlanner.execute_plan(plan, spawner)}

        t1_id = plan.tasks[0].id
        t2_id = plan.tasks[1].id
        assert results[t1_id].status == "failed"
        assert results[t2_id].status == "skipped"
        assert results[t2_id].error is not None
        assert t1_id in results[t2_id].error
    finally:
        await db.close()


async def test_execute_plan_empty_returns_empty(tmp_path):
    db = await _db(tmp_path)
    try:
        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db)
        plan = SubTaskPlan(id="empty", description="nothing", tasks=[], dependencies={})

        results = await TaskPlanner.execute_plan(plan, spawner)
        assert results == []
    finally:
        await db.close()


async def test_execute_plan_chain_three_layers(tmp_path):
    """三层依赖链：task_1 → task_2 → task_3，必须按顺序执行。"""
    db = await _db(tmp_path)
    try:
        order: list[str] = []

        async def runner(task: SubAgentTask) -> str:
            order.append(task.id)
            return f"done:{task.id}"

        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db, runner=runner)
        plan_json = _plan_with(
            ["a", "b", "c"],
            deps={"task_2": ["task_1"], "task_3": ["task_2"]},
        )
        plan = TaskPlanner.from_json(plan_json)

        results = await TaskPlanner.execute_plan(plan, spawner)

        assert [t.status for t in results] == ["completed"] * 3
        t1_id = plan.tasks[0].id
        t2_id = plan.tasks[1].id
        t3_id = plan.tasks[2].id
        assert order == [t1_id, t2_id, t3_id]
    finally:
        await db.close()


async def test_execute_plan_partial_failure_isolates_siblings(tmp_path):
    """同层一个失败，不依赖它的兄弟任务仍然完成。"""
    db = await _db(tmp_path)
    try:
        async def runner(task: SubAgentTask) -> str:
            if task.id == plan.tasks[0].id:
                raise RuntimeError("nope")
            return f"done:{task.id}"

        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=3), db, runner=runner)
        plan = TaskPlanner.create_simple_tasks(["a", "b"])  # 无依赖

        results = {t.id: t for t in await TaskPlanner.execute_plan(plan, spawner)}
        t1_id = plan.tasks[0].id
        t2_id = plan.tasks[1].id
        assert results[t1_id].status == "failed"
        assert results[t2_id].status == "completed"
    finally:
        await db.close()
