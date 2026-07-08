"""Orchestrator tools: spawn subagents, collect results, manage task plans.

Phase 8.3 — exposes the subagent spawner/runner as tool handlers so the
Orchestrator agent (or any agent in office/coding mode) can drive parallel
subagent execution through the normal tool-calling interface.

Dependencies (``SubAgentSpawner`` / ``SubAgentRunner``) are injected once at
startup via :func:`init_orchestrator` and held in module-level globals. This
mirrors how other tool modules (e.g. ``browser_tools``) receive their runtime
state, keeping the handler signatures compatible with the scheduler.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from khaos.subagents.runner import SubAgentRunner
    from khaos.subagents.spawner import SubAgentSpawner

logger = logging.getLogger(__name__)

# 全局引用，在 create_runtime_registry / 应用启动时通过 init_orchestrator 注入。
_spawner: Optional["SubAgentSpawner"] = None
_runner: Optional["SubAgentRunner"] = None


def init_orchestrator(spawner: "SubAgentSpawner", runner: "SubAgentRunner") -> None:
    """初始化 orchestrator 工具的全局依赖。

    在应用启动时调用一次，传入 SubAgentSpawner 和 SubAgentRunner 实例。
    重复调用会覆盖旧引用（便于测试重置）。
    """
    global _spawner, _runner
    _spawner = spawner
    _runner = runner


def _task_to_dict(task) -> dict[str, Any]:
    """把 SubAgentTask 序列化为工具返回结构。"""
    return {
        "task_id": task.id,
        "goal": task.goal,
        "status": task.status,
        "result": task.result,
        "error": task.error,
    }


async def spawn_subagent(
    goal: str,
    context: str = "",
    tools: list[str] | None = None,
    timeout: int = 300,
) -> dict[str, Any]:
    """启动一个子代理执行指定任务。

    参数：
    - goal: 子任务描述
    - context: 额外上下文信息
    - tools: 子代理可用的工具列表（None / 空列表表示使用全部）
    - timeout: 超时秒数

    返回：
        ``{"ok": True, "task_id": "...", "status": "running"}``
        或 ``{"ok": False, "error": "..."}``
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    from khaos.subagents.spawner import SubAgentTask

    task = SubAgentTask(
        id="",  # 由 spawner 自动生成 task_N
        goal=goal,
        context=context,
        tools=tools or [],
        timeout=timeout,
        parent_session_id="orchestrator",
        depth=1,
    )
    try:
        result = await _spawner.spawn(task)
        return {"ok": True, "task_id": result.id, "status": "running"}
    except Exception as exc:  # noqa: BLE001 — 工具层兜底，转为结构化错误
        logger.error("Failed to spawn subagent: %s", exc)
        return {"ok": False, "error": str(exc)}


async def collect_results() -> dict[str, Any]:
    """等待所有子任务完成并收集结果。

    返回：
        ``{"ok": True, "results": [...], "total": int, "completed": int, "failed": int}``
        或 ``{"ok": False, "error": "..."}``
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    try:
        tasks = await _spawner.wait_all(timeout=600)
        results = [_task_to_dict(task) for task in tasks]
        completed = sum(1 for r in results if r["status"] == "completed")
        failed = sum(1 for r in results if r["status"] == "failed")
        return {
            "ok": True,
            "results": results,
            "total": len(tasks),
            "completed": completed,
            "failed": failed,
        }
    except Exception as exc:  # noqa: BLE001 — wait_all 超时等异常转为结构化错误
        logger.error("Failed to collect results: %s", exc)
        return {"ok": False, "error": str(exc)}


async def execute_plan(plan_json: str) -> dict[str, Any]:
    """执行一个任务计划（JSON 格式）。

    参数：
    - plan_json: TaskPlanner.from_json() 可解析的 JSON 字符串

    返回：
        ``{"ok": True, "plan_id": "...", "results": [...], "total": int,
           "completed": int, "failed": int}``
        或 ``{"ok": False, "error": "..."}``
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    from khaos.subagents.planner import TaskPlanner

    plan = TaskPlanner.from_json(plan_json)
    if plan is None:
        return {"ok": False, "error": "Invalid plan JSON: failed to parse"}

    try:
        tasks = await TaskPlanner.execute_plan(plan, _spawner)
        results = [_task_to_dict(task) for task in tasks]
        completed = sum(1 for r in results if r["status"] == "completed")
        failed = sum(1 for r in results if r["status"] == "failed")
        return {
            "ok": True,
            "plan_id": plan.id,
            "results": results,
            "total": len(tasks),
            "completed": completed,
            "failed": failed,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to execute plan: %s", exc)
        return {"ok": False, "error": str(exc)}


async def subagent_status() -> dict[str, Any]:
    """查看当前所有子任务状态（不等待）。

    返回：
        ``{"ok": True, "stats": {"active": int, "total": int, "completed": int,
           "failed": int, "pending": int}}``
        或 ``{"ok": False, "error": "..."}``
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}
    return {"ok": True, "stats": _spawner.stats()}
