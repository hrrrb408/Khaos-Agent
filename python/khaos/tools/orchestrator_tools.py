"""Orchestrator tools: spawn subagents, collect results, manage task plans.

Phase 8.3 — exposes the subagent spawner/runner as tool handlers so the
Orchestrator agent (or any agent in office/coding mode) can drive parallel
subagent execution through the normal tool-calling interface.

Dependencies (``SubAgentSpawner`` / ``SubAgentRunner``) are injected once at
startup via :func:`init_orchestrator` and held in module-level globals. This
mirrors how other tool modules (e.g. ``browser_tools``) receive their runtime
state, keeping the handler signatures compatible with the scheduler.

MEDIUM (batch 3.1.8): the four orchestrator tool handlers now accept a
``principal_id`` keyword parameter (injected by the
``ToolInvocationBroker`` via the ``subagent.spawn`` capability declared in
``registry.py``).  ``spawn_subagent`` stamps the principal on the
``SubAgentTask``; ``collect_results`` / ``subagent_status`` / ``execute_plan``
pass it to ``wait_all`` / ``stats`` / each task in the plan so a principal
only observes its own tasks.  ``spawn_subagent`` also returns the real
post-spawn status (typically ``pending`` / ``initializing``) instead of the
hardcoded ``"running"`` — so a spawn that failed during reservation reports
the actual failure.  ``init_orchestrator`` is now wired in production by
``_build_subagent_service`` (grpc_server.py) so the four handlers no longer
return ``"Orchestrator not initialized"``.

MEDIUM (batch 3.1.9): two further closures.
  1. ``spawn_subagent`` now returns ``ok=false`` when the spawner reports a
     terminal failure status (``failed`` / ``cancelled``) instead of
     ``ok=true`` with ``status="failed"``.  This matches the RPC
     ``SubAgentService`` contract so callers can branch on ``ok`` rather
     than re-checking ``status``.
  2. All four handlers now REFUSE empty ``principal_id`` instead of
     falling back to ``"local-uid:orchestrator"``.  The fallback was
     fail-open: any handler invoked without an authenticated principal
     (e.g. a misconfigured tool context) would silently land all tasks
     under a shared pseudo-principal, bypassing the spawner's
     "empty principal → empty result" defense.  The RPC path already
     requires a principal; the tool path now matches.
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

# MEDIUM (batch 3.1.9): statuses that represent a terminal failure of the
# spawn itself (the task was never started, or was cancelled by a shutdown
# race).  When ``spawn_subagent`` sees one of these on the returned task,
# it returns ``ok=false`` so the caller can branch on ``ok`` rather than
# re-checking ``status``.  Matches the RPC ``SubAgentService`` contract.
_SPAWN_FAILURE_STATUSES = frozenset({"failed", "cancelled"})


def init_orchestrator(spawner: "SubAgentSpawner", runner: "SubAgentRunner") -> None:
    """初始化 orchestrator 工具的全局依赖。

    在应用启动时调用一次，传入 SubAgentSpawner 和 SubAgentRunner 实例。
    重复调用会覆盖旧引用（便于测试重置）。

    MEDIUM (batch 3.1.8): this is now called in production by
    ``_build_subagent_service`` (grpc_server.py) so the four orchestrator
    tool handlers are wired with the real spawner / runner instead of
    returning ``"Orchestrator not initialized"``.
    """
    global _spawner, _runner
    _spawner = spawner
    _runner = runner


def _require_principal(principal_id: str) -> dict[str, Any] | None:
    """MEDIUM (batch 3.1.9): return an ``ok=false`` error dict if
    ``principal_id`` is empty, else ``None``.

    The orchestrator tools must not fail open to a shared pseudo-principal
    when the caller's principal is missing — that would bypass the
    spawner's "empty principal → empty result" defense and let a
    misconfigured tool context silently land tasks under
    ``local-uid:orchestrator``.  The RPC path already requires a
    principal; the tool path now matches.
    """
    if not principal_id:
        return {"ok": False, "error": "principal_id is required"}
    return None


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
    *,
    principal_id: str = "",
) -> dict[str, Any]:
    """启动一个子代理执行指定任务。

    参数：
    - goal: 子任务描述
    - context: 额外上下文信息
    - tools: 子代理可用的工具列表（None / 空列表表示使用全部）
    - timeout: 超时秒数
    - principal_id: 调用方主体 ID（由 ToolInvocationBroker 通过
      ``subagent.spawn`` capability 注入）。必须非空。

    返回：
        ``{"ok": True, "task_id": "...", "status": "<post-spawn status>"}``
        或 ``{"ok": False, "error": "..."}``

    MEDIUM (batch 3.1.8): previously this handler hard-coded
        ``{"ok": True, "status": "running"}`` regardless of the actual
        spawn result, and did not stamp ``principal_id`` on the task —
        so ``collect_results`` / ``subagent_status`` (which filter by
        principal) returned empty for tasks spawned via this tool.
        Now the principal is stamped on the task and the real
        post-spawn status (typically ``pending`` / ``initializing``,
        or ``failed`` if reservation was rejected) is returned.

    MEDIUM (batch 3.1.9): when the spawner returns a terminal failure
        status (``failed`` / ``cancelled`` — e.g. the spawn lost a
        shutdown race and the task was aborted), the handler now
        returns ``ok=false`` with the task's error.  Previously it
        returned ``ok=true, status="failed"`` which contradicted the
        ``ok`` flag's meaning and broke callers that branched on
        ``ok``.  Also refuses empty ``principal_id`` instead of
        falling back to a shared pseudo-principal.
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    # MEDIUM (batch 3.1.9): refuse empty principal — fail closed.
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    from khaos.subagents.spawner import SubAgentTask

    task = SubAgentTask(
        id="",  # 由 spawner 自动生成 UUID
        goal=goal,
        context=context,
        tools=tools or [],
        timeout=timeout,
        parent_session_id="orchestrator",
        depth=1,
        principal_id=principal_id,
    )
    try:
        result = await _spawner.spawn(task)
        # MEDIUM (batch 3.1.9): if the spawner reports a terminal
        # failure (e.g. the spawn lost a shutdown race and the task
        # was aborted with status=failed / error=cancelled), return
        # ok=false so the caller can branch on ``ok``.  Matches the
        # RPC SubAgentService contract.
        if result.status in _SPAWN_FAILURE_STATUSES:
            return {
                "ok": False,
                "task_id": result.id,
                "status": result.status,
                "error": result.error or "spawn failed",
                "principal_id": principal_id,
            }
        # MEDIUM (batch 3.1.8): return the REAL post-spawn status
        # (typically "pending" or "initializing").  Previously this was
        # hard-coded to "running".
        return {
            "ok": True,
            "task_id": result.id,
            "status": result.status,
            "principal_id": principal_id,
        }
    except Exception as exc:  # noqa: BLE001 — 工具层兜底，转为结构化错误
        logger.error("Failed to spawn subagent: %s", exc)
        return {"ok": False, "error": str(exc)}


async def collect_results(
    *,
    principal_id: str = "",
) -> dict[str, Any]:
    """等待所有子任务完成并收集结果。

    参数：
    - principal_id: 调用方主体 ID（由 ToolInvocationBroker 注入）。
      必须非空。只收集属于该 principal 的任务。

    返回：
        ``{"ok": True, "results": [...], "total": int, "completed": int, "failed": int}``
        或 ``{"ok": False, "error": "..."}``

    MEDIUM (batch 3.1.8): previously this handler called
        ``_spawner.wait_all(timeout=600)`` with NO principal_id — the
        spawner returns an empty list for empty principal (defense in
        depth), so the tool always reported zero results for tasks
        spawned via ``spawn_subagent``.  Now the principal is passed
        through so the caller's own tasks are collected.

    MEDIUM (batch 3.1.9): refuses empty ``principal_id`` instead of
        falling back to a shared pseudo-principal.
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    # MEDIUM (batch 3.1.9): refuse empty principal — fail closed.
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    try:
        tasks = await _spawner.wait_all(
            timeout=600, principal_id=principal_id,
        )
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


async def execute_plan(
    plan_json: str,
    *,
    principal_id: str = "",
) -> dict[str, Any]:
    """执行一个任务计划（JSON 格式）。

    参数：
    - plan_json: TaskPlanner.from_json() 可解析的 JSON 字符串
    - principal_id: 调用方主体 ID（由 ToolInvocationBroker 注入）。
      必须非空。每个计划任务的 principal_id 都设为该值，确保
      collect_results / subagent_status 能正确过滤。

    返回：
        ``{"ok": True, "plan_id": "...", "results": [...], "total": int,
           "completed": int, "failed": int}``
        或 ``{"ok": False, "error": "..."}``

    MEDIUM (batch 3.1.8): previously this handler did not stamp
        ``principal_id`` on the plan's tasks, so collect_results /
        subagent_status could not observe them.  Now every task in the
        plan is stamped with the caller's principal before execution.

    MEDIUM (batch 3.1.9): refuses empty ``principal_id`` instead of
        falling back to a shared pseudo-principal.
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}

    # MEDIUM (batch 3.1.9): refuse empty principal — fail closed.
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error

    from khaos.subagents.planner import TaskPlanner

    plan = TaskPlanner.from_json(plan_json)
    if plan is None:
        return {"ok": False, "error": "Invalid plan JSON: failed to parse"}

    # MEDIUM (batch 3.1.8): stamp every task in the plan with the
    # caller's principal so collect_results / subagent_status can
    # observe them.
    for task in plan.tasks:
        task.principal_id = principal_id

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


async def subagent_status(
    *,
    principal_id: str = "",
) -> dict[str, Any]:
    """查看当前所有子任务状态（不等待）。

    参数：
    - principal_id: 调用方主体 ID（由 ToolInvocationBroker 注入）。
      必须非空。只统计属于该 principal 的任务。

    返回：
        ``{"ok": True, "stats": {"active": int, "total": int, "completed": int,
           "failed": int, "pending": int}}``
        或 ``{"ok": False, "error": "..."}``

    MEDIUM (batch 3.1.8): previously this handler called
        ``_spawner.stats()`` with NO principal_id — the spawner returns
        an empty stats dict for empty principal (defense in depth), so
        the tool always reported zero counts for tasks spawned via
        ``spawn_subagent``.  Now the principal is passed through.

    MEDIUM (batch 3.1.9): refuses empty ``principal_id`` instead of
        falling back to a shared pseudo-principal.
    """
    if _spawner is None:
        return {"ok": False, "error": "Orchestrator not initialized"}
    # MEDIUM (batch 3.1.9): refuse empty principal — fail closed.
    principal_error = _require_principal(principal_id)
    if principal_error is not None:
        return principal_error
    return {"ok": True, "stats": _spawner.stats(principal_id=principal_id)}
