"""Task decomposition for multi-agent parallel execution."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

from khaos.subagents.spawner import SubAgentTask

logger = logging.getLogger(__name__)


@dataclass
class SubTaskPlan:
    """一组子任务计划。"""

    id: str
    description: str
    tasks: list[SubAgentTask] = field(default_factory=list)
    dependencies: dict[str, list[str]] = field(default_factory=dict)  # task_id -> [dep_task_ids]
    has_dependencies: bool = False


class TaskPlanner:
    """将复杂任务拆分为可并行的子任务。

    使用方式：
    1. 手动创建（用户在 prompt 中明确指定子任务）
    2. 自动拆分（由 orchestrator 模型生成计划）

    本模块提供数据结构和执行调度逻辑，不包含 LLM 调用。
    LLM 调用在 orchestrator 中处理。
    """

    @staticmethod
    def from_json(plan_json: str, parent_session_id: str = "root") -> Optional[SubTaskPlan]:
        """从 JSON 字符串解析任务计划。

        JSON 格式：
            {
                "description": "给项目添加测试覆盖",
                "tasks": [
                    {"goal": "...", "tools": [...], "context": "..."},
                    ...
                ],
                "dependencies": {
                    "task_2": ["task_1"]
                }
            }

        如果没有 dependencies 字段或为空，所有任务可并行。
        task_id 自动生成（task_1, task_2, ...）。返回 None 表示 JSON 无效。
        """
        try:
            data = json.loads(plan_json)
        except (json.JSONDecodeError, TypeError) as exc:
            logger.warning("invalid task plan JSON: %s", exc)
            return None
        if not isinstance(data, dict):
            logger.warning("task plan JSON must be an object, got %r", type(data).__name__)
            return None

        plan_id = data.get("id") or f"plan-{uuid.uuid4().hex[:8]}"
        description = data.get("description", "")

        # ── 构建 tasks，自动生成 task_N 形式的 id ──
        task_specs = data.get("tasks", [])
        if not isinstance(task_specs, list):
            task_specs = []
        tasks: list[SubAgentTask] = []
        # 记录 JSON 中声明的 id（如果有）→ 自动生成 id 的映射，
        # 以便 dependencies 可以引用任一形式。
        declared_to_auto: dict[str, str] = {}
        auto_index = 0
        for spec in task_specs:
            if not isinstance(spec, dict):
                continue
            auto_index += 1
            auto_id = f"task_{auto_index}"
            declared_id = spec.get("id")
            if declared_id:
                declared_to_auto[str(declared_id)] = auto_id
            declared_to_auto[auto_id] = auto_id
            goal = str(spec.get("goal", ""))
            tools = spec.get("tools", [])
            if not isinstance(tools, list):
                tools = []
            tools = [str(t) for t in tools]
            tasks.append(
                SubAgentTask(
                    id=auto_id,
                    goal=goal,
                    context=str(spec.get("context", "") or ""),
                    tools=tools,
                    timeout=int(spec.get("timeout", 300)),
                    parent_session_id=str(spec.get("parent_session_id", parent_session_id)),
                    depth=int(spec.get("depth", 1)),
                )
            )

        # ── 构建 dependencies，归一化引用 id ──
        raw_deps = data.get("dependencies", {})
        dependencies: dict[str, list[str]] = {}
        if isinstance(raw_deps, dict) and raw_deps:
            for key, deps in raw_deps.items():
                resolved_key = declared_to_auto.get(str(key), str(key))
                if not isinstance(deps, list):
                    deps = [deps] if deps is not None else []
                resolved_deps = [
                    declared_to_auto.get(str(d), str(d)) for d in deps if d is not None
                ]
                if resolved_deps:
                    dependencies[resolved_key] = resolved_deps

        return SubTaskPlan(
            id=plan_id,
            description=description,
            tasks=tasks,
            dependencies=dependencies,
            has_dependencies=bool(dependencies),
        )

    @staticmethod
    def to_json(plan: SubTaskPlan) -> str:
        """将 SubTaskPlan 序列化为 JSON 字符串。"""
        payload: dict[str, Any] = {
            "id": plan.id,
            "description": plan.description,
            "tasks": [
                {
                    "id": task.id,
                    "goal": task.goal,
                    "context": task.context,
                    "tools": task.tools,
                    "timeout": task.timeout,
                    "parent_session_id": task.parent_session_id,
                }
                for task in plan.tasks
            ],
            "dependencies": plan.dependencies,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=False)

    @staticmethod
    def create_simple_tasks(
        goals: list[str],
        parent_session_id: str = "root",
        tools: list[str] | None = None,
        context: str = "",
        timeout: int = 300,
    ) -> SubTaskPlan:
        """快捷创建无依赖的并行任务计划。"""
        tool_set = tools if tools is not None else []
        tasks = [
            SubAgentTask(
                id=f"task_{index}",
                goal=goal,
                context=context,
                tools=list(tool_set),
                timeout=timeout,
                parent_session_id=parent_session_id,
            )
            for index, goal in enumerate(goals, start=1)
        ]
        return SubTaskPlan(
            id=f"plan-{uuid.uuid4().hex[:8]}",
            description=f"{len(goals)} parallel tasks",
            tasks=tasks,
            dependencies={},
            has_dependencies=False,
        )

    @staticmethod
    def _topological_layers(plan: SubTaskPlan) -> list[list[str]]:
        """将依赖图划分为可并行执行的层级。

        返回 ``[["task_1", "task_3"], ["task_2"]]`` 形式，每个内层列表内的
        任务互不依赖，可同时 spawn。依赖中出现但 plan.tasks 不存在的 id
        视为已满足（外部已完成），仅忽略不存在的叶子任务。
        """
        task_ids = {task.id for task in plan.tasks}
        deps: dict[str, set[str]] = {
            tid: {d for d in plan.dependencies.get(tid, []) if d in task_ids}
            for tid in task_ids
        }
        layers: list[list[str]] = []
        resolved: set[str] = set()
        remaining = set(task_ids)
        # 防御循环依赖：最多迭代 task_ids 次数 + 1
        max_iterations = len(task_ids) + 1
        while remaining:
            progress = False
            current_layer = sorted(
                tid
                for tid in remaining
                if deps[tid].issubset(resolved)
            )
            if current_layer:
                layers.append(current_layer)
                resolved.update(current_layer)
                remaining.difference_update(current_layer)
                progress = True
            if not progress:
                # 存在循环依赖或不可解析的依赖；把剩余任务全部塞进最后一层，
                # 以便调度器仍然尝试执行（避免永久卡死）。
                logger.warning(
                    "unresolvable task dependencies in plan %s: %s",
                    plan.id,
                    sorted(remaining),
                )
                layers.append(sorted(remaining))
                break
            if len(layers) >= max_iterations:
                break
        return layers

    @staticmethod
    async def execute_plan(plan: SubTaskPlan, spawner) -> list[SubAgentTask]:
        """执行任务计划，处理依赖关系。

        逻辑：
        1. 构建依赖图（DAG）
        2. 拓扑排序，确定执行层级
           - 层0：无依赖的任务（全部并行）
           - 层1：只依赖层0的任务（层0全部完成后并行启动）
           - 层2：依赖层1的任务（以此类推）
        3. 按层级执行：
           a. 当前层的所有任务并行 spawn
           b. wait_all 等待全部完成
           c. 检查是否有任务失败
              - 如果某任务失败且下游任务依赖它，标记下游为 "skipped"
           d. 进入下一层
        4. 返回所有完成（或被跳过/失败）的任务

        M2: the planner is an in-process caller (not the RPC service),
        so it stamps every task with the sentinel principal_id
        ``"orchestrator"`` and passes that to ``wait_all``.  This keeps
        the planner working now that the spawner's empty-principal path
        returns NOTHING (M2 defense in depth) instead of all tasks.

        Returns:
            所有见过的 SubAgentTask 列表（status 为 completed / failed / skipped）。
        """
        if not plan.tasks:
            return []

        # M2: stamp every task with the sentinel "orchestrator" principal
        # so ``wait_all(principal_id="orchestrator")`` actually waits for
        # them.  Without this, the spawner's empty-principal path returns
        # [] immediately (M2) and the planner would race the tasks.
        _PLANNER_PRINCIPAL = "orchestrator"
        for task in plan.tasks:
            if not task.principal_id:
                task.principal_id = _PLANNER_PRINCIPAL

        tasks_by_id: dict[str, SubAgentTask] = {task.id: task for task in plan.tasks}
        seen: list[SubAgentTask] = []
        # 收集每层完成后已成功（completed）的 task_id。
        completed_ids: set[str] = set()

        layers = TaskPlanner._topological_layers(plan)
        for layer in layers:
            # 先判定 skip：任一未满足的依赖即标记 skipped，不 spawn。
            to_spawn: list[SubAgentTask] = []
            for tid in layer:
                task = tasks_by_id[tid]
                failed_deps = [
                    dep
                    for dep in plan.dependencies.get(tid, [])
                    if dep in tasks_by_id and dep not in completed_ids
                ]
                if failed_deps:
                    task.status = "skipped"
                    task.error = f"上游任务失败/未完成: {', '.join(failed_deps)}"
                    seen.append(task)
                    logger.info(
                        "skipping task %s due to failed deps: %s", tid, failed_deps
                    )
                else:
                    to_spawn.append(task)

            # 并行 spawn 当前层
            for task in to_spawn:
                seen.append(task)
            spawned: list[SubAgentTask] = []
            for task in to_spawn:
                try:
                    await spawner.spawn(task)
                    spawned.append(task)
                except Exception as exc:  # noqa: BLE001 — 并发超限等，跳过本任务
                    task.status = "failed"
                    task.error = f"spawn 失败: {exc}"
                    logger.warning("spawn failed for task %s: %s", task.id, exc)

            if spawned:
                # M2: pass the sentinel principal so wait_all actually
                # waits for the spawned tasks.
                await spawner.wait_all(principal_id=_PLANNER_PRINCIPAL)

            # 记录成功的 task_id
            for task in to_spawn:
                if task.status == "completed":
                    completed_ids.add(task.id)

        return seen
