"""Real subagent runner that creates isolated AgentLoop instances."""

from __future__ import annotations

import logging
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any

from khaos.agent.core import AgentConfig, Message, SimpleTokenEngine
from khaos.db.state_root import project_id as compute_project_id
from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile
from khaos.subagents.assignment import DelegatedExecutionContext
from khaos.subagents.spawner import SubAgentTask

if TYPE_CHECKING:
    from khaos.coding.context import CodingContextBuilder
    from khaos.memory.manager import MemoryManager
    from khaos.memory.runtime import MemoryHost
    from khaos.skills.manager import SkillManager

logger = logging.getLogger(__name__)


class _DelegatedWorkspaceManager:
    """Narrow read/attach view over the already-owned parent workspace."""

    def __init__(self, manager: Any, context: DelegatedExecutionContext) -> None:
        self._manager = manager
        self._context = context

    def get(self, workspace_id: str) -> Any:
        if workspace_id != self._context.workspace_id:
            return None
        workspace = self._manager.get(workspace_id)
        if workspace is None or workspace.task_id != self._context.parent_task_id:
            return None
        return workspace

    def require(self, workspace_id: str, *, task_id: str, principal_id: str, project_id: str, runtime_id: str) -> Any:
        del principal_id, runtime_id
        workspace = self.get(workspace_id)
        if workspace is None or task_id != self._context.parent_task_id or project_id != self._context.project_id:
            raise PermissionError("delegated workspace attachment is outside the assignment")
        return workspace

    def __getattr__(self, name: str) -> Any:
        return getattr(self._manager, name)


class SubAgentRunner:
    """为每个子任务创建独立 AgentLoop 实例并执行。

    每个子代理拥有：
    - 独立 session_id（parent_session_id + "/" + task_id）
    - 独立 system prompt（根据任务定制）
    - 独立工具集（限定为子集或全部）
    - 独立 token 预算（默认比主 agent 低）
    - 独立记忆空间（不与主 agent 共享，但可选择性继承）

    B1: ``project_root`` / ``config_path`` 是不可变的——它们必须与
    主 AgentService 完全相同，否则子代理会重新加载另一份
    ``khaos_policy.yaml`` / ``config.yaml``，形成第二套安全权威。
    生产入口（``_build_subagent_service``）必须显式传入，不得回退到
    ``Path.cwd()``。
    """

    def __init__(
        self,
        router,                          # ModelRouter 实例
        db,                              # Database 实例
        mode_manager=None,               # C-1-5b: 默认 None，让 build_runtime 按 per-turn principal 构造
        tool_scheduler=None,             # B1: 不再接收裸 scheduler；默认 None
        memory_manager: MemoryManager | None = None,  # 可选，默认不共享记忆
        skill_manager: SkillManager | None = None,    # 可选
        coding_context_builder: CodingContextBuilder | None = None,  # 可选
        token_engine: SimpleTokenEngine | None = None,  # SimpleTokenEngine
        max_turns: int = 30,            # 子代理轮次限制（比主 agent 低）
        max_budget_tokens: int = 100000,  # 子代理 token 预算（比主 agent 低）
        stream_timeout: int = 60,        # 子代理超时（比主 agent 低）
        inherit_memory: bool = False,    # 是否从父会话继承记忆
        office_authority: Any | None = None,  # B1: 共享 Office authority
        approval_broker: Any | None = None,   # B1: 继承主 AgentService 的审批 broker
        principal_id: str = "",                  # B1: 继承 principal
        audit_logger: Any | None = None,      # B1: 继承审计 logger
        project_root: Path | None = None,     # B1: 继承项目根（不可变）
        config_path: Path | None = None,      # B1: 继承 config 路径
        cleanup_authority: Any | None = None,
        memory_host: MemoryHost | None = None,
        runtime_profile: RuntimeProfile | str | None = None,
        workspace_manager: Any | None = None,
        assignment_repository: Any | None = None,
    ):
        self.router = router
        self.db = db
        # C-1-5b: ``mode_manager`` defaults to ``None`` — the production
        # path (``_build_subagent_service``) no longer passes a server-level
        # ``ModeManager(local-uid)`` singleton.  When ``None``,
        # ``build_runtime`` constructs a per-turn ``ModeManager`` from
        # ``cfg.principal_id`` (= ``task.principal_id``), so the subagent's
        # mode switches are scoped to the CALLING principal.  Legacy / test
        # callers may still pass a mock for ad-hoc construction.
        self.mode_manager = mode_manager
        # B1: ``tool_scheduler`` 保留为可选向后兼容字段，但生产路径
        # （``_build_subagent_service``）不再传入裸 scheduler。当为 ``None``
        # 时，``build_runtime`` 会按 ``task.tools`` 裁剪出带完整
        # SecurityMiddleware（Sandbox / NetworkGuard / EffectivePolicy /
        # AuditLogger）的全新 ToolScheduler，与主 AgentLoop 共享同一安全栈。
        self.tool_scheduler = tool_scheduler
        # C-1-5b: ``memory_manager`` defaults to ``None`` — same rationale
        # as ``mode_manager``.  ``build_runtime`` constructs a per-turn
        # ``MemoryManager`` from ``cfg.principal_id``.
        self.memory_manager = memory_manager
        self.skill_manager = skill_manager
        self.coding_context_builder = coding_context_builder
        self.token_engine = token_engine or SimpleTokenEngine()
        self.max_turns = max_turns
        self.max_budget_tokens = max_budget_tokens
        self.stream_timeout = stream_timeout
        self.inherit_memory = inherit_memory
        # B1: server-lifecycle Office authority shared across every subagent
        # run — keeps the aggregate storage baseline stable and prevents
        # build_runtime from silently replacing the scheduler's authority.
        self.office_authority = office_authority
        # B1: inherit the server-level approval broker / principal / audit
        # logger so the subagent's security decisions are bound to the same
        # authority as the main AgentLoop, not a parallel unsupervised path.
        self.approval_broker = approval_broker
        self.principal_id = principal_id
        self.audit_logger = audit_logger
        # B1: project_root / config_path MUST be inherited verbatim from the
        # AgentService so the subagent loads the SAME ``khaos_policy.yaml``
        # and compiles the SAME EffectivePolicy as the main AgentLoop.
        # When ``None`` (legacy callers), fall back to ``Path.cwd()`` — but
        # the production path (``_build_subagent_service``) always supplies
        # the server's project root, never the process cwd.
        self.project_root = project_root
        self.config_path = config_path
        self.cleanup_authority = cleanup_authority
        self.memory_host = memory_host
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        self.workspace_manager = workspace_manager
        self.assignment_repository = assignment_repository

    async def run(self, task: SubAgentTask) -> str:
        """执行子任务并返回结果字符串。

        步骤：
        1. 创建独立 session_id: "{parent_session_id}/{task_id}"
        2. 创建独立的 AgentConfig（降低限制）
        3. 构建 system prompt（定制版，注入到 mode prompt 之后）
        4. 创建 AgentLoop 实例（共享 router/db/mode_manager，独立 config）
        5. 执行 run(task.goal, session_id) 并收集所有消息
        6. 提取最终 assistant 回复作为结果

        B1: 在 ``finally`` 中调用 ``runtime.aclose()``，确保 ExecutionService /
        MemoryManager 即使在 ``loop.run`` 抛错或被取消时也能被释放。注入的
        共享 ``office_authority`` 是借用的，``aclose`` 不会关闭它。
        """
        session_id = task.session_id or f"{task.parent_session_id}/{task.id}"
        # M7.8: assignment-bound children are structurally distinct from the
        # legacy free-form office runner.  The coordinator supplies all
        # identities; no prompt or RPC payload can construct this context.
        delegated_context: DelegatedExecutionContext | None = None
        if task.assignment_id:
            if not task.assignment_digest or not task.task_owner_principal_id or not task.execution_principal_id:
                raise PermissionError("delegated child is missing its trusted assignment context")
            if self.assignment_repository is None:
                raise PermissionError("delegated child assignment repository is unavailable")
            parent_workspace_manager = (
                self.workspace_manager or task.parent_workspace_manager
            )
            if parent_workspace_manager is None:
                raise PermissionError("delegated child parent workspace is unavailable")
            if not await self.assignment_repository.validate_active_for_route(
                assignment_id=task.assignment_id,
                assignment_digest=task.assignment_digest,
                child_execution_principal_id=task.execution_principal_id,
                task_owner_principal_id=task.task_owner_principal_id,
                project_id=task.project_id,
                parent_task_id=task.parent_task_id,
                workspace_id=task.workspace_id,
                published_plan_revision_id=task.published_plan_revision_id,
                plan_step_id=task.plan_step_id,
                execution_epoch_digest=task.execution_epoch_digest,
            ):
                raise PermissionError("delegated child assignment is not active")
            delegated_context = DelegatedExecutionContext(
                assignment_id=task.assignment_id,
                assignment_digest=task.assignment_digest,
                task_owner_principal_id=task.task_owner_principal_id,
                parent_task_id=task.parent_task_id,
                child_execution_principal_id=task.execution_principal_id,
                project_id=task.project_id,
                workspace_id=task.workspace_id,
                published_plan_revision_id=task.published_plan_revision_id,
                plan_step_id=task.plan_step_id,
                execution_epoch_digest=task.execution_epoch_digest,
            )
        project_root = self.project_root or Path.cwd()
        effective_project_id = task.project_id or compute_project_id(project_root)
        config = AgentConfig(
            max_turns=self.max_turns,
            max_budget_tokens=self.max_budget_tokens,
            stream_timeout=self.stream_timeout,
        )
        # 保证子代理 session 已持久化（与 spawn() 的 create_session 对齐）。
        # M4 batch 3.1.16A-4-3: stamp the task's principal_id so the
        # subagent's session history is scoped to the calling principal.
        # M4 batch 3.1.16A-5-1b: stamp the task's project_id too
        # (sub-agents inherit the parent runtime's bound project
        # identity — there is no legitimate cross-project sub-agent
        # flow).  Owner-preserving ON CONFLICT.
        await self.db.create_session(
            session_id,
            principal_id=task.principal_id or self.principal_id or "legacy",
            project_id=effective_project_id,
        )

        from khaos.runtime import (
            ProductionRuntimeConfig,
            RuntimeConfig,
            build_production_runtime,
            build_runtime,
            close_runtime_or_register,
        )
        # B1: use the TASK's principal_id (set from the authenticated
        # RPC payload), NOT the server-fixed self.principal_id.  This
        # ensures the subagent's BrowserContext / Memory scope /
        # audit events are bound to the CALLING principal, not the
        # server's local UID.
        #
        # C-1-5a: build_runtime fail-closed on empty principal_id, so
        # if both task.principal_id and self.principal_id are empty
        # the runtime construction raises ValueError.  No implicit
        # local-uid fallback in the build_runtime path.
        principal_id = task.execution_principal_id if delegated_context is not None else (task.principal_id or self.principal_id)
        if task.delegation_digest:
            # The child delegation was issued to the typed execution
            # subject ``subagent:<owner>:<task-id>``; the runtime's
            # authority principal must be exactly that subject or the
            # authority-side grant check (delegation subject match) fails
            # closed.  DB ownership stays task.principal_id (the owner);
            # this value is only the security principal.
            principal_id = f"subagent:{principal_id}:{task.id}"
        # Production-safe subagents use the structural config that cannot
        # carry a second scheduler, execution service, sandbox, network
        # guard, memory owner, browser manager, or workspace manager.  The
        # legacy config remains available for explicit test/development
        # adapters that inject those components.
        runtime_config_type = (
            ProductionRuntimeConfig
            if self.tool_scheduler is None
            and not (self.inherit_memory and self.memory_manager is not None)
            else RuntimeConfig
        )
        parent_workspace_manager = self.workspace_manager or task.parent_workspace_manager
        delegated_workspace_manager = (
            _DelegatedWorkspaceManager(parent_workspace_manager, delegated_context)
            if delegated_context is not None and parent_workspace_manager is not None
            else None
        )
        runtime_kwargs: dict[str, Any] = {
            "db": self.db,
            # C-1-5b: pass ``mode_manager=None`` (production path) so
            # ``build_runtime`` constructs a per-turn manager from the task
            # principal.  Legacy / test callers may pass a mock.
            "mode_manager": self.mode_manager,
            "router": self.router,
            # B1: prune the registry down to the declared task tools.
            "tool_allowlist": (task.tools if self.tool_scheduler is None else None),
            "skill_manager": self.skill_manager,
            "agent_config": config,
            "office_authority": self.office_authority,
            # B1: inherit the server-level approval broker / audit logger.
            "approval_broker": self.approval_broker,
            "principal_id": principal_id,
            "principal_kind": "subagent",
            "parent_principal_id": task.parent_principal_id or principal_id,
            "delegation_digest": task.delegation_digest,
            "source_transport": "subagent",
            "foreground_session": False,
            "session_id": session_id,
            "runtime_id": task.runtime_id or uuid.uuid4().hex,
            "audit_logger": self.audit_logger,
            "project_id": effective_project_id,
            # Legacy free-form children are permanently office-scoped.  A
            # coding child may enter coding mode only through the structural
            # assignment path, where the parent task/workspace/plan binding
            # is already present.
            "mode_override": "coding" if delegated_context is not None else "office",
            "task_id": task.parent_task_id if delegated_context is not None else "",
            "workspace_id": task.workspace_id if delegated_context is not None else "",
            # B1: inherit the same project policy/config root.
            "project_root": project_root,
            "config_path": self.config_path,
            "cleanup_authority": self.cleanup_authority,
            "memory_host": self.memory_host,
            "delegated_execution_context": delegated_context,
            "delegated_workspace_manager": delegated_workspace_manager,
        }
        if runtime_config_type is RuntimeConfig:
            # Explicit legacy/test adapters may inject these components; the
            # production structural type has no fields for them.
            runtime_kwargs["coding_context_builder"] = self.coding_context_builder
            runtime_kwargs["tool_scheduler"] = self.tool_scheduler
            runtime_kwargs["memory_manager"] = (
                self.memory_manager if self.inherit_memory else None
            )
            runtime_kwargs["profile"] = self.runtime_profile
        elif not self.runtime_profile.is_production:
            # A non-production server profile still needs to survive the
            # structural-to-legacy adapter even when the runner has no
            # injected test components.  Otherwise RuntimeConfig would
            # resolve the ambient legacy environment again and an explicit
            # TESTING/DEVELOPMENT profile could silently become production.
            runtime_kwargs["profile"] = self.runtime_profile
        if (
            runtime_config_type is ProductionRuntimeConfig
            and self.runtime_profile.is_production
        ):
            runtime = await build_production_runtime(
                ProductionRuntimeConfig(**runtime_kwargs)
            )
        else:
            # Legacy/test adapters and explicitly non-production server
            # profiles use the ordinary factory with the typed profile.  A
            # production profile can never reach this branch with the
            # structural production config.
            runtime = await build_runtime(RuntimeConfig(**runtime_kwargs))
        try:
            logger.info(
                "SubAgentRunner starting: task=%s session=%s goal=%r",
                task.id,
                session_id,
                task.goal,
            )

            messages: list[Message] = []
            if delegated_context is not None:
                async for message in runtime.loop.run(
                    task.goal, session_id, task_id=delegated_context.parent_task_id
                ):
                    messages.append(message)
            else:
                async for message in runtime.loop.run(task.goal, session_id):
                    messages.append(message)

            return await self._collect_result(messages)
        finally:
            # B1: release per-run resources (ExecutionService / MemoryManager).
            # The shared office_authority (if injected) is borrowed, not owned.
            await close_runtime_or_register(runtime)

    def _build_subagent_system_prompt(self, task: SubAgentTask) -> str:
        """构建子代理专用的 system prompt。

        格式：
            你是 Khaos 子代理 #{task.id}。
            你的任务：{task.goal}

            {task.context（如果有）}

            约束：
            - 专注于你的任务，不要做范围外的事情
            - 完成后报告结果
            - 遇到无法解决的问题，报告错误信息
        """
        lines = [
            f"你是 Khaos 子代理 #{task.id}。",
            f"你的任务：{task.goal}",
        ]
        if task.context:
            lines.append("")
            lines.append(task.context)
        lines.extend(
            [
                "",
                "约束：",
                "- 专注于你的任务，不要做范围外的事情",
                "- 完成后报告结果",
                "- 遇到无法解决的问题，报告错误信息",
            ]
        )
        return "\n".join(lines)

    async def _collect_result(self, messages: list[Message]) -> str:
        """从消息列表中提取最终结果。

        策略：
        1. 找到（按时间顺序的）最后一条 assistant 消息
        2. 若其 content 非空（去空白后），直接返回它
        3. 否则（空 content 或只有 tool_calls），拼接所有 assistant 消息的非空 content
        4. 若拼接仍为空，返回 "[子代理未产生有效输出]"
        """
        # 1. 找到最后一条 assistant 消息
        last_assistant: Message | None = None
        for message in reversed(messages):
            if message.role == "assistant":
                last_assistant = message
                break

        # 2. 最后一条 assistant 非空 → 直接返回
        if last_assistant is not None and last_assistant.content.strip():
            return last_assistant.content

        # 3. 最后一条为空/只有 tool_calls → 拼接所有 assistant 非空 content
        assistant_texts = [
            message.content
            for message in messages
            if message.role == "assistant" and message.content.strip()
        ]
        if assistant_texts:
            return "\n".join(assistant_texts)

        # 4. 全部为空
        return "[子代理未产生有效输出]"
