"""P0-A agent loop with mock streaming model support."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

if TYPE_CHECKING:
    from khaos.agent.control.completion_flow import (
        CompletionFactProvider,
        CompletionProposalController,
        CompletionProposalResult,
    )
    from khaos.agent.control.completion_gate import (
        CompletionGate,
        CompletionGateResult,
    )
    from khaos.coding.cost_tracker import CostTracker
    from khaos.coding.fingerprint import FileFingerprintCache
    from khaos.coding.task_manager import TaskManager
    from khaos.coding.verify_fix import VerifyFixLoop
    from khaos.project_context import ProjectContextLoader

from khaos.agent.turn_repository import DatabaseTurnRepository, TurnRepository
from khaos.exceptions import CompressionCircuitOpenError
from khaos.runtime_profile import RuntimeProfile, resolve_runtime_profile
from khaos.security.orchestration_components import TurnAdmission, TurnFinalizer
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    TurnPhase,
    TurnPhaseSnapshot,
    digest_phase_payload,
)

logger = logging.getLogger(__name__)


def _default_runtime_environment(key: str) -> str:
    """Return the deterministic value used in the spawn authority snapshot."""
    if key == "PATH":
        return os.defpath
    if key == "LANG":
        return "C.UTF-8"
    return ""


class StopReason(Enum):
    """Reasons an agent turn can stop."""

    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TURNS = "max_turns"
    MAX_BUDGET = "max_budget"
    USER_ABORT = "user_abort"
    ERROR = "error"


@dataclass
class AgentConfig:
    """Agent runtime limits."""

    max_turns: int = 100
    max_budget_tokens: int = 500000
    stream_timeout: int = 120
    compression_threshold: int = 128000
    # Token budget for the injected project-structure tree (coding mode only).
    project_structure_token_budget: int = 2000


@dataclass
class Message:
    """Chat message used by the agent loop and SSE encoder."""

    role: str
    content: str
    tool_calls: list[dict] = field(default_factory=list)
    tool_call_id: str | None = None
    token_count: int = 0
    created_at: float = 0.0
    stop_reason: str | None = None
    event: str | None = None
    metadata: dict = field(default_factory=dict)


class SimpleTokenEngine:
    """Small token counter placeholder until the Rust tokenizer lands."""

    def count_tokens(self, text: str) -> int:
        """Return a deterministic approximate token count."""
        return len(text.split()) if text.strip() else 0


class AgentLoop:
    """Agent core loop for P0-A."""

    def __init__(
        self,
        config: AgentConfig,
        mode_manager,
        router,
        db,
        turn_repository: TurnRepository | None = None,
        tool_scheduler=None,
        confirm_callback=None,
        context_compressor=None,
        memory_manager=None,
        error_handler=None,
        token_engine: SimpleTokenEngine | None = None,
        skill_manager=None,
        project_root=None,
        coding_context_builder=None,
        project_context_loader: ProjectContextLoader | None = None,
        file_fingerprint_cache: FileFingerprintCache | None = None,
        cost_tracker: CostTracker | None = None,
        verify_fix_loop: VerifyFixLoop | None = None,
        verify_fix_factory=None,
        task_manager: TaskManager | None = None,
        task_id: str | None = None,
        skill_generator=None,
        workspace_manager=None,
        execution_service=None,
        approval_broker=None,
        principal_id: str | None = None,
        principal_kind: str = "",
        parent_principal_id: str = "",
        delegation_digest: str = "",
        source_transport: str = "unknown",
        foreground_session: bool = False,
        # H5: runtime_id + session_id extend the per-session BrowserContext
        # key so two concurrent local sessions under the same UID get
        # independent BrowserContexts.  Propagated into ``tool_context`` so
        # the broker can inject them into browser tools.
        runtime_id: str = "",
        session_id: str = "",
        # M4 batch 3.1.16A-4-4-3: the server-lifecycle ChannelRegistry and
        # the admin principal allowlist compiled into the immutable
        # EffectiveSecurityPolicy.  Propagated into ``tool_context`` so the
        # four channel tools (channel_list / channel_health /
        # channel_enable / channel_disable) receive them via the
        # ``channel.read`` / ``channel.manage`` broker injection.  Without
        # these the handlers fail-closed (``unavailable`` / ``forbidden``).
        channel_registry=None,
        channel_admins: frozenset[str] | None = None,
        cron_engine=None,
        browser_manager=None,
        subagent_spawner=None,
        credential_broker=None,
        # M4 batch 3.1.16A-5-1b (CRITICAL): project identity stamp.
        # Bound at construction from ``RuntimeConfig.project_id`` (set by
        # ``AgentService`` from the verified RPC payload) — NOT recomputed
        # from ``project_root``.  Stamped on every message / turn write so
        # rows are cryptographically tied to the project that produced
        # them.  ``_bound_project_id`` (the underscore-prefixed alias) is
        # the value the RPC dispatcher compares against ``ctx.project_id``
        # for drift detection (fail-closed rejection).
        project_id: str = "",
        runtime_profile: RuntimeProfile | str | None = None,
        completion_controller: CompletionProposalController | None = None,
        completion_fact_provider: CompletionFactProvider | None = None,
        completion_gate: CompletionGate | None = None,
    ):
        self.config = config
        self.mode_manager = mode_manager
        self.router = router
        self.db = db
        self.runtime_profile = resolve_runtime_profile(runtime_profile)
        # The agent loop still uses ``db`` for message/session persistence,
        # while durable turn events travel through one explicit port.  The
        # default keeps legacy construction sites source-compatible; runtime
        # tests may inject a fake repository without exposing a database.
        self.turn_repository = turn_repository or DatabaseTurnRepository(db)
        self.tool_scheduler = tool_scheduler
        self.confirm_callback = confirm_callback
        self.compressor = context_compressor
        self.memory_manager = memory_manager
        self.error_handler = error_handler
        self.token_engine = token_engine or SimpleTokenEngine()
        self.skill_manager = skill_manager
        # Coding-mode context building. ``project_root`` may be a str or Path;
        # left as-is (not resolved) so callers can pass relative paths.
        self.project_root = project_root
        self.coding_context_builder = coding_context_builder
        # Phase 6: 项目约定文件加载器（KHAOS.md / AGENTS.md）。注入优先级
        # 高于 memory / skill，因为它们是项目级硬规则。
        self.project_context_loader = project_context_loader
        # Phase 6.3: 文件指纹缓存——跳过未修改文件，节省 token。
        self.file_fingerprint_cache = file_fingerprint_cache
        # Phase 6.3: 会话级 token / 费用追踪。
        self.cost_tracker = cost_tracker
        # Verify-fix loop: when a test_run result contains failures, inject a
        # guidance message so the model diagnoses, fixes, and re-runs. Only
        # active in coding mode (office mode leaves this as None).
        self.verify_fix_loop = verify_fix_loop
        self._verify_fix_factory = verify_fix_factory
        # Long-task tracking: record files viewed/modified and test outcomes.
        self.task_manager = task_manager
        self.task_id = task_id
        # M7.1.6: a coding END_TURN is a completion proposal, not a task
        # lifecycle transition.  The controller is a narrow orchestration
        # port; it owns no tool, approval, workspace, or sandbox authority.
        self.completion_controller = completion_controller
        self.completion_fact_provider = completion_fact_provider
        self.completion_gate = completion_gate
        self.skill_generator = skill_generator
        self.workspace_manager = workspace_manager
        self.active_workspace = None
        self._active_session_id = ""
        self._active_task_id: str | None = None
        self.execution_service = execution_service
        if approval_broker is None:
            from khaos.agent.approval import ApprovalBroker

            approval_broker = ApprovalBroker(db=db)
        self.approval_broker = approval_broker
        # Direct, lower-level constructions without authenticated identity
        # remain in the quarantined legacy partition.  Production paths go
        # through RuntimeConfig, which requires an explicit principal (CLI /
        # TUI provide local-uid; RPC provides ctx.principal_id).
        self.principal_id = principal_id or "legacy"
        self.principal_kind = principal_kind
        self.parent_principal_id = parent_principal_id
        self.delegation_digest = delegation_digest
        self.source_transport = source_transport
        self.foreground_session = foreground_session
        # H5: per-runtime + per-session identifiers propagated to the
        # browser tools via the broker so concurrent sessions under the
        # same UID get independent BrowserContexts.
        self.runtime_id = runtime_id
        self.session_id = session_id
        # M4 batch 3.1.16A-4-4-3: channel registry + admin allowlist,
        # injected by ``build_runtime`` from RuntimeConfig (which in turn
        # is populated by ``AgentService`` from the server-lifecycle
        # ChannelRegistry and the effective policy's compiled
        # ``channel_admins`` frozenset).  ``getattr(self, "channel_registry",
        # None)`` / ``getattr(self, "channel_admins", frozenset())`` in
        # the ``tool_context`` assembly below tolerate older callers that
        # do not pass these kwargs (e.g. ad-hoc test loops) — they get
        # ``None`` / empty frozenset and the handlers fail-closed.
        self.channel_registry = channel_registry
        self.cron_engine = cron_engine
        self.browser_manager = browser_manager
        self.subagent_spawner = subagent_spawner
        self.credential_broker = credential_broker
        self.channel_admins = (
            channel_admins if channel_admins is not None else frozenset()
        )
        # M4 batch 3.1.16A-5-1b: project identity stamp (bound from
        # RuntimeConfig.project_id, NOT recomputed from project_root).
        # Exposed as ``self.project_id`` for read access and
        # ``self._bound_project_id`` (alias) for the RPC dispatcher's
        # drift-check contract.
        self.project_id = project_id
        self._bound_project_id = project_id
        if self.execution_service is not None:
            self.execution_service.bind_runtime_authority(
                principal_id=self.principal_id,
                project_id=self.project_id,
                runtime_id=self.runtime_id,
            )
        self._active_context_facts: list[Message] = []
        if self.execution_service is None:
            from khaos.coding.execution import ExecutionService, UnsupportedBackend

            # Agent construction must fail closed.  Office-only callers may
            # still construct a loop without an execution service, but any
            # accidental coding/tool execution is denied instead of escaping
            # to an unrestricted host subprocess.
            self.execution_service = ExecutionService(
                UnsupportedBackend(), runtime_profile=self.runtime_profile
            )

    @staticmethod
    def _turn_context_digest(messages: list[Message]) -> str:
        """Digest the immutable message facts crossing the context boundary."""
        return digest_phase_payload(
            [
                {
                    "role": message.role,
                    "content": message.content,
                    "tool_call_id": message.tool_call_id or "",
                    "event": message.event or "",
                }
                for message in messages
            ]
        )

    @staticmethod
    def _tool_batch_phase_digest(tool_calls: list[dict]) -> str:
        """Digest the model-produced tool batch before scheduler admission."""
        return digest_phase_payload(
            [
                {
                    "id": str(call.get("id") or ""),
                    "name": str(call.get("name") or ""),
                    "arguments": call.get("arguments", {}),
                }
                for call in tool_calls
            ]
        )

    @staticmethod
    def _finish_turn_phase(
        phase: TurnPhaseSnapshot,
        *,
        terminal_status: str,
    ) -> TurnPhaseSnapshot:
        """Close a turn through the explicit finalization boundary."""
        return TurnFinalizer.finalize(phase, terminal_status=terminal_status)

    async def run(
        self,
        user_input: str,
        session_id: str,
        task_id: str | None = None,
    ) -> AsyncIterator[Message]:
        """
        Stream one user turn through the model router.

        P0-A intentionally skips real tools, permissions, memory injection, and
        compression. It persists the user message immediately and persists the
        aggregated assistant message after streaming completes.

        ``task_id`` optionally links this turn to a tracked coding task so file
        reads/writes and test results are recorded for observability.
        """
        # A task_id passed to run() overrides the instance default for this turn.
        active_task_id = task_id or self.task_id
        self._active_task_id = active_task_id
        self._active_session_id = session_id
        is_coding = self.mode_manager.current_mode.value == "coding"
        if is_coding and self._verify_fix_factory is not None:
            self.verify_fix_loop = self._verify_fix_factory()
        elif not is_coding:
            self.verify_fix_loop = None
        if self.task_manager is not None and is_coding:
            if active_task_id is None:
                task = await self.task_manager.create(user_input)
                active_task_id = task.id
                self._active_task_id = active_task_id
                await self.task_manager.update_status(active_task_id, "running")
                cognitive_result = await self.task_manager.initialize_cognitive_state(
                    active_task_id
                )
                if not cognitive_result.updated:
                    raise RuntimeError(
                        "new coding task could not initialize cognitive state: "
                        f"{cognitive_result.status.value}"
                    )
                await self._record_memory_runtime_event(
                    "TASK_CREATED",
                    session_id=session_id,
                    task_id=active_task_id,
                    payload={"task_id": active_task_id, "title": user_input[:512]},
                )
                if self.workspace_manager is not None and self.project_root is not None:
                    root = Path(self.project_root).expanduser().resolve()
                    if (root / ".git").exists():
                        self.active_workspace = await self.workspace_manager.create(
                            root,
                            active_task_id,
                            principal_id=self.principal_id,
                            project_id=self.project_id,
                            creator_runtime_id=self.runtime_id,
                        )
                        await self.task_manager.update_status(
                            active_task_id,
                            "running",
                            workspace_id=self.active_workspace.id,
                            worktree_path=str(self.active_workspace.worktree_path),
                            base_sha=self.active_workspace.base_sha,
                        )
                        await self._record_memory_runtime_event(
                            "WORKSPACE_CREATED",
                            session_id=session_id,
                            task_id=active_task_id,
                            payload={
                                "workspace_id": self.active_workspace.id,
                                "worktree_path": str(self.active_workspace.worktree_path),
                                "base_sha": self.active_workspace.base_sha,
                            },
                            workspace_id=self.active_workspace.id,
                            commit_sha=getattr(self.active_workspace, "base_sha", None),
                        )
            else:
                task = await self.task_manager.get(active_task_id)
                if task is not None and task.status.value == "blocked":
                    raise PermissionError(
                        "blocked task must consume its approval capability before resume"
                    )
        from khaos.agent.events import TurnCoordinator

        turn = await TurnCoordinator.start(
            self.turn_repository,
            session_id=session_id,
            task_id=active_task_id,
            principal_id=self.principal_id,
            # M4 batch 3.1.16A-5-1b: stamp the project identity on the
            # agent_turns row.
            project_id=self.project_id,
        )
        self._active_context_facts = await self._build_durable_task_facts(
            active_task_id
        )
        orchestration_phase = TurnAdmission.admit(
            session_id=session_id,
            turn_id=turn.turn_id,
            attempt_id=turn.attempt_id,
            task_id=active_task_id or "",
        )
        total_tokens = 0
        budget_exhausted = False
        stop_reason: str | None = None
        try:
            messages = await self._build_context(session_id, user_input)
            user_msg = Message(
                role="user",
                content=user_input,
                token_count=self.token_engine.count_tokens(user_input),
                created_at=time.time(),
            )
            await self._persist_message(session_id, user_msg, task_id=active_task_id)
            messages.append(user_msg)
            total_tokens += user_msg.token_count
            orchestration_phase = orchestration_phase.transition(
                TurnPhase.CONTEXT_ASSEMBLED,
                context_digest=self._turn_context_digest(messages),
            )

            turn_count = 0

            while turn_count < self.config.max_turns:
                if orchestration_phase.phase is not TurnPhase.MODEL_EXECUTING:
                    orchestration_phase = orchestration_phase.transition(
                        TurnPhase.MODEL_EXECUTING,
                    )
                if self._budget_exceeded(total_tokens):
                    budget_exhausted = True
                    stop_reason = StopReason.MAX_BUDGET.value
                    break
                empty_response_retries = 0
                if await self._check_compression(messages) and self.compressor is not None:
                    result = await self.compressor.compress(
                        messages,
                        self.config.compression_threshold,
                    )
                    messages = result.messages
                    await turn.emit(
                        "context.compacted",
                        {
                            "level": result.level.name,
                            "window_id": result.window_id,
                            "result_digest": result.result_digest,
                            "original_tokens": result.original_tokens,
                            "compressed_tokens": result.compressed_tokens,
                            "replaced_message_count": result.replaced_message_count,
                        },
                    )
                # Phase 6.3: 记录本轮的输入 token（整个上下文）。
                if self.cost_tracker is not None:
                    input_tokens = sum(
                        message.token_count
                        or self.token_engine.count_tokens(message.content)
                        for message in messages
                    )
                    self.cost_tracker.add_input_tokens(input_tokens)
                while True:
                    assistant_content = ""
                    tool_calls: list[dict] = []
                    stop_reason = StopReason.END_TURN.value
                    tools_schema = self._build_tools_schema()
                    call_kwargs = {"tools": tools_schema} if tools_schema is not None else {}

                    async for chunk in self.router.call(
                        self.mode_manager.mode_config.preferred_model_function,
                        messages,
                        **call_kwargs,
                    ):
                        if chunk.content:
                            chunk.metadata.update({
                                "turn_id": turn.turn_id,
                                "attempt_id": turn.attempt_id,
                                "orchestration_phase": orchestration_phase.phase.value,
                                "orchestration_phase_digest": orchestration_phase.digest(),
                            })
                            chunk.token_count = self.token_engine.count_tokens(chunk.content)
                            chunk.created_at = time.time()
                            assistant_content += chunk.content
                            total_tokens += chunk.token_count
                            if self.cost_tracker is not None:
                                self.cost_tracker.add_output_tokens(chunk.token_count)
                            yield chunk
                            if self._budget_exceeded(total_tokens):
                                budget_exhausted = True
                                stop_reason = StopReason.MAX_BUDGET.value
                                break
                        if chunk.tool_calls:
                            for raw_tool_call in chunk.tool_calls:
                                tool_call: dict[str, Any] = cast(
                                    dict[str, Any], dict(raw_tool_call)
                                )
                                bind_operation = getattr(
                                    self.tool_scheduler,
                                    "bind_server_operation_key",
                                    None,
                                )
                                if callable(bind_operation):
                                    tool_call = cast(
                                        dict[str, Any],
                                        bind_operation(
                                            tool_call,
                                            session_id=session_id,
                                            turn_id=turn.turn_id,
                                            attempt_id=turn.attempt_id,
                                            tool_context={
                                                "principal_id": self.principal_id,
                                                "project_id": self.project_id,
                                                "workspace_id": getattr(
                                                    self.active_workspace, "id", None
                                                ),
                                            },
                                        ),
                                    )
                                tool_calls.append(tool_call)
                                turn_event = await turn.emit(
                                    "tool.call",
                                    {
                                        "tool_call_id": str(tool_call.get("id") or ""),
                                        "name": str(tool_call.get("name") or ""),
                                        "operation_id": str(
                                            tool_call.get("_idempotency_key") or ""
                                        ),
                                    },
                                )
                                await self._record_memory_runtime_event(
                                    "TOOL_CALL",
                                    session_id=session_id,
                                    task_id=active_task_id,
                                    workspace_id=getattr(self.active_workspace, "id", None),
                                    payload={
                                        "tool_call_id": str(tool_call.get("id") or ""),
                                        "name": str(tool_call.get("name") or ""),
                                        "operation_id": str(tool_call.get("_idempotency_key") or ""),
                                        "arguments": tool_call.get("arguments") or {},
                                    },
                                    source_type="TOOL",
                                    trust_hint="TOOL_OBSERVED",
                                )
                                yield Message(
                                    role="assistant",
                                    content="",
                                    tool_calls=[tool_call],
                                    event="tool_call",
                                    metadata={
                                        **tool_call,
                                        "turn_id": turn.turn_id,
                                        "attempt_id": turn.attempt_id,
                                        "event_sequence": turn_event.sequence,
                                    },
                                    created_at=time.time(),
                                )
                        if chunk.stop_reason:
                            stop_reason = chunk.stop_reason

                    if budget_exhausted:
                        break
                    if assistant_content.strip() or tool_calls or stop_reason == StopReason.TOOL_USE.value:
                        break
                    if empty_response_retries >= 1:
                        orchestration_phase = self._finish_turn_phase(
                            orchestration_phase,
                            terminal_status="failed",
                        )
                        terminal = await turn.terminal(
                            "failed",
                            reason="empty-model-response",
                            error_code="EMPTY_MODEL_RESPONSE",
                        )
                        yield Message(
                            role="system",
                            content="model returned an empty response",
                            stop_reason="error",
                            event="error",
                            metadata={
                                "code": "EMPTY_MODEL_RESPONSE",
                                "message": "Model returned no text or tool calls.",
                                "turn_id": turn.turn_id,
                                "attempt_id": turn.attempt_id,
                                "event_sequence": terminal.sequence,
                                "orchestration_phase": orchestration_phase.phase.value,
                                "orchestration_phase_digest": orchestration_phase.digest(),
                            },
                            created_at=time.time(),
                        )
                        return
                    empty_response_retries += 1
                    logger.warning("empty model response, retrying once: session=%s", session_id)

                assistant_msg = Message(
                    role="assistant",
                    content=assistant_content,
                    tool_calls=tool_calls,
                    token_count=self.token_engine.count_tokens(assistant_content),
                    created_at=time.time(),
                    stop_reason=stop_reason,
                    metadata={
                        "tool_calls": list(tool_calls)[:32],
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                    },
                )
                messages.append(assistant_msg)
                await self._persist_message(session_id, assistant_msg, task_id=active_task_id)
                turn_count += 1
                # Phase 6.3: 结束本轮 token / 费用统计（无论是否继续工具循环）。
                if self.cost_tracker is not None:
                    self.cost_tracker.finish_turn()

                if budget_exhausted:
                    break

                if stop_reason != StopReason.TOOL_USE.value:
                    break

                if self.tool_scheduler is None:
                    orchestration_phase = self._finish_turn_phase(
                        orchestration_phase,
                        terminal_status="failed",
                    )
                    terminal = await turn.terminal(
                        "failed",
                        reason="tool-scheduler-unavailable",
                        error_code="TOOL_SCHEDULER_UNAVAILABLE",
                    )
                    yield Message(
                        role="system",
                        content="error: tool scheduler is not configured",
                        stop_reason="error",
                        event="error",
                        metadata={
                            "turn_id": turn.turn_id,
                            "attempt_id": turn.attempt_id,
                            "event_sequence": terminal.sequence,
                            "orchestration_phase": orchestration_phase.phase.value,
                            "orchestration_phase_digest": orchestration_phase.digest(),
                        },
                    )
                    return

                active_workspace = self.active_workspace
                workspace_root_identity = (
                    getattr(active_workspace, "root_device", None),
                    getattr(active_workspace, "root_inode", None),
                )
                if workspace_root_identity == (None, None):
                    workspace_root_identity = str(
                        getattr(active_workspace, "worktree_path", "workspace:unspecified")
                    )
                execution_backend = getattr(self.execution_service, "backend", None)
                if execution_backend is None:
                    execution_backend = getattr(
                        self.execution_service, "backend_selector", None
                    )
                execution_backend_identity = (
                    f"{type(execution_backend).__module__}."
                    f"{type(execution_backend).__qualname__}"
                    if execution_backend is not None
                    else "backend:unspecified"
                )
                stream_args = {
                    "session_id": session_id,
                    "confirm_callback": self.confirm_callback,
                    "tool_context": {
                        "execution_service": self.execution_service,
                        "task_id": active_task_id,
                        "workspace_id": getattr(self.active_workspace, "id", None),
                        # StepExecutionAuthority inputs: freeze the active
                        # workspace generation/cwd/backend/environment at the
                        # exact tool step, not just at turn construction.
                        "workspace_generation": int(
                            getattr(active_workspace, "generation", 0) or 0
                        ),
                        "cwd_identity": workspace_root_identity,
                        "workspace_cwd_identity": workspace_root_identity,
                        "workspace_root_identity": workspace_root_identity,
                        "workspace_root": str(
                            getattr(active_workspace, "worktree_path", "")
                        ),
                        "environment_keys": (
                            "LANG", "LC_ALL", "PATH", "TMPDIR"
                        ),
                        "environment": {
                            key: os.environ.get(key, _default_runtime_environment(key))
                            for key in ("LANG", "LC_ALL", "PATH", "TMPDIR")
                        },
                        "sandbox_backend": execution_backend_identity,
                        "workspace_manager": self.workspace_manager,
                        "coding_workspace_enforced": self.active_workspace is not None,
                        "production_runtime": self.runtime_profile.is_production,
                        "approval_broker": self.approval_broker,
                        "credential_broker": self.credential_broker,
                        "requester": session_id,
                        "principal_id": self.principal_id,
                        "principal_kind": self.principal_kind,
                        "parent_principal_id": self.parent_principal_id,
                        "delegation_digest": self.delegation_digest,
                        "source_transport": self.source_transport,
                        "foreground_session": self.foreground_session,
                        # M4 batch 3.1.16A-5-1b: stamp the bound project
                        # identity into ``tool_context`` so the broker can
                        # inject it into orchestrator tools that spawn
                        # sub-agents (``spawn_subagent``).  The sub-agent
                        # inherits this ``project_id`` via ``SubAgentTask``
                        # → ``create_session`` / ``RuntimeConfig``, keeping
                        # every row in the spawn chain scoped to the same
                        # (principal, project) pair as the parent runtime.
                        "project_id": self.project_id,
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        # H5: pass session_id + runtime_id so browser tools
                        # key their BrowserContext by (principal, session,
                        # runtime) — concurrent local sessions under the
                        # same UID get independent contexts.
                        "session_id": session_id,
                        "runtime_id": self.runtime_id,
                        # M4 batch 3.1.16A-4-4-1 (CRITICAL): inject the
                        # caller's principal-scoped PermissionEngine and
                        # the runtime's AuditLogger so the five permission
                        # tools (list_permission_rules / grant_permission /
                        # revoke_permission / query_audit_logs /
                        # security_status) receive them via the
                        # ``permission.read`` / ``permission.manage``
                        # broker injection — no module-global holders, no
                        # cross-principal race.  ``audit_logger`` may be
                        # the server-lifecycle singleton (bound to
                        # ``local-uid``), but the handlers pass
                        # ``principal_id`` explicitly to ``query()`` so
                        # the logger's bound default is overridden per-call.
                        "permission_engine": getattr(
                            self.tool_scheduler, "permission_engine", None
                        ),
                        "audit_logger": getattr(
                            getattr(self.tool_scheduler, "security_middleware", None),
                            "audit_logger",
                            None,
                        ),
                        # M4 batch 3.1.16A-4-4-2: inject ``db`` so the
                        # three history tools (history_search /
                        # history_browse / history_read) can construct a
                        # per-call ``SessionSearch(db, principal_id=...)``
                        # via the ``history.read`` broker injection —
                        # no module-global holder, no cross-principal leak.
                        "db": self.db,
                        # M4 batch 3.1.16A-4-4-3: inject ``channel_registry``
                        # + ``channel_admins`` so the four channel tools
                        # (channel_list / channel_health / channel_enable /
                        # channel_disable) receive them via the
                        # ``channel.read`` / ``channel.manage`` broker
                        # injection.  ``channel_registry`` is the server-
                        # lifecycle ChannelRegistry (previously installed
                        # into a module-global holder by
                        # ``set_channel_registry``); ``channel_admins`` is
                        # the admin principal allowlist compiled into the
                        # immutable EffectiveSecurityPolicy from
                        # ``khaos_policy.yaml``'s ``channels.admin_principals``
                        # field (user ∪ project, OR semantics).  Without
                        # this injection the handlers fall open to the
                        # holder and any principal can mutate channels.
                        "channel_registry": getattr(
                            self, "channel_registry", None
                        ),
                        "channel_admins": getattr(
                            self, "channel_admins", frozenset()
                        ),
                        "cron_engine": getattr(self, "cron_engine", None),
                        "browser_manager": getattr(self, "browser_manager", None),
                        "subagent_spawner": getattr(
                            self, "subagent_spawner", None
                        ),
                    },
                }
                orchestration_phase = orchestration_phase.transition(
                    TurnPhase.TOOL_EXECUTING,
                    tool_batch_digest=self._tool_batch_phase_digest(tool_calls),
                )
                if "tool_context" not in inspect.signature(self.tool_scheduler.stream_batch).parameters:
                    stream_args.pop("tool_context")
                event_stream = self.tool_scheduler.stream_batch(tool_calls, self.mode_manager.current_mode.value, **stream_args)
                verification_phase_entered = False
                async for event in event_stream:
                    if event.permission_request is not None:
                        request = event.permission_request
                        turn_event = await turn.emit(
                            "approval.wait",
                            {
                                "tool_call_id": request.tool_call_id,
                                "binding_digest": request.binding_digest,
                                "expires_at": request.expires_at,
                            },
                        )
                        await self._record_memory_runtime_event(
                            "APPROVAL_REQUESTED",
                            session_id=session_id,
                            task_id=active_task_id,
                            workspace_id=request.workspace_id,
                            payload={
                                "tool_call_id": request.tool_call_id,
                                "name": request.name,
                                "target": request.target,
                                "binding_digest": request.binding_digest,
                                "expires_at": request.expires_at,
                            },
                        )
                        if self.task_manager is not None and active_task_id:
                            await self.task_manager.update_status(
                                active_task_id,
                                "blocked",
                                pending_approval={
                                    "tool_call_id": request.tool_call_id,
                                    "tool_name": request.name,
                                    "target": request.target,
                                    "binding_digest": request.binding_digest,
                                    "expires_at": request.expires_at,
                                    "principal_id": self.principal_id,
                                    "session_id": session_id,
                                },
                            )
                        yield Message(
                            role="system",
                            content="permission_request",
                            event="permission_request",
                            metadata={
                                "id": request.tool_call_id,
                                "name": request.name,
                                "arguments": request.arguments,
                                "level": request.level,
                                "target": request.target,
                                "reason": request.reason,
                                "binding_digest": request.binding_digest,
                                "expires_at": request.expires_at,
                                "principal_id": request.principal_id,
                                "session_id": request.session_id,
                                "task_id": request.task_id,
                                "workspace_id": request.workspace_id,
                                "arguments_digest": request.arguments_digest,
                                "profile_digest": request.profile_digest,
                                "turn_id": turn.turn_id,
                                "attempt_id": turn.attempt_id,
                                "event_sequence": turn_event.sequence,
                            },
                            created_at=time.time(),
                        )
                    if event.result is not None:
                        result = event.result
                        content = json.dumps(
                            {
                                "success": result.success,
                                "output": result.output,
                                "error": result.error,
                                "error_code": result.error_code,
                                "effect_status": result.effect_status,
                                "delivery_status": result.delivery_status,
                                "warning": result.warning,
                                "effect_id": result.effect_id,
                                "phase_digest": result.phase_digest,
                                "retry_safe": result.retry_safe,
                            },
                            ensure_ascii=False,
                        )
                        tool_msg = Message(
                            role="tool",
                            content=content,
                            tool_call_id=result.tool_call_id,
                            token_count=self.token_engine.count_tokens(content),
                            event="tool_result",
                            metadata={
                                "id": result.tool_call_id,
                                "name": result.name,
                                "success": result.success,
                                "output": result.output,
                                "error": result.error,
                                "error_code": result.error_code,
                                "duration_ms": result.duration_ms,
                                "arguments": result.arguments or {},
                                "effect_status": result.effect_status,
                                "delivery_status": result.delivery_status,
                                "warning": result.warning,
                                "effect_id": result.effect_id,
                                "phase_digest": result.phase_digest,
                                "reconciliation_hint": result.reconciliation_hint,
                                "retry_safe": result.retry_safe,
                            },
                            created_at=time.time(),
                        )
                        messages.append(tool_msg)
                        turn_event = await turn.emit(
                            "tool.result",
                            {
                                "tool_call_id": result.tool_call_id,
                                "name": result.name,
                                "success": result.success,
                                "effect_status": result.effect_status,
                                "delivery_status": result.delivery_status,
                                "effect_id": result.effect_id,
                                "phase_digest": result.phase_digest,
                                "reconciliation_hint": result.reconciliation_hint,
                                "retry_safe": result.retry_safe,
                            },
                        )
                        tool_msg.metadata.update({
                            "turn_id": turn.turn_id,
                            "attempt_id": turn.attempt_id,
                            "event_sequence": turn_event.sequence,
                        })
                        await self._persist_message(
                            session_id,
                            tool_msg,
                            task_id=active_task_id,
                            workspace_id=getattr(self.active_workspace, "id", None),
                            commit_sha=getattr(self.active_workspace, "base_sha", None),
                        )
                        if self.cost_tracker is not None:
                            self.cost_tracker.add_tool_tokens(tool_msg.token_count)
                        total_tokens += tool_msg.token_count
                        if self._budget_exceeded(total_tokens):
                            budget_exhausted = True
                            stop_reason = StopReason.MAX_BUDGET.value
                        # Long-task observability: record what this turn touched.
                        await self._record_task_activity(result, active_task_id)
                        if result.name == "test_run" and self.task_manager is not None and active_task_id:
                            await self.task_manager.update_status(active_task_id, "waiting_test")
                        if self.task_manager is not None and active_task_id:
                            await self.task_manager.record_trace(
                                active_task_id,
                                {"tool_name": result.name, "arguments": result.arguments or {}, "success": result.success, "result_summary": str(result.output or result.error)[:500], "timestamp": time.time()},
                            )
                        # Verify-fix loop: when a test_run result contains
                        # failures, inject a guidance message so the model
                        # diagnoses, fixes, and re-runs the tests.
                        if self.verify_fix_loop is not None:
                            result_dict = {
                                "name": result.name,
                                "success": result.success,
                                "output": result.output,
                                "error": result.error,
                            }
                            # Observation is deliberately first and is not
                            # hidden inside should_enter_loop(). This records
                            # every parseable test result, including results
                            # received after the repair budget is exhausted.
                            verification_observation = (
                                self.verify_fix_loop.observe_test_result(
                                    result_dict
                                )
                            )
                            if self.verify_fix_loop.should_enter_loop(
                                result_dict,
                                observation=verification_observation,
                            ):
                                failure_context = (
                                    self.verify_fix_loop.build_failure_context(
                                        result_dict,
                                        observation=verification_observation,
                                    )
                                )
                                if failure_context:
                                    if not verification_phase_entered:
                                        orchestration_phase = orchestration_phase.transition(
                                            TurnPhase.VERIFYING,
                                            verification_digest=digest_phase_payload(
                                                result_dict
                                            ),
                                        )
                                        verification_phase_entered = True
                                    fix_msg = Message(
                                        role="system",
                                        content=failure_context,
                                        token_count=self.token_engine.count_tokens(
                                            failure_context
                                        ),
                                        event="verify_fix",
                                        created_at=time.time(),
                                    )
                                    messages.append(fix_msg)
                                    await self._persist_message(
                                        session_id,
                                        fix_msg,
                                        task_id=active_task_id,
                                        workspace_id=getattr(self.active_workspace, "id", None),
                                    )
                                    await self._record_memory_runtime_event(
                                        "VERIFICATION_RESULT",
                                        session_id=session_id,
                                        task_id=active_task_id,
                                        workspace_id=getattr(self.active_workspace, "id", None),
                                        payload={
                                            "result": False,
                                            "tool_name": result.name,
                                            "failure_context": failure_context,
                                            "attempt": self.verify_fix_loop.attempt_count,
                                        },
                                        source_type="VERIFICATION",
                                    )
                                    if self.task_manager is not None and active_task_id:
                                        await self.task_manager.update_status(
                                            active_task_id,
                                            "fixing",
                                            fix_attempts=self.verify_fix_loop.attempt_count,
                                        )
                                    yield fix_msg
                            # Exhaustion is a terminal interpretation of the
                            # latest observed failure, not of the repair count
                            # alone. Emit the report once, after observation,
                            # even when no further repair can be admitted.
                            if (
                                self.verify_fix_loop.is_loop_exhausted()
                                and not self.verify_fix_loop.report_emitted
                            ):
                                report = self.verify_fix_loop.get_final_report()
                                self.verify_fix_loop.mark_report_emitted()
                                yield Message(
                                    role="system",
                                    content=report,
                                    event="verify_fix_report",
                                    created_at=time.time(),
                                )
                        yield tool_msg

                if budget_exhausted:
                    break

            else:
                stop_reason = StopReason.MAX_TURNS.value

            coding_completion_proposed = (
                is_coding
                and active_task_id is not None
                and stop_reason == StopReason.END_TURN.value
            )
            if coding_completion_proposed:
                assert active_task_id is not None
                completion_result = await self._propose_completion(
                    turn=turn,
                    task_id=active_task_id,
                )
                yield self._completion_result_message(
                    result=completion_result,
                    turn_id=turn.turn_id,
                    attempt_id=turn.attempt_id,
                    task_id=active_task_id,
                )
                from khaos.agent.control.completion_flow import (
                    CompletionProposalStatus,
                )

                if completion_result.status is CompletionProposalStatus.RECORDED:
                    assert completion_result.decision is not None
                    gate_result = await self._evaluate_completion_gate(
                        turn=turn,
                        task_id=active_task_id,
                        decision_id=completion_result.decision.decision_id,
                    )
                    yield self._completion_gate_message(
                        result=gate_result,
                        turn_id=turn.turn_id,
                        attempt_id=turn.attempt_id,
                        task_id=active_task_id,
                    )

            if self.task_manager is not None and active_task_id:
                await self._finalize_task(
                    active_task_id,
                    stop_reason,
                )

            # Non-terminal accounting events must precede the durable terminal.
            if self.cost_tracker is not None:
                summary = self.cost_tracker.format_summary()
                if summary:
                    yield Message(
                        role="system",
                        content=summary,
                        event="cost_summary",
                        metadata={
                            "cost_report": self.cost_tracker.get_report().__dict__,
                            "turn_id": turn.turn_id,
                            "attempt_id": turn.attempt_id,
                        },
                        created_at=time.time(),
                    )
            terminal_status = (
                "failed"
                if stop_reason == StopReason.MAX_BUDGET.value
                and turn.active_tool_calls
                else "completed"
            )
            orchestration_phase = self._finish_turn_phase(
                orchestration_phase,
                terminal_status=terminal_status,
            )
            terminal = await turn.terminal(
                terminal_status,
                reason=stop_reason or StopReason.END_TURN.value,
                error_code=("MAX_BUDGET" if terminal_status == "failed" else None),
            )
            if terminal_status == "failed":
                yield Message(
                    role="system",
                    content=(
                        "token budget exhausted; outstanding tool calls were not "
                        "executed"
                    ),
                    stop_reason="error",
                    event="error",
                    metadata={
                        "code": "MAX_BUDGET",
                        "message": (
                            "Token budget exhausted with outstanding tool calls."
                        ),
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": terminal.sequence,
                        "orchestration_phase": orchestration_phase.phase.value,
                        "orchestration_phase_digest": orchestration_phase.digest(),
                    },
                    created_at=time.time(),
                )
            else:
                yield Message(
                    role="system",
                    content="done",
                    token_count=total_tokens,
                    stop_reason=stop_reason,
                    event="done",
                    metadata={
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": terminal.sequence,
                        "orchestration_phase": orchestration_phase.phase.value,
                        "orchestration_phase_digest": orchestration_phase.digest(),
                    },
                    created_at=time.time(),
                )
        except asyncio.CancelledError:
            if self.task_manager is not None and active_task_id:
                await self.task_manager.update_status(active_task_id, "cancelled", error="task cancelled")
            try:
                orchestration_phase = self._finish_turn_phase(
                    orchestration_phase,
                    terminal_status="interrupted",
                )
            except OrchestrationPhaseError:
                logger.exception("failed to finalize orchestration phase")
            if not turn.is_terminal:
                await turn.terminal(
                    "interrupted", reason="user-cancelled", error_code="USER_ABORT"
                )
            raise
        except Exception as exc:
            logger.exception("Agent loop error")
            if self.task_manager is not None and active_task_id:
                await self.task_manager.update_status(active_task_id, "failed", error=str(exc))
            try:
                orchestration_phase = self._finish_turn_phase(
                    orchestration_phase,
                    terminal_status="failed",
                )
            except OrchestrationPhaseError:
                logger.exception("failed to finalize orchestration phase")
            terminal = None
            error_code = (
                "COMPRESSION_CIRCUIT_OPEN"
                if isinstance(exc, CompressionCircuitOpenError)
                else "ORCHESTRATION_PHASE_ERROR"
                if isinstance(exc, OrchestrationPhaseError)
                else "INTERNAL_ERROR"
            )
            if not turn.is_terminal:
                terminal = await turn.terminal(
                    "failed", reason=type(exc).__name__, error_code=error_code
                )
            if self.error_handler is not None:
                error_event = await self.error_handler.handle(exc, session_id)
                message = error_event.to_message()
                if terminal is not None:
                    message.metadata.update({
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": terminal.sequence,
                        "orchestration_phase": orchestration_phase.phase.value,
                        "orchestration_phase_digest": orchestration_phase.digest(),
                    })
                yield message
            else:
                yield Message(
                    role="system",
                    content=f"error: {exc}",
                    stop_reason="error",
                    event="error",
                    metadata={
                        "code": error_code,
                        "message": str(exc),
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": (
                            terminal.sequence if terminal is not None else turn.sequence
                        ),
                        "orchestration_phase": orchestration_phase.phase.value,
                        "orchestration_phase_digest": orchestration_phase.digest(),
                    },
                )
        finally:
            if not turn.is_terminal:
                try:
                    orchestration_phase = self._finish_turn_phase(
                        orchestration_phase,
                        terminal_status="interrupted",
                    )
                    await turn.terminal(
                        "interrupted",
                        reason="consumer-disconnected",
                        error_code="STREAM_CLOSED",
                    )
                except Exception:
                    logger.exception(
                        "failed to persist interrupted turn: %s", turn.turn_id
                    )
            self._active_task_id = None

    async def _persist_message(
        self,
        session_id: str,
        message: Message,
        *,
        task_id: str | None = None,
        workspace_id: str | None = None,
        repo_id: str | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
    ) -> None:
        """Persist and index a message as one logical core-loop operation.

        M4 batch 3.1.16A-4-3: stamp ``self.principal_id`` on the row so
        ``list_messages`` / ``get_session_messages`` / ``search_sessions``
        can scope by the calling principal.

        M4 batch 3.1.16A-5-1b: stamp ``self.project_id`` so the message
        is cryptographically tied to the project that produced it.
        ``insert_message``'s ``ON CONFLICT`` does NOT touch
        ``project_id`` — owner-preserving.
        """
        rowid = await self.db.insert_message(
            session_id, message,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        await self.db.insert_message_fts(
            session_id, message.role, message.content, message.token_count, rowid=rowid
        )
        # Memory V2 observes the durable message after the canonical session
        # write.  Event-ledger failure is deliberately isolated from the
        # AgentLoop: memory is allowed to become unavailable, but that must
        # never relax or break the execution/approval path.
        record_event = getattr(self.memory_manager, "record_message", None)
        if callable(record_event):
            try:
                await record_event(
                    message,
                    session_id=session_id,
                    task_id=(
                        task_id
                        if task_id is not None
                        else getattr(self, "_active_task_id", None)
                    ),
                    workspace_id=workspace_id,
                    repo_id=repo_id,
                    commit_sha=commit_sha,
                    branch=branch,
                )
            except Exception:
                logger.warning(
                    "memory event observation failed; continuing turn",
                    exc_info=True,
                )

    async def _record_memory_runtime_event(
        self,
        event_type: str,
        *,
        session_id: str,
        task_id: str | None,
        payload: dict[str, Any],
        workspace_id: str | None = None,
        repo_id: str | None = None,
        commit_sha: str | None = None,
        branch: str | None = None,
        source_type: str = "SYSTEM",
        trust_hint: str = "AGENT_INFERRED",
    ) -> None:
        """Publish runtime provenance without affecting agent execution."""

        recorder = getattr(
            getattr(self, "memory_manager", None),
            "record_runtime_event",
            None,
        )
        if not callable(recorder):
            return
        try:
            await recorder(
                event_type,
                session_id=session_id,
                task_id=task_id,
                workspace_id=workspace_id,
                repo_id=repo_id,
                commit_sha=commit_sha,
                branch=branch,
                payload=payload,
                source_type=source_type,
                trust_hint=trust_hint,
            )
        except Exception:
            logger.warning(
                "memory runtime event observation failed; continuing turn",
                exc_info=True,
            )

    def _budget_exceeded(self, total_tokens: int) -> bool:
        """Return whether the current turn has crossed its hard token budget."""
        exceeded = total_tokens > self.config.max_budget_tokens
        if exceeded:
            logger.warning(
                "agent token budget exhausted: used=%d budget=%d",
                total_tokens,
                self.config.max_budget_tokens,
            )
        return exceeded

    def _ensure_completion_controller(self) -> CompletionProposalController | None:
        """Build the default proposal controller for a DB-backed coding task.

        The runtime factory normally injects this controller explicitly.  The
        lazy fallback keeps direct, authenticated AgentLoop construction
        compatible while still requiring the existing composed repositories;
        it never creates a new database or authority owner.
        """
        controller = self.completion_controller
        if controller is not None:
            return controller
        if self.db is None or self.task_manager is None:
            return None

        from khaos.agent.control.completion_flow import (
            CompletionProposalController,
            EmptyCompletionFactProvider,
        )

        goal_spec_repository = getattr(
            self.task_manager,
            "goal_spec_repository",
            None,
        )
        if goal_spec_repository is None:
            goal_spec_repository = getattr(self.db, "goal_spec_repository", None)
        decision_repository = getattr(
            self.db,
            "completion_decision_repository",
            None,
        )
        if goal_spec_repository is None or decision_repository is None:
            return None

        fact_provider = self.completion_fact_provider
        if fact_provider is None:
            fact_provider = EmptyCompletionFactProvider()
        controller = CompletionProposalController(
            goal_spec_repository=goal_spec_repository,
            decision_repository=decision_repository,
            principal_id=self.principal_id,
            project_id=self.project_id,
            fact_provider=fact_provider,
        )
        self.completion_controller = controller
        return controller

    def _ensure_completion_gate(self) -> CompletionGate | None:
        """Build the fail-closed Gate from the existing DB repositories."""
        gate = self.completion_gate
        if gate is not None:
            return gate
        if self.db is None or self.task_manager is None:
            return None

        from khaos.agent.control.completion_gate import CompletionGate

        goal_spec_repository = getattr(
            self.task_manager,
            "goal_spec_repository",
            None,
        )
        if goal_spec_repository is None:
            goal_spec_repository = getattr(self.db, "goal_spec_repository", None)
        decision_repository = getattr(
            self.db,
            "completion_decision_repository",
            None,
        )
        if goal_spec_repository is None or decision_repository is None:
            return None
        gate = CompletionGate(
            decision_repository=decision_repository,
            goal_spec_repository=goal_spec_repository,
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        self.completion_gate = gate
        return gate

    async def _propose_completion(
        self,
        *,
        turn: Any,
        task_id: str,
    ) -> CompletionProposalResult:
        """Evaluate a structured END_TURN proposal without task projection."""
        from khaos.agent.control.completion_flow import (
            CompletionProposal,
            CompletionProposalResult,
            CompletionProposalStatus,
            CompletionProposalTrigger,
        )

        proposal = CompletionProposal(
            task_id=task_id,
            turn_id=turn.turn_id,
            attempt_id=turn.attempt_id,
            trigger=CompletionProposalTrigger.MODEL_END_TURN,
        )
        await turn.emit(
            "completion.proposed",
            {
                "task_id": proposal.task_id,
                "turn_id": proposal.turn_id,
                "attempt_id": proposal.attempt_id,
                "trigger": proposal.trigger.value,
            },
        )

        controller = self._ensure_completion_controller()
        if controller is None:
            result = CompletionProposalResult(
                status=CompletionProposalStatus.REJECTED,
                decision=None,
                decision_sequence=None,
                reason="completion controller is unavailable.",
            )
        else:
            result = await controller.propose(proposal)

        payload: dict[str, Any] = {
            "task_id": proposal.task_id,
            "turn_id": proposal.turn_id,
            "attempt_id": proposal.attempt_id,
            "status": result.status.value,
        }
        if result.decision is not None:
            payload.update(
                {
                    "decision_id": result.decision.decision_id,
                    "decision_digest": result.decision.decision_digest,
                    "decision_sequence": result.decision_sequence,
                    "outcome": result.decision.outcome.value,
                }
            )
        if result.reason:
            payload["reason"] = result.reason
        await turn.emit("completion.evaluated", payload)
        return result

    async def _evaluate_completion_gate(
        self,
        *,
        turn: Any,
        task_id: str,
        decision_id: str,
    ) -> CompletionGateResult:
        """Run the Gate after a recorded proposal and emit its bounded event."""
        from khaos.agent.control.completion_gate import (
            CompletionGateResult,
            CompletionGateStatus,
        )

        gate = self._ensure_completion_gate()
        if gate is None:
            result = CompletionGateResult(
                status=CompletionGateStatus.ERROR,
                decision_id=decision_id,
                decision_digest=None,
                task_status=None,
                reason="completion gate is unavailable",
            )
        else:
            result = await gate.evaluate(decision_id)
        if (
            result.status is CompletionGateStatus.COMPLETED
            and self.task_manager is not None
        ):
            # The Gate owns the durable SQL projection.  Keep this loop's
            # cache aligned before the post-turn skill/trace projection can
            # persist anything, even when a caller supplied a Gate without
            # its optional cache sink.
            await self.task_manager.reflect_gate_completion(task_id)
        await turn.emit(
            "completion.gated",
            {
                "task_id": task_id,
                "decision_id": result.decision_id,
                "decision_digest": result.decision_digest,
                "gate_status": result.status.value,
                "resulting_task_status": result.task_status,
                **({"reason": result.reason} if result.reason else {}),
            },
        )
        return result

    @staticmethod
    def _completion_result_message(
        *,
        result: CompletionProposalResult,
        turn_id: str,
        attempt_id: str,
        task_id: str,
    ) -> Message:
        """Expose a bounded passive proposal result to turn consumers."""
        metadata: dict[str, Any] = {
            "task_id": task_id,
            "turn_id": turn_id,
            "attempt_id": attempt_id,
            "status": result.status.value,
        }
        if result.decision is not None:
            metadata.update(
                {
                    "decision_id": result.decision.decision_id,
                    "decision_digest": result.decision.decision_digest,
                    "decision_sequence": result.decision_sequence,
                    "outcome": result.decision.outcome.value,
                }
            )
        if result.reason:
            metadata["reason"] = result.reason
        return Message(
            role="system",
            content="completion proposal evaluated",
            event="completion_evaluated",
            metadata=metadata,
            created_at=time.time(),
        )

    @staticmethod
    def _completion_gate_message(
        *,
        result: CompletionGateResult,
        turn_id: str,
        attempt_id: str,
        task_id: str,
    ) -> Message:
        """Expose a bounded passive Gate result to turn consumers."""
        metadata: dict[str, Any] = {
            "task_id": task_id,
            "turn_id": turn_id,
            "attempt_id": attempt_id,
            "status": result.status.value,
            "decision_id": result.decision_id,
            "decision_digest": result.decision_digest,
            "task_status": result.task_status,
        }
        if result.reason:
            metadata["reason"] = result.reason
        return Message(
            role="system",
            content="completion gate evaluated",
            event="completion_gated",
            metadata=metadata,
            created_at=time.time(),
        )

    async def _analyze_task_skill(self, task_id: str) -> None:
        if self.skill_generator is None or self.task_manager is None:
            return
        from khaos.skills import TaskTrace, ToolTrace

        task = await self.task_manager.get(task_id)
        if task is None:
            return
        trace = TaskTrace(
            task_id=task.id,
            goal=task.goal,
            tools_called=[ToolTrace(**entry) for entry in task.trace],
            files_modified=task.files_modified,
            test_results=task.test_results,
            status=task.status.value,
        )
        candidates = self.skill_generator.analyze(trace)
        await self.task_manager.update_status(
            task_id,
            task.status,
            skill_candidates=[candidate.__dict__ for candidate in candidates],
        )
        if candidates:
            await self._record_memory_runtime_event(
                "SKILL_CANDIDATE_CREATED",
                session_id=getattr(self, "_active_session_id", ""),
                task_id=task_id,
                workspace_id=getattr(self.active_workspace, "id", None),
                commit_sha=getattr(self.active_workspace, "base_sha", None),
                payload={
                    "task_id": task_id,
                    "candidates": [candidate.__dict__ for candidate in candidates],
                },
                source_type="TASK",
            )

    async def _finalize_task(
        self,
        task_id: str,
        stop_reason: str | None,
    ) -> None:
        """Apply non-success terminal semantics after a turn.

        Successful coding-task projection is intentionally absent here.  The
        Completion Gate is the sole control-plane owner of COMPLETE ->
        ``TaskStatus.COMPLETED``.
        """
        from khaos.coding.task_manager import TaskStatus
        from khaos.coding.verify_fix import VerificationState

        if stop_reason == StopReason.MAX_TURNS.value:
            await self.task_manager.update_status(task_id, TaskStatus.FAILED, error="max_turns exhausted without completion")
        elif stop_reason == StopReason.MAX_BUDGET.value:
            await self.task_manager.update_status(
                task_id,
                TaskStatus.FAILED,
                error="token budget exhausted without completion",
            )
        elif self.verify_fix_loop is not None:
            verification_state = self.verify_fix_loop.verification_state
            if verification_state is VerificationState.EXHAUSTED_FAILURE:
                await self.task_manager.update_status(
                    task_id,
                    TaskStatus.FAILED,
                    error="verify-fix loop exhausted, tests still failing",
                )
            elif verification_state is VerificationState.FAILING:
                # A model END_TURN cannot erase the latest known failing
                # verification result. UNKNOWN remains legacy-compatible until
                # the M7 Completion Gate owns this decision.
                await self.task_manager.update_status(
                    task_id,
                    TaskStatus.FAILED,
                    error="latest verification is failing; task did not complete",
                )
            # A passing/unknown verification result does not authorize task
            # completion. The Gate owns the successful lifecycle projection.
        await self._analyze_task_skill(task_id)
        task = await self.task_manager.get(task_id)
        await self._record_memory_runtime_event(
            "TASK_TRANSITION",
            session_id=getattr(self, "_active_session_id", ""),
            task_id=task_id,
            workspace_id=getattr(getattr(self, "active_workspace", None), "id", None),
            commit_sha=getattr(getattr(self, "active_workspace", None), "base_sha", None),
            payload={
                "task_id": task_id,
                "status": getattr(
                    getattr(task, "status", None),
                    "value",
                    getattr(task, "status", ""),
                ),
                "rationale": (
                    "turn finalized; completion projection is Gate-owned"
                    if stop_reason == StopReason.END_TURN.value
                    else stop_reason or "turn finalized"
                ),
            },
            source_type="TASK",
        )
    async def _build_context(self, session_id: str, user_input: str = "") -> list[Message]:
        """Build the P0-A context from mode prompt and persisted messages.

        In coding mode (when ``project_root`` is set) this also injects:

        1. The project structure tree into the *system* prompt (see
           :meth:`_build_system_prompt`) — kept small (≤ token budget).
        2. The contents of files relevant to ``user_input`` as an extra
           ``# Relevant Files`` system message appended *after* the persisted
           history, so the model sees them just before the current turn.

        Neither injection happens in office mode or when ``project_root`` is
        unset, so non-coding behaviour is unchanged.
        """
        messages = [
            Message(
                role="system",
                content=await self._build_system_prompt(session_id, user_input),
                token_count=0,
                metadata={
                    "durable_fact": True,
                    "context_layer": "immutable-rules",
                },
            )
        ]
        messages.extend(
            await self.db.list_messages(
                session_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
        )
        messages.extend(self._active_context_facts)

        relevant = self._build_relevant_files_message(user_input)
        if relevant is not None:
            messages.append(relevant)

        return messages

    async def _build_durable_task_facts(
        self, task_id: str | None
    ) -> list[Message]:
        """Reconstruct authoritative Task/approval facts outside summaries."""
        if task_id is None or self.task_manager is None:
            return []
        task = await self.task_manager.get(task_id)
        if task is None:
            return []
        raw = task.to_dict(include_internal=True)
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        goal_spec = getattr(task, "goal_spec", None)
        facts = {
            "task_id": raw.get("id"),
            "goal": raw.get("goal"),
            "status": raw.get("status"),
            "cognitive_state": getattr(
                getattr(task, "cognitive_state", None),
                "value",
                None,
            ),
            "control_state_version": getattr(
                task, "control_state_version", None
            ),
            # M7.1.2: these are bounded durable references/projections.  The
            # canonical GoalSpec body remains in agent_goal_specs and is not
            # copied into task metadata or injected wholesale.
            "goal_spec_id": getattr(task, "goal_spec_id", None),
            "goal_spec_digest": getattr(task, "goal_spec_digest", None),
            "workspace_id": metadata.get("workspace_id"),
            "base_sha": metadata.get("base_sha"),
            "pending_approval": metadata.get("pending_approval"),
            "plan_id": metadata.get("plan_id"),
            "changeset_id": metadata.get("changeset_id"),
            "verification_run_id": metadata.get("verification_run_id"),
        }
        if goal_spec is not None:
            max_goal_fact_chars = 4096
            facts["goal_spec_raw_goal"] = goal_spec.raw_goal[:max_goal_fact_chars]
            facts["goal_spec_normalized_goal"] = goal_spec.normalized_goal[
                :max_goal_fact_chars
            ]
            facts["goal_spec_raw_goal_truncated"] = len(
                goal_spec.raw_goal
            ) > max_goal_fact_chars
            facts["goal_spec_requirements"] = [
                {
                    "requirement_id": requirement.requirement_id,
                    "description": requirement.description[:max_goal_fact_chars],
                    "required": requirement.required,
                    "source": requirement.source.value,
                    "description_truncated": len(requirement.description)
                    > max_goal_fact_chars,
                }
                for requirement in goal_spec.requirements[:32]
            ]
            facts["goal_spec_requirements_truncated"] = len(
                goal_spec.requirements
            ) > 32
        content = "# Durable Task Facts\n" + json.dumps(
            facts, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return [Message(
            role="system",
            content=content,
            token_count=self.token_engine.count_tokens(content),
            metadata={
                "durable_fact": True,
                "context_layer": "durable-facts",
                "task_id": task_id,
            },
        )]

    def _build_tools_schema(self) -> list[dict] | None:
        """Return provider-neutral function tool schemas for the current mode."""
        if self.tool_scheduler is None:
            return None
        registry = getattr(self.tool_scheduler, "registry", None)
        if registry is None:
            return None
        mode = self.mode_manager.current_mode.value
        tool_defs = registry.list_by_mode(mode)
        if not tool_defs:
            return None
        return [
            {
                "type": "function",
                "function": {
                    "name": tool_def.name,
                    "description": tool_def.description,
                    "parameters": tool_def.parameters,
                },
            }
            for tool_def in tool_defs
        ]

    async def _build_system_prompt(self, session_id: str, user_input: str = "") -> str:
        # 注入顺序：项目约定文件 > memory > skill > 项目结构（见 AGENTS.md Phase 6）
        prompt = await self.mode_manager.load_system_prompt()

        if self.project_context_loader is not None:
            project_ctx = self.project_context_loader.load()
            if project_ctx:
                prompt = f"{prompt}\n\n# Project Instructions\n\n{project_ctx}"

        if self.memory_manager is not None:
            memory_text = await self.memory_manager.inject(session_id)
            if memory_text:
                prompt = f"{prompt}\n\n{memory_text}"
        if self.skill_manager is not None:
            mode = self.mode_manager.current_mode.value
            matched = self.skill_manager.match(mode, user_input)
            skill_text = self.skill_manager.format_for_prompt(matched)
            if skill_text:
                prompt = f"{prompt}\n\n{skill_text}"

        structure = self._build_project_structure()
        if structure:
            prompt = f"{prompt}\n\n{structure}"

        return prompt

    def _is_coding_mode(self) -> bool:
        """Return True when the active mode is coding and a project root is set."""
        if self.project_root is None:
            return False
        try:
            return self.mode_manager.current_mode.value == "coding"
        except AttributeError:
            return False

    def _build_project_structure(self) -> str:
        """Return a ``# Project Structure`` block for the system prompt.

        Only populated in coding mode. The tree is trimmed to the configured
        token budget so it never dominates the system prompt.
        """
        if not self._is_coding_mode():
            return ""
        builder = self.coding_context_builder
        if builder is None:
            return ""
        try:
            from pathlib import Path

            root = Path(self.project_root).expanduser().resolve()
            index = builder.indexer.scan(root)
        except (OSError, FileNotFoundError, NotADirectoryError) as exc:
            logger.warning("coding project structure scan failed: %s", exc)
            return ""
        except Exception as exc:  # noqa: BLE001 — scan must never break the loop
            logger.warning("coding project structure scan errored: %s", exc)
            return ""

        tree = str(index.get("tree", ""))
        budget = getattr(self.config, "project_structure_token_budget", 2000)
        trimmed = self._trim_to_budget(tree, budget)
        return f"# Project Structure\n\n{trimmed}"

    def _build_relevant_files_message(self, user_input: str):
        """Return a ``# Relevant Files`` system Message, or None.

        Aggregates the file contents collected by the coding context builder
        into one fenced block per file. Returns None outside coding mode or
        when no relevant files are found.

        When a ``file_fingerprint_cache`` is configured, only files whose
        content changed since the last injection are actually included; the
        rest are skipped to save tokens. Each header is annotated with its
        status: ``(changed)`` or ``(cached)``.
        """
        if not self._is_coding_mode():
            return None
        builder = self.coding_context_builder
        if builder is None:
            return None
        try:
            from pathlib import Path

            root = Path(self.project_root).expanduser().resolve()
            context_files = builder.build(user_input, root, target_files=None)
        except (OSError, FileNotFoundError, NotADirectoryError) as exc:
            logger.warning("coding relevant-files build failed: %s", exc)
            return None
        except Exception as exc:  # noqa: BLE001 — context build must not break the loop
            logger.warning("coding relevant-files build errored: %s", exc)
            return None

        if not context_files:
            return None

        try:
            root_for_rel = Path(self.project_root).expanduser().resolve()
        except (OSError, ValueError):
            root_for_rel = None

        cache = self.file_fingerprint_cache
        blocks: list[str] = ["# Relevant Files\n"]
        skipped = 0
        for entry in context_files:
            path = entry["path"]
            content = entry["content"]
            path_key = str(path)

            # Fingerprint filter: skip unchanged files, inject only changed ones.
            if cache is not None:
                if not cache.is_changed(path_key, content):
                    skipped += 1
                    continue
                cache.update(path_key, content)
                status = "changed"
            else:
                status = "changed"  # no cache → treat everything as fresh

            if root_for_rel is not None:
                try:
                    display = str(Path(path).relative_to(root_for_rel))
                except ValueError:
                    display = str(path)
            else:
                display = str(path)
            language = self._language_for_path(str(path))
            blocks.append(
                f"## {display} ({status})\n```{language}\n{content}\n```\n"
            )

        if skipped > 0:
            logger.info(
                "fingerprint cache skipped %d unchanged files (of %d)",
                skipped,
                len(context_files),
            )

        # If a cache is configured and every candidate was unchanged, there is
        # nothing to inject this turn.
        if cache is not None and len(blocks) == 1:
            return None

        text = (
            "<untrusted_repository_content>\n"
            + "\n".join(blocks)
            + "\n</untrusted_repository_content>"
        )
        return Message(
            role="user",
            content=text,
            token_count=self.token_engine.count_tokens(text),
            metadata={
                "context_layer": "ephemeral-observation",
                "trusted": False,
            },
        )

    def _trim_to_budget(self, text: str, budget: int) -> str:
        """Trim ``text`` to approximately ``budget`` tokens, on line boundaries."""
        if not text or budget <= 0:
            return ""
        if self.token_engine.count_tokens(text) <= budget:
            return text
        lines = text.splitlines()
        kept: list[str] = []
        used = 0
        for line in lines:
            line_tokens = self.token_engine.count_tokens(line)
            if used + line_tokens > budget:
                break
            kept.append(line)
            used += line_tokens
        if not kept:
            kept = lines[:1]
        kept.append(f"... (trimmed, {len(lines) - len(kept)} more lines)")
        return "\n".join(kept)

    @staticmethod
    def _language_for_path(path: str) -> str:
        """Map a file extension to a fenced-code language hint."""
        suffix = path.rsplit(".", 1)[-1].lower() if "." in path else ""
        mapping = {
            "py": "python",
            "go": "go",
            "rs": "rust",
            "js": "javascript",
            "jsx": "jsx",
            "ts": "typescript",
            "tsx": "tsx",
            "md": "markdown",
            "toml": "toml",
            "yaml": "yaml",
            "yml": "yaml",
            "json": "json",
            "txt": "text",
        }
        return mapping.get(suffix, "")

    async def _record_task_activity(self, result, task_id: str | None) -> None:
        """Record a tool result against the tracked coding task, if any.

        Maps tool names to task fields: ``read_file``/``list_directory`` →
        viewed, ``write_file``/``patch``/``multi_edit`` → modified,
        ``test_run`` → a test result entry. Failures are non-fatal — task
        tracking is observability only and must never break the loop.
        """
        if self.task_manager is None or not task_id:
            return
        try:
            name = result.name
            args = result.arguments or {}
            output = result.output
            if name in {"read_file", "list_directory"}:
                path = args.get("path") or args.get("cwd")
                if path:
                    await self.task_manager.track_file_viewed(task_id, str(path))
            elif name in {"write_file", "patch", "multi_edit"}:
                path = args.get("path")
                if path:
                    await self.task_manager.track_file_modified(task_id, str(path))
            elif name == "test_run":
                await self.task_manager.add_test_result(
                    task_id, {"success": result.success, "output": output}
                )
            event_type = {
                "read_file": "FILE_OBSERVED",
                "list_directory": "FILE_OBSERVED",
                "write_file": "PATCH_APPLIED",
                "patch": "PATCH_APPLIED",
                "multi_edit": "PATCH_APPLIED",
                "test_run": "VERIFICATION_RESULT",
                "git_commit": "COMMIT_OBSERVED",
                "commit": "COMMIT_OBSERVED",
                "execute_plan": "PLAN_CREATED",
            }.get(name)
            if event_type:
                event_payload = {
                    "tool_name": name,
                    "success": bool(result.success),
                    "arguments": args,
                    "output_summary": str(output or result.error)[:2048],
                }
                if event_type == "PLAN_CREATED":
                    event_payload["plan"] = args.get(
                        "plan_json", args.get("plan", "")
                    )
                await self._record_memory_runtime_event(
                    event_type,
                    session_id=getattr(self, "_active_session_id", ""),
                    task_id=task_id,
                    workspace_id=getattr(self.active_workspace, "id", None),
                    commit_sha=getattr(self.active_workspace, "base_sha", None),
                    payload=event_payload,
                    source_type=(
                        "VERIFICATION"
                        if event_type == "VERIFICATION_RESULT"
                        else "TASK"
                        if event_type == "PLAN_CREATED"
                        else "TOOL"
                    ),
                    trust_hint="TOOL_OBSERVED",
                )
        except Exception as exc:  # noqa: BLE001 — observability must not break the loop
            logger.warning("task tracking failed: %s", exc)

    async def _check_compression(self, messages: list[Message]) -> bool:
        total_tokens = sum(
            message.token_count or self.token_engine.count_tokens(message.content)
            for message in messages
        )
        return total_tokens > self.config.compression_threshold
