"""P0-A agent loop with mock streaming model support."""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator, Optional

if TYPE_CHECKING:
    from khaos.coding.cost_tracker import CostTracker
    from khaos.coding.fingerprint import FileFingerprintCache
    from khaos.coding.task_manager import TaskManager
    from khaos.coding.verify_fix import VerifyFixLoop
    from khaos.project_context import ProjectContextLoader

logger = logging.getLogger(__name__)


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
    tool_call_id: Optional[str] = None
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
        tool_scheduler=None,
        confirm_callback=None,
        context_compressor=None,
        memory_manager=None,
        error_handler=None,
        token_engine: SimpleTokenEngine | None = None,
        skill_manager=None,
        project_root=None,
        coding_context_builder=None,
        project_context_loader: "Optional[ProjectContextLoader]" = None,
        file_fingerprint_cache: "Optional[FileFingerprintCache]" = None,
        cost_tracker: "Optional[CostTracker]" = None,
        verify_fix_loop: "Optional[VerifyFixLoop]" = None,
        verify_fix_factory=None,
        task_manager: "Optional[TaskManager]" = None,
        task_id: str | None = None,
        skill_generator=None,
        workspace_manager=None,
        execution_service=None,
        approval_broker=None,
        principal_id: str | None = None,
        # H5: runtime_id + session_id extend the per-session BrowserContext
        # key so two concurrent local sessions under the same UID get
        # independent BrowserContexts.  Propagated into ``tool_context`` so
        # the broker can inject them into browser tools.
        runtime_id: str = "",
        session_id: str = "",
    ):
        self.config = config
        self.mode_manager = mode_manager
        self.router = router
        self.db = db
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
        self.skill_generator = skill_generator
        self.workspace_manager = workspace_manager
        self.active_workspace = None
        self.execution_service = execution_service
        if approval_broker is None:
            from khaos.agent.approval import ApprovalBroker

            approval_broker = ApprovalBroker(db=db)
        self.approval_broker = approval_broker
        self.principal_id = principal_id or f"local-uid:{os.getuid()}"
        # H5: per-runtime + per-session identifiers propagated to the
        # browser tools via the broker so concurrent sessions under the
        # same UID get independent BrowserContexts.
        self.runtime_id = runtime_id
        self.session_id = session_id
        self._active_context_facts: list[Message] = []
        if self.execution_service is None:
            from khaos.coding.execution import ExecutionService, UnsupportedBackend

            # Agent construction must fail closed.  Office-only callers may
            # still construct a loop without an execution service, but any
            # accidental coding/tool execution is denied instead of escaping
            # to an unrestricted host subprocess.
            self.execution_service = ExecutionService(UnsupportedBackend())

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
        is_coding = self.mode_manager.current_mode.value == "coding"
        if is_coding and self._verify_fix_factory is not None:
            self.verify_fix_loop = self._verify_fix_factory()
        elif not is_coding:
            self.verify_fix_loop = None
        if self.task_manager is not None and is_coding:
            if active_task_id is None:
                task = await self.task_manager.create(user_input)
                active_task_id = task.id
                await self.task_manager.update_status(active_task_id, "running")
                if self.workspace_manager is not None and self.project_root is not None:
                    root = Path(self.project_root).expanduser().resolve()
                    if (root / ".git").exists():
                        self.active_workspace = await self.workspace_manager.create(root, active_task_id)
                        await self.task_manager.update_status(
                            active_task_id,
                            "running",
                            workspace_id=self.active_workspace.id,
                            worktree_path=str(self.active_workspace.worktree_path),
                            base_sha=self.active_workspace.base_sha,
                        )
            else:
                task = await self.task_manager.get(active_task_id)
                if task is not None and task.status.value == "blocked":
                    raise PermissionError(
                        "blocked task must consume its approval capability before resume"
                    )
        from khaos.agent.events import TurnCoordinator

        turn = await TurnCoordinator.start(
            self.db,
            session_id=session_id,
            task_id=active_task_id,
            principal_id=self.principal_id,
        )
        self._active_context_facts = await self._build_durable_task_facts(
            active_task_id
        )
        total_tokens = 0
        try:
            messages = await self._build_context(session_id, user_input)
            user_msg = Message(
                role="user",
                content=user_input,
                token_count=self.token_engine.count_tokens(user_input),
                created_at=time.time(),
            )
            await self._persist_message(session_id, user_msg)
            messages.append(user_msg)
            total_tokens += user_msg.token_count

            turn_count = 0

            while turn_count < self.config.max_turns:
                empty_response_retries = 0
                if await self._check_compression(messages):
                    if self.compressor is not None:
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
                            })
                            chunk.token_count = self.token_engine.count_tokens(chunk.content)
                            chunk.created_at = time.time()
                            assistant_content += chunk.content
                            total_tokens += chunk.token_count
                            if self.cost_tracker is not None:
                                self.cost_tracker.add_output_tokens(chunk.token_count)
                            yield chunk
                        if chunk.tool_calls:
                            tool_calls.extend(chunk.tool_calls)
                            for tool_call in chunk.tool_calls:
                                turn_event = await turn.emit(
                                    "tool.call",
                                    {
                                        "tool_call_id": str(tool_call.get("id") or ""),
                                        "name": str(tool_call.get("name") or ""),
                                    },
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

                    if assistant_content.strip() or tool_calls or stop_reason == StopReason.TOOL_USE.value:
                        break
                    if empty_response_retries >= 1:
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
                )
                messages.append(assistant_msg)
                await self._persist_message(session_id, assistant_msg)
                turn_count += 1
                # Phase 6.3: 结束本轮 token / 费用统计（无论是否继续工具循环）。
                if self.cost_tracker is not None:
                    self.cost_tracker.finish_turn()

                if stop_reason != StopReason.TOOL_USE.value:
                    break

                if self.tool_scheduler is None:
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
                        },
                    )
                    return

                stream_args = {
                    "session_id": session_id,
                    "confirm_callback": self.confirm_callback,
                    "tool_context": {
                        "execution_service": self.execution_service,
                        "task_id": active_task_id,
                        "workspace_id": getattr(self.active_workspace, "id", None),
                        "workspace_manager": self.workspace_manager,
                        "coding_workspace_enforced": self.active_workspace is not None,
                        "approval_broker": self.approval_broker,
                        "requester": session_id,
                        "principal_id": self.principal_id,
                        "turn_id": f"{session_id}:{turn_count}",
                        # H5: pass session_id + runtime_id so browser tools
                        # key their BrowserContext by (principal, session,
                        # runtime) — concurrent local sessions under the
                        # same UID get independent contexts.
                        "session_id": session_id,
                        "runtime_id": self.runtime_id,
                    },
                }
                if "tool_context" not in inspect.signature(self.tool_scheduler.stream_batch).parameters:
                    stream_args.pop("tool_context")
                event_stream = self.tool_scheduler.stream_batch(tool_calls, self.mode_manager.current_mode.value, **stream_args)
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
                                "duration_ms": result.duration_ms,
                                "arguments": result.arguments or {},
                            },
                            created_at=time.time(),
                        )
                        messages.append(tool_msg)
                        await self._persist_message(session_id, tool_msg)
                        turn_event = await turn.emit(
                            "tool.result",
                            {
                                "tool_call_id": result.tool_call_id,
                                "name": result.name,
                                "success": result.success,
                            },
                        )
                        tool_msg.metadata.update({
                            "turn_id": turn.turn_id,
                            "attempt_id": turn.attempt_id,
                            "event_sequence": turn_event.sequence,
                        })
                        if self.cost_tracker is not None:
                            self.cost_tracker.add_tool_tokens(tool_msg.token_count)
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
                            if self.verify_fix_loop.should_enter_loop(result_dict):
                                failure_context = (
                                    self.verify_fix_loop.build_failure_context(
                                        result_dict
                                    )
                                )
                                if failure_context:
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
                                    await self._persist_message(session_id, fix_msg)
                                    if self.task_manager is not None and active_task_id:
                                        await self.task_manager.update_status(
                                            active_task_id,
                                            "fixing",
                                            fix_attempts=self.verify_fix_loop.attempt_count,
                                        )
                                    yield fix_msg
                                    if self.verify_fix_loop.is_loop_exhausted():
                                        report = self.verify_fix_loop.get_final_report()
                                        yield Message(
                                            role="system",
                                            content=report,
                                            event="verify_fix_report",
                                            created_at=time.time(),
                                        )
                        yield tool_msg

            else:
                stop_reason = StopReason.MAX_TURNS.value

            if self.task_manager is not None and active_task_id:
                await self._finalize_task(active_task_id, stop_reason)

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
            terminal = await turn.terminal(
                "completed", reason=stop_reason or StopReason.END_TURN.value
            )
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
                },
                created_at=time.time(),
            )
        except asyncio.CancelledError:
            if self.task_manager is not None and active_task_id:
                await self.task_manager.update_status(active_task_id, "cancelled", error="task cancelled")
            if not turn.is_terminal:
                await turn.terminal(
                    "interrupted", reason="user-cancelled", error_code="USER_ABORT"
                )
            raise
        except Exception as exc:
            logger.error("Agent loop error: %s", exc, exc_info=True)
            if self.task_manager is not None and active_task_id:
                await self.task_manager.update_status(active_task_id, "failed", error=str(exc))
            terminal = None
            if not turn.is_terminal:
                terminal = await turn.terminal(
                    "failed", reason=type(exc).__name__, error_code="INTERNAL_ERROR"
                )
            if self.error_handler is not None:
                error_event = await self.error_handler.handle(exc, session_id)
                message = error_event.to_message()
                if terminal is not None:
                    message.metadata.update({
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": terminal.sequence,
                    })
                yield message
            else:
                yield Message(
                    role="system",
                    content=f"error: {exc}",
                    stop_reason="error",
                    event="error",
                    metadata={
                        "code": "INTERNAL_ERROR",
                        "message": str(exc),
                        "turn_id": turn.turn_id,
                        "attempt_id": turn.attempt_id,
                        "event_sequence": (
                            terminal.sequence if terminal is not None else turn.sequence
                        ),
                    },
                )
        finally:
            if not turn.is_terminal:
                try:
                    await turn.terminal(
                        "interrupted",
                        reason="consumer-disconnected",
                        error_code="STREAM_CLOSED",
                    )
                except Exception:
                    logger.error(
                        "failed to persist interrupted turn: %s", turn.turn_id,
                        exc_info=True,
                    )

    async def _persist_message(self, session_id: str, message: Message) -> None:
        """Persist and index a message as one logical core-loop operation.

        M4 batch 3.1.16A-4-3: stamp ``self.principal_id`` on the row so
        ``list_messages`` / ``get_session_messages`` / ``search_sessions``
        can scope by the calling principal.
        """
        rowid = await self.db.insert_message(
            session_id, message, principal_id=self.principal_id
        )
        await self.db.insert_message_fts(
            session_id, message.role, message.content, message.token_count, rowid=rowid
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

    async def _finalize_task(self, task_id: str, stop_reason: str | None) -> None:
        """Apply terminal task semantics and run successful-task observation."""
        from khaos.coding.task_manager import TaskStatus

        if stop_reason == StopReason.MAX_TURNS.value:
            await self.task_manager.update_status(task_id, TaskStatus.FAILED, error="max_turns exhausted without completion")
        elif self.verify_fix_loop is not None and self.verify_fix_loop.is_loop_exhausted():
            await self.task_manager.update_status(task_id, TaskStatus.FAILED, error="verify-fix loop exhausted, tests still failing")
        else:
            await self.task_manager.update_status(task_id, TaskStatus.COMPLETED)
        await self._analyze_task_skill(task_id)
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
            await self.db.list_messages(session_id, principal_id=self.principal_id)
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
        facts = {
            "task_id": raw.get("id"),
            "goal": raw.get("goal"),
            "status": raw.get("status"),
            "workspace_id": metadata.get("workspace_id"),
            "base_sha": metadata.get("base_sha"),
            "pending_approval": metadata.get("pending_approval"),
            "plan_id": metadata.get("plan_id"),
            "changeset_id": metadata.get("changeset_id"),
            "verification_run_id": metadata.get("verification_run_id"),
        }
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
        except Exception as exc:  # noqa: BLE001 — observability must not break the loop
            logger.warning("task tracking failed: %s", exc)

    async def _check_compression(self, messages: list[Message]) -> bool:
        total_tokens = sum(
            message.token_count or self.token_engine.count_tokens(message.content)
            for message in messages
        )
        return total_tokens > self.config.compression_threshold
