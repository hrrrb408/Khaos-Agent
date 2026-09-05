"""P0-A agent loop with mock streaming model support."""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import logging
import os
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from khaos.agent.control.state import AgentCognitiveState

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
    from khaos.agent.control.completion_recovery import CompletionRecoveryService
    from khaos.agent.control.recovery import NormalizedFailureSignature
    from khaos.agent.control.recovery_control import RecoveryControlCoordinator
    from khaos.coding.cost_tracker import CostTracker
    from khaos.coding.fingerprint import FileFingerprintCache
    from khaos.coding.intelligence.query_service import ContextIntelligenceService
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


def _observable_text_digest(value: object) -> dict[str, object] | None:
    """Return bounded metadata for text that must not enter task telemetry."""
    if not isinstance(value, str):
        return None
    encoded = value.encode("utf-8")
    return {"bytes": len(encoded), "sha256": hashlib.sha256(encoded).hexdigest()}


def _sanitize_tool_activity_arguments(
    tool_name: str,
    arguments: object,
) -> object:
    """Remove edit source/replacement text from persisted observability data.

    The model-facing approval/tool contract retains its original arguments,
    but task traces, runtime memory events, and tool-result metadata only need
    path and digest evidence.  Keeping hashes and bounded offsets preserves
    replay/audit usefulness without duplicating source material or secrets in
    long-lived telemetry.
    """
    if tool_name not in {"apply_edit_transaction", "preview_edit_transaction"}:
        return arguments
    if not isinstance(arguments, dict):
        return {}
    sanitized: dict[str, object] = {}
    for field_name in (
        "transaction_id",
        "base_generation",
        "expected_workspace_digest",
    ):
        value = arguments.get(field_name)
        if value is not None:
            sanitized[field_name] = value
    intent_digest = _observable_text_digest(arguments.get("intent"))
    if intent_digest is not None:
        sanitized["intent"] = intent_digest

    operations = arguments.get("operations")
    if not isinstance(operations, list):
        sanitized["operation_count"] = 0
        return sanitized
    sanitized_operations: list[dict[str, object]] = []
    for operation in operations[:64]:
        if not isinstance(operation, dict):
            continue
        projection: dict[str, object] = {}
        for field_name in (
            "operation",
            "path",
            "destination_path",
            "expected_exists",
            "expected_digest",
        ):
            value = operation.get(field_name)
            if value is not None:
                projection[field_name] = value
        content_digest = _observable_text_digest(operation.get("content"))
        if content_digest is not None:
            projection["content"] = content_digest
        edits = operation.get("text_edits")
        if isinstance(edits, list):
            projection["text_edits"] = [
                {
                    "start": edit.get("start"),
                    "end": edit.get("end"),
                    "replacement": _observable_text_digest(edit.get("replacement")),
                }
                for edit in edits[:256]
                if isinstance(edit, dict)
            ]
        sanitized_operations.append(projection)
    sanitized["operations"] = sanitized_operations
    sanitized["operation_count"] = len(operations)
    if len(operations) > 64:
        sanitized["operations_truncated"] = True
    return sanitized


def _sanitize_tool_activity_output(
    tool_name: str,
    output: object,
    error: object = "",
    *,
    max_chars: int = 2048,
) -> str:
    """Return a bounded task-telemetry summary without preview source text."""
    if tool_name not in {"apply_edit_transaction", "preview_edit_transaction"}:
        return str(output or error)[:max_chars]
    if isinstance(output, dict):
        safe: dict[str, object] = {}
        for field_name in (
            "status",
            "transaction_id",
            "workspace_id",
            "base_generation",
            "resulting_generation",
            "transaction_digest",
            "before_workspace_digest",
            "after_workspace_digest",
            "predicted_workspace_digest",
        ):
            value = output.get(field_name)
            if value is not None:
                safe[field_name] = value
        operations = output.get("operations")
        if isinstance(operations, list):
            safe_operations: list[dict[str, object]] = []
            for operation in operations[:64]:
                if not isinstance(operation, dict):
                    continue
                safe_operation: dict[str, object] = {}
                for field_name in (
                    "index",
                    "operation",
                    "path",
                    "destination_path",
                    "before_exists",
                    "after_exists",
                    "before_digest",
                    "after_digest",
                ):
                    value = operation.get(field_name)
                    if value is not None:
                        safe_operation[field_name] = value
                safe_operations.append(safe_operation)
            safe["operations"] = safe_operations
            safe["operation_count"] = len(operations)
            if len(operations) > 64:
                safe["operations_truncated"] = True
        summary = safe
    else:
        summary = {
            "output_type": type(output).__name__,
            "output_digest": _observable_text_digest(output),
        }
    if error:
        summary["error"] = str(error)[:512]
    return json.dumps(summary, ensure_ascii=False, sort_keys=True)[:max_chars]


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
    # M7.2 bounded workspace context limits.  These are disclosure/compute
    # bounds, never filesystem or execution authority.
    context_token_budget: int = 12_000
    context_max_files: int = 16
    context_max_symbols: int = 128
    context_max_bytes: int = 256 * 1024
    context_max_file_bytes: int = 64 * 1024
    # M8.4: one bounded context engine owns final selection/eviction.  These
    # values are disclosure budgets only; they do not alter workspace or tool
    # authority.
    context_output_reserve_tokens: int = 2_048
    context_output_reserve_bytes: int = 32 * 1024
    context_layer_token_budgets: tuple[int, int, int, int] = (
        2_048,
        3_072,
        5_120,
        1_760,
    )
    context_layer_byte_budgets: tuple[int, int, int, int] = (
        48 * 1024,
        64 * 1024,
        112 * 1024,
        32 * 1024,
    )
    context_recent_message_count: int = 12
    tool_output_max_bytes: int = 64 * 1024
    tool_output_max_tokens: int = 4_096
    tool_output_max_lines: int = 512


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
        context_intelligence: ContextIntelligenceService | None = None,
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
        subagent_control_coordinator=None,
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
        completion_recovery: CompletionRecoveryService | None = None,
        planning_coordinator: Any = None,
        trusted_verification_authority: Any = None,
        trusted_verification_service: Any = None,
        recovery_control: RecoveryControlCoordinator | None = None,
        delegated_execution_context: Any = None,
        repo_intelligence=None,
        edit_transaction_service=None,
        verification_coordinator=None,
        context_engine=None,
        parallel_subagent_coordinator=None,
        supervision_service=None,
        checkpoint_service=None,
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
        # M7.2: production coding context is built through the
        # owner-scoped, SafeWorkspaceFS-backed service.  The legacy builder
        # remains available for explicitly injected development/test loops.
        self.context_intelligence = context_intelligence
        self.repo_intelligence = repo_intelligence or getattr(
            context_intelligence, "repo_intelligence", None
        )
        self.edit_transaction_service = edit_transaction_service
        # M8.3: post-edit verification is an observation coordinator only.
        # Execution remains owned by ExecutionService and completion remains
        # owned by the existing trusted provider plus CompletionGate.
        self.verification_coordinator = verification_coordinator
        # M8.5: parent-only thin orchestration seam.  Child workspaces,
        # budgets, merge CAS, verification, and completion remain owned by
        # their existing services; the loop only exposes the composed port.
        self.parallel_subagent_coordinator = parallel_subagent_coordinator
        # M8.6: the loop emits semantic lifecycle facts through this thin
        # service.  It never calls a UI adapter and never treats the
        # supervision projection as permission, mutation, or completion
        # authority.
        self.supervision_service = supervision_service
        self.checkpoint_service = checkpoint_service
        # M8.4: final context selection/serialization owner.  This service is
        # optional for direct legacy/test constructions; the runtime factory
        # wires it for the normal path so the old builder is not a second
        # production context manager.
        self.context_engine = context_engine
        # M8.4 keeps the typed M8.1 result separate from its legacy rendered
        # projection.  The bundle is turn-local and never becomes authority;
        # ContextEngineService consumes its bounded candidate records.
        self._active_context_bundle = None
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
        self.completion_recovery = completion_recovery
        # M7.3: planning is an explicit control-plane coordinator.  The loop
        # only invokes the composed owner; it does not infer plans from tool
        # names or implement planner/risk/DAG logic itself.
        self.planning_coordinator = planning_coordinator
        # M7.4: trusted verification is a passive evidence/assessment
        # composition. These references do not grant execution authority and
        # are not lifecycle writers.
        self.trusted_verification_authority = trusted_verification_authority
        self.trusted_verification_service = trusted_verification_service
        # M7.5: recovery is an explicit control-plane seam.  It only consumes
        # durable facts and can project cognitive recovery state; it never
        # grants tools/approval/workspace authority or changes TaskStatus.
        self.recovery_control = recovery_control
        # M7.8: a delegated loop is a worker attached to a parent control
        # plane.  This structural marker is never inferred from prompt text.
        self.delegated_execution_context = delegated_execution_context
        self._active_planning_result: Any = None
        self.skill_generator = skill_generator
        self.workspace_manager = workspace_manager
        self.active_workspace = None
        self._active_session_id = ""
        self._active_task_id: str | None = None
        self._supervision_runtime_registered = False
        self._recovery_cycles_this_turn = 0
        self._context_needs_rebuild = False
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
        self.subagent_control_coordinator = subagent_control_coordinator
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

    def _require_parallel_parent(self) -> tuple[Any, Any]:
        """Return the parent workspace and M8.5 coordinator, fail-closed."""
        if self.delegated_execution_context is not None:
            raise PermissionError("delegated children cannot create parallel children")
        coordinator = self.parallel_subagent_coordinator
        if coordinator is None:
            raise RuntimeError("parallel subagent coordinator is not configured")
        workspace = self.active_workspace
        if workspace is None:
            raise PermissionError("parallel subagents require an active parent workspace")
        active_task_id = self._active_task_id or self.task_id
        if active_task_id is not None and workspace.task_id != active_task_id:
            raise PermissionError("active workspace is not bound to the parent task")
        return coordinator, workspace

    async def run_parallel_subagents(
        self,
        assignments: tuple[Any, ...],
        worker: Any,
    ) -> tuple[Any, ...]:
        """Run bounded child assignments from the active parent workspace."""
        coordinator, workspace = self._require_parallel_parent()
        return await coordinator.run_parallel(workspace, assignments, worker)

    async def merge_parallel_subagents(
        self,
        assignments: tuple[Any, ...],
    ) -> tuple[Any, Any]:
        """Trigger deterministic child merge through the composed coordinator."""
        coordinator, workspace = self._require_parallel_parent()
        return await coordinator.merge(workspace, assignments)

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

    def _autonomous_verification_message(
        self,
        *,
        run: Any,
        impact: Any,
        task_id: str,
        turn_id: str,
        attempt_id: str,
        repair_attempt: int | None = None,
    ) -> Message:
        """Build a bounded model observation for one M8.3 run."""
        from khaos.coding.verification.contracts import VerificationRunStatus
        from khaos.coding.verification.service import AutonomousVerificationCoordinator

        status = getattr(getattr(run, "status", None), "value", "unknown")
        if status == VerificationRunStatus.PASSED.value:
            content = (
                "# Autonomous verification result (UNTRUSTED OBSERVATION)\n"
                "Verification checks passed. This is advisory evidence only; "
                "completion still requires the trusted verification authority."
            )
        else:
            if impact is None:
                raise TypeError("autonomous verification impact is invalid")
            context = AutonomousVerificationCoordinator.repair_context(run, impact)
            content = context.render()
            if repair_attempt is not None:
                content += (
                    f"\n\nRepair attempt admitted by the existing verify-fix "
                    f"controller: {repair_attempt}. Use a new EditTransaction "
                    "to produce a new workspace generation and verification plan."
                )
            else:
                content += (
                    "\n\nNo automatic repair attempt was admitted. The failure "
                    "remains a negative observation and may require user action."
                )
        plan = getattr(run, "plan", None)
        checks = tuple(getattr(plan, "checks", ()) or ())
        stage_counts: dict[str, int] = {}
        kind_counts: dict[str, int] = {}
        for check in checks:
            stage = getattr(getattr(check, "stage", None), "name", "")
            if stage:
                stage_counts[stage.casefold()] = stage_counts.get(stage.casefold(), 0) + 1
            kind = getattr(getattr(check, "kind", None), "value", "")
            if kind:
                kind_counts[kind] = kind_counts.get(kind, 0) + 1
        checks_by_id = {
            getattr(check, "check_id", ""): check
            for check in checks
            if getattr(check, "check_id", "")
        }
        executed_kind_counts: dict[str, int] = {}
        for evidence in tuple(getattr(run, "evidence", ()) or ()):
            check = checks_by_id.get(getattr(evidence, "check_id", ""))
            kind = getattr(getattr(check, "kind", None), "value", "")
            if kind:
                executed_kind_counts[kind] = executed_kind_counts.get(kind, 0) + 1
        metadata = {
            "task_id": task_id,
            "turn_id": turn_id,
            "attempt_id": attempt_id,
            "run_id": getattr(run, "run_id", ""),
            "plan_id": getattr(plan, "plan_id", ""),
            "plan_digest": getattr(plan, "plan_digest", ""),
            "status": status,
            "workspace_generation": getattr(plan, "workspace_generation", None),
            "repository_generation": getattr(plan, "repository_generation", None),
            "required_check_count": int(getattr(run, "required_count", 0)),
            "passed_check_count": int(getattr(run, "passed_count", 0)),
            "check_count": len(checks),
            "executed_check_count": len(tuple(getattr(run, "evidence", ()) or ())),
            "stage_counts": stage_counts,
            "kind_counts": executed_kind_counts,
            "planned_kind_counts": kind_counts,
            "diagnostic_count": len(tuple(getattr(run, "diagnostics", ()) or ())),
            "repair_attempt": repair_attempt,
        }
        return Message(
            role="system",
            content=content,
            token_count=self.token_engine.count_tokens(content),
            event="verification_result",
            metadata=metadata,
            created_at=time.time(),
        )

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
        if self.delegated_execution_context is not None:
            if self.workspace_manager is None:
                raise PermissionError("delegated execution requires the parent workspace authority")
            self.active_workspace = self.workspace_manager.get(
                self.delegated_execution_context.workspace_id
            )
            if self.active_workspace is None:
                raise PermissionError("delegated execution cannot attach the parent workspace")
        self._recovery_cycles_this_turn = 0
        self._context_needs_rebuild = False
        is_coding = self.mode_manager.current_mode.value == "coding"
        if is_coding and self._verify_fix_factory is not None:
            self.verify_fix_loop = self._verify_fix_factory()
        elif not is_coding:
            self.verify_fix_loop = None
        if self.task_manager is not None and is_coding and self.delegated_execution_context is None:
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
                            repository_id=(
                                self.context_intelligence.repository_id_for_workspace(
                                    self.active_workspace
                                )
                                if self.context_intelligence is not None
                                else None
                            ),
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
        if (
            is_coding
            and active_task_id is not None
            and self.planning_coordinator is not None
            and self.active_workspace is not None
            and self.delegated_execution_context is None
            and (
                self._active_planning_result is None
                or getattr(self._active_planning_result, "task_id", None)
                != active_task_id
            )
        ):
            self._active_planning_result = await self.planning_coordinator.plan(
                active_task_id,
                workspace=self.active_workspace,
                query=user_input,
                runtime_id=self.runtime_id,
                event_sink=turn,
            )
            if self.supervision_service is not None:
                await self.supervision_service.emit(
                    task_id=active_task_id,
                    workspace_id=self.active_workspace.id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                    event_type="plan.created",
                    payload={
                        "plan": {
                            "revision_id": str(
                                getattr(self._active_planning_result, "revision_id", "")
                                or getattr(self._active_planning_result, "plan_id", "planning")
                            ),
                            "digest": str(
                                getattr(self._active_planning_result, "revision_digest", "")
                                or getattr(self._active_planning_result, "plan_digest", "unknown")
                            ),
                            "current_step": 0,
                            "total_steps": int(
                                getattr(self._active_planning_result, "step_count", 0) or 0
                            ),
                            "summary": "durable Coding plan created",
                        },
                        "status": "PLANNING",
                    },
                )
            await self._observe_context_event(
                "PlanRevision",
                {
                    "plan_revision": (
                        getattr(self._active_planning_result, "revision_digest", None)
                        or getattr(self._active_planning_result, "plan_digest", None)
                        or ""
                    ),
                    "summary": "planning revision created",
                },
                task_id=active_task_id,
            )
            # The coordinator owns the physical cognitive CAS.  Refresh only
            # the in-memory projection so the task facts below do not expose a
            # stale pre-CAS state; this is not restart ``load()`` semantics.
            refresh = getattr(self.task_manager, "refresh_projection", None)
            if refresh is not None:
                await refresh(active_task_id)
        self._active_context_facts = await self._build_durable_task_facts(
            active_task_id
        )
        orchestration_phase = TurnAdmission.admit(
            session_id=session_id,
            turn_id=turn.turn_id,
            attempt_id=turn.attempt_id,
            task_id=active_task_id or "",
        )
        # M8.6: register the live runtime only after the TaskWorkspace is
        # bound and before model/tool effects can start.  A durable PAUSED or
        # CANCELLING state is recovered by the control owner at this point.
        self._supervision_runtime_registered = False
        if (
            is_coding
            and active_task_id
            and self.active_workspace is not None
            and self.supervision_service is not None
            and self.delegated_execution_context is None
        ):
            supervision_state = await self.supervision_service.state(
                active_task_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
            if supervision_state is None:
                task_goal = str(getattr(locals().get("task", None), "goal", user_input))
                await self.supervision_service.start_task(
                    task_id=active_task_id,
                    workspace_id=self.active_workspace.id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                    goal=task_goal,
                )
            await self.supervision_service.register_runtime(
                task_id=active_task_id,
                workspace_id=self.active_workspace.id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                runtime_id=self.runtime_id,
                runtime_task=asyncio.current_task(),
                checkpoint_service=self.checkpoint_service,
            )
            self._supervision_runtime_registered = True
            await self.supervision_service.emit(
                task_id=active_task_id,
                workspace_id=self.active_workspace.id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                event_type="context.prepared",
                payload={"status": "INVESTIGATING"},
            )
        total_tokens = 0
        budget_exhausted = False
        stop_reason: str | None = None
        recovery_result: Any = None
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
                if (
                    active_task_id
                    and self.supervision_service is not None
                    and self._supervision_runtime_registered
                ):
                    resumed = await self.supervision_service.wait_if_paused(
                        active_task_id,
                        principal_id=self.principal_id,
                        project_id=self.project_id,
                    )
                    if resumed:
                        self._context_needs_rebuild = True
                empty_response_retries = 0
                if self.context_engine is not None:
                    if self._context_needs_rebuild:
                        messages = await self._build_context(session_id, user_input)
                        self._context_needs_rebuild = False
                    else:
                        messages = cast(
                            list[Message],
                            await self.context_engine.rebalance_messages(
                                messages,
                                requirements=self._context_requirements(user_input),
                            ),
                        )
                elif await self._check_compression(messages) and self.compressor is not None:
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
                    tools_schema = self._build_tools_schema(user_input)
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
                    # A pause may arrive while the model stream is in
                    # flight.  Do not admit the returned tool calls into the
                    # scheduler until the durable control owner has reached
                    # a safe point and the user resumes the task.
                    if (
                        active_task_id
                        and self.supervision_service is not None
                        and self._supervision_runtime_registered
                    ):
                        resumed = await self.supervision_service.wait_if_paused(
                            active_task_id,
                            principal_id=self.principal_id,
                            project_id=self.project_id,
                        )
                        if resumed:
                            self._context_needs_rebuild = True
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
                        "repo_intelligence": self.repo_intelligence,
                        "edit_transaction_service": self.edit_transaction_service,
                        "coding_workspace_enforced": self.active_workspace is not None,
                        "production_runtime": self.runtime_profile.is_production,
                        "approval_broker": self.approval_broker,
                        "credential_broker": self.credential_broker,
                        "requester": session_id,
                        "principal_id": self.principal_id,
                        "execution_principal_id": self.principal_id,
                        "task_owner_principal_id": (
                            self.delegated_execution_context.task_owner_principal_id
                            if self.delegated_execution_context is not None
                            else self.principal_id
                        ),
                        "subagent_assignment_id": (
                            self.delegated_execution_context.assignment_id
                            if self.delegated_execution_context is not None
                            else None
                        ),
                        "subagent_assignment_digest": (
                            self.delegated_execution_context.assignment_digest
                            if self.delegated_execution_context is not None
                            else None
                        ),
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
                        "subagent_control_coordinator": getattr(
                            self, "subagent_control_coordinator", None
                        ),
                        "parallel_subagent_coordinator": getattr(
                            self, "parallel_subagent_coordinator", None
                        ),
                    },
                }
                if (
                    active_task_id
                    and self.supervision_service is not None
                    and self._supervision_runtime_registered
                ):
                    await self.supervision_service.wait_if_paused(
                        active_task_id,
                        principal_id=self.principal_id,
                        project_id=self.project_id,
                    )
                    if any(
                        str(call.get("name", "")) == "apply_edit_transaction"
                        for call in tool_calls
                    ):
                        if self.checkpoint_service is None or self.active_workspace is None:
                            raise PermissionError(
                                "mutating Coding work requires a checkpoint owner"
                            )
                        try:
                            await self.checkpoint_service.create_checkpoint(
                                task_id=active_task_id,
                                workspace_id=self.active_workspace.id,
                                kind="PRE_EDIT",
                                label="before coding edit",
                                expected_generation=self.active_workspace.generation,
                                principal_id=self.principal_id,
                                project_id=self.project_id,
                            )
                        except Exception as exc:
                            logger.warning(
                                "pre-edit checkpoint refused: %s",
                                type(exc).__name__,
                            )
                            await self.supervision_service.emit(
                                task_id=active_task_id,
                                workspace_id=self.active_workspace.id,
                                principal_id=self.principal_id,
                                project_id=self.project_id,
                                event_type="task.failed",
                                payload={
                                    "reason": "pre-edit checkpoint unavailable",
                                    "error_type": type(exc).__name__,
                                },
                                severity="error",
                            )
                            raise PermissionError(
                                "pre-edit checkpoint is required before mutation"
                            ) from exc
                    await self.supervision_service.emit(
                        task_id=active_task_id,
                        workspace_id=getattr(self.active_workspace, "id", ""),
                        principal_id=self.principal_id,
                        project_id=self.project_id,
                        event_type="step.started",
                        payload={
                            "current_step": "tool execution",
                            "activity": {
                                "operation": "coding",
                                "kind": "tool_batch",
                                "stage": "executing",
                                "description": "Executing approved Coding tools",
                                "scope": [
                                    str(call.get("name", ""))[:128]
                                    for call in tool_calls[:64]
                                ],
                                "status": "active",
                            },
                        },
                    )
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
                        if (
                            active_task_id
                            and self.supervision_service is not None
                            and self._supervision_runtime_registered
                        ):
                            await self.supervision_service.emit(
                                task_id=active_task_id,
                                workspace_id=request.workspace_id or getattr(self.active_workspace, "id", ""),
                                principal_id=self.principal_id,
                                project_id=self.project_id,
                                event_type="approval.requested",
                                payload={
                                    "approval_id": request.tool_call_id,
                                    "operation": request.name,
                                    "binding_digest": request.binding_digest,
                                    "expires_at": request.expires_at,
                                    "approval_state": "pending",
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
                                    "workspace_id": request.workspace_id
                                    or getattr(self.active_workspace, "id", ""),
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
                        bounded_envelope = None
                        if self.context_engine is not None:
                            bounded_envelope = self.context_engine.bound_tool_result(result)
                            wrapper_prefix = '<untrusted_tool_output source="tool">\n'
                            wrapper_suffix = "</untrusted_tool_output>"
                            output_budget = max(
                                1,
                                int(
                                    getattr(
                                        self.config,
                                        "tool_output_max_bytes",
                                        64 * 1024,
                                    )
                                )
                                - len(
                                    (wrapper_prefix + wrapper_suffix).encode("utf-8")
                                ),
                            )
                            bounded_content = bounded_envelope.to_json(
                                max_bytes=output_budget
                            )
                            content = (
                                f"{wrapper_prefix}{bounded_content}\n{wrapper_suffix}"
                            )
                        else:
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
                                "output": (
                                    result.output
                                    if bounded_envelope is None
                                    else ""
                                ),
                                "output_digest": (
                                    bounded_envelope.full_result_digest
                                    if bounded_envelope is not None
                                    else None
                                ),
                                "output_truncated": (
                                    bounded_envelope.truncated
                                    if bounded_envelope is not None
                                    else False
                                ),
                                "error": result.error,
                                "error_code": result.error_code,
                                "duration_ms": result.duration_ms,
                                "arguments": _sanitize_tool_activity_arguments(
                                    result.name, result.arguments or {}
                                ),
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
                        if (
                            result.success
                            and result.name == "apply_edit_transaction"
                        ):
                            self._context_needs_rebuild = True
                            await self._observe_context_event(
                                "EditTransactionApplied",
                                {
                                    "summary": "edit transaction applied",
                                    "operation_digest": result.phase_digest or result.effect_id or "",
                                    "changed_files": [
                                        str(operation.get("path"))
                                        for operation in (result.arguments or {}).get("operations", [])
                                        if isinstance(operation, dict) and operation.get("path")
                                    ],
                                },
                                task_id=active_task_id,
                            )
                        await self._observe_context_event(
                            "ToolResult",
                            {
                                "tool_name": result.name,
                                "success": result.success,
                                "summary": (
                                    _sanitize_tool_activity_output(
                                        result.name,
                                        result.output,
                                        result.error,
                                        max_chars=512,
                                    )
                                ),
                                "workspace_id": getattr(
                                    self.active_workspace, "id", ""
                                ),
                            },
                            task_id=active_task_id,
                        )
                        if (
                            result.success
                            and self.context_intelligence is not None
                            and active_task_id
                            and self.active_workspace is not None
                        ):
                            self.context_intelligence.invalidate_from_tool_result(
                                workspace_id=self.active_workspace.id,
                                tool_name=result.name,
                                arguments=result.arguments or {},
                            )
                        # M8.3: every successful canonical coding edit enters
                        # the autonomous planner through the existing
                        # coordinator.  Read-only tools, failed mutations, and
                        # legacy text-edit tools do not enter this path.
                        if (
                            is_coding
                            and result.success
                            and result.name == "apply_edit_transaction"
                            and self.verification_coordinator is not None
                            and active_task_id is not None
                            and self.active_workspace is not None
                        ):
                            try:
                                from khaos.coding.verification.impact import (
                                    EditImpact,
                                    edit_transaction_result_from_tool_output,
                                )

                                # A successful tool envelope is still an
                                # observation boundary.  Clear the previous
                                # run before decoding it so malformed output
                                # cannot leave stale positive evidence visible
                                # to completion or repair logic.
                                self.verification_coordinator.invalidate(active_task_id)
                                edit_result = edit_transaction_result_from_tool_output(
                                    result.output
                                )
                                if self.checkpoint_service is not None:
                                    await self.checkpoint_service.record_transaction(
                                        active_task_id,
                                        edit_result,
                                        principal_id=self.principal_id,
                                        project_id=self.project_id,
                                    )
                                if self.supervision_service is not None:
                                    await self.supervision_service.emit(
                                        task_id=active_task_id,
                                        workspace_id=self.active_workspace.id,
                                        principal_id=self.principal_id,
                                        project_id=self.project_id,
                                        event_type="verification.started",
                                        repository_generation=edit_result.resulting_generation,
                                        payload={
                                            "transaction_id": edit_result.transaction_id,
                                            "transaction_digest": edit_result.transaction_digest,
                                            "changed_paths": [
                                                operation.path
                                                for operation in edit_result.operations
                                            ],
                                            "verification_state": "running",
                                        },
                                    )
                                await self._observe_context_event(
                                    "VerificationPlanCreated",
                                    {
                                        "summary": "post-edit verification plan created",
                                        "changed_files": list(
                                            getattr(edit_result, "changed_files", ()) or ()
                                        )[:32],
                                    },
                                    task_id=active_task_id,
                                )
                                autonomous_run = (
                                    await self.verification_coordinator.verify_after_edit(
                                        edit_result,
                                        task_id=active_task_id,
                                        workspace=self.active_workspace,
                                        event_sink=turn,
                                        principal_id=self.principal_id,
                                        project_id=self.project_id,
                                    )
                                )
                                impact = self.verification_coordinator.impact_for_task(
                                    active_task_id
                                ) or EditImpact.from_result(edit_result)
                                repair_attempt = None
                                autonomous_observation = None
                                suppress_autonomous_repair = False
                                if self.verify_fix_loop is not None:
                                    autonomous_observation = (
                                        self.verify_fix_loop.observe_autonomous_run(
                                            autonomous_run
                                        )
                                    )
                                    autonomous_status = autonomous_run.status.value
                                    no_progress = self.verify_fix_loop.no_progress_signal()
                                    if (
                                        no_progress.detected
                                        and autonomous_status in {"failed", "timed_out"}
                                        and autonomous_observation is not None
                                        and active_task_id is not None
                                    ):
                                        normalized_failure = (
                                            self._normalize_verify_fix_failure(
                                                autonomous_observation
                                            )
                                        )
                                        await turn.emit(
                                            "recovery.no_progress",
                                            {
                                                "task_id": active_task_id,
                                                "observation_indices": list(
                                                    no_progress.observation_indices
                                                ),
                                                "failure_signature_digest": (
                                                    normalized_failure.failure_signature_digest
                                                ),
                                                "reason": "identical_failure_signature",
                                            },
                                        )
                                        recovery_for_observation = (
                                            await self._recover_after_no_progress(
                                                turn=turn,
                                                task_id=active_task_id,
                                                failure_signature=normalized_failure,
                                                query=user_input,
                                            )
                                        )
                                        recovery_status = getattr(
                                            getattr(
                                                recovery_for_observation,
                                                "status",
                                                None,
                                            ),
                                            "value",
                                            None,
                                        )
                                        recovery_action = getattr(
                                            getattr(
                                                recovery_for_observation,
                                                "action",
                                                None,
                                            ),
                                            "value",
                                            None,
                                        )
                                        suppress_autonomous_repair = (
                                            recovery_status in {"applied", "blocked"}
                                            and recovery_action in {"replan", "block"}
                                        )
                                    if (
                                        autonomous_status in {"failed", "timed_out"}
                                        and autonomous_observation is not None
                                        and not suppress_autonomous_repair
                                    ):
                                        repair_attempt = self.verify_fix_loop.admit_repair(
                                            autonomous_observation
                                        )
                                verification_msg = self._autonomous_verification_message(
                                    run=autonomous_run,
                                    impact=impact,
                                    task_id=active_task_id,
                                    turn_id=turn.turn_id,
                                    attempt_id=turn.attempt_id,
                                    repair_attempt=repair_attempt,
                                )
                                messages.append(verification_msg)
                                await self._observe_context_event(
                                    "VerificationResult",
                                    {
                                        "status": getattr(
                                            getattr(autonomous_run, "status", None),
                                            "value",
                                            "unknown",
                                        ),
                                        "summary": "autonomous verification observed",
                                    },
                                    task_id=active_task_id,
                                )
                                verification_status = getattr(
                                    getattr(autonomous_run, "status", None),
                                    "value",
                                    "unknown",
                                )
                                if (
                                    repair_attempt is not None
                                    and self.supervision_service is not None
                                    and active_task_id is not None
                                ):
                                    await self.supervision_service.emit(
                                        task_id=active_task_id,
                                        workspace_id=self.active_workspace.id,
                                        principal_id=self.principal_id,
                                        project_id=self.project_id,
                                        event_type="repair.started",
                                        repository_generation=edit_result.resulting_generation,
                                        payload={
                                            "attempt": repair_attempt,
                                            "verification_state": verification_status,
                                            "status": "REPAIRING",
                                        },
                                    )
                                if self.supervision_service is not None:
                                    await self.supervision_service.emit(
                                        task_id=active_task_id,
                                        workspace_id=self.active_workspace.id,
                                        principal_id=self.principal_id,
                                        project_id=self.project_id,
                                        event_type=(
                                            "verification.passed"
                                            if verification_status == "passed"
                                            else "verification.failed"
                                        ),
                                        repository_generation=edit_result.resulting_generation,
                                        payload={
                                            "verification_state": verification_status,
                                            "changed_paths": [
                                                operation.path
                                                for operation in edit_result.operations
                                            ],
                                        },
                                    )
                                if (
                                    verification_status == "passed"
                                    and self.checkpoint_service is not None
                                ):
                                    try:
                                        await self.checkpoint_service.create_checkpoint(
                                            task_id=active_task_id,
                                            workspace_id=self.active_workspace.id,
                                            kind="POST_VERIFICATION",
                                            label="after verified coding edit",
                                            expected_generation=edit_result.resulting_generation,
                                            verification_evidence_digest=(
                                                getattr(autonomous_run, "run_digest", None)
                                                if isinstance(
                                                    getattr(autonomous_run, "run_digest", None),
                                                    str,
                                                )
                                                and len(getattr(autonomous_run, "run_digest", "")) == 64
                                                else None
                                            ),
                                            known_state=True,
                                            principal_id=self.principal_id,
                                            project_id=self.project_id,
                                        )
                                    except Exception:
                                        logger.warning(
                                            "post-verification checkpoint unavailable",
                                            exc_info=True,
                                        )
                                if verification_status in {"failed", "timed_out"}:
                                    diagnostics = tuple(
                                        getattr(autonomous_run, "diagnostics", ()) or ()
                                    )
                                    diagnostic_text = str(
                                        getattr(diagnostics[0], "message", diagnostics[0])
                                        if diagnostics
                                        else "autonomous verification failed"
                                    )[:2048]
                                    await self._observe_context_event(
                                        "VerificationDiagnostic",
                                        {
                                            "summary": diagnostic_text,
                                            "diagnostic_count": len(diagnostics),
                                        },
                                        task_id=active_task_id,
                                    )
                                elif verification_status == "passed":
                                    await self._observe_context_event(
                                        "VerificationGreen",
                                        {"summary": "autonomous verification is green"},
                                        task_id=active_task_id,
                                    )
                                await self._persist_message(
                                    session_id,
                                    verification_msg,
                                    task_id=active_task_id,
                                    workspace_id=getattr(
                                        self.active_workspace, "id", None
                                    ),
                                    commit_sha=getattr(
                                        self.active_workspace, "base_sha", None
                                    ),
                                )
                                if self.task_manager is not None and active_task_id:
                                    if autonomous_run.status.value == "passed":
                                        await self.task_manager.update_status(
                                            active_task_id,
                                            "waiting_test",
                                        )
                                    elif repair_attempt is not None:
                                        await self.task_manager.update_status(
                                            active_task_id,
                                            "fixing",
                                            fix_attempts=self.verify_fix_loop.attempt_count,
                                        )
                                if (
                                    self.verify_fix_loop is not None
                                    and self.verify_fix_loop.is_loop_exhausted()
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
                            except Exception as exc:  # noqa: BLE001 - verification failure is observed fail-closed
                                # A malformed edit projection or unavailable
                                # verification coordinator is an explicit
                                # infrastructure observation.  It must not
                                # turn a successful edit into positive proof,
                                # and raw exception text never enters model
                                # context or telemetry.
                                logger.warning(
                                    "autonomous verification could not start: %s",
                                    type(exc).__name__,
                                )
                                await turn.emit(
                                    "verification.infrastructure_error",
                                    {
                                        "task_id": active_task_id,
                                        "workspace_id": self.active_workspace.id,
                                        "tool_name": result.name,
                                        "error_type": type(exc).__name__,
                                    },
                                )
                                unavailable_msg = Message(
                                    role="system",
                                    content=(
                                        "# Autonomous verification result "
                                        "(UNTRUSTED OBSERVATION)\n"
                                        "Verification infrastructure was unavailable; "
                                        "no verification pass or completion authority was granted."
                                    ),
                                    event="verification_unavailable",
                                    metadata={
                                        "task_id": active_task_id,
                                        "workspace_id": self.active_workspace.id,
                                        "error_type": type(exc).__name__,
                                    },
                                    created_at=time.time(),
                                )
                                messages.append(unavailable_msg)
                                await self._persist_message(
                                    session_id,
                                    unavailable_msg,
                                    task_id=active_task_id,
                                    workspace_id=getattr(
                                        self.active_workspace, "id", None
                                    ),
                                )
                        if result.name == "test_run" and self.task_manager is not None and active_task_id:
                            await self.task_manager.update_status(active_task_id, "waiting_test")
                        if result.name == "test_run":
                            if result.success:
                                await self._observe_context_event(
                                    "VerificationGreen",
                                    {"summary": "test_run passed"},
                                    task_id=active_task_id,
                                )
                            else:
                                await self._observe_context_event(
                                    "VerificationDiagnostic",
                                    {
                                        "summary": str(
                                            result.error or result.output or "test_run failed"
                                        )[:2048],
                                    },
                                    task_id=active_task_id,
                                )
                        if self.task_manager is not None and active_task_id:
                            await self.task_manager.record_trace(
                                active_task_id,
                                {
                                    "tool_name": result.name,
                                    "arguments": _sanitize_tool_activity_arguments(
                                        result.name, result.arguments or {}
                                    ),
                                    "success": result.success,
                                    "result_summary": _sanitize_tool_activity_output(
                                        result.name,
                                        result.output,
                                        result.error,
                                        max_chars=500,
                                    ),
                                    "timestamp": time.time(),
                                },
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
                            recovery_for_observation = None
                            no_progress = self.verify_fix_loop.no_progress_signal()
                            if (
                                no_progress.detected
                                and verification_observation is not None
                                and active_task_id is not None
                            ):
                                normalized_failure = (
                                    self._normalize_verify_fix_failure(
                                        verification_observation
                                    )
                                )
                                await turn.emit(
                                    "recovery.no_progress",
                                    {
                                        "task_id": active_task_id,
                                        "observation_indices": list(
                                            no_progress.observation_indices
                                        ),
                                        "failure_signature_digest": (
                                            normalized_failure.failure_signature_digest
                                        ),
                                        "reason": "identical_failure_signature",
                                    },
                                )
                                recovery_for_observation = (
                                    await self._recover_after_no_progress(
                                        turn=turn,
                                        task_id=active_task_id,
                                        failure_signature=normalized_failure,
                                        query=user_input,
                                    )
                                )
                                if recovery_for_observation is not None:
                                    recovery_result = recovery_for_observation
                            recovery_status = getattr(
                                getattr(
                                    recovery_for_observation,
                                    "status",
                                    None,
                                ),
                                "value",
                                None,
                            )
                            recovery_action = getattr(
                                getattr(
                                    recovery_for_observation,
                                    "action",
                                    None,
                                ),
                                "value",
                                None,
                            )
                            suppress_legacy_repair = (
                                recovery_status in {"applied", "blocked"}
                                and recovery_action in {"replan", "block"}
                            )
                            if (
                                not suppress_legacy_repair
                                and self.verify_fix_loop.should_enter_loop(
                                    result_dict,
                                    observation=verification_observation,
                                )
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
                and self.delegated_execution_context is None
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
                    recovery_result = await self._recover_after_completion(
                        turn=turn,
                        task_id=active_task_id,
                        decision_outcome=completion_result.decision.outcome.value,
                        query=user_input,
                    )
                    if recovery_result is not None:
                        yield self._recovery_result_message(
                            result=recovery_result,
                            turn_id=turn.turn_id,
                            attempt_id=turn.attempt_id,
                            task_id=active_task_id,
                        )

            if self.task_manager is not None and active_task_id:
                await self._finalize_task(
                    active_task_id,
                    stop_reason,
                    recovery_result=recovery_result,
                )
            if (
                self.supervision_service is not None
                and self._supervision_runtime_registered
                and active_task_id
                and self.active_workspace is not None
            ):
                task_projection = (
                    await self.task_manager.get(active_task_id)
                    if self.task_manager is not None
                    else None
                )
                task_status = getattr(
                    getattr(task_projection, "status", None), "value", "ready"
                )
                await self.supervision_service.emit(
                    task_id=active_task_id,
                    workspace_id=self.active_workspace.id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                    event_type=(
                        "task.completed"
                        if task_status == "completed"
                        else "completion.rejected"
                    ),
                    payload={
                        "status": "COMPLETED" if task_status == "completed" else "BLOCKED",
                        "completion_eligibility": (
                            "completed" if task_status == "completed" else "not_current"
                        ),
                    },
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
            if (
                self.supervision_service is not None
                and self._supervision_runtime_registered
                and active_task_id
                and self.active_workspace is not None
            ):
                await self.supervision_service.settle_cancel(
                    task_id=active_task_id,
                    workspace_id=self.active_workspace.id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                )
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
            if (
                self.supervision_service is not None
                and self._supervision_runtime_registered
                and active_task_id
                and self.active_workspace is not None
            ):
                await self.supervision_service.emit(
                    task_id=active_task_id,
                    workspace_id=self.active_workspace.id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                    event_type="task.failed",
                    payload={"error_type": type(exc).__name__, "status": "FAILED"},
                    severity="error",
                )
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
            if (
                self.supervision_service is not None
                and self._supervision_runtime_registered
                and active_task_id
            ):
                await self.supervision_service.unregister_runtime(
                    active_task_id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                )
                self._supervision_runtime_registered = False

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

    def _ensure_completion_recovery(self) -> CompletionRecoveryService | None:
        """Build the read-only durable continuation service when needed.

        Recovery is deliberately lazy for direct AgentLoop construction, but
        the runtime factory composes the same service explicitly.  This
        fallback only wires owner-scoped readers; it cannot invoke a model,
        planner, evaluator, gate, or task lifecycle writer.
        """
        recovery = self.completion_recovery
        if recovery is not None:
            return recovery
        if self.db is None:
            return None

        from khaos.agent.control.completion_recovery import (
            CompletionRecoveryService,
            DatabaseCompletionGateHistoryReader,
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
        recovery = CompletionRecoveryService(
            decision_repository=decision_repository,
            goal_spec_repository=goal_spec_repository,
            gate_history_reader=DatabaseCompletionGateHistoryReader(self.db),
            principal_id=self.principal_id,
            project_id=self.project_id,
        )
        self.completion_recovery = recovery
        return recovery

    def _ensure_recovery_control(self) -> RecoveryControlCoordinator | None:
        """Build the owner-scoped M7.5 control seam for direct loop callers.

        The runtime factory composes this coordinator explicitly.  This small
        fallback keeps older/test AgentLoop construction sites functional while
        still requiring the database-owned repositories; it never invents an
        authority policy or turns recovery history into a TaskStatus write.
        """
        control = self.recovery_control
        if control is not None:
            return control
        if self.db is None or not self.principal_id:
            return None

        from khaos.agent.control.recovery import RecoveryPolicy
        from khaos.agent.control.recovery_control import RecoveryControlCoordinator
        from khaos.agent.control.recovery_gate import RecoveryGate

        recovery_repository = getattr(self.db, "recovery_decision_repository", None)
        gate_repository = getattr(self.db, "recovery_gate_repository", None)
        if recovery_repository is None or gate_repository is None:
            return None
        goal_spec_repository = getattr(
            self.task_manager, "goal_spec_repository", None
        )
        if goal_spec_repository is None:
            goal_spec_repository = getattr(self.db, "goal_spec_repository", None)
        if goal_spec_repository is None:
            return None
        control = RecoveryControlCoordinator(
            recovery_repository=recovery_repository,
            recovery_gate=RecoveryGate(
                gate_repository=gate_repository,
                principal_id=self.principal_id,
                project_id=self.project_id,
            ),
            principal_id=self.principal_id,
            project_id=self.project_id,
            policy=RecoveryPolicy.production_default(),
            goal_spec_repository=goal_spec_repository,
            plan_revision_repository=getattr(
                self.db, "plan_revision_repository", None
            ),
            verification_assessment_repository=getattr(
                self.db, "verification_assessment_repository", None
            ),
            completion_recovery=self._ensure_completion_recovery(),
            planning_coordinator=self.planning_coordinator,
            control_state_repository=getattr(
                self.db, "agent_control_state_repository", None
            ),
        )
        self.recovery_control = control
        return control

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

    async def _recover_after_completion(
        self,
        *,
        turn: Any,
        task_id: str,
        decision_outcome: str,
        query: str,
    ) -> Any:
        """Handle only negative completion outcomes at an explicit boundary.

        ``COMPLETE`` remains the Completion Gate's concern.  A recorded
        ``REPLAN``, ``BLOCKED``, or ``FAILED`` decision is a deterministic
        recovery signal; the recovery coordinator may persist/apply its
        cognitive control decision and, when safely composed, invoke the
        existing planning coordinator.  No model prose is inspected and no
        recovery path writes TaskStatus.
        """
        if decision_outcome == "complete":
            return None
        control = self._ensure_recovery_control()
        if control is None:
            return None
        if not self._admit_recovery_cycle(control):
            result = self._recovery_cycle_limit_result(task_id)
            await self._emit_recovery_blocked(turn, task_id, result)
            return result
        result = await control.evaluate_current(
            task_id,
            workspace=self.active_workspace,
            query=query,
            runtime_id=self.runtime_id,
            event_sink=turn,
        )
        if (
            getattr(getattr(result, "action", None), "value", None) == "block"
            or getattr(getattr(result, "status", None), "value", None) == "blocked"
        ):
            await self._emit_recovery_blocked(turn, task_id, result)
        refresh = getattr(self.task_manager, "refresh_projection", None)
        if refresh is not None and result.cognitive_state is not None:
            await refresh(task_id)
        return result

    async def _recover_after_no_progress(
        self,
        *,
        turn: Any,
        task_id: str,
        failure_signature: NormalizedFailureSignature,
        query: str,
    ) -> Any:
        """Apply one bounded recovery decision for a repeated failure.

        VerifyFixLoop remains the low-level observation/repair strategy.  This
        boundary only forwards its typed negative signal to M7.5; it never
        treats test output as successful verification or completion authority.
        """
        control = self._ensure_recovery_control()
        if control is None:
            return None
        if not self._admit_recovery_cycle(control):
            result = self._recovery_cycle_limit_result(task_id)
            await self._emit_recovery_blocked(turn, task_id, result)
            return result
        result = await control.evaluate_current(
            task_id,
            failure_signature=failure_signature,
            no_progress_detected=True,
            workspace=self.active_workspace,
            query=query,
            runtime_id=self.runtime_id,
            event_sink=turn,
        )
        if getattr(result, "gate_status", None) is not None:
            refresh = getattr(self.task_manager, "refresh_projection", None)
            if refresh is not None and result.cognitive_state is not None:
                await refresh(task_id)
        if (
            getattr(getattr(result, "action", None), "value", None) == "block"
            or getattr(getattr(result, "status", None), "value", None) == "blocked"
        ):
            await self._emit_recovery_blocked(turn, task_id, result)
        return result

    def _admit_recovery_cycle(self, control: Any) -> bool:
        """Consume one bounded recovery cycle for the current user turn."""
        limit = getattr(
            getattr(control, "policy", None),
            "max_recovery_cycles_per_turn",
            0,
        )
        if type(limit) is not int or limit < 0:
            return False
        if self._recovery_cycles_this_turn >= limit:
            return False
        self._recovery_cycles_this_turn += 1
        return True

    @staticmethod
    def _recovery_cycle_limit_result(task_id: str) -> Any:
        """Return a bounded non-authoritative result when the turn budget ends."""
        from khaos.agent.control.recovery import RecoveryAction, RecoveryReasonCode
        from khaos.agent.control.recovery_control import (
            RecoveryControlResult,
            RecoveryControlStatus,
        )

        return RecoveryControlResult(
            status=RecoveryControlStatus.BLOCKED,
            task_id=task_id,
            action=RecoveryAction.BLOCK,
            reason_code=RecoveryReasonCode.RECOVERY_ATTEMPT_BUDGET_EXHAUSTED,
            reason="per-turn recovery cycle budget is exhausted",
        )

    @staticmethod
    async def _emit_recovery_blocked(
        turn: Any,
        task_id: str,
        result: Any,
    ) -> None:
        """Emit a bounded observability event for an explicit recovery stop."""
        await turn.emit(
            "recovery.blocked",
            {
                "task_id": task_id,
                "recovery_decision_id": getattr(
                    result, "recovery_decision_id", None
                ),
                "recovery_sequence": getattr(result, "recovery_sequence", None),
                "action": getattr(
                    getattr(result, "action", None), "value", None
                ),
                "reason_code": getattr(
                    getattr(result, "reason_code", None), "value", None
                ),
                "status": getattr(
                    getattr(result, "status", None), "value", None
                ),
            },
        )

    @staticmethod
    def _normalize_verify_fix_failure(
        observation: Any,
    ) -> NormalizedFailureSignature:
        """Convert VerifyFix observations to bounded M7.5 failure identity."""
        from khaos.agent.control.recovery import (
            NormalizedFailureCase,
            NormalizedFailureSignature,
            RecoveryFailureSource,
        )

        cases: list[NormalizedFailureCase] = []
        for index, raw_case in enumerate(getattr(observation, "failed_cases", ())):
            if not isinstance(raw_case, dict):
                continue
            name = raw_case.get("name")
            subject_id = str(name)[:512] if name else f"test-case:{index + 1}"
            file_value = raw_case.get("file")
            file_identity = (
                str(file_value)[:512] if isinstance(file_value, str) and file_value else None
            )
            line_value = raw_case.get("line")
            line = line_value if type(line_value) is int and line_value > 0 else None
            error_value = raw_case.get("error")
            error_digest = None
            if isinstance(error_value, str) and error_value:
                error_digest = hashlib.sha256(
                    error_value[:4096].encode("utf-8", errors="replace")
                ).hexdigest()
            cases.append(
                NormalizedFailureCase(
                    subject_id=subject_id,
                    check_id=subject_id,
                    file_identity=file_identity,
                    line=line,
                    error_digest=error_digest,
                    result_status="failed",
                )
            )
        if not cases:
            cases.append(
                NormalizedFailureCase(
                    subject_id="test-run:unresolved-failure",
                    result_status="failed",
                )
            )
        check_ids = tuple(
            case.check_id for case in cases if case.check_id is not None
        )
        return NormalizedFailureSignature.from_cases(
            source=RecoveryFailureSource.VERIFY_FIX,
            failed_count=int(getattr(observation, "failed", 0)),
            error_count=int(getattr(observation, "errors", 0)),
            failed_cases=tuple(cases),
            verification_check_ids=check_ids,
            result_statuses=("failed",),
        )

    @staticmethod
    def _recovery_result_message(
        *,
        result: Any,
        turn_id: str,
        attempt_id: str,
        task_id: str,
    ) -> Message:
        """Expose a bounded recovery result without injecting raw history."""
        metadata: dict[str, Any] = {
            "task_id": task_id,
            "turn_id": turn_id,
            "attempt_id": attempt_id,
            "status": getattr(getattr(result, "status", None), "value", None),
            "recovery_decision_id": getattr(result, "recovery_decision_id", None),
            "recovery_sequence": getattr(result, "recovery_sequence", None),
            "action": getattr(
                getattr(result, "action", None), "value", None
            ),
            "reason_code": getattr(
                getattr(result, "reason_code", None), "value", None
            ),
            "gate_status": getattr(
                getattr(result, "gate_status", None), "value", None
            ),
            "planning_status": getattr(result, "planning_status", None),
            "planning_revision_id": getattr(result, "planning_revision_id", None),
        }
        if getattr(result, "reason", ""):
            metadata["reason"] = result.reason
        return Message(
            role="system",
            content="recovery control evaluated",
            event="recovery_control",
            metadata=metadata,
            created_at=time.time(),
        )

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
        recovery_result: Any = None,
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
            recovery_replanned = (
                getattr(getattr(recovery_result, "action", None), "value", None)
                == "replan"
                and getattr(
                    getattr(recovery_result, "status", None), "value", None
                )
                == "applied"
            )
            if (
                verification_state is VerificationState.EXHAUSTED_FAILURE
                and not recovery_replanned
            ):
                await self.task_manager.update_status(
                    task_id,
                    TaskStatus.FAILED,
                    error="verify-fix loop exhausted, tests still failing",
                )
            elif (
                verification_state is VerificationState.FAILING
                and not recovery_replanned
            ):
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
        """Dispatch model-context construction to the single active owner.

        The runtime factory supplies Context Engine 2.0.  The explicitly
        named legacy adapter below exists only for direct compatibility/test
        constructions that do not provide that service.
        """
        if self.context_engine is not None:
            history = await self.db.list_messages(
                session_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
            memory_message = await self._build_memory_message(session_id)
            self._active_context_bundle = None
            repo_message = None
            if self.context_intelligence is not None and self._is_coding_mode():
                repo_message = await self._build_context_intelligence_message(user_input)
            context = await self.context_engine.build_for_agent(
                system_prompt=await self._build_system_prompt_for_context_engine(
                    session_id, user_input
                ),
                history=history,
                active_facts=self._active_context_facts,
                memory_message=memory_message,
                repo_message=(
                    None if self._active_context_bundle is not None else repo_message
                ),
                repo_bundle=self._active_context_bundle,
                task_id=self._active_task_id or "",
                workspace_id=getattr(self.active_workspace, "id", "") or "",
                generation=self._context_generation(),
                plan_revision=(
                    getattr(self._active_planning_result, "revision_digest", None)
                    or getattr(self._active_planning_result, "plan_digest", None)
                ),
                goal=user_input,
                operation=self._context_operation(user_input),
                target_path=self._context_target_path(user_input),
            )
            return [self._context_message_to_message(message) for message in context.messages]
        return await self._build_legacy_context(session_id, user_input)

    async def _build_legacy_context(
        self, session_id: str, user_input: str = ""
    ) -> list[Message]:
        """Compatibility adapter for direct loops without Context Engine."""

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

        memory_message = await self._build_memory_message(session_id)
        if memory_message is not None:
            messages.append(memory_message)

        if self.context_intelligence is not None and self._is_coding_mode():
            relevant = await self._build_context_intelligence_message(user_input)
        else:
            relevant = self._build_relevant_files_message(user_input)
        if relevant is not None:
            messages.append(relevant)

        return messages

    async def _build_system_prompt_for_context_engine(
        self, session_id: str, user_input: str = ""
    ) -> str:
        """Build only the application prompt and deferred skill projection."""

        del session_id
        prompt = await self.mode_manager.load_system_prompt()
        skill_prompt = getattr(self.context_engine, "skill_prompt", None)
        if callable(skill_prompt):
            rendered = skill_prompt(self.mode_manager.current_mode.value, user_input)
            if rendered:
                prompt = f"{prompt}\n\n{rendered}"
        return prompt

    def _context_target_path(self, user_input: str) -> Path | None:
        """Choose one safe target for scoped project-instruction resolution."""

        if self.project_root is None:
            return None
        root = Path(self.project_root).expanduser().resolve()
        candidates: list[str] = []
        plan = self._active_planning_result
        for container in (
            getattr(plan, "target_files", ()),
            getattr(plan, "affected_files", ()),
        ):
            for value in tuple(container or ())[:16]:
                if isinstance(value, str):
                    candidates.append(value)
                else:
                    for field_name in ("path", "relative_path", "file_path"):
                        field_value = getattr(value, field_name, None)
                        if isinstance(field_value, str) and field_value:
                            candidates.append(field_value)
                            break
        # This is only an explicit-path hint; it never scans the repository or
        # treats arbitrary user text as a filesystem authority.
        candidates.extend(
            re.findall(
                r"(?<![A-Za-z0-9_])(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+\.(?:py|go|rs|js|jsx|ts|tsx|md|yaml|yml|toml|json)(?::\d+(?:-\d+)?)?",
                user_input or "",
            )
        )
        for raw in candidates:
            clean = raw.split(":", 1)[0].strip("`'\".,;()[]{}")
            if not clean:
                continue
            candidate = Path(clean).expanduser()
            if not candidate.is_absolute():
                candidate = root / candidate
            try:
                resolved = candidate.resolve(strict=False)
                if os.path.commonpath((str(root), str(resolved))) == str(root):
                    return resolved
            except (OSError, ValueError):
                continue
        return root

    def _context_operation(self, user_input: str):
        """Map the current orchestration phase to operation-aware budgets."""

        from khaos.coding.context_engine import ContextOperation

        text = (user_input or "").casefold()
        if any(token in text for token in ("verify", "test", "失败", "修复")):
            return ContextOperation.VERIFICATION_REPAIR
        if self._active_planning_result is None:
            return ContextOperation.PLANNING
        return ContextOperation.EDITING

    def _context_generation(self) -> str | None:
        """Return the repository-generation identity for context freshness."""

        bundle = self._active_context_bundle
        bundle_generation = getattr(bundle, "repository_generation", None)
        if bundle_generation:
            return str(bundle_generation)
        workspace = self.active_workspace
        value = getattr(workspace, "generation", None) or getattr(
            workspace, "base_sha", None
        )
        return str(value) if value is not None else None

    def _context_requirements(self, user_input: str):
        """Build the same bounded requirements used by AgentLoop rebalances."""

        from khaos.coding.context_engine import ContextBudget, ContextRequirements

        engine_budget = getattr(self.context_engine, "default_budget", None)
        if not isinstance(engine_budget, ContextBudget):
            engine_budget = ContextBudget()
        return ContextRequirements(
            operation=self._context_operation(user_input),
            task_id=self._active_task_id or "",
            workspace_id=getattr(self.active_workspace, "id", "") or "",
            generation=self._context_generation(),
            plan_revision=(
                getattr(self._active_planning_result, "revision_digest", None)
                or getattr(self._active_planning_result, "plan_digest", None)
            ),
            query=user_input or "",
            recent_message_count=max(
                0,
                int(
                    getattr(
                        self.config,
                        "context_recent_message_count",
                        getattr(self.context_engine, "recent_message_count", 12),
                    )
                ),
            ),
            budget=engine_budget,
        )

    async def _build_memory_message(self, session_id: str) -> Message | None:
        """Project retrieved memory as bounded, low-trust data context.

        Memory is intentionally not part of the system prompt. The provider
        boundary may discard Khaos metadata, so the role and explicit envelope
        are the actual prompt-privilege fence; persisted text never becomes a
        control instruction merely because it was retrieved locally.
        """
        if self.memory_manager is None:
            return None
        inject = getattr(self.memory_manager, "inject", None)
        if not callable(inject):
            return None
        try:
            parameters = inspect.signature(inject).parameters
            supports_task = any(
                parameter.kind is inspect.Parameter.VAR_KEYWORD
                or name == "task_id"
                for name, parameter in parameters.items()
            )
            if supports_task:
                memory_text = await cast(Any, inject)(
                    session_id,
                    task_id=self._active_task_id,
                )
            else:
                memory_text = await cast(Any, inject)(session_id)
        except Exception:
            logger.warning(
                "memory prompt projection unavailable; continuing without memory",
                exc_info=True,
            )
            return None
        if not memory_text:
            return None
        text = str(memory_text)
        return Message(
            role="user",
            content=text,
            token_count=self.token_engine.count_tokens(text),
            metadata={
                "context_layer": "historical-memory",
                "trusted": False,
                "authority": "low-trust-data",
            },
        )

    async def _build_context_intelligence_message(
        self, user_input: str
    ) -> Message | None:
        """Build a bounded projection from the canonical GoalSpec/workspace.

        A missing or invalid TaskWorkspace is intentionally unavailable: this
        path never falls back to ``project_root`` or to the legacy builder.
        """

        task_id = self._active_task_id
        workspace = self.active_workspace
        if task_id is None or workspace is None or self.task_manager is None:
            logger.warning(
                "workspace-bound context unavailable: task=%s workspace=%s",
                task_id,
                getattr(workspace, "id", None),
            )
            return None
        goal_repository = getattr(self.task_manager, "goal_spec_repository", None)
        if goal_repository is None:
            logger.warning("workspace-bound context unavailable: GoalSpec repository missing")
            return None
        try:
            goal_spec = await goal_repository.get_for_task(
                task_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
            )
            if goal_spec is None:
                logger.warning("workspace-bound context unavailable: GoalSpec missing for %s", task_id)
                return None
            service = self.context_intelligence
            if service is None:
                return None
            repository_id = service.repository_id_for_workspace(workspace)
            from khaos.coding.intelligence.context import (
                ContextFreshness,
                ContextRequest,
            )

            request = ContextRequest(
                task_id=task_id,
                principal_id=self.principal_id,
                project_id=self.project_id,
                goal_spec_id=goal_spec.goal_spec_id,
                goal_spec_digest=goal_spec.semantic_digest,
                workspace_id=workspace.id,
                repository_id=repository_id,
                base_revision=getattr(workspace, "base_sha", None),
                query=user_input or goal_spec.normalized_goal,
                runtime_id=self.runtime_id,
                token_budget=max(
                    1,
                    int(getattr(self.config, "context_token_budget", 12_000)),
                ),
                max_bytes=max(
                    1,
                    int(getattr(self.config, "context_max_bytes", 256 * 1024)),
                ),
                max_file_bytes=max(
                    1,
                    int(getattr(self.config, "context_max_file_bytes", 64 * 1024)),
                ),
                max_files=max(
                    1,
                    int(getattr(self.config, "context_max_files", 16)),
                ),
                max_symbols=max(
                    1,
                    int(getattr(self.config, "context_max_symbols", 128)),
                ),
            )
            bundle = await service.retrieve(request, goal_spec)
        except Exception as exc:  # noqa: BLE001 - context is non-fatal and fail-closed
            logger.warning("workspace-bound context build failed: %s", exc)
            return None
        if bundle.freshness is not ContextFreshness.FRESH:
            logger.warning(
                "workspace-bound context is not fresh: task=%s freshness=%s",
                task_id,
                bundle.freshness.value,
            )
            return None
        self._active_context_bundle = bundle
        await self._observe_context_event(
            "RepoQueryResult",
            {
                "workspace_id": bundle.workspace_id,
                "generation": bundle.repository_generation,
                "query_digest": hashlib.sha256(
                    (user_input or goal_spec.normalized_goal).encode("utf-8")
                ).hexdigest(),
                "summary": (
                    f"repository candidates={len(bundle.documents)} files, "
                    f"{len(bundle.symbols)} symbols, {len(bundle.evidence)} relations"
                ),
            },
            task_id=task_id,
        )
        if self.context_engine is not None:
            # The engine consumes the typed M8.1 bundle directly.  Avoid
            # constructing a second monolithic rendered projection on the
            # normal runtime path; the legacy message remains below for
            # explicitly constructed loops without Context Engine 2.0.
            return None
        blocks = [
            "# Context Bundle",
            "",
            "<untrusted_workspace_context>",
            (
                f"bundle_digest={bundle.bundle_digest} "
                f"workspace_id={bundle.workspace_id} "
                f"repository_id={bundle.repository_id} "
                f"base_revision={bundle.base_revision or ''} "
                f"repository_generation={bundle.repository_generation} "
                f"index_generation={bundle.index_generation} "
                f"truncated={str(bundle.truncated).lower()}"
            ),
        ]
        if bundle.structure_paths:
            blocks.extend(["", "## Workspace Structure", "", *bundle.structure_paths])
        if bundle.documents:
            blocks.extend(["", "## Relevant Files", ""])
            for document in bundle.documents:
                language = document.language if document.language != "text" else ""
                blocks.extend(
                    [
                        f"### {document.relative_path}",
                        f"```{language}",
                        document.content,
                        "```",
                    ]
                )
        if bundle.symbols:
            blocks.extend(["", "## Relevant Symbols", ""])
            blocks.extend(
                f"- {symbol.relative_path}:{symbol.start_line + 1} "
                f"{symbol.qualified_name} ({symbol.kind})"
                for symbol in bundle.symbols
            )
        blocks.append("</untrusted_workspace_context>")
        content = "\n".join(blocks)
        render_truncated = False
        render_budget = max(
            1, int(getattr(self.config, "context_token_budget", 12_000))
        )
        if self.token_engine.count_tokens(content) > render_budget:
            render_truncated = True
            # Keep the projection bounded even when the token engine is more
            # precise than the byte-based service bound.  The service bundle
            # remains immutable; this is only a smaller prompt projection.
            closing = "</untrusted_workspace_context>"
            marker = "... (context projection truncated)"
            prefix_budget = max(
                1,
                render_budget
                - self.token_engine.count_tokens(f"{marker}\n{closing}"),
            )
            prefix = self._trim_to_budget("\n".join(blocks[:-1]), prefix_budget).rstrip()
            content = f"{prefix}\n{marker}\n{closing}"
            while self.token_engine.count_tokens(content) > render_budget:
                prefix_lines = prefix.splitlines()
                if len(prefix_lines) <= 1:
                    break
                prefix = "\n".join(prefix_lines[:-1]).rstrip()
                content = f"{prefix}\n{marker}\n{closing}"
        # Repository/workspace bytes are data.  The OpenAI-compatible client
        # forwards Message.role and does not forward Khaos metadata, so this
        # must remain a user-level observation rather than a system message.
        return Message(
            role="user",
            content=content,
            token_count=self.token_engine.count_tokens(content),
            metadata={
                "context_layer": "workspace-bound-observation",
                "trusted": False,
                "context_bundle_id": bundle.bundle_id,
                "context_bundle_digest": bundle.bundle_digest,
                "workspace_id": bundle.workspace_id,
                "repository_id": bundle.repository_id,
                "base_revision": bundle.base_revision,
                "repository_generation": bundle.repository_generation,
                "index_generation": bundle.index_generation,
                "truncated": bundle.truncated or render_truncated,
                "freshness": bundle.freshness.value,
            },
        )

    async def _build_durable_task_facts(
        self, task_id: str | None
    ) -> list[Message]:
        """Reconstruct authoritative Task/approval facts outside summaries."""
        if task_id is None:
            return []
        recovery = self._ensure_completion_recovery()
        recovery_state = (
            await recovery.recover(task_id) if recovery is not None else None
        )
        recovery_control = self._ensure_recovery_control()
        recovery_control_fact = (
            await recovery_control.recover(task_id)
            if recovery_control is not None
            else None
        )
        task = (
            await self.task_manager.get(task_id)
            if self.task_manager is not None
            else None
        )
        if task is None and recovery_state is None:
            return []
        raw = task.to_dict(include_internal=True) if task is not None else {}
        metadata = raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}
        goal_spec = getattr(task, "goal_spec", None) if task is not None else None
        facts = {
            "task_id": raw.get("id", task_id),
            "goal": raw.get("goal"),
            "status": raw.get("status"),
            "cognitive_state": getattr(
                getattr(task, "cognitive_state", None)
                if task is not None
                else None,
                "value",
                None,
            ),
            "control_state_version": (
                getattr(task, "control_state_version", None)
                if task is not None
                else None
            ),
            # M7.1.2: these are bounded durable references/projections.  The
            # canonical GoalSpec body remains in agent_goal_specs and is not
            # copied into task metadata or injected wholesale.
            "goal_spec_id": (
                getattr(task, "goal_spec_id", None) if task is not None else None
            ),
            "goal_spec_digest": (
                getattr(task, "goal_spec_digest", None) if task is not None else None
            ),
            "workspace_id": metadata.get("workspace_id"),
            "base_sha": metadata.get("base_sha"),
            "pending_approval": metadata.get("pending_approval"),
            "plan_id": metadata.get("plan_id"),
            "changeset_id": metadata.get("changeset_id"),
            "verification_run_id": metadata.get("verification_run_id"),
        }
        # M7.3: expose only a bounded read projection of the durable plan
        # history.  The canonical revision remains in the owner-scoped
        # ledger; no raw plan JSON or repository text is injected here.
        plan_repository = getattr(self.db, "plan_revision_repository", None)
        if plan_repository is not None:
            try:
                current_plan_snapshot = (
                    await plan_repository.get_current_task_snapshot(
                        task_id,
                        principal_id=self.principal_id,
                        project_id=self.project_id,
                    )
                )
                latest_plan = await plan_repository.get_latest_for_task(
                    task_id,
                    principal_id=self.principal_id,
                    project_id=self.project_id,
                )
                published_plan = None
                published_plan_revision_id = (
                    current_plan_snapshot.published_plan_revision_id
                    if current_plan_snapshot is not None
                    else None
                )
                if published_plan_revision_id is not None:
                    # This strict reader resolves the physical publication
                    # identity to its exact owner/task-scoped ledger row.  A
                    # missing or malformed published row is an integrity
                    # failure; latest history is never a fallback.
                    published_plan = await plan_repository.get_published_for_task(
                        task_id,
                        principal_id=self.principal_id,
                        project_id=self.project_id,
                    )
            except Exception as exc:  # noqa: BLE001 - facts fail closed
                logger.warning(
                    "durable planning facts unavailable: task=%s error=%s",
                    task_id,
                    type(exc).__name__,
                )
                facts["planning_integrity"] = "unavailable"
            else:
                facts["latest_plan_revision_id"] = (
                    latest_plan.plan_revision_id if latest_plan is not None else None
                )
                facts["published_plan_revision_id"] = published_plan_revision_id
                is_implementing = (
                    current_plan_snapshot is not None
                    and current_plan_snapshot.cognitive_state
                    is AgentCognitiveState.IMPLEMENTING
                )
                if is_implementing and published_plan_revision_id is None:
                    # An IMPLEMENTING task must have a durable publication
                    # identity.  The latest history head is not an
                    # implementation-plan authority and must not be
                    # projected into the current-plan fact when the
                    # publication projection is absent.
                    facts["planning_integrity"] = (
                        "legacy_unpublished_implementation_plan"
                    )
                    facts["plan_revision_source"] = "none"
                    selected_plan = None
                else:
                    selected_plan = (
                        published_plan
                        if published_plan_revision_id is not None
                        else latest_plan
                    )
                if published_plan_revision_id is not None and published_plan is None:
                    facts["planning_integrity"] = "unavailable"
                elif selected_plan is not None:
                    revision = selected_plan.revision
                    facts["plan_revision_source"] = (
                        "published"
                        if published_plan_revision_id is not None
                        else "latest"
                    )
                    facts["plan_revision"] = {
                        "plan_revision_id": revision.plan_revision_id,
                        "revision_sequence": selected_plan.revision_sequence,
                        "plan_semantic_digest": revision.plan_semantic_digest,
                        "status": revision.disposition.value,
                        "disposition": revision.disposition.value,
                        "planning_input_digest": revision.planning_input_digest,
                        "goal_spec_digest": revision.goal_spec_digest,
                        "workspace_id": revision.workspace_id,
                        "repository_id": revision.repository_id,
                        "base_revision": revision.base_revision,
                        "context_bundle_id": revision.context_bundle_id,
                        "context_bundle_digest": revision.context_bundle_digest,
                        "repository_generation": revision.repository_generation,
                        "index_generation": revision.index_generation,
                        "target_files": tuple(
                            item.path for item in revision.affected_files[:32]
                        ),
                        "target_symbols": tuple(
                            item.symbol_id for item in revision.affected_symbols[:64]
                        ),
                        "step_ids": tuple(
                            item.step_id for item in revision.steps[:32]
                        ),
                        "step_operations": tuple(
                            item.operation.value for item in revision.steps[:32]
                        ),
                        "step_titles": tuple(
                            item.title[:512] for item in revision.steps[:32]
                        ),
                        "step_targets": tuple(
                            {
                                "step_id": item.step_id,
                                "target_files": tuple(item.target_files[:32]),
                                "target_symbols": tuple(item.target_symbols[:64]),
                            }
                            for item in revision.steps[:32]
                        ),
                        "diagnostic_codes": tuple(
                            item.code for item in revision.diagnostics[:32]
                        ),
                        "context_truncated": any(
                            item.code == "context-truncated"
                            for item in revision.diagnostics
                        ),
                    }
        # M7.1.8: expose only a bounded read-only continuation projection.
        # Recovery never invokes a planner/model/gate and never projects a
        # lifecycle status.
        if recovery_state is not None:
            facts["completion_recovery"] = recovery_state.to_bounded_fact()
            # The recovery service reads the physical SQL task snapshot.  If
            # the in-memory projection is stale, keep these bounded top-level
            # facts aligned with the durable source without mutating it.
            if recovery_state.task_status is not None:
                facts["status"] = recovery_state.task_status
            if recovery_state.cognitive_state is not None:
                facts["cognitive_state"] = recovery_state.cognitive_state.value
            if recovery_state.control_state_version is not None:
                facts["control_state_version"] = (
                    recovery_state.control_state_version
                )
            facts["workspace_id"] = recovery_state.workspace_id
        if recovery_control_fact is not None:
            facts["recovery_control"] = recovery_control_fact.to_bounded_fact()
            # RecoveryControlCoordinator reads the same physical task row and
            # is therefore another safe source for correcting a stale cache
            # projection.  It is read-only and never applies recovery here.
            facts["status"] = recovery_control_fact.task_status
            facts["cognitive_state"] = recovery_control_fact.cognitive_state
            facts["control_state_version"] = (
                recovery_control_fact.control_state_version
            )
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

    def _build_tools_schema(self, intent: str = "") -> list[dict] | None:
        """Return provider-neutral function tool schemas for the current mode."""
        if self.tool_scheduler is None:
            return None
        registry = getattr(self.tool_scheduler, "registry", None)
        if registry is None:
            return None
        mode = self.mode_manager.current_mode.value
        if self.context_engine is not None:
            return self.context_engine.tool_schemas(mode=mode, intent=intent)
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

    @staticmethod
    def _context_message_to_message(message: object) -> Message:
        """Convert a provider-neutral M8.4 message into AgentLoop data."""

        result = Message(
            role=str(getattr(message, "role", "user")),
            content=str(getattr(message, "content", "")),
            tool_calls=[
                dict(call)
                for call in (getattr(message, "tool_calls", ()) or ())
                if isinstance(call, dict)
            ],
            tool_call_id=getattr(message, "tool_call_id", None),
            token_count=0,
            event=getattr(message, "event", None),
            metadata=dict(getattr(message, "metadata", {}) or {}),
        )
        # The marker is process-local and never enters the serialized
        # metadata.  Rebalance can therefore preserve engine-owned typed
        # provenance without trusting a model/provider-supplied key.
        setattr(result, "_context_engine_message", True)  # noqa: B010 - private provenance marker
        return result

    async def _observe_context_event(
        self,
        event: str,
        payload: dict[str, object],
        *,
        task_id: str | None,
    ) -> None:
        """Project observability into the working set without failing a turn."""

        if self.context_engine is None or not task_id:
            return
        try:
            observe = getattr(self.context_engine, "observe_event", None)
            if callable(observe):
                workspace = getattr(self.active_workspace, "id", "") or ""
                if event in {
                    "EditTransactionApplied",
                    "VerificationPlanCreated",
                } or self._context_needs_rebuild:
                    generation_value = getattr(
                        self.active_workspace, "generation", None
                    ) or getattr(self.active_workspace, "base_sha", None)
                    event_generation = (
                        str(generation_value) if generation_value is not None else None
                    )
                else:
                    event_generation = self._context_generation()
                observed_payload = dict(payload)
                if workspace:
                    observed_payload.setdefault("workspace_id", workspace)
                if event_generation is not None:
                    observed_payload.setdefault("generation", event_generation)
                await cast(Any, observe)(
                    task_id,
                    event,
                    observed_payload,
                    workspace_id=workspace,
                    goal="",
                    generation=event_generation,
                )
        except Exception:
            logger.debug("context working-set update unavailable", exc_info=True)

    async def _build_system_prompt(self, session_id: str, user_input: str = "") -> str:
        # 注入顺序：项目约定文件 > memory > skill > 项目结构（见 AGENTS.md Phase 6）
        prompt = await self.mode_manager.load_system_prompt()

        if self.project_context_loader is not None:
            project_ctx = self.project_context_loader.load()
            if project_ctx:
                prompt = f"{prompt}\n\n# Project Instructions\n\n{project_ctx}"

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
        if self.context_intelligence is not None:
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
        """Return a ``# Relevant Files`` user observation, or None.

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
        if self.context_intelligence is not None:
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
            activity_args = _sanitize_tool_activity_arguments(name, args)
            output = result.output
            if name in {"read_file", "list_directory"}:
                path = args.get("path") or args.get("cwd")
                if path:
                    await self.task_manager.track_file_viewed(task_id, str(path))
            elif name in {"write_file", "patch", "multi_edit"}:
                path = args.get("path")
                if path:
                    await self.task_manager.track_file_modified(task_id, str(path))
            elif name == "apply_edit_transaction":
                for operation in args.get("operations", []):
                    if not isinstance(operation, dict):
                        continue
                    for path in (
                        operation.get("path"),
                        operation.get("destination_path"),
                    ):
                        if path:
                            await self.task_manager.track_file_modified(
                                task_id, str(path)
                            )
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
                "apply_edit_transaction": "PATCH_APPLIED",
                "test_run": "VERIFICATION_RESULT",
                "git_commit": "COMMIT_OBSERVED",
                "commit": "COMMIT_OBSERVED",
                "execute_plan": "PLAN_CREATED",
            }.get(name)
            if event_type:
                event_payload = {
                    "tool_name": name,
                    "success": bool(result.success),
                    "arguments": activity_args,
                    "output_summary": _sanitize_tool_activity_output(
                        name, output, result.error
                    ),
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
