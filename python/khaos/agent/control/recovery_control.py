"""Production composition for the M7.5 recovery control plane.

The value objects and policy in :mod:`khaos.agent.control.recovery` remain
pure.  This module is the narrow I/O orchestration seam that binds those
objects to the owner-scoped recovery ledger and the atomic ``RecoveryGate``.
It never interprets model prose and it never grants a tool, approval,
workspace, verification, or completion capability.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, replace
from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

from khaos.agent.control.completion_recovery import (
    CompletionRecoveryService,
)
from khaos.agent.control.recovery import (
    NormalizedFailureSignature,
    PlanningRecoveryStatus,
    RecoveryAction,
    RecoveryEvaluator,
    RecoveryInput,
    RecoveryPolicy,
    RecoveryReasonCode,
)
from khaos.agent.control.recovery_gate import (
    RecoveryGate,
    RecoveryGateResult,
    RecoveryGateStatus,
)
from khaos.agent.control.recovery_repository import (
    RecoveryDecisionRepository,
    RecoveryDecisionRepositoryError,
    RecoveryTaskSnapshot,
    StoredRecoveryDecision,
)
from khaos.agent.control.state import (
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.agent.control.state_repository import (
    AgentControlStateRepository,
    CognitiveTransitionStatus,
    CognitiveWorkspaceBinding,
)

if TYPE_CHECKING:
    from khaos.coding.planning.repository import PlanRevisionRepository
    from khaos.coding.planning.verification_assessment_repository import (
        VerificationAssessmentRepository,
    )

logger = logging.getLogger(__name__)

_MAX_REASON_LENGTH = 512
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


class RecoveryControlContinuation(str, Enum):
    """Read-only interpretation of the current recovery history head."""

    NO_DECISION = "no_decision"
    RECOVERY_REQUIRED = "recovery_required"
    REPLAN_REQUIRED = "replan_required"
    BLOCKED = "blocked"
    APPLIED = "applied"
    TERMINAL = "terminal"
    STALE = "stale"
    INTEGRITY_ERROR = "integrity_error"


class RecoveryControlStatus(str, Enum):
    """Bounded result vocabulary for one recovery-control operation."""

    RECORDED = "recorded"
    APPLIED = "applied"
    NO_ACTION = "no_action"
    BLOCKED = "blocked"
    STALE = "stale"
    INVALID = "invalid"
    TERMINAL = "terminal"
    NOT_FOUND = "not_found"
    INTEGRITY_ERROR = "integrity_error"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RecoveryControlFact:
    """Small durable recovery projection safe to expose to AgentLoop."""

    task_id: str
    continuation: RecoveryControlContinuation
    task_status: str
    cognitive_state: str
    control_state_version: int
    latest_decision_id: str | None = None
    latest_decision_digest: str | None = None
    latest_recovery_sequence: int | None = None
    action: RecoveryAction | None = None
    reason_code: RecoveryReasonCode | None = None
    published_plan_revision_id: str | None = None
    latest_plan_revision_id: str | None = None
    replan_count: int = 0
    failure_signature_digest: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.task_id) is not str or not self.task_id:
            raise ValueError("task_id must be a non-empty string")
        if type(self.continuation) is not RecoveryControlContinuation:
            raise ValueError("continuation must be a RecoveryControlContinuation")
        for value, label in (
            (self.task_status, "task_status"),
            (self.cognitive_state, "cognitive_state"),
        ):
            if type(value) is not str or not value:
                raise ValueError(f"{label} must be a non-empty string")
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise ValueError("control_state_version must be non-negative")
        if self.latest_recovery_sequence is not None and (
            type(self.latest_recovery_sequence) is not int
            or self.latest_recovery_sequence < 1
        ):
            raise ValueError("latest_recovery_sequence must be positive or None")
        if self.action is not None and type(self.action) is not RecoveryAction:
            raise ValueError("action must be a RecoveryAction or None")
        if self.reason_code is not None and type(self.reason_code) is not RecoveryReasonCode:
            raise ValueError("reason_code must be a RecoveryReasonCode or None")
        if type(self.replan_count) is not int or self.replan_count < 0:
            raise ValueError("replan_count must be non-negative")
        if type(self.reason) is not str or len(self.reason) > _MAX_REASON_LENGTH:
            raise ValueError("reason exceeds its bound")

    def to_bounded_fact(self) -> dict[str, object | None]:
        """Return a bounded projection for durable task facts."""
        return {
            "task_id": self.task_id,
            "continuation": self.continuation.value,
            "task_status": self.task_status,
            "cognitive_state": self.cognitive_state,
            "control_state_version": self.control_state_version,
            "latest_decision_id": self.latest_decision_id,
            "latest_decision_digest": self.latest_decision_digest,
            "latest_recovery_sequence": self.latest_recovery_sequence,
            "action": self.action.value if self.action is not None else None,
            "reason_code": self.reason_code.value if self.reason_code is not None else None,
            "published_plan_revision_id": self.published_plan_revision_id,
            "latest_plan_revision_id": self.latest_plan_revision_id,
            "replan_count": self.replan_count,
            "failure_signature_digest": self.failure_signature_digest,
        }


@dataclass(frozen=True, slots=True)
class RecoveryControlResult:
    """Bounded result of evaluate/append/apply orchestration."""

    status: RecoveryControlStatus
    recovery_decision_id: str | None = None
    recovery_sequence: int | None = None
    task_id: str | None = None
    action: RecoveryAction | None = None
    reason_code: RecoveryReasonCode | None = None
    gate_status: RecoveryGateStatus | None = None
    task_status: str | None = None
    cognitive_state: str | None = None
    control_state_version: int | None = None
    published_plan_revision_id: str | None = None
    planning_status: str | None = None
    planning_revision_id: str | None = None
    reason: str = ""

    def __post_init__(self) -> None:
        if type(self.status) is not RecoveryControlStatus:
            raise ValueError("status must be a RecoveryControlStatus")
        if self.recovery_decision_id is not None and (
            type(self.recovery_decision_id) is not str or not self.recovery_decision_id
        ):
            raise ValueError("recovery_decision_id must be non-empty or None")
        if self.recovery_sequence is not None and (
            type(self.recovery_sequence) is not int or self.recovery_sequence < 1
        ):
            raise ValueError("recovery_sequence must be positive or None")
        if self.action is not None and type(self.action) is not RecoveryAction:
            raise ValueError("action must be a RecoveryAction or None")
        if self.reason_code is not None and type(self.reason_code) is not RecoveryReasonCode:
            raise ValueError("reason_code must be a RecoveryReasonCode or None")
        if type(self.reason) is not str or len(self.reason) > _MAX_REASON_LENGTH:
            raise ValueError("reason exceeds its bound")


class RecoveryEventSink(Protocol):
    """Minimal bounded event sink used by a turn coordinator."""

    async def emit(self, event_type: str, payload: dict[str, object]) -> Any:
        """Append one bounded control-plane event."""
        ...


class RecoveryControlCoordinator:
    """Bind pure recovery policy to durable storage and the atomic gate.

    ``recover`` is strictly read-only.  ``evaluate_current`` is only for an
    explicit runtime failure boundary supplied by its caller; it creates one
    immutable decision and, when required, asks ``RecoveryGate`` to apply the
    corresponding cognitive projection.  No method invokes a model or tool.
    """

    def __init__(
        self,
        *,
        recovery_repository: RecoveryDecisionRepository,
        recovery_gate: RecoveryGate,
        principal_id: str,
        project_id: str,
        policy: RecoveryPolicy | None = None,
        goal_spec_repository: Any = None,
        plan_revision_repository: PlanRevisionRepository | None = None,
        verification_assessment_repository: VerificationAssessmentRepository | None = None,
        completion_recovery: CompletionRecoveryService | None = None,
        planning_coordinator: Any = None,
        control_state_repository: AgentControlStateRepository | None = None,
    ) -> None:
        if type(principal_id) is not str or not principal_id:
            raise ValueError("principal_id must be a non-empty string")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._recovery_repository = recovery_repository
        self._recovery_gate = recovery_gate
        self._principal_id = principal_id
        self._project_id = project_id
        self._policy = policy or RecoveryPolicy.production_default()
        self._goal_spec_repository = goal_spec_repository
        self._plan_revision_repository = plan_revision_repository
        self._verification_repository = verification_assessment_repository
        self._completion_recovery = completion_recovery
        self._planning_coordinator = planning_coordinator
        self._control_state_repository = control_state_repository

    @property
    def principal_id(self) -> str:
        """Return the authenticated owner bound to this coordinator."""
        return self._principal_id

    @property
    def project_id(self) -> str:
        """Return the project identity bound to this coordinator."""
        return self._project_id

    @property
    def policy(self) -> RecoveryPolicy:
        """Return the trusted immutable policy used by this coordinator."""
        return self._policy

    async def recover(self, task_id: str) -> RecoveryControlFact | None:
        """Read current recovery knowledge without appending or applying.

        This method is restart-safe and idempotent.  It never replays a gate,
        planner, model, verification run, approval, or tool operation.
        """
        _validate_task_id(task_id)
        try:
            snapshot = await self._recovery_repository.read_current_task_snapshot(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if snapshot is None:
                return None
            latest = await self._recovery_repository.get_latest_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if latest is None:
                return _fact(snapshot, RecoveryControlContinuation.NO_DECISION)
            if snapshot.task_status in _TERMINAL_TASK_STATUSES:
                return _fact(
                    snapshot,
                    RecoveryControlContinuation.TERMINAL,
                    latest=latest,
                    reason="terminal task has precedence over recovery history",
                )
            # An applied decision intentionally changes the cognitive source
            # snapshot (and, for REPLAN, retires the published plan).  The
            # durable causal projection is therefore the acknowledgement that
            # prevents replay; do not misclassify that intentional post-apply
            # drift as a pending stale decision.
            if snapshot.last_applied_recovery_decision_id == latest.recovery_decision_id:
                return _fact(
                    snapshot,
                    RecoveryControlContinuation.APPLIED,
                    latest=latest,
                    reason="recovery decision is already applied",
                )
            if not await self._decision_is_current(latest, snapshot):
                return _fact(
                    snapshot,
                    RecoveryControlContinuation.STALE,
                    latest=latest,
                    reason="recovery decision snapshot is stale",
                )
            if latest.action is RecoveryAction.REPLAN:
                continuation = RecoveryControlContinuation.REPLAN_REQUIRED
            elif latest.action is RecoveryAction.RECOVER_CURRENT_PLAN:
                continuation = RecoveryControlContinuation.RECOVERY_REQUIRED
            elif latest.action is RecoveryAction.BLOCK:
                continuation = RecoveryControlContinuation.BLOCKED
            else:
                continuation = RecoveryControlContinuation.NO_DECISION
            return _fact(snapshot, continuation, latest=latest)
        except RecoveryDecisionRepositoryError as exc:
            logger.warning("recovery control read failed: %s", type(exc).__name__)
            snapshot = await self._safe_snapshot(task_id)
            if snapshot is None:
                return None
            return _fact(
                snapshot,
                RecoveryControlContinuation.INTEGRITY_ERROR,
                reason=type(exc).__name__,
            )
        except Exception as exc:  # noqa: BLE001 - read boundary fails closed
            logger.warning("recovery control read failed: %s", type(exc).__name__)
            snapshot = await self._safe_snapshot(task_id)
            if snapshot is None:
                return None
            return _fact(
                snapshot,
                RecoveryControlContinuation.INTEGRITY_ERROR,
                reason=type(exc).__name__,
            )

    async def evaluate_current(
        self,
        task_id: str,
        *,
        failure_signature: NormalizedFailureSignature | None = None,
        no_progress_detected: bool = False,
        planning_status: PlanningRecoveryStatus = PlanningRecoveryStatus.NONE,
        workspace: Any = None,
        query: str = "",
        target_files: tuple[str, ...] = (),
        target_symbols: tuple[str, ...] = (),
        changed_files: tuple[str, ...] = (),
        runtime_id: str = "",
        event_sink: RecoveryEventSink | None = None,
    ) -> RecoveryControlResult:
        """Evaluate a fresh durable snapshot at an explicit failure boundary."""
        _validate_task_id(task_id)
        try:
            recovery_input = await self._build_input(
                task_id,
                failure_signature=failure_signature,
                no_progress_detected=no_progress_detected,
                planning_status=planning_status,
            )
            recovery_input, preparation_result = await self._admit_diagnosis_if_needed(
                recovery_input,
                failure_signature=failure_signature,
                no_progress_detected=no_progress_detected,
                planning_status=planning_status,
            )
        except (RecoveryDecisionRepositoryError, ValueError) as exc:
            return RecoveryControlResult(
                status=RecoveryControlStatus.INTEGRITY_ERROR,
                task_id=task_id,
                reason=type(exc).__name__,
            )
        except Exception as exc:  # noqa: BLE001 - explicit control boundary fails closed
            logger.warning("recovery input construction failed: %s", type(exc).__name__)
            return RecoveryControlResult(
                status=RecoveryControlStatus.ERROR,
                task_id=task_id,
                reason=type(exc).__name__,
            )
        if preparation_result is not None:
            return preparation_result
        result = await self.evaluate_and_apply(
            recovery_input,
            event_sink=event_sink,
            workspace=workspace,
            query=query,
            target_files=target_files,
            target_symbols=target_symbols,
            changed_files=changed_files,
            runtime_id=runtime_id,
        )
        return result

    async def _admit_diagnosis_if_needed(
        self,
        recovery_input: RecoveryInput,
        *,
        failure_signature: NormalizedFailureSignature | None,
        no_progress_detected: bool,
        planning_status: PlanningRecoveryStatus,
    ) -> tuple[RecoveryInput, RecoveryControlResult | None]:
        """Enter ``DIAGNOSING`` before applying a recovery projection.

        The pure evaluator chooses an action from the original observation,
        but the closed cognitive graph intentionally does not contain direct
        ``IMPLEMENTING -> RECOVERING/REPLANNING`` edges.  This method admits
        the explicit diagnosis phase through the existing SQL CAS owner and
        rebuilds the input snapshot after that versioned transition.  It does
        not append a decision, call a planner, or widen the transition graph.
        """
        evaluation = RecoveryEvaluator.evaluate_action(recovery_input)
        if evaluation.action not in {
            RecoveryAction.RECOVER_CURRENT_PLAN,
            RecoveryAction.REPLAN,
        }:
            return recovery_input, None

        current = recovery_input.cognitive_state
        needs_diagnosis = current is not AgentCognitiveState.DIAGNOSING
        if needs_diagnosis:
            target_is_legal = (
                AgentCognitiveStateMachine.validate_transition(
                    current,
                    AgentCognitiveState.DIAGNOSING,
                )
                is CognitiveTransitionValidation.ALLOWED
            )
            direct_target = (
                AgentCognitiveState.REPLANNING
                if evaluation.action is RecoveryAction.REPLAN
                else AgentCognitiveState.RECOVERING
            )
            direct_is_legal = (
                AgentCognitiveStateMachine.validate_transition(
                    current,
                    direct_target,
                )
                is not CognitiveTransitionValidation.ILLEGAL
            )
            # Some phases have a semantically justified direct replan edge
            # (for example RECOVERING/COMPLETION_CHECK).  Use it only when the
            # canonical graph explicitly allows it; otherwise require the
            # dedicated diagnosis admission below.
            if direct_is_legal:
                return recovery_input, None
            if not target_is_legal:
                return recovery_input, RecoveryControlResult(
                    status=RecoveryControlStatus.INVALID,
                    task_id=recovery_input.task_id,
                    action=evaluation.action,
                    reason_code=evaluation.reason_code,
                    task_status=recovery_input.task_status,
                    cognitive_state=recovery_input.cognitive_state.value,
                    control_state_version=recovery_input.control_state_version,
                    published_plan_revision_id=(
                        recovery_input.published_plan_revision_id
                    ),
                    reason="recovery action has no legal diagnosis admission",
                )
            if self._control_state_repository is None:
                return recovery_input, RecoveryControlResult(
                    status=RecoveryControlStatus.INVALID,
                    task_id=recovery_input.task_id,
                    action=evaluation.action,
                    reason_code=evaluation.reason_code,
                    task_status=recovery_input.task_status,
                    cognitive_state=recovery_input.cognitive_state.value,
                    control_state_version=recovery_input.control_state_version,
                    published_plan_revision_id=(
                        recovery_input.published_plan_revision_id
                    ),
                    reason="diagnosis CAS owner is unavailable",
                )
            transition = await self._control_state_repository.compare_and_transition(
                recovery_input.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                expected_state=current,
                expected_version=recovery_input.control_state_version,
                target_state=AgentCognitiveState.DIAGNOSING,
                expected_task_status=recovery_input.task_status,
                expected_workspace_binding=CognitiveWorkspaceBinding(
                    workspace_id=recovery_input.workspace_id,
                    base_revision=recovery_input.base_revision,
                    repository_id=recovery_input.repository_id,
                ),
            )
            if transition.status is not CognitiveTransitionStatus.UPDATED:
                return recovery_input, RecoveryControlResult(
                    status=_diagnosis_transition_status(transition.status),
                    task_id=recovery_input.task_id,
                    action=evaluation.action,
                    reason_code=evaluation.reason_code,
                    task_status=transition.task_status or recovery_input.task_status,
                    cognitive_state=(
                        transition.current_state.value
                        if transition.current_state is not None
                        else current.value
                    ),
                    control_state_version=(
                        transition.control_state_version
                        if transition.control_state_version is not None
                        else recovery_input.control_state_version
                    ),
                    published_plan_revision_id=(
                        recovery_input.published_plan_revision_id
                    ),
                    reason="diagnosis CAS did not admit the recovery action",
                )
            # The control-state version is now different.  Rebuild every
            # dependent input binding rather than mutating the old snapshot.
            recovery_input = await self._build_input(
                recovery_input.task_id,
                failure_signature=failure_signature,
                no_progress_detected=no_progress_detected,
                planning_status=planning_status,
            )
        return recovery_input, None

    async def evaluate_and_apply(
        self,
        recovery_input: RecoveryInput,
        *,
        event_sink: RecoveryEventSink | None = None,
        workspace: Any = None,
        query: str = "",
        target_files: tuple[str, ...] = (),
        target_symbols: tuple[str, ...] = (),
        changed_files: tuple[str, ...] = (),
        runtime_id: str = "",
    ) -> RecoveryControlResult:
        """Evaluate, append, and atomically apply one bound recovery input."""
        if type(recovery_input) is not RecoveryInput:
            raise TypeError("recovery_input must be a RecoveryInput")
        if (
            recovery_input.principal_id != self._principal_id
            or recovery_input.project_id != self._project_id
        ):
            return RecoveryControlResult(
                status=RecoveryControlStatus.ERROR,
                task_id=recovery_input.task_id,
                reason="recovery input owner does not match coordinator",
            )
        decision = RecoveryEvaluator.evaluate(
            recovery_input,
            recovery_decision_id=_new_decision_id(),
        )
        try:
            stored = await self._recovery_repository.append(
                decision,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except RecoveryDecisionRepositoryError as exc:
            return RecoveryControlResult(
                status=_repository_error_status(exc),
                task_id=decision.task_id,
                action=decision.action,
                reason_code=decision.reason_code,
                reason=type(exc).__name__,
            )
        await _emit(
            event_sink,
            "recovery.evaluated",
            {
                "task_id": decision.task_id,
                "recovery_decision_id": stored.recovery_decision_id,
                "recovery_sequence": stored.recovery_sequence,
                "action": decision.action.value,
                "reason_code": decision.reason_code.value,
                "failure_signature_digest": decision.failure_signature_digest,
            },
        )

        gate_result = await self._recovery_gate.apply(stored.recovery_decision_id)
        result = _control_result(stored, gate_result)
        await _emit(
            event_sink,
            "recovery.applied",
            {
                "task_id": decision.task_id,
                "recovery_decision_id": stored.recovery_decision_id,
                "recovery_sequence": stored.recovery_sequence,
                "action": decision.action.value,
                "gate_status": gate_result.status.value,
                "cognitive_state": gate_result.cognitive_state.value
                if gate_result.cognitive_state is not None
                else None,
                "control_state_version": gate_result.control_state_version,
                "published_plan_revision_id": gate_result.published_plan_revision_id,
            },
        )

        if (
            decision.action is RecoveryAction.REPLAN
            and gate_result.status is RecoveryGateStatus.APPLIED
            and self._planning_coordinator is not None
            and workspace is not None
        ):
            await _emit(
                event_sink,
                "recovery.replan.started",
                {
                    "task_id": decision.task_id,
                    "recovery_decision_id": stored.recovery_decision_id,
                    "recovery_sequence": stored.recovery_sequence,
                },
            )
            planning_result = await self._planning_coordinator.plan(
                decision.task_id,
                workspace=workspace,
                query=query,
                target_files=target_files,
                target_symbols=target_symbols,
                changed_files=changed_files,
                runtime_id=runtime_id,
                event_sink=event_sink,
            )
            result = replace(
                result,
                planning_status=getattr(
                    getattr(planning_result, "status", None), "value", None
                ),
                planning_revision_id=(
                    getattr(planning_result, "plan_revision_id", None)
                    or getattr(
                        getattr(planning_result, "revision", None),
                        "plan_revision_id",
                        None,
                    )
                ),
            )
            try:
                final_snapshot = (
                    await self._recovery_repository.read_current_task_snapshot(
                        decision.task_id,
                        principal_id=self._principal_id,
                        project_id=self._project_id,
                    )
                )
            except RecoveryDecisionRepositoryError:
                final_snapshot = None
            if final_snapshot is not None:
                result = replace(
                    result,
                    task_status=final_snapshot.task_status,
                    cognitive_state=final_snapshot.cognitive_state.value,
                    control_state_version=final_snapshot.control_state_version,
                    published_plan_revision_id=(
                        final_snapshot.published_plan_revision_id
                    ),
                )
            else:
                result = replace(
                    result,
                    reason=(
                        "replan committed but the final durable task snapshot "
                        "could not be read"
                    ),
                )
            await _emit(
                event_sink,
                "recovery.replan.completed",
                {
                    "task_id": decision.task_id,
                    "recovery_decision_id": stored.recovery_decision_id,
                    "planning_status": result.planning_status,
                    "planning_revision_id": result.planning_revision_id,
                },
            )
        return result

    async def _build_input(
        self,
        task_id: str,
        *,
        failure_signature: NormalizedFailureSignature | None,
        no_progress_detected: bool,
        planning_status: PlanningRecoveryStatus,
    ) -> RecoveryInput:
        snapshot = await self._recovery_repository.read_current_task_snapshot(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if snapshot is None:
            raise RecoveryDecisionRepositoryError("task is unavailable")
        if self._goal_spec_repository is None:
            raise RecoveryDecisionRepositoryError("GoalSpec repository is unavailable")
        goal_spec = await self._goal_spec_repository.get_for_task(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if goal_spec is None:
            raise RecoveryDecisionRepositoryError("canonical GoalSpec is unavailable")

        latest_plan = None
        published_plan = None
        if self._plan_revision_repository is not None:
            latest_plan = await self._plan_revision_repository.get_latest_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            published_plan = await self._plan_revision_repository.get_published_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if (
                snapshot.published_plan_revision_id is not None
                and published_plan is None
            ):
                raise RecoveryDecisionRepositoryError(
                    "published plan projection is missing or malformed"
                )

        verification = None
        if self._verification_repository is not None:
            verification = await self._verification_repository.get_current_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )

        completion = None
        if self._completion_recovery is not None:
            completion = await self._completion_recovery.recover(task_id)

        history = await self._recovery_repository.summarize_for_task(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
            published_plan_revision_id=snapshot.published_plan_revision_id,
            failure_signature_digest=(
                failure_signature.failure_signature_digest
                if failure_signature is not None
                else None
            ),
        )
        return RecoveryInput(
            principal_id=self._principal_id,
            project_id=self._project_id,
            task_id=task_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=snapshot.cognitive_state,
            control_state_version=snapshot.control_state_version,
            task_status=snapshot.task_status,
            workspace_id=snapshot.workspace_id,
            repository_id=snapshot.repository_id,
            base_revision=snapshot.base_revision,
            published_plan_revision_id=(
                published_plan.plan_revision_id
                if published_plan is not None
                else snapshot.published_plan_revision_id
            ),
            published_plan_revision_digest=(
                published_plan.revision.plan_semantic_digest
                if published_plan is not None
                else None
            ),
            latest_plan_revision_id=(
                latest_plan.plan_revision_id if latest_plan is not None else None
            ),
            latest_plan_revision_sequence=(
                latest_plan.revision_sequence if latest_plan is not None else None
            ),
            verification_assessment_id=(
                verification.assessment_id if verification is not None else None
            ),
            verification_assessment_digest=(
                verification.assessment_digest if verification is not None else None
            ),
            verification_disposition=(
                verification.disposition if verification is not None else None
            ),
            verification_repository_generation=(
                verification.assessment.repository_generation
                if verification is not None
                else None
            ),
            verification_change_identity=(
                verification.assessment.change_identity
                if verification is not None
                else None
            ),
            completion_decision_id=(
                completion.latest_decision_id
                if completion is not None
                and completion.latest_decision_id is not None
                else None
            ),
            completion_decision_digest=(
                completion.latest_decision_digest
                if completion is not None
                and completion.latest_decision_id is not None
                else None
            ),
            completion_decision_sequence=(
                completion.latest_decision_sequence
                if completion is not None
                and completion.latest_decision_id is not None
                else None
            ),
            completion_outcome=(
                completion.decision_outcome
                if completion is not None
                and completion.latest_decision_id is not None
                else None
            ),
            completion_continuation_state=(
                completion.continuation_state
                if completion is not None
                and completion.latest_decision_id is not None
                else None
            ),
            failure_signature=failure_signature,
            no_progress_detected=no_progress_detected,
            identical_failure_streak=history.identical_failure_streak,
            recovery_attempt_count=history.recovery_attempt_count,
            replan_count=history.replan_count,
            total_recovery_count=history.total_recovery_count,
            planning_status=planning_status,
            policy=self._policy,
        )

    async def _decision_is_current(
        self,
        latest: StoredRecoveryDecision,
        snapshot: RecoveryTaskSnapshot,
    ) -> bool:
        source = latest.decision.input
        if (
            source.task_id != snapshot.task_id
            or source.principal_id != snapshot.principal_id
            or source.project_id != snapshot.project_id
            or source.cognitive_state is not snapshot.cognitive_state
            or source.control_state_version != snapshot.control_state_version
            or source.task_status != snapshot.task_status
            or source.workspace_id != snapshot.workspace_id
            or source.repository_id != snapshot.repository_id
            or source.base_revision != snapshot.base_revision
            or source.published_plan_revision_id
            != snapshot.published_plan_revision_id
        ):
            return False
        if self._goal_spec_repository is not None:
            goal_spec = await self._goal_spec_repository.get_for_task(
                snapshot.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if goal_spec is None or (
                source.goal_spec_id != goal_spec.goal_spec_id
                or source.goal_spec_digest != goal_spec.semantic_digest
            ):
                return False
        if self._plan_revision_repository is not None:
            latest_plan = await self._plan_revision_repository.get_latest_for_task(
                snapshot.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if latest_plan is None:
                if source.latest_plan_revision_id is not None:
                    return False
            elif (
                source.latest_plan_revision_id != latest_plan.plan_revision_id
                or source.latest_plan_revision_sequence != latest_plan.revision_sequence
            ):
                return False
            published_plan = await self._plan_revision_repository.get_published_for_task(
                snapshot.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            if published_plan is None:
                if source.published_plan_revision_id is not None:
                    return False
            elif (
                source.published_plan_revision_id != published_plan.plan_revision_id
                or source.published_plan_revision_digest
                != published_plan.revision.plan_semantic_digest
            ):
                return False
        if self._verification_repository is not None:
            current_verification = (
                await self._verification_repository.get_current_for_task(
                    snapshot.task_id,
                    principal_id=self._principal_id,
                    project_id=self._project_id,
                )
            )
            if current_verification is None:
                if any(
                    value is not None
                    for value in (
                        source.verification_assessment_id,
                        source.verification_assessment_digest,
                        source.verification_disposition,
                        source.verification_repository_generation,
                        source.verification_change_identity,
                    )
                ):
                    return False
            elif (
                source.verification_assessment_id
                != current_verification.assessment_id
                or source.verification_assessment_digest
                != current_verification.assessment_digest
                or source.verification_disposition
                != current_verification.disposition
                or source.verification_repository_generation
                != current_verification.assessment.repository_generation
                or source.verification_change_identity
                != current_verification.assessment.change_identity
            ):
                return False
        if self._completion_recovery is not None:
            current_completion = await self._completion_recovery.recover(
                snapshot.task_id
            )
            if current_completion is None:
                if any(
                    value is not None
                    for value in (
                        source.completion_decision_id,
                        source.completion_decision_digest,
                        source.completion_decision_sequence,
                        source.completion_outcome,
                        source.completion_continuation_state,
                    )
                ):
                    return False
            elif (
                source.completion_decision_id
                != current_completion.latest_decision_id
                or source.completion_decision_digest
                != current_completion.latest_decision_digest
                or source.completion_decision_sequence
                != current_completion.latest_decision_sequence
                or source.completion_outcome
                != current_completion.decision_outcome
                or source.completion_continuation_state
                != current_completion.continuation_state
            ):
                return False
        return True

    async def _safe_snapshot(self, task_id: str) -> RecoveryTaskSnapshot | None:
        try:
            return await self._recovery_repository.read_current_task_snapshot(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except Exception:  # noqa: BLE001 - already on fail-closed path
            return None


def _fact(
    snapshot: RecoveryTaskSnapshot,
    continuation: RecoveryControlContinuation,
    *,
    latest: StoredRecoveryDecision | None = None,
    reason: str = "",
) -> RecoveryControlFact:
    decision = latest.decision if latest is not None else None
    return RecoveryControlFact(
        task_id=snapshot.task_id,
        continuation=continuation,
        task_status=snapshot.task_status,
        cognitive_state=snapshot.cognitive_state.value,
        control_state_version=snapshot.control_state_version,
        latest_decision_id=(latest.recovery_decision_id if latest is not None else None),
        latest_decision_digest=(latest.decision_digest if latest is not None else None),
        latest_recovery_sequence=(
            latest.recovery_sequence if latest is not None else None
        ),
        action=decision.action if decision is not None else None,
        reason_code=decision.reason_code if decision is not None else None,
        published_plan_revision_id=snapshot.published_plan_revision_id,
        latest_plan_revision_id=(
            decision.input.latest_plan_revision_id if decision is not None else None
        ),
        replan_count=(decision.input.replan_count if decision is not None else 0),
        failure_signature_digest=(
            decision.failure_signature_digest if decision is not None else None
        ),
        reason=reason,
    )


def _control_result(
    stored: StoredRecoveryDecision,
    gate_result: RecoveryGateResult,
) -> RecoveryControlResult:
    status = {
        RecoveryGateStatus.APPLIED: RecoveryControlStatus.APPLIED,
        RecoveryGateStatus.ALREADY_APPLIED: RecoveryControlStatus.APPLIED,
        RecoveryGateStatus.NO_ACTION: RecoveryControlStatus.NO_ACTION,
        RecoveryGateStatus.BLOCKED: RecoveryControlStatus.BLOCKED,
        RecoveryGateStatus.STALE: RecoveryControlStatus.STALE,
        RecoveryGateStatus.TERMINAL: RecoveryControlStatus.TERMINAL,
        RecoveryGateStatus.NOT_FOUND: RecoveryControlStatus.NOT_FOUND,
        RecoveryGateStatus.INVALID: RecoveryControlStatus.INVALID,
        RecoveryGateStatus.INTEGRITY_ERROR: RecoveryControlStatus.INTEGRITY_ERROR,
        RecoveryGateStatus.CONFLICT: RecoveryControlStatus.STALE,
        RecoveryGateStatus.ERROR: RecoveryControlStatus.ERROR,
    }.get(gate_result.status, RecoveryControlStatus.ERROR)
    return RecoveryControlResult(
        status=status,
        recovery_decision_id=stored.recovery_decision_id,
        recovery_sequence=stored.recovery_sequence,
        task_id=stored.task_id,
        action=stored.action,
        reason_code=stored.reason_code,
        gate_status=gate_result.status,
        task_status=gate_result.task_status,
        cognitive_state=(
            gate_result.cognitive_state.value
            if gate_result.cognitive_state is not None
            else None
        ),
        control_state_version=gate_result.control_state_version,
        published_plan_revision_id=gate_result.published_plan_revision_id,
        reason=gate_result.reason,
    )


def _repository_error_status(exc: RecoveryDecisionRepositoryError) -> RecoveryControlStatus:
    name = type(exc).__name__
    if name.endswith("StaleError"):
        return RecoveryControlStatus.STALE
    if name.endswith("BindingError"):
        return RecoveryControlStatus.INVALID
    if name.endswith("IntegrityError"):
        return RecoveryControlStatus.INTEGRITY_ERROR
    return RecoveryControlStatus.ERROR


def _diagnosis_transition_status(
    status: CognitiveTransitionStatus,
) -> RecoveryControlStatus:
    """Map a diagnosis CAS result without collapsing stale state into error."""
    if status is CognitiveTransitionStatus.NOT_FOUND:
        return RecoveryControlStatus.NOT_FOUND
    if status is CognitiveTransitionStatus.OWNER_MISMATCH:
        # Owner probing is intentionally indistinguishable from absence.
        return RecoveryControlStatus.NOT_FOUND
    if status in {
        CognitiveTransitionStatus.STALE_VERSION,
        CognitiveTransitionStatus.STALE_STATE,
        CognitiveTransitionStatus.STALE_TASK_STATUS,
        CognitiveTransitionStatus.STALE_WORKSPACE_BINDING,
    }:
        return RecoveryControlStatus.STALE
    if status is CognitiveTransitionStatus.TERMINAL_TASK:
        return RecoveryControlStatus.TERMINAL
    if status is CognitiveTransitionStatus.ILLEGAL_TRANSITION:
        return RecoveryControlStatus.INVALID
    return RecoveryControlStatus.ERROR


async def _emit(
    event_sink: RecoveryEventSink | None,
    event_type: str,
    payload: dict[str, object],
) -> None:
    if event_sink is None:
        return
    try:
        await event_sink.emit(event_type, payload)
    except Exception:
        logger.warning("recovery event emission failed: %s", event_type, exc_info=True)


def _new_decision_id() -> str:
    """Generate a server-owned recovery identity."""
    return f"recovery-{uuid.uuid4().hex}"


def _validate_task_id(task_id: str) -> None:
    if type(task_id) is not str or not task_id:
        raise ValueError("task_id must be a non-empty string")


__all__ = [
    "RecoveryControlContinuation",
    "RecoveryControlCoordinator",
    "RecoveryControlFact",
    "RecoveryControlResult",
    "RecoveryControlStatus",
    "RecoveryEventSink",
]
