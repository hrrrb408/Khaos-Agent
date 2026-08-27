"""M7.3 planning-control orchestration.

This module coordinates fresh context capture, the existing deterministic
planner, immutable plan-revision persistence, and cognitive-state CAS.  It is
not a planner, execution scheduler, recovery engine, or task-lifecycle owner.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any, Protocol

from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import GoalSpecRepository
from khaos.agent.control.state import AgentCognitiveState
from khaos.agent.control.state_repository import (
    AgentControlStateRepository,
    CognitiveTransitionResult,
    CognitiveTransitionStatus,
    CognitiveWorkspaceBinding,
)
from khaos.coding.intelligence.context import (
    ContextBundle,
    ContextQueryReason,
    ContextRequest,
)
from khaos.coding.planning.repository import (
    PlanningTaskSnapshot,
    PlanRevisionBindingError,
    PlanRevisionConflictError,
    PlanRevisionIntegrityError,
    PlanRevisionRepository,
    PlanRevisionStaleError,
)
from khaos.coding.planning.revision import (
    PLANNER_ALGORITHM_VERSION,
    PLANNING_SCHEMA_VERSION,
    PlanDisposition,
    PlanningInput,
    PlanRevision,
)
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.workspace.models import TaskWorkspace

logger = logging.getLogger(__name__)


class PlanningControlStatus(str, Enum):
    """Typed result of one planning-control attempt."""

    READY = "ready"
    BLOCKED = "blocked"
    STALE = "stale"
    INVALID = "invalid"
    IMPLEMENTING = "implementing"
    NOT_FOUND = "not_found"
    NOT_READY = "not_ready"
    TERMINAL = "terminal"
    CONFLICT = "conflict"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class PlanningControlResult:
    """Bounded result of planning and optional cognitive publication."""

    status: PlanningControlStatus
    task_id: str
    revision: PlanRevision | None = None
    revision_sequence: int | None = None
    cognitive_transition: CognitiveTransitionResult | None = None
    reason: str = ""

    @property
    def disposition(self) -> PlanDisposition | None:
        """Return the passive plan disposition, if a revision was recorded."""
        return self.revision.disposition if self.revision is not None else None


class PlanningEventSink(Protocol):
    """Minimal event port used to publish bounded planning lifecycle facts."""

    async def emit(self, event_type: str, payload: dict[str, object]) -> Any:
        """Append one bounded event to the current turn/event ledger."""
        ...


class PlanningContextProvider(Protocol):
    """M7.2 context retrieval port used by the coordinator."""

    def repository_id_for_workspace(self, workspace: TaskWorkspace) -> str:
        """Return the stable repository identity for a workspace."""
        ...

    async def retrieve(self, request: ContextRequest, goal_spec: GoalSpec) -> ContextBundle:
        """Capture one workspace-bound context bundle."""
        ...


class PlanningControlCoordinator:
    """Coordinate one owner-scoped deterministic planning attempt.

    The coordinator never fabricates cognitive history.  It can legally move
    an already initialized active task into ``PLANNING``, persist the plan,
    and publish ``IMPLEMENTING`` only for a current ``READY`` revision.  It
    never changes ``TaskStatus`` and never invokes a model or a tool.
    """

    def __init__(
        self,
        *,
        planning_service: DeterministicPlanningService,
        context_intelligence: PlanningContextProvider,
        goal_spec_repository: GoalSpecRepository,
        plan_revision_repository: PlanRevisionRepository,
        control_state_repository: AgentControlStateRepository,
        principal_id: str,
        project_id: str,
    ) -> None:
        if not principal_id:
            raise ValueError("principal_id is required")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        self._planning_service = planning_service
        self._context_intelligence = context_intelligence
        self._goal_spec_repository = goal_spec_repository
        self._plan_revision_repository = plan_revision_repository
        self._control_state_repository = control_state_repository
        self._principal_id = principal_id
        self._project_id = project_id

    @property
    def principal_id(self) -> str:
        """Return the owner bound to this coordinator."""
        return self._principal_id

    @property
    def project_id(self) -> str:
        """Return the project bound to this coordinator."""
        return self._project_id

    async def plan(
        self,
        task_id: str,
        *,
        workspace: TaskWorkspace,
        query: str = "",
        target_files: tuple[str, ...] = (),
        target_symbols: tuple[str, ...] = (),
        changed_files: tuple[str, ...] = (),
        runtime_id: str = "",
        event_sink: PlanningEventSink | None = None,
    ) -> PlanningControlResult:
        """Capture context, append a revision, and publish READY cognitively.

        A stale or blocked result is durable planning history only.  It does
        not become ``TaskStatus.BLOCKED`` and does not invoke replanning.
        """
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be a non-empty string")
        snapshot = await self._plan_revision_repository.get_current_task_snapshot(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if snapshot is None:
            return PlanningControlResult(
                PlanningControlStatus.NOT_FOUND,
                task_id,
                reason="task is unavailable in the supplied owner scope",
            )
        if snapshot.task_status in {"completed", "failed", "cancelled"}:
            return PlanningControlResult(
                PlanningControlStatus.TERMINAL,
                task_id,
                reason="terminal task cannot enter planning",
            )
        workspace_id = snapshot.workspace_id
        repository_id = snapshot.repository_id
        if workspace_id != getattr(workspace, "id", None):
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                reason="planning workspace does not match the durable task binding",
            )
        if workspace_id is None or repository_id is None:
            return PlanningControlResult(
                PlanningControlStatus.NOT_READY,
                task_id,
                reason="planning requires durable workspace and repository identity",
            )
        try:
            workspace_repository_id = (
                self._context_intelligence.repository_id_for_workspace(workspace)
            )
        except (AttributeError, KeyError, TypeError, ValueError, RuntimeError):
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                reason="workspace repository identity is unavailable",
            )
        if workspace_repository_id != repository_id:
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                reason="workspace repository identity does not match the task",
            )
        try:
            initial_head = await self._plan_revision_repository.get_latest_for_task(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except PlanRevisionIntegrityError:
            return PlanningControlResult(
                PlanningControlStatus.INVALID,
                task_id,
                reason="durable planning history is malformed",
            )
        expected_parent_revision_id = (
            initial_head.plan_revision_id if initial_head is not None else None
        )
        await _emit(
            event_sink,
            "planning.started",
            {
                "task_id": task_id,
                "principal_id": self._principal_id,
                "project_id": self._project_id,
            },
        )

        transition = await self._enter_planning(snapshot)
        if transition.status not in {
            CognitiveTransitionStatus.UPDATED,
            CognitiveTransitionStatus.UNCHANGED,
        }:
            return PlanningControlResult(
                _transition_result_status(transition.status),
                task_id,
                cognitive_transition=transition,
                reason="task could not enter the planning cognitive state",
            )

        # The CAS may have won a race after the first read.  Read the physical
        # snapshot again before binding the ContextRequest and PlanRevision.
        snapshot = await self._plan_revision_repository.get_current_task_snapshot(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if snapshot is None:
            return PlanningControlResult(
                PlanningControlStatus.NOT_FOUND,
                task_id,
                cognitive_transition=transition,
                reason="task disappeared after planning-state CAS",
            )
        if snapshot.workspace_id != getattr(workspace, "id", None):
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                cognitive_transition=transition,
                reason="workspace changed after planning-state CAS",
            )
        workspace_id = snapshot.workspace_id
        repository_id = snapshot.repository_id
        if workspace_id is None or repository_id is None:
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                cognitive_transition=transition,
                reason="workspace/repository binding disappeared after planning-state CAS",
            )
        goal_spec = await self._goal_spec_repository.get_for_task(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if goal_spec is None:
            return PlanningControlResult(
                PlanningControlStatus.INVALID,
                task_id,
                cognitive_transition=transition,
                reason="canonical GoalSpec is unavailable",
            )
        if not target_files and not target_symbols:
            target_files, target_symbols = self._planning_service.explicit_target_hints(
                goal_spec.raw_goal
            )
        try:
            request = ContextRequest(
                task_id=task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                goal_spec_id=goal_spec.goal_spec_id,
                goal_spec_digest=goal_spec.semantic_digest,
                workspace_id=workspace_id,
                repository_id=repository_id,
                query=query or goal_spec.normalized_goal,
                base_revision=snapshot.base_revision,
                reason=(
                    ContextQueryReason.EXPLICIT_TARGET
                    if target_files or target_symbols
                    else ContextQueryReason.USER_GOAL
                ),
                target_files=target_files,
                target_symbols=target_symbols,
                changed_files=changed_files,
                runtime_id=runtime_id,
            )
            context_bundle = await self._context_intelligence.retrieve(
                request, goal_spec
            )
        except Exception as exc:  # noqa: BLE001 - context is fail-closed
            logger.warning("planning context unavailable: %s", type(exc).__name__)
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                cognitive_transition=transition,
                reason="workspace-bound planning context is unavailable",
            )

        planning_input = _planning_input(
            goal_spec=goal_spec,
            snapshot=snapshot,
            context_bundle=context_bundle,
            target_files=target_files,
            target_symbols=target_symbols,
        )
        try:
            revision = self._planning_service.plan_from_context(
                goal_spec=goal_spec,
                planning_input=planning_input,
                context_bundle=context_bundle,
            )
            # The parent is captured before context/planning work starts.  A
            # competing planner that publishes first must make this attempt
            # stale instead of silently appending a second sibling revision.
            revision = replace(
                revision,
                parent_revision_id=expected_parent_revision_id,
            )
            stored = await self._plan_revision_repository.append(
                revision,
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
        except (PlanRevisionBindingError, PlanRevisionStaleError) as exc:
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                cognitive_transition=transition,
                reason=type(exc).__name__,
            )
        except PlanRevisionIntegrityError as exc:
            return PlanningControlResult(
                PlanningControlStatus.INVALID,
                task_id,
                cognitive_transition=transition,
                reason=type(exc).__name__,
            )
        except PlanRevisionConflictError as exc:
            return PlanningControlResult(
                PlanningControlStatus.CONFLICT,
                task_id,
                cognitive_transition=transition,
                reason=type(exc).__name__,
            )
        except (TypeError, ValueError) as exc:
            return PlanningControlResult(
                PlanningControlStatus.INVALID,
                task_id,
                cognitive_transition=transition,
                reason=type(exc).__name__,
            )

        await _emit(
            event_sink,
            "planning.revision.created",
            {
                "task_id": task_id,
                "plan_revision_id": stored.plan_revision_id,
                "revision_sequence": stored.revision_sequence,
                "plan_semantic_digest": stored.revision.plan_semantic_digest,
                "disposition": stored.revision.disposition.value,
            },
        )

        if stored.revision.disposition is not PlanDisposition.READY:
            return PlanningControlResult(
                _disposition_status(stored.revision.disposition),
                task_id,
                revision=stored.revision,
                revision_sequence=stored.revision_sequence,
                cognitive_transition=transition,
                reason=stored.revision.summary,
            )

        publish = await self._control_state_repository.compare_and_transition(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
            expected_state=snapshot.cognitive_state,
            expected_version=snapshot.control_state_version,
            target_state=AgentCognitiveState.IMPLEMENTING,
            expected_task_status=snapshot.task_status,
            expected_workspace_binding=_workspace_binding(snapshot),
        )
        if publish.status not in {
            CognitiveTransitionStatus.UPDATED,
            CognitiveTransitionStatus.UNCHANGED,
        }:
            return PlanningControlResult(
                PlanningControlStatus.STALE,
                task_id,
                revision=stored.revision,
                revision_sequence=stored.revision_sequence,
                cognitive_transition=publish,
                reason="READY plan was not published because the task snapshot changed",
            )
        return PlanningControlResult(
            PlanningControlStatus.IMPLEMENTING,
            task_id,
            revision=stored.revision,
            revision_sequence=stored.revision_sequence,
            cognitive_transition=publish,
            reason="READY plan published as the next cognitive phase",
        )

    async def _enter_planning(
        self, snapshot: PlanningTaskSnapshot
    ) -> CognitiveTransitionResult:
        """CAS the current initialized cognitive phase into PLANNING."""
        if snapshot.cognitive_state is AgentCognitiveState.PLANNING:
            return await self._control_state_repository.compare_and_transition(
                snapshot.task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                expected_state=AgentCognitiveState.PLANNING,
                expected_version=snapshot.control_state_version,
                target_state=AgentCognitiveState.PLANNING,
                expected_task_status=snapshot.task_status,
                expected_workspace_binding=_workspace_binding(snapshot),
            )
        return await self._control_state_repository.compare_and_transition(
            snapshot.task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
            expected_state=snapshot.cognitive_state,
            expected_version=snapshot.control_state_version,
            target_state=AgentCognitiveState.PLANNING,
            expected_task_status=snapshot.task_status,
            expected_workspace_binding=_workspace_binding(snapshot),
        )


def _workspace_binding(snapshot: PlanningTaskSnapshot) -> CognitiveWorkspaceBinding:
    """Convert a task snapshot into a non-authoritative CAS identity fence."""
    return CognitiveWorkspaceBinding(
        workspace_id=snapshot.workspace_id,
        base_revision=snapshot.base_revision,
        repository_id=snapshot.repository_id,
    )


def _planning_input(
    *,
    goal_spec: GoalSpec,
    snapshot: PlanningTaskSnapshot,
    context_bundle: ContextBundle,
    target_files: tuple[str, ...],
    target_symbols: tuple[str, ...],
) -> PlanningInput:
    """Create the exact planner input from the current durable/context facts."""
    return PlanningInput(
        schema_version=PLANNING_SCHEMA_VERSION,
        task_id=snapshot.task_id,
        principal_id=snapshot.principal_id,
        project_id=snapshot.project_id,
        goal_spec_id=goal_spec.goal_spec_id,
        goal_spec_digest=goal_spec.semantic_digest,
        workspace_id=context_bundle.workspace_id,
        repository_id=context_bundle.repository_id,
        base_revision=context_bundle.base_revision,
        context_bundle_id=context_bundle.bundle_id,
        context_bundle_digest=context_bundle.bundle_digest,
        context_request_digest=context_bundle.request_digest,
        repository_generation=context_bundle.repository_generation,
        index_generation=context_bundle.index_generation,
        context_freshness=context_bundle.freshness,
        cognitive_state=snapshot.cognitive_state,
        control_state_version=snapshot.control_state_version,
        task_status=snapshot.task_status,
        planner_schema_version=PLANNING_SCHEMA_VERSION,
        planner_algorithm_version=PLANNER_ALGORITHM_VERSION,
        target_files=target_files,
        target_symbols=target_symbols,
        context_truncated=context_bundle.truncated,
        truncation_reasons=context_bundle.truncation_reasons,
    )


async def _emit(
    event_sink: PlanningEventSink | None,
    event_type: str,
    payload: dict[str, object],
) -> None:
    if event_sink is not None:
        await event_sink.emit(event_type, payload)


def _transition_result_status(status: CognitiveTransitionStatus) -> PlanningControlStatus:
    if status is CognitiveTransitionStatus.NOT_FOUND:
        return PlanningControlStatus.NOT_FOUND
    if status in {
        CognitiveTransitionStatus.STALE_STATE,
        CognitiveTransitionStatus.STALE_VERSION,
        CognitiveTransitionStatus.STALE_TASK_STATUS,
        CognitiveTransitionStatus.STALE_WORKSPACE_BINDING,
        CognitiveTransitionStatus.TERMINAL_TASK,
    }:
        return PlanningControlStatus.STALE
    if status is CognitiveTransitionStatus.ILLEGAL_TRANSITION:
        return PlanningControlStatus.NOT_READY
    return PlanningControlStatus.ERROR


def _disposition_status(disposition: PlanDisposition) -> PlanningControlStatus:
    return {
        PlanDisposition.READY: PlanningControlStatus.READY,
        PlanDisposition.BLOCKED: PlanningControlStatus.BLOCKED,
        PlanDisposition.STALE: PlanningControlStatus.STALE,
        PlanDisposition.INVALID: PlanningControlStatus.INVALID,
    }[disposition]


__all__ = [
    "PlanningContextProvider",
    "PlanningControlCoordinator",
    "PlanningControlResult",
    "PlanningControlStatus",
    "PlanningEventSink",
]
