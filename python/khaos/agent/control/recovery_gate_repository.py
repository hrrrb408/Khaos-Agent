"""Atomic application of one durable M7.5 recovery decision.

The recovery decision ledger is passive history.  This module owns the much
narrower control-state projection that may apply a recovery decision to the
current task.  It never writes ``TaskStatus`` and it never grants execution,
approval, workspace, verification, or completion authority.

All source-snapshot checks and the cognitive-state/publication update execute
under the database's shared writer transaction.  The ledger-head check is
therefore a cross-runtime fence rather than an in-memory coordination hint.
"""

from __future__ import annotations

import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from khaos.agent.control.recovery import RecoveryAction, RecoveryDecision
from khaos.agent.control.recovery_repository import (
    RecoveryDecisionBindingError,
    RecoveryDecisionIntegrityError,
    RecoveryDecisionRepositoryError,
    RecoveryDecisionStaleError,
    RecoveryTaskSnapshot,
    _decode_plan,
    _decode_row,
    _decode_task_snapshot,
    _load_goal_spec,
    _select_plan,
    _select_task,
    _validate_completion_binding,
    _validate_decision_binding,
    _validate_plan_bindings,
    _validate_verification_binding,
)
from khaos.agent.control.state import (
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.coding.planning.revision import PlanDisposition


class RecoveryGateDatabase(Protocol):
    """Minimal shared database port required by the recovery gate."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the database's single-writer transaction."""
        ...


class RecoveryProjectionStatus(str, Enum):
    """Typed result of one atomic recovery-control application attempt."""

    APPLIED = "applied"
    ALREADY_APPLIED = "already_applied"
    NO_ACTION = "no_action"
    BLOCKED = "blocked"
    STALE = "stale"
    TERMINAL = "terminal"
    NOT_FOUND = "not_found"
    REJECTED = "rejected"
    INVALID = "invalid"
    INTEGRITY_ERROR = "integrity_error"
    CONFLICT = "conflict"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class RecoveryProjectionResult:
    """Bounded result of one recovery decision application attempt."""

    status: RecoveryProjectionStatus
    recovery_decision_id: str
    recovery_sequence: int | None = None
    task_id: str | None = None
    action: RecoveryAction | None = None
    cognitive_state: AgentCognitiveState | None = None
    control_state_version: int | None = None
    task_status: str | None = None
    published_plan_revision_id: str | None = None
    reason: str = ""


# The public RecoveryGate obtains this identity from this module.  A raw
# repository caller cannot turn a constructible RecoveryDecision into a
# control-state mutation by passing a boolean or a model-provided claim.
_RECOVERY_GATE_TOKEN = object()

_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})
_RECOVERY_ELIGIBLE_TASK_STATUSES = frozenset(
    {"pending", "running", "waiting_test", "fixing"}
)


class RecoveryGateRepository:
    """Own the atomic, owner-scoped cognitive recovery projection."""

    def __init__(self, database: RecoveryGateDatabase) -> None:
        self._database = database

    @property
    def database(self) -> RecoveryGateDatabase:
        """Return the shared database owner used by this repository."""
        return self._database

    async def apply_decision(
        self,
        recovery_decision_id: str,
        *,
        principal_id: str,
        project_id: str,
        gate_token: object,
    ) -> RecoveryProjectionResult:
        """Atomically apply one current recovery decision.

        ``REPLAN`` retires the exact currently published plan by clearing the
        physical publication projection and moving the cognitive phase to
        ``REPLANNING``.  ``RECOVER_CURRENT_PLAN`` preserves that publication
        identity and moves a legally recoverable phase to ``RECOVERING``.
        ``BLOCK`` and ``NO_ACTION`` remain passive results.  No branch writes
        ``coding_tasks.status``.
        """
        _validate_scope(
            recovery_decision_id=recovery_decision_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if gate_token is not _RECOVERY_GATE_TOKEN:
            raise PermissionError("recovery projection is owned by RecoveryGate")

        try:
            async with self._database.transaction() as conn:
                decision_row = await _select_decision(
                    conn,
                    recovery_decision_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if decision_row is None:
                    return _result(
                        RecoveryProjectionStatus.NOT_FOUND,
                        recovery_decision_id,
                        reason="recovery decision is unavailable in the supplied owner scope",
                    )
                try:
                    stored = _decode_row(
                        decision_row,
                        expected_decision_id=recovery_decision_id,
                        expected_principal_id=principal_id,
                        expected_project_id=project_id,
                    )
                except RecoveryDecisionIntegrityError as exc:
                    return _result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        reason=type(exc).__name__,
                    )
                if stored is None:
                    return _result(
                        RecoveryProjectionStatus.NOT_FOUND,
                        recovery_decision_id,
                        reason="recovery decision is unavailable in the supplied owner scope",
                    )
                decision = stored.decision

                head_row = await _select_recovery_head(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if head_row is None:
                    return _result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason="recovery decision has no durable history head",
                    )
                try:
                    head = _decode_row(
                        head_row,
                        expected_principal_id=principal_id,
                        expected_project_id=project_id,
                        expected_task_id=decision.task_id,
                    )
                except RecoveryDecisionIntegrityError as exc:
                    return _result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason=type(exc).__name__,
                    )
                if head is None:
                    return _result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason="recovery history head disappeared during application",
                    )
                if (
                    head.recovery_decision_id != stored.recovery_decision_id
                    or head.recovery_sequence != stored.recovery_sequence
                    or head.decision_digest != stored.decision_digest
                ):
                    return _result(
                        RecoveryProjectionStatus.STALE,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason="recovery decision is no longer the durable history head",
                    )

                task_row = await _select_task(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_row is None:
                    return _result(
                        RecoveryProjectionStatus.NOT_FOUND,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason="task is unavailable in the supplied owner scope",
                    )
                try:
                    task_snapshot = _decode_task_snapshot(task_row)
                except RecoveryDecisionBindingError as exc:
                    return _result(
                        RecoveryProjectionStatus.NOT_FOUND,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionIntegrityError as exc:
                    return _result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        recovery_sequence=stored.recovery_sequence,
                        task_id=decision.task_id,
                        action=decision.action,
                        reason=type(exc).__name__,
                    )
                if task_snapshot.task_status in _TERMINAL_TASK_STATUSES:
                    return _task_result(
                        RecoveryProjectionStatus.TERMINAL,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="terminal task cannot be recovered",
                    )
                if task_snapshot.last_applied_recovery_decision_id == decision.recovery_decision_id:
                    return _task_result(
                        RecoveryProjectionStatus.ALREADY_APPLIED,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="recovery decision was already applied",
                    )

                try:
                    goal_spec = await _load_goal_spec(
                        conn,
                        task_id=decision.task_id,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    _validate_decision_binding(
                        decision,
                        task_snapshot=task_snapshot,
                        goal_spec=goal_spec,
                    )
                    await _validate_plan_bindings(
                        conn,
                        decision.input,
                        task_snapshot=task_snapshot,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    await _validate_verification_binding(
                        conn,
                        decision.input,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    await _validate_completion_binding(
                        conn,
                        decision.input,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    await _validate_source_history(
                        conn,
                        decision=decision,
                        recovery_sequence=stored.recovery_sequence,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                except RecoveryDecisionStaleError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.STALE,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionBindingError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.REJECTED,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionIntegrityError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionRepositoryError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.ERROR,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )

                if decision.action is RecoveryAction.NO_ACTION:
                    return _task_result(
                        RecoveryProjectionStatus.NO_ACTION,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="recovery policy requested no action",
                    )
                if decision.action is RecoveryAction.BLOCK:
                    return _task_result(
                        RecoveryProjectionStatus.BLOCKED,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="recovery policy requires an external/blocking review",
                    )
                if task_snapshot.task_status not in _RECOVERY_ELIGIBLE_TASK_STATUSES:
                    return _task_result(
                        RecoveryProjectionStatus.BLOCKED,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="task lifecycle is not eligible for recovery application",
                    )
                if task_snapshot.published_plan_revision_id is None:
                    return _task_result(
                        RecoveryProjectionStatus.INVALID,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="recovery action requires a published implementation plan",
                    )
                try:
                    published_plan_row = await _select_plan(
                        conn,
                        plan_revision_id=task_snapshot.published_plan_revision_id,
                        task_id=decision.task_id,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    published_plan = _decode_plan(published_plan_row)
                except RecoveryDecisionBindingError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.INVALID,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionIntegrityError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.INTEGRITY_ERROR,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                except RecoveryDecisionRepositoryError as exc:
                    return _task_result(
                        RecoveryProjectionStatus.ERROR,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason=type(exc).__name__,
                    )
                if published_plan.disposition is not PlanDisposition.READY:
                    return _task_result(
                        RecoveryProjectionStatus.INVALID,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="published implementation plan is not READY",
                    )

                target_state, target_plan_id = _target_projection(
                    decision.action,
                    task_snapshot=task_snapshot,
                )
                transition_validation = AgentCognitiveStateMachine.validate_transition(
                    task_snapshot.cognitive_state,
                    target_state,
                )
                if transition_validation is not CognitiveTransitionValidation.ALLOWED:
                    if transition_validation is not CognitiveTransitionValidation.UNCHANGED:
                        return _task_result(
                            RecoveryProjectionStatus.INVALID,
                            recovery_decision_id,
                            stored.recovery_sequence,
                            decision,
                            task_snapshot,
                            reason="recovery action is not a legal cognitive transition",
                        )

                    # Recovery under the current plan may be requested again
                    # while the task is already RECOVERING.  This is an
                    # idempotent control acknowledgement, not a cognitive
                    # transition: preserve M7.1.3's no-version-increment
                    # self-transition invariant while recording the decision
                    # that was applied.
                    cursor = await conn.execute(
                        """
                        UPDATE coding_tasks
                        SET last_applied_recovery_decision_id = ?
                        WHERE id = ?
                          AND principal_id = ?
                          AND project_id = ?
                          AND status = ?
                          AND cognitive_state = ?
                          AND control_state_version = ?
                          AND published_plan_revision_id = ?
                          AND (
                              last_applied_recovery_decision_id IS NULL
                              OR last_applied_recovery_decision_id <> ?
                          )
                        """,
                        (
                            decision.recovery_decision_id,
                            decision.task_id,
                            principal_id,
                            project_id,
                            task_snapshot.task_status,
                            task_snapshot.cognitive_state.value,
                            task_snapshot.control_state_version,
                            task_snapshot.published_plan_revision_id,
                            decision.recovery_decision_id,
                        ),
                    )
                    if int(cursor.rowcount or 0) != 1:
                        return _task_result(
                            RecoveryProjectionStatus.CONFLICT,
                            recovery_decision_id,
                            stored.recovery_sequence,
                            decision,
                            task_snapshot,
                            reason="recovery self-transition acknowledgement conflicted",
                        )
                    updated_row = await _select_task(
                        conn,
                        task_id=decision.task_id,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    updated = _decode_task_snapshot(updated_row)
                    if (
                        updated.cognitive_state is not target_state
                        or updated.control_state_version
                        != task_snapshot.control_state_version
                        or updated.published_plan_revision_id != target_plan_id
                        or updated.last_applied_recovery_decision_id
                        != decision.recovery_decision_id
                        or updated.task_status != task_snapshot.task_status
                    ):
                        raise RecoveryDecisionIntegrityError(
                            "recovery self-transition acknowledgement disagrees with task row"
                        )
                    return _task_result(
                        RecoveryProjectionStatus.APPLIED,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        updated,
                        reason="recovery decision acknowledged without a cognitive transition",
                    )

                cursor = await conn.execute(
                    """
                    UPDATE coding_tasks
                    SET cognitive_state = ?,
                        control_state_version = control_state_version + 1,
                        published_plan_revision_id = ?,
                        last_applied_recovery_decision_id = ?
                    WHERE id = ?
                      AND principal_id = ?
                      AND project_id = ?
                      AND status = ?
                      AND cognitive_state = ?
                      AND control_state_version = ?
                      AND published_plan_revision_id = ?
                      AND (
                          last_applied_recovery_decision_id IS NULL
                          OR last_applied_recovery_decision_id <> ?
                      )
                    """,
                    (
                        target_state.value,
                        target_plan_id,
                        decision.recovery_decision_id,
                        decision.task_id,
                        principal_id,
                        project_id,
                        task_snapshot.task_status,
                        task_snapshot.cognitive_state.value,
                        task_snapshot.control_state_version,
                        task_snapshot.published_plan_revision_id,
                        decision.recovery_decision_id,
                    ),
                )
                if int(cursor.rowcount or 0) != 1:
                    return _task_result(
                        RecoveryProjectionStatus.CONFLICT,
                        recovery_decision_id,
                        stored.recovery_sequence,
                        decision,
                        task_snapshot,
                        reason="recovery cognitive CAS did not update exactly one row",
                    )

                updated_row = await _select_task(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                updated = _decode_task_snapshot(updated_row)
                if (
                    updated.cognitive_state is not target_state
                    or updated.control_state_version
                    != task_snapshot.control_state_version + 1
                    or updated.published_plan_revision_id != target_plan_id
                    or updated.last_applied_recovery_decision_id
                    != decision.recovery_decision_id
                    or updated.task_status != task_snapshot.task_status
                ):
                    raise RecoveryDecisionIntegrityError(
                        "recovery projection disagrees with the committed task row"
                    )
                return _task_result(
                    RecoveryProjectionStatus.APPLIED,
                    recovery_decision_id,
                    stored.recovery_sequence,
                    decision,
                    updated,
                    reason="recovery decision atomically applied",
                )
        except sqlite3.Error as exc:
            return _result(
                RecoveryProjectionStatus.ERROR,
                recovery_decision_id,
                reason=type(exc).__name__,
            )
        except RecoveryDecisionIntegrityError as exc:
            return _result(
                RecoveryProjectionStatus.INTEGRITY_ERROR,
                recovery_decision_id,
                reason=type(exc).__name__,
            )


async def _select_decision(
    conn: Any,
    recovery_decision_id: str,
    *,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_recovery_decisions
        WHERE recovery_decision_id = ?
          AND principal_id = ?
          AND project_id = ?
        """,
        (recovery_decision_id, principal_id, project_id),
    )
    return await cursor.fetchone()


async def _select_recovery_head(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        ORDER BY recovery_sequence DESC
        LIMIT 1
        """,
        (task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


async def _validate_source_history(
    conn: Any,
    *,
    decision: RecoveryDecision,
    recovery_sequence: int,
    principal_id: str,
    project_id: str,
) -> None:
    """Validate source counters without materializing the history ledger.

    The recovery ledger is append-only and can outlive one process.  Gate
    application must therefore validate the sequence/counter fence inside the
    writer transaction, but it must not turn a long-lived task history into an
    unbounded memory read.  SQL aggregates preserve the same checks while the
    exact failure suffix is computed from the sequence boundary.
    """
    cursor = await conn.execute(
        """
        SELECT COUNT(*) AS total_count,
               COALESCE(MIN(recovery_sequence), 0) AS first_sequence,
               COALESCE(MAX(recovery_sequence), 0) AS last_sequence,
               COALESCE(SUM(
                   action = ? AND published_plan_revision_id IS ?
               ), 0) AS recovery_attempt_count,
               COALESCE(SUM(action = ?), 0) AS replan_count,
               COALESCE(SUM(
                   action IS NULL OR action NOT IN (?, ?, ?, ?)
               ), 0) AS invalid_action_count
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        """,
        (
            RecoveryAction.RECOVER_CURRENT_PLAN.value,
            decision.input.published_plan_revision_id,
            RecoveryAction.REPLAN.value,
            RecoveryAction.NO_ACTION.value,
            RecoveryAction.RECOVER_CURRENT_PLAN.value,
            RecoveryAction.REPLAN.value,
            RecoveryAction.BLOCK.value,
            decision.task_id,
            principal_id,
            project_id,
        ),
    )
    summary = await cursor.fetchone()
    if summary is None or any(
        type(summary[key]) is not int
        for key in (
            "total_count",
            "first_sequence",
            "last_sequence",
            "recovery_attempt_count",
            "replan_count",
            "invalid_action_count",
        )
    ):
        raise RecoveryDecisionIntegrityError("recovery history summary is malformed")
    if (
        summary["total_count"] != recovery_sequence
        or summary["first_sequence"] != 1
        or summary["last_sequence"] != recovery_sequence
        or summary["invalid_action_count"] != 0
    ):
        raise RecoveryDecisionIntegrityError(
            "recovery history sequence is not contiguous"
        )
    source = decision.input
    prior_count = recovery_sequence - 1
    if source.total_recovery_count != prior_count:
        raise RecoveryDecisionStaleError("recovery total count is stale")
    recovery_attempts = summary["recovery_attempt_count"] - (
        decision.action is RecoveryAction.RECOVER_CURRENT_PLAN
    )
    replans = summary["replan_count"] - (decision.action is RecoveryAction.REPLAN)
    if source.recovery_attempt_count != recovery_attempts:
        raise RecoveryDecisionStaleError("recovery attempt count is stale")
    if source.replan_count != replans:
        raise RecoveryDecisionStaleError("replan count is stale")

    signature_digest = source.failure_signature_digest
    if signature_digest is None:
        if source.identical_failure_streak != 0:
            raise RecoveryDecisionStaleError("failure streak is stale")
        return
    cursor = await conn.execute(
        """
        SELECT COALESCE(MAX(recovery_sequence), 0) AS last_different
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
          AND recovery_sequence < ?
          AND failure_signature_digest IS NOT ?
        """,
        (
            decision.task_id,
            principal_id,
            project_id,
            recovery_sequence,
            signature_digest,
        ),
    )
    boundary = await cursor.fetchone()
    if boundary is None or type(boundary["last_different"]) is not int:
        raise RecoveryDecisionIntegrityError("failure streak boundary is malformed")
    cursor = await conn.execute(
        """
        SELECT COUNT(*) AS streak
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
          AND recovery_sequence > ?
          AND recovery_sequence < ?
          AND failure_signature_digest = ?
        """,
        (
            decision.task_id,
            principal_id,
            project_id,
            boundary["last_different"],
            recovery_sequence,
            signature_digest,
        ),
    )
    streak_row = await cursor.fetchone()
    if streak_row is None or type(streak_row["streak"]) is not int:
        raise RecoveryDecisionIntegrityError("failure streak is malformed")
    streak = streak_row["streak"]
    if source.identical_failure_streak != streak:
        raise RecoveryDecisionStaleError("identical failure streak is stale")


def _target_projection(
    action: RecoveryAction,
    *,
    task_snapshot: RecoveryTaskSnapshot,
) -> tuple[AgentCognitiveState, str | None]:
    if action is RecoveryAction.RECOVER_CURRENT_PLAN:
        return AgentCognitiveState.RECOVERING, task_snapshot.published_plan_revision_id
    if action is RecoveryAction.REPLAN:
        return AgentCognitiveState.REPLANNING, None
    raise ValueError(f"action {action.value!r} has no cognitive projection")


def _task_result(
    status: RecoveryProjectionStatus,
    recovery_decision_id: str,
    recovery_sequence: int,
    decision: RecoveryDecision,
    snapshot: RecoveryTaskSnapshot,
    *,
    reason: str,
) -> RecoveryProjectionResult:
    return RecoveryProjectionResult(
        status=status,
        recovery_decision_id=recovery_decision_id,
        recovery_sequence=recovery_sequence,
        task_id=snapshot.task_id,
        action=decision.action,
        cognitive_state=snapshot.cognitive_state,
        control_state_version=snapshot.control_state_version,
        task_status=snapshot.task_status,
        published_plan_revision_id=snapshot.published_plan_revision_id,
        reason=reason,
    )


def _result(
    status: RecoveryProjectionStatus,
    recovery_decision_id: str,
    *,
    recovery_sequence: int | None = None,
    task_id: str | None = None,
    action: RecoveryAction | None = None,
    cognitive_state: AgentCognitiveState | None = None,
    control_state_version: int | None = None,
    task_status: str | None = None,
    published_plan_revision_id: str | None = None,
    reason: str = "",
) -> RecoveryProjectionResult:
    return RecoveryProjectionResult(
        status=status,
        recovery_decision_id=recovery_decision_id,
        recovery_sequence=recovery_sequence,
        task_id=task_id,
        action=action,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
        published_plan_revision_id=published_plan_revision_id,
        reason=reason,
    )


def _validate_scope(
    *,
    recovery_decision_id: str,
    principal_id: str,
    project_id: str,
) -> None:
    if type(recovery_decision_id) is not str or not recovery_decision_id:
        raise ValueError("recovery_decision_id must be a non-empty string")
    if type(principal_id) is not str or not principal_id:
        raise ValueError("principal_id must be a non-empty string")
    if type(project_id) is not str:
        raise ValueError("project_id must be a string")


__all__ = [
    "_RECOVERY_GATE_TOKEN",
    "RecoveryGateDatabase",
    "RecoveryGateRepository",
    "RecoveryProjectionResult",
    "RecoveryProjectionStatus",
]
