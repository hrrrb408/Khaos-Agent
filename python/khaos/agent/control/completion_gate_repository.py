"""Atomic, owner-scoped Completion Gate task projection repository."""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from khaos.agent.control.completion import CompletionOutcome
from khaos.agent.control.completion_gate import (
    CompletionAuthorityResult,
    CompletionAuthorityStatus,
)
from khaos.agent.control.completion_repository import (
    CompletionDecisionIntegrityError,
    _decode_goal_spec_row,
    _decode_row,
    _decode_task_snapshot,
    _select_goal_spec,
    _select_task,
    _validate_binding,
)
from khaos.agent.control.goal import GoalSpec
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)

_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})
_ELIGIBLE_TASK_STATUSES = frozenset({"running"})
# The repository is an internal SQL owner.  Only CompletionGate may cross
# into its lifecycle projection method after the separate authority policy has
# returned a bound authorization result.  A private identity token prevents a
# caller from treating a constructible CompletionAuthorityResult as a free
# completion capability.
_COMPLETION_GATE_TOKEN = object()


class CompletionGateDatabase(Protocol):
    """Minimal shared-writer database port required by the gate."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the database's global atomic writer transaction."""
        ...


class CompletionProjectionStatus(str, Enum):
    """Typed repository result before the public gate result mapping."""

    PROJECTED = "projected"
    NOT_COMPLETE = "not_complete"
    STALE = "stale"
    AUTHORITY_INSUFFICIENT = "authority_insufficient"
    REJECTED = "rejected"
    ALREADY_TERMINAL = "already_terminal"
    DELEGATED_CHILD_ACTIVE = "delegated_child_active"
    NOT_FOUND = "not_found"
    INTEGRITY_ERROR = "integrity_error"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class CompletionProjectionResult:
    """Result of one atomic decision reload and task status CAS."""

    status: CompletionProjectionStatus
    decision_id: str
    decision_digest: str | None
    task_status: str | None
    reason: str = ""


class CompletionGateRepository:
    """Own the only SQL path for successful coding-task completion."""

    def __init__(self, database: CompletionGateDatabase) -> None:
        self._database = database

    async def project_completion(
        self,
        decision_id: str,
        *,
        principal_id: str,
        project_id: str,
        authority: CompletionAuthorityResult,
        gate_token: object,
    ) -> CompletionProjectionResult:
        """Atomically reload, stale-check, and project one COMPLETE decision.

        ``gate_token`` is an internal owner fence.  The public Gate obtains it
        only after its separately composed authority policy returns a bound
        result; a caller-supplied ``CompletionAuthorityResult`` alone cannot
        invoke this lifecycle write.

        Decision, GoalSpec, workspace projection, physical cognitive snapshot,
        and task lifecycle status are all read while the shared writer
        transaction is held.  The final UPDATE repeats the lifecycle and
        cognitive-state predicates, so a concurrent runtime cannot turn a
        stale pre-read into a successful completion.
        """
        _validate_scope(
            decision_id=decision_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if type(authority) is not CompletionAuthorityResult:
            raise TypeError("authority must be a CompletionAuthorityResult")
        if gate_token is not _COMPLETION_GATE_TOKEN:
            raise PermissionError(
                "completion projection is owned by CompletionGate"
            )

        try:
            async with self._database.transaction() as conn:
                decision_row = await _select_decision(
                    conn,
                    decision_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if decision_row is None:
                    return _result(
                        CompletionProjectionStatus.NOT_FOUND,
                        decision_id,
                        reason="decision is unavailable in the supplied owner scope",
                    )
                try:
                    stored = _decode_row(
                        decision_row,
                        expected_decision_id=decision_id,
                        expected_principal_id=principal_id,
                        expected_project_id=project_id,
                    )
                except CompletionDecisionIntegrityError as exc:
                    return _result(
                        CompletionProjectionStatus.INTEGRITY_ERROR,
                        decision_id,
                        reason=type(exc).__name__,
                    )
                if stored is None:
                    return _result(
                        CompletionProjectionStatus.NOT_FOUND,
                        decision_id,
                        reason="decision is unavailable in the supplied owner scope",
                    )
                decision = stored.decision
                if not _authority_matches(authority, decision):
                    return _result(
                        CompletionProjectionStatus.REJECTED,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        reason="completion authority result is not decision-bound",
                    )
                if authority.status is not CompletionAuthorityStatus.AUTHORIZED:
                    return _result(
                        (
                            CompletionProjectionStatus.AUTHORITY_INSUFFICIENT
                            if authority.status
                            is CompletionAuthorityStatus.INSUFFICIENT
                            else CompletionProjectionStatus.REJECTED
                        ),
                        decision_id,
                        decision_digest=decision.decision_digest,
                        reason=authority.reason or "completion authority is insufficient",
                    )
                if decision.outcome is not CompletionOutcome.COMPLETE:
                    return _result(
                        CompletionProjectionStatus.NOT_COMPLETE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=decision.task_status_at_evaluation,
                        reason="only a COMPLETE decision is eligible for projection",
                    )

                task_row = await _select_task(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_row is None:
                    return _result(
                        CompletionProjectionStatus.NOT_FOUND,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        reason="task is unavailable in the supplied owner scope",
                    )
                try:
                    task_snapshot = _decode_task_snapshot(task_row)
                except CompletionDecisionIntegrityError as exc:
                    return _result(
                        CompletionProjectionStatus.INTEGRITY_ERROR,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        reason=type(exc).__name__,
                    )

                if task_snapshot.task_status in _TERMINAL_TASK_STATUSES:
                    return _result(
                        CompletionProjectionStatus.ALREADY_TERMINAL,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="task is already terminal",
                    )

                goal_row = await _select_goal_spec(conn, task_id=decision.task_id)
                if goal_row is None:
                    return _result(
                        CompletionProjectionStatus.INTEGRITY_ERROR,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="task has no canonical GoalSpec",
                    )
                try:
                    goal_spec = _decode_goal_spec_row(goal_row)
                except CompletionDecisionIntegrityError as exc:
                    return _result(
                        CompletionProjectionStatus.INTEGRITY_ERROR,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason=type(exc).__name__,
                    )
                if not _goal_row_matches_scope(
                    goal_row,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                ) or type(goal_spec) is not GoalSpec:
                    return _result(
                        CompletionProjectionStatus.STALE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="canonical GoalSpec binding is stale or mismatched",
                    )

                try:
                    _validate_binding(
                        decision,
                        task_snapshot=task_snapshot,
                        goal_spec=goal_spec,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                except Exception as exc:  # noqa: BLE001 - binding fails closed
                    return _result(
                        CompletionProjectionStatus.STALE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason=type(exc).__name__,
                    )

                if task_snapshot.task_status not in _ELIGIBLE_TASK_STATUSES:
                    return _result(
                        CompletionProjectionStatus.NOT_COMPLETE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason=(
                            "task status is not eligible for successful "
                            "completion projection"
                        ),
                    )

                delegated_child = await conn.execute(
                    """SELECT 1 FROM agent_subagent_assignments a
                       JOIN agent_subagent_runs r ON r.assignment_id = a.assignment_id
                       WHERE a.task_owner_principal_id = ? AND a.project_id = ?
                         AND a.parent_task_id = ?
                         AND r.state IN ('PENDING', 'ACTIVE') LIMIT 1""",
                    (principal_id, project_id, decision.task_id),
                )
                if await delegated_child.fetchone() is not None:
                    return _result(
                        CompletionProjectionStatus.DELEGATED_CHILD_ACTIVE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="active delegated child blocks parent completion",
                    )

                active_fence = await conn.execute(
                    "SELECT 1 FROM agent_plan_dispatch_fences WHERE principal_id = ? AND project_id = ? AND task_id = ? AND status = 'ACTIVE' LIMIT 1",
                    (principal_id, project_id, decision.task_id),
                )
                if await active_fence.fetchone() is not None:
                    return _result(
                        CompletionProjectionStatus.STALE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="active plan dispatch fence prevents completion",
                    )

                try:
                    state = _decode_state_projection(task_row["state_json"])
                except CompletionDecisionIntegrityError as exc:
                    return _result(
                        CompletionProjectionStatus.INTEGRITY_ERROR,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason=type(exc).__name__,
                    )
                timestamp = utc_now_naive().isoformat()
                state["status"] = "completed"
                state["updated_at"] = timestamp
                state_json = json.dumps(
                    state,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                cursor = await conn.execute(
                    """
                    UPDATE coding_tasks
                    SET status = ?, state_json = ?, updated_at = ?
                    WHERE id = ?
                      AND principal_id = ?
                      AND project_id = ?
                      AND status = ?
                      AND cognitive_state = ?
                      AND control_state_version = ?
                    """,
                    (
                        "completed",
                        state_json,
                        timestamp,
                        decision.task_id,
                        principal_id,
                        project_id,
                        task_snapshot.task_status,
                        task_snapshot.cognitive_state.value,
                        task_snapshot.control_state_version,
                    ),
                )
                if cursor.rowcount != 1:
                    return _result(
                        CompletionProjectionStatus.STALE,
                        decision_id,
                        decision_digest=decision.decision_digest,
                        task_status=task_snapshot.task_status,
                        reason="task completion CAS did not update exactly one row",
                    )
                return _result(
                    CompletionProjectionStatus.PROJECTED,
                    decision_id,
                    decision_digest=decision.decision_digest,
                    task_status="completed",
                )
        except sqlite3.Error as exc:
            logger.exception("completion projection SQL failed")
            return _result(
                CompletionProjectionStatus.ERROR,
                decision_id,
                reason=type(exc).__name__,
            )


async def _select_decision(
    conn: Any,
    decision_id: str,
    *,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT decision_id, task_id, principal_id, project_id,
               decision_sequence, schema_version, decision_digest,
               canonical_json, created_at
        FROM agent_completion_decisions
        WHERE decision_id = ? AND principal_id = ? AND project_id = ?
        """,
        (decision_id, principal_id, project_id),
    )
    return await cursor.fetchone()


def _decode_state_projection(state_json: Any) -> dict[str, Any]:
    if type(state_json) is not str:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is not a JSON string"
        )
    try:
        state = json.loads(state_json)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is malformed"
        ) from exc
    if type(state) is not dict:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is not an object"
        )
    metadata = state.get("metadata")
    if metadata is not None and type(metadata) is not dict:
        raise CompletionDecisionIntegrityError(
            "coding task metadata projection is not an object"
        )
    if metadata is not None and "workspace_id" in metadata:
        workspace_id = metadata["workspace_id"]
        if workspace_id is not None and (
            type(workspace_id) is not str or not workspace_id
        ):
            raise CompletionDecisionIntegrityError(
                "coding task workspace_id projection is malformed"
            )
    return state


def _goal_row_matches_scope(
    row: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> bool:
    return (
        row["task_id"] == task_id
        and row["principal_id"] == principal_id
        and row["project_id"] == project_id
    )


def _authority_matches(authority: CompletionAuthorityResult, decision: Any) -> bool:
    return (
        authority.task_id == decision.task_id
        and authority.goal_spec_id == decision.goal_spec_id
        and authority.goal_spec_digest == decision.goal_spec_digest
        and authority.decision_id == decision.decision_id
        and authority.decision_digest == decision.decision_digest
    )


def _validate_scope(
    *, decision_id: str, principal_id: str, project_id: str
) -> None:
    if type(decision_id) is not str or not decision_id:
        raise ValueError("decision_id must be a non-empty string")
    if type(principal_id) is not str or not principal_id:
        raise ValueError("principal_id must be a non-empty string")
    if type(project_id) is not str:
        raise ValueError("project_id must be a string")


def _result(
    status: CompletionProjectionStatus,
    decision_id: str,
    *,
    decision_digest: str | None = None,
    task_status: str | None = None,
    reason: str = "",
) -> CompletionProjectionResult:
    return CompletionProjectionResult(
        status=status,
        decision_id=decision_id,
        decision_digest=decision_digest,
        task_status=task_status,
        reason=reason[:512],
    )


__all__ = [
    "CompletionGateDatabase",
    "CompletionGateRepository",
    "CompletionProjectionResult",
    "CompletionProjectionStatus",
]
