"""Durable owner-scoped supervision event and projection repository."""

from __future__ import annotations

import json
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from typing import Any, Protocol

from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.supervision.contracts import (
    ControlState,
    CurrentActivity,
    PlanProjection,
    SupervisionEvent,
    SupervisionEventType,
    SupervisionStatus,
    TaskSupervisionState,
)
from khaos.time_utils import utc_now_naive

MAX_EVENT_ROWS = 1024
MAX_EVENT_JSON_BYTES = 64 * 1024
MAX_STATE_JSON_BYTES = 128 * 1024
MAX_CONTROL_RESULT_BYTES = 16 * 1024


class SupervisionRepositoryDatabase(Protocol):
    """Minimal database port required by this repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]: ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


class SupervisionRepositoryError(RuntimeError):
    """Base error for durable supervision operations."""


class SupervisionEventConflictError(SupervisionRepositoryError):
    """An event identity or sequence conflicts with durable history."""


class SupervisionBindingError(SupervisionRepositoryError):
    """A task/event is not owned by the supplied principal and project."""


class SupervisionIntegrityError(SupervisionRepositoryError):
    """Durable supervision data failed digest or schema validation."""


@dataclass(frozen=True, slots=True)
class ControlSnapshot:
    """Owner-scoped durable control projection."""

    task_id: str
    principal_id: str
    project_id: str
    workspace_id: str
    state: ControlState
    revision: int
    last_command_id: str = ""
    last_result: dict[str, object] | None = None
    updated_at: str = ""


def _now() -> str:
    return utc_now_naive().isoformat()


def _row_value(row: Any, key: str, index: int) -> Any:
    """Read both sqlite Row and small dict/tuple test doubles."""
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def _owner(principal_id: str, project_id: str) -> tuple[str, str]:
    if type(principal_id) is not str or not principal_id:
        raise SupervisionBindingError("principal_id is required")
    if type(project_id) is not str or not project_id:
        raise SupervisionBindingError("project_id is required")
    return principal_id, project_id


_STATUS_BY_EVENT: dict[SupervisionEventType, SupervisionStatus] = {
    SupervisionEventType.TASK_STARTED: SupervisionStatus.PLANNING,
    SupervisionEventType.PLAN_CREATED: SupervisionStatus.PLANNING,
    SupervisionEventType.PLAN_REVISED: SupervisionStatus.PLANNING,
    SupervisionEventType.STEP_STARTED: SupervisionStatus.INVESTIGATING,
    SupervisionEventType.CONTEXT_PREPARED: SupervisionStatus.INVESTIGATING,
    SupervisionEventType.REPO_INVESTIGATED: SupervisionStatus.INVESTIGATING,
    SupervisionEventType.EDIT_PROPOSED: SupervisionStatus.EDITING,
    SupervisionEventType.EDIT_APPLIED: SupervisionStatus.EDITING,
    SupervisionEventType.VERIFICATION_STARTED: SupervisionStatus.VERIFYING,
    SupervisionEventType.VERIFICATION_PROGRESS: SupervisionStatus.VERIFYING,
    SupervisionEventType.VERIFICATION_FAILED: SupervisionStatus.REPAIRING,
    SupervisionEventType.VERIFICATION_PASSED: SupervisionStatus.READY,
    SupervisionEventType.REPAIR_STARTED: SupervisionStatus.REPAIRING,
    SupervisionEventType.APPROVAL_REQUESTED: SupervisionStatus.WAITING_FOR_APPROVAL,
    SupervisionEventType.APPROVAL_RESOLVED: SupervisionStatus.READY,
    SupervisionEventType.SUBAGENT_STARTED: SupervisionStatus.RUNNING_SUBAGENTS,
    SupervisionEventType.SUBAGENT_PROGRESS: SupervisionStatus.RUNNING_SUBAGENTS,
    SupervisionEventType.SUBAGENT_FINISHED: SupervisionStatus.READY,
    SupervisionEventType.MERGE_PLANNED: SupervisionStatus.INTEGRATING,
    SupervisionEventType.MERGE_PUBLISHED: SupervisionStatus.VERIFYING,
    SupervisionEventType.TASK_PAUSED: SupervisionStatus.PAUSED,
    SupervisionEventType.TASK_RESUMED: SupervisionStatus.READY,
    SupervisionEventType.COMPLETION_REJECTED: SupervisionStatus.BLOCKED,
    SupervisionEventType.TASK_COMPLETED: SupervisionStatus.COMPLETED,
    SupervisionEventType.TASK_FAILED: SupervisionStatus.FAILED,
    SupervisionEventType.TASK_CANCELLED: SupervisionStatus.CANCELLED,
}


def _tuple_payload(payload: dict[str, object], key: str) -> tuple[str, ...] | None:
    value = payload.get(key)
    if value is None:
        return None
    if not isinstance(value, (list, tuple)):
        raise SupervisionIntegrityError(f"event payload {key!r} is not a list")
    if not all(isinstance(item, str) for item in value):
        raise SupervisionIntegrityError(
            f"event payload {key!r} contains a non-text item"
        )
    return tuple(value)


def _apply_event(
    state: TaskSupervisionState | None,
    event: SupervisionEvent,
    *,
    principal_id: str,
    project_id: str,
) -> TaskSupervisionState:
    """Purely apply one canonical event to the bounded state projection."""
    payload = dict(event.payload)
    if state is None:
        goal = payload.get("goal", "")
        state = TaskSupervisionState(
            task_id=event.task_id,
            principal_id=principal_id,
            project_id=project_id,
            workspace_id=event.workspace_id,
            goal=goal if isinstance(goal, str) else "",
            repository_generation=event.repository_generation or 1,
            revision=0,
            sequence=0,
        )
    if (
        state.task_id != event.task_id
        or state.workspace_id != event.workspace_id
        or state.principal_id != principal_id
        or state.project_id != project_id
    ):
        raise SupervisionBindingError("supervision event and state owners differ")

    status = _STATUS_BY_EVENT.get(event.event_type, state.status)
    payload_status = payload.get("status")
    if payload_status is not None:
        try:
            status = SupervisionStatus(str(payload_status))
        except ValueError:
            # A model-facing display string cannot widen the state machine.
            pass

    generation = state.repository_generation
    if event.repository_generation is not None:
        generation = max(generation, event.repository_generation)

    activity_value = payload.get("activity", payload.get("current_activity"))
    activity = state.activity
    if activity_value is not None:
        activity = CurrentActivity.from_payload(activity_value)
    if payload.get("activity_cleared") is True:
        activity = None

    plan = state.current_plan
    plan_value = payload.get("plan")
    if plan_value is not None:
        plan = PlanProjection.from_payload(plan_value)

    changed_paths_value = _tuple_payload(payload, "changed_paths")
    changed_paths = (
        changed_paths_value
        if changed_paths_value is not None
        else state.changed_paths
    )
    active_subagents_value = _tuple_payload(payload, "active_subagents")
    active_subagents = (
        active_subagents_value
        if active_subagents_value is not None
        else state.active_subagents
    )
    checkpoints = list(state.checkpoint_ids)
    checkpoint_id = payload.get("checkpoint_id")
    if isinstance(checkpoint_id, str) and checkpoint_id and checkpoint_id not in checkpoints:
        checkpoints.append(checkpoint_id)

    blockers_value = _tuple_payload(payload, "blockers")
    blockers = blockers_value if blockers_value is not None else state.blockers
    known = state.known_file_digests
    known_value = payload.get("known_file_digests")
    if known_value is not None:
        if not isinstance(known_value, dict):
            raise SupervisionIntegrityError("known_file_digests must be an object")
        known = dict(known_value)

    verification_state = payload.get("verification_state", state.verification_state)
    approval_state = payload.get("approval_state", state.approval_state)
    merge_state = payload.get("merge_state", state.merge_state)
    completion_eligibility = payload.get(
        "completion_eligibility", state.completion_eligibility
    )
    current_step = payload.get("current_step", state.current_step)
    if not isinstance(verification_state, str):
        verification_state = state.verification_state
    if not isinstance(approval_state, str):
        approval_state = state.approval_state
    if not isinstance(merge_state, str):
        merge_state = state.merge_state
    if not isinstance(completion_eligibility, str):
        completion_eligibility = state.completion_eligibility
    if current_step is not None and not isinstance(current_step, str):
        current_step = state.current_step

    if event.event_type is SupervisionEventType.TASK_PAUSED:
        status = SupervisionStatus.PAUSED
    if event.event_type is SupervisionEventType.TASK_RESUMED:
        status = SupervisionStatus.READY

    return replace(
        state,
        status=status,
        repository_generation=generation,
        current_plan=plan,
        current_step=current_step,
        activity=activity,
        changed_paths=changed_paths,
        verification_state=verification_state,
        approval_state=approval_state,
        active_subagents=active_subagents,
        merge_state=merge_state,
        checkpoint_ids=tuple(checkpoints),
        blockers=blockers,
        completion_eligibility=completion_eligibility,
        known_file_digests=known,
        revision=state.revision + 1,
        sequence=event.sequence,
        updated_at=event.created_at,
        state_digest="",
    )


def _decode_event(row: Any) -> SupervisionEvent:
    payload = json.loads(str(_row_value(row, "payload_json", 11)))
    return SupervisionEvent(
        event_id=str(_row_value(row, "event_id", 0)),
        task_id=str(_row_value(row, "task_id", 1)),
        workspace_id=str(_row_value(row, "workspace_id", 2)),
        sequence=int(_row_value(row, "sequence", 5)),
        event_type=str(_row_value(row, "event_type", 6)),
        repository_generation=(
            int(_row_value(row, "repository_generation", 7))
            if _row_value(row, "repository_generation", 7) is not None
            else None
        ),
        plan_revision=(
            int(_row_value(row, "plan_revision", 8))
            if _row_value(row, "plan_revision", 8) is not None
            else None
        ),
        actor=str(_row_value(row, "actor", 9)),
        severity=str(_row_value(row, "severity", 10)),
        payload=payload,
        created_at=str(_row_value(row, "created_at", 13)),
        event_digest=str(_row_value(row, "event_digest", 12)),
        principal_id=str(_row_value(row, "principal_id", 3)),
        project_id=str(_row_value(row, "project_id", 4)),
    )


def _decode_state(row: Any) -> TaskSupervisionState:
    payload = json.loads(str(_row_value(row, "state_json", 6)))
    state = TaskSupervisionState.from_payload(payload)
    if state.state_digest != str(_row_value(row, "state_digest", 7)):
        raise SupervisionIntegrityError("supervision state digest mismatch")
    return state


def _decode_control(row: Any) -> ControlSnapshot:
    raw_result = _row_value(row, "last_result_json", 8)
    result = json.loads(str(raw_result)) if raw_result else None
    if result is not None and not isinstance(result, dict):
        raise SupervisionIntegrityError("control result is not an object")
    return ControlSnapshot(
        task_id=str(_row_value(row, "task_id", 0)),
        principal_id=str(_row_value(row, "principal_id", 1)),
        project_id=str(_row_value(row, "project_id", 2)),
        workspace_id=str(_row_value(row, "workspace_id", 3)),
        state=ControlState(str(_row_value(row, "control_state", 4))),
        revision=int(_row_value(row, "revision", 5)),
        last_command_id=str(_row_value(row, "last_command_id", 6) or ""),
        last_result=result,
        updated_at=str(_row_value(row, "updated_at", 8)),
    )


class TaskSupervisionRepository:
    """Own append-only supervision events and their restart-safe projection."""

    def __init__(self, database: SupervisionRepositoryDatabase) -> None:
        self._database = database

    async def append(
        self,
        event: SupervisionEvent,
        *,
        principal_id: str = "",
        project_id: str = "",
    ) -> SupervisionEvent:
        """Assign the next per-task sequence and atomically project the event."""
        if not isinstance(event, SupervisionEvent):
            raise TypeError("event must be a SupervisionEvent")
        owner_principal = principal_id or event.principal_id or "legacy"
        owner_project = project_id or event.project_id or "legacy"
        _owner(owner_principal, owner_project)
        if event.principal_id and event.principal_id != owner_principal:
            raise SupervisionBindingError("event principal does not match owner")
        if event.project_id and event.project_id != owner_project:
            raise SupervisionBindingError("event project does not match owner")
        bound = SupervisionEvent(
            event_id=event.event_id,
            task_id=event.task_id,
            workspace_id=event.workspace_id,
            event_type=event.event_type,
            sequence=event.sequence,
            repository_generation=event.repository_generation,
            plan_revision=event.plan_revision,
            actor=event.actor,
            severity=event.severity,
            payload=event.payload,
            created_at=event.created_at,
            principal_id=owner_principal,
            project_id=owner_project,
        )
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_supervision_events WHERE event_id = ?",
                (bound.event_id,),
            )
            existing_row = await cursor.fetchone()
            if existing_row is not None:
                existing = _decode_event(existing_row)
                if (
                    existing.task_id != bound.task_id
                    or existing.workspace_id != bound.workspace_id
                    or existing.principal_id != owner_principal
                    or existing.project_id != owner_project
                    or existing.event_type != bound.event_type
                    or dict(existing.payload) != dict(bound.payload)
                ):
                    raise SupervisionEventConflictError("event id is already bound to another event")
                return existing

            cursor = await conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) AS sequence "
                "FROM task_supervision_events WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (bound.task_id, owner_principal, owner_project),
            )
            row = await cursor.fetchone()
            sequence = int(_row_value(row, "sequence", 0)) + 1
            persisted = bound.with_sequence(sequence)
            payload_json = canonical_json_bytes(dict(persisted.payload)).decode("utf-8")
            if len(payload_json.encode("utf-8")) > MAX_EVENT_JSON_BYTES:
                raise SupervisionRepositoryError("event payload exceeds repository bound")
            await conn.execute(
                """
                INSERT INTO task_supervision_events (
                    event_id, task_id, workspace_id, principal_id, project_id,
                    sequence, event_type, repository_generation, plan_revision,
                    actor, severity, payload_json, event_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    persisted.event_id,
                    persisted.task_id,
                    persisted.workspace_id,
                    owner_principal,
                    owner_project,
                    persisted.sequence,
                    persisted.event_type.value,
                    persisted.repository_generation,
                    persisted.plan_revision,
                    persisted.actor.value,
                    persisted.severity.value,
                    payload_json,
                    persisted.event_digest,
                    persisted.created_at,
                ),
            )
            state = await self._state_from_connection(
                conn, bound.task_id, owner_principal, owner_project
            )
            projected = _apply_event(
                state,
                persisted,
                principal_id=owner_principal,
                project_id=owner_project,
            )
            state_json = canonical_json_bytes(projected.to_payload()).decode("utf-8")
            if len(state_json.encode("utf-8")) > MAX_STATE_JSON_BYTES:
                raise SupervisionRepositoryError("state projection exceeds repository bound")
            await conn.execute(
                """
                INSERT INTO task_supervision_states (
                    task_id, workspace_id, principal_id, project_id,
                    sequence, revision, state_json, state_digest, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(task_id, principal_id, project_id) DO UPDATE SET
                    workspace_id = excluded.workspace_id,
                    sequence = excluded.sequence,
                    revision = excluded.revision,
                    state_json = excluded.state_json,
                    state_digest = excluded.state_digest,
                    updated_at = excluded.updated_at
                """,
                (
                    projected.task_id,
                    projected.workspace_id,
                    owner_principal,
                    owner_project,
                    projected.sequence,
                    projected.revision,
                    state_json,
                    projected.state_digest,
                    projected.updated_at,
                ),
            )
        return persisted

    async def _state_from_connection(
        self, conn: Any, task_id: str, principal_id: str, project_id: str
    ) -> TaskSupervisionState | None:
        cursor = await conn.execute(
            "SELECT * FROM task_supervision_states WHERE task_id = ? "
            "AND principal_id = ? AND project_id = ?",
            (task_id, principal_id, project_id),
        )
        row = await cursor.fetchone()
        return _decode_state(row) if row is not None else None

    async def get_state(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> TaskSupervisionState | None:
        _owner(principal_id, project_id)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_supervision_states WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_state(row) if row is not None else None

    async def list_events(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        after_sequence: int = 0,
        limit: int = MAX_EVENT_ROWS,
    ) -> tuple[SupervisionEvent, ...]:
        _owner(principal_id, project_id)
        if type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("after_sequence must be non-negative")
        if type(limit) is not int or limit <= 0 or limit > MAX_EVENT_ROWS:
            raise ValueError("event limit exceeds its bound")
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_supervision_events WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ? AND sequence > ? "
                "ORDER BY sequence ASC LIMIT ?",
                (task_id, principal_id, project_id, after_sequence, limit),
            )
            rows = await cursor.fetchall()
        events = tuple(_decode_event(row) for row in rows)
        expected_sequence = after_sequence + 1
        for event in events:
            if event.sequence != expected_sequence:
                raise SupervisionIntegrityError(
                    "supervision event sequence has a gap or reordering"
                )
            expected_sequence += 1
        return events

    async def stream_events(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        after_sequence: int = 0,
        limit: int = MAX_EVENT_ROWS,
    ):
        """Replay the bounded canonical history for reconnecting adapters."""
        for event in await self.list_events(
            task_id,
            principal_id=principal_id,
            project_id=project_id,
            after_sequence=after_sequence,
            limit=limit,
        ):
            yield event

    async def ensure_control(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        workspace_id: str,
        initial: ControlState = ControlState.RUNNING,
    ) -> ControlSnapshot:
        _owner(principal_id, project_id)
        if not workspace_id:
            raise SupervisionBindingError("workspace_id is required")
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT OR IGNORE INTO task_control_state (
                    task_id, workspace_id, principal_id, project_id,
                    control_state, revision, last_command_id,
                    last_result_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, 0, '', NULL, ?)
                """,
                (task_id, workspace_id, principal_id, project_id, initial.value, _now()),
            )
            cursor = await conn.execute(
                "SELECT * FROM task_control_state WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        if row is None:
            raise SupervisionIntegrityError("control state disappeared after insert")
        return _decode_control(row)

    async def get_control(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> ControlSnapshot | None:
        _owner(principal_id, project_id)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_control_state WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_control(row) if row is not None else None

    async def compare_and_set_control(
        self,
        current: ControlSnapshot,
        *,
        expected_revision: int,
        desired_state: ControlState,
        command_id: str,
        result: dict[str, object],
    ) -> ControlSnapshot | None:
        """Atomically advance control state and retain idempotent result."""
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("expected control revision is invalid")
        if not command_id or len(command_id.encode("utf-8")) > 128:
            raise ValueError("command_id is invalid")
        result_json = canonical_json_bytes(result).decode("utf-8")
        if len(result_json.encode("utf-8")) > MAX_CONTROL_RESULT_BYTES:
            raise ValueError("control result exceeds its bound")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT * FROM task_control_state WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (current.task_id, current.principal_id, current.project_id),
            )
            row = await cursor.fetchone()
            if row is None:
                raise SupervisionBindingError("control state is not initialized")
            actual = _decode_control(row)
            if actual.revision != expected_revision:
                return None
            if actual.last_command_id == command_id and actual.last_result is not None:
                return actual
            revision = expected_revision + 1
            await conn.execute(
                """
                UPDATE task_control_state SET control_state = ?, revision = ?,
                    last_command_id = ?, last_result_json = ?, updated_at = ?
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                    AND revision = ?
                """,
                (
                    desired_state.value,
                    revision,
                    command_id,
                    result_json,
                    _now(),
                    current.task_id,
                    current.principal_id,
                    current.project_id,
                    expected_revision,
                ),
            )
            cursor = await conn.execute(
                "SELECT * FROM task_control_state WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (current.task_id, current.principal_id, current.project_id),
            )
            updated = await cursor.fetchone()
        if updated is None:
            raise SupervisionIntegrityError("control state disappeared after CAS")
        return _decode_control(updated)

    async def set_control_state(
        self,
        current: ControlSnapshot,
        *,
        expected_revision: int,
        desired_state: ControlState,
    ) -> ControlSnapshot | None:
        """Advance a runtime-settled state without creating a new command."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE task_control_state SET control_state = ?, revision = revision + 1,
                    updated_at = ?
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                    AND revision = ?
                """,
                (
                    desired_state.value,
                    _now(),
                    current.task_id,
                    current.principal_id,
                    current.project_id,
                    expected_revision,
                ),
            )
            if getattr(cursor, "rowcount", 1) == 0:
                return None
            cursor = await conn.execute(
                "SELECT * FROM task_control_state WHERE task_id = ? "
                "AND principal_id = ? AND project_id = ?",
                (current.task_id, current.principal_id, current.project_id),
            )
            row = await cursor.fetchone()
        return _decode_control(row) if row is not None else None


__all__ = [
    "ControlSnapshot",
    "SupervisionBindingError",
    "SupervisionEventConflictError",
    "SupervisionIntegrityError",
    "SupervisionRepositoryError",
    "TaskSupervisionRepository",
]
