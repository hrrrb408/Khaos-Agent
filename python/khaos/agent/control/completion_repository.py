"""Owner-scoped append-only persistence for completion decisions."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol

from khaos.agent.control.completion import (
    CompletionDecision,
    CompletionDecisionValidationError,
    CompletionOutcome,
)
from khaos.agent.control.completion_evaluator import CompletionEvaluationSnapshot
from khaos.agent.control.goal import GoalSpec, GoalSpecValidationError
from khaos.agent.control.state import AgentCognitiveState
from khaos.time_utils import utc_now_naive


class CompletionDecisionDatabase(Protocol):
    """Minimal database port required by the decision repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction owner."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class CompletionDecisionRepositoryError(RuntimeError):
    """Base error for durable completion-decision persistence."""


class CompletionDecisionBindingError(CompletionDecisionRepositoryError):
    """The decision is not bound to the supplied current task snapshot."""


class CompletionDecisionConflictError(CompletionDecisionRepositoryError):
    """An immutable decision identity or sequence conflicts with a row."""


class CompletionDecisionIntegrityError(CompletionDecisionRepositoryError):
    """A durable decision row failed closed integrity validation."""


@dataclass(frozen=True, slots=True)
class StoredCompletionDecision:
    """Immutable decision plus its owner-scoped ledger envelope."""

    decision: CompletionDecision
    decision_sequence: int
    principal_id: str
    project_id: str
    created_at: str

    @property
    def decision_id(self) -> str:
        """Return the immutable decision identity."""
        return self.decision.decision_id

    @property
    def task_id(self) -> str:
        """Return the task bound by the decision."""
        return self.decision.task_id

    @property
    def goal_spec_id(self) -> str:
        """Return the bound GoalSpec identity."""
        return self.decision.goal_spec_id

    @property
    def goal_spec_digest(self) -> str:
        """Return the bound GoalSpec semantic digest."""
        return self.decision.goal_spec_digest

    @property
    def cognitive_state(self) -> AgentCognitiveState:
        """Return the cognitive state captured by the decision."""
        return self.decision.cognitive_state

    @property
    def control_state_version(self) -> int:
        """Return the cognitive-state CAS version captured by the decision."""
        return self.decision.control_state_version

    @property
    def outcome(self) -> CompletionOutcome:
        """Return the recorded outcome without adding projection semantics."""
        return self.decision.outcome

    @property
    def decision_digest(self) -> str:
        """Return the semantic decision digest."""
        return self.decision.decision_digest

    @property
    def continuation_possible(self) -> bool:
        """Return continuation semantics derived from the recorded outcome."""
        return self.decision.continuation_possible


@dataclass(frozen=True, slots=True)
class _CompletionTaskSnapshot:
    """Owner-scoped task facts used to bind a decision at append time.

    Cognitive state, control-state version, and task status come from their
    canonical SQL columns.  M7.1.4 has no task-level workspace column, so
    ``workspace_id`` is decoded from the task's durable
    ``state_json.metadata`` projection after strict shape validation.  This
    is an identity-consistency fact only; it does not grant workspace access
    or any execution authority.
    """

    task_id: str
    principal_id: str
    project_id: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str | None


class CompletionDecisionRepository:
    """Append and read immutable decisions inside an authenticated owner scope.

    The repository is the sole sequence allocator.  ``append`` verifies the
    current task, GoalSpec, cognitive-state, and workspace snapshot in the same
    ``Database.transaction()`` that allocates and inserts the next sequence.
    There are intentionally no update, delete, or unscoped read methods.
    """

    def __init__(self, database: CompletionDecisionDatabase) -> None:
        self._database = database

    @property
    def database(self) -> CompletionDecisionDatabase:
        """Return the composed database port for explicit transaction sharing."""
        return self._database

    async def append(
        self,
        decision: CompletionDecision,
        *,
        principal_id: str,
        project_id: str,
        created_at: str | None = None,
    ) -> StoredCompletionDecision:
        """Atomically validate, sequence, and append one decision.

        ``decision_sequence`` is deliberately not a caller argument.  A
        caller/model cannot choose an ordering number; the shared writer
        transaction allocates it from the owner-scoped durable ledger.
        """
        if type(decision) is not CompletionDecision:
            raise TypeError("decision must be a CompletionDecision")
        _validate_scope(
            task_id=decision.task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        timestamp = _validate_timestamp(created_at)
        canonical_json = decision.canonical_json()

        try:
            async with self._database.transaction() as conn:
                task_row = await _select_task(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_row is None:
                    # Missing and foreign tasks intentionally share the same
                    # boundary error; callers cannot turn this into an owner
                    # existence oracle.
                    raise CompletionDecisionBindingError(
                        "task is unavailable in the supplied owner scope"
                    )
                task_snapshot = _decode_task_snapshot(task_row)

                goal_row = await _select_goal_spec(
                    conn,
                    task_id=decision.task_id,
                )
                if goal_row is None:
                    raise CompletionDecisionBindingError("task has no durable GoalSpec")
                goal_spec = _decode_goal_spec_row(goal_row)
                if (
                    goal_row["principal_id"] != principal_id
                    or goal_row["project_id"] != project_id
                ):
                    raise CompletionDecisionBindingError(
                        "GoalSpec is not owned by the supplied task scope"
                    )

                _validate_binding(
                    decision,
                    task_snapshot=task_snapshot,
                    goal_spec=goal_spec,
                    principal_id=principal_id,
                    project_id=project_id,
                )

                cursor = await conn.execute(
                    """
                    SELECT COALESCE(MAX(decision_sequence), 0) + 1 AS next_sequence
                    FROM agent_completion_decisions
                    WHERE task_id = ? AND principal_id = ? AND project_id = ?
                    """,
                    (decision.task_id, principal_id, project_id),
                )
                sequence_row = await cursor.fetchone()
                if (
                    sequence_row is None
                    or type(sequence_row["next_sequence"]) is not int
                ):
                    raise CompletionDecisionIntegrityError(
                        "decision sequence allocator returned an invalid value"
                    )
                decision_sequence = sequence_row["next_sequence"]
                if decision_sequence < 1:
                    raise CompletionDecisionIntegrityError(
                        "decision sequence allocator returned a non-positive value"
                    )

                await conn.execute(
                    """
                    INSERT INTO agent_completion_decisions (
                        decision_id, task_id, principal_id, project_id,
                        decision_sequence, schema_version, decision_digest,
                        canonical_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        decision.decision_id,
                        decision.task_id,
                        principal_id,
                        project_id,
                        decision_sequence,
                        decision.schema_version,
                        decision.decision_digest,
                        canonical_json,
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise CompletionDecisionConflictError(
                "completion decision identity or sequence conflicts with an existing row"
            ) from exc

        return StoredCompletionDecision(
            decision=decision,
            decision_sequence=decision_sequence,
            principal_id=principal_id,
            project_id=project_id,
            created_at=timestamp,
        )

    async def read_current_task_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        goal_spec: GoalSpec,
    ) -> CompletionEvaluationSnapshot | None:
        """Read one owner-scoped current task snapshot for evaluation.

        Cognitive state, its CAS version, and ``TaskStatus`` are read from
        their physical SQL columns.  The workspace value is decoded from the
        existing durable task projection by the same strict decoder used by
        ``append``.  ``goal_spec`` must already have been loaded through the
        owner-scoped GoalSpec repository; this method only binds its identity
        into the returned evaluation snapshot.

        The read is deliberately non-mutating and does not use
        ``TaskManager.load()``.  The append path performs the authoritative
        recheck after evaluation, so a concurrent task change is reported as
        a stale append rather than being silently retried.
        """
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if type(goal_spec) is not GoalSpec:
            raise TypeError("goal_spec must be a GoalSpec")
        async with self._database.read_connection() as conn:
            task_row = await _select_task(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
        if task_row is None:
            return None
        task_snapshot = _decode_task_snapshot(task_row)
        if (
            task_snapshot.task_id != task_id
            or task_snapshot.principal_id != principal_id
            or task_snapshot.project_id != project_id
        ):
            raise CompletionDecisionIntegrityError(
                "current task snapshot owner or identity disagrees"
            )
        return CompletionEvaluationSnapshot(
            task_id=task_snapshot.task_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            cognitive_state=task_snapshot.cognitive_state,
            control_state_version=task_snapshot.control_state_version,
            task_status=task_snapshot.task_status,
            workspace_id=task_snapshot.workspace_id,
        )

    async def get_by_id(
        self,
        decision_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredCompletionDecision | None:
        """Read one decision only inside the supplied owner scope."""
        _validate_lookup_id(decision_id, label="decision_id")
        _validate_scope(
            task_id="lookup", principal_id=principal_id, project_id=project_id
        )
        async with self._database.read_connection() as conn:
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
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_decision_id=decision_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def get_latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredCompletionDecision | None:
        """Read the latest decision for an owner-scoped task."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT decision_id, task_id, principal_id, project_id,
                       decision_sequence, schema_version, decision_digest,
                       canonical_json, created_at
                FROM agent_completion_decisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY decision_sequence DESC
                LIMIT 1
                """,
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_task_id=task_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def list_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> list[StoredCompletionDecision]:
        """List owner-scoped decisions in durable sequence order."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT decision_id, task_id, principal_id, project_id,
                       decision_sequence, schema_version, decision_digest,
                       canonical_json, created_at
                FROM agent_completion_decisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY decision_sequence ASC
                """,
                (task_id, principal_id, project_id),
            )
            rows = await cursor.fetchall()
        decoded: list[StoredCompletionDecision] = []
        for row in rows:
            stored = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                raise CompletionDecisionIntegrityError(
                    "stored completion decision row disappeared during read"
                )
            decoded.append(stored)
        return decoded


def _validate_scope(*, task_id: str, principal_id: str, project_id: str) -> None:
    if type(task_id) is not str or not task_id:
        raise ValueError("task_id must be a non-empty string")
    if type(principal_id) is not str or not principal_id:
        raise ValueError("principal_id must be a non-empty string")
    if type(project_id) is not str:
        raise ValueError("project_id must be a string")


def _validate_lookup_id(value: str, *, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")


def _validate_timestamp(value: str | None) -> str:
    if value is None:
        return utc_now_naive().isoformat()
    if type(value) is not str or not value:
        raise ValueError("created_at must be a non-empty string")
    return value


async def _select_task(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT id, principal_id, project_id, cognitive_state,
               control_state_version, status, state_json
        FROM coding_tasks
        WHERE id = ? AND principal_id = ? AND project_id = ?
        """,
        (task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


async def _select_goal_spec(conn: Any, *, task_id: str) -> Any:
    cursor = await conn.execute(
        """
        SELECT goal_spec_id, task_id, principal_id, project_id,
               schema_version, semantic_digest, canonical_json, created_at
        FROM agent_goal_specs
        WHERE task_id = ?
        """,
        (task_id,),
    )
    return await cursor.fetchone()


def _decode_task_snapshot(
    row: Any,
) -> _CompletionTaskSnapshot:
    try:
        row_task_id = row["id"]
        row_principal_id = row["principal_id"]
        row_project_id = row["project_id"]
        row_state = AgentCognitiveState.parse(row["cognitive_state"])
        row_version = row["control_state_version"]
        row_status = row["status"]
        state_json = row["state_json"]
    except (KeyError, TypeError, ValueError) as exc:
        raise CompletionDecisionIntegrityError(
            "coding task control-state snapshot is malformed"
        ) from exc
    if (
        type(row_task_id) is not str
        or not row_task_id
        or type(row_principal_id) is not str
        or not row_principal_id
        or type(row_project_id) is not str
        or type(row_version) is not int
        or row_version < 0
        or type(row_status) is not str
        or not row_status
    ):
        raise CompletionDecisionIntegrityError(
            "coding task owner, version, or status is malformed"
        )
    workspace_id = _decode_workspace_projection(state_json)
    return _CompletionTaskSnapshot(
        task_id=row_task_id,
        principal_id=row_principal_id,
        project_id=row_project_id,
        cognitive_state=row_state,
        control_state_version=row_version,
        task_status=row_status,
        workspace_id=workspace_id,
    )


def _decode_workspace_projection(state_json: Any) -> str | None:
    """Decode the task's durable workspace projection, failing closed.

    Only ``metadata.workspace_id`` is read from ``state_json``.  The physical
    SQL columns remain authoritative for every other task snapshot field.  A
    missing metadata object means that the task has no workspace binding; an
    explicitly malformed metadata value is never silently treated as
    unbound.
    """
    if type(state_json) is not str:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is not a JSON string"
        )
    try:
        decoded = json.loads(state_json)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is malformed"
        ) from exc
    if type(decoded) is not dict:
        raise CompletionDecisionIntegrityError(
            "coding task state_json is not an object"
        )
    if "metadata" not in decoded:
        return None
    metadata = decoded["metadata"]
    if type(metadata) is not dict:
        raise CompletionDecisionIntegrityError(
            "coding task metadata projection is not an object"
        )
    if "workspace_id" not in metadata or metadata["workspace_id"] is None:
        return None
    workspace_id = metadata["workspace_id"]
    if type(workspace_id) is not str or not workspace_id:
        raise CompletionDecisionIntegrityError(
            "coding task workspace_id projection is malformed"
        )
    return workspace_id


def _decode_goal_spec_row(row: Any) -> GoalSpec:
    try:
        goal_spec_id = row["goal_spec_id"]
        task_id = row["task_id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        schema_version = row["schema_version"]
        semantic_digest = row["semantic_digest"]
        canonical_json = row["canonical_json"]
    except (KeyError, TypeError) as exc:
        raise CompletionDecisionIntegrityError(
            "GoalSpec binding row is malformed"
        ) from exc
    if (
        type(goal_spec_id) is not str
        or not goal_spec_id
        or type(task_id) is not str
        or not task_id
        or type(principal_id) is not str
        or not principal_id
        or type(project_id) is not str
        or type(schema_version) is not int
        or type(semantic_digest) is not str
        or not semantic_digest
        or type(canonical_json) is not str
    ):
        raise CompletionDecisionIntegrityError("GoalSpec binding row is invalid")
    try:
        spec = GoalSpec.from_canonical_json(
            canonical_json,
            expected_digest=semantic_digest,
        )
    except (GoalSpecValidationError, TypeError, ValueError) as exc:
        raise CompletionDecisionIntegrityError(
            "GoalSpec binding payload failed integrity validation"
        ) from exc
    if spec.schema_version != schema_version or spec.goal_spec_id != goal_spec_id:
        raise CompletionDecisionIntegrityError(
            "GoalSpec binding row disagrees with its canonical payload"
        )
    return spec


def _validate_binding(
    decision: CompletionDecision,
    *,
    task_snapshot: _CompletionTaskSnapshot,
    goal_spec: GoalSpec,
    principal_id: str,
    project_id: str,
) -> None:
    # Keep each comparison explicit: these fields are the input snapshot
    # fence for a future stale-decision gate, not a free-form caller claim.
    if task_snapshot.task_id != decision.task_id:
        raise CompletionDecisionBindingError("decision task binding mismatch")
    if (
        task_snapshot.principal_id != principal_id
        or task_snapshot.project_id != project_id
    ):
        raise CompletionDecisionBindingError("task owner binding mismatch")
    if decision.goal_spec_id != goal_spec.goal_spec_id:
        raise CompletionDecisionBindingError("decision GoalSpec identity mismatch")
    if decision.goal_spec_digest != goal_spec.semantic_digest:
        raise CompletionDecisionBindingError("decision GoalSpec digest mismatch")
    if decision.cognitive_state is not task_snapshot.cognitive_state:
        raise CompletionDecisionBindingError(
            "decision cognitive-state snapshot is stale"
        )
    if decision.control_state_version != task_snapshot.control_state_version:
        raise CompletionDecisionBindingError(
            "decision cognitive-state version is stale"
        )
    if decision.task_status_at_evaluation != task_snapshot.task_status:
        raise CompletionDecisionBindingError("decision task-status snapshot is stale")
    if decision.workspace_id != task_snapshot.workspace_id:
        raise CompletionDecisionBindingError(
            "decision workspace snapshot is stale or mismatched"
        )


def _decode_row(
    row: Any,
    *,
    expected_decision_id: str | None = None,
    expected_task_id: str | None = None,
    expected_principal_id: str | None = None,
    expected_project_id: str | None = None,
) -> StoredCompletionDecision | None:
    if row is None:
        return None
    try:
        row_decision_id = row["decision_id"]
        row_task_id = row["task_id"]
        row_principal_id = row["principal_id"]
        row_project_id = row["project_id"]
        row_sequence = row["decision_sequence"]
        row_schema_version = row["schema_version"]
        row_digest = row["decision_digest"]
        canonical_json = row["canonical_json"]
        created_at = row["created_at"]
    except (KeyError, TypeError) as exc:
        raise CompletionDecisionIntegrityError(
            "stored completion decision row is malformed"
        ) from exc
    if (
        type(row_decision_id) is not str
        or not row_decision_id
        or type(row_task_id) is not str
        or not row_task_id
        or type(row_principal_id) is not str
        or not row_principal_id
        or type(row_project_id) is not str
        or type(row_sequence) is not int
        or row_sequence < 1
        or type(row_schema_version) is not int
        or type(row_digest) is not str
        or not row_digest
        or type(canonical_json) is not str
        or type(created_at) is not str
        or not created_at
    ):
        raise CompletionDecisionIntegrityError(
            "stored completion decision identity, sequence, or payload is invalid"
        )
    if expected_decision_id is not None and row_decision_id != expected_decision_id:
        raise CompletionDecisionIntegrityError("decision identity mismatch")
    if expected_task_id is not None and row_task_id != expected_task_id:
        raise CompletionDecisionIntegrityError("decision task identity mismatch")
    if expected_principal_id is not None and row_principal_id != expected_principal_id:
        raise CompletionDecisionIntegrityError("decision principal identity mismatch")
    if expected_project_id is not None and row_project_id != expected_project_id:
        raise CompletionDecisionIntegrityError("decision project identity mismatch")
    try:
        decision = CompletionDecision.from_canonical_json(
            canonical_json,
            expected_digest=row_digest,
        )
    except (CompletionDecisionValidationError, TypeError, ValueError) as exc:
        raise CompletionDecisionIntegrityError(
            "stored completion decision payload failed integrity validation"
        ) from exc
    if (
        decision.decision_id != row_decision_id
        or decision.task_id != row_task_id
        or decision.schema_version != row_schema_version
        or decision.decision_digest != row_digest
    ):
        raise CompletionDecisionIntegrityError(
            "stored completion decision row disagrees with its canonical payload"
        )
    return StoredCompletionDecision(
        decision=decision,
        decision_sequence=row_sequence,
        principal_id=row_principal_id,
        project_id=row_project_id,
        created_at=created_at,
    )


__all__ = [
    "CompletionDecisionBindingError",
    "CompletionDecisionConflictError",
    "CompletionDecisionDatabase",
    "CompletionDecisionIntegrityError",
    "CompletionDecisionRepository",
    "CompletionDecisionRepositoryError",
    "StoredCompletionDecision",
]
