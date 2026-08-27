"""Owner-scoped durable persistence for immutable plan revisions.

The repository is deliberately narrower than the task manager.  It owns the
append-only planning ledger and its task/GoalSpec/control-state binding, while
the cognitive state machine and the planning service remain separate
authorities.  No method in this module executes a plan or changes a task
lifecycle status.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol

from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import GoalSpecIntegrityError
from khaos.agent.control.state import (
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.coding.planning.revision import (
    PlanDisposition,
    PlanningContractError,
    PlanRevision,
    plan_revision_from_canonical_json,
)


class PlanRevisionDatabase(Protocol):
    """Minimal database port required by ``PlanRevisionRepository``."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared single-writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class PlanRevisionRepositoryError(RuntimeError):
    """Base error for durable plan-revision operations."""


class PlanRevisionBindingError(PlanRevisionRepositoryError):
    """A revision is not bound to the supplied current owner/task snapshot."""


class PlanRevisionConflictError(PlanRevisionRepositoryError):
    """An immutable revision identity, parent, or sequence conflicts."""


class PlanRevisionIntegrityError(PlanRevisionRepositoryError):
    """A durable task, GoalSpec, or plan row failed closed validation."""


class PlanRevisionStaleError(PlanRevisionRepositoryError):
    """The plan input no longer describes the current durable task snapshot."""


class PlanPublicationStatus(str, Enum):
    """Typed result of one atomic READY-plan publication attempt."""

    PUBLISHED = "published"
    ALREADY_PUBLISHED = "already_published"
    STALE = "stale"
    CONFLICT = "conflict"
    NOT_FOUND = "not_found"
    TERMINAL = "terminal"
    INVALID = "invalid"


@dataclass(frozen=True, slots=True)
class PlanningTaskSnapshot:
    """Owner-scoped physical task facts used to bind a plan revision.

    ``cognitive_state``, ``control_state_version``, and ``task_status`` are
    read from SQL columns.  Workspace and base revision are read from the
    existing task metadata projection solely for identity consistency; they do
    not grant workspace or execution authority.
    """

    task_id: str
    principal_id: str
    project_id: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str | None
    base_revision: str | None
    repository_id: str | None
    published_plan_revision_id: str | None = None


@dataclass(frozen=True, slots=True)
class StoredPlanRevision:
    """Immutable plan revision plus its durable ledger envelope."""

    revision: PlanRevision
    revision_sequence: int
    principal_id: str
    project_id: str
    created_at: str

    @property
    def plan_revision_id(self) -> str:
        """Return the durable revision identity."""
        return self.revision.plan_revision_id

    @property
    def task_id(self) -> str:
        """Return the task bound by the revision."""
        return self.revision.task_id

    @property
    def disposition(self) -> PlanDisposition:
        """Return the planning disposition without lifecycle semantics."""
        return self.revision.disposition


@dataclass(frozen=True, slots=True)
class PlanPublicationResult:
    """Bounded result of one atomic plan-ledger/cognitive publication.

    ``published_plan_revision_id`` is a descriptive control-plane projection.
    It identifies the exact READY revision that caused the cognitive phase to
    become ``IMPLEMENTING``; it grants no execution, approval, or workspace
    authority.
    """

    status: PlanPublicationStatus
    task_id: str | None
    plan_revision_id: str
    revision_sequence: int | None = None
    published_plan_revision_id: str | None = None
    cognitive_state: AgentCognitiveState | None = None
    control_state_version: int | None = None
    task_status: str | None = None
    reason: str = ""


class PlanRevisionRepository:
    """Append and read plan revisions inside an authenticated owner scope."""

    def __init__(self, database: PlanRevisionDatabase) -> None:
        self._database = database

    @property
    def database(self) -> PlanRevisionDatabase:
        """Return the composed database port for transaction sharing."""
        return self._database

    async def get_current_task_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> PlanningTaskSnapshot | None:
        """Read current task facts without applying restart semantics."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            row = await _select_task(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
        return _decode_task_snapshot(row)

    async def append(
        self,
        revision: PlanRevision,
        *,
        principal_id: str,
        project_id: str,
        created_at: str | None = None,
    ) -> StoredPlanRevision:
        """Atomically bind, sequence, and append one plan revision.

        The caller may provide only a draft envelope (empty id and sequence
        zero).  Durable identity, sequence, parent, and timestamp are assigned
        inside the database writer transaction.  There is intentionally no
        update, delete, or ``INSERT OR REPLACE`` path.
        """
        if type(revision) is not PlanRevision:
            raise TypeError("revision must be a PlanRevision")
        _validate_scope(
            task_id=revision.task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if revision.plan_revision_id or revision.revision_sequence:
            raise PlanRevisionConflictError(
                "only an unpersisted plan revision draft may be appended"
            )
        if revision.principal_id != principal_id or revision.project_id != project_id:
            raise PlanRevisionBindingError(
                "plan revision owner does not match the supplied scope"
            )
        timestamp = _validate_timestamp(created_at)

        try:
            async with self._database.transaction() as conn:
                task_row = await _select_task(
                    conn,
                    task_id=revision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_row is None:
                    raise PlanRevisionBindingError(
                        "task is unavailable in the supplied owner scope"
                    )
                task_snapshot = _decode_task_snapshot(task_row)
                if task_snapshot is None:
                    raise PlanRevisionIntegrityError(
                        "task snapshot disappeared during plan append"
                    )

                goal_row = await _select_goal_spec(conn, task_id=revision.task_id)
                if goal_row is None:
                    raise PlanRevisionBindingError("task has no durable GoalSpec")
                goal_spec = _decode_goal_spec_row(goal_row)
                if (
                    goal_row["task_id"] != revision.task_id
                    or goal_row["principal_id"] != principal_id
                    or goal_row["project_id"] != project_id
                ):
                    raise PlanRevisionBindingError(
                        "GoalSpec is not bound to the supplied task scope"
                    )
                _validate_revision_binding(
                    revision,
                    task_snapshot=task_snapshot,
                    goal_spec=goal_spec,
                    principal_id=principal_id,
                    project_id=project_id,
                )

                cursor = await conn.execute(
                    """
                    SELECT COALESCE(MAX(revision_sequence), 0) AS current_sequence,
                           (SELECT plan_revision_id
                              FROM agent_plan_revisions AS parent
                             WHERE parent.task_id = ?
                               AND parent.principal_id = ?
                               AND parent.project_id = ?
                             ORDER BY parent.revision_sequence DESC
                             LIMIT 1) AS current_parent_id
                    FROM agent_plan_revisions
                    WHERE task_id = ? AND principal_id = ? AND project_id = ?
                    """,
                    (
                        revision.task_id,
                        principal_id,
                        project_id,
                        revision.task_id,
                        principal_id,
                        project_id,
                    ),
                )
                sequence_row = await cursor.fetchone()
                if sequence_row is None or type(sequence_row["current_sequence"]) is not int:
                    raise PlanRevisionIntegrityError(
                        "plan revision sequence allocator returned an invalid value"
                    )
                current_sequence = sequence_row["current_sequence"]
                current_parent_id = sequence_row["current_parent_id"]
                if current_parent_id is not None and (
                    type(current_parent_id) is not str or not current_parent_id
                ):
                    raise PlanRevisionIntegrityError(
                        "plan revision ledger head has an invalid parent identity"
                    )
                # ``parent_revision_id`` is an optimistic history-head fence.
                # ``None`` is a meaningful expected value for the first
                # revision; it is not a wildcard that lets a stale planner
                # append after another revision has become the head.
                if revision.parent_revision_id != current_parent_id:
                    raise PlanRevisionConflictError(
                        "plan revision parent is not the current owner-scoped ledger head"
                    )
                plan_revision_id = _new_revision_id()
                revision_sequence = current_sequence + 1
                parent_revision_id = current_parent_id
                persisted = _materialize_revision(
                    revision,
                    plan_revision_id=plan_revision_id,
                    revision_sequence=revision_sequence,
                    parent_revision_id=parent_revision_id,
                    created_at=timestamp,
                )
                await conn.execute(
                    """
                    INSERT INTO agent_plan_revisions (
                        plan_revision_id, task_id, principal_id, project_id,
                        revision_sequence, parent_revision_id, schema_version,
                        planner_schema_version, planner_algorithm_version,
                        goal_spec_id, goal_spec_digest, workspace_id,
                        repository_id, base_revision, context_bundle_id,
                        context_bundle_digest, context_request_digest,
                        repository_generation, index_generation,
                        context_freshness, cognitive_state,
                        control_state_version, task_status, disposition,
                        planning_input_digest, plan_semantic_digest,
                        canonical_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        persisted.plan_revision_id,
                        persisted.task_id,
                        principal_id,
                        project_id,
                        persisted.revision_sequence,
                        persisted.parent_revision_id,
                        persisted.schema_version,
                        persisted.planner_schema_version,
                        persisted.planner_algorithm_version,
                        persisted.goal_spec_id,
                        persisted.goal_spec_digest,
                        persisted.workspace_id,
                        persisted.repository_id,
                        persisted.base_revision,
                        persisted.context_bundle_id,
                        persisted.context_bundle_digest,
                        persisted.context_request_digest,
                        persisted.repository_generation,
                        persisted.index_generation,
                        persisted.context_freshness.value,
                        persisted.cognitive_state.value,
                        persisted.control_state_version,
                        persisted.task_status,
                        persisted.disposition.value,
                        persisted.planning_input_digest,
                        persisted.plan_semantic_digest,
                        persisted.canonical_json(),
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise PlanRevisionConflictError(
                "plan revision identity or sequence conflicts with an existing row"
            ) from exc

        return StoredPlanRevision(
            revision=persisted,
            revision_sequence=persisted.revision_sequence,
            principal_id=principal_id,
            project_id=project_id,
            created_at=timestamp,
        )

    async def publish_ready_revision(
        self,
        plan_revision_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> PlanPublicationResult:
        """Atomically publish the exact current READY ledger head.

        The append and publication transactions are intentionally separate:
        append is immutable planning history, while this method is the focused
        publication fence.  The fence makes the following checks and writes
        one SQLite writer transaction so another planner cannot move the
        owner/task ledger head between validation and ``PLANNING`` to
        ``IMPLEMENTING`` publication:

        * the requested revision is the strict owner/task ledger head;
        * its canonical revision and GoalSpec bindings are intact;
        * its task snapshot is still the physical task snapshot; and
        * the cognitive CAS and ``published_plan_revision_id`` write commit
          together.

        A stale or conflicting attempt returns a typed result and never
        substitutes a newer revision.  Malformed durable rows raise the
        existing integrity errors and fail closed.
        """
        _validate_id(plan_revision_id, label="plan_revision_id")
        _validate_scope(
            task_id="lookup",
            principal_id=principal_id,
            project_id=project_id,
        )

        async with self._database.transaction() as conn:
            revision_row = await _select_revision_by_id(
                conn,
                plan_revision_id=plan_revision_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            stored = _decode_row(
                revision_row,
                expected_plan_revision_id=plan_revision_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                return PlanPublicationResult(
                    status=PlanPublicationStatus.NOT_FOUND,
                    task_id=None,
                    plan_revision_id=plan_revision_id,
                    reason="plan revision is unavailable in the supplied owner scope",
                )

            task_row = await _select_task(
                conn,
                task_id=stored.task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            task_snapshot = _decode_task_snapshot(task_row)
            if task_snapshot is None:
                return _publication_result(
                    PlanPublicationStatus.NOT_FOUND,
                    stored=stored,
                    reason="task is unavailable in the supplied owner scope",
                )

            if task_snapshot.task_status in {
                "completed",
                "failed",
                "cancelled",
            }:
                return _publication_result(
                    PlanPublicationStatus.TERMINAL,
                    stored=stored,
                    snapshot=task_snapshot,
                    reason="terminal task cannot publish a plan revision",
                )

            # Publication identity is write-once for the active cognitive
            # phase.  A repeated call for the same already-published revision
            # is an idempotent observation; a different revision can never
            # overwrite the causal identity.
            if task_snapshot.published_plan_revision_id is not None:
                if (
                    task_snapshot.published_plan_revision_id == plan_revision_id
                    and task_snapshot.cognitive_state
                    is AgentCognitiveState.IMPLEMENTING
                    and task_snapshot.control_state_version
                    == stored.revision.control_state_version + 1
                ):
                    return _publication_result(
                        PlanPublicationStatus.ALREADY_PUBLISHED,
                        stored=stored,
                        snapshot=task_snapshot,
                        reason="plan revision is already the published implementation plan",
                    )
                return _publication_result(
                    PlanPublicationStatus.CONFLICT,
                    stored=stored,
                    snapshot=task_snapshot,
                    reason="task already has a different published plan revision",
                )

            head_row = await _select_plan_head(
                conn,
                task_id=stored.task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            head = _decode_row(
                head_row,
                expected_task_id=stored.task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if head is None:
                return _publication_result(
                    PlanPublicationStatus.STALE,
                    stored=stored,
                    snapshot=task_snapshot,
                    reason="plan ledger head disappeared before publication",
                )
            if head.plan_revision_id != plan_revision_id:
                return _publication_result(
                    PlanPublicationStatus.STALE,
                    stored=stored,
                    snapshot=task_snapshot,
                    reason="requested plan revision is no longer the ledger head",
                )
            if head.revision.disposition is not PlanDisposition.READY:
                return _publication_result(
                    PlanPublicationStatus.INVALID,
                    stored=head,
                    snapshot=task_snapshot,
                    reason="only a READY plan revision may be published",
                )
            if head.revision.cognitive_state is not AgentCognitiveState.PLANNING:
                return _publication_result(
                    PlanPublicationStatus.STALE,
                    stored=head,
                    snapshot=task_snapshot,
                    reason="published plan snapshot is not bound to PLANNING",
                )
            if (
                AgentCognitiveStateMachine.validate_transition(
                    AgentCognitiveState.PLANNING,
                    AgentCognitiveState.IMPLEMENTING,
                )
                is CognitiveTransitionValidation.ILLEGAL
            ):
                return _publication_result(
                    PlanPublicationStatus.INVALID,
                    stored=head,
                    snapshot=task_snapshot,
                    reason="cognitive state machine rejects plan publication",
                )

            goal_row = await _select_goal_spec(conn, task_id=head.task_id)
            if goal_row is None:
                return _publication_result(
                    PlanPublicationStatus.INVALID,
                    stored=head,
                    snapshot=task_snapshot,
                    reason="task has no durable GoalSpec",
                )
            goal_spec = _decode_goal_spec_row(goal_row)
            if (
                goal_row["task_id"] != head.task_id
                or goal_row["principal_id"] != principal_id
                or goal_row["project_id"] != project_id
            ):
                return _publication_result(
                    PlanPublicationStatus.INVALID,
                    stored=head,
                    snapshot=task_snapshot,
                    reason="GoalSpec is not bound to the supplied task scope",
                )

            try:
                _validate_revision_binding(
                    head.revision,
                    task_snapshot=task_snapshot,
                    goal_spec=goal_spec,
                    principal_id=principal_id,
                    project_id=project_id,
                )
            except PlanRevisionStaleError as exc:
                return _publication_result(
                    PlanPublicationStatus.STALE,
                    stored=head,
                    snapshot=task_snapshot,
                    reason=str(exc),
                )
            except PlanRevisionBindingError as exc:
                return _publication_result(
                    PlanPublicationStatus.CONFLICT,
                    stored=head,
                    snapshot=task_snapshot,
                    reason=str(exc),
                )

            cursor = await conn.execute(
                """
                UPDATE coding_tasks
                   SET cognitive_state = ?,
                       control_state_version = control_state_version + 1,
                       published_plan_revision_id = ?
                 WHERE id = ?
                   AND principal_id = ?
                   AND project_id = ?
                   AND cognitive_state = ?
                   AND control_state_version = ?
                   AND status = ?
                   AND status NOT IN ('completed', 'failed', 'cancelled')
                   AND published_plan_revision_id IS NULL
                """,
                (
                    AgentCognitiveState.IMPLEMENTING.value,
                    head.plan_revision_id,
                    head.task_id,
                    principal_id,
                    project_id,
                    AgentCognitiveState.PLANNING.value,
                    head.revision.control_state_version,
                    head.revision.task_status,
                ),
            )
            if int(cursor.rowcount or 0) != 1:
                current_row = await _select_task(
                    conn,
                    task_id=head.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                current_snapshot = _decode_task_snapshot(current_row)
                if current_snapshot is None:
                    return _publication_result(
                        PlanPublicationStatus.NOT_FOUND,
                        stored=head,
                        reason="task disappeared during plan publication",
                    )
                if current_snapshot.task_status in {
                    "completed",
                    "failed",
                    "cancelled",
                }:
                    return _publication_result(
                        PlanPublicationStatus.TERMINAL,
                        stored=head,
                        snapshot=current_snapshot,
                        reason="task became terminal during plan publication",
                    )
                return _publication_result(
                    PlanPublicationStatus.STALE,
                    stored=head,
                    snapshot=current_snapshot,
                    reason="task snapshot changed during plan publication",
                )

            published_row = await _select_task(
                conn,
                task_id=head.task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            published_snapshot = _decode_task_snapshot(published_row)
            if published_snapshot is None:
                raise PlanRevisionIntegrityError(
                    "task disappeared after successful plan publication"
                )
            if (
                published_snapshot.cognitive_state
                is not AgentCognitiveState.IMPLEMENTING
                or published_snapshot.control_state_version
                != head.revision.control_state_version + 1
                or published_snapshot.published_plan_revision_id
                != head.plan_revision_id
            ):
                raise PlanRevisionIntegrityError(
                    "plan publication projection disagrees with the committed task row"
                )
            return _publication_result(
                PlanPublicationStatus.PUBLISHED,
                stored=head,
                snapshot=published_snapshot,
                reason="READY plan revision atomically published as IMPLEMENTING",
            )

    async def get_published_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredPlanRevision | None:
        """Read the exact durable published plan, never the latest fallback.

        ``None`` means the task has no published plan identity.  If the
        physical identity exists but its owner/task-scoped ledger row is
        missing or malformed, the method raises ``PlanRevisionIntegrityError``
        rather than silently returning the history head.
        """
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            task_row = await _select_task(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            task_snapshot = _decode_task_snapshot(task_row)
            if task_snapshot is None:
                return None
            published_id = task_snapshot.published_plan_revision_id
            if published_id is None:
                return None
            row = await _select_revision_by_id(
                conn,
                plan_revision_id=published_id,
                principal_id=principal_id,
                project_id=project_id,
                task_id=task_id,
            )
            stored = _decode_row(
                row,
                expected_plan_revision_id=published_id,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                raise PlanRevisionIntegrityError(
                    "published plan revision identity has no owner-scoped ledger row"
                )
            if stored.plan_revision_id != published_id:
                raise PlanRevisionIntegrityError(
                    "published plan revision identity disagrees with its ledger row"
                )
            return stored

    async def get_by_id(
        self,
        plan_revision_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredPlanRevision | None:
        """Read one revision only in the supplied owner scope."""
        _validate_id(plan_revision_id, label="plan_revision_id")
        _validate_scope(
            task_id="lookup",
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_plan_revisions
                WHERE plan_revision_id = ? AND principal_id = ? AND project_id = ?
                """,
                (plan_revision_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_plan_revision_id=plan_revision_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def get_latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredPlanRevision | None:
        """Read the ledger head by durable sequence, never by timestamp."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_plan_revisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY revision_sequence DESC
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
    ) -> list[StoredPlanRevision]:
        """Read all owner-scoped revisions in ascending sequence order."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_plan_revisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY revision_sequence ASC
                """,
                (task_id, principal_id, project_id),
            )
            rows = await cursor.fetchall()
        decoded: list[StoredPlanRevision] = []
        for row in rows:
            stored = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                raise PlanRevisionIntegrityError("plan revision row disappeared")
            decoded.append(stored)
        return decoded


def _new_revision_id() -> str:
    # Kept local so repository identity is server-generated and never comes
    # from model/caller input.  Importing uuid at module scope is unnecessary.
    import uuid

    return uuid.uuid4().hex


def _materialize_revision(
    revision: PlanRevision,
    *,
    plan_revision_id: str,
    revision_sequence: int,
    parent_revision_id: str | None,
    created_at: str,
) -> PlanRevision:
    from dataclasses import replace

    return replace(
        revision,
        plan_revision_id=plan_revision_id,
        revision_sequence=revision_sequence,
        parent_revision_id=parent_revision_id,
        created_at=created_at,
    )


async def _select_task(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT id, principal_id, project_id, status, cognitive_state,
               control_state_version, published_plan_revision_id, state_json
        FROM coding_tasks
        WHERE id = ? AND principal_id = ? AND project_id = ?
        """,
        (task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


async def _select_revision_by_id(
    conn: Any,
    *,
    plan_revision_id: str,
    principal_id: str,
    project_id: str,
    task_id: str | None = None,
) -> Any:
    task_clause = " AND task_id = ?" if task_id is not None else ""
    parameters: tuple[Any, ...]
    if task_id is None:
        parameters = (plan_revision_id, principal_id, project_id)
    else:
        parameters = (plan_revision_id, principal_id, project_id, task_id)
    cursor = await conn.execute(
        """
        SELECT * FROM agent_plan_revisions
        WHERE plan_revision_id = ? AND principal_id = ? AND project_id = ?
        """
        + task_clause,
        parameters,
    )
    return await cursor.fetchone()


async def _select_plan_head(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_plan_revisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        ORDER BY revision_sequence DESC
        LIMIT 1
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


def _decode_task_snapshot(row: Any) -> PlanningTaskSnapshot | None:
    if row is None:
        return None
    try:
        task_id = row["id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        task_status = row["status"]
        raw_state = row["cognitive_state"]
        version = row["control_state_version"]
        if any(type(value) is not str or not value for value in (task_id, principal_id)):
            raise PlanRevisionIntegrityError("task identity projection is malformed")
        if type(project_id) is not str or type(task_status) is not str or not task_status:
            raise PlanRevisionIntegrityError("task owner/status projection is malformed")
        try:
            cognitive_state = AgentCognitiveState.parse(raw_state)
        except (TypeError, ValueError) as exc:
            raise PlanRevisionIntegrityError("task cognitive_state is malformed") from exc
        if type(version) is not int or version < 0:
            raise PlanRevisionIntegrityError("task control_state_version is malformed")
        state = _decode_state_json(row["state_json"])
        metadata = state.get("metadata", {})
        workspace_id = metadata.get("workspace_id")
        base_revision = metadata.get("base_sha")
        repository_id = metadata.get("repository_id")
        published_plan_revision_id = row["published_plan_revision_id"]
        for name, value in (
            ("workspace_id", workspace_id),
            ("base_sha", base_revision),
            ("repository_id", repository_id),
            ("published_plan_revision_id", published_plan_revision_id),
        ):
            if value is not None and (type(value) is not str or not value):
                raise PlanRevisionIntegrityError(
                    f"task metadata {name} projection is malformed"
                )
        return PlanningTaskSnapshot(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
            cognitive_state=cognitive_state,
            control_state_version=version,
            task_status=task_status,
            workspace_id=workspace_id,
            base_revision=base_revision,
            repository_id=repository_id,
            published_plan_revision_id=published_plan_revision_id,
        )
    except PlanRevisionIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanRevisionIntegrityError("task snapshot failed integrity validation") from exc


def _decode_state_json(value: Any) -> dict[str, Any]:
    if type(value) is not str:
        raise PlanRevisionIntegrityError("task state_json is not text")
    try:
        state = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PlanRevisionIntegrityError("task state_json is malformed") from exc
    if type(state) is not dict:
        raise PlanRevisionIntegrityError("task state_json root is not an object")
    metadata = state.get("metadata", {})
    if type(metadata) is not dict:
        raise PlanRevisionIntegrityError("task metadata is not an object")
    state["metadata"] = metadata
    return state


def _decode_goal_spec_row(row: Any) -> GoalSpec:
    if row is None:
        raise PlanRevisionBindingError("task has no durable GoalSpec")
    try:
        values = {
            "goal_spec_id": row["goal_spec_id"],
            "task_id": row["task_id"],
            "principal_id": row["principal_id"],
            "project_id": row["project_id"],
            "schema_version": row["schema_version"],
            "semantic_digest": row["semantic_digest"],
            "canonical_json": row["canonical_json"],
        }
        if any(type(values[name]) is not str or not values[name] for name in (
            "goal_spec_id", "task_id", "principal_id", "semantic_digest", "canonical_json"
        )) or type(values["project_id"]) is not str or type(values["schema_version"]) is not int:
            raise GoalSpecIntegrityError("GoalSpec row has malformed scalar fields")
        spec = GoalSpec.from_canonical_json(
            values["canonical_json"],
            expected_digest=values["semantic_digest"],
        )
        if spec.goal_spec_id != values["goal_spec_id"] or spec.schema_version != values["schema_version"]:
            raise GoalSpecIntegrityError("GoalSpec row disagrees with canonical JSON")
        if spec.goal_spec_id != values["goal_spec_id"] or values["task_id"] == "":
            raise GoalSpecIntegrityError("GoalSpec identity is malformed")
        return spec
    except (GoalSpecIntegrityError, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, GoalSpecIntegrityError):
            raise PlanRevisionIntegrityError(str(exc)) from exc
        raise PlanRevisionIntegrityError("GoalSpec row failed integrity validation") from exc


def _validate_revision_binding(
    revision: PlanRevision,
    *,
    task_snapshot: PlanningTaskSnapshot,
    goal_spec: GoalSpec,
    principal_id: str,
    project_id: str,
) -> None:
    if revision.task_id != task_snapshot.task_id:
        raise PlanRevisionBindingError("plan task identity does not match current task")
    if revision.principal_id != principal_id or revision.project_id != project_id:
        raise PlanRevisionBindingError("plan owner does not match current scope")
    if revision.goal_spec_id != goal_spec.goal_spec_id or revision.goal_spec_digest != goal_spec.semantic_digest:
        raise PlanRevisionBindingError("plan GoalSpec binding is stale or mismatched")
    if revision.cognitive_state is not task_snapshot.cognitive_state:
        raise PlanRevisionStaleError("plan cognitive state is stale")
    if revision.control_state_version != task_snapshot.control_state_version:
        raise PlanRevisionStaleError("plan cognitive-state version is stale")
    if revision.task_status != task_snapshot.task_status:
        raise PlanRevisionStaleError("plan task status is stale")
    if task_snapshot.workspace_id != revision.workspace_id:
        raise PlanRevisionStaleError("plan workspace binding is stale")
    if task_snapshot.base_revision != revision.base_revision:
        raise PlanRevisionStaleError("plan base revision binding is stale")
    if task_snapshot.repository_id != revision.repository_id:
        raise PlanRevisionStaleError("plan repository identity is stale or unavailable")


def _decode_row(
    row: Any,
    *,
    expected_plan_revision_id: str | None = None,
    expected_task_id: str | None = None,
    expected_principal_id: str | None = None,
    expected_project_id: str | None = None,
) -> StoredPlanRevision | None:
    if row is None:
        return None
    try:
        plan_revision_id = row["plan_revision_id"]
        task_id = row["task_id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        sequence = row["revision_sequence"]
        canonical_json = row["canonical_json"]
        created_at = row["created_at"]
        if any(type(value) is not str or not value for value in (
            plan_revision_id, task_id, principal_id, canonical_json, created_at
        )) or type(project_id) is not str:
            raise PlanRevisionIntegrityError("plan revision row identity is malformed")
        if type(sequence) is not int or sequence < 1:
            raise PlanRevisionIntegrityError("plan revision sequence is malformed")
        expected_values = (
            (expected_plan_revision_id, plan_revision_id, "plan revision id"),
            (expected_task_id, task_id, "task id"),
            (expected_principal_id, principal_id, "principal id"),
            (expected_project_id, project_id, "project id"),
        )
        for expected, actual, label in expected_values:
            if expected is not None and expected != actual:
                raise PlanRevisionIntegrityError(f"stored {label} disagrees with lookup")
        revision = plan_revision_from_canonical_json(
            canonical_json,
            expected_digest=row["plan_semantic_digest"],
        )
        if (
            revision.plan_revision_id != plan_revision_id
            or revision.task_id != task_id
            or revision.principal_id != principal_id
            or revision.project_id != project_id
            or revision.revision_sequence != sequence
            or revision.parent_revision_id != row["parent_revision_id"]
            or revision.created_at != created_at
        ):
            raise PlanRevisionIntegrityError("plan revision envelope disagrees with canonical JSON")
        _validate_scalar_columns(row, revision)
        return StoredPlanRevision(
            revision=revision,
            revision_sequence=sequence,
            principal_id=principal_id,
            project_id=project_id,
            created_at=created_at,
        )
    except PlanRevisionIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, PlanningContractError) as exc:
        raise PlanRevisionIntegrityError("stored plan revision failed integrity validation") from exc


def _validate_scalar_columns(row: Any, revision: PlanRevision) -> None:
    pairs = (
        (row["schema_version"], revision.schema_version, "schema_version"),
        (row["planner_schema_version"], revision.planner_schema_version, "planner_schema_version"),
        (row["planner_algorithm_version"], revision.planner_algorithm_version, "planner_algorithm_version"),
        (row["goal_spec_id"], revision.goal_spec_id, "goal_spec_id"),
        (row["goal_spec_digest"], revision.goal_spec_digest, "goal_spec_digest"),
        (row["workspace_id"], revision.workspace_id, "workspace_id"),
        (row["repository_id"], revision.repository_id, "repository_id"),
        (row["base_revision"], revision.base_revision, "base_revision"),
        (row["context_bundle_id"], revision.context_bundle_id, "context_bundle_id"),
        (row["context_bundle_digest"], revision.context_bundle_digest, "context_bundle_digest"),
        (row["context_request_digest"], revision.context_request_digest, "context_request_digest"),
        (row["repository_generation"], revision.repository_generation, "repository_generation"),
        (row["index_generation"], revision.index_generation, "index_generation"),
        (row["context_freshness"], revision.context_freshness.value, "context_freshness"),
        (row["cognitive_state"], revision.cognitive_state.value, "cognitive_state"),
        (row["control_state_version"], revision.control_state_version, "control_state_version"),
        (row["task_status"], revision.task_status, "task_status"),
        (row["disposition"], revision.disposition.value, "disposition"),
        (row["planning_input_digest"], revision.planning_input_digest, "planning_input_digest"),
        (row["plan_semantic_digest"], revision.plan_semantic_digest, "plan_semantic_digest"),
    )
    for actual, expected, label in pairs:
        if actual != expected:
            raise PlanRevisionIntegrityError(f"stored {label} disagrees with canonical JSON")


def _validate_scope(*, task_id: str, principal_id: str, project_id: str) -> None:
    _validate_id(task_id, label="task_id")
    _validate_id(principal_id, label="principal_id")
    if type(project_id) is not str:
        raise ValueError("project_id must be a string")


def _publication_result(
    status: PlanPublicationStatus,
    *,
    stored: StoredPlanRevision,
    snapshot: PlanningTaskSnapshot | None = None,
    reason: str = "",
) -> PlanPublicationResult:
    """Build a bounded publication result from one durable observation."""
    return PlanPublicationResult(
        status=status,
        task_id=stored.task_id,
        plan_revision_id=stored.plan_revision_id,
        revision_sequence=stored.revision_sequence,
        published_plan_revision_id=(
            snapshot.published_plan_revision_id if snapshot is not None else None
        ),
        cognitive_state=(snapshot.cognitive_state if snapshot is not None else None),
        control_state_version=(
            snapshot.control_state_version if snapshot is not None else None
        ),
        task_status=snapshot.task_status if snapshot is not None else None,
        reason=reason,
    )


def _validate_id(value: str, *, label: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a non-empty string")


def _validate_timestamp(value: str | None) -> str:
    if value is None:
        from khaos.time_utils import utc_now_naive

        return utc_now_naive().isoformat()
    if type(value) is not str or not value:
        raise ValueError("created_at must be a non-empty string")
    return value


__all__ = [
    "PlanPublicationResult",
    "PlanPublicationStatus",
    "PlanRevisionBindingError",
    "PlanRevisionConflictError",
    "PlanRevisionDatabase",
    "PlanRevisionIntegrityError",
    "PlanRevisionRepository",
    "PlanRevisionRepositoryError",
    "PlanRevisionStaleError",
    "PlanningTaskSnapshot",
    "StoredPlanRevision",
]
