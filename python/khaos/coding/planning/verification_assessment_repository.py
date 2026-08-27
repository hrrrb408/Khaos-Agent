"""Owner-scoped durable storage for trusted verification assessments.

This repository is the publication boundary for M7.4 assessment history.  It
does not execute verification and it does not project a result onto
``TaskStatus``.  It binds an assessment to the physical task, canonical
GoalSpec, and (when present) the exact published plan revision inside one
database transaction.  A separate current-snapshot reader is required before
a positive assessment is exposed as a current completion fact.

The repository intentionally has no unscoped reads and no update/delete API.
The immutable canonical payload remains the semantic source; duplicated SQL
columns are checked against it on every read so corruption fails closed.
"""

from __future__ import annotations

import inspect
import json
import re
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from typing import Any, Protocol

from khaos.agent.control.goal import GoalSpec, GoalSpecValidationError
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.revision import (
    PlanningContractError,
    plan_revision_from_canonical_json,
)
from khaos.coding.planning.verification_assessment import (
    VERIFICATION_ALGORITHM_VERSION,
    VerificationAssessment,
    VerificationAssessmentDisposition,
    VerificationContractError,
)
from khaos.time_utils import utc_now_naive

_SHA256_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


def _require_non_empty_text(value: object, *, label: str) -> None:
    if type(value) is not str or not value:
        raise VerificationContractError(f"{label} must be a non-empty string")


def _require_sha256(value: object, *, label: str) -> None:
    if type(value) is not str or _SHA256_DIGEST.fullmatch(value) is None:
        raise VerificationContractError(f"{label} must be a SHA-256 hex digest")


class VerificationAssessmentDatabase(Protocol):
    """Minimal database port required by the assessment repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared single-writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class VerificationAssessmentRepositoryError(RuntimeError):
    """Base error for durable trusted-verification assessment operations."""


class VerificationAssessmentBindingError(VerificationAssessmentRepositoryError):
    """The assessment is not bound to the supplied owner/task snapshot."""


class VerificationAssessmentConflictError(VerificationAssessmentRepositoryError):
    """An immutable assessment identity or sequence conflicts with a row."""


class VerificationAssessmentIntegrityError(VerificationAssessmentRepositoryError):
    """A durable task, GoalSpec, plan, or assessment row is malformed."""


class VerificationAssessmentUnavailableError(VerificationAssessmentRepositoryError):
    """Current trusted-verification freshness evidence is unavailable."""


@dataclass(frozen=True, slots=True)
class VerificationTaskSnapshot:
    """Owner-scoped physical task facts used for assessment binding.

    Lifecycle/cognitive values come from physical SQL columns.  Workspace,
    base, and repository values are decoded from the existing task metadata
    projection solely for identity consistency; they do not grant access.
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
    published_plan_revision_id: str | None


@dataclass(frozen=True, slots=True)
class VerificationCurrentSnapshot:
    """Current post-change snapshot supplied by an audited evidence owner.

    The repository can validate task/GoalSpec/plan identity itself.  It must
    not invent a repository generation, change identity, policy digest, or
    catalog fingerprint; those fields therefore come from an explicit
    current-snapshot adapter before a positive assessment is projected.
    """

    task_id: str
    principal_id: str
    project_id: str
    goal_spec_id: str
    goal_spec_digest: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str
    repository_id: str
    base_revision: str | None
    published_plan_revision_id: str | None
    published_plan_revision_digest: str | None
    repository_generation: str | None
    change_identity: str | None
    policy_digest: str
    catalog_fingerprint: str
    verification_algorithm_version: str = VERIFICATION_ALGORITHM_VERSION

    def __post_init__(self) -> None:
        """Reject malformed currentness facts before they can be compared."""
        for label, value in (
            ("task_id", self.task_id),
            ("principal_id", self.principal_id),
            ("goal_spec_id", self.goal_spec_id),
            ("workspace_id", self.workspace_id),
            ("repository_id", self.repository_id),
            ("policy_digest", self.policy_digest),
            ("catalog_fingerprint", self.catalog_fingerprint),
            ("verification_algorithm_version", self.verification_algorithm_version),
        ):
            _require_non_empty_text(value, label=label)
        if type(self.project_id) is not str:
            raise VerificationContractError("project_id must be a string")
        _require_sha256(self.goal_spec_digest, label="goal_spec_digest")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise VerificationContractError(
                "cognitive_state must be an AgentCognitiveState"
            )
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise VerificationContractError(
                "control_state_version must be a non-negative integer"
            )
        _require_non_empty_text(self.task_status, label="task_status")
        if self.base_revision is not None:
            _require_non_empty_text(self.base_revision, label="base_revision")
        if self.published_plan_revision_id is None:
            if self.published_plan_revision_digest is not None:
                raise VerificationContractError(
                    "published plan digest requires a published plan identity"
                )
        else:
            _require_non_empty_text(
                self.published_plan_revision_id,
                label="published_plan_revision_id",
            )
            _require_sha256(
                self.published_plan_revision_digest,
                label="published_plan_revision_digest",
            )
        if self.repository_generation is None and self.change_identity is None:
            raise VerificationContractError(
                "post-change repository_generation or change_identity is required"
            )
        if self.repository_generation is not None:
            _require_non_empty_text(
                self.repository_generation, label="repository_generation"
            )
        if self.change_identity is not None:
            _require_non_empty_text(self.change_identity, label="change_identity")
        _require_sha256(self.policy_digest, label="policy_digest")
        _require_sha256(self.catalog_fingerprint, label="catalog_fingerprint")


class VerificationCurrentSnapshotReader(Protocol):
    """Read current post-change identity from an audited authority owner."""

    async def read_current_snapshot(
        self,
        *,
        connection: Any,
        assessment: VerificationAssessment,
    ) -> VerificationCurrentSnapshot | None:
        """Return current facts, or ``None`` when freshness is unavailable."""
        ...


@dataclass(frozen=True, slots=True)
class StoredVerificationAssessment:
    """Immutable assessment plus its durable owner/task sequence envelope."""

    assessment: VerificationAssessment
    assessment_sequence: int
    principal_id: str
    project_id: str
    created_at: str

    @property
    def assessment_id(self) -> str:
        """Return the immutable assessment identity."""
        return self.assessment.assessment_id

    @property
    def task_id(self) -> str:
        """Return the owner-bound task identity."""
        return self.assessment.task_id

    @property
    def disposition(self) -> VerificationAssessmentDisposition:
        """Return the aggregate trusted-verification disposition."""
        return self.assessment.disposition

    @property
    def assessment_digest(self) -> str:
        """Return the semantic assessment digest."""
        return self.assessment.assessment_digest


class VerificationAssessmentRepository:
    """Append and read immutable assessments inside an authenticated scope."""

    def __init__(
        self,
        database: VerificationAssessmentDatabase,
        *,
        current_snapshot_reader: VerificationCurrentSnapshotReader | None = None,
    ) -> None:
        self._database = database
        self._current_snapshot_reader = current_snapshot_reader

    @property
    def database(self) -> VerificationAssessmentDatabase:
        """Return the composed database port for explicit transaction sharing."""
        return self._database

    async def append(
        self,
        assessment: VerificationAssessment,
        *,
        principal_id: str,
        project_id: str,
        created_at: str | None = None,
    ) -> StoredVerificationAssessment:
        """Atomically bind, sequence, and append one immutable assessment.

        The caller may only append the in-memory draft returned by the
        authority (sequence zero).  Sequence allocation and all owner/task
        binding checks occur under the shared SQLite writer transaction.  A
        positive assessment is still history until ``get_current_for_task``
        revalidates it through an explicit current-snapshot reader.
        """
        if type(assessment) is not VerificationAssessment:
            raise TypeError("assessment must be a VerificationAssessment")
        _validate_scope(
            task_id=assessment.task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if assessment.assessment_sequence != 0:
            raise VerificationAssessmentConflictError(
                "only an unpersisted assessment draft may be appended"
            )
        if (
            assessment.principal_id != principal_id
            or assessment.project_id != project_id
        ):
            raise VerificationAssessmentBindingError(
                "assessment owner does not match the supplied scope"
            )
        timestamp = _validate_timestamp(created_at)

        try:
            async with self._database.transaction() as conn:
                task_row = await _select_task(
                    conn,
                    task_id=assessment.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_row is None:
                    raise VerificationAssessmentBindingError(
                        "task is unavailable in the supplied owner scope"
                    )
                task_snapshot = _decode_task_snapshot(task_row)

                goal_row = await _select_goal_spec(conn, task_id=assessment.task_id)
                if goal_row is None:
                    raise VerificationAssessmentBindingError(
                        "task has no durable GoalSpec"
                    )
                goal_spec = _decode_goal_spec_row(goal_row)
                if not _owner_task_matches(
                    goal_row,
                    task_id=assessment.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                ):
                    raise VerificationAssessmentBindingError(
                        "GoalSpec is not bound to the supplied task scope"
                    )

                _validate_assessment_binding(
                    assessment,
                    task_snapshot=task_snapshot,
                    goal_spec=goal_spec,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if (
                    assessment.disposition
                    is VerificationAssessmentDisposition.SATISFIED
                    and task_snapshot.task_status in _TERMINAL_TASK_STATUSES
                ):
                    raise VerificationAssessmentBindingError(
                        "positive verification cannot bind a terminal task"
                    )
                if task_snapshot.published_plan_revision_id is not None:
                    plan_row = await _select_published_plan(
                        conn,
                        plan_revision_id=task_snapshot.published_plan_revision_id,
                        task_id=assessment.task_id,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    published_plan_id, published_plan_digest = _decode_plan_binding(
                        plan_row
                    )
                    if (
                        assessment.published_plan_revision_id != published_plan_id
                        or assessment.published_plan_revision_digest
                        != published_plan_digest
                    ):
                        raise VerificationAssessmentBindingError(
                            "assessment published plan digest is stale or mismatched"
                        )

                if self._current_snapshot_reader is not None:
                    current = await _read_current_snapshot(
                        self._current_snapshot_reader,
                        connection=conn,
                        assessment=assessment,
                    )
                    if (
                        current is None
                        and assessment.disposition
                        is VerificationAssessmentDisposition.SATISFIED
                    ):
                        raise VerificationAssessmentUnavailableError(
                            "current trusted-verification snapshot is unavailable"
                        )
                    if current is not None and not _current_matches_assessment(
                        current, assessment
                    ):
                        raise VerificationAssessmentBindingError(
                            "assessment current snapshot is stale or mismatched"
                        )

                cursor = await conn.execute(
                    """
                    SELECT COALESCE(MAX(assessment_sequence), 0) + 1
                           AS next_sequence
                    FROM agent_verification_assessments
                    WHERE task_id = ? AND principal_id = ? AND project_id = ?
                    """,
                    (assessment.task_id, principal_id, project_id),
                )
                sequence_row = await cursor.fetchone()
                if (
                    sequence_row is None
                    or type(sequence_row["next_sequence"]) is not int
                    or sequence_row["next_sequence"] < 1
                ):
                    raise VerificationAssessmentIntegrityError(
                        "assessment sequence allocator returned an invalid value"
                    )
                assessment_sequence = sequence_row["next_sequence"]
                persisted = replace(
                    assessment,
                    assessment_sequence=assessment_sequence,
                    created_at=timestamp,
                )
                await conn.execute(
                    """
                    INSERT INTO agent_verification_assessments (
                        assessment_id, task_id, principal_id, project_id,
                        assessment_sequence, schema_version,
                        goal_spec_id, goal_spec_digest, cognitive_state,
                        control_state_version, task_status, workspace_id,
                        repository_id, base_revision,
                        published_plan_revision_id,
                        published_plan_revision_digest, repository_generation,
                        change_identity, policy_digest, catalog_fingerprint,
                        verification_algorithm_version, input_digest,
                        disposition, assessment_digest,
                        canonical_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                              ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        persisted.assessment_id,
                        persisted.task_id,
                        principal_id,
                        project_id,
                        persisted.assessment_sequence,
                        persisted.schema_version,
                        persisted.goal_spec_id,
                        persisted.goal_spec_digest,
                        persisted.cognitive_state.value,
                        persisted.control_state_version,
                        persisted.task_status,
                        persisted.workspace_id,
                        persisted.repository_id,
                        persisted.base_revision,
                        persisted.published_plan_revision_id,
                        persisted.published_plan_revision_digest,
                        persisted.repository_generation,
                        persisted.change_identity,
                        persisted.policy_digest,
                        persisted.catalog_fingerprint,
                        persisted.verification_algorithm_version,
                        persisted.input_digest,
                        persisted.disposition.value,
                        persisted.assessment_digest,
                        persisted.canonical_json(),
                        timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise VerificationAssessmentConflictError(
                "verification assessment identity or sequence conflicts with an existing row"
            ) from exc

        return StoredVerificationAssessment(
            assessment=persisted,
            assessment_sequence=persisted.assessment_sequence,
            principal_id=principal_id,
            project_id=project_id,
            created_at=timestamp,
        )

    async def get_by_id(
        self,
        assessment_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredVerificationAssessment | None:
        """Read one assessment only in the supplied owner scope."""
        _validate_lookup_id(assessment_id, label="assessment_id")
        _validate_scope(
            task_id="lookup", principal_id=principal_id, project_id=project_id
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_verification_assessments
                WHERE assessment_id = ? AND principal_id = ? AND project_id = ?
                """,
                (assessment_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_assessment_id=assessment_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def get_latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredVerificationAssessment | None:
        """Read the owner/task ledger head by durable sequence."""
        _validate_scope(
            task_id=task_id, principal_id=principal_id, project_id=project_id
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_verification_assessments
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY assessment_sequence DESC
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
    ) -> list[StoredVerificationAssessment]:
        """Read every owner/task assessment in ascending durable order."""
        _validate_scope(
            task_id=task_id, principal_id=principal_id, project_id=project_id
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_verification_assessments
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY assessment_sequence ASC
                """,
                (task_id, principal_id, project_id),
            )
            rows = await cursor.fetchall()
        decoded: list[StoredVerificationAssessment] = []
        for row in rows:
            stored = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                raise VerificationAssessmentIntegrityError(
                    "stored assessment row disappeared during read"
                )
            decoded.append(stored)
        return decoded

    async def get_current_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredVerificationAssessment | None:
        """Return the current assessment only after freshness validation.

        Negative history is safe to expose as a narrowing fact after the
        physical task binding has been checked.  A positive assessment is
        never current without an explicit audited snapshot reader; the
        default production composition therefore fails closed rather than
        treating a persisted ``SATISFIED`` row as a bearer capability.
        """
        # The latest assessment, task row, GoalSpec, and optional current
        # snapshot are checked through one writer transaction.  This prevents
        # a newer assessment from being appended between a separate latest
        # read and the currentness check, which could otherwise expose an old
        # positive record as the ledger head.
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_verification_assessments
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY assessment_sequence DESC
                LIMIT 1
                """,
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
            stored = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                return None
            task_row = await _select_task(
                conn,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            if task_row is None:
                return None
            task_snapshot = _decode_task_snapshot(task_row)
            goal_row = await _select_goal_spec(conn, task_id=task_id)
            if goal_row is None or not _owner_task_matches(
                goal_row,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
            ):
                return None
            goal_spec = _decode_goal_spec_row(goal_row)
            try:
                _validate_assessment_binding(
                    stored.assessment,
                    task_snapshot=task_snapshot,
                    goal_spec=goal_spec,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                if task_snapshot.published_plan_revision_id is not None:
                    plan_row = await _select_published_plan(
                        conn,
                        plan_revision_id=task_snapshot.published_plan_revision_id,
                        task_id=task_id,
                        principal_id=principal_id,
                        project_id=project_id,
                    )
                    plan_id, plan_digest = _decode_plan_binding(plan_row)
                    if (
                        stored.assessment.published_plan_revision_id != plan_id
                        or stored.assessment.published_plan_revision_digest
                        != plan_digest
                    ):
                        return None
            except VerificationAssessmentBindingError:
                return None
            if stored.disposition is not VerificationAssessmentDisposition.SATISFIED:
                return stored
            if task_snapshot.task_status in _TERMINAL_TASK_STATUSES:
                return None
            if self._current_snapshot_reader is None:
                return None
            current = await _read_current_snapshot(
                self._current_snapshot_reader,
                connection=conn,
                assessment=stored.assessment,
            )
        if current is None or not _current_matches_assessment(current, stored.assessment):
            return None
        return stored

    async def is_current(
        self,
        assessment: VerificationAssessment,
        *,
        principal_id: str,
        project_id: str,
    ) -> bool:
        """Return whether a positive assessment matches current audited facts."""
        if type(assessment) is not VerificationAssessment:
            raise TypeError("assessment must be a VerificationAssessment")
        _validate_scope(
            task_id=assessment.task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if assessment.principal_id != principal_id or assessment.project_id != project_id:
            return False
        if self._current_snapshot_reader is None:
            return False
        async with self._database.read_connection() as conn:
            current = await _read_current_snapshot(
                self._current_snapshot_reader,
                connection=conn,
                assessment=assessment,
            )
        return current is not None and _current_matches_assessment(current, assessment)


async def _read_current_snapshot(
    reader: VerificationCurrentSnapshotReader,
    *,
    connection: Any,
    assessment: VerificationAssessment,
) -> VerificationCurrentSnapshot | None:
    try:
        value = reader.read_current_snapshot(
            connection=connection,
            assessment=assessment,
        )
        if inspect.isawaitable(value):
            value = await value
    except (TypeError, ValueError, VerificationContractError) as exc:
        raise VerificationAssessmentIntegrityError(
            "current snapshot reader returned malformed facts"
        ) from exc
    if value is not None and type(value) is not VerificationCurrentSnapshot:
        raise VerificationAssessmentIntegrityError(
            "current snapshot reader returned an invalid value"
        )
    return value


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
               control_state_version, status, published_plan_revision_id,
               state_json
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


async def _select_published_plan(
    conn: Any,
    *,
    plan_revision_id: str,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_plan_revisions
        WHERE plan_revision_id = ? AND task_id = ?
          AND principal_id = ? AND project_id = ?
        """,
        (plan_revision_id, task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


def _decode_task_snapshot(row: Any) -> VerificationTaskSnapshot:
    if row is None:
        raise VerificationAssessmentBindingError("task is unavailable")
    try:
        task_id = row["id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        cognitive_state = AgentCognitiveState.parse(row["cognitive_state"])
        control_state_version = row["control_state_version"]
        task_status = row["status"]
        published_plan_revision_id = row["published_plan_revision_id"]
        state_json = row["state_json"]
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationAssessmentIntegrityError(
            "coding task control-state snapshot is malformed"
        ) from exc
    if (
        type(task_id) is not str
        or not task_id
        or type(principal_id) is not str
        or not principal_id
        or type(project_id) is not str
        or type(control_state_version) is not int
        or control_state_version < 0
        or type(task_status) is not str
        or not task_status
    ):
        raise VerificationAssessmentIntegrityError(
            "coding task identity, version, or status is malformed"
        )
    if published_plan_revision_id is not None and (
        type(published_plan_revision_id) is not str or not published_plan_revision_id
    ):
        raise VerificationAssessmentIntegrityError(
            "published plan revision identity is malformed"
        )
    workspace_id, base_revision, repository_id = _decode_task_metadata(state_json)
    return VerificationTaskSnapshot(
        task_id=task_id,
        principal_id=principal_id,
        project_id=project_id,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
        workspace_id=workspace_id,
        base_revision=base_revision,
        repository_id=repository_id,
        published_plan_revision_id=published_plan_revision_id,
    )


def _decode_task_metadata(value: Any) -> tuple[str | None, str | None, str | None]:
    if type(value) is not str:
        raise VerificationAssessmentIntegrityError("task state_json is not text")
    try:
        state = json.loads(value)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        raise VerificationAssessmentIntegrityError(
            "task state_json is malformed"
        ) from exc
    if type(state) is not dict:
        raise VerificationAssessmentIntegrityError("task state_json is not an object")
    metadata = state.get("metadata", {})
    if type(metadata) is not dict:
        raise VerificationAssessmentIntegrityError("task metadata is not an object")
    values: list[str | None] = []
    for key in ("workspace_id", "base_sha", "repository_id"):
        raw = metadata.get(key)
        if raw is not None and (type(raw) is not str or not raw):
            raise VerificationAssessmentIntegrityError(
                f"task metadata {key} projection is malformed"
            )
        values.append(raw)
    return values[0], values[1], values[2]


def _decode_goal_spec_row(row: Any) -> GoalSpec:
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
    except (KeyError, TypeError) as exc:
        raise VerificationAssessmentIntegrityError(
            "GoalSpec binding row is malformed"
        ) from exc
    if (
        type(values["goal_spec_id"]) is not str
        or not values["goal_spec_id"]
        or type(values["task_id"]) is not str
        or not values["task_id"]
        or type(values["principal_id"]) is not str
        or not values["principal_id"]
        or type(values["project_id"]) is not str
        or type(values["schema_version"]) is not int
        or type(values["semantic_digest"]) is not str
        or not values["semantic_digest"]
        or type(values["canonical_json"]) is not str
    ):
        raise VerificationAssessmentIntegrityError("GoalSpec binding row is invalid")
    try:
        spec = GoalSpec.from_canonical_json(
            values["canonical_json"],
            expected_digest=values["semantic_digest"],
        )
    except (GoalSpecValidationError, TypeError, ValueError) as exc:
        raise VerificationAssessmentIntegrityError(
            "GoalSpec binding payload failed integrity validation"
        ) from exc
    if (
        spec.schema_version != values["schema_version"]
        or spec.goal_spec_id != values["goal_spec_id"]
    ):
        raise VerificationAssessmentIntegrityError(
            "GoalSpec row disagrees with canonical payload"
        )
    return spec


def _validate_assessment_binding(
    assessment: VerificationAssessment,
    *,
    task_snapshot: VerificationTaskSnapshot,
    goal_spec: GoalSpec,
    principal_id: str,
    project_id: str,
) -> None:
    if assessment.task_id != task_snapshot.task_id:
        raise VerificationAssessmentBindingError("assessment task identity mismatch")
    if assessment.principal_id != principal_id or assessment.project_id != project_id:
        raise VerificationAssessmentBindingError("assessment owner binding mismatch")
    if assessment.goal_spec_id != goal_spec.goal_spec_id:
        raise VerificationAssessmentBindingError("assessment GoalSpec identity mismatch")
    if assessment.goal_spec_digest != goal_spec.semantic_digest:
        raise VerificationAssessmentBindingError("assessment GoalSpec digest mismatch")
    if assessment.cognitive_state is not task_snapshot.cognitive_state:
        raise VerificationAssessmentBindingError("assessment cognitive state is stale")
    if assessment.control_state_version != task_snapshot.control_state_version:
        raise VerificationAssessmentBindingError(
            "assessment cognitive-state version is stale"
        )
    if assessment.task_status != task_snapshot.task_status:
        raise VerificationAssessmentBindingError("assessment task status is stale")
    if assessment.workspace_id != task_snapshot.workspace_id:
        raise VerificationAssessmentBindingError("assessment workspace is stale")
    if assessment.repository_id != task_snapshot.repository_id:
        raise VerificationAssessmentBindingError("assessment repository is stale")
    if assessment.base_revision != task_snapshot.base_revision:
        raise VerificationAssessmentBindingError("assessment base revision is stale")
    if assessment.published_plan_revision_id != task_snapshot.published_plan_revision_id:
        raise VerificationAssessmentBindingError("assessment published plan is stale")


def _owner_task_matches(
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


def _decode_plan_binding(row: Any) -> tuple[str, str]:
    if row is None:
        raise VerificationAssessmentBindingError(
            "published plan revision is unavailable"
        )
    try:
        plan_revision_id = row["plan_revision_id"]
        task_id = row["task_id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        revision_sequence = row["revision_sequence"]
        digest = row["plan_semantic_digest"]
        canonical_json = row["canonical_json"]
    except (KeyError, TypeError) as exc:
        raise VerificationAssessmentIntegrityError(
            "published plan row is malformed"
        ) from exc
    if (
        type(plan_revision_id) is not str
        or not plan_revision_id
        or type(task_id) is not str
        or not task_id
        or type(principal_id) is not str
        or not principal_id
        or type(project_id) is not str
        or type(revision_sequence) is not int
        or revision_sequence < 1
        or type(digest) is not str
        or not digest
        or type(canonical_json) is not str
    ):
        raise VerificationAssessmentIntegrityError("published plan row is invalid")
    try:
        revision = plan_revision_from_canonical_json(
            canonical_json,
            expected_digest=digest,
        )
    except (PlanningContractError, TypeError, ValueError) as exc:
        raise VerificationAssessmentIntegrityError(
            "published plan canonical payload failed integrity validation"
        ) from exc
    if (
        revision.plan_revision_id != plan_revision_id
        or revision.task_id != task_id
        or revision.principal_id != principal_id
        or revision.project_id != project_id
        or revision.revision_sequence != revision_sequence
        or revision.plan_semantic_digest != digest
    ):
        raise VerificationAssessmentIntegrityError(
            "published plan row disagrees with canonical payload"
        )
    return plan_revision_id, digest


def _current_matches_assessment(
    current: VerificationCurrentSnapshot,
    assessment: VerificationAssessment,
) -> bool:
    return (
        current.task_id == assessment.task_id
        and current.principal_id == assessment.principal_id
        and current.project_id == assessment.project_id
        and current.goal_spec_id == assessment.goal_spec_id
        and current.goal_spec_digest == assessment.goal_spec_digest
        and current.cognitive_state is assessment.cognitive_state
        and current.control_state_version == assessment.control_state_version
        and current.task_status == assessment.task_status
        and current.workspace_id == assessment.workspace_id
        and current.repository_id == assessment.repository_id
        and current.base_revision == assessment.base_revision
        and current.published_plan_revision_id
        == assessment.published_plan_revision_id
        and current.published_plan_revision_digest
        == assessment.published_plan_revision_digest
        and current.repository_generation == assessment.repository_generation
        and current.change_identity == assessment.change_identity
        and current.policy_digest == assessment.policy_digest
        and current.catalog_fingerprint == assessment.catalog_fingerprint
        and current.verification_algorithm_version
        == assessment.verification_algorithm_version
    )


def _decode_row(
    row: Any,
    *,
    expected_assessment_id: str | None = None,
    expected_task_id: str | None = None,
    expected_principal_id: str | None = None,
    expected_project_id: str | None = None,
) -> StoredVerificationAssessment | None:
    if row is None:
        return None
    try:
        physical = {
            "assessment_id": row["assessment_id"],
            "task_id": row["task_id"],
            "principal_id": row["principal_id"],
            "project_id": row["project_id"],
            "assessment_sequence": row["assessment_sequence"],
            "assessment_digest": row["assessment_digest"],
            "canonical_json": row["canonical_json"],
            "created_at": row["created_at"],
        }
    except (KeyError, TypeError) as exc:
        raise VerificationAssessmentIntegrityError(
            "stored assessment row is malformed"
        ) from exc
    if (
        type(physical["assessment_id"]) is not str
        or not physical["assessment_id"]
        or type(physical["task_id"]) is not str
        or not physical["task_id"]
        or type(physical["principal_id"]) is not str
        or not physical["principal_id"]
        or type(physical["project_id"]) is not str
        or type(physical["assessment_sequence"]) is not int
        or physical["assessment_sequence"] < 1
        or type(physical["assessment_digest"]) is not str
        or not physical["assessment_digest"]
        or type(physical["canonical_json"]) is not str
        or type(physical["created_at"]) is not str
        or not physical["created_at"]
    ):
        raise VerificationAssessmentIntegrityError("stored assessment row is invalid")
    if expected_assessment_id is not None and physical["assessment_id"] != expected_assessment_id:
        raise VerificationAssessmentIntegrityError("assessment identity mismatch")
    if expected_task_id is not None and physical["task_id"] != expected_task_id:
        raise VerificationAssessmentIntegrityError("assessment task identity mismatch")
    if expected_principal_id is not None and physical["principal_id"] != expected_principal_id:
        raise VerificationAssessmentIntegrityError("assessment principal identity mismatch")
    if expected_project_id is not None and physical["project_id"] != expected_project_id:
        raise VerificationAssessmentIntegrityError("assessment project identity mismatch")
    try:
        assessment = VerificationAssessment.from_canonical_json(
            physical["canonical_json"],
            expected_digest=physical["assessment_digest"],
        )
    except (VerificationContractError, TypeError, ValueError) as exc:
        raise VerificationAssessmentIntegrityError(
            "stored assessment canonical payload failed integrity validation"
        ) from exc
    for name in ("assessment_id", "task_id", "principal_id", "project_id", "assessment_sequence", "created_at"):
        if getattr(assessment, name) != physical[name]:
            raise VerificationAssessmentIntegrityError(
                f"stored assessment {name} disagrees with canonical payload"
            )
    # Every scalar duplicated in the schema is checked against the decoded
    # value.  This catches tampering even when the canonical JSON itself was
    # replaced with a self-consistent but incorrectly bound payload.
    try:
        for name, value in (
            ("schema_version", assessment.schema_version),
            ("goal_spec_id", assessment.goal_spec_id),
            ("goal_spec_digest", assessment.goal_spec_digest),
            ("cognitive_state", assessment.cognitive_state.value),
            ("control_state_version", assessment.control_state_version),
            ("task_status", assessment.task_status),
            ("workspace_id", assessment.workspace_id),
            ("repository_id", assessment.repository_id),
            ("base_revision", assessment.base_revision),
            ("published_plan_revision_id", assessment.published_plan_revision_id),
            ("published_plan_revision_digest", assessment.published_plan_revision_digest),
            ("repository_generation", assessment.repository_generation),
            ("change_identity", assessment.change_identity),
            ("policy_digest", assessment.policy_digest),
            ("catalog_fingerprint", assessment.catalog_fingerprint),
            (
                "verification_algorithm_version",
                assessment.verification_algorithm_version,
            ),
            ("input_digest", assessment.input_digest),
            ("disposition", assessment.disposition.value),
        ):
            if row[name] != value:
                raise VerificationAssessmentIntegrityError(
                    f"stored assessment {name} disagrees with canonical payload"
                )
    except (KeyError, TypeError) as exc:
        raise VerificationAssessmentIntegrityError(
            "stored assessment duplicated columns are malformed"
        ) from exc
    return StoredVerificationAssessment(
        assessment=assessment,
        assessment_sequence=physical["assessment_sequence"],
        principal_id=physical["principal_id"],
        project_id=physical["project_id"],
        created_at=physical["created_at"],
    )


__all__ = [
    "StoredVerificationAssessment",
    "VerificationAssessmentBindingError",
    "VerificationAssessmentConflictError",
    "VerificationAssessmentDatabase",
    "VerificationAssessmentIntegrityError",
    "VerificationAssessmentRepository",
    "VerificationAssessmentRepositoryError",
    "VerificationAssessmentUnavailableError",
    "VerificationCurrentSnapshot",
    "VerificationCurrentSnapshotReader",
    "VerificationTaskSnapshot",
]
