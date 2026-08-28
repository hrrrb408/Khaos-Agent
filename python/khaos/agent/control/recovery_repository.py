"""Owner-scoped durable storage for M7.5 recovery decisions.

This repository owns the immutable recovery-decision ledger and the strict
read boundary for its task/control snapshots.  It does not evaluate recovery,
execute a replan, mutate TaskStatus, or grant any capability.  A later gate
may use the same database transaction owner for a causal control transition.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol

from khaos.agent.control.completion import CompletionDecision
from khaos.agent.control.goal import GoalSpec, GoalSpecValidationError
from khaos.agent.control.recovery import (
    MAX_RECOVERY_HISTORY_RECORDS,
    RecoveryAction,
    RecoveryContractError,
    RecoveryDecision,
    RecoveryInput,
    RecoveryReasonCode,
)
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.revision import (
    PlanningContractError,
    PlanRevision,
    plan_revision_from_canonical_json,
)
from khaos.coding.planning.verification_assessment import (
    VerificationAssessment,
    VerificationContractError,
)
from khaos.time_utils import utc_now_naive


class RecoveryDecisionDatabase(Protocol):
    """Minimal database port required by the recovery repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared single-writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class RecoveryDecisionRepositoryError(RuntimeError):
    """Base error for durable recovery-decision operations."""


class RecoveryDecisionBindingError(RecoveryDecisionRepositoryError):
    """A decision does not match the supplied owner/task snapshot."""


class RecoveryDecisionConflictError(RecoveryDecisionRepositoryError):
    """An immutable decision identity or sequence conflicts with history."""


class RecoveryDecisionIntegrityError(RecoveryDecisionRepositoryError):
    """A durable recovery, task, GoalSpec, plan, or evidence row is malformed."""


class RecoveryDecisionStaleError(RecoveryDecisionRepositoryError):
    """A decision input no longer describes the current durable snapshot."""


@dataclass(frozen=True, slots=True)
class RecoveryTaskSnapshot:
    """Owner-scoped physical task/control facts used by recovery.

    Cognitive state, control-state version, and lifecycle status come from
    physical SQL columns.  Workspace, repository, and base revision are read
    from the existing task metadata projection only for identity binding.
    """

    task_id: str
    principal_id: str
    project_id: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str | None
    repository_id: str | None
    base_revision: str | None
    published_plan_revision_id: str | None
    last_applied_recovery_decision_id: str | None


@dataclass(frozen=True, slots=True)
class StoredRecoveryDecision:
    """Immutable recovery decision plus its durable ledger envelope."""

    decision: RecoveryDecision
    recovery_sequence: int
    principal_id: str
    project_id: str
    created_at: str

    @property
    def recovery_decision_id(self) -> str:
        """Return the server-owned decision identity."""
        return self.decision.recovery_decision_id

    @property
    def task_id(self) -> str:
        """Return the owner-bound task identity."""
        return self.decision.task_id

    @property
    def action(self) -> RecoveryAction:
        """Return the recorded recovery action."""
        return self.decision.action

    @property
    def reason_code(self) -> RecoveryReasonCode:
        """Return the recorded deterministic reason."""
        return self.decision.reason_code

    @property
    def decision_digest(self) -> str:
        """Return the semantic decision digest."""
        return self.decision.decision_digest


@dataclass(frozen=True, slots=True)
class RecoveryHistorySummary:
    """Bounded SQL summary used to construct a fresh recovery input."""

    total_recovery_count: int
    recovery_attempt_count: int
    replan_count: int
    identical_failure_streak: int


class RecoveryDecisionRepository:
    """Append/read recovery history in an authenticated owner scope.

    ``append`` validates the entire source snapshot inside the same writer
    transaction that allocates the monotonic recovery sequence.  There are no
    update, delete, unscoped-read, or caller-selected-sequence methods.
    """

    def __init__(self, database: RecoveryDecisionDatabase) -> None:
        self._database = database

    @property
    def database(self) -> RecoveryDecisionDatabase:
        """Return the composed database port for transaction sharing."""
        return self._database

    async def append(
        self,
        decision: RecoveryDecision,
        *,
        principal_id: str,
        project_id: str,
        created_at: str | None = None,
    ) -> StoredRecoveryDecision:
        """Validate and append one immutable recovery decision.

        The decision's sequence is assigned by the durable owner.  A stale
        input is rejected; the repository never rewrites it against a newer
        task, plan, verification, or completion snapshot.
        """
        if type(decision) is not RecoveryDecision:
            raise TypeError("decision must be a RecoveryDecision")
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
                    raise RecoveryDecisionBindingError(
                        "task is unavailable in the supplied owner scope"
                    )
                task_snapshot = _decode_task_snapshot(task_row)
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
                await _validate_recovery_counters(
                    conn,
                    decision.input,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                sequence_row = await _next_sequence(
                    conn,
                    task_id=decision.task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                )
                recovery_sequence = sequence_row["next_sequence"]
                await conn.execute(
                    """
                    INSERT INTO agent_recovery_decisions (
                        recovery_decision_id, task_id, principal_id, project_id,
                        recovery_sequence, schema_version,
                        goal_spec_id, goal_spec_digest,
                        source_cognitive_state, source_control_state_version,
                        source_task_status, workspace_id, repository_id,
                        base_revision, published_plan_revision_id,
                        published_plan_revision_digest, latest_plan_revision_id,
                        latest_plan_revision_sequence,
                        verification_assessment_id, verification_assessment_digest,
                        verification_disposition,
                        verification_repository_generation,
                        verification_change_identity, completion_decision_id,
                        completion_decision_digest, completion_decision_sequence,
                        completion_outcome, completion_continuation_state,
                        failure_signature_digest, identical_failure_streak,
                        recovery_attempt_count, replan_count, total_recovery_count,
                        planning_status, policy_schema_version,
                        policy_max_recovery_attempts_per_plan,
                        policy_identical_failure_threshold,
                        policy_max_replans_per_task,
                        policy_max_recovery_cycles_per_turn,
                        policy_max_history_records, policy_digest,
                        action, reason_code, subject_ids_json, input_digest,
                        decision_digest, canonical_json, created_at
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    _storage_values(
                        decision,
                        principal_id=principal_id,
                        project_id=project_id,
                        recovery_sequence=recovery_sequence,
                        canonical_json=canonical_json,
                        created_at=timestamp,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise RecoveryDecisionConflictError(
                "recovery decision identity or sequence conflicts with history"
            ) from exc

        return StoredRecoveryDecision(
            decision=decision,
            recovery_sequence=recovery_sequence,
            principal_id=principal_id,
            project_id=project_id,
            created_at=timestamp,
        )

    async def get_by_id(
        self,
        recovery_decision_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredRecoveryDecision | None:
        """Read one recovery decision only inside the supplied owner scope."""
        _validate_lookup_id(recovery_decision_id, label="recovery_decision_id")
        _validate_scope(
            task_id="lookup",
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_recovery_decisions
                WHERE recovery_decision_id = ?
                  AND principal_id = ? AND project_id = ?
                """,
                (recovery_decision_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(
            row,
            expected_decision_id=recovery_decision_id,
            expected_principal_id=principal_id,
            expected_project_id=project_id,
        )

    async def get_latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredRecoveryDecision | None:
        """Read the strict history head by recovery sequence."""
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_recovery_decisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY recovery_sequence DESC
                LIMIT 1
                """,
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
            latest = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if latest is not None:
                await _validate_history_shape(
                    conn,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    latest_sequence=latest.recovery_sequence,
                )
        return latest

    async def list_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        limit: int = MAX_RECOVERY_HISTORY_RECORDS,
    ) -> list[StoredRecoveryDecision]:
        """Read a bounded owner-scoped recovery-history tail.

        Recovery history is immutable and sequence-addressed.  Returning a
        bounded tail keeps a large task history from becoming an unbounded
        memory read while retaining the most recent records needed for
        continuation and no-progress diagnostics.  The sequence head is
        always available through :meth:`get_latest_for_task`.
        """
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if (
            type(limit) is not int
            or limit < 1
            or limit > MAX_RECOVERY_HISTORY_RECORDS
        ):
            raise ValueError(
                "limit must be between 1 and "
                f"{MAX_RECOVERY_HISTORY_RECORDS}"
            )
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT * FROM agent_recovery_decisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY recovery_sequence DESC
                LIMIT ?
                """,
                (task_id, principal_id, project_id, limit),
            )
            rows = await cursor.fetchall()
        result: list[StoredRecoveryDecision] = []
        for row in reversed(rows):
            stored = _decode_row(
                row,
                expected_task_id=task_id,
                expected_principal_id=principal_id,
                expected_project_id=project_id,
            )
            if stored is None:
                raise RecoveryDecisionIntegrityError(
                    "recovery decision row disappeared during read"
                )
            result.append(stored)
        return result

    async def read_current_task_snapshot(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> RecoveryTaskSnapshot | None:
        """Read the physical current task snapshot without restart mutation."""
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
        return _decode_task_snapshot(row) if row is not None else None

    async def summarize_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
        published_plan_revision_id: str | None,
        failure_signature_digest: str | None,
    ) -> RecoveryHistorySummary:
        """Return durable counters without materializing an unbounded ledger.

        The counters are computed by the database owner.  The failure streak
        is the exact suffix of prior decisions with the supplied normalized
        signature; a changed signature (including ``NULL``) resets it.
        """
        _validate_scope(
            task_id=task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        if (
            failure_signature_digest is not None
            and (
                type(failure_signature_digest) is not str
                or len(failure_signature_digest) != 64
                or any(
                    char not in "0123456789abcdef"
                    for char in failure_signature_digest
                )
            )
        ):
            raise ValueError("failure_signature_digest must be a SHA-256 digest")
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT
                    COUNT(*) AS total_count,
                    COALESCE(SUM(
                        action = ? AND published_plan_revision_id IS ?
                    ), 0) AS recovery_attempt_count,
                    COALESCE(SUM(action = ?), 0) AS replan_count
                FROM agent_recovery_decisions
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                """,
                (
                    RecoveryAction.RECOVER_CURRENT_PLAN.value,
                    published_plan_revision_id,
                    RecoveryAction.REPLAN.value,
                    task_id,
                    principal_id,
                    project_id,
                ),
            )
            counts = await cursor.fetchone()
            if counts is None or any(
                type(counts[key]) is not int
                for key in ("total_count", "recovery_attempt_count", "replan_count")
            ):
                raise RecoveryDecisionIntegrityError("recovery history counters are malformed")

            streak = 0
            if failure_signature_digest is not None and counts["total_count"]:
                cursor = await conn.execute(
                    """
                    SELECT COALESCE(MAX(recovery_sequence), 0) AS last_different
                    FROM agent_recovery_decisions
                    WHERE task_id = ? AND principal_id = ? AND project_id = ?
                      AND failure_signature_digest IS NOT ?
                    """,
                    (
                        task_id,
                        principal_id,
                        project_id,
                        failure_signature_digest,
                    ),
                )
                boundary = await cursor.fetchone()
                if boundary is None or type(boundary["last_different"]) is not int:
                    raise RecoveryDecisionIntegrityError(
                        "recovery failure-streak boundary is malformed"
                    )
                cursor = await conn.execute(
                    """
                    SELECT COUNT(*) AS streak
                    FROM agent_recovery_decisions
                    WHERE task_id = ? AND principal_id = ? AND project_id = ?
                      AND recovery_sequence > ?
                      AND failure_signature_digest = ?
                    """,
                    (
                        task_id,
                        principal_id,
                        project_id,
                        boundary["last_different"],
                        failure_signature_digest,
                    ),
                )
                streak_row = await cursor.fetchone()
                if streak_row is None or type(streak_row["streak"]) is not int:
                    raise RecoveryDecisionIntegrityError(
                        "recovery failure streak is malformed"
                    )
                streak = streak_row["streak"]
        return RecoveryHistorySummary(
            total_recovery_count=counts["total_count"],
            recovery_attempt_count=counts["recovery_attempt_count"],
            replan_count=counts["replan_count"],
            identical_failure_streak=streak,
        )


async def _next_sequence(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT COALESCE(MAX(recovery_sequence), 0) + 1 AS next_sequence
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        """,
        (task_id, principal_id, project_id),
    )
    row = await cursor.fetchone()
    if row is None or type(row["next_sequence"]) is not int:
        raise RecoveryDecisionIntegrityError("recovery sequence allocator is malformed")
    if row["next_sequence"] < 1:
        raise RecoveryDecisionIntegrityError("recovery sequence is not positive")
    return row


async def _validate_history_shape(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
    latest_sequence: int,
) -> None:
    """Reject a recovery ledger with a non-contiguous or invalid history head.

    The recovery service reads only the durable sequence head.  The aggregate
    check keeps that bounded read from treating a physically corrupted gap or
    an out-of-vocabulary action as a valid continuation, without materializing
    the whole append-only ledger in memory.
    """
    cursor = await conn.execute(
        """
        SELECT COUNT(*) AS total_count,
               COALESCE(MIN(recovery_sequence), 0) AS first_sequence,
               COALESCE(MAX(recovery_sequence), 0) AS last_sequence,
               COALESCE(SUM(
                   recovery_sequence IS NULL OR recovery_sequence < 1
               ), 0) AS invalid_sequence_count,
               COALESCE(SUM(
                   action IS NULL OR action NOT IN (?, ?, ?, ?)
               ), 0)
                   AS invalid_action_count
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        """,
        (
            RecoveryAction.NO_ACTION.value,
            RecoveryAction.RECOVER_CURRENT_PLAN.value,
            RecoveryAction.REPLAN.value,
            RecoveryAction.BLOCK.value,
            task_id,
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
            "invalid_sequence_count",
            "invalid_action_count",
        )
    ):
        raise RecoveryDecisionIntegrityError("recovery history summary is malformed")
    if (
        latest_sequence < 1
        or summary["total_count"] != latest_sequence
        or summary["first_sequence"] != 1
        or summary["last_sequence"] != latest_sequence
        or summary["invalid_sequence_count"] != 0
        or summary["invalid_action_count"] != 0
    ):
        raise RecoveryDecisionIntegrityError(
            "recovery history sequence or action vocabulary is invalid"
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
        SELECT id, principal_id, project_id, cognitive_state,
               control_state_version, status, published_plan_revision_id,
               last_applied_recovery_decision_id, state_json
        FROM coding_tasks
        WHERE id = ? AND principal_id = ? AND project_id = ?
        """,
        (task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


def _decode_task_snapshot(row: Any) -> RecoveryTaskSnapshot:
    if row is None:
        raise RecoveryDecisionBindingError("task is unavailable")
    try:
        task_id = row["id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        cognitive_state = AgentCognitiveState.parse(row["cognitive_state"])
        control_state_version = row["control_state_version"]
        task_status = row["status"]
        published_plan_revision_id = row["published_plan_revision_id"]
        last_applied = row["last_applied_recovery_decision_id"]
        state_json = row["state_json"]
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryDecisionIntegrityError(
            "coding task recovery snapshot is malformed"
        ) from exc
    if (
        type(task_id) is not str
        or not task_id
        or type(principal_id) is not str
        or not principal_id
        or type(project_id) is not str
        or type(task_status) is not str
        or not task_status
        or type(control_state_version) is not int
        or control_state_version < 0
    ):
        raise RecoveryDecisionIntegrityError("coding task identity/status is malformed")
    for value, label in (
        (published_plan_revision_id, "published_plan_revision_id"),
        (last_applied, "last_applied_recovery_decision_id"),
    ):
        if value is not None and (type(value) is not str or not value):
            raise RecoveryDecisionIntegrityError(f"task {label} is malformed")
    workspace_id, repository_id, base_revision = _decode_task_metadata(state_json)
    return RecoveryTaskSnapshot(
        task_id=task_id,
        principal_id=principal_id,
        project_id=project_id,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status=task_status,
        workspace_id=workspace_id,
        repository_id=repository_id,
        base_revision=base_revision,
        published_plan_revision_id=published_plan_revision_id,
        last_applied_recovery_decision_id=last_applied,
    )


def _decode_task_metadata(value: Any) -> tuple[str | None, str | None, str | None]:
    if type(value) is not str:
        raise RecoveryDecisionIntegrityError("task state_json is not text")
    try:
        state = json.loads(value)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        raise RecoveryDecisionIntegrityError("task state_json is malformed") from exc
    if type(state) is not dict:
        raise RecoveryDecisionIntegrityError("task state_json is not an object")
    metadata = state.get("metadata", {})
    if type(metadata) is not dict:
        raise RecoveryDecisionIntegrityError("task metadata is not an object")
    values: list[str | None] = []
    for key in ("workspace_id", "repository_id", "base_sha"):
        raw = metadata.get(key)
        if raw is not None and (type(raw) is not str or not raw):
            raise RecoveryDecisionIntegrityError(f"task metadata {key} is malformed")
        values.append(raw)
    return values[0], values[1], values[2]


async def _load_goal_spec(
    conn: Any,
    *,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> GoalSpec:
    cursor = await conn.execute(
        """
        SELECT goal_spec_id, task_id, principal_id, project_id,
               schema_version, semantic_digest, canonical_json
        FROM agent_goal_specs
        WHERE task_id = ?
        """,
        (task_id,),
    )
    row = await cursor.fetchone()
    if row is None:
        raise RecoveryDecisionBindingError("task has no durable GoalSpec")
    if row["principal_id"] != principal_id or row["project_id"] != project_id:
        raise RecoveryDecisionBindingError("GoalSpec is unavailable in owner scope")
    try:
        spec = GoalSpec.from_canonical_json(
            row["canonical_json"],
            expected_digest=row["semantic_digest"],
        )
    except (GoalSpecValidationError, TypeError, ValueError) as exc:
        raise RecoveryDecisionIntegrityError(
            "durable GoalSpec failed integrity validation"
        ) from exc
    if spec.goal_spec_id != row["goal_spec_id"] or spec.schema_version != row["schema_version"]:
        raise RecoveryDecisionIntegrityError(
            "GoalSpec row disagrees with its canonical payload"
        )
    return spec


def _validate_decision_binding(
    decision: RecoveryDecision,
    *,
    task_snapshot: RecoveryTaskSnapshot,
    goal_spec: GoalSpec,
) -> None:
    source = decision.input
    if (
        source.task_id != task_snapshot.task_id
        or source.principal_id != task_snapshot.principal_id
        or source.project_id != task_snapshot.project_id
    ):
        raise RecoveryDecisionBindingError("recovery decision owner/task binding mismatch")
    if source.goal_spec_id != goal_spec.goal_spec_id:
        raise RecoveryDecisionBindingError("recovery decision GoalSpec identity mismatch")
    if source.goal_spec_digest != goal_spec.semantic_digest:
        raise RecoveryDecisionBindingError("recovery decision GoalSpec digest mismatch")
    if source.cognitive_state is not task_snapshot.cognitive_state:
        raise RecoveryDecisionStaleError("recovery cognitive state is stale")
    if source.control_state_version != task_snapshot.control_state_version:
        raise RecoveryDecisionStaleError("recovery control-state version is stale")
    if source.task_status != task_snapshot.task_status:
        raise RecoveryDecisionStaleError("recovery task status is stale")
    if source.workspace_id != task_snapshot.workspace_id:
        raise RecoveryDecisionStaleError("recovery workspace binding is stale")
    if source.repository_id != task_snapshot.repository_id:
        raise RecoveryDecisionStaleError("recovery repository binding is stale")
    if source.base_revision != task_snapshot.base_revision:
        raise RecoveryDecisionStaleError("recovery base revision is stale")
    if source.published_plan_revision_id != task_snapshot.published_plan_revision_id:
        raise RecoveryDecisionStaleError("recovery published plan is stale")


async def _validate_plan_bindings(
    conn: Any,
    source: RecoveryInput,
    *,
    task_snapshot: RecoveryTaskSnapshot,
    principal_id: str,
    project_id: str,
) -> None:
    if source.published_plan_revision_id is not None:
        row = await _select_plan(
            conn,
            plan_revision_id=source.published_plan_revision_id,
            task_id=source.task_id,
            principal_id=principal_id,
            project_id=project_id,
        )
        revision = _decode_plan(row)
        if revision.plan_semantic_digest != source.published_plan_revision_digest:
            raise RecoveryDecisionStaleError("published plan digest is stale")
        if revision.plan_revision_id != task_snapshot.published_plan_revision_id:
            raise RecoveryDecisionStaleError("published plan identity is stale")

    head_row = await _select_plan_head(
        conn,
        task_id=source.task_id,
        principal_id=principal_id,
        project_id=project_id,
    )
    if head_row is None:
        if source.latest_plan_revision_id is not None:
            raise RecoveryDecisionStaleError("latest plan input is stale")
        return
    head = _decode_plan(head_row)
    if source.latest_plan_revision_id != head.plan_revision_id:
        raise RecoveryDecisionStaleError("latest plan identity is stale")
    if source.latest_plan_revision_sequence != head.revision_sequence:
        raise RecoveryDecisionStaleError("latest plan sequence is stale")


async def _validate_verification_binding(
    conn: Any,
    source: RecoveryInput,
    *,
    principal_id: str,
    project_id: str,
) -> None:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_verification_assessments
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        ORDER BY assessment_sequence DESC
        LIMIT 1
        """,
        (source.task_id, principal_id, project_id),
    )
    latest_row = await cursor.fetchone()
    if source.verification_assessment_id is None:
        if latest_row is not None:
            raise RecoveryDecisionStaleError(
                "recovery input omitted the current verification assessment"
            )
        return
    row = await _select_verification(
        conn,
        assessment_id=source.verification_assessment_id,
        task_id=source.task_id,
        principal_id=principal_id,
        project_id=project_id,
    )
    assessment = _decode_verification(row)
    if assessment.assessment_digest != source.verification_assessment_digest:
        raise RecoveryDecisionStaleError("verification assessment digest is stale")
    if latest_row is None or latest_row["assessment_id"] != source.verification_assessment_id:
        raise RecoveryDecisionStaleError("verification assessment is not the history head")
    if source.verification_disposition is not assessment.disposition:
        raise RecoveryDecisionStaleError("verification disposition is stale")


async def _validate_completion_binding(
    conn: Any,
    source: RecoveryInput,
    *,
    principal_id: str,
    project_id: str,
) -> None:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_completion_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        ORDER BY decision_sequence DESC
        LIMIT 1
        """,
        (source.task_id, principal_id, project_id),
    )
    latest_row = await cursor.fetchone()
    if source.completion_decision_id is None:
        if latest_row is not None:
            raise RecoveryDecisionStaleError(
                "recovery input omitted the current completion decision"
            )
        return
    row = await _select_completion(
        conn,
        decision_id=source.completion_decision_id,
        task_id=source.task_id,
        principal_id=principal_id,
        project_id=project_id,
    )
    decision = _decode_completion(row)
    if decision.decision_digest != source.completion_decision_digest:
        raise RecoveryDecisionStaleError("completion decision digest is stale")
    if latest_row is None or latest_row["decision_id"] != source.completion_decision_id:
        raise RecoveryDecisionStaleError("completion decision is not the history head")
    if source.completion_decision_sequence != latest_row["decision_sequence"]:
        raise RecoveryDecisionStaleError("completion decision sequence is stale")
    if source.completion_outcome is not decision.outcome:
        raise RecoveryDecisionStaleError("completion decision outcome is stale")


async def _validate_recovery_counters(
    conn: Any,
    source: RecoveryInput,
    *,
    principal_id: str,
    project_id: str,
) -> None:
    cursor = await conn.execute(
        """
        SELECT
            COUNT(*) AS total_count,
            COALESCE(SUM(
                action = ? AND published_plan_revision_id IS ?
            ), 0) AS recovery_attempt_count,
            COALESCE(SUM(action = ?), 0) AS replan_count
        FROM agent_recovery_decisions
        WHERE task_id = ? AND principal_id = ? AND project_id = ?
        """,
        (
            RecoveryAction.RECOVER_CURRENT_PLAN.value,
            source.published_plan_revision_id,
            RecoveryAction.REPLAN.value,
            source.task_id,
            principal_id,
            project_id,
        ),
    )
    row = await cursor.fetchone()
    if row is None or any(
        type(row[key]) is not int
        for key in ("total_count", "recovery_attempt_count", "replan_count")
    ):
        raise RecoveryDecisionIntegrityError("recovery counters are malformed")
    total = row["total_count"]
    recovery_attempts = row["recovery_attempt_count"]
    replans = row["replan_count"]
    if (
        source.total_recovery_count != total
        or source.recovery_attempt_count != recovery_attempts
        or source.replan_count != replans
    ):
        raise RecoveryDecisionStaleError("recovery durable counters are stale")


async def _select_plan(
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


def _decode_plan(row: Any) -> PlanRevision:
    if row is None:
        raise RecoveryDecisionBindingError("plan revision is unavailable")
    try:
        revision = plan_revision_from_canonical_json(
            row["canonical_json"],
            expected_digest=row["plan_semantic_digest"],
        )
        if (
            revision.plan_revision_id != row["plan_revision_id"]
            or revision.task_id != row["task_id"]
            or revision.principal_id != row["principal_id"]
            or revision.project_id != row["project_id"]
            or revision.revision_sequence != row["revision_sequence"]
            or revision.created_at != row["created_at"]
        ):
            raise RecoveryDecisionIntegrityError(
                "plan revision envelope disagrees with canonical payload"
            )
    except RecoveryDecisionIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, PlanningContractError) as exc:
        raise RecoveryDecisionIntegrityError("plan revision failed integrity validation") from exc
    return revision


async def _select_verification(
    conn: Any,
    *,
    assessment_id: str,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_verification_assessments
        WHERE assessment_id = ? AND task_id = ?
          AND principal_id = ? AND project_id = ?
        """,
        (assessment_id, task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


def _decode_verification(row: Any) -> VerificationAssessment:
    if row is None:
        raise RecoveryDecisionBindingError("verification assessment is unavailable")
    try:
        assessment = VerificationAssessment.from_canonical_json(
            row["canonical_json"],
            expected_digest=row["assessment_digest"],
        )
        if (
            assessment.assessment_id != row["assessment_id"]
            or assessment.task_id != row["task_id"]
            or assessment.assessment_sequence != row["assessment_sequence"]
        ):
            raise RecoveryDecisionIntegrityError(
                "verification assessment envelope disagrees with canonical payload"
            )
    except RecoveryDecisionIntegrityError:
        raise
    except (KeyError, TypeError, ValueError, VerificationContractError) as exc:
        raise RecoveryDecisionIntegrityError(
            "verification assessment failed integrity validation"
        ) from exc
    return assessment


async def _select_completion(
    conn: Any,
    *,
    decision_id: str,
    task_id: str,
    principal_id: str,
    project_id: str,
) -> Any:
    cursor = await conn.execute(
        """
        SELECT * FROM agent_completion_decisions
        WHERE decision_id = ? AND task_id = ?
          AND principal_id = ? AND project_id = ?
        """,
        (decision_id, task_id, principal_id, project_id),
    )
    return await cursor.fetchone()


def _decode_completion(row: Any) -> CompletionDecision:
    if row is None:
        raise RecoveryDecisionBindingError("completion decision is unavailable")
    try:
        decision = CompletionDecision.from_canonical_json(
            row["canonical_json"],
            expected_digest=row["decision_digest"],
        )
        if (
            decision.decision_id != row["decision_id"]
            or decision.task_id != row["task_id"]
        ):
            raise RecoveryDecisionIntegrityError(
                "completion decision envelope disagrees with canonical payload"
            )
    except RecoveryDecisionIntegrityError:
        raise
    except (KeyError, TypeError, ValueError) as exc:
        raise RecoveryDecisionIntegrityError(
            "completion decision failed integrity validation"
        ) from exc
    return decision


def _storage_values(
    decision: RecoveryDecision,
    *,
    principal_id: str,
    project_id: str,
    recovery_sequence: int,
    canonical_json: str,
    created_at: str,
) -> tuple[Any, ...]:
    source = decision.input
    return (
        decision.recovery_decision_id,
        decision.task_id,
        principal_id,
        project_id,
        recovery_sequence,
        decision.schema_version,
        source.goal_spec_id,
        source.goal_spec_digest,
        source.cognitive_state.value,
        source.control_state_version,
        source.task_status,
        source.workspace_id,
        source.repository_id,
        source.base_revision,
        source.published_plan_revision_id,
        source.published_plan_revision_digest,
        source.latest_plan_revision_id,
        source.latest_plan_revision_sequence,
        source.verification_assessment_id,
        source.verification_assessment_digest,
        source.verification_disposition.value
        if source.verification_disposition is not None
        else None,
        source.verification_repository_generation,
        source.verification_change_identity,
        source.completion_decision_id,
        source.completion_decision_digest,
        source.completion_decision_sequence,
        source.completion_outcome.value
        if source.completion_outcome is not None
        else None,
        source.completion_continuation_state.value
        if source.completion_continuation_state is not None
        else None,
        source.failure_signature_digest,
        source.identical_failure_streak,
        source.recovery_attempt_count,
        source.replan_count,
        source.total_recovery_count,
        source.planning_status.value,
        source.policy.schema_version,
        source.policy.max_recovery_attempts_per_plan,
        source.policy.identical_failure_threshold,
        source.policy.max_replans_per_task,
        source.policy.max_recovery_cycles_per_turn,
        source.policy.max_history_records,
        source.policy.policy_digest,
        decision.action.value,
        decision.reason_code.value,
        json.dumps(list(decision.subject_ids), ensure_ascii=False, separators=(",", ":")),
        decision.input_digest,
        decision.decision_digest,
        canonical_json,
        created_at,
    )


def _decode_row(
    row: Any,
    *,
    expected_decision_id: str | None = None,
    expected_task_id: str | None = None,
    expected_principal_id: str | None = None,
    expected_project_id: str | None = None,
) -> StoredRecoveryDecision | None:
    if row is None:
        return None
    try:
        decision_id = row["recovery_decision_id"]
        task_id = row["task_id"]
        principal_id = row["principal_id"]
        project_id = row["project_id"]
        sequence = row["recovery_sequence"]
        schema_version = row["schema_version"]
        decision_digest = row["decision_digest"]
        canonical_json = row["canonical_json"]
        created_at = row["created_at"]
    except (KeyError, TypeError) as exc:
        raise RecoveryDecisionIntegrityError("recovery decision row is malformed") from exc
    if (
        type(decision_id) is not str
        or not decision_id
        or type(task_id) is not str
        or not task_id
        or type(principal_id) is not str
        or not principal_id
        or type(project_id) is not str
        or type(sequence) is not int
        or sequence < 1
        or type(schema_version) is not int
        or type(decision_digest) is not str
        or type(canonical_json) is not str
        or not canonical_json
        or type(created_at) is not str
        or not created_at
    ):
        raise RecoveryDecisionIntegrityError("recovery decision row has invalid scalars")
    for expected, actual, label in (
        (expected_decision_id, decision_id, "decision identity"),
        (expected_task_id, task_id, "task identity"),
        (expected_principal_id, principal_id, "principal identity"),
        (expected_project_id, project_id, "project identity"),
    ):
        if expected is not None and expected != actual:
            raise RecoveryDecisionIntegrityError(f"recovery decision {label} mismatch")
    try:
        decision = RecoveryDecision.from_canonical_json(
            canonical_json,
            expected_digest=decision_digest,
            expected_decision_id=decision_id,
        )
    except (RecoveryContractError, TypeError, ValueError) as exc:
        raise RecoveryDecisionIntegrityError(
            "recovery decision canonical payload failed integrity validation"
        ) from exc
    if (
        decision.schema_version != schema_version
        or decision.task_id != task_id
        or decision.principal_id != principal_id
        or decision.project_id != project_id
        or decision.decision_digest != decision_digest
    ):
        raise RecoveryDecisionIntegrityError(
            "recovery decision envelope disagrees with canonical payload"
        )
    _validate_physical_columns(row, decision)
    try:
        subject_ids = json.loads(row["subject_ids_json"])
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError) as exc:
        raise RecoveryDecisionIntegrityError("recovery subject ids are malformed") from exc
    if subject_ids != list(decision.subject_ids):
        raise RecoveryDecisionIntegrityError("recovery subject ids disagree with payload")
    if row["input_digest"] != decision.input_digest:
        raise RecoveryDecisionIntegrityError("recovery input digest disagrees with payload")
    return StoredRecoveryDecision(
        decision=decision,
        recovery_sequence=sequence,
        principal_id=principal_id,
        project_id=project_id,
        created_at=created_at,
    )


def _validate_physical_columns(row: Any, decision: RecoveryDecision) -> None:
    """Cross-check every duplicated scalar against the canonical decision.

    The ledger stores selected columns for indexed owner/task queries.  They
    are never an alternate authority: a physical-column edit must be
    detected before a caller can observe the row as a valid decision.
    """
    source = decision.input
    expected: dict[str, object | None] = {
        "schema_version": decision.schema_version,
        "goal_spec_id": source.goal_spec_id,
        "goal_spec_digest": source.goal_spec_digest,
        "source_cognitive_state": source.cognitive_state.value,
        "source_control_state_version": source.control_state_version,
        "source_task_status": source.task_status,
        "workspace_id": source.workspace_id,
        "repository_id": source.repository_id,
        "base_revision": source.base_revision,
        "published_plan_revision_id": source.published_plan_revision_id,
        "published_plan_revision_digest": source.published_plan_revision_digest,
        "latest_plan_revision_id": source.latest_plan_revision_id,
        "latest_plan_revision_sequence": source.latest_plan_revision_sequence,
        "verification_assessment_id": source.verification_assessment_id,
        "verification_assessment_digest": source.verification_assessment_digest,
        "verification_disposition": (
            source.verification_disposition.value
            if source.verification_disposition is not None
            else None
        ),
        "verification_repository_generation": source.verification_repository_generation,
        "verification_change_identity": source.verification_change_identity,
        "completion_decision_id": source.completion_decision_id,
        "completion_decision_digest": source.completion_decision_digest,
        "completion_decision_sequence": source.completion_decision_sequence,
        "completion_outcome": (
            source.completion_outcome.value
            if source.completion_outcome is not None
            else None
        ),
        "completion_continuation_state": (
            source.completion_continuation_state.value
            if source.completion_continuation_state is not None
            else None
        ),
        "failure_signature_digest": source.failure_signature_digest,
        "identical_failure_streak": source.identical_failure_streak,
        "recovery_attempt_count": source.recovery_attempt_count,
        "replan_count": source.replan_count,
        "total_recovery_count": source.total_recovery_count,
        "planning_status": source.planning_status.value,
        "policy_schema_version": source.policy.schema_version,
        "policy_max_recovery_attempts_per_plan": (
            source.policy.max_recovery_attempts_per_plan
        ),
        "policy_identical_failure_threshold": source.policy.identical_failure_threshold,
        "policy_max_replans_per_task": source.policy.max_replans_per_task,
        "policy_max_recovery_cycles_per_turn": (
            source.policy.max_recovery_cycles_per_turn
        ),
        "policy_max_history_records": source.policy.max_history_records,
        "policy_digest": source.policy.policy_digest,
        "action": decision.action.value,
        "reason_code": decision.reason_code.value,
        "input_digest": decision.input_digest,
        "decision_digest": decision.decision_digest,
    }
    try:
        for column, value in expected.items():
            if row[column] != value:
                raise RecoveryDecisionIntegrityError(
                    f"recovery column {column} disagrees with payload"
                )
    except (KeyError, TypeError) as exc:
        raise RecoveryDecisionIntegrityError(
            "recovery decision physical columns are malformed"
        ) from exc
    expected_subjects = json.dumps(
        list(decision.subject_ids), ensure_ascii=False, separators=(",", ":")
    )
    if row["subject_ids_json"] != expected_subjects:
        raise RecoveryDecisionIntegrityError(
            "recovery subject ids column disagrees with payload"
        )


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


__all__ = [
    "RecoveryDecisionBindingError",
    "RecoveryDecisionConflictError",
    "RecoveryDecisionDatabase",
    "RecoveryDecisionIntegrityError",
    "RecoveryDecisionRepository",
    "RecoveryDecisionRepositoryError",
    "RecoveryDecisionStaleError",
    "RecoveryHistorySummary",
    "RecoveryTaskSnapshot",
    "StoredRecoveryDecision",
]
