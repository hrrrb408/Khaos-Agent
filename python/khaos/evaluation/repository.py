"""Owner-scoped append-only persistence for capability evaluations."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.evaluation.models import (
    CapabilityEvaluation,
    DelegationMetrics,
    EfficiencyMetrics,
    EvaluationContractError,
    EvaluationDisposition,
    ExecutionMetrics,
    MemoryMetrics,
    OutcomeMetrics,
    PlanningMetrics,
    RecoveryMetrics,
    SafetyMetrics,
    SecurityIntegrity,
    SourceAvailability,
    VerificationMetrics,
)
from khaos.time_utils import utc_now_naive


class CapabilityEvaluationDatabase(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[Any]: ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


class CapabilityEvaluationRepositoryError(RuntimeError):
    """Base error for evaluation ledger failures."""


class CapabilityEvaluationIntegrityError(CapabilityEvaluationRepositoryError):
    """A stored evaluation failed strict canonical or scalar validation."""


class CapabilityEvaluationConflictError(CapabilityEvaluationRepositoryError):
    """An append collided with an existing immutable evaluation identity."""


class CapabilityEvaluationRepository:
    """The sole owner-scoped writer and reader for ``agent_capability_evaluations``."""

    def __init__(self, database: CapabilityEvaluationDatabase) -> None:
        self._database = database

    async def append(
        self,
        evaluation: CapabilityEvaluation,
        *,
        created_at: str | None = None,
    ) -> CapabilityEvaluation:
        """Allocate a DB sequence and append one immutable observation."""

        if type(evaluation) is not CapabilityEvaluation:
            raise TypeError("evaluation must be a CapabilityEvaluation")
        if evaluation.evaluation_sequence != 0:
            raise CapabilityEvaluationConflictError("caller cannot choose evaluation sequence")
        timestamp = created_at or utc_now_naive().isoformat()
        stored: CapabilityEvaluation | None = None
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """SELECT COALESCE(MAX(evaluation_sequence), 0) + 1 AS next_sequence
                   FROM agent_capability_evaluations
                   WHERE principal_id = ? AND project_id = ? AND task_id = ?""",
                (evaluation.principal_id, evaluation.project_id, evaluation.task_id),
            )
            row = await cursor.fetchone()
            sequence = int(row["next_sequence"] if row is not None else 1)
            stored = evaluation.with_sequence(sequence, timestamp)
            try:
                await conn.execute(
                    """INSERT INTO agent_capability_evaluations (
                        evaluation_id, principal_id, project_id, task_id,
                        evaluation_sequence, goal_spec_id, goal_spec_digest,
                        snapshot_digest, policy_digest, evaluator_schema_version,
                        evaluator_algorithm_version, disposition, evaluation_json,
                        evaluation_digest, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        stored.evaluation_id,
                        stored.principal_id,
                        stored.project_id,
                        stored.task_id,
                        stored.evaluation_sequence,
                        stored.goal_spec_id,
                        stored.goal_spec_digest,
                        stored.snapshot_digest,
                        stored.policy_digest,
                        stored.evaluator_schema_version,
                        stored.evaluator_algorithm_version,
                        stored.disposition.value,
                        stored.canonical_json(),
                        stored.evaluation_digest,
                        stored.created_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CapabilityEvaluationConflictError("evaluation append conflicted") from exc
        assert stored is not None
        return stored

    async def get_by_id(
        self,
        evaluation_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> CapabilityEvaluation | None:
        """Read one evaluation without exposing an unscoped lookup."""

        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """SELECT * FROM agent_capability_evaluations
                   WHERE evaluation_id = ? AND principal_id = ? AND project_id = ?""",
                (evaluation_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(row) if row is not None else None

    async def latest_for_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
    ) -> CapabilityEvaluation | None:
        """Read the latest observation in an authenticated task scope."""

        rows = await self.list_for_task(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            limit=1,
            descending=True,
        )
        return rows[0] if rows else None

    async def list_for_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
        limit: int = 256,
        descending: bool = False,
    ) -> tuple[CapabilityEvaluation, ...]:
        """Read bounded immutable history; malformed rows fail closed."""

        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("evaluation history limit is outside bounds")
        order = "DESC" if descending else "ASC"
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"""SELECT * FROM agent_capability_evaluations
                    WHERE principal_id = ? AND project_id = ? AND task_id = ?
                    ORDER BY evaluation_sequence {order} LIMIT ?""",
                (principal_id, project_id, task_id, limit),
            )
            rows = await cursor.fetchall()
        return tuple(_decode_row(row) for row in rows)


def _decode_row(row: Any) -> CapabilityEvaluation:
    try:
        payload = json.loads(str(row["evaluation_json"]))
        if type(payload) is not dict:
            raise EvaluationContractError("evaluation JSON must be an object")
        expected = {
            "schema_version", "evaluator_algorithm_version", "principal_id", "project_id",
            "task_id", "goal_spec_id", "goal_spec_digest", "snapshot_digest", "policy_digest",
            "disposition", "outcome_metrics", "planning_metrics", "verification_metrics",
            "recovery_metrics", "execution_metrics", "safety_metrics", "delegation_metrics",
            "efficiency_metrics", "memory_metrics", "security_integrity", "aggregate_score",
            "source_availability", "evaluation_id", "evaluation_sequence", "created_at", "evaluation_digest",
        }
        if set(payload) != expected:
            raise EvaluationContractError("evaluation JSON schema is not closed")
        evaluation = CapabilityEvaluation(
            evaluation_id=payload["evaluation_id"],
            evaluation_sequence=payload["evaluation_sequence"],
            principal_id=payload["principal_id"],
            project_id=payload["project_id"],
            task_id=payload["task_id"],
            goal_spec_id=payload["goal_spec_id"],
            goal_spec_digest=payload["goal_spec_digest"],
            snapshot_digest=payload["snapshot_digest"],
            policy_digest=payload["policy_digest"],
            evaluator_schema_version=payload["schema_version"],
            evaluator_algorithm_version=payload["evaluator_algorithm_version"],
            disposition=EvaluationDisposition(payload["disposition"]),
            outcome_metrics=_decode_metric(OutcomeMetrics, payload["outcome_metrics"]),
            planning_metrics=_decode_metric(PlanningMetrics, payload["planning_metrics"]),
            verification_metrics=_decode_metric(VerificationMetrics, payload["verification_metrics"]),
            recovery_metrics=_decode_metric(RecoveryMetrics, payload["recovery_metrics"]),
            execution_metrics=_decode_metric(ExecutionMetrics, payload["execution_metrics"]),
            safety_metrics=_decode_metric(SafetyMetrics, payload["safety_metrics"]),
            delegation_metrics=_decode_metric(DelegationMetrics, payload["delegation_metrics"]),
            efficiency_metrics=_decode_metric(EfficiencyMetrics, payload["efficiency_metrics"]),
            memory_metrics=(
                _decode_metric(MemoryMetrics, payload["memory_metrics"])
                if payload["memory_metrics"] is not None
                else None
            ),
            security_integrity=SecurityIntegrity(payload["security_integrity"]),
            aggregate_score=payload["aggregate_score"],
            created_at=payload["created_at"],
            source_availability=tuple(
                SourceAvailability(**item) for item in payload["source_availability"]
            ),
        )
        _cross_check(row, evaluation)
        if evaluation.canonical_json() != str(row["evaluation_json"]):
            raise EvaluationContractError("evaluation JSON is not canonical")
        return evaluation
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, EvaluationContractError) as exc:
        if isinstance(exc, CapabilityEvaluationRepositoryError):
            raise
        raise CapabilityEvaluationIntegrityError("stored evaluation failed closed validation") from exc


def _decode_metric(metric_type: type[Any], value: object) -> Any:
    if type(value) is not dict or set(value) != {item.name for item in metric_type.__dataclass_fields__.values()}:
        raise EvaluationContractError(f"{metric_type.__name__} schema is not closed")
    return metric_type(**value)


def _cross_check(row: Any, evaluation: CapabilityEvaluation) -> None:
    for key, value in (
        ("evaluation_id", evaluation.evaluation_id),
        ("principal_id", evaluation.principal_id),
        ("project_id", evaluation.project_id),
        ("task_id", evaluation.task_id),
        ("evaluation_sequence", evaluation.evaluation_sequence),
        ("goal_spec_id", evaluation.goal_spec_id),
        ("goal_spec_digest", evaluation.goal_spec_digest),
        ("snapshot_digest", evaluation.snapshot_digest),
        ("policy_digest", evaluation.policy_digest),
        ("evaluator_schema_version", evaluation.evaluator_schema_version),
        ("evaluator_algorithm_version", evaluation.evaluator_algorithm_version),
        ("disposition", evaluation.disposition.value),
        ("evaluation_digest", evaluation.evaluation_digest),
        ("created_at", evaluation.created_at),
    ):
        if row[key] != value:
            raise EvaluationContractError(f"evaluation scalar {key} disagrees with canonical JSON")


__all__ = [
    "CapabilityEvaluationConflictError",
    "CapabilityEvaluationIntegrityError",
    "CapabilityEvaluationRepository",
    "CapabilityEvaluationRepositoryError",
]
