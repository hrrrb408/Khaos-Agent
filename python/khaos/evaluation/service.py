"""Coherent evidence capture and evaluation orchestration.

The service is the only stateful part of M7.9.  It performs bounded,
owner-scoped read transactions and appends an observation to the evaluation
ledger.  The evaluator itself remains completely pure.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.agent.control.completion import CompletionDecision
from khaos.evaluation.evaluator import CapabilityEvaluator
from khaos.evaluation.models import (
    CapabilityEvaluation,
    CapabilityEvaluationPolicy,
    CapabilityEvaluationRequest,
    CapabilityEvidenceSnapshot,
    EvaluationContractError,
    EvidenceRecord,
    SourceAvailability,
    SourceHighWaterMark,
    TaskEvidence,
)
from khaos.evaluation.repository import CapabilityEvaluationRepository
from khaos.security.protocol_boundary import canonical_digest
from khaos.time_utils import utc_now_naive


class EvaluationDatabase(Protocol):
    def read_transaction(self) -> AbstractAsyncContextManager[Any]: ...


class EvaluationCaptureError(RuntimeError):
    """The requested task is unavailable or its durable evidence is invalid."""


class EvaluationNotFoundError(EvaluationCaptureError):
    """The task is unavailable in the requested owner scope."""


class CapabilityEvidenceService:
    """Capture owner-scoped evidence at one SQLite logical observation point."""

    def __init__(self, database: EvaluationDatabase, *, max_source_records: int = 256) -> None:
        if type(max_source_records) is not int or not 1 <= max_source_records <= 10_000:
            raise ValueError("max_source_records is outside bounds")
        self._database = database
        self._max_source_records = max_source_records

    async def request_for_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
        policy: CapabilityEvaluationPolicy,
        requested_evaluation_kind: str = "task",
    ) -> CapabilityEvaluationRequest:
        """Build identity from the durable task and GoalSpec, never model input."""

        async with self._database.read_transaction() as conn:
            task = await self._task_row(conn, principal_id, project_id, task_id)
            if task is None:
                raise EvaluationNotFoundError("task is unavailable in the supplied owner scope")
            goal = await self._goal_row(conn, principal_id, project_id, task_id)
        if goal is None:
            goal_id = "missing-goal-spec:" + task_id
            goal_digest = canonical_digest({"missing_goal_spec": task_id})
        else:
            goal_id = str(goal["goal_spec_id"])
            goal_digest = str(goal["semantic_digest"])
        return CapabilityEvaluationRequest(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            goal_spec_id=goal_id,
            goal_spec_digest=goal_digest,
            requested_evaluation_kind=requested_evaluation_kind,
            policy_digest=policy.policy_digest,
        )

    async def capture(
        self,
        request: CapabilityEvaluationRequest,
        policy: CapabilityEvaluationPolicy,
    ) -> CapabilityEvidenceSnapshot:
        """Capture all selected source heads and rows in one read transaction."""

        if request.policy_digest != policy.policy_digest:
            raise EvaluationCaptureError("evaluation request policy digest mismatch")
        limit = min(policy.max_history_records_per_source, self._max_source_records)
        async with self._database.read_transaction() as conn:
            task_row = await self._task_row(conn, request.principal_id, request.project_id, request.task_id)
            if task_row is None:
                raise EvaluationNotFoundError("task is unavailable in the supplied owner scope")
            goal_row = await self._goal_row(conn, request.principal_id, request.project_id, request.task_id)
            if goal_row is not None and (
                str(goal_row["goal_spec_id"]) != request.goal_spec_id
                or str(goal_row["semantic_digest"]) != request.goal_spec_digest
            ):
                raise EvaluationCaptureError("GoalSpec identity changed before evidence capture")

            state, task_valid = _decode_state(task_row)
            workspace_id = _optional_text(state.get("workspace_id"))
            repository_id = _optional_text(state.get("repository_id"))
            base_revision = _optional_text(state.get("base_revision"))
            published_plan = _optional_text(_row_value(task_row, "published_plan_revision_id"))
            task_digest = canonical_digest(
                {
                    "task_id": request.task_id,
                    "principal_id": request.principal_id,
                    "project_id": request.project_id,
                    "status": str(task_row["status"]),
                    "cognitive_state": str(_row_value(task_row, "cognitive_state") or "uninitialized"),
                    "control_state_version": int(_row_value(task_row, "control_state_version") or 0),
                    "workspace_id": workspace_id,
                    "repository_id": repository_id,
                    "base_revision": base_revision,
                    "published_plan_revision_id": published_plan,
                }
            )
            task = TaskEvidence(
                task_id=request.task_id,
                principal_id=request.principal_id,
                project_id=request.project_id,
                status=str(task_row["status"]),
                cognitive_state=str(_row_value(task_row, "cognitive_state") or "uninitialized"),
                control_state_version=int(_row_value(task_row, "control_state_version") or 0),
                workspace_id=workspace_id,
                repository_id=repository_id,
                base_revision=base_revision,
                published_plan_revision_id=published_plan,
                task_digest=task_digest,
            )

            availability: dict[str, SourceAvailability] = {
                "task": SourceAvailability("task", task_valid),
                "goal_spec": SourceAvailability("goal_spec", goal_row is not None),
            }
            marks: dict[str, SourceHighWaterMark] = {
                "task": SourceHighWaterMark("task", None, request.task_id, task_digest, task_digest),
                "goal_spec": SourceHighWaterMark(
                    "goal_spec",
                    None,
                    str(goal_row["goal_spec_id"]) if goal_row is not None else None,
                    str(goal_row["semantic_digest"]) if goal_row is not None else None,
                ),
            }

            completion, availability["completion_decisions"], marks["completion_decisions"] = await self._completion(conn, request, limit)
            plan, availability["plan_revisions"], marks["plan_revisions"] = await self._records(
                conn,
                source="plan_revisions",
                query="""SELECT plan_revision_id, revision_sequence, plan_semantic_digest, disposition
                         FROM agent_plan_revisions
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY revision_sequence ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="plan_revision_id",
                sequence_key="revision_sequence",
                digest_key="plan_semantic_digest",
                field_keys=("disposition",),
            )
            verification, availability["verification_assessments"], marks["verification_assessments"] = await self._records(
                conn,
                source="verification_assessments",
                query="""SELECT assessment_id, assessment_sequence, assessment_digest,
                                disposition, goal_spec_id, goal_spec_digest,
                                control_state_version, task_status, workspace_id,
                                published_plan_revision_id
                         FROM agent_verification_assessments
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY assessment_sequence ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="assessment_id",
                sequence_key="assessment_sequence",
                digest_key="assessment_digest",
                field_keys=("disposition", "goal_spec_id", "goal_spec_digest", "control_state_version", "task_status", "workspace_id", "published_plan_revision_id"),
            )
            recovery, availability["recovery_decisions"], marks["recovery_decisions"] = await self._records(
                conn,
                source="recovery_decisions",
                query="""SELECT recovery_decision_id, recovery_sequence, decision_digest,
                                action, reason_code, identical_failure_streak
                         FROM agent_recovery_decisions
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY recovery_sequence ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="recovery_decision_id",
                sequence_key="recovery_sequence",
                digest_key="decision_digest",
                field_keys=("action", "reason_code", "identical_failure_streak"),
            )
            routes, availability["routes"], marks["routes"] = await self._records(
                conn,
                source="routes",
                query="""SELECT route_id, route_sequence, route_digest, route_disposition, reason_code
                         FROM agent_plan_tool_routes
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY route_sequence ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="route_id",
                sequence_key="route_sequence",
                digest_key="route_digest",
                field_keys=("route_disposition", "reason_code"),
            )
            steps, availability["step_states"], marks["step_states"] = await self._records(
                conn,
                source="step_states",
                query="""SELECT plan_step_id, plan_step_digest, state, attempt_generation,
                                execution_epoch_digest, updated_at
                         FROM agent_plan_step_states
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY updated_at ASC, plan_step_id ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="plan_step_id",
                sequence_key=None,
                digest_key="plan_step_digest",
                field_keys=("state", "attempt_generation", "execution_epoch_digest", "updated_at"),
            )
            marks["step_states"] = _with_state_digest(marks["step_states"], steps)
            fences, availability["dispatch_fences"], marks["dispatch_fences"] = await self._records(
                conn,
                source="dispatch_fences",
                query="""SELECT fence_id, route_digest, status, effect_status, effect_id,
                                created_at
                         FROM agent_plan_dispatch_fences
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY created_at ASC, fence_id ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="fence_id",
                sequence_key=None,
                digest_key="route_digest",
                field_keys=("status", "effect_status", "effect_id", "created_at"),
            )
            marks["dispatch_fences"] = _with_state_digest(marks["dispatch_fences"], fences)
            assignments, availability["subagent_assignments"], marks["subagent_assignments"] = await self._records(
                conn,
                source="subagent_assignments",
                query="""SELECT a.assignment_id, a.assignment_sequence, a.assignment_digest,
                                a.plan_step_id, r.state AS run_state,
                                r.state_version AS run_state_version,
                                s.state AS parent_step_state
                         FROM agent_subagent_assignments a
                         LEFT JOIN agent_subagent_runs r ON r.assignment_id = a.assignment_id
                         LEFT JOIN agent_plan_step_states s
                           ON s.principal_id = a.task_owner_principal_id
                          AND s.project_id = a.project_id
                          AND s.task_id = a.parent_task_id
                          AND s.execution_epoch_digest = a.execution_epoch_digest
                          AND s.plan_step_id = a.plan_step_id
                         WHERE a.task_owner_principal_id = ? AND a.project_id = ?
                           AND a.parent_task_id = ?
                         ORDER BY a.assignment_sequence ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="assignment_id",
                sequence_key="assignment_sequence",
                digest_key="assignment_digest",
                field_keys=("plan_step_id", "run_state", "run_state_version", "parent_step_state"),
            )
            assignment_availability = availability["subagent_assignments"]
            availability["subagent_runs"] = SourceAvailability(
                "subagent_runs",
                assignment_availability.available,
                assignment_availability.truncated,
                assignment_availability.reason,
            )
            marks["subagent_runs"] = _subagent_run_mark(assignments)
            turns, availability["turns"], marks["turns"] = await self._turns(conn, request, limit)
            audits, availability["audit_log"], marks["audit_log"] = await self._records(
                conn,
                source="audit_log",
                query="""SELECT id, action, result, operation_id
                         FROM audit_log
                         WHERE principal_id = ? AND project_id = ? AND task_id = ?
                         ORDER BY id ASC LIMIT ?""",
                params=(request.principal_id, request.project_id, request.task_id),
                limit=limit,
                id_key="id",
                sequence_key="id",
                digest_key=None,
                field_keys=("action", "result", "operation_id"),
            )
            memory, availability["memory"], marks["memory"] = await self._memory(conn, request, limit)

        return CapabilityEvidenceSnapshot(
            principal_id=request.principal_id,
            project_id=request.project_id,
            task_id=request.task_id,
            goal_spec_id=request.goal_spec_id,
            goal_spec_digest=request.goal_spec_digest,
            task=task,
            workspace_id=workspace_id,
            repository_id=repository_id,
            base_revision=base_revision,
            published_plan_revision_id=published_plan,
            source_high_water_marks=tuple(marks.values()),
            source_availability=tuple(availability.values()),
            captured_at=utc_now_naive().isoformat(),
            policy_digest=policy.policy_digest,
            evidence_schema_version=policy.evidence_schema_version,
            completion_decisions=completion,
            plan_revisions=plan,
            verification_assessments=verification,
            recovery_decisions=recovery,
            routes=routes,
            step_states=steps,
            dispatch_fences=fences,
            subagent_assignments=assignments,
            turns=turns,
            audit_events=audits,
            memory_observations=memory,
        )

    async def evaluate_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
        policy: CapabilityEvaluationPolicy | None = None,
        repository: CapabilityEvaluationRepository | None = None,
    ) -> CapabilityEvaluation:
        """Evaluate one task and optionally append the observation ledger row."""

        effective_policy = policy or CapabilityEvaluationPolicy.production()
        request = await self.request_for_task(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            policy=effective_policy,
        )
        snapshot = await self.capture(request, effective_policy)
        evaluation = CapabilityEvaluator().evaluate(snapshot, effective_policy)
        if repository is not None:
            return await repository.append(evaluation)
        return evaluation

    async def _task_row(self, conn: Any, principal_id: str, project_id: str, task_id: str) -> Any | None:
        cursor = await conn.execute(
            "SELECT * FROM coding_tasks WHERE id = ? AND principal_id = ? AND project_id = ?",
            (task_id, principal_id, project_id),
        )
        return await cursor.fetchone()

    async def _goal_row(self, conn: Any, principal_id: str, project_id: str, task_id: str) -> Any | None:
        cursor = await conn.execute(
            "SELECT * FROM agent_goal_specs WHERE task_id = ? AND principal_id = ? AND project_id = ?",
            (task_id, principal_id, project_id),
        )
        return await cursor.fetchone()

    async def _completion(self, conn: Any, request: CapabilityEvaluationRequest, limit: int) -> tuple[tuple[EvidenceRecord, ...], SourceAvailability, SourceHighWaterMark]:
        cursor = await conn.execute(
            """SELECT decision_id, decision_sequence, decision_digest, canonical_json
               FROM agent_completion_decisions
               WHERE principal_id = ? AND project_id = ? AND task_id = ?
               ORDER BY decision_sequence ASC LIMIT ?""",
            (request.principal_id, request.project_id, request.task_id, limit + 1),
        )
        rows = await cursor.fetchall()
        truncated = len(rows) > limit
        if truncated:
            rows = rows[:limit]
        records: list[EvidenceRecord] = []
        try:
            for row in rows:
                decision = CompletionDecision.from_canonical_json(
                    str(row["canonical_json"]),
                    expected_digest=str(row["decision_digest"]),
                )
                fields = {
                    "outcome": decision.outcome.value,
                    "task_status_at_evaluation": decision.task_status_at_evaluation,
                    "goal_spec_id": decision.goal_spec_id,
                    "goal_spec_digest": decision.goal_spec_digest,
                    "control_state_version": decision.control_state_version,
                }
                records.append(EvidenceRecord("completion_decisions", str(row["decision_id"]), str(row["decision_digest"]), int(row["decision_sequence"]), fields))
        except (json.JSONDecodeError, TypeError, ValueError, EvaluationContractError) as exc:
            availability = SourceAvailability("completion_decisions", False, truncated, type(exc).__name__)
            return (), availability, SourceHighWaterMark("completion_decisions", None, None, None)
        mark = _mark("completion_decisions", rows, "decision_id", "decision_sequence", "decision_digest")
        return tuple(records), SourceAvailability("completion_decisions", True, truncated, "bounded history" if truncated else ""), mark

    async def _records(self, conn: Any, *, source: str, query: str, params: tuple[Any, ...], limit: int, id_key: str, sequence_key: str | None, digest_key: str | None, field_keys: tuple[str, ...]) -> tuple[tuple[EvidenceRecord, ...], SourceAvailability, SourceHighWaterMark]:
        try:
            cursor = await conn.execute(query, (*params, limit + 1))
            rows = await cursor.fetchall()
        except sqlite3.Error as exc:
            return (), SourceAvailability(source, False, False, type(exc).__name__), SourceHighWaterMark(source, None, None, None)
        truncated = len(rows) > limit
        mark_row = rows[-1] if rows else None
        rows = rows[:limit]
        records: list[EvidenceRecord] = []
        try:
            for row in rows:
                record_id = str(row[id_key])
                sequence = int(row[sequence_key]) if sequence_key is not None and row[sequence_key] is not None else None
                raw_digest = str(row[digest_key]) if digest_key is not None and row[digest_key] else ""
                fields = {key: _json_scalar(row[key]) for key in field_keys}
                digest = raw_digest if _is_digest(raw_digest) else canonical_digest({"source": source, "record_id": record_id, "sequence": sequence, "fields": fields})
                records.append(EvidenceRecord(source, record_id, digest, sequence, fields))
        except (KeyError, TypeError, ValueError, EvaluationContractError) as exc:
            return (), SourceAvailability(source, False, truncated, type(exc).__name__), SourceHighWaterMark(source, None, None, None)
        mark = _mark(source, [mark_row] if mark_row is not None else [], id_key, sequence_key, digest_key, field_keys=field_keys)
        return tuple(records), SourceAvailability(source, True, truncated, "bounded history" if truncated else ""), mark

    async def _turns(self, conn: Any, request: CapabilityEvaluationRequest, limit: int) -> tuple[tuple[EvidenceRecord, ...], SourceAvailability, SourceHighWaterMark]:
        try:
            cursor = await conn.execute(
                """SELECT turn_id, status, started_at, finished_at
                   FROM agent_turns
                   WHERE principal_id = ? AND project_id = ? AND task_id = ?
                   ORDER BY started_at ASC, turn_id ASC LIMIT ?""",
                (request.principal_id, request.project_id, request.task_id, limit + 1),
            )
            rows = await cursor.fetchall()
            truncated = len(rows) > limit
            mark_row = rows[-1] if rows else None
            rows = rows[:limit]
            records: list[EvidenceRecord] = []
            for row in rows:
                event_cursor = await conn.execute(
                    "SELECT COUNT(*) AS count FROM agent_turn_events "
                    "WHERE turn_id = ? AND event_type LIKE 'tool.%'",
                    (row["turn_id"],),
                )
                event_count = await event_cursor.fetchone()
                fields = {
                    "status": str(row["status"]),
                    "started_at": row["started_at"],
                    "finished_at": row["finished_at"],
                    "tool_call_count": int(event_count["count"] if event_count is not None else 0),
                }
                digest = canonical_digest({"source": "turns", "record_id": str(row["turn_id"]), "fields": fields})
                records.append(EvidenceRecord("turns", str(row["turn_id"]), digest, None, fields))
            mark = _mark("turns", [mark_row] if mark_row is not None else [], "turn_id", None, None, field_keys=("status", "started_at", "finished_at"))
            return tuple(records), SourceAvailability("turns", True, truncated, "bounded history" if truncated else ""), mark
        except (sqlite3.Error, KeyError, TypeError, ValueError, EvaluationContractError) as exc:
            return (), SourceAvailability("turns", False, False, type(exc).__name__), SourceHighWaterMark("turns", None, None, None)

    async def _memory(self, conn: Any, request: CapabilityEvaluationRequest, limit: int) -> tuple[tuple[EvidenceRecord, ...], SourceAvailability, SourceHighWaterMark]:
        try:
            cursor = await conn.execute(
                """SELECT memory_id, record_digest, source_kind, status,
                          retrieval_count, provenance_json
                   FROM memory_nodes
                   WHERE principal_id = ? AND project_id = ?
                   ORDER BY updated_at ASC, memory_id ASC LIMIT ?""",
                (request.principal_id, request.project_id, limit + 1),
            )
            rows = await cursor.fetchall()
        except sqlite3.Error as exc:
            return (), SourceAvailability("memory", False, False, type(exc).__name__), SourceHighWaterMark("memory", None, None, None)
        truncated = len(rows) > limit
        mark_row = rows[-1] if rows else None
        selected: list[Any] = []
        try:
            for row in rows:
                provenance = json.loads(str(row["provenance_json"] or "{}"))
                if type(provenance) is dict and provenance.get("task_id") == request.task_id:
                    selected.append(row)
            selected = selected[:limit]
            records = tuple(
                EvidenceRecord(
                    "memory",
                    str(row["memory_id"]),
                    str(row["record_digest"]) if _is_digest(str(row["record_digest"] or "")) else canonical_digest({"memory_id": row["memory_id"], "source_kind": row["source_kind"], "status": row["status"]}),
                    None,
                    {"source_kind": str(row["source_kind"]), "status": str(row["status"]), "retrieval_count": int(row["retrieval_count"] or 0)},
                )
                for row in selected
            )
        except (json.JSONDecodeError, TypeError, ValueError, EvaluationContractError) as exc:
            return (), SourceAvailability("memory", False, truncated, type(exc).__name__), SourceHighWaterMark("memory", None, None, None)
        mark = SourceHighWaterMark("memory", None, str(mark_row["memory_id"]) if mark_row is not None else None, str(mark_row["record_digest"]) if mark_row is not None and _is_digest(str(mark_row["record_digest"] or "")) else (canonical_digest({"memory_id": mark_row["memory_id"]}) if mark_row is not None else None))
        return records, SourceAvailability("memory", True, truncated, "bounded history" if truncated else ""), mark


class CapabilityEvaluationService:
    """Facade that combines capture, pure evaluation, and optional persistence."""

    def __init__(self, evidence: CapabilityEvidenceService, repository: CapabilityEvaluationRepository):
        self.evidence = evidence
        self.repository = repository

    async def evaluate_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
        policy: CapabilityEvaluationPolicy | None = None,
    ) -> CapabilityEvaluation:
        return await self.evidence.evaluate_task(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            policy=policy,
            repository=self.repository,
        )

    async def latest_current_for_task(
        self,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
        policy: CapabilityEvaluationPolicy | None = None,
    ) -> CapabilityEvaluation | None:
        """Return history only when its source-bound snapshot is still current."""

        latest = await self.repository.latest_for_task(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
        )
        if latest is None:
            return None
        effective_policy = policy or CapabilityEvaluationPolicy.production()
        request = await self.evidence.request_for_task(
            principal_id=principal_id,
            project_id=project_id,
            task_id=task_id,
            policy=effective_policy,
        )
        current = await self.evidence.capture(request, effective_policy)
        return latest if latest.snapshot_digest == current.snapshot_digest else None


def build_capability_evaluation_service(database: Any) -> CapabilityEvaluationService:
    """Create M7.9 components without connecting them to an authority path."""

    policy = CapabilityEvaluationPolicy.production()
    return CapabilityEvaluationService(
        CapabilityEvidenceService(database, max_source_records=policy.max_history_records_per_source),
        CapabilityEvaluationRepository(database),
    )


def _decode_state(row: Any) -> tuple[dict[str, object], bool]:
    raw = str(_row_value(row, "state_json") or "{}")
    try:
        decoded = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}, False
    return (decoded, True) if type(decoded) is dict else ({}, False)


def _row_value(row: Any, key: str) -> Any:
    try:
        return row[key]
    except (KeyError, IndexError):
        return None


def _optional_text(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _json_scalar(value: Any) -> object:
    if value is None or type(value) in (str, int, float, bool):
        return value
    return str(value)


def _is_digest(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _mark(source: str, rows: list[Any], id_key: str, sequence_key: str | None, digest_key: str | None, *, field_keys: tuple[str, ...] = ()) -> SourceHighWaterMark:
    row = rows[-1] if rows else None
    if row is None:
        return SourceHighWaterMark(source, None, None, None)
    record_id = str(row[id_key])
    sequence = int(row[sequence_key]) if sequence_key is not None and row[sequence_key] is not None else None
    raw_digest = str(row[digest_key]) if digest_key is not None and row[digest_key] else ""
    if not _is_digest(raw_digest):
        fields = {key: _json_scalar(row[key]) for key in field_keys}
        raw_digest = canonical_digest({"source": source, "record_id": record_id, "sequence": sequence, "fields": fields})
    return SourceHighWaterMark(source, sequence, record_id, raw_digest)


def _subagent_run_mark(records: tuple[EvidenceRecord, ...]) -> SourceHighWaterMark:
    if not records:
        return SourceHighWaterMark("subagent_runs", None, None, None)
    latest = records[-1]
    state_digest = canonical_digest(
        {
            "assignment_id": latest.record_id,
            "run_state": latest.fields.get("run_state"),
            "run_state_version": latest.fields.get("run_state_version"),
        }
    )
    return SourceHighWaterMark("subagent_runs", latest.sequence, latest.record_id, state_digest, state_digest)


def _with_state_digest(mark: SourceHighWaterMark, records: tuple[EvidenceRecord, ...]) -> SourceHighWaterMark:
    """Bind a mutable projection HWM to the complete bounded state vector."""

    state_digest = canonical_digest([record.to_payload() for record in records])
    return SourceHighWaterMark(
        mark.source,
        mark.latest_sequence,
        mark.latest_record_id,
        mark.latest_record_digest,
        state_digest,
    )


__all__ = [
    "CapabilityEvaluationService",
    "CapabilityEvidenceService",
    "EvaluationCaptureError",
    "EvaluationNotFoundError",
    "build_capability_evaluation_service",
]
