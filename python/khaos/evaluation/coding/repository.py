"""Owner-scoped append-only repository for M8.0 run evidence."""

from __future__ import annotations

import json
import sqlite3
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Any, Protocol

from khaos.evaluation.coding.contracts import (
    CodingRunIdentity,
    CodingFailureReason,
    CodingScenarioKind,
    CodingVerdict,
    OracleKind,
)
from khaos.evaluation.coding.metrics import CodingMetrics, CodingTraceEvent
from khaos.evaluation.coding.oracle import (
    DiffSummary,
    OracleCheckResult,
    OracleEvaluation,
    ReviewFinding,
)
from khaos.evaluation.coding.results import AgentExecution, CodingEvaluationRun


class CodingEvaluationDatabase(Protocol):
    def transaction(self) -> AbstractAsyncContextManager[Any]: ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]: ...


class CodingEvaluationRepositoryError(RuntimeError):
    """Base error for Coding evaluation ledger failures."""


class CodingEvaluationConflictError(CodingEvaluationRepositoryError):
    """An immutable run identity already exists."""


class CodingEvaluationIntegrityError(CodingEvaluationRepositoryError):
    """Stored run evidence failed closed validation."""


class CodingEvaluationRepository:
    """The sole writer/reader for ``coding_evaluation_runs``."""

    def __init__(
        self,
        database: CodingEvaluationDatabase,
        *,
        principal_id: str = "evaluation",
        project_id: str = "coding-evaluation",
    ) -> None:
        self._database = database
        if not principal_id or not project_id:
            raise ValueError("coding evaluation owner identity is required")
        self._principal_id = principal_id
        self._project_id = project_id

    async def append(self, run: CodingEvaluationRun) -> CodingEvaluationRun:
        """Append one canonical run; callers cannot choose a second payload."""

        if type(run) is not CodingEvaluationRun:
            raise TypeError("run must be a CodingEvaluationRun")
        payload = run.canonical_json()
        async with self._database.transaction() as conn:
            try:
                await conn.execute(
                    """INSERT INTO coding_evaluation_runs (
                        run_id, principal_id, project_id, scenario_id,
                        scenario_version, scenario_digest, fixture_digest,
                        source_sha, verdict, result_json, result_digest,
                        started_at, finished_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run.identity.run_id,
                        self._principal_id,
                        self._project_id,
                        run.identity.scenario_id,
                        run.identity.scenario_version,
                        run.identity.scenario_digest,
                        run.identity.fixture_digest,
                        run.identity.source_sha,
                        run.verdict.value,
                        payload,
                        run.result_digest,
                        run.started_at,
                        run.finished_at,
                        run.finished_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CodingEvaluationConflictError("coding evaluation append conflicted") from exc
        return run

    async def append_owned(
        self,
        run: CodingEvaluationRun,
        *,
        principal_id: str,
        project_id: str,
    ) -> CodingEvaluationRun:
        """Append with the explicit owner identity used by the ledger row."""

        if not principal_id or not project_id:
            raise ValueError("coding evaluation owner identity is required")
        if type(run) is not CodingEvaluationRun:
            raise TypeError("run must be a CodingEvaluationRun")
        payload = run.canonical_json()
        async with self._database.transaction() as conn:
            try:
                await conn.execute(
                    """INSERT INTO coding_evaluation_runs (
                        run_id, principal_id, project_id, scenario_id,
                        scenario_version, scenario_digest, fixture_digest,
                        source_sha, verdict, result_json, result_digest,
                        started_at, finished_at, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        run.identity.run_id,
                        principal_id,
                        project_id,
                        run.identity.scenario_id,
                        run.identity.scenario_version,
                        run.identity.scenario_digest,
                        run.identity.fixture_digest,
                        run.identity.source_sha,
                        run.verdict.value,
                        payload,
                        run.result_digest,
                        run.started_at,
                        run.finished_at,
                        run.finished_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise CodingEvaluationConflictError("coding evaluation append conflicted") from exc
        return run

    async def get_by_id(
        self,
        run_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> CodingEvaluationRun | None:
        """Read one run only in its authenticated owner scope."""

        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """SELECT * FROM coding_evaluation_runs
                   WHERE run_id = ? AND principal_id = ? AND project_id = ?""",
                (run_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _decode_row(row) if row is not None else None

    async def list(
        self,
        *,
        principal_id: str,
        project_id: str,
        scenario_id: str | None = None,
        limit: int = 256,
        descending: bool = True,
    ) -> tuple[CodingEvaluationRun, ...]:
        """Read a bounded owner-scoped run history."""

        if type(limit) is not int or not 1 <= limit <= 10_000:
            raise ValueError("coding evaluation history limit is outside bounds")
        query = """SELECT * FROM coding_evaluation_runs
                   WHERE principal_id = ? AND project_id = ?"""
        params: list[object] = [principal_id, project_id]
        if scenario_id is not None:
            query += " AND scenario_id = ?"
            params.append(scenario_id)
        query += f" ORDER BY created_at {'DESC' if descending else 'ASC'}, run_id LIMIT ?"
        params.append(limit)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(query, tuple(params))
            rows = await cursor.fetchall()
        return tuple(_decode_row(row) for row in rows)


def _decode_row(row: Any) -> CodingEvaluationRun:
    try:
        payload = json.loads(str(row["result_json"]))
        if not isinstance(payload, dict) or set(payload) != {
            "schema_version", "identity", "scenario_kind", "fixture_base_revision",
            "fixture_source_digest", "evaluated_source_digest", "verdict", "agent",
            "metrics", "oracle", "diff", "trace", "started_at", "finished_at",
            "task_id", "workspace_id", "failure_reason", "result_digest",
        }:
            raise ValueError("coding evaluation JSON schema is not closed")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise ValueError("coding evaluation schema version is unsupported")
        identity_data = _expect_dict(payload["identity"], "identity")
        if set(identity_data) != set(CodingRunIdentity.__dataclass_fields__):
            raise ValueError("coding evaluation identity schema is not closed")
        identity = CodingRunIdentity(**identity_data)
        agent_data = _expect_dict(payload["agent"], "agent")
        if set(agent_data) != {
            "status", "completion_status", "runtime_id", "model", "provider",
            "review_findings", "input_tokens", "output_tokens", "error",
            "task_id", "workspace_id",
        }:
            raise ValueError("coding evaluation agent schema is not closed")
        raw_findings = agent_data.pop("review_findings", [])
        if not isinstance(raw_findings, list):
            raise ValueError("agent review_findings must be a list")
        findings = tuple(
            ReviewFinding.from_mapping(_expect_dict(item, "review finding"))
            for item in raw_findings
        )
        agent = AgentExecution(
            status=agent_data["status"],
            completion_status=agent_data["completion_status"],
            final_root=Path("<persisted-evaluation>"),
            runtime_id=agent_data["runtime_id"],
            model=agent_data["model"],
            provider=agent_data["provider"],
            review_findings=findings,
            input_tokens=agent_data["input_tokens"],
            output_tokens=agent_data["output_tokens"],
            error=agent_data["error"],
            task_id=agent_data.get("task_id"),
            workspace_id=agent_data.get("workspace_id"),
        )
        metrics_data = _expect_dict(payload["metrics"], "metrics")
        if set(metrics_data) != set(CodingMetrics.__dataclass_fields__):
            raise ValueError("coding evaluation metrics schema is not closed")
        metrics_data["verdict"] = CodingVerdict(metrics_data["verdict"])
        metrics = CodingMetrics(
            **metrics_data,
        )
        oracle = _decode_oracle(payload["oracle"])
        diff_data = _expect_dict(payload["diff"], "diff")
        if set(diff_data) != {
            "changed_files", "added_files", "deleted_files", "renamed_files",
            "insertions", "deletions", "binary_files", "digest",
        }:
            raise ValueError("coding evaluation diff schema is not closed")
        diff = DiffSummary(
            changed_files=_expect_string_sequence(diff_data["changed_files"], "diff.changed_files"),
            added_files=_expect_string_sequence(diff_data["added_files"], "diff.added_files"),
            deleted_files=_expect_string_sequence(diff_data["deleted_files"], "diff.deleted_files"),
            renamed_files=_expect_string_sequence(diff_data["renamed_files"], "diff.renamed_files"),
            insertions=diff_data["insertions"],
            deletions=diff_data["deletions"],
            binary_files=_expect_string_sequence(diff_data["binary_files"], "diff.binary_files"),
            digest=_expect_string(diff_data["digest"], "diff.digest"),
        )
        if not isinstance(payload["trace"], list):
            raise ValueError("coding evaluation trace must be a list")
        trace = tuple(
            CodingTraceEvent(**_expect_dict(item, "trace event"))
            for item in payload["trace"]
        )
        run = CodingEvaluationRun(
            identity=identity,
            scenario_kind=CodingScenarioKind(payload["scenario_kind"]),
            fixture_base_revision=_expect_string(payload["fixture_base_revision"], "fixture_base_revision"),
            fixture_source_digest=_expect_string(payload["fixture_source_digest"], "fixture_source_digest"),
            evaluated_source_digest=_expect_string(payload["evaluated_source_digest"], "evaluated_source_digest"),
            verdict=CodingVerdict(payload["verdict"]),
            agent=agent,
            metrics=metrics,
            oracle=oracle,
            diff=diff,
            trace=trace,
            started_at=_expect_string(payload["started_at"], "started_at"),
            finished_at=_expect_string(payload["finished_at"], "finished_at"),
            task_id=_expect_optional_string(payload["task_id"], "task_id"),
            workspace_id=_expect_optional_string(payload["workspace_id"], "workspace_id"),
            failure_reason=(
                CodingFailureReason(payload["failure_reason"])
                if payload["failure_reason"] is not None
                else None
            ),
            result_digest=_expect_string(payload["result_digest"], "result_digest"),
        )
        for key, value in {
            "run_id": run.identity.run_id,
            "scenario_id": run.identity.scenario_id,
            "scenario_version": run.identity.scenario_version,
            "scenario_digest": run.identity.scenario_digest,
            "fixture_digest": run.identity.fixture_digest,
            "source_sha": run.identity.source_sha,
            "verdict": run.verdict.value,
            "result_digest": run.result_digest,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }.items():
            if row[key] != value:
                raise ValueError(f"coding evaluation scalar {key} disagrees with JSON")
        if run.canonical_json() != str(row["result_json"]):
            raise ValueError("coding evaluation JSON is not canonical")
        return run
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise CodingEvaluationIntegrityError("stored coding evaluation failed closed validation") from exc


def _expect_dict(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object")
    return dict(value)


def _expect_string(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    return value


def _expect_optional_string(value: object, label: str) -> str | None:
    if value is not None and not isinstance(value, str):
        raise ValueError(f"{label} must be a string or null")
    return value


def _expect_string_sequence(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{label} must be a list of strings")
    return tuple(value)


def _decode_oracle(value: object) -> OracleEvaluation | None:
    if value is None:
        return None
    data = _expect_dict(value, "oracle")
    if set(data) != {"verdict", "checks", "evidence_digest", "error"}:
        raise ValueError("coding evaluation oracle schema is not closed")
    if not isinstance(data["checks"], list):
        raise ValueError("coding evaluation oracle checks must be a list")
    checks: list[OracleCheckResult] = []
    for item in data["checks"]:
        check = _expect_dict(item, "oracle check")
        if set(check) != {"kind", "passed", "summary", "evidence"}:
            raise ValueError("coding evaluation oracle check schema is not closed")
        if type(check["passed"]) is not bool:
            raise ValueError("coding evaluation oracle check passed is not boolean")
        checks.append(
            OracleCheckResult(
                kind=OracleKind(check["kind"]),
                passed=check["passed"],
                summary=check["summary"],
                evidence=_expect_dict(check["evidence"], "oracle evidence"),
            )
        )
    if data["error"] is not None and not isinstance(data["error"], str):
        raise ValueError("coding evaluation oracle error is invalid")
    return OracleEvaluation(
        verdict=CodingVerdict(data["verdict"]),
        checks=tuple(checks),
        evidence_digest=data["evidence_digest"],
        error=data["error"],
    )


__all__ = [
    "CodingEvaluationConflictError",
    "CodingEvaluationIntegrityError",
    "CodingEvaluationRepository",
    "CodingEvaluationRepositoryError",
]
