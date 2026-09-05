"""Bounded autonomous-verification evidence and observation persistence.

This ledger is deliberately an observation store.  It preserves immutable
plan/check/result identities across restarts, but it is not a completion or
execution authority.  Positive completion proof continues through the
existing M4/M7 trusted-verification ledger and ``CompletionGate``.
"""

from __future__ import annotations

import json
import math
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from typing import Any, Protocol

from khaos.coding.verification.contracts import (
    VerificationCheckStatus,
    VerificationContractError,
    VerificationDiagnostic,
    VerificationPlan,
    VerificationRunStatus,
)
from khaos.security.protocol_boundary import canonical_digest

_MAX_EVIDENCE = 256
_MAX_RUNS_IN_MEMORY = 256


def _digest(value: object, *, label: str, allow_empty: bool = False) -> str:
    if allow_empty and value == "":
        return ""
    if type(value) is not str or len(value) != 64 or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise VerificationContractError(f"{label} must be a SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class VerificationEvidence:
    """One immutable, output-digest-only check result."""

    run_id: str
    plan_id: str
    check_id: str
    workspace_id: str
    workspace_generation: int
    repository_generation: int
    command_digest: str
    status: VerificationCheckStatus
    exit_code: int | None
    duration_ms: int
    stdout_digest: str
    stderr_digest: str
    output_truncated: bool
    diagnostics: tuple[VerificationDiagnostic, ...] = ()
    evidence_digest: str = ""
    started_at: float = 0.0
    finished_at: float = 0.0

    def __post_init__(self) -> None:
        for label, value in (
            ("run_id", self.run_id),
            ("plan_id", self.plan_id),
            ("check_id", self.check_id),
            ("workspace_id", self.workspace_id),
        ):
            if type(value) is not str or not value or len(value) > 512:
                raise VerificationContractError(f"{label} is invalid")
        for label, value in (
            ("workspace_generation", self.workspace_generation),
            ("repository_generation", self.repository_generation),
            ("duration_ms", self.duration_ms),
        ):
            if type(value) is not int or value < 0:
                raise VerificationContractError(f"{label} is invalid")
        object.__setattr__(self, "command_digest", _digest(self.command_digest, label="command_digest"))
        status = self.status
        if isinstance(status, str):
            status = VerificationCheckStatus(status)
            object.__setattr__(self, "status", status)
        if type(status) is not VerificationCheckStatus:
            raise VerificationContractError("evidence status is invalid")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise VerificationContractError("exit_code is invalid")
        object.__setattr__(self, "stdout_digest", _digest(self.stdout_digest, label="stdout_digest", allow_empty=True))
        object.__setattr__(self, "stderr_digest", _digest(self.stderr_digest, label="stderr_digest", allow_empty=True))
        if type(self.output_truncated) is not bool:
            raise VerificationContractError("output_truncated must be a bool")
        if (
            type(self.started_at) not in (int, float)
            or type(self.finished_at) not in (int, float)
            or not math.isfinite(float(self.started_at))
            or not math.isfinite(float(self.finished_at))
            or self.started_at < 0
            or self.finished_at < self.started_at
        ):
            raise VerificationContractError("evidence timestamps are invalid")
        if type(self.diagnostics) is not tuple or len(self.diagnostics) > _MAX_EVIDENCE or any(
            type(item) is not VerificationDiagnostic for item in self.diagnostics
        ):
            raise VerificationContractError("diagnostics are invalid")
        computed = self._computed_digest()
        if self.evidence_digest:
            object.__setattr__(self, "evidence_digest", _digest(self.evidence_digest, label="evidence_digest"))
            if self.evidence_digest != computed:
                raise VerificationContractError("evidence_digest does not match evidence")
        else:
            object.__setattr__(self, "evidence_digest", computed)

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "plan_id": self.plan_id,
            "check_id": self.check_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "repository_generation": self.repository_generation,
            "command_digest": self.command_digest,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "output_truncated": self.output_truncated,
            "diagnostics": tuple(item.to_payload() for item in self.diagnostics),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }

    def _computed_digest(self) -> str:
        return canonical_digest(self._payload_without_digest())

    def is_valid(self) -> bool:
        return self.evidence_digest == self._computed_digest()

    def to_payload(self) -> dict[str, object]:
        payload = self._payload_without_digest()
        payload["evidence_digest"] = self.evidence_digest
        return payload


@dataclass(frozen=True, slots=True)
class VerificationEvidenceSet:
    """Plan-bound set of check observations, separate from completion authority."""

    plan: VerificationPlan
    evidence: tuple[VerificationEvidence, ...]

    def __post_init__(self) -> None:
        if type(self.plan) is not VerificationPlan or not self.plan.is_valid():
            raise VerificationContractError("evidence set plan is invalid")
        if type(self.evidence) is not tuple or len(self.evidence) > _MAX_EVIDENCE:
            raise VerificationContractError("evidence set is invalid")
        checks = {check.check_id: check for check in self.plan.checks}
        seen: set[str] = set()
        for item in self.evidence:
            if type(item) is not VerificationEvidence:
                raise VerificationContractError("evidence set contains an invalid item")
            if item.check_id in seen:
                raise VerificationContractError("evidence set contains duplicate checks")
            check = checks.get(item.check_id)
            if check is None:
                raise VerificationContractError("evidence set contains an unknown check")
            if (
                item.plan_id != self.plan.plan_id
                or item.workspace_id != self.plan.workspace_id
                or item.workspace_generation != self.plan.workspace_generation
                or item.repository_generation != self.plan.repository_generation
                or item.command_digest != check.command_digest
            ):
                raise VerificationContractError("evidence is not bound to the plan")
            if not item.is_valid():
                raise VerificationContractError("evidence digest is invalid")
            seen.add(item.check_id)

    @property
    def workspace_generation(self) -> int:
        """Return the exact workspace generation covered by this set."""
        return self.plan.workspace_generation

    @property
    def repository_generation(self) -> int:
        """Return the exact repository-intelligence generation covered by this set."""
        return self.plan.repository_generation

    @property
    def required_checks_complete(self) -> bool:
        """Return whether every required plan check has an observation."""
        observed = {item.check_id for item in self.evidence}
        return bool(self.plan.required_checks) and all(
            check.check_id in observed for check in self.plan.required_checks
        )

    @property
    def required_checks_passed(self) -> bool:
        """Return required-check sufficiency, never a completion decision."""
        if not self.required_checks_complete:
            return False
        by_id = {item.check_id: item for item in self.evidence}
        return all(
            by_id[check.check_id].status is VerificationCheckStatus.PASSED
            and not by_id[check.check_id].output_truncated
            for check in self.plan.required_checks
        )

    @property
    def remaining_required_checks(self) -> tuple[str, ...]:
        """Return required checks with no recorded observation yet."""
        observed = {item.check_id for item in self.evidence}
        return tuple(
            check.check_id
            for check in self.plan.required_checks
            if check.check_id not in observed
        )

    @property
    def passed_count(self) -> int:
        """Count only required, non-truncated passing observations."""
        required_ids = {check.check_id for check in self.plan.required_checks}
        return sum(
            item.check_id in required_ids
            and item.status is VerificationCheckStatus.PASSED
            and not item.output_truncated
            for item in self.evidence
        )

    @property
    def set_digest(self) -> str:
        """Return a digest of the exact plan/evidence identity set."""
        return canonical_digest(
            {
                "plan_digest": self.plan.plan_digest,
                "workspace_generation": self.workspace_generation,
                "repository_generation": self.repository_generation,
                "evidence": tuple(item.evidence_digest for item in self.evidence),
            }
        )

    def is_current(
        self,
        *,
        workspace_id: str,
        workspace_generation: int,
        repository_generation: int,
        plan_id: str,
        plan_digest: str,
    ) -> bool:
        """Require exact workspace, repository, plan, and generation identity."""
        return (
            self.plan.workspace_id == workspace_id
            and self.workspace_generation == workspace_generation
            and self.repository_generation == repository_generation
            and self.plan.plan_id == plan_id
            and self.plan.plan_digest == plan_digest
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "plan_id": self.plan.plan_id,
            "plan_digest": self.plan.plan_digest,
            "workspace_id": self.plan.workspace_id,
            "workspace_generation": self.workspace_generation,
            "repository_generation": self.repository_generation,
            "evidence": tuple(item.to_payload() for item in self.evidence),
            "remaining_required_checks": self.remaining_required_checks,
            "required_checks_passed": self.required_checks_passed,
            "set_digest": self.set_digest,
        }


@dataclass(frozen=True, slots=True)
class VerificationRun:
    """Aggregate result for one autonomous plan execution."""

    run_id: str
    plan: VerificationPlan
    status: VerificationRunStatus
    evidence: tuple[VerificationEvidence, ...]
    started_at: float
    finished_at: float
    diagnostics: tuple[VerificationDiagnostic, ...] = ()

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or not self.run_id:
            raise VerificationContractError("run_id is invalid")
        if type(self.plan) is not VerificationPlan or not self.plan.is_valid():
            raise VerificationContractError("run plan is invalid")
        status = self.status
        if isinstance(status, str):
            status = VerificationRunStatus(status)
            object.__setattr__(self, "status", status)
        if type(status) is not VerificationRunStatus:
            raise VerificationContractError("run status is invalid")
        if type(self.evidence) is not tuple or len(self.evidence) > _MAX_EVIDENCE or any(
            type(item) is not VerificationEvidence for item in self.evidence
        ):
            raise VerificationContractError("run evidence is invalid")
        if any(item.run_id != self.run_id or item.plan_id != self.plan.plan_id for item in self.evidence):
            raise VerificationContractError("run evidence is not bound to the run")
        # Validate command/generation binding once at the run boundary.  The
        # set remains an observation object; it never grants completion.
        _ = self.evidence_set
        if (
            type(self.started_at) not in (int, float)
            or type(self.finished_at) not in (int, float)
            or not math.isfinite(float(self.started_at))
            or not math.isfinite(float(self.finished_at))
        ):
            raise VerificationContractError("run timestamps are invalid")
        if self.started_at < 0 or self.finished_at < self.started_at:
            raise VerificationContractError("run timestamps are out of order")
        if type(self.diagnostics) is not tuple or any(type(item) is not VerificationDiagnostic for item in self.diagnostics):
            raise VerificationContractError("run diagnostics are invalid")

    @property
    def required_checks_passed(self) -> bool:
        """Return a descriptive aggregate; it never grants completion."""
        return self.evidence_set.required_checks_passed

    @property
    def evidence_set(self) -> VerificationEvidenceSet:
        """Return the validated plan-bound observation set for this run."""
        return VerificationEvidenceSet(self.plan, self.evidence)

    @property
    def passed_count(self) -> int:
        return self.evidence_set.passed_count

    @property
    def required_count(self) -> int:
        return len(self.plan.required_checks)

    @property
    def result_digest(self) -> str:
        return canonical_digest(
            {
                "run_id": self.run_id,
                "plan_digest": self.plan.plan_digest,
                "status": self.status.value,
                "evidence": tuple(item.evidence_digest for item in self.evidence),
                "diagnostics": tuple(item.to_payload() for item in self.diagnostics),
            }
        )

    def is_current(
        self,
        *,
        workspace_id: str,
        workspace_generation: int,
        repository_generation: int,
        plan_id: str,
        plan_digest: str,
    ) -> bool:
        """Validate exact workspace/plan/generation identity."""
        return (
            self.plan.workspace_id == workspace_id
            and self.plan.workspace_generation == workspace_generation
            and self.plan.repository_generation == repository_generation
            and self.plan.plan_id == plan_id
            and self.plan.plan_digest == plan_digest
            and all(
                item.workspace_id == workspace_id
                and item.workspace_generation == workspace_generation
                and item.repository_generation == repository_generation
                for item in self.evidence
            )
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "plan": self.plan.to_payload(),
            "status": self.status.value,
            "evidence": tuple(item.to_payload() for item in self.evidence),
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "diagnostics": tuple(item.to_payload() for item in self.diagnostics),
            "result_digest": self.result_digest,
            "required_count": self.required_count,
            "passed_count": self.passed_count,
        }


@dataclass(frozen=True, slots=True)
class StoredVerificationRun:
    """Owner-scoped durable observation identity."""

    run_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    repository_generation: int
    plan_id: str
    plan_digest: str
    status: VerificationRunStatus
    required_count: int
    passed_count: int
    result_digest: str
    created_at: str
    run: VerificationRun | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("run_id", self.run_id),
            ("task_id", self.task_id),
            ("workspace_id", self.workspace_id),
            ("plan_id", self.plan_id),
            ("created_at", self.created_at),
        ):
            if type(value) is not str or not value:
                raise VerificationContractError(f"{label} is invalid")
        for label, value in (
            ("workspace_generation", self.workspace_generation),
            ("repository_generation", self.repository_generation),
            ("required_count", self.required_count),
            ("passed_count", self.passed_count),
        ):
            if type(value) is not int or value < 0:
                raise VerificationContractError(f"{label} is invalid")
        if self.passed_count > self.required_count:
            raise VerificationContractError("passed_count exceeds required_count")
        object.__setattr__(self, "plan_digest", _digest(self.plan_digest, label="plan_digest"))
        object.__setattr__(self, "result_digest", _digest(self.result_digest, label="result_digest"))
        status = self.status
        if isinstance(status, str):
            status = VerificationRunStatus(status)
            object.__setattr__(self, "status", status)
        if type(status) is not VerificationRunStatus:
            raise VerificationContractError("stored run status is invalid")


class VerificationObservationDatabase(Protocol):
    """Minimal shared-database port for the append-only observation ledger."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared single-writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class VerificationObservationStore:
    """Persist M8.3 runs without creating an authority or lifecycle writer."""

    def __init__(self, database: VerificationObservationDatabase | None = None) -> None:
        self._database = database
        self._memory: list[StoredVerificationRun] = []
        self._memory_owners: dict[str, tuple[str, str]] = {}

    async def append(
        self,
        run: VerificationRun,
        *,
        principal_id: str,
        project_id: str,
        task_id: str,
    ) -> StoredVerificationRun:
        """Append one immutable run observation, idempotently by run identity."""
        if type(run) is not VerificationRun:
            raise TypeError("run must be a VerificationRun")
        for label, value in (("principal_id", principal_id), ("project_id", project_id), ("task_id", task_id)):
            if type(value) is not str or not value:
                raise ValueError(f"{label} must be non-empty")
        stored = StoredVerificationRun(
            run_id=run.run_id,
            task_id=task_id,
            workspace_id=run.plan.workspace_id,
            workspace_generation=run.plan.workspace_generation,
            repository_generation=run.plan.repository_generation,
            plan_id=run.plan.plan_id,
            plan_digest=run.plan.plan_digest,
            status=run.status,
            required_count=run.required_count,
            passed_count=run.passed_count,
            result_digest=run.result_digest,
            created_at=f"{run.finished_at:.6f}",
            run=run,
        )
        if self._database is None:
            existing = next((item for item in self._memory if item.run_id == run.run_id), None)
            if existing is not None:
                if self._memory_owners.get(run.run_id) != (principal_id, project_id):
                    raise PermissionError("verification run belongs to another owner")
                if existing.result_digest != stored.result_digest:
                    raise ValueError("verification run identity is already bound to another result")
                return existing
            self._memory.append(stored)
            self._memory_owners[run.run_id] = (principal_id, project_id)
            self._memory = self._memory[-_MAX_RUNS_IN_MEMORY:]
            live_ids = {item.run_id for item in self._memory}
            self._memory_owners = {
                run_id: owner
                for run_id, owner in self._memory_owners.items()
                if run_id in live_ids
            }
            return stored
        payload = json.dumps(run.to_payload(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        async with self._database.transaction() as connection:
            await connection.execute(
                """
                INSERT INTO autonomous_verification_runs (
                    run_id, principal_id, project_id, task_id, workspace_id,
                    workspace_generation, repository_generation, plan_id,
                    plan_digest, status, required_count, passed_count,
                    result_json, result_digest, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO NOTHING
                """,
                (
                    stored.run_id,
                    principal_id,
                    project_id,
                    stored.task_id,
                    stored.workspace_id,
                    stored.workspace_generation,
                    stored.repository_generation,
                    stored.plan_id,
                    stored.plan_digest,
                    stored.status.value,
                    stored.required_count,
                    stored.passed_count,
                    payload,
                    stored.result_digest,
                    stored.created_at,
                ),
            )
            cursor = await connection.execute(
                """
                SELECT run_id, task_id, workspace_id, workspace_generation,
                       repository_generation, plan_id, plan_digest, status,
                       required_count, passed_count, result_digest, created_at
                FROM autonomous_verification_runs
                WHERE run_id = ? AND principal_id = ? AND project_id = ?
                """,
                (stored.run_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
            if row is None:
                owner_cursor = await connection.execute(
                    """
                    SELECT principal_id, project_id, result_digest
                    FROM autonomous_verification_runs
                    WHERE run_id = ?
                    """,
                    (stored.run_id,),
                )
                owner_row = await owner_cursor.fetchone()
                if owner_row is not None:
                    raise PermissionError(
                        "verification run belongs to another owner"
                    )
        if row is None:
            raise RuntimeError("autonomous verification observation was not persisted")
        persisted = _stored_from_row(row)
        if persisted.result_digest != stored.result_digest:
            raise ValueError("verification run identity is already bound to another result")
        return persisted

    async def latest_for_task(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> StoredVerificationRun | None:
        """Return the latest owner-scoped observation, if any."""
        if self._database is None:
            values = [
                item
                for item in self._memory
                if item.task_id == task_id
                and self._memory_owners.get(item.run_id) == (principal_id, project_id)
            ]
            return values[-1] if values else None
        async with self._database.read_connection() as connection:
            cursor = await connection.execute(
                """
                SELECT run_id, task_id, workspace_id, workspace_generation,
                       repository_generation, plan_id, plan_digest, status,
                       required_count, passed_count, result_digest, created_at
                FROM autonomous_verification_runs
                WHERE task_id = ? AND principal_id = ? AND project_id = ?
                ORDER BY CAST(created_at AS REAL) DESC, run_id DESC LIMIT 1
                """,
                (task_id, principal_id, project_id),
            )
            row = await cursor.fetchone()
        return _stored_from_row(row) if row is not None else None


def _stored_from_row(row: Any) -> StoredVerificationRun:
    values = dict(row) if not isinstance(row, dict) else row
    return StoredVerificationRun(
        run_id=str(values["run_id"]),
        task_id=str(values["task_id"]),
        workspace_id=str(values["workspace_id"]),
        workspace_generation=int(values["workspace_generation"]),
        repository_generation=int(values["repository_generation"]),
        plan_id=str(values["plan_id"]),
        plan_digest=str(values["plan_digest"]),
        status=VerificationRunStatus(str(values["status"])),
        required_count=int(values["required_count"]),
        passed_count=int(values["passed_count"]),
        result_digest=str(values["result_digest"]),
        created_at=str(values["created_at"]),
    )


# Names used in the milestone text.
VerificationEvidenceStore = VerificationObservationStore
VerificationEvidenceLedger = VerificationObservationStore
VerificationRunResult = VerificationRun


__all__ = [
    "StoredVerificationRun",
    "VerificationEvidence",
    "VerificationEvidenceLedger",
    "VerificationEvidenceSet",
    "VerificationEvidenceStore",
    "VerificationObservationDatabase",
    "VerificationObservationStore",
    "VerificationRun",
    "VerificationRunResult",
]
