"""Canonical run result objects for M8.0 reporting and persistence."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Awaitable, Callable, Mapping

from khaos.evaluation.coding.contracts import (
    CodingRunIdentity,
    CodingFailureReason,
    CodingScenarioKind,
    CodingVerdict,
    digest_payload,
)
from khaos.evaluation.coding.metrics import CodingMetrics, CodingTraceEvent
from khaos.evaluation.coding.oracle import DiffSummary, OracleEvaluation, ReviewFinding
from khaos.security.protocol_boundary import canonical_json_bytes


@dataclass(frozen=True, slots=True)
class AgentExecution:
    """Sanitized adapter result returned by a real runtime invocation."""

    status: str
    completion_status: str | None
    final_root: object
    runtime_id: str
    model: str
    provider: str
    review_findings: tuple[ReviewFinding, ...] = ()
    input_tokens: int | None = None
    output_tokens: int | None = None
    error: str | None = None
    task_id: str | None = None
    workspace_id: str | None = None
    cleanup: Callable[[], Awaitable[None]] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        for name in ("status", "runtime_id", "model", "provider"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"agent execution {name} is invalid")
        for name in ("completion_status", "error", "task_id", "workspace_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"agent execution {name} is invalid")
        if not isinstance(self.final_root, (str, Path)):
            raise ValueError("agent execution final_root is invalid")
        if not isinstance(self.review_findings, (list, tuple)) or any(
            not isinstance(finding, ReviewFinding) for finding in self.review_findings
        ):
            raise ValueError("agent execution review findings are invalid")
        object.__setattr__(self, "review_findings", tuple(self.review_findings))
        for name in ("input_tokens", "output_tokens"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"agent execution {name} is invalid")

    @property
    def completed(self) -> bool:
        if not isinstance(self.status, str) or self.status.casefold() not in {
            "completed", "passed", "success", "ok"
        }:
            return False
        if self.completion_status is None:
            return True
        if not isinstance(self.completion_status, str):
            return False
        return self.completion_status.casefold() in {
            "completed",
            "complete",
            "passed",
            "success",
            "ok",
            "done",
        }

    def to_payload(self) -> dict[str, object]:
        return {
            "status": self.status,
            "completion_status": self.completion_status,
            "runtime_id": self.runtime_id,
            "model": self.model,
            "provider": self.provider,
            "review_findings": [finding.to_payload() for finding in self.review_findings],
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "error": self.error,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
        }


@dataclass(frozen=True, slots=True)
class CodingEvaluationRun:
    """Immutable, append-only run evidence; no authority projection."""

    identity: CodingRunIdentity
    scenario_kind: CodingScenarioKind
    fixture_base_revision: str
    fixture_source_digest: str
    evaluated_source_digest: str
    verdict: CodingVerdict
    agent: AgentExecution
    metrics: CodingMetrics
    oracle: OracleEvaluation | None
    diff: DiffSummary
    trace: tuple[CodingTraceEvent, ...]
    started_at: str
    finished_at: str
    task_id: str | None = None
    workspace_id: str | None = None
    failure_reason: CodingFailureReason | None = None
    result_digest: str = ""

    def __post_init__(self) -> None:
        if not self.started_at or not self.finished_at:
            raise ValueError("coding evaluation timestamps are required")
        if not isinstance(self.identity, CodingRunIdentity):
            raise ValueError("coding evaluation identity is invalid")
        if not isinstance(self.scenario_kind, CodingScenarioKind):
            raise ValueError("coding evaluation scenario kind is invalid")
        if not isinstance(self.verdict, CodingVerdict):
            raise ValueError("coding evaluation verdict is invalid")
        if not isinstance(self.agent, AgentExecution):
            raise ValueError("coding evaluation agent is invalid")
        if not isinstance(self.metrics, CodingMetrics):
            raise ValueError("coding evaluation metrics are invalid")
        if self.metrics.verdict is not self.verdict:
            raise ValueError("coding evaluation verdict disagrees with metrics")
        if self.oracle is not None and not isinstance(self.oracle, OracleEvaluation):
            raise ValueError("coding evaluation oracle is invalid")
        if not isinstance(self.diff, DiffSummary):
            raise ValueError("coding evaluation diff is invalid")
        if not isinstance(self.trace, (list, tuple)) or any(
            not isinstance(event, CodingTraceEvent) for event in self.trace
        ):
            raise ValueError("coding evaluation trace is invalid")
        object.__setattr__(self, "trace", tuple(self.trace))
        if self.failure_reason is not None and not isinstance(self.failure_reason, CodingFailureReason):
            raise ValueError("coding evaluation failure reason is invalid")
        for name in ("task_id", "workspace_id"):
            value = getattr(self, name)
            if value is not None and not isinstance(value, str):
                raise ValueError(f"coding evaluation {name} is invalid")
        expected = digest_payload(self._payload_without_digest())
        if self.result_digest and self.result_digest != expected:
            raise ValueError("coding evaluation result digest does not match payload")
        object.__setattr__(self, "result_digest", expected)

    @classmethod
    def new(
        cls,
        *,
        identity: CodingRunIdentity,
        scenario_kind: CodingScenarioKind,
        fixture_base_revision: str,
        fixture_source_digest: str,
        evaluated_source_digest: str,
        verdict: CodingVerdict,
        agent: AgentExecution,
        metrics: CodingMetrics,
        oracle: OracleEvaluation | None,
        diff: DiffSummary,
        trace: tuple[CodingTraceEvent, ...],
        started_at: str,
        finished_at: str,
        task_id: str | None = None,
        workspace_id: str | None = None,
        failure_reason: CodingFailureReason | None = None,
    ) -> CodingEvaluationRun:
        return cls(
            identity=identity,
            scenario_kind=scenario_kind,
            fixture_base_revision=fixture_base_revision,
            fixture_source_digest=fixture_source_digest,
            evaluated_source_digest=evaluated_source_digest,
            verdict=verdict,
            agent=agent,
            metrics=metrics,
            oracle=oracle,
            diff=diff,
            trace=trace,
            started_at=started_at,
            finished_at=finished_at,
            task_id=task_id,
            workspace_id=workspace_id,
            failure_reason=failure_reason,
        )

    def _payload_without_digest(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "identity": self.identity.to_payload(),
            "scenario_kind": self.scenario_kind.value,
            "fixture_base_revision": self.fixture_base_revision,
            "fixture_source_digest": self.fixture_source_digest,
            "evaluated_source_digest": self.evaluated_source_digest,
            "verdict": self.verdict.value,
            "agent": self.agent.to_payload(),
            "metrics": self.metrics.to_payload(),
            "oracle": self.oracle.to_payload() if self.oracle is not None else None,
            "diff": self.diff.to_payload(),
            "trace": [event.to_payload() for event in self.trace],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "failure_reason": self.failure_reason.value if self.failure_reason is not None else None,
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload_without_digest(), "result_digest": self.result_digest}

    def canonical_json(self) -> str:
        return canonical_json_bytes(self.to_payload()).decode("utf-8")


def new_run_id() -> str:
    """Create a bounded opaque run identifier."""

    return f"m8-{uuid.uuid4().hex}"


def utc_timestamp() -> str:
    """Return a stable UTC timestamp for run evidence."""

    return datetime.now(UTC).isoformat()


__all__ = ["AgentExecution", "CodingEvaluationRun", "new_run_id", "utc_timestamp"]
