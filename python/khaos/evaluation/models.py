"""Immutable contracts for deterministic capability evaluation.

M7.9 is deliberately an observation plane.  The value objects in this
module contain evidence identities and bounded metric facts; none of them
can be used as an execution, approval, completion, or policy capability.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any, cast

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 512


class EvaluationContractError(ValueError):
    """Raised when an evaluation contract is malformed or inconsistent."""


class EvaluationDisposition(str, Enum):
    """Closed disposition for an evaluation observation."""

    EVALUATED = "EVALUATED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    STALE = "STALE"
    INVALID = "INVALID"


class SecurityIntegrity(str, Enum):
    """Security is a hard dimension and cannot be averaged with productivity."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class SecurityFailurePolicy(str, Enum):
    """Trusted policy for handling an observed security violation."""

    HARD_FAIL = "HARD_FAIL"


# Public spelling used by the M7.9 policy contract.  Keep the security
# prefixed implementation name available for callers that prefer it.
SafetyFailurePolicy = SecurityFailurePolicy


class IncompleteEvidencePolicy(str, Enum):
    """Trusted policy for missing or bounded-out evidence."""

    EXPLICIT_DISPOSITION = "EXPLICIT_DISPOSITION"


def _text(value: object, *, label: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not value) or len(value) > _MAX_TEXT:
        raise EvaluationContractError(f"{label} must be bounded text")
    return value


def _digest(value: object, *, label: str, allow_empty: bool = False) -> str:
    if type(value) is not str or (not allow_empty and not _HEX_DIGEST.fullmatch(value)):
        raise EvaluationContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _freeze(value: object) -> object:
    """Recursively freeze JSON values used by evidence records."""

    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise EvaluationContractError("evidence fields must contain JSON values")


def _thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class CapabilityEvaluationPolicy:
    """Deep-immutable trusted composition policy for M7.9."""

    schema_version: int = 1
    algorithm_version: str = "m7.9-1"
    evidence_schema_version: int = 1
    max_history_records_per_source: int = 256
    max_evaluation_payload_bytes: int = 256 * 1024
    included_metric_groups: tuple[str, ...] = (
        "outcome",
        "planning",
        "verification",
        "recovery",
        "execution",
        "safety",
        "delegation",
        "efficiency",
        "memory",
    )
    security_failure_policy: SecurityFailurePolicy = SecurityFailurePolicy.HARD_FAIL
    incomplete_evidence_policy: IncompleteEvidencePolicy = (
        IncompleteEvidencePolicy.EXPLICIT_DISPOSITION
    )
    policy_digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version < 1:
            raise EvaluationContractError("schema_version must be positive")
        if type(self.evidence_schema_version) is not int or self.evidence_schema_version < 1:
            raise EvaluationContractError("evidence_schema_version must be positive")
        if type(self.max_history_records_per_source) is not int or not 1 <= self.max_history_records_per_source <= 10_000:
            raise EvaluationContractError("max_history_records_per_source is outside bounds")
        if type(self.max_evaluation_payload_bytes) is not int or not 1024 <= self.max_evaluation_payload_bytes <= 4 * 1024 * 1024:
            raise EvaluationContractError("max_evaluation_payload_bytes is outside bounds")
        _text(self.algorithm_version, label="algorithm_version")
        groups = tuple(sorted(set(self.included_metric_groups)))
        if not groups or any(type(group) is not str or not group for group in groups):
            raise EvaluationContractError("included_metric_groups must contain names")
        object.__setattr__(self, "included_metric_groups", groups)
        object.__setattr__(self, "security_failure_policy", SecurityFailurePolicy(self.security_failure_policy))
        object.__setattr__(self, "incomplete_evidence_policy", IncompleteEvidencePolicy(self.incomplete_evidence_policy))
        object.__setattr__(self, "policy_digest", canonical_digest(self._payload()))

    @classmethod
    def production(cls) -> CapabilityEvaluationPolicy:
        """Build the fixed policy used by trusted production composition."""

        return cls()

    def _payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "algorithm_version": self.algorithm_version,
            "evidence_schema_version": self.evidence_schema_version,
            "max_history_records_per_source": self.max_history_records_per_source,
            "max_evaluation_payload_bytes": self.max_evaluation_payload_bytes,
            "included_metric_groups": list(self.included_metric_groups),
            "security_failure_policy": self.security_failure_policy.value,
            "incomplete_evidence_policy": self.incomplete_evidence_policy.value,
        }

    def to_payload(self) -> dict[str, object]:
        return {**self._payload(), "policy_digest": self.policy_digest}


@dataclass(frozen=True, slots=True)
class CapabilityEvaluationRequest:
    """Owner-bound immutable request; identity is not model-controlled."""

    principal_id: str
    project_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    requested_evaluation_kind: str
    policy_digest: str
    benchmark_scenario_id: str | None = None
    benchmark_manifest_digest: str | None = None

    def __post_init__(self) -> None:
        for label in ("principal_id", "project_id", "task_id", "goal_spec_id", "requested_evaluation_kind"):
            _text(getattr(self, label), label=label)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _digest(self.policy_digest, label="policy_digest")
        if self.benchmark_scenario_id is not None:
            _text(self.benchmark_scenario_id, label="benchmark_scenario_id")
        if self.benchmark_manifest_digest is not None:
            _digest(self.benchmark_manifest_digest, label="benchmark_manifest_digest")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Bounded source record containing only typed, non-secret observations."""

    source: str
    record_id: str
    digest: str
    sequence: int | None = None
    fields: Mapping[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _text(self.source, label="source")
        _text(self.record_id, label="record_id")
        _digest(self.digest, label="digest")
        if self.sequence is not None and (type(self.sequence) is not int or self.sequence < 1):
            raise EvaluationContractError("evidence sequence must be positive")
        object.__setattr__(self, "fields", _freeze(self.fields))

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source,
            "record_id": self.record_id,
            "digest": self.digest,
            "sequence": self.sequence,
            "fields": _thaw(self.fields),
        }


@dataclass(frozen=True, slots=True)
class SourceAvailability:
    """Availability and truncation proof for one evidence source."""

    source: str
    available: bool
    truncated: bool = False
    reason: str = ""

    def __post_init__(self) -> None:
        _text(self.source, label="source")
        if type(self.available) is not bool or type(self.truncated) is not bool:
            raise EvaluationContractError("source availability flags must be bool")
        _text(self.reason, label="reason", allow_empty=True)

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source,
            "available": self.available,
            "truncated": self.truncated,
            "reason": self.reason,
        }


@dataclass(frozen=True, slots=True)
class SourceHighWaterMark:
    """Exact source head identity captured by a snapshot."""

    source: str
    latest_sequence: int | None
    latest_record_id: str | None
    latest_record_digest: str | None
    state_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.source, label="source")
        if self.latest_sequence is not None and (type(self.latest_sequence) is not int or self.latest_sequence < 1):
            raise EvaluationContractError("latest_sequence must be positive")
        if self.latest_record_id is None:
            if self.latest_record_digest is not None:
                raise EvaluationContractError("record digest requires record id")
        else:
            _text(self.latest_record_id, label="latest_record_id")
            _digest(self.latest_record_digest, label="latest_record_digest")
        if self.state_digest is not None:
            _digest(self.state_digest, label="state_digest")

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source,
            "latest_sequence": self.latest_sequence,
            "latest_record_id": self.latest_record_id,
            "latest_record_digest": self.latest_record_digest,
            "state_digest": self.state_digest,
        }


@dataclass(frozen=True, slots=True)
class TaskEvidence:
    """Physical task projection captured at the same SQLite observation point."""

    task_id: str
    principal_id: str
    project_id: str
    status: str
    cognitive_state: str
    control_state_version: int
    workspace_id: str | None
    repository_id: str | None
    base_revision: str | None
    published_plan_revision_id: str | None
    task_digest: str

    def __post_init__(self) -> None:
        for label in ("task_id", "principal_id", "project_id", "status", "cognitive_state"):
            _text(getattr(self, label), label=label)
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise EvaluationContractError("control_state_version must be non-negative")
        for label in ("workspace_id", "repository_id", "base_revision", "published_plan_revision_id"):
            value = getattr(self, label)
            if value is not None:
                _text(value, label=label)
        _digest(self.task_digest, label="task_digest")

    def to_payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "status": self.status,
            "cognitive_state": self.cognitive_state,
            "control_state_version": self.control_state_version,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "published_plan_revision_id": self.published_plan_revision_id,
            "task_digest": self.task_digest,
        }


_RECORD_GROUPS = (
    "completion_decisions",
    "plan_revisions",
    "verification_assessments",
    "recovery_decisions",
    "routes",
    "step_states",
    "dispatch_fences",
    "subagent_assignments",
    "turns",
    "audit_events",
    "memory_observations",
)


@dataclass(frozen=True, slots=True)
class CapabilityEvidenceSnapshot:
    """Coherent, immutable evidence captured at one logical observation point."""

    principal_id: str
    project_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    task: TaskEvidence
    workspace_id: str | None
    repository_id: str | None
    base_revision: str | None
    published_plan_revision_id: str | None
    source_high_water_marks: tuple[SourceHighWaterMark, ...]
    source_availability: tuple[SourceAvailability, ...]
    captured_at: str
    policy_digest: str
    evidence_schema_version: int = 1
    completion_decisions: tuple[EvidenceRecord, ...] = ()
    plan_revisions: tuple[EvidenceRecord, ...] = ()
    verification_assessments: tuple[EvidenceRecord, ...] = ()
    recovery_decisions: tuple[EvidenceRecord, ...] = ()
    routes: tuple[EvidenceRecord, ...] = ()
    step_states: tuple[EvidenceRecord, ...] = ()
    dispatch_fences: tuple[EvidenceRecord, ...] = ()
    subagent_assignments: tuple[EvidenceRecord, ...] = ()
    turns: tuple[EvidenceRecord, ...] = ()
    audit_events: tuple[EvidenceRecord, ...] = ()
    memory_observations: tuple[EvidenceRecord, ...] = ()
    snapshot_digest: str = field(init=False)

    def __post_init__(self) -> None:
        for label in ("principal_id", "project_id", "task_id", "goal_spec_id", "captured_at"):
            _text(getattr(self, label), label=label)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _digest(self.policy_digest, label="policy_digest")
        if type(self.evidence_schema_version) is not int or self.evidence_schema_version < 1:
            raise EvaluationContractError("evidence_schema_version must be positive")
        if type(self.task) is not TaskEvidence:
            raise EvaluationContractError("task must be TaskEvidence")
        if (self.task.task_id, self.task.principal_id, self.task.project_id) != (
            self.task_id,
            self.principal_id,
            self.project_id,
        ):
            raise EvaluationContractError("task identity does not match snapshot")
        if (
            self.task.workspace_id != self.workspace_id
            or self.task.repository_id != self.repository_id
            or self.task.base_revision != self.base_revision
            or self.task.published_plan_revision_id != self.published_plan_revision_id
        ):
            raise EvaluationContractError("task binding does not match snapshot")
        marks = tuple(sorted(self.source_high_water_marks, key=lambda item: item.source))
        availability = tuple(sorted(self.source_availability, key=lambda item: item.source))
        if len({item.source for item in marks}) != len(marks):
            raise EvaluationContractError("source high-water marks must be unique")
        if len({item.source for item in availability}) != len(availability):
            raise EvaluationContractError("source availability must be unique")
        object.__setattr__(self, "source_high_water_marks", marks)
        object.__setattr__(self, "source_availability", availability)
        for group in _RECORD_GROUPS:
            records = tuple(getattr(self, group))
            if any(type(item) is not EvidenceRecord for item in records):
                raise EvaluationContractError(f"{group} contains invalid evidence")
            records = tuple(
                sorted(
                    records,
                    key=lambda item: (item.sequence if item.sequence is not None else 0, item.record_id),
                )
            )
            object.__setattr__(self, group, records)
        semantic_payload = self._payload(include_digest=False)
        # Capture time is metadata, not evidence semantics.  Excluding it
        # lets a caller distinguish a current evaluation from a stale one by
        # comparing source-bound snapshot digests.
        semantic_payload.pop("captured_at", None)
        object.__setattr__(self, "snapshot_digest", canonical_digest(semantic_payload))

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "evidence_schema_version": self.evidence_schema_version,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "task": self.task.to_payload(),
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "published_plan_revision_id": self.published_plan_revision_id,
            "source_high_water_marks": [item.to_payload() for item in self.source_high_water_marks],
            "source_availability": [item.to_payload() for item in self.source_availability],
            "captured_at": self.captured_at,
        }
        for group in _RECORD_GROUPS:
            payload[group] = [item.to_payload() for item in getattr(self, group)]
        if include_digest:
            payload["policy_digest"] = self.policy_digest
            payload["snapshot_digest"] = self.snapshot_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)

    def source_is_available(self, source: str) -> bool:
        for item in self.source_availability:
            if item.source == source:
                return item.available and not item.truncated
        return False


@dataclass(frozen=True, slots=True)
class OutcomeMetrics:
    terminal_status: str | None
    completion_proposals: int | None
    completion_rejections: int | None
    completion_acceptances: int | None
    false_completion_attempts: int | None
    completion_after_trusted_verification: int | None
    terminal_without_completion_gate: int | None


@dataclass(frozen=True, slots=True)
class PlanningMetrics:
    plan_revision_count: int | None
    ready_count: int | None
    blocked_count: int | None
    stale_count: int | None
    invalid_count: int | None
    published_revision_count: int | None
    replan_count: int | None
    plan_churn: int | None


@dataclass(frozen=True, slots=True)
class VerificationMetrics:
    assessment_count: int | None
    satisfied_count: int | None
    failed_count: int | None
    blocked_count: int | None
    stale_count: int | None
    invalid_count: int | None
    attempts_before_success: int | None
    current_disposition: str | None


@dataclass(frozen=True, slots=True)
class RecoveryMetrics:
    recovery_decision_count: int | None
    recover_current_plan_count: int | None
    replan_count: int | None
    block_count: int | None
    identical_failure_streak_max: int | None
    no_progress_escalations: int | None
    recovery_cycles: int | None


@dataclass(frozen=True, slots=True)
class ExecutionMetrics:
    route_total: int | None
    route_allow: int | None
    route_supporting_read: int | None
    route_blocked: int | None
    route_stale: int | None
    route_ambiguous: int | None
    route_invalid: int | None
    dispatch_count: int | None
    applied_effects: int | None
    not_applied_effects: int | None
    no_effect: int | None
    partial_effects: int | None
    unknown_effects: int | None
    executed_steps: int | None
    uncertain_steps: int | None


@dataclass(frozen=True, slots=True)
class SafetyMetrics:
    permission_denials: int | None
    approval_denials: int | None
    router_denials: int | None
    stale_authority_rejections: int | None
    workspace_boundary_rejections: int | None
    security_event_count: int | None
    unexpected_authority_success_count: int | None
    terminal_monotonicity_violation_count: int | None
    cross_owner_project_isolation_violation_count: int | None
    authority_replay_violation_count: int | None


@dataclass(frozen=True, slots=True)
class DelegationMetrics:
    assignment_count: int | None
    activated_assignments: int | None
    completed_assignments: int | None
    failed_assignments: int | None
    stale_assignments: int | None
    orphaned_assignments: int | None
    delegated_steps_executed: int | None
    delegated_steps_uncertain: int | None


@dataclass(frozen=True, slots=True)
class EfficiencyMetrics:
    turn_count: int | None
    tool_call_count: int | None
    wall_clock_duration_ms: int | None
    tool_duration_total_ms: int | None
    recovery_per_success: float | None


@dataclass(frozen=True, slots=True)
class MemoryMetrics:
    retrieval_count: int | None
    selected_items: int | None
    stale_items: int | None
    historical_items: int | None
    truncated_retrievals: int | None
    unavailable_retrievals: int | None


@dataclass(frozen=True, slots=True)
class CapabilityEvaluation:
    """Typed immutable evaluation vector derived from one snapshot."""

    evaluation_id: str
    evaluation_sequence: int
    principal_id: str
    project_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    snapshot_digest: str
    policy_digest: str
    evaluator_schema_version: int
    evaluator_algorithm_version: str
    disposition: EvaluationDisposition
    outcome_metrics: OutcomeMetrics
    planning_metrics: PlanningMetrics
    verification_metrics: VerificationMetrics
    recovery_metrics: RecoveryMetrics
    execution_metrics: ExecutionMetrics
    safety_metrics: SafetyMetrics
    delegation_metrics: DelegationMetrics
    efficiency_metrics: EfficiencyMetrics
    memory_metrics: MemoryMetrics | None
    security_integrity: SecurityIntegrity
    aggregate_score: float | None
    created_at: str
    source_availability: tuple[SourceAvailability, ...] = ()
    evaluation_digest: str = field(init=False)

    def __post_init__(self) -> None:
        for label in ("evaluation_id", "principal_id", "project_id", "task_id", "goal_spec_id", "evaluator_algorithm_version", "created_at"):
            _text(getattr(self, label), label=label)
        if type(self.evaluation_sequence) is not int or self.evaluation_sequence < 0:
            raise EvaluationContractError("evaluation_sequence must be non-negative")
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _digest(self.snapshot_digest, label="snapshot_digest")
        _digest(self.policy_digest, label="policy_digest")
        if type(self.evaluator_schema_version) is not int or self.evaluator_schema_version < 1:
            raise EvaluationContractError("evaluator_schema_version must be positive")
        object.__setattr__(self, "disposition", EvaluationDisposition(self.disposition))
        object.__setattr__(self, "security_integrity", SecurityIntegrity(self.security_integrity))
        availability = tuple(self.source_availability)
        if any(type(item) is not SourceAvailability for item in availability):
            raise EvaluationContractError("source_availability contains invalid evidence")
        if len({item.source for item in availability}) != len(availability):
            raise EvaluationContractError("source_availability sources must be unique")
        object.__setattr__(self, "source_availability", tuple(sorted(availability, key=lambda item: item.source)))
        if self.aggregate_score is not None and type(self.aggregate_score) not in (int, float):
            raise EvaluationContractError("aggregate_score must be numeric or None")
        object.__setattr__(self, "evaluation_digest", canonical_digest(self.semantic_payload()))

    def semantic_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.evaluator_schema_version,
            "evaluator_algorithm_version": self.evaluator_algorithm_version,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "snapshot_digest": self.snapshot_digest,
            "policy_digest": self.policy_digest,
            "disposition": self.disposition.value,
            "outcome_metrics": _metric_payload(self.outcome_metrics),
            "planning_metrics": _metric_payload(self.planning_metrics),
            "verification_metrics": _metric_payload(self.verification_metrics),
            "recovery_metrics": _metric_payload(self.recovery_metrics),
            "execution_metrics": _metric_payload(self.execution_metrics),
            "safety_metrics": _metric_payload(self.safety_metrics),
            "delegation_metrics": _metric_payload(self.delegation_metrics),
            "efficiency_metrics": _metric_payload(self.efficiency_metrics),
            "memory_metrics": _metric_payload(self.memory_metrics) if self.memory_metrics is not None else None,
            "security_integrity": self.security_integrity.value,
            "aggregate_score": self.aggregate_score,
            "source_availability": [item.to_payload() for item in self.source_availability],
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self.semantic_payload(),
            "evaluation_id": self.evaluation_id,
            "evaluation_sequence": self.evaluation_sequence,
            "created_at": self.created_at,
            "evaluation_digest": self.evaluation_digest,
        }

    def canonical_json(self) -> str:
        return canonical_json_bytes(self.to_payload()).decode("utf-8")

    def with_sequence(self, sequence: int, created_at: str) -> CapabilityEvaluation:
        return CapabilityEvaluation(
            # The pure evaluator emits a deterministic observation identity.
            # The durable envelope adds the DB sequence so repeated
            # evaluations of unchanged evidence remain appendable while
            # retaining the same semantic evaluation digest.
            evaluation_id=(
                f"{self.evaluation_id}-{sequence}"
                if sequence > 0
                else self.evaluation_id
            ),
            evaluation_sequence=sequence,
            principal_id=self.principal_id,
            project_id=self.project_id,
            task_id=self.task_id,
            goal_spec_id=self.goal_spec_id,
            goal_spec_digest=self.goal_spec_digest,
            snapshot_digest=self.snapshot_digest,
            policy_digest=self.policy_digest,
            evaluator_schema_version=self.evaluator_schema_version,
            evaluator_algorithm_version=self.evaluator_algorithm_version,
            disposition=self.disposition,
            outcome_metrics=self.outcome_metrics,
            planning_metrics=self.planning_metrics,
            verification_metrics=self.verification_metrics,
            recovery_metrics=self.recovery_metrics,
            execution_metrics=self.execution_metrics,
            safety_metrics=self.safety_metrics,
            delegation_metrics=self.delegation_metrics,
            efficiency_metrics=self.efficiency_metrics,
            memory_metrics=self.memory_metrics,
            security_integrity=self.security_integrity,
            aggregate_score=self.aggregate_score,
            created_at=created_at,
            source_availability=self.source_availability,
        )


def _metric_payload(value: object) -> dict[str, object]:
    if value is None:
        return {}
    metric = cast(Any, value)
    return {key: getattr(metric, key) for key in metric.__dataclass_fields__}


__all__ = [
    "CapabilityEvaluation",
    "CapabilityEvaluationPolicy",
    "CapabilityEvaluationRequest",
    "CapabilityEvidenceSnapshot",
    "DelegationMetrics",
    "EfficiencyMetrics",
    "EvaluationContractError",
    "EvaluationDisposition",
    "EvidenceRecord",
    "ExecutionMetrics",
    "IncompleteEvidencePolicy",
    "MemoryMetrics",
    "OutcomeMetrics",
    "PlanningMetrics",
    "RecoveryMetrics",
    "SafetyFailurePolicy",
    "SafetyMetrics",
    "SecurityFailurePolicy",
    "SecurityIntegrity",
    "SourceAvailability",
    "SourceHighWaterMark",
    "TaskEvidence",
    "VerificationMetrics",
]
