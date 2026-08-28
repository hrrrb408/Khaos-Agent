"""Pure M7.5 recovery contracts and deterministic recovery policy.

This module is intentionally free of database, filesystem, model, and tool
dependencies.  It turns already owner-bound control-plane observations into a
typed ``RecoveryDecision``.  Persistence and application of that decision are
owned by the recovery repository/gate modules added in later layers.

Recovery is deliberately narrower than execution authority: a decision can
request recovery or replanning, but it can never complete a task, approve an
operation, execute a tool, or grant a capability.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Final

from khaos.agent.control.completion import CompletionOutcome
from khaos.agent.control.completion_recovery import CompletionContinuationState
from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.verification_assessment import (
    VerificationAssessmentDisposition,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

RECOVERY_DECISION_SCHEMA_VERSION: Final = 1
RECOVERY_POLICY_SCHEMA_VERSION: Final = 1
MAX_RECOVERY_ID_LENGTH: Final = 512
MAX_RECOVERY_TEXT_LENGTH: Final = 1024
MAX_FAILURE_CASES: Final = 32
MAX_FAILURE_SIGNATURE_BYTES: Final = 8192
MAX_SUBJECT_IDS: Final = 32
MAX_RECOVERY_HISTORY_RECORDS: Final = 256

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})


class RecoveryContractError(ValueError):
    """Raised when a M7.5 typed contract is malformed."""


class RecoveryAction(str, Enum):
    """Closed set of control-plane recovery actions."""

    NO_ACTION = "no_action"
    RECOVER_CURRENT_PLAN = "recover_current_plan"
    REPLAN = "replan"
    BLOCK = "block"


class RecoveryReasonCode(str, Enum):
    """Closed deterministic reasons for a recovery decision."""

    NO_RECOVERY_REQUIRED = "no_recovery_required"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_STALE = "verification_stale"
    VERIFICATION_UNAVAILABLE = "verification_unavailable"
    COMPLETION_REPLAN_REQUIRED = "completion_replan_required"
    COMPLETION_EXTERNAL_BLOCKED = "completion_external_blocked"
    COMPLETION_FAILURE_REVIEW_REQUIRED = "completion_failure_review_required"
    IDENTICAL_FAILURE_SIGNATURE = "identical_failure_signature"
    RECOVERY_ATTEMPT_BUDGET_EXHAUSTED = "recovery_attempt_budget_exhausted"
    REPLAN_BUDGET_EXHAUSTED = "replan_budget_exhausted"
    PLANNING_BLOCKED = "planning_blocked"
    PLANNING_STALE = "planning_stale"
    PLANNING_INVALID = "planning_invalid"
    DURABLE_HISTORY_INTEGRITY_ERROR = "durable_history_integrity_error"
    TASK_TERMINAL = "task_terminal"


class RecoveryFailureSource(str, Enum):
    """Bounded source vocabulary for normalized failure signatures."""

    VERIFY_FIX = "verify_fix"
    TRUSTED_VERIFICATION = "trusted_verification"
    EXECUTION = "execution"
    COMPLETION = "completion"
    PLANNING = "planning"
    UNKNOWN = "unknown"


class PlanningRecoveryStatus(str, Enum):
    """Negative planning signals consumed by the recovery policy."""

    NONE = "none"
    BLOCKED = "blocked"
    STALE = "stale"
    INVALID = "invalid"


def _text(value: object, *, label: str, allow_empty: bool = False, limit: int = MAX_RECOVERY_ID_LENGTH) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise RecoveryContractError(f"{label} must be a string")
    if len(value) > limit:
        raise RecoveryContractError(f"{label} exceeds its bound")
    if "\x00" in value:
        raise RecoveryContractError(f"{label} contains a NUL byte")
    return value


def _optional_text(value: object, *, label: str, limit: int = MAX_RECOVERY_ID_LENGTH) -> str | None:
    if value is None:
        return None
    return _text(value, label=label, limit=limit)


def _digest(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise RecoveryContractError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _optional_digest(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label=label)


def _enum(value: object, enum_type: type[Enum], *, label: str) -> None:
    if type(value) is not enum_type:
        raise RecoveryContractError(f"{label} must be a {enum_type.__name__}")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Reject duplicate JSON keys instead of allowing last-write-wins."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise RecoveryContractError("canonical recovery JSON has duplicate keys")
        result[key] = value
    return result


def _tuple_text(
    value: object,
    *,
    label: str,
    limit: int = MAX_RECOVERY_ID_LENGTH,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise RecoveryContractError(f"{label} must be a tuple")
    result = tuple(_text(item, label=label, limit=limit) for item in value)
    if len(result) != len(set(result)):
        raise RecoveryContractError(f"{label} must not contain duplicates")
    if max_items is not None and len(result) > max_items:
        raise RecoveryContractError(f"{label} exceeds its bound")
    return tuple(sorted(result))


@dataclass(frozen=True, slots=True)
class NormalizedFailureCase:
    """Bounded identity of one failure without retaining its raw message."""

    subject_id: str
    check_id: str | None = None
    file_identity: str | None = None
    line: int | None = None
    error_digest: str | None = None
    command_digest: str | None = None
    result_status: str | None = None

    def __post_init__(self) -> None:
        _text(self.subject_id, label="subject_id")
        _optional_text(self.check_id, label="check_id")
        _optional_text(self.file_identity, label="file_identity")
        if self.line is not None and (type(self.line) is not int or self.line < 1):
            raise RecoveryContractError("line must be a positive integer or None")
        _optional_digest(self.error_digest, label="error_digest")
        _optional_digest(self.command_digest, label="command_digest")
        _optional_text(self.result_status, label="result_status")

    def to_payload(self) -> dict[str, object | None]:
        """Return the bounded canonical representation of this failure."""
        return {
            "subject_id": self.subject_id,
            "check_id": self.check_id,
            "file_identity": self.file_identity,
            "line": self.line,
            "error_digest": self.error_digest,
            "command_digest": self.command_digest,
            "result_status": self.result_status,
        }


def _failure_case_key(value: NormalizedFailureCase) -> tuple[object, ...]:
    return (
        value.subject_id,
        value.check_id or "",
        value.file_identity or "",
        value.line or 0,
        value.error_digest or "",
        value.command_digest or "",
        value.result_status or "",
    )


@dataclass(frozen=True, slots=True)
class NormalizedFailureSignature:
    """Canonical, bounded failure identity used by no-progress detection.

    Full error text, stack traces, stdout, and stderr are intentionally absent.
    Overflow is represented by a count and digest, so truncation cannot turn
    two different failure sets into the same apparently complete signature.
    """

    source: RecoveryFailureSource
    failed_count: int
    error_count: int
    failed_cases: tuple[NormalizedFailureCase, ...] = ()
    verification_requirement_ids: tuple[str, ...] = ()
    verification_check_ids: tuple[str, ...] = ()
    command_digests: tuple[str, ...] = ()
    result_statuses: tuple[str, ...] = ()
    published_plan_revision_id: str | None = None
    published_plan_revision_digest: str | None = None
    overflow_count: int = 0
    overflow_digest: str | None = None
    signature_digest: str = ""

    def __post_init__(self) -> None:
        _enum(self.source, RecoveryFailureSource, label="source")
        for value, label in (
            (self.failed_count, "failed_count"),
            (self.error_count, "error_count"),
            (self.overflow_count, "overflow_count"),
        ):
            if type(value) is not int or value < 0:
                raise RecoveryContractError(f"{label} must be non-negative")
        if type(self.failed_cases) is not tuple:
            raise RecoveryContractError("failed_cases must be a tuple")
        if len(self.failed_cases) > MAX_FAILURE_CASES:
            raise RecoveryContractError("failed_cases exceeds its fixed bound")
        if any(type(item) is not NormalizedFailureCase for item in self.failed_cases):
            raise RecoveryContractError("failed_cases contains an invalid item")
        object.__setattr__(
            self,
            "failed_cases",
            tuple(sorted(self.failed_cases, key=_failure_case_key)),
        )
        for value, label in (
            (self.verification_requirement_ids, "verification_requirement_ids"),
            (self.verification_check_ids, "verification_check_ids"),
            (self.command_digests, "command_digests"),
            (self.result_statuses, "result_statuses"),
        ):
            normalized = _tuple_text(value, label=label, max_items=MAX_FAILURE_CASES)
            if label == "command_digests":
                for item in normalized:
                    _digest(item, label=label)
            object.__setattr__(self, label, normalized)
        _optional_text(self.published_plan_revision_id, label="published_plan_revision_id")
        if self.published_plan_revision_id is None and self.published_plan_revision_digest is not None:
            raise RecoveryContractError(
                "published_plan_revision_digest requires a plan revision identity"
            )
        _optional_digest(
            self.published_plan_revision_digest,
            label="published_plan_revision_digest",
        )
        if self.overflow_count == 0 and self.overflow_digest is not None:
            raise RecoveryContractError("overflow_digest requires overflow_count")
        _optional_digest(self.overflow_digest, label="overflow_digest")
        if type(self.signature_digest) is not str:
            raise RecoveryContractError("signature_digest must be a string")
        expected = canonical_digest(self.semantic_payload)
        if self.signature_digest:
            _digest(self.signature_digest, label="signature_digest")
            if self.signature_digest != expected:
                raise RecoveryContractError("signature_digest does not match semantics")
        else:
            object.__setattr__(self, "signature_digest", expected)
        if len(canonical_json_bytes(self.semantic_payload)) > MAX_FAILURE_SIGNATURE_BYTES:
            raise RecoveryContractError("failure signature exceeds its byte bound")

    @classmethod
    def from_cases(
        cls,
        *,
        source: RecoveryFailureSource,
        failed_count: int,
        error_count: int,
        failed_cases: tuple[NormalizedFailureCase, ...] = (),
        verification_requirement_ids: tuple[str, ...] = (),
        verification_check_ids: tuple[str, ...] = (),
        command_digests: tuple[str, ...] = (),
        result_statuses: tuple[str, ...] = (),
        published_plan_revision_id: str | None = None,
        published_plan_revision_digest: str | None = None,
    ) -> NormalizedFailureSignature:
        """Normalize and bound a failure-case collection deterministically."""
        ordered = tuple(sorted(failed_cases, key=_failure_case_key))
        overflow = ordered[MAX_FAILURE_CASES:]
        retained = ordered[:MAX_FAILURE_CASES]
        overflow_digest = (
            canonical_digest([item.to_payload() for item in overflow])
            if overflow
            else None
        )
        return cls(
            source=source,
            failed_count=failed_count,
            error_count=error_count,
            failed_cases=retained,
            verification_requirement_ids=verification_requirement_ids,
            verification_check_ids=verification_check_ids,
            command_digests=command_digests,
            result_statuses=result_statuses,
            published_plan_revision_id=published_plan_revision_id,
            published_plan_revision_digest=published_plan_revision_digest,
            overflow_count=len(overflow),
            overflow_digest=overflow_digest,
        )

    @property
    def semantic_payload(self) -> dict[str, object]:
        """Return the exact payload covered by ``signature_digest``."""
        return {
            "source": self.source.value,
            "failed_count": self.failed_count,
            "error_count": self.error_count,
            "failed_cases": [item.to_payload() for item in self.failed_cases],
            "verification_requirement_ids": list(self.verification_requirement_ids),
            "verification_check_ids": list(self.verification_check_ids),
            "command_digests": list(self.command_digests),
            "result_statuses": list(self.result_statuses),
            "published_plan_revision_id": self.published_plan_revision_id,
            "published_plan_revision_digest": self.published_plan_revision_digest,
            "overflow_count": self.overflow_count,
            "overflow_digest": self.overflow_digest,
        }

    @property
    def failure_signature_digest(self) -> str:
        """Compatibility name used by the recovery input contract."""
        return self.signature_digest

    def canonical_json(self) -> str:
        """Serialize the bounded signature for diagnostics/tests only."""
        return canonical_json_bytes(self.semantic_payload).decode("utf-8")


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    """Trusted, immutable, bounded recovery budget policy."""

    schema_version: int = RECOVERY_POLICY_SCHEMA_VERSION
    max_recovery_attempts_per_plan: int = 3
    identical_failure_threshold: int = 2
    max_replans_per_task: int = 3
    max_recovery_cycles_per_turn: int = 4
    max_history_records: int = MAX_RECOVERY_HISTORY_RECORDS
    policy_digest: str = ""

    def __post_init__(self) -> None:
        if self.schema_version != RECOVERY_POLICY_SCHEMA_VERSION:
            raise RecoveryContractError("unsupported recovery policy schema")
        values = (
            (self.max_recovery_attempts_per_plan, "max_recovery_attempts_per_plan", 8),
            (self.identical_failure_threshold, "identical_failure_threshold", 8),
            (self.max_replans_per_task, "max_replans_per_task", 8),
            (self.max_recovery_cycles_per_turn, "max_recovery_cycles_per_turn", 8),
            (self.max_history_records, "max_history_records", MAX_RECOVERY_HISTORY_RECORDS),
        )
        for value, label, upper_bound in values:
            if type(value) is not int or value < 0 or value > upper_bound:
                raise RecoveryContractError(f"{label} is outside its trusted bound")
        expected = canonical_digest(self.semantic_payload)
        if self.policy_digest:
            _digest(self.policy_digest, label="policy_digest")
            if self.policy_digest != expected:
                raise RecoveryContractError("policy_digest does not match semantics")
        else:
            object.__setattr__(self, "policy_digest", expected)

    @classmethod
    def production_default(cls) -> RecoveryPolicy:
        """Return the fixed production default used by runtime composition."""
        return cls()

    @property
    def semantic_payload(self) -> dict[str, int]:
        """Return the policy fields covered by ``policy_digest``."""
        return {
            "schema_version": self.schema_version,
            "max_recovery_attempts_per_plan": self.max_recovery_attempts_per_plan,
            "identical_failure_threshold": self.identical_failure_threshold,
            "max_replans_per_task": self.max_replans_per_task,
            "max_recovery_cycles_per_turn": self.max_recovery_cycles_per_turn,
            "max_history_records": self.max_history_records,
        }


@dataclass(frozen=True, slots=True)
class RecoveryInput:
    """Immutable owner-bound snapshot consumed by ``RecoveryEvaluator``."""

    principal_id: str
    project_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    workspace_id: str | None
    repository_id: str | None
    base_revision: str | None
    published_plan_revision_id: str | None
    published_plan_revision_digest: str | None
    latest_plan_revision_id: str | None = None
    latest_plan_revision_sequence: int | None = None
    verification_assessment_id: str | None = None
    verification_assessment_digest: str | None = None
    verification_disposition: VerificationAssessmentDisposition | None = None
    verification_repository_generation: str | None = None
    verification_change_identity: str | None = None
    completion_decision_id: str | None = None
    completion_decision_digest: str | None = None
    completion_decision_sequence: int | None = None
    completion_outcome: CompletionOutcome | None = None
    completion_continuation_state: CompletionContinuationState | None = None
    failure_signature: NormalizedFailureSignature | None = None
    failure_signature_digest: str | None = None
    no_progress_detected: bool = False
    identical_failure_streak: int = 0
    recovery_attempt_count: int = 0
    replan_count: int = 0
    total_recovery_count: int = 0
    planning_status: PlanningRecoveryStatus = PlanningRecoveryStatus.NONE
    policy: RecoveryPolicy = field(default_factory=RecoveryPolicy)

    def __post_init__(self) -> None:
        for value, label in (
            (self.principal_id, "principal_id"),
            (self.task_id, "task_id"),
            (self.goal_spec_id, "goal_spec_id"),
            (self.task_status, "task_status"),
        ):
            _text(value, label=label)
        if type(self.project_id) is not str:
            raise RecoveryContractError("project_id must be a string")
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _enum(self.cognitive_state, AgentCognitiveState, label="cognitive_state")
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise RecoveryContractError("control_state_version must be non-negative")
        for value, label in (
            (self.workspace_id, "workspace_id"),
            (self.repository_id, "repository_id"),
            (self.base_revision, "base_revision"),
            (self.published_plan_revision_id, "published_plan_revision_id"),
            (self.latest_plan_revision_id, "latest_plan_revision_id"),
            (self.verification_assessment_id, "verification_assessment_id"),
            (self.verification_repository_generation, "verification_repository_generation"),
            (self.verification_change_identity, "verification_change_identity"),
            (self.completion_decision_id, "completion_decision_id"),
        ):
            _optional_text(value, label=label)
        if self.published_plan_revision_id is None and self.published_plan_revision_digest is not None:
            raise RecoveryContractError("published plan digest requires a plan identity")
        _optional_digest(
            self.published_plan_revision_digest,
            label="published_plan_revision_digest",
        )
        _optional_digest(self.verification_assessment_digest, label="verification_assessment_digest")
        _optional_digest(self.completion_decision_digest, label="completion_decision_digest")
        if self.verification_disposition is not None:
            _enum(
                self.verification_disposition,
                VerificationAssessmentDisposition,
                label="verification_disposition",
            )
        if self.completion_outcome is not None:
            _enum(self.completion_outcome, CompletionOutcome, label="completion_outcome")
        if self.completion_continuation_state is not None:
            _enum(
                self.completion_continuation_state,
                CompletionContinuationState,
                label="completion_continuation_state",
            )
        verification_fields = (
            self.verification_assessment_digest,
            self.verification_disposition,
            self.verification_repository_generation,
            self.verification_change_identity,
        )
        if self.verification_assessment_id is None:
            if any(value is not None for value in verification_fields):
                raise RecoveryContractError(
                    "verification facts require a verification assessment identity"
                )
        elif self.verification_assessment_digest is None or self.verification_disposition is None:
            raise RecoveryContractError(
                "verification assessment identity requires digest and disposition"
            )
        completion_fields = (
            self.completion_decision_digest,
            self.completion_decision_sequence,
            self.completion_outcome,
            self.completion_continuation_state,
        )
        if self.completion_decision_id is None:
            if any(value is not None for value in completion_fields):
                raise RecoveryContractError(
                    "completion facts require a completion decision identity"
                )
        elif any(value is None for value in completion_fields):
            raise RecoveryContractError(
                "completion decision identity requires all decision facts"
            )
        if self.failure_signature is not None and type(self.failure_signature) is not NormalizedFailureSignature:
            raise RecoveryContractError("failure_signature has an invalid type")
        derived_failure_digest = (
            self.failure_signature.failure_signature_digest
            if self.failure_signature is not None
            else None
        )
        if self.failure_signature_digest is not None:
            _digest(self.failure_signature_digest, label="failure_signature_digest")
        if derived_failure_digest is not None and self.failure_signature_digest not in (None, derived_failure_digest):
            raise RecoveryContractError("failure signature digest is inconsistent")
        if derived_failure_digest is not None:
            object.__setattr__(self, "failure_signature_digest", derived_failure_digest)
        if type(self.no_progress_detected) is not bool:
            raise RecoveryContractError("no_progress_detected must be a boolean")
        if self.no_progress_detected and self.failure_signature_digest is None:
            raise RecoveryContractError(
                "no_progress_detected requires a normalized failure signature digest"
            )
        for value, label in (
            (self.latest_plan_revision_sequence, "latest_plan_revision_sequence"),
            (self.completion_decision_sequence, "completion_decision_sequence"),
            (self.identical_failure_streak, "identical_failure_streak"),
            (self.recovery_attempt_count, "recovery_attempt_count"),
            (self.replan_count, "replan_count"),
            (self.total_recovery_count, "total_recovery_count"),
        ):
            if value is not None and (type(value) is not int or value < 0):
                raise RecoveryContractError(f"{label} must be non-negative")
        if self.latest_plan_revision_id is None:
            if self.latest_plan_revision_sequence is not None:
                raise RecoveryContractError(
                    "latest plan sequence requires a latest plan identity"
                )
        elif self.latest_plan_revision_sequence is None:
            raise RecoveryContractError(
                "latest plan identity requires a latest plan sequence"
            )
        if self.completion_decision_sequence is not None and self.completion_decision_id is None:
            raise RecoveryContractError("completion sequence requires a completion decision identity")
        _enum(self.planning_status, PlanningRecoveryStatus, label="planning_status")
        if type(self.policy) is not RecoveryPolicy:
            raise RecoveryContractError("policy must be a RecoveryPolicy")
        if len(canonical_json_bytes(self.semantic_payload)) > MAX_FAILURE_SIGNATURE_BYTES:
            raise RecoveryContractError("recovery input exceeds its bounded size")

    @property
    def semantic_payload(self) -> dict[str, object | None]:
        """Return the input snapshot without retaining raw failure content."""
        return {
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "cognitive_state": self.cognitive_state.value,
            "control_state_version": self.control_state_version,
            "task_status": self.task_status,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "published_plan_revision_id": self.published_plan_revision_id,
            "published_plan_revision_digest": self.published_plan_revision_digest,
            "latest_plan_revision_id": self.latest_plan_revision_id,
            "latest_plan_revision_sequence": self.latest_plan_revision_sequence,
            "verification_assessment_id": self.verification_assessment_id,
            "verification_assessment_digest": self.verification_assessment_digest,
            "verification_disposition": (
                self.verification_disposition.value
                if self.verification_disposition is not None
                else None
            ),
            "verification_repository_generation": self.verification_repository_generation,
            "verification_change_identity": self.verification_change_identity,
            "completion_decision_id": self.completion_decision_id,
            "completion_decision_digest": self.completion_decision_digest,
            "completion_decision_sequence": self.completion_decision_sequence,
            "completion_outcome": (
                self.completion_outcome.value if self.completion_outcome is not None else None
            ),
            "completion_continuation_state": (
                self.completion_continuation_state.value
                if self.completion_continuation_state is not None
                else None
            ),
            "failure_signature_digest": self.failure_signature_digest,
            "no_progress_detected": self.no_progress_detected,
            "identical_failure_streak": self.identical_failure_streak,
            "recovery_attempt_count": self.recovery_attempt_count,
            "replan_count": self.replan_count,
            "total_recovery_count": self.total_recovery_count,
            "planning_status": self.planning_status.value,
            "policy_schema_version": self.policy.schema_version,
            "policy_max_recovery_attempts_per_plan": self.policy.max_recovery_attempts_per_plan,
            "policy_identical_failure_threshold": self.policy.identical_failure_threshold,
            "policy_max_replans_per_task": self.policy.max_replans_per_task,
            "policy_max_recovery_cycles_per_turn": self.policy.max_recovery_cycles_per_turn,
            "policy_max_history_records": self.policy.max_history_records,
            "policy_digest": self.policy.policy_digest,
        }

    @property
    def input_digest(self) -> str:
        """Return the deterministic digest of this bound input snapshot."""
        return canonical_digest(self.semantic_payload)


@dataclass(frozen=True, slots=True)
class RecoveryEvaluation:
    """Pure evaluator output before a storage identity is assigned."""

    action: RecoveryAction
    reason_code: RecoveryReasonCode
    subject_ids: tuple[str, ...] = ()
    reason_summary: str = ""

    def __post_init__(self) -> None:
        _enum(self.action, RecoveryAction, label="action")
        _enum(self.reason_code, RecoveryReasonCode, label="reason_code")
        object.__setattr__(
            self,
            "subject_ids",
            _tuple_text(self.subject_ids, label="subject_ids", max_items=MAX_SUBJECT_IDS),
        )
        _text(
            self.reason_summary,
            label="reason_summary",
            allow_empty=True,
            limit=MAX_RECOVERY_TEXT_LENGTH,
        )


@dataclass(frozen=True, slots=True)
class RecoveryDecision:
    """Immutable durable judgment produced from one recovery input snapshot."""

    schema_version: int
    recovery_decision_id: str
    input: RecoveryInput
    action: RecoveryAction
    reason_code: RecoveryReasonCode
    subject_ids: tuple[str, ...]
    reason_summary: str
    decision_digest: str

    def __post_init__(self) -> None:
        if self.schema_version != RECOVERY_DECISION_SCHEMA_VERSION:
            raise RecoveryContractError("unsupported recovery decision schema")
        _text(self.recovery_decision_id, label="recovery_decision_id")
        if type(self.input) is not RecoveryInput:
            raise RecoveryContractError("input must be a RecoveryInput")
        _enum(self.action, RecoveryAction, label="action")
        _enum(self.reason_code, RecoveryReasonCode, label="reason_code")
        object.__setattr__(
            self,
            "subject_ids",
            _tuple_text(self.subject_ids, label="subject_ids", max_items=MAX_SUBJECT_IDS),
        )
        _text(
            self.reason_summary,
            label="reason_summary",
            allow_empty=True,
            limit=MAX_RECOVERY_TEXT_LENGTH,
        )
        expected = canonical_digest(self.semantic_payload)
        _digest(self.decision_digest, label="decision_digest")
        if self.decision_digest != expected:
            raise RecoveryContractError("decision_digest does not match semantics")

    @classmethod
    def from_input(
        cls,
        *,
        recovery_decision_id: str,
        input: RecoveryInput,
        evaluation: RecoveryEvaluation,
        schema_version: int = RECOVERY_DECISION_SCHEMA_VERSION,
    ) -> RecoveryDecision:
        """Create a decision and calculate its semantic digest."""
        payload = {
            "schema_version": schema_version,
            **input.semantic_payload,
            "action": evaluation.action.value,
            "reason_code": evaluation.reason_code.value,
            "subject_ids": list(evaluation.subject_ids),
            "reason_summary": evaluation.reason_summary,
        }
        return cls(
            schema_version=schema_version,
            recovery_decision_id=recovery_decision_id,
            input=input,
            action=evaluation.action,
            reason_code=evaluation.reason_code,
            subject_ids=evaluation.subject_ids,
            reason_summary=evaluation.reason_summary,
            decision_digest=canonical_digest(payload),
        )

    @property
    def task_id(self) -> str:
        """Return the owner-bound task identity."""
        return self.input.task_id

    @property
    def principal_id(self) -> str:
        """Return the owner-bound principal identity."""
        return self.input.principal_id

    @property
    def project_id(self) -> str:
        """Return the owner-bound project identity."""
        return self.input.project_id

    @property
    def goal_spec_id(self) -> str:
        """Return the bound GoalSpec identity."""
        return self.input.goal_spec_id

    @property
    def goal_spec_digest(self) -> str:
        """Return the bound GoalSpec semantic digest."""
        return self.input.goal_spec_digest

    @property
    def source_cognitive_state(self) -> AgentCognitiveState:
        """Return the source cognitive snapshot."""
        return self.input.cognitive_state

    @property
    def source_control_state_version(self) -> int:
        """Return the source cognitive CAS version."""
        return self.input.control_state_version

    @property
    def source_task_status(self) -> str:
        """Return the source TaskStatus snapshot."""
        return self.input.task_status

    @property
    def published_plan_revision_id(self) -> str | None:
        """Return the source published implementation plan identity."""
        return self.input.published_plan_revision_id

    @property
    def published_plan_revision_digest(self) -> str | None:
        """Return the source published implementation plan digest."""
        return self.input.published_plan_revision_digest

    @property
    def failure_signature_digest(self) -> str | None:
        """Return only the normalized failure digest, never raw failure text."""
        return self.input.failure_signature_digest

    @property
    def input_digest(self) -> str:
        """Return the digest binding this decision to its input snapshot."""
        return self.input.input_digest

    @property
    def semantic_payload(self) -> dict[str, object]:
        """Return the exact bounded payload covered by ``decision_digest``."""
        return {
            "schema_version": self.schema_version,
            **self.input.semantic_payload,
            "action": self.action.value,
            "reason_code": self.reason_code.value,
            "subject_ids": list(self.subject_ids),
            "reason_summary": self.reason_summary,
        }

    def to_canonical_mapping(self) -> dict[str, object]:
        """Return the complete bounded storage representation."""
        return {
            **self.semantic_payload,
            "recovery_decision_id": self.recovery_decision_id,
            "decision_digest": self.decision_digest,
        }

    def canonical_json(self) -> str:
        """Serialize the decision through the shared canonical encoder."""
        return canonical_json_bytes(self.to_canonical_mapping()).decode("utf-8")

    @classmethod
    def from_canonical_json(
        cls,
        payload: str,
        *,
        expected_digest: str | None = None,
        expected_decision_id: str | None = None,
    ) -> RecoveryDecision:
        """Decode and integrity-check one immutable durable decision."""
        if type(payload) is not str:
            raise RecoveryContractError("canonical recovery decision must be text")
        try:
            decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
        except (TypeError, ValueError, UnicodeDecodeError) as exc:
            raise RecoveryContractError("canonical recovery decision JSON is malformed") from exc
        if type(decoded) is not dict:
            raise RecoveryContractError("canonical recovery decision must be an object")
        input_keys = {
            "principal_id",
            "project_id",
            "task_id",
            "goal_spec_id",
            "goal_spec_digest",
            "cognitive_state",
            "control_state_version",
            "task_status",
            "workspace_id",
            "repository_id",
            "base_revision",
            "published_plan_revision_id",
            "published_plan_revision_digest",
            "latest_plan_revision_id",
            "latest_plan_revision_sequence",
            "verification_assessment_id",
            "verification_assessment_digest",
            "verification_disposition",
            "verification_repository_generation",
            "verification_change_identity",
            "completion_decision_id",
            "completion_decision_digest",
            "completion_decision_sequence",
            "completion_outcome",
            "completion_continuation_state",
            "failure_signature_digest",
            "no_progress_detected",
            "identical_failure_streak",
            "recovery_attempt_count",
            "replan_count",
            "total_recovery_count",
            "planning_status",
            "policy_schema_version",
            "policy_max_recovery_attempts_per_plan",
            "policy_identical_failure_threshold",
            "policy_max_replans_per_task",
            "policy_max_recovery_cycles_per_turn",
            "policy_max_history_records",
            "policy_digest",
        }
        required = {
            "schema_version",
            "recovery_decision_id",
            "decision_digest",
            "action",
            "reason_code",
            "subject_ids",
            "reason_summary",
        } | input_keys
        if set(decoded) != required:
            raise RecoveryContractError("canonical recovery decision has an invalid schema")
        decision_id = decoded["recovery_decision_id"]
        if expected_decision_id is not None and decision_id != expected_decision_id:
            raise RecoveryContractError("recovery decision identity mismatch")
        stored_digest = decoded["decision_digest"]
        if expected_digest is not None and stored_digest != expected_digest:
            raise RecoveryContractError("recovery decision digest mismatch")
        raw_subject_ids = decoded["subject_ids"]
        if type(raw_subject_ids) is not list:
            raise RecoveryContractError("subject_ids must be a JSON array")
        if any(type(subject_id) is not str for subject_id in raw_subject_ids):
            raise RecoveryContractError("subject_ids must contain only strings")

        def optional_enum(value: object, enum_type: type[Enum], label: str) -> Any:
            if value is None:
                return None
            try:
                return enum_type(value)
            except (TypeError, ValueError) as exc:
                raise RecoveryContractError(f"{label} is invalid") from exc

        try:
            policy = RecoveryPolicy(
                schema_version=decoded["policy_schema_version"],
                max_recovery_attempts_per_plan=decoded[
                    "policy_max_recovery_attempts_per_plan"
                ],
                identical_failure_threshold=decoded["policy_identical_failure_threshold"],
                max_replans_per_task=decoded["policy_max_replans_per_task"],
                max_recovery_cycles_per_turn=decoded[
                    "policy_max_recovery_cycles_per_turn"
                ],
                max_history_records=decoded["policy_max_history_records"],
                policy_digest=decoded["policy_digest"],
            )
            input_value = RecoveryInput(
                principal_id=decoded["principal_id"],
                project_id=decoded["project_id"],
                task_id=decoded["task_id"],
                goal_spec_id=decoded["goal_spec_id"],
                goal_spec_digest=decoded["goal_spec_digest"],
                cognitive_state=AgentCognitiveState(decoded["cognitive_state"]),
                control_state_version=decoded["control_state_version"],
                task_status=decoded["task_status"],
                workspace_id=decoded["workspace_id"],
                repository_id=decoded["repository_id"],
                base_revision=decoded["base_revision"],
                published_plan_revision_id=decoded["published_plan_revision_id"],
                published_plan_revision_digest=decoded[
                    "published_plan_revision_digest"
                ],
                latest_plan_revision_id=decoded["latest_plan_revision_id"],
                latest_plan_revision_sequence=decoded["latest_plan_revision_sequence"],
                verification_assessment_id=decoded["verification_assessment_id"],
                verification_assessment_digest=decoded["verification_assessment_digest"],
                verification_disposition=optional_enum(
                    decoded["verification_disposition"],
                    VerificationAssessmentDisposition,
                    "verification_disposition",
                ),
                verification_repository_generation=decoded[
                    "verification_repository_generation"
                ],
                verification_change_identity=decoded["verification_change_identity"],
                completion_decision_id=decoded["completion_decision_id"],
                completion_decision_digest=decoded["completion_decision_digest"],
                completion_decision_sequence=decoded["completion_decision_sequence"],
                completion_outcome=optional_enum(
                    decoded["completion_outcome"], CompletionOutcome, "completion_outcome"
                ),
                completion_continuation_state=optional_enum(
                    decoded["completion_continuation_state"],
                    CompletionContinuationState,
                    "completion_continuation_state",
                ),
                failure_signature_digest=decoded["failure_signature_digest"],
                no_progress_detected=decoded["no_progress_detected"],
                identical_failure_streak=decoded["identical_failure_streak"],
                recovery_attempt_count=decoded["recovery_attempt_count"],
                replan_count=decoded["replan_count"],
                total_recovery_count=decoded["total_recovery_count"],
                planning_status=PlanningRecoveryStatus(decoded["planning_status"]),
                policy=policy,
            )
            evaluation = RecoveryEvaluation(
                action=RecoveryAction(decoded["action"]),
                reason_code=RecoveryReasonCode(decoded["reason_code"]),
                subject_ids=tuple(decoded["subject_ids"]),
                reason_summary=decoded["reason_summary"],
            )
        except (KeyError, TypeError, ValueError, RecoveryContractError) as exc:
            if isinstance(exc, RecoveryContractError):
                raise
            raise RecoveryContractError(
                "canonical recovery decision contains malformed values"
            ) from exc
        result = cls.from_input(
            recovery_decision_id=decision_id,
            input=input_value,
            evaluation=evaluation,
            schema_version=decoded["schema_version"],
        )
        if result.decision_digest != stored_digest:
            raise RecoveryContractError("recovery decision digest does not match payload")
        return result


class RecoveryEvaluator:
    """Pure deterministic policy for negative recovery signals."""

    @staticmethod
    def evaluate_action(input: RecoveryInput) -> RecoveryEvaluation:
        """Return the action dictated by the trusted recovery policy."""
        if type(input) is not RecoveryInput:
            raise TypeError("input must be a RecoveryInput")

        if input.task_status in _TERMINAL_TASK_STATUSES:
            return RecoveryEvaluation(
                RecoveryAction.NO_ACTION,
                RecoveryReasonCode.TASK_TERMINAL,
                reason_summary="terminal task has no recovery action",
            )

        if input.planning_status is PlanningRecoveryStatus.INVALID:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.PLANNING_INVALID,
                reason_summary="planning input is invalid",
            )
        if input.planning_status is PlanningRecoveryStatus.STALE:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.PLANNING_STALE,
                reason_summary="planning input is stale",
            )
        if input.planning_status is PlanningRecoveryStatus.BLOCKED:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.PLANNING_BLOCKED,
                reason_summary="planning is blocked",
            )

        continuation = input.completion_continuation_state
        if continuation is CompletionContinuationState.INTEGRITY_ERROR:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.DURABLE_HISTORY_INTEGRITY_ERROR,
                reason_summary="durable completion history failed integrity checks",
            )
        if continuation is CompletionContinuationState.REPLAN_REQUIRED:
            return RecoveryEvaluation(
                RecoveryAction.REPLAN,
                RecoveryReasonCode.COMPLETION_REPLAN_REQUIRED,
                reason_summary="completion history requires a fresh plan",
            )
        if continuation is CompletionContinuationState.EXTERNAL_BLOCKED:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.COMPLETION_EXTERNAL_BLOCKED,
                reason_summary="completion is blocked by an external condition",
            )
        if continuation is CompletionContinuationState.FAILURE_REVIEW_REQUIRED:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.COMPLETION_FAILURE_REVIEW_REQUIRED,
                reason_summary="completion failure requires review",
            )

        # A durable verification failure/staleness boundary has precedence
        # over a low-level no-progress hint.  No-progress can request a
        # replan, but it must never bypass a stronger trusted-verification
        # blocker or make unavailable evidence look recoverable.
        if input.verification_disposition is VerificationAssessmentDisposition.FAILED:
            return RecoveryEvaluator._failure_action(input)
        if input.verification_disposition is VerificationAssessmentDisposition.STALE:
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.VERIFICATION_STALE,
                reason_summary="trusted verification is stale",
            )
        if input.verification_disposition in (
            VerificationAssessmentDisposition.UNAVAILABLE,
            VerificationAssessmentDisposition.INCONCLUSIVE,
        ):
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.VERIFICATION_UNAVAILABLE,
                reason_summary="trusted verification is unavailable",
            )

        # No-progress is a typed negative signal from a low-level observation
        # boundary.  It can only narrow control behaviour: it never asserts
        # that a change succeeded and never grants a tool or lifecycle
        # capability.  Two identical failures therefore stop consuming blind
        # repair attempts and request a bounded replan instead.
        if input.no_progress_detected:
            if input.replan_count < input.policy.max_replans_per_task:
                return RecoveryEvaluation(
                    RecoveryAction.REPLAN,
                    RecoveryReasonCode.IDENTICAL_FAILURE_SIGNATURE,
                    reason_summary="identical failure observations indicate no progress",
                )
            return RecoveryEvaluation(
                RecoveryAction.BLOCK,
                RecoveryReasonCode.REPLAN_BUDGET_EXHAUSTED,
                reason_summary="replan budget is exhausted after no progress",
            )

        if (
            input.failure_signature_digest is not None
            and input.identical_failure_streak >= input.policy.identical_failure_threshold
        ):
            return RecoveryEvaluator._repeated_failure_action(input)

        return RecoveryEvaluation(
            RecoveryAction.NO_ACTION,
            RecoveryReasonCode.NO_RECOVERY_REQUIRED,
            reason_summary="no deterministic recovery signal is present",
        )

    @staticmethod
    def evaluate(
        input: RecoveryInput,
        *,
        recovery_decision_id: str,
    ) -> RecoveryDecision:
        """Create an immutable decision without performing I/O."""
        evaluation = RecoveryEvaluator.evaluate_action(input)
        return RecoveryDecision.from_input(
            recovery_decision_id=recovery_decision_id,
            input=input,
            evaluation=evaluation,
        )

    @staticmethod
    def _failure_action(input: RecoveryInput) -> RecoveryEvaluation:
        if (
            input.identical_failure_streak >= input.policy.identical_failure_threshold
            or input.recovery_attempt_count >= input.policy.max_recovery_attempts_per_plan
        ):
            return RecoveryEvaluator._repeated_failure_action(input)
        return RecoveryEvaluation(
            RecoveryAction.RECOVER_CURRENT_PLAN,
            RecoveryReasonCode.VERIFICATION_FAILED,
            reason_summary="trusted verification failed; current plan may be recovered",
        )

    @staticmethod
    def _repeated_failure_action(input: RecoveryInput) -> RecoveryEvaluation:
        if input.replan_count < input.policy.max_replans_per_task:
            reason = (
                RecoveryReasonCode.IDENTICAL_FAILURE_SIGNATURE
                if input.identical_failure_streak >= input.policy.identical_failure_threshold
                else RecoveryReasonCode.RECOVERY_ATTEMPT_BUDGET_EXHAUSTED
            )
            return RecoveryEvaluation(
                RecoveryAction.REPLAN,
                reason,
                reason_summary="current-plan recovery budget requires replanning",
            )
        return RecoveryEvaluation(
            RecoveryAction.BLOCK,
            RecoveryReasonCode.REPLAN_BUDGET_EXHAUSTED,
            reason_summary="replan budget is exhausted",
        )


__all__ = [
    "MAX_FAILURE_CASES",
    "MAX_FAILURE_SIGNATURE_BYTES",
    "MAX_RECOVERY_HISTORY_RECORDS",
    "RECOVERY_DECISION_SCHEMA_VERSION",
    "RECOVERY_POLICY_SCHEMA_VERSION",
    "NormalizedFailureCase",
    "NormalizedFailureSignature",
    "PlanningRecoveryStatus",
    "RecoveryAction",
    "RecoveryContractError",
    "RecoveryDecision",
    "RecoveryEvaluation",
    "RecoveryEvaluator",
    "RecoveryFailureSource",
    "RecoveryInput",
    "RecoveryPolicy",
    "RecoveryReasonCode",
]
