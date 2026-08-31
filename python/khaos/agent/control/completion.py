"""Immutable contracts for one completion evaluation record.

M7.1.4 deliberately stops at the durable decision record.  A
``CompletionDecision`` is not an evaluator, a completion gate, or a task
status transition.  It is an immutable snapshot of an evaluation performed
against a particular GoalSpec and cognitive-state version.  Later batches
decide whether any recorded outcome is authoritative enough to project onto
the task lifecycle.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Final, cast

from khaos.agent.control.state import AgentCognitiveState
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

COMPLETION_DECISION_SCHEMA_VERSION = 1
"""Canonical schema version for the M7.1.4 decision contract."""

_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_ID_LENGTH = 512
_MAX_TEXT_LENGTH = 2048


class CompletionDecisionValidationError(ValueError):
    """Raised when a completion contract or canonical row is invalid."""


class CompletionOutcome(str, Enum):
    """Recorded outcome vocabulary for a completion evaluation."""

    COMPLETE = "complete"
    REPLAN = "replan"
    BLOCKED = "blocked"
    FAILED = "failed"

    @property
    def continuation_possible(self) -> bool:
        """Return the outcome-derived continuation semantics.

        This is intentionally derived from the closed outcome vocabulary;
        there is no independent mutable or caller-controlled ``recoverable``
        boolean in the contract.
        """
        return self in (CompletionOutcome.REPLAN, CompletionOutcome.BLOCKED)


class AssessmentStatus(str, Enum):
    """Snapshot status for one requirement or acceptance criterion."""

    SATISFIED = "satisfied"
    UNSATISFIED = "unsatisfied"
    UNKNOWN = "unknown"


class CompletionEvidenceKind(str, Enum):
    """Typed identity kinds that a decision may reference.

    The enum identifies an evidence owner and reference shape only.  In
    particular, ``VERIFICATION_RUN`` does not imply trusted verification or
    completion authority.
    """

    GOAL_SPEC = "goal_spec"
    PLAN_REVISION = "plan_revision"
    TOOL_RESULT = "tool_result"
    CHANGESET = "changeset"
    VERIFICATION_RUN = "verification_run"
    REVIEW = "review"
    TASK_STATE = "task_state"


@dataclass(frozen=True, slots=True)
class CompletionEvidenceRef:
    """Bounded typed reference to evidence owned by another subsystem."""

    kind: CompletionEvidenceKind
    ref_id: str
    digest: str | None = None

    def __post_init__(self) -> None:
        _require_enum(self.kind, CompletionEvidenceKind, label="kind")
        _require_text(self.ref_id, label="ref_id", max_length=_MAX_ID_LENGTH)
        if self.digest is not None:
            _require_text(self.digest, label="digest", max_length=_MAX_ID_LENGTH)


# Short alias for callers that use the contract name from the M7 design.
EvidenceRef = CompletionEvidenceRef


@dataclass(frozen=True, slots=True)
class RequirementAssessment:
    """Immutable assessment snapshot keyed by a GoalSpec requirement ID."""

    requirement_id: str
    status: AssessmentStatus
    evidence: tuple[CompletionEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _require_text(
            self.requirement_id,
            label="requirement_id",
            max_length=_MAX_ID_LENGTH,
        )
        _require_enum(self.status, AssessmentStatus, label="status")
        _require_evidence_tuple(self.evidence, label="evidence")


@dataclass(frozen=True, slots=True)
class CriterionAssessment:
    """Immutable assessment snapshot keyed by an acceptance criterion ID."""

    criterion_id: str
    status: AssessmentStatus
    evidence: tuple[CompletionEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _require_text(
            self.criterion_id,
            label="criterion_id",
            max_length=_MAX_ID_LENGTH,
        )
        _require_enum(self.status, AssessmentStatus, label="status")
        _require_evidence_tuple(self.evidence, label="evidence")


class CompletionIssueCode(str, Enum):
    """Closed vocabulary for explanatory completion issues."""

    REQUIREMENT_UNSATISFIED = "requirement_unsatisfied"
    REQUIREMENT_UNKNOWN = "requirement_unknown"
    CRITERION_UNSATISFIED = "criterion_unsatisfied"
    CRITERION_UNKNOWN = "criterion_unknown"
    PLAN_INCOMPLETE = "plan_incomplete"
    VERIFICATION_MISSING = "verification_missing"
    VERIFICATION_FAILED = "verification_failed"
    EXTERNAL_BLOCKER = "external_blocker"
    UNRECOVERABLE_FAILURE = "unrecoverable_failure"
    STALE_INPUT = "stale_input"


@dataclass(frozen=True, slots=True)
class CompletionIssue:
    """Typed explanatory issue attached to a decision snapshot.

    ``summary`` is human-readable context only.  It is never an authority
    flag and cannot make an evidence reference trusted.
    """

    code: CompletionIssueCode
    subject_id: str | None
    evidence: tuple[CompletionEvidenceRef, ...] = ()
    summary: str = ""

    def __post_init__(self) -> None:
        _require_enum(self.code, CompletionIssueCode, label="code")
        if self.subject_id is not None:
            _require_text(
                self.subject_id,
                label="subject_id",
                max_length=_MAX_ID_LENGTH,
            )
        _require_evidence_tuple(self.evidence, label="evidence")
        _require_text(
            self.summary,
            label="summary",
            allow_empty=True,
            max_length=_MAX_TEXT_LENGTH,
        )


_SEMANTIC_SCHEMA_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "task_id",
        "goal_spec_id",
        "goal_spec_digest",
        "cognitive_state",
        "control_state_version",
        "task_status_at_evaluation",
        "workspace_id",
        "outcome",
        "requirement_assessments",
        "criterion_assessments",
        "evidence",
        "issues",
    }
)
_STORAGE_SCHEMA_KEYS: Final[frozenset[str]] = _SEMANTIC_SCHEMA_KEYS | frozenset(
    {"decision_id", "decision_digest"}
)
_EVIDENCE_SCHEMA_KEYS: Final[frozenset[str]] = frozenset({"kind", "ref_id", "digest"})
_REQUIREMENT_ASSESSMENT_SCHEMA_KEYS: Final[frozenset[str]] = frozenset(
    {"requirement_id", "status", "evidence"}
)
_CRITERION_ASSESSMENT_SCHEMA_KEYS: Final[frozenset[str]] = frozenset(
    {"criterion_id", "status", "evidence"}
)
_ISSUE_SCHEMA_KEYS: Final[frozenset[str]] = frozenset(
    {"code", "subject_id", "evidence", "summary"}
)


def _require_text(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
    max_length: int | None = None,
) -> str:
    if type(value) is not str or (not allow_empty and not value):
        empty_suffix = "" if allow_empty else " and must not be empty"
        raise CompletionDecisionValidationError(
            f"{label} must be a string{empty_suffix}"
        )
    if max_length is not None and len(value) > max_length:
        raise CompletionDecisionValidationError(
            f"{label} exceeds the maximum length of {max_length}"
        )
    return value


def _require_enum(value: object, enum_type: type[Enum], *, label: str) -> None:
    if type(value) is not enum_type:
        raise CompletionDecisionValidationError(
            f"{label} must be a {enum_type.__name__} value"
        )


def _require_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise CompletionDecisionValidationError(
            f"{label} must be a lowercase SHA-256 hex digest"
        )
    return value


def _require_tuple(value: object, *, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise CompletionDecisionValidationError(f"{label} must be a tuple")
    return value


def _require_evidence_tuple(
    value: object, *, label: str
) -> tuple[CompletionEvidenceRef, ...]:
    values = _require_tuple(value, label=label)
    if any(type(item) is not CompletionEvidenceRef for item in values):
        raise CompletionDecisionValidationError(
            f"{label} must contain only CompletionEvidenceRef values"
        )
    return values  # type: ignore[return-value]


def _evidence_sort_key(ref: CompletionEvidenceRef) -> tuple[str, str, str]:
    return (ref.kind.value, ref.ref_id, ref.digest or "")


def _evidence_payload(ref: CompletionEvidenceRef) -> dict[str, object]:
    return {
        "kind": ref.kind.value,
        "ref_id": ref.ref_id,
        "digest": ref.digest,
    }


def _sorted_evidence_payload(
    refs: tuple[CompletionEvidenceRef, ...],
) -> list[dict[str, object]]:
    return [_evidence_payload(ref) for ref in sorted(refs, key=_evidence_sort_key)]


def _semantic_payload(
    *,
    schema_version: int,
    task_id: str,
    goal_spec_id: str,
    goal_spec_digest: str,
    cognitive_state: AgentCognitiveState,
    control_state_version: int,
    task_status_at_evaluation: str,
    workspace_id: str | None,
    outcome: CompletionOutcome,
    requirement_assessments: tuple[RequirementAssessment, ...],
    criterion_assessments: tuple[CriterionAssessment, ...],
    evidence: tuple[CompletionEvidenceRef, ...],
    issues: tuple[CompletionIssue, ...],
) -> dict[str, object]:
    """Build the semantic serialization, excluding storage identity fields."""
    return {
        "schema_version": schema_version,
        "task_id": task_id,
        "goal_spec_id": goal_spec_id,
        "goal_spec_digest": goal_spec_digest,
        "cognitive_state": cognitive_state.value,
        "control_state_version": control_state_version,
        "task_status_at_evaluation": task_status_at_evaluation,
        "workspace_id": workspace_id,
        "outcome": outcome.value,
        "requirement_assessments": [
            {
                "requirement_id": assessment.requirement_id,
                "status": assessment.status.value,
                "evidence": _sorted_evidence_payload(assessment.evidence),
            }
            for assessment in sorted(
                requirement_assessments,
                key=lambda item: item.requirement_id,
            )
        ],
        "criterion_assessments": [
            {
                "criterion_id": assessment.criterion_id,
                "status": assessment.status.value,
                "evidence": _sorted_evidence_payload(assessment.evidence),
            }
            for assessment in sorted(
                criterion_assessments,
                key=lambda item: item.criterion_id,
            )
        ],
        "evidence": _sorted_evidence_payload(evidence),
        "issues": [
            {
                "code": issue.code.value,
                "subject_id": issue.subject_id,
                "evidence": _sorted_evidence_payload(issue.evidence),
                "summary": issue.summary,
            }
            for issue in sorted(issues, key=_issue_sort_key)
        ],
    }


def _issue_sort_key(
    issue: CompletionIssue,
) -> tuple[str, str, str, tuple[tuple[str, str, str], ...]]:
    return (
        issue.code.value,
        issue.subject_id or "",
        issue.summary,
        tuple(
            _evidence_sort_key(ref)
            for ref in sorted(issue.evidence, key=_evidence_sort_key)
        ),
    )


def _compute_decision_digest(
    *,
    schema_version: int,
    task_id: str,
    goal_spec_id: str,
    goal_spec_digest: str,
    cognitive_state: AgentCognitiveState,
    control_state_version: int,
    task_status_at_evaluation: str,
    workspace_id: str | None,
    outcome: CompletionOutcome,
    requirement_assessments: tuple[RequirementAssessment, ...],
    criterion_assessments: tuple[CriterionAssessment, ...],
    evidence: tuple[CompletionEvidenceRef, ...],
    issues: tuple[CompletionIssue, ...],
) -> str:
    _validate_semantic_inputs(
        schema_version=schema_version,
        task_id=task_id,
        goal_spec_id=goal_spec_id,
        goal_spec_digest=goal_spec_digest,
        cognitive_state=cognitive_state,
        control_state_version=control_state_version,
        task_status_at_evaluation=task_status_at_evaluation,
        workspace_id=workspace_id,
        outcome=outcome,
        requirement_assessments=requirement_assessments,
        criterion_assessments=criterion_assessments,
        evidence=evidence,
        issues=issues,
    )
    return canonical_digest(
        _semantic_payload(
            schema_version=schema_version,
            task_id=task_id,
            goal_spec_id=goal_spec_id,
            goal_spec_digest=goal_spec_digest,
            cognitive_state=cognitive_state,
            control_state_version=control_state_version,
            task_status_at_evaluation=task_status_at_evaluation,
            workspace_id=workspace_id,
            outcome=outcome,
            requirement_assessments=requirement_assessments,
            criterion_assessments=criterion_assessments,
            evidence=evidence,
            issues=issues,
        )
    )


def _validate_semantic_inputs(
    *,
    schema_version: int,
    task_id: str,
    goal_spec_id: str,
    goal_spec_digest: str,
    cognitive_state: AgentCognitiveState,
    control_state_version: int,
    task_status_at_evaluation: str,
    workspace_id: str | None,
    outcome: CompletionOutcome,
    requirement_assessments: tuple[RequirementAssessment, ...],
    criterion_assessments: tuple[CriterionAssessment, ...],
    evidence: tuple[CompletionEvidenceRef, ...],
    issues: tuple[CompletionIssue, ...],
) -> None:
    """Validate inputs before digest code accesses typed enum members."""
    if type(schema_version) is not int:
        raise CompletionDecisionValidationError("schema_version must be an integer")
    if schema_version != COMPLETION_DECISION_SCHEMA_VERSION:
        raise CompletionDecisionValidationError(
            f"unsupported CompletionDecision schema_version: {schema_version}"
        )
    _require_text(task_id, label="task_id", max_length=_MAX_ID_LENGTH)
    _require_text(goal_spec_id, label="goal_spec_id", max_length=_MAX_ID_LENGTH)
    _require_digest(goal_spec_digest, label="goal_spec_digest")
    _require_enum(cognitive_state, AgentCognitiveState, label="cognitive_state")
    if type(control_state_version) is not int or control_state_version < 0:
        raise CompletionDecisionValidationError(
            "control_state_version must be a non-negative integer"
        )
    _require_text(
        task_status_at_evaluation,
        label="task_status_at_evaluation",
        max_length=_MAX_ID_LENGTH,
    )
    if workspace_id is not None:
        _require_text(workspace_id, label="workspace_id", max_length=_MAX_ID_LENGTH)
    _require_enum(outcome, CompletionOutcome, label="outcome")

    requirement_values = cast(
        tuple[RequirementAssessment, ...],
        _require_tuple(
            requirement_assessments,
            label="requirement_assessments",
        ),
    )
    if any(type(item) is not RequirementAssessment for item in requirement_values):
        raise CompletionDecisionValidationError(
            "requirement_assessments must contain only RequirementAssessment values"
        )
    requirement_ids = [item.requirement_id for item in requirement_values]
    if len(requirement_ids) != len(set(requirement_ids)):
        raise CompletionDecisionValidationError(
            "requirement_assessments must not contain duplicate requirement IDs"
        )

    criterion_values = cast(
        tuple[CriterionAssessment, ...],
        _require_tuple(
            criterion_assessments,
            label="criterion_assessments",
        ),
    )
    if any(type(item) is not CriterionAssessment for item in criterion_values):
        raise CompletionDecisionValidationError(
            "criterion_assessments must contain only CriterionAssessment values"
        )
    criterion_ids = [item.criterion_id for item in criterion_values]
    if len(criterion_ids) != len(set(criterion_ids)):
        raise CompletionDecisionValidationError(
            "criterion_assessments must not contain duplicate criterion IDs"
        )
    _require_evidence_tuple(evidence, label="evidence")
    issue_values = _require_tuple(issues, label="issues")
    if any(type(item) is not CompletionIssue for item in issue_values):
        raise CompletionDecisionValidationError(
            "issues must contain only CompletionIssue values"
        )


@dataclass(frozen=True, slots=True)
class CompletionDecision:
    """Immutable record of one completion evaluation snapshot.

    The contract validates structural consistency and its own digest.  It
    does not determine whether all required GoalSpec facts were assessed and
    it does not project ``outcome`` onto ``TaskStatus``.
    """

    schema_version: int
    decision_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status_at_evaluation: str
    workspace_id: str | None
    outcome: CompletionOutcome
    requirement_assessments: tuple[RequirementAssessment, ...]
    criterion_assessments: tuple[CriterionAssessment, ...]
    evidence: tuple[CompletionEvidenceRef, ...]
    issues: tuple[CompletionIssue, ...]
    decision_digest: str

    def __post_init__(self) -> None:
        _require_text(self.decision_id, label="decision_id", max_length=_MAX_ID_LENGTH)
        _validate_semantic_inputs(
            schema_version=self.schema_version,
            task_id=self.task_id,
            goal_spec_id=self.goal_spec_id,
            goal_spec_digest=self.goal_spec_digest,
            cognitive_state=self.cognitive_state,
            control_state_version=self.control_state_version,
            task_status_at_evaluation=self.task_status_at_evaluation,
            workspace_id=self.workspace_id,
            outcome=self.outcome,
            requirement_assessments=self.requirement_assessments,
            criterion_assessments=self.criterion_assessments,
            evidence=self.evidence,
            issues=self.issues,
        )
        _require_digest(self.decision_digest, label="decision_digest")
        expected_digest = _compute_decision_digest(
            schema_version=self.schema_version,
            task_id=self.task_id,
            goal_spec_id=self.goal_spec_id,
            goal_spec_digest=self.goal_spec_digest,
            cognitive_state=self.cognitive_state,
            control_state_version=self.control_state_version,
            task_status_at_evaluation=self.task_status_at_evaluation,
            workspace_id=self.workspace_id,
            outcome=self.outcome,
            requirement_assessments=self.requirement_assessments,
            criterion_assessments=self.criterion_assessments,
            evidence=self.evidence,
            issues=self.issues,
        )
        if self.decision_digest != expected_digest:
            raise CompletionDecisionValidationError(
                "decision_digest does not match the semantic payload"
            )

    @classmethod
    def from_parts(
        cls,
        *,
        decision_id: str,
        task_id: str,
        goal_spec_id: str,
        goal_spec_digest: str,
        cognitive_state: AgentCognitiveState,
        control_state_version: int,
        task_status_at_evaluation: str,
        workspace_id: str | None = None,
        outcome: CompletionOutcome,
        requirement_assessments: tuple[RequirementAssessment, ...] = (),
        criterion_assessments: tuple[CriterionAssessment, ...] = (),
        evidence: tuple[CompletionEvidenceRef, ...] = (),
        issues: tuple[CompletionIssue, ...] = (),
        schema_version: int = COMPLETION_DECISION_SCHEMA_VERSION,
    ) -> CompletionDecision:
        """Build a typed decision and calculate its semantic digest."""
        digest = _compute_decision_digest(
            schema_version=schema_version,
            task_id=task_id,
            goal_spec_id=goal_spec_id,
            goal_spec_digest=goal_spec_digest,
            cognitive_state=cognitive_state,
            control_state_version=control_state_version,
            task_status_at_evaluation=task_status_at_evaluation,
            workspace_id=workspace_id,
            outcome=outcome,
            requirement_assessments=requirement_assessments,
            criterion_assessments=criterion_assessments,
            evidence=evidence,
            issues=issues,
        )
        return cls(
            schema_version=schema_version,
            decision_id=decision_id,
            task_id=task_id,
            goal_spec_id=goal_spec_id,
            goal_spec_digest=goal_spec_digest,
            cognitive_state=cognitive_state,
            control_state_version=control_state_version,
            task_status_at_evaluation=task_status_at_evaluation,
            workspace_id=workspace_id,
            outcome=outcome,
            requirement_assessments=requirement_assessments,
            criterion_assessments=criterion_assessments,
            evidence=evidence,
            issues=issues,
            decision_digest=digest,
        )

    @property
    def continuation_possible(self) -> bool:
        """Return continuation semantics derived solely from ``outcome``."""
        return self.outcome.continuation_possible

    @property
    def semantic_payload(self) -> Mapping[str, object]:
        """Return a fresh serialization representation used by the digest."""
        return _semantic_payload(
            schema_version=self.schema_version,
            task_id=self.task_id,
            goal_spec_id=self.goal_spec_id,
            goal_spec_digest=self.goal_spec_digest,
            cognitive_state=self.cognitive_state,
            control_state_version=self.control_state_version,
            task_status_at_evaluation=self.task_status_at_evaluation,
            workspace_id=self.workspace_id,
            outcome=self.outcome,
            requirement_assessments=self.requirement_assessments,
            criterion_assessments=self.criterion_assessments,
            evidence=self.evidence,
            issues=self.issues,
        )

    def to_canonical_mapping(self) -> dict[str, object]:
        """Return the closed canonical storage representation."""
        return {
            **self.semantic_payload,
            "decision_id": self.decision_id,
            "decision_digest": self.decision_digest,
        }

    def canonical_json(self) -> str:
        """Serialize the decision using the shared canonical JSON format."""
        return canonical_json_bytes(self.to_canonical_mapping()).decode("utf-8")

    @classmethod
    def from_canonical_json(
        cls,
        payload: str,
        *,
        expected_digest: str | None = None,
    ) -> CompletionDecision:
        """Parse and integrity-check one canonical decision payload."""
        if type(payload) is not str:
            raise CompletionDecisionValidationError(
                "canonical CompletionDecision payload must be a string"
            )
        try:
            decoded = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise CompletionDecisionValidationError(
                "canonical CompletionDecision JSON is malformed"
            ) from exc
        if type(decoded) is not dict:
            raise CompletionDecisionValidationError(
                "canonical CompletionDecision JSON must be an object"
            )
        _require_closed_keys(decoded, _STORAGE_SCHEMA_KEYS, label="CompletionDecision")
        try:
            decision = cls(
                schema_version=decoded["schema_version"],
                decision_id=decoded["decision_id"],
                task_id=decoded["task_id"],
                goal_spec_id=decoded["goal_spec_id"],
                goal_spec_digest=decoded["goal_spec_digest"],
                cognitive_state=AgentCognitiveState(decoded["cognitive_state"]),
                control_state_version=decoded["control_state_version"],
                task_status_at_evaluation=decoded["task_status_at_evaluation"],
                workspace_id=decoded["workspace_id"],
                outcome=CompletionOutcome(decoded["outcome"]),
                requirement_assessments=_decode_requirement_assessments(
                    decoded["requirement_assessments"]
                ),
                criterion_assessments=_decode_criterion_assessments(
                    decoded["criterion_assessments"]
                ),
                evidence=_decode_evidence(decoded["evidence"], label="evidence"),
                issues=_decode_issues(decoded["issues"]),
                decision_digest=decoded["decision_digest"],
            )
        except CompletionDecisionValidationError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise CompletionDecisionValidationError(
                "canonical CompletionDecision value is invalid"
            ) from exc
        if expected_digest is not None:
            _require_digest(expected_digest, label="expected_digest")
            if decision.decision_digest != expected_digest:
                raise CompletionDecisionValidationError(
                    "stored decision_digest does not match the decision payload"
                )
        if decision.canonical_json() != payload:
            raise CompletionDecisionValidationError(
                "stored CompletionDecision JSON is not canonical"
            )
        return decision


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _require_closed_keys(
    value: dict[str, object], allowed: frozenset[str], *, label: str
) -> None:
    unknown = set(value) - allowed
    missing = allowed - set(value)
    if unknown:
        raise CompletionDecisionValidationError(
            f"{label} contains unknown fields: {sorted(unknown)}"
        )
    if missing:
        raise CompletionDecisionValidationError(
            f"{label} is missing fields: {sorted(missing)}"
        )


def _decode_evidence(value: object, *, label: str) -> tuple[CompletionEvidenceRef, ...]:
    if type(value) is not list:
        raise CompletionDecisionValidationError(f"{label} must be a JSON array")
    decoded: list[CompletionEvidenceRef] = []
    for item in value:
        if type(item) is not dict:
            raise CompletionDecisionValidationError(
                f"each {label} reference must be an object"
            )
        _require_closed_keys(item, _EVIDENCE_SCHEMA_KEYS, label=label)
        try:
            decoded.append(
                CompletionEvidenceRef(
                    kind=CompletionEvidenceKind(item["kind"]),
                    ref_id=item["ref_id"],
                    digest=item["digest"],
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompletionDecisionValidationError(
                f"{label} contains an invalid reference"
            ) from exc
    return tuple(decoded)


def _decode_requirement_assessments(
    value: object,
) -> tuple[RequirementAssessment, ...]:
    if type(value) is not list:
        raise CompletionDecisionValidationError(
            "requirement_assessments must be a JSON array"
        )
    decoded: list[RequirementAssessment] = []
    for item in value:
        if type(item) is not dict:
            raise CompletionDecisionValidationError(
                "each requirement assessment must be an object"
            )
        _require_closed_keys(
            item,
            _REQUIREMENT_ASSESSMENT_SCHEMA_KEYS,
            label="requirement assessment",
        )
        try:
            decoded.append(
                RequirementAssessment(
                    requirement_id=item["requirement_id"],
                    status=AssessmentStatus(item["status"]),
                    evidence=_decode_evidence(
                        item["evidence"], label="requirement assessment evidence"
                    ),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompletionDecisionValidationError(
                "requirement assessment is invalid"
            ) from exc
    return tuple(decoded)


def _decode_criterion_assessments(
    value: object,
) -> tuple[CriterionAssessment, ...]:
    if type(value) is not list:
        raise CompletionDecisionValidationError(
            "criterion_assessments must be a JSON array"
        )
    decoded: list[CriterionAssessment] = []
    for item in value:
        if type(item) is not dict:
            raise CompletionDecisionValidationError(
                "each criterion assessment must be an object"
            )
        _require_closed_keys(
            item,
            _CRITERION_ASSESSMENT_SCHEMA_KEYS,
            label="criterion assessment",
        )
        try:
            decoded.append(
                CriterionAssessment(
                    criterion_id=item["criterion_id"],
                    status=AssessmentStatus(item["status"]),
                    evidence=_decode_evidence(
                        item["evidence"], label="criterion assessment evidence"
                    ),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompletionDecisionValidationError(
                "criterion assessment is invalid"
            ) from exc
    return tuple(decoded)


def _decode_issues(value: object) -> tuple[CompletionIssue, ...]:
    if type(value) is not list:
        raise CompletionDecisionValidationError("issues must be a JSON array")
    decoded: list[CompletionIssue] = []
    for item in value:
        if type(item) is not dict:
            raise CompletionDecisionValidationError("each issue must be an object")
        _require_closed_keys(item, _ISSUE_SCHEMA_KEYS, label="issue")
        try:
            decoded.append(
                CompletionIssue(
                    code=CompletionIssueCode(item["code"]),
                    subject_id=item["subject_id"],
                    evidence=_decode_evidence(item["evidence"], label="issue evidence"),
                    summary=item["summary"],
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise CompletionDecisionValidationError("issue is invalid") from exc
    return tuple(decoded)


__all__ = [
    "COMPLETION_DECISION_SCHEMA_VERSION",
    "AssessmentStatus",
    "CompletionDecision",
    "CompletionDecisionValidationError",
    "CompletionEvidenceKind",
    "CompletionEvidenceRef",
    "CompletionIssue",
    "CompletionIssueCode",
    "CompletionOutcome",
    "CriterionAssessment",
    "EvidenceRef",
    "RequirementAssessment",
]
