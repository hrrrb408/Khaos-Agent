"""Immutable M7.4 trusted-verification input and assessment contracts.

The contracts in this module deliberately sit between the M4 verification
authority/ledger and the M7 completion control plane.  They carry bounded
identity and digest references only; they do not contain command output,
repository content, permissions, or lifecycle authority.

``VerificationAssessment`` is immutable history.  A later completion fact
provider may project a *current* ``SATISFIED`` assessment into a completion
evaluation, but neither this module nor an assessment record can complete a
task or authorize an execution.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Final

from khaos.agent.control.state import AgentCognitiveState
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

VERIFICATION_ASSESSMENT_SCHEMA_VERSION = 1
TRUSTED_VERIFICATION_INPUT_SCHEMA_VERSION = 1
VERIFICATION_ALGORITHM_VERSION = "m7.4-trusted-verification-v1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_ID_LENGTH = 512
_MAX_TEXT_LENGTH = 2048
_MAX_DIAGNOSTICS = 32


class VerificationContractError(ValueError):
    """Raised when a trusted-verification contract is malformed."""


class VerificationAssessmentDisposition(str, Enum):
    """Deterministic result of evaluating trusted verification evidence."""

    SATISFIED = "satisfied"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    UNAVAILABLE = "unavailable"
    STALE = "stale"


# Vocabulary aliases make the boundary readable to adapters without creating
# a second enum or a second serialization format.
VerificationDisposition = VerificationAssessmentDisposition
VerificationAssessmentStatus = VerificationAssessmentDisposition


class VerificationExecutionStatus(str, Enum):
    """Persisted execution result states accepted as evidence descriptors."""

    PASSED = "passed"
    FAILED = "failed"
    ERRORED = "errored"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    ABORTED = "aborted"


class VerificationTermination(str, Enum):
    """Bounded termination descriptor for one verification execution."""

    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    ABORTED = "aborted"
    UNKNOWN = "unknown"


class VerificationEvidenceKind(str, Enum):
    """Identity kinds for evidence owned by the M4 verification subsystem."""

    EXECUTION_RUN = "execution_run"
    VERIFICATION_RUN = "verification_run"
    VERIFICATION_STEP = "verification_step"
    FINAL_MUTATION_ATTESTATION = "final_mutation_attestation"
    CHANGESET = "changeset"


def _text(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
    limit: int = _MAX_ID_LENGTH,
) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise VerificationContractError(f"{label} must be a string")
    if len(value) > limit:
        raise VerificationContractError(f"{label} exceeds its bound")
    if "\x00" in value:
        raise VerificationContractError(f"{label} contains a NUL byte")
    return value


def _digest(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise VerificationContractError(f"{label} must be a SHA-256 hex digest")
    return value


def _optional_digest(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _digest(value, label=label)


def _optional_text(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    return _text(value, label=label)


def _tuple_of(value: object, *, label: str, item_type: type[Any]) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise VerificationContractError(f"{label} must be a tuple")
    if any(type(item) is not item_type for item in value):
        raise VerificationContractError(
            f"{label} must contain only {item_type.__name__} values"
        )
    return value


def _string_tuple(value: object, *, label: str, limit: int = _MAX_TEXT_LENGTH) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise VerificationContractError(f"{label} must be a tuple")
    values = tuple(_text(item, label=label, limit=limit) for item in value)
    if len(values) != len(set(values)):
        raise VerificationContractError(f"{label} must not contain duplicates")
    return tuple(sorted(values))


@dataclass(frozen=True, slots=True)
class VerificationEvidenceRef:
    """Bounded reference to an M4-owned verification fact."""

    kind: VerificationEvidenceKind
    ref_id: str
    digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not VerificationEvidenceKind:
            raise VerificationContractError("kind must be VerificationEvidenceKind")
        _text(self.ref_id, label="ref_id")
        object.__setattr__(self, "digest", _optional_digest(self.digest, label="digest"))

    def to_payload(self) -> dict[str, object]:
        """Return the bounded canonical serialization payload."""
        return {
            "kind": self.kind.value,
            "ref_id": self.ref_id,
            "digest": self.digest,
        }


# Short adapter-facing name used by a few verification integrations.
VerificationEvidence = VerificationEvidenceRef


def _evidence_key(value: VerificationEvidenceRef) -> tuple[str, str, str]:
    return (value.kind.value, value.ref_id, value.digest or "")


@dataclass(frozen=True, slots=True)
class VerificationRequirement:
    """Declarative verification intent copied from a published plan."""

    requirement_id: str
    verification_type: str
    scope: str
    required: bool
    command_digest: str | None = None
    plan_step_id: str | None = None
    source_intent_id: str | None = None

    def __post_init__(self) -> None:
        _text(self.requirement_id, label="requirement_id")
        _text(self.verification_type, label="verification_type")
        _text(self.scope, label="scope")
        if type(self.required) is not bool:
            raise VerificationContractError("required must be a bool")
        object.__setattr__(
            self,
            "command_digest",
            _optional_digest(self.command_digest, label="command_digest"),
        )
        object.__setattr__(
            self,
            "plan_step_id",
            _optional_text(self.plan_step_id, label="plan_step_id"),
        )
        object.__setattr__(
            self,
            "source_intent_id",
            _optional_text(self.source_intent_id, label="source_intent_id"),
        )

    def to_payload(self) -> dict[str, object]:
        """Return the declarative requirement payload."""
        return {
            "requirement_id": self.requirement_id,
            "verification_type": self.verification_type,
            "scope": self.scope,
            "required": self.required,
            "command_digest": self.command_digest,
            "plan_step_id": self.plan_step_id,
            "source_intent_id": self.source_intent_id,
        }


@dataclass(frozen=True, slots=True)
class VerificationExecutionEvidence:
    """Bounded descriptor returned by an authorized verification evidence owner.

    This value intentionally stores digests and identities rather than raw
    stdout, stderr, patches, or repository files.  ``authority_id`` and
    ``authority_digest`` identify the owner that validated the record; their
    presence alone never makes caller-supplied data authoritative.
    """

    evidence_id: str
    requirement_id: str
    execution_run_id: str
    verification_run_id: str
    verification_step_id: str | None
    workspace_id: str
    repository_id: str
    base_revision: str | None
    repository_generation: str | None
    change_identity: str | None
    command_digest: str
    authority_id: str
    authority_digest: str
    status: VerificationExecutionStatus
    exit_code: int | None
    termination: VerificationTermination
    stdout_digest: str | None
    stderr_digest: str | None
    output_truncated: bool
    evidence_digest: str
    references: tuple[VerificationEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        for name in (
            "evidence_id",
            "requirement_id",
            "execution_run_id",
            "verification_run_id",
            "workspace_id",
            "repository_id",
            "command_digest",
            "authority_id",
            "authority_digest",
        ):
            _text(getattr(self, name), label=name)
        if self.repository_generation is not None:
            _text(self.repository_generation, label="repository_generation")
        if self.change_identity is not None:
            _text(self.change_identity, label="change_identity")
        if self.repository_generation is None and self.change_identity is None:
            raise VerificationContractError(
                "post-change repository_generation or change_identity is required"
            )
        object.__setattr__(
            self,
            "verification_step_id",
            _optional_text(self.verification_step_id, label="verification_step_id"),
        )
        if self.base_revision is not None:
            _text(self.base_revision, label="base_revision")
        _digest(self.command_digest, label="command_digest")
        _digest(self.authority_digest, label="authority_digest")
        _digest(self.evidence_digest, label="evidence_digest")
        if type(self.status) is not VerificationExecutionStatus:
            raise VerificationContractError(
                "status must be a VerificationExecutionStatus"
            )
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise VerificationContractError("exit_code must be an integer or None")
        if type(self.termination) is not VerificationTermination:
            raise VerificationContractError(
                "termination must be a VerificationTermination"
            )
        object.__setattr__(
            self,
            "stdout_digest",
            _optional_digest(self.stdout_digest, label="stdout_digest"),
        )
        object.__setattr__(
            self,
            "stderr_digest",
            _optional_digest(self.stderr_digest, label="stderr_digest"),
        )
        if type(self.output_truncated) is not bool:
            raise VerificationContractError("output_truncated must be a bool")
        references = _tuple_of(
            self.references,
            label="references",
            item_type=VerificationEvidenceRef,
        )
        object.__setattr__(
            self,
            "references",
            tuple(sorted(references, key=_evidence_key)),
        )

    @property
    def authority_instance_id(self) -> str:
        """Compatibility spelling for the M4 authority identity."""
        return self.authority_id

    def to_payload(self) -> dict[str, object]:
        """Return the bounded canonical evidence descriptor."""
        return {
            "evidence_id": self.evidence_id,
            "requirement_id": self.requirement_id,
            "execution_run_id": self.execution_run_id,
            "verification_run_id": self.verification_run_id,
            "verification_step_id": self.verification_step_id,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "repository_generation": self.repository_generation,
            "change_identity": self.change_identity,
            "command_digest": self.command_digest,
            "authority_id": self.authority_id,
            "authority_digest": self.authority_digest,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "termination": self.termination.value,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "output_truncated": self.output_truncated,
            "evidence_digest": self.evidence_digest,
            "references": [item.to_payload() for item in self.references],
        }


def _input_payload(value: TrustedVerificationInput) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "principal_id": value.principal_id,
        "project_id": value.project_id,
        "task_id": value.task_id,
        "goal_spec_id": value.goal_spec_id,
        "goal_spec_digest": value.goal_spec_digest,
        "cognitive_state": value.cognitive_state.value,
        "control_state_version": value.control_state_version,
        "task_status": value.task_status,
        "workspace_id": value.workspace_id,
        "repository_id": value.repository_id,
        "base_revision": value.base_revision,
        "published_plan_revision_id": value.published_plan_revision_id,
        "published_plan_revision_digest": value.published_plan_revision_digest,
        "repository_generation": value.repository_generation,
        "change_identity": value.change_identity,
        "policy_digest": value.policy_digest,
        "catalog_fingerprint": value.catalog_fingerprint,
        "verification_algorithm_version": value.verification_algorithm_version,
        "requirements": [
            item.to_payload()
            for item in sorted(value.requirements, key=lambda item: item.requirement_id)
        ],
        "evidence": [
            item.to_payload()
            for item in sorted(
                value.evidence,
                key=lambda item: (item.requirement_id, item.evidence_id),
            )
        ],
    }


@dataclass(frozen=True, slots=True)
class TrustedVerificationInput:
    """Exact immutable snapshot presented to the trusted verifier."""

    schema_version: int
    principal_id: str
    project_id: str
    task_id: str
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
    requirements: tuple[VerificationRequirement, ...]
    evidence: tuple[VerificationExecutionEvidence, ...]
    verification_algorithm_version: str = VERIFICATION_ALGORITHM_VERSION
    input_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != TRUSTED_VERIFICATION_INPUT_SCHEMA_VERSION:
            raise VerificationContractError("unsupported trusted-verification input schema")
        for name in (
            "principal_id",
            "task_id",
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "policy_digest",
            "catalog_fingerprint",
        ):
            _text(getattr(self, name), label=name)
        _text(self.project_id, label="project_id", allow_empty=True)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise VerificationContractError(
                "cognitive_state must be an AgentCognitiveState"
            )
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise VerificationContractError(
                "control_state_version must be a non-negative integer"
            )
        _text(self.task_status, label="task_status", limit=_MAX_ID_LENGTH)
        if self.base_revision is not None:
            _text(self.base_revision, label="base_revision")
        if self.published_plan_revision_id is None:
            if self.published_plan_revision_digest is not None:
                raise VerificationContractError(
                    "published plan digest requires a published plan identity"
                )
        else:
            _text(self.published_plan_revision_id, label="published_plan_revision_id")
            _digest(
                self.published_plan_revision_digest,
                label="published_plan_revision_digest",
            )
        if self.repository_generation is None and self.change_identity is None:
            raise VerificationContractError(
                "post-change repository_generation or change_identity is required"
            )
        if self.repository_generation is not None:
            _text(self.repository_generation, label="repository_generation")
        if self.change_identity is not None:
            _text(self.change_identity, label="change_identity")
        _digest(self.policy_digest, label="policy_digest")
        _digest(self.catalog_fingerprint, label="catalog_fingerprint")
        _text(
            self.verification_algorithm_version,
            label="verification_algorithm_version",
            limit=_MAX_ID_LENGTH,
        )
        requirements = _tuple_of(
            self.requirements,
            label="requirements",
            item_type=VerificationRequirement,
        )
        requirement_ids = [item.requirement_id for item in requirements]
        if len(requirement_ids) != len(set(requirement_ids)):
            raise VerificationContractError("verification requirement IDs must be unique")
        object.__setattr__(
            self,
            "requirements",
            tuple(sorted(requirements, key=lambda item: item.requirement_id)),
        )
        evidence = _tuple_of(
            self.evidence,
            label="evidence",
            item_type=VerificationExecutionEvidence,
        )
        evidence_ids = [item.evidence_id for item in evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise VerificationContractError("verification evidence IDs must be unique")
        known_ids = set(requirement_ids)
        if any(item.requirement_id not in known_ids for item in evidence):
            raise VerificationContractError(
                "verification evidence references an unknown requirement"
            )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=lambda item: (item.requirement_id, item.evidence_id))),
        )
        if type(self.input_digest) is not str:
            raise VerificationContractError("input_digest must be a string")
        expected = canonical_digest(_input_payload(self))
        if self.input_digest:
            _digest(self.input_digest, label="input_digest")
            if self.input_digest != expected:
                raise VerificationContractError("input_digest does not match input semantics")
        else:
            object.__setattr__(self, "input_digest", expected)

    @property
    def post_change_generation(self) -> str | None:
        """Compatibility spelling for repository generation."""
        return self.repository_generation

    def semantic_payload(self) -> dict[str, object]:
        """Return the exact payload covered by ``input_digest``."""
        return _input_payload(self)

    def canonical_json(self) -> str:
        """Serialize the input with the shared canonical encoder."""
        return canonical_json_bytes(
            {**self.semantic_payload(), "input_digest": self.input_digest}
        ).decode("utf-8")


def _check_payload(value: VerificationCheckAssessment) -> dict[str, object]:
    return {
        "check_id": value.check_id,
        "requirement_id": value.requirement_id,
        "scope": value.scope,
        "command_digest": value.command_digest,
        "execution_evidence_id": value.execution_evidence_id,
        "execution_evidence_digest": value.execution_evidence_digest,
        "status": value.status.value,
        "exit_code": value.exit_code,
        "termination": (
            value.termination.value if value.termination is not None else None
        ),
        "evidence": [item.to_payload() for item in value.evidence],
        "diagnostic": value.diagnostic,
        "result_digest": value.result_digest,
    }


@dataclass(frozen=True, slots=True)
class VerificationCheckAssessment:
    """Immutable bounded result for one declared verification check."""

    check_id: str
    requirement_id: str
    status: VerificationAssessmentDisposition
    evidence: tuple[VerificationEvidenceRef, ...] = ()
    diagnostic: str = ""
    scope: str = ""
    command_digest: str | None = None
    execution_evidence_id: str | None = None
    execution_evidence_digest: str | None = None
    exit_code: int | None = None
    termination: VerificationTermination | None = None
    result_digest: str | None = None

    def __post_init__(self) -> None:
        _text(self.check_id, label="check_id")
        _text(self.requirement_id, label="requirement_id")
        if type(self.status) is not VerificationAssessmentDisposition:
            raise VerificationContractError(
                "status must be a VerificationAssessmentDisposition"
            )
        evidence = _tuple_of(
            self.evidence,
            label="evidence",
            item_type=VerificationEvidenceRef,
        )
        object.__setattr__(self, "evidence", tuple(sorted(evidence, key=_evidence_key)))
        _text(self.diagnostic, label="diagnostic", allow_empty=True, limit=_MAX_TEXT_LENGTH)
        _text(self.scope, label="scope", allow_empty=True, limit=_MAX_TEXT_LENGTH)
        object.__setattr__(
            self,
            "command_digest",
            _optional_digest(self.command_digest, label="command_digest"),
        )
        object.__setattr__(
            self,
            "execution_evidence_id",
            _optional_text(self.execution_evidence_id, label="execution_evidence_id"),
        )
        object.__setattr__(
            self,
            "execution_evidence_digest",
            _optional_digest(
                self.execution_evidence_digest,
                label="execution_evidence_digest",
            ),
        )
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise VerificationContractError(
                "exit_code must be an integer or None"
            )
        if self.termination is not None and type(self.termination) is not VerificationTermination:
            raise VerificationContractError(
                "termination must be a VerificationTermination or None"
            )
        object.__setattr__(
            self,
            "result_digest",
            _optional_digest(self.result_digest, label="result_digest"),
        )

    @property
    def evidence_id(self) -> str | None:
        """Compatibility alias for the execution evidence identity."""
        return self.execution_evidence_id

    @property
    def evidence_digest(self) -> str | None:
        """Compatibility alias for the execution evidence digest."""
        return self.execution_evidence_digest

    @property
    def termination_reason(self) -> VerificationTermination | None:
        """Compatibility alias for the bounded termination descriptor."""
        return self.termination

    def to_payload(self) -> dict[str, object]:
        """Return the bounded canonical check payload."""
        return _check_payload(self)


def _assessment_payload(value: VerificationAssessment) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "principal_id": value.principal_id,
        "project_id": value.project_id,
        "task_id": value.task_id,
        "goal_spec_id": value.goal_spec_id,
        "goal_spec_digest": value.goal_spec_digest,
        "cognitive_state": value.cognitive_state.value,
        "control_state_version": value.control_state_version,
        "task_status": value.task_status,
        "workspace_id": value.workspace_id,
        "repository_id": value.repository_id,
        "base_revision": value.base_revision,
        "published_plan_revision_id": value.published_plan_revision_id,
        "published_plan_revision_digest": value.published_plan_revision_digest,
        "repository_generation": value.repository_generation,
        "change_identity": value.change_identity,
        "policy_digest": value.policy_digest,
        "catalog_fingerprint": value.catalog_fingerprint,
        "verification_algorithm_version": value.verification_algorithm_version,
        "input_digest": value.input_digest,
        "disposition": value.disposition.value,
        "requirements": [
            item.to_payload()
            for item in sorted(value.requirements, key=lambda item: item.requirement_id)
        ],
        "checks": [
            item.to_payload()
            for item in sorted(value.checks, key=lambda item: (item.requirement_id, item.check_id))
        ],
        "evidence": [item.to_payload() for item in sorted(value.evidence, key=_evidence_key)],
        "diagnostics": list(value.diagnostics),
    }


@dataclass(frozen=True, slots=True)
class VerificationAssessment:
    """Immutable assessment history produced by ``TrustedVerificationAuthority``."""

    schema_version: int
    assessment_id: str
    task_id: str
    principal_id: str
    project_id: str
    assessment_sequence: int
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
    input_digest: str
    disposition: VerificationAssessmentDisposition
    requirements: tuple[VerificationRequirement, ...]
    checks: tuple[VerificationCheckAssessment, ...]
    evidence: tuple[VerificationEvidenceRef, ...]
    diagnostics: tuple[str, ...]
    assessment_digest: str
    created_at: str
    verification_algorithm_version: str = VERIFICATION_ALGORITHM_VERSION

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != VERIFICATION_ASSESSMENT_SCHEMA_VERSION:
            raise VerificationContractError("unsupported verification assessment schema")
        _text(self.assessment_id, label="assessment_id")
        _text(self.task_id, label="task_id")
        _text(self.principal_id, label="principal_id")
        _text(self.project_id, label="project_id", allow_empty=True)
        if type(self.assessment_sequence) is not int or self.assessment_sequence < 0:
            raise VerificationContractError("assessment_sequence must be non-negative")
        for name in (
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "policy_digest",
            "catalog_fingerprint",
            "input_digest",
            "assessment_digest",
            "created_at",
        ):
            _text(getattr(self, name), label=name)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise VerificationContractError(
                "cognitive_state must be an AgentCognitiveState"
            )
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise VerificationContractError(
                "control_state_version must be a non-negative integer"
            )
        _text(self.task_status, label="task_status", limit=_MAX_ID_LENGTH)
        _digest(self.policy_digest, label="policy_digest")
        _digest(self.catalog_fingerprint, label="catalog_fingerprint")
        _text(
            self.verification_algorithm_version,
            label="verification_algorithm_version",
            limit=_MAX_ID_LENGTH,
        )
        _digest(self.input_digest, label="input_digest")
        _digest(self.assessment_digest, label="assessment_digest")
        if self.base_revision is not None:
            _text(self.base_revision, label="base_revision")
        if self.published_plan_revision_id is None:
            if self.published_plan_revision_digest is not None:
                raise VerificationContractError(
                    "published plan digest requires a published plan identity"
                )
        else:
            _text(self.published_plan_revision_id, label="published_plan_revision_id")
            _digest(
                self.published_plan_revision_digest,
                label="published_plan_revision_digest",
            )
        if self.repository_generation is not None:
            _text(self.repository_generation, label="repository_generation")
        if self.change_identity is not None:
            _text(self.change_identity, label="change_identity")
        if self.repository_generation is None and self.change_identity is None:
            raise VerificationContractError(
                "post-change repository_generation or change_identity is required"
            )
        if type(self.disposition) is not VerificationAssessmentDisposition:
            raise VerificationContractError(
                "disposition must be a VerificationAssessmentDisposition"
            )
        requirements = _tuple_of(
            self.requirements,
            label="requirements",
            item_type=VerificationRequirement,
        )
        if len({item.requirement_id for item in requirements}) != len(requirements):
            raise VerificationContractError("assessment requirements must be unique")
        object.__setattr__(
            self,
            "requirements",
            tuple(sorted(requirements, key=lambda item: item.requirement_id)),
        )
        checks = _tuple_of(
            self.checks,
            label="checks",
            item_type=VerificationCheckAssessment,
        )
        check_ids = [item.check_id for item in checks]
        if len(check_ids) != len(set(check_ids)):
            raise VerificationContractError("assessment check IDs must be unique")
        known_ids = {item.requirement_id for item in requirements}
        if any(item.requirement_id not in known_ids for item in checks):
            raise VerificationContractError("assessment check references unknown requirement")
        object.__setattr__(
            self,
            "checks",
            tuple(sorted(checks, key=lambda item: (item.requirement_id, item.check_id))),
        )
        evidence = _tuple_of(
            self.evidence,
            label="evidence",
            item_type=VerificationEvidenceRef,
        )
        object.__setattr__(self, "evidence", tuple(sorted(evidence, key=_evidence_key)))
        diagnostics = _string_tuple(self.diagnostics, label="diagnostics")
        if len(diagnostics) > _MAX_DIAGNOSTICS:
            raise VerificationContractError("diagnostics exceed the fixed bound")
        object.__setattr__(self, "diagnostics", diagnostics)
        expected = canonical_digest(_assessment_payload(self))
        if self.assessment_digest != expected:
            raise VerificationContractError(
                "assessment_digest does not match assessment semantics"
            )

    @property
    def verification_status(self) -> VerificationAssessmentDisposition:
        """Compatibility alias for the aggregate disposition."""
        return self.disposition

    @property
    def semantic_payload(self) -> dict[str, object]:
        """Return the exact assessment payload covered by the digest."""
        return _assessment_payload(self)

    def canonical_payload(self) -> dict[str, object]:
        """Return the complete bounded storage payload."""
        return {
            **self.semantic_payload,
            "assessment_id": self.assessment_id,
            "assessment_sequence": self.assessment_sequence,
            "created_at": self.created_at,
            "assessment_digest": self.assessment_digest,
        }

    def canonical_json(self) -> str:
        """Serialize the assessment using the shared canonical encoder."""
        return canonical_json_bytes(self.canonical_payload()).decode("utf-8")

    @classmethod
    def from_canonical_json(
        cls,
        payload: str,
        *,
        expected_digest: str | None = None,
    ) -> VerificationAssessment:
        """Strictly decode and integrity-check one durable assessment."""
        if type(payload) is not str:
            raise VerificationContractError("canonical assessment must be text")
        try:
            raw = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
        except (json.JSONDecodeError, TypeError, UnicodeDecodeError, ValueError) as exc:
            raise VerificationContractError("canonical assessment JSON is malformed") from exc
        if type(raw) is not dict:
            raise VerificationContractError("canonical assessment must be an object")
        _require_keys(raw, _ASSESSMENT_STORAGE_KEYS, label="verification assessment")
        try:
            requirements = tuple(_decode_requirement(item) for item in _require_list(raw["requirements"], label="requirements"))
            checks = tuple(_decode_check(item) for item in _require_list(raw["checks"], label="checks"))
            evidence = tuple(_decode_evidence(item) for item in _require_list(raw["evidence"], label="evidence"))
            value = cls(
                schema_version=raw["schema_version"],
                assessment_id=raw["assessment_id"],
                task_id=raw["task_id"],
                principal_id=raw["principal_id"],
                project_id=raw["project_id"],
                assessment_sequence=raw["assessment_sequence"],
                goal_spec_id=raw["goal_spec_id"],
                goal_spec_digest=raw["goal_spec_digest"],
                cognitive_state=AgentCognitiveState(raw["cognitive_state"]),
                control_state_version=raw["control_state_version"],
                task_status=raw["task_status"],
                workspace_id=raw["workspace_id"],
                repository_id=raw["repository_id"],
                base_revision=raw["base_revision"],
                published_plan_revision_id=raw["published_plan_revision_id"],
                published_plan_revision_digest=raw["published_plan_revision_digest"],
                repository_generation=raw["repository_generation"],
                change_identity=raw["change_identity"],
                policy_digest=raw["policy_digest"],
                catalog_fingerprint=raw["catalog_fingerprint"],
                input_digest=raw["input_digest"],
                disposition=VerificationAssessmentDisposition(raw["disposition"]),
                requirements=requirements,
                checks=checks,
                evidence=evidence,
                diagnostics=tuple(
                    _text(
                        item,
                        label="diagnostic",
                        allow_empty=True,
                        limit=_MAX_TEXT_LENGTH,
                    )
                    for item in _require_list(raw["diagnostics"], label="diagnostics")
                ),
                assessment_digest=raw["assessment_digest"],
                created_at=raw["created_at"],
                verification_algorithm_version=raw["verification_algorithm_version"],
            )
        except VerificationContractError:
            raise
        except (KeyError, TypeError, ValueError) as exc:
            raise VerificationContractError("canonical assessment values are invalid") from exc
        if expected_digest is not None:
            _digest(expected_digest, label="expected_digest")
            if value.assessment_digest != expected_digest:
                raise VerificationContractError("assessment digest mismatch")
        if value.canonical_json() != payload:
            raise VerificationContractError("canonical assessment JSON is not canonical")
        return value


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def _require_keys(value: dict[str, object], allowed: frozenset[str], *, label: str) -> None:
    if set(value) != allowed:
        raise VerificationContractError(f"{label} has an invalid schema")


def _require_list(value: object, *, label: str) -> list[object]:
    if type(value) is not list:
        raise VerificationContractError(f"{label} must be an array")
    return value


def _decode_evidence(value: object) -> VerificationEvidenceRef:
    if type(value) is not dict:
        raise VerificationContractError("evidence reference must be an object")
    _require_keys(value, _EVIDENCE_KEYS, label="evidence reference")
    try:
        return VerificationEvidenceRef(
            kind=VerificationEvidenceKind(value["kind"]),
            ref_id=value["ref_id"],  # type: ignore[arg-type]
            digest=value["digest"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationContractError("evidence reference is invalid") from exc


def _decode_requirement(value: object) -> VerificationRequirement:
    if type(value) is not dict:
        raise VerificationContractError("verification requirement must be an object")
    _require_keys(value, _REQUIREMENT_KEYS, label="verification requirement")
    try:
        return VerificationRequirement(
            requirement_id=value["requirement_id"],  # type: ignore[arg-type]
            verification_type=value["verification_type"],  # type: ignore[arg-type]
            scope=value["scope"],  # type: ignore[arg-type]
            required=value["required"],  # type: ignore[arg-type]
            command_digest=value["command_digest"],  # type: ignore[arg-type]
            plan_step_id=value["plan_step_id"],  # type: ignore[arg-type]
            source_intent_id=value["source_intent_id"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationContractError("verification requirement is invalid") from exc


def _decode_check(value: object) -> VerificationCheckAssessment:
    if type(value) is not dict:
        raise VerificationContractError("verification check must be an object")
    _require_keys(value, _CHECK_KEYS, label="verification check")
    try:
        return VerificationCheckAssessment(
            check_id=value["check_id"],  # type: ignore[arg-type]
            requirement_id=value["requirement_id"],  # type: ignore[arg-type]
            status=VerificationAssessmentDisposition(value["status"]),
            evidence=tuple(_decode_evidence(item) for item in _require_list(value["evidence"], label="check evidence")),
            diagnostic=value["diagnostic"],  # type: ignore[arg-type]
            scope=value["scope"],  # type: ignore[arg-type]
            command_digest=value["command_digest"],  # type: ignore[arg-type]
            execution_evidence_id=value["execution_evidence_id"],  # type: ignore[arg-type]
            execution_evidence_digest=value["execution_evidence_digest"],  # type: ignore[arg-type]
            exit_code=value["exit_code"],  # type: ignore[arg-type]
            termination=(
                None
                if value["termination"] is None
                else VerificationTermination(value["termination"])
            ),
            result_digest=value["result_digest"],  # type: ignore[arg-type]
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise VerificationContractError("verification check is invalid") from exc


_EVIDENCE_KEYS: Final[frozenset[str]] = frozenset({"kind", "ref_id", "digest"})
_REQUIREMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "requirement_id",
        "verification_type",
        "scope",
        "required",
        "command_digest",
        "plan_step_id",
        "source_intent_id",
    }
)
_CHECK_KEYS: Final[frozenset[str]] = frozenset(
    {
        "check_id",
        "requirement_id",
        "scope",
        "command_digest",
        "execution_evidence_id",
        "execution_evidence_digest",
        "status",
        "exit_code",
        "termination",
        "evidence",
        "diagnostic",
        "result_digest",
    }
)
_ASSESSMENT_STORAGE_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema_version",
        "assessment_id",
        "task_id",
        "principal_id",
        "project_id",
        "assessment_sequence",
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
        "repository_generation",
        "change_identity",
        "policy_digest",
        "catalog_fingerprint",
        "verification_algorithm_version",
        "input_digest",
        "disposition",
        "requirements",
        "checks",
        "evidence",
        "diagnostics",
        "assessment_digest",
        "created_at",
    }
)


__all__ = [
    "TRUSTED_VERIFICATION_INPUT_SCHEMA_VERSION",
    "VERIFICATION_ALGORITHM_VERSION",
    "VERIFICATION_ASSESSMENT_SCHEMA_VERSION",
    "TrustedVerificationInput",
    "VerificationAssessment",
    "VerificationAssessmentDisposition",
    "VerificationAssessmentStatus",
    "VerificationCheckAssessment",
    "VerificationContractError",
    "VerificationDisposition",
    "VerificationEvidence",
    "VerificationEvidenceKind",
    "VerificationEvidenceRef",
    "VerificationExecutionEvidence",
    "VerificationExecutionStatus",
    "VerificationRequirement",
    "VerificationTermination",
]
