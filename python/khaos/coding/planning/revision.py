"""Immutable M7.3 planning inputs and durable plan-revision contracts.

The legacy planning objects in :mod:`khaos.coding.planning.contracts` remain
available to older approval/execution adapters.  This module is the canonical
M7.3 control-plane boundary: it contains only deeply immutable value objects,
deterministic serialization, and no database, filesystem, or execution
authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.intelligence.context import (
    ContextFreshness,
    normalize_relative_path,
)
from khaos.coding.planning.contracts import PlanOperation
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

PLANNING_SCHEMA_VERSION = 1
PLANNER_ALGORITHM_VERSION = "m7.3-context-bound-deterministic-v1"
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_TEXT = 16 * 1024
_MAX_ID = 512


class PlanningContractError(ValueError):
    """Raised when an M7.3 planning value object is malformed."""


class PlanDisposition(str, Enum):
    """Control-plane disposition of one immutable plan revision.

    These values describe planning output only.  They are not task lifecycle
    statuses and do not grant approval, execution, or completion authority.
    """

    READY = "ready"
    BLOCKED = "blocked"
    STALE = "stale"
    INVALID = "invalid"


class PlanningEvidenceKind(str, Enum):
    """Descriptive provenance kinds for bounded planning evidence."""

    GOAL_SPEC = "goal_spec"
    CONTEXT_BUNDLE = "context_bundle"
    CONTEXT_DOCUMENT = "context_document"
    CONTEXT_SYMBOL = "context_symbol"
    CONTEXT_RELATION = "context_relation"
    TASK_SNAPSHOT = "task_snapshot"
    REPOSITORY_CONFIG = "repository_config"
    PLANNING_DIAGNOSTIC = "planning_diagnostic"


class PlanningRiskLevel(str, Enum):
    """Descriptive deterministic planning-risk levels."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _text(value: object, *, label: str, allow_empty: bool = False, limit: int = _MAX_ID) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise PlanningContractError(f"{label} must be a string")
    if len(value) > limit:
        raise PlanningContractError(f"{label} exceeds its bound")
    if "\x00" in value:
        raise PlanningContractError(f"{label} contains a NUL byte")
    return value


def _digest(value: object, *, label: str) -> str:
    if type(value) is not str or _HEX_DIGEST.fullmatch(value) is None:
        raise PlanningContractError(f"{label} must be a SHA-256 hex digest")
    return value


def _tuple(value: object, *, label: str) -> tuple[Any, ...]:
    if type(value) is not tuple:
        raise PlanningContractError(f"{label} must be a tuple")
    return value


def _strings(value: object, *, label: str, normalize_paths: bool = False) -> tuple[str, ...]:
    values = _tuple(value, label=label)
    result: list[str] = []
    for item in values:
        if normalize_paths:
            if type(item) is not str:
                raise PlanningContractError(f"{label} must contain strings")
            result.append(normalize_relative_path(item, label=label))
        else:
            result.append(_text(item, label=label, limit=_MAX_TEXT))
    return tuple(sorted(set(result)))


def _optional_text(value: object, *, label: str, limit: int = _MAX_ID) -> str | None:
    if value is None:
        return None
    return _text(value, label=label, limit=limit)


def _typed_tuple(value: object, *, label: str, item_type: type[Any]) -> tuple[Any, ...]:
    values = _tuple(value, label=label)
    if any(type(item) is not item_type for item in values):
        raise PlanningContractError(f"{label} contains an invalid typed value")
    return values


def _stable_evidence_key(item: PlanningEvidenceRef) -> tuple[str, str, str, str, str]:
    return (
        item.kind.value,
        item.ref_id,
        item.digest or "",
        item.relative_path or "",
        item.symbol_id or "",
    )


@dataclass(frozen=True, slots=True)
class PlanningEvidenceRef:
    """Bounded descriptive reference; never an authority assertion."""

    kind: PlanningEvidenceKind
    ref_id: str
    digest: str | None = None
    relative_path: str | None = None
    symbol_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.kind) is not PlanningEvidenceKind:
            raise PlanningContractError("kind must be a PlanningEvidenceKind")
        _text(self.ref_id, label="ref_id")
        if self.digest is not None:
            _digest(self.digest, label="digest")
        if self.relative_path is not None:
            object.__setattr__(
                self,
                "relative_path",
                normalize_relative_path(self.relative_path),
            )
        if self.symbol_id is not None:
            _text(self.symbol_id, label="symbol_id")

    def to_payload(self) -> dict[str, object]:
        """Return the serialization-only representation of this reference."""
        return {
            "kind": self.kind.value,
            "ref_id": self.ref_id,
            "digest": self.digest,
            "relative_path": self.relative_path,
            "symbol_id": self.symbol_id,
        }


@dataclass(frozen=True, slots=True)
class PlanningRisk:
    """Deterministic risk description, not an approval decision."""

    level: PlanningRiskLevel
    category: str
    description: str
    affected_scope: tuple[str, ...]
    mitigation: str
    requires_approval: bool

    def __post_init__(self) -> None:
        if type(self.level) is not PlanningRiskLevel:
            raise PlanningContractError("level must be a PlanningRiskLevel")
        _text(self.category, label="category")
        _text(self.description, label="description", limit=_MAX_TEXT)
        object.__setattr__(
            self,
            "affected_scope",
            _strings(self.affected_scope, label="affected_scope", normalize_paths=True),
        )
        _text(self.mitigation, label="mitigation", limit=_MAX_TEXT)
        if type(self.requires_approval) is not bool:
            raise PlanningContractError("requires_approval must be a bool")

    def to_payload(self) -> dict[str, object]:
        return {
            "level": self.level.value,
            "category": self.category,
            "description": self.description,
            "affected_scope": list(self.affected_scope),
            "mitigation": self.mitigation,
            "requires_approval": self.requires_approval,
        }


@dataclass(frozen=True, slots=True)
class PlanningVerificationIntent:
    """Descriptive verification intent; it never executes a command."""

    verification_type: str
    scope: str
    expected_result: str
    required: bool
    risk_level: PlanningRiskLevel
    command: tuple[str, ...] | None = None
    evidence: tuple[PlanningEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _text(self.verification_type, label="verification_type")
        _text(self.scope, label="scope")
        _text(self.expected_result, label="expected_result", limit=_MAX_TEXT)
        if type(self.required) is not bool:
            raise PlanningContractError("required must be a bool")
        if type(self.risk_level) is not PlanningRiskLevel:
            raise PlanningContractError("risk_level must be a PlanningRiskLevel")
        if self.command is not None:
            command = _tuple(self.command, label="command")
            if any(type(part) is not str or not part for part in command):
                raise PlanningContractError("command must contain non-empty strings")
            object.__setattr__(self, "command", tuple(command))
        evidence = _typed_tuple(
            self.evidence, label="evidence", item_type=PlanningEvidenceRef
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=_stable_evidence_key)),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "verification_type": self.verification_type,
            "scope": self.scope,
            "expected_result": self.expected_result,
            "required": self.required,
            "risk_level": self.risk_level.value,
            "command": list(self.command) if self.command is not None else None,
            "evidence": [item.to_payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class PlanningDiagnostic:
    """Bounded deterministic explanation of a planning disposition."""

    code: str
    severity: str
    message: str
    recoverable: bool
    evidence: tuple[PlanningEvidenceRef, ...] = ()

    def __post_init__(self) -> None:
        _text(self.code, label="code")
        _text(self.severity, label="severity")
        _text(self.message, label="message", limit=_MAX_TEXT)
        if type(self.recoverable) is not bool:
            raise PlanningContractError("recoverable must be a bool")
        evidence = _typed_tuple(
            self.evidence, label="evidence", item_type=PlanningEvidenceRef
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=_stable_evidence_key)),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
            "recoverable": self.recoverable,
            "evidence": [item.to_payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class PlanningStep:
    """One immutable, dependency-aware engineering plan step."""

    step_id: str
    title: str
    description: str
    operation: PlanOperation
    target_files: tuple[str, ...]
    target_symbols: tuple[str, ...]
    dependencies: tuple[str, ...]
    expected_outcome: str
    verification_requirements: tuple[PlanningVerificationIntent, ...]
    risk: PlanningRisk
    requires_approval: bool
    evidence: tuple[PlanningEvidenceRef, ...]

    def __post_init__(self) -> None:
        _text(self.step_id, label="step_id")
        _text(self.title, label="title", limit=_MAX_TEXT)
        _text(self.description, label="description", limit=_MAX_TEXT)
        if type(self.operation) is not PlanOperation:
            raise PlanningContractError("operation must be a PlanOperation")
        object.__setattr__(
            self,
            "target_files",
            _strings(self.target_files, label="target_files", normalize_paths=True),
        )
        object.__setattr__(
            self,
            "target_symbols",
            _strings(self.target_symbols, label="target_symbols"),
        )
        raw_dependencies = _tuple(self.dependencies, label="dependencies")
        if any(type(item) is not str or not item for item in raw_dependencies):
            raise PlanningContractError("dependencies must contain strings")
        if len(raw_dependencies) != len(set(raw_dependencies)):
            raise PlanningContractError("dependencies must not be duplicated")
        dependencies = _strings(raw_dependencies, label="dependencies")
        if self.step_id in dependencies:
            raise PlanningContractError("a plan step cannot depend on itself")
        object.__setattr__(self, "dependencies", dependencies)
        _text(self.expected_outcome, label="expected_outcome", limit=_MAX_TEXT)
        requirements = _typed_tuple(
            self.verification_requirements,
            label="verification_requirements",
            item_type=PlanningVerificationIntent,
        )
        object.__setattr__(
            self,
            "verification_requirements",
            tuple(
                sorted(
                    requirements,
                    key=lambda item: (
                        item.verification_type,
                        item.scope,
                        item.command or (),
                    ),
                )
            ),
        )
        if type(self.risk) is not PlanningRisk:
            raise PlanningContractError("risk must be a PlanningRisk")
        if type(self.requires_approval) is not bool:
            raise PlanningContractError("requires_approval must be a bool")
        evidence = _typed_tuple(
            self.evidence, label="evidence", item_type=PlanningEvidenceRef
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=_stable_evidence_key)),
        )

    @property
    def depends_on(self) -> tuple[str, ...]:
        """Compatibility spelling used by the legacy DAG adapter."""
        return self.dependencies

    def to_payload(self) -> dict[str, object]:
        return {
            "step_id": self.step_id,
            "title": self.title,
            "description": self.description,
            "operation": self.operation.value,
            "target_files": list(self.target_files),
            "target_symbols": list(self.target_symbols),
            "dependencies": list(self.dependencies),
            "expected_outcome": self.expected_outcome,
            "verification_requirements": [
                item.to_payload() for item in self.verification_requirements
            ],
            "risk": self.risk.to_payload(),
            "requires_approval": self.requires_approval,
            "evidence": [item.to_payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class PlanningAffectedFile:
    """Bounded file impact projection used by a plan revision."""

    path: str
    operation: PlanOperation
    reason: str
    confidence: float
    exists: bool
    language: str | None
    evidence: tuple[PlanningEvidenceRef, ...]
    destination_path: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", normalize_relative_path(self.path))
        if type(self.operation) is not PlanOperation:
            raise PlanningContractError("operation must be a PlanOperation")
        _text(self.reason, label="reason", limit=_MAX_TEXT)
        if type(self.confidence) is not float or not 0.0 <= self.confidence <= 1.0:
            raise PlanningContractError("confidence must be a float in [0, 1]")
        if type(self.exists) is not bool:
            raise PlanningContractError("exists must be a bool")
        if self.language is not None:
            _text(self.language, label="language")
        if self.destination_path is not None:
            object.__setattr__(
                self,
                "destination_path",
                normalize_relative_path(self.destination_path, label="destination_path"),
            )
        evidence = _typed_tuple(
            self.evidence, label="evidence", item_type=PlanningEvidenceRef
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=_stable_evidence_key)),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "operation": self.operation.value,
            "reason": self.reason,
            "confidence": self.confidence,
            "exists": self.exists,
            "language": self.language,
            "evidence": [item.to_payload() for item in self.evidence],
            "destination_path": self.destination_path,
        }


@dataclass(frozen=True, slots=True)
class PlanningAffectedSymbol:
    """Generation-bound symbol impact projection."""

    symbol_id: str
    relative_path: str
    language: str
    qualified_name: str
    kind: str
    evidence: tuple[PlanningEvidenceRef, ...]

    def __post_init__(self) -> None:
        _text(self.symbol_id, label="symbol_id")
        object.__setattr__(
            self,
            "relative_path",
            normalize_relative_path(self.relative_path),
        )
        for name in ("language", "qualified_name", "kind"):
            _text(getattr(self, name), label=name)
        evidence = _typed_tuple(
            self.evidence, label="evidence", item_type=PlanningEvidenceRef
        )
        object.__setattr__(
            self,
            "evidence",
            tuple(sorted(evidence, key=_stable_evidence_key)),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "symbol_id": self.symbol_id,
            "relative_path": self.relative_path,
            "language": self.language,
            "qualified_name": self.qualified_name,
            "kind": self.kind,
            "evidence": [item.to_payload() for item in self.evidence],
        }


@dataclass(frozen=True, slots=True)
class PlanningDependencyImpact:
    """Descriptive dependency/relation edge; no execution instruction."""

    source: str
    target: str
    relation: str
    status: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("source", "target", "relation", "status", "reason"):
            _text(getattr(self, name), label=name, limit=_MAX_TEXT)

    def to_payload(self) -> dict[str, object]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "status": self.status,
            "reason": self.reason,
        }


def _planning_input_payload(value: PlanningInput) -> dict[str, object]:
    return {
        "schema_version": value.schema_version,
        "task_id": value.task_id,
        "principal_id": value.principal_id,
        "project_id": value.project_id,
        "goal_spec_id": value.goal_spec_id,
        "goal_spec_digest": value.goal_spec_digest,
        "workspace_id": value.workspace_id,
        "repository_id": value.repository_id,
        "base_revision": value.base_revision,
        "context_bundle_id": value.context_bundle_id,
        "context_bundle_digest": value.context_bundle_digest,
        "context_request_digest": value.context_request_digest,
        "repository_generation": value.repository_generation,
        "index_generation": value.index_generation,
        "context_freshness": value.context_freshness.value,
        "cognitive_state": value.cognitive_state.value,
        "control_state_version": value.control_state_version,
        "task_status": value.task_status,
        "planner_schema_version": value.planner_schema_version,
        "planner_algorithm_version": value.planner_algorithm_version,
        "target_files": list(value.target_files),
        "target_symbols": list(value.target_symbols),
        "context_truncated": value.context_truncated,
        "truncation_reasons": list(value.truncation_reasons),
    }


@dataclass(frozen=True, slots=True)
class PlanningInput:
    """Exact durable snapshot binding supplied to deterministic planning."""

    schema_version: int
    task_id: str
    principal_id: str
    project_id: str
    goal_spec_id: str
    goal_spec_digest: str
    workspace_id: str
    repository_id: str
    base_revision: str | None
    context_bundle_id: str
    context_bundle_digest: str
    context_request_digest: str
    repository_generation: str
    index_generation: str
    context_freshness: ContextFreshness
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    planner_schema_version: int
    planner_algorithm_version: str
    target_files: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    context_truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    input_digest: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != PLANNING_SCHEMA_VERSION:
            raise PlanningContractError("unsupported planning input schema_version")
        for name in (
            "task_id",
            "principal_id",
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "context_bundle_id",
            "repository_generation",
            "index_generation",
            "planner_algorithm_version",
        ):
            _text(getattr(self, name), label=name)
        _text(self.project_id, label="project_id", allow_empty=True)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _digest(self.context_bundle_digest, label="context_bundle_digest")
        _digest(self.context_request_digest, label="context_request_digest")
        if self.base_revision is not None:
            _text(self.base_revision, label="base_revision")
        if type(self.context_freshness) is not ContextFreshness:
            raise PlanningContractError("context_freshness must be a ContextFreshness")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise PlanningContractError("cognitive_state must be an AgentCognitiveState")
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise PlanningContractError("control_state_version must be non-negative")
        _text(self.task_status, label="task_status")
        if type(self.planner_schema_version) is not int or self.planner_schema_version < 1:
            raise PlanningContractError("planner_schema_version must be positive")
        object.__setattr__(
            self,
            "target_files",
            _strings(self.target_files, label="target_files", normalize_paths=True),
        )
        object.__setattr__(
            self,
            "target_symbols",
            _strings(self.target_symbols, label="target_symbols"),
        )
        if type(self.context_truncated) is not bool:
            raise PlanningContractError("context_truncated must be a bool")
        object.__setattr__(
            self,
            "truncation_reasons",
            _strings(self.truncation_reasons, label="truncation_reasons"),
        )
        if type(self.input_digest) is not str:
            raise PlanningContractError("input_digest must be a string")
        expected = canonical_digest(_planning_input_payload(self))
        if self.input_digest:
            _digest(self.input_digest, label="input_digest")
            if self.input_digest != expected:
                raise PlanningContractError("input_digest does not match planning input")
        else:
            object.__setattr__(self, "input_digest", expected)

    @property
    def planning_input_digest(self) -> str:
        """Compatibility spelling used by persistence and coordinator code."""
        return self.input_digest

    def canonical_json(self) -> str:
        """Serialize the input using the shared canonical wire format."""
        return canonical_json_bytes(_planning_input_payload(self)).decode("utf-8")


def _revision_semantic_payload(value: PlanRevision) -> dict[str, object]:
    """Return the exact plan semantics covered by ``plan_semantic_digest``.

    Storage identity (revision id, sequence, parent, owner and timestamp) is
    intentionally excluded.  Task and snapshot bindings remain included so a
    plan cannot be semantically reused for a different task snapshot.
    """
    return {
        "schema_version": value.schema_version,
        "task_id": value.task_id,
        "goal_spec_id": value.goal_spec_id,
        "goal_spec_digest": value.goal_spec_digest,
        "workspace_id": value.workspace_id,
        "repository_id": value.repository_id,
        "base_revision": value.base_revision,
        "context_bundle_id": value.context_bundle_id,
        "context_bundle_digest": value.context_bundle_digest,
        "context_request_digest": value.context_request_digest,
        "repository_generation": value.repository_generation,
        "index_generation": value.index_generation,
        "context_freshness": value.context_freshness.value,
        "cognitive_state": value.cognitive_state.value,
        "control_state_version": value.control_state_version,
        "task_status": value.task_status,
        "planner_schema_version": value.planner_schema_version,
        "planner_algorithm_version": value.planner_algorithm_version,
        "planning_input_digest": value.planning_input_digest,
        "disposition": value.disposition.value,
        "summary": value.summary,
        "steps": [item.to_payload() for item in sorted(value.steps, key=lambda item: item.step_id)],
        "affected_files": [
            item.to_payload()
            for item in sorted(value.affected_files, key=lambda item: item.path)
        ],
        "affected_symbols": [
            item.to_payload()
            for item in sorted(
                value.affected_symbols,
                key=lambda item: (item.relative_path, item.qualified_name, item.symbol_id),
            )
        ],
        "dependency_impacts": [
            item.to_payload()
            for item in sorted(
                value.dependency_impacts,
                key=lambda item: (item.source, item.target, item.relation, item.status),
            )
        ],
        "verification_intents": [
            item.to_payload()
            for item in sorted(
                value.verification_intents,
                key=lambda item: (item.verification_type, item.scope, item.command or ()),
            )
        ],
        "risks": [
            item.to_payload()
            for item in sorted(
                value.risks,
                key=lambda item: (item.level.value, item.category, item.affected_scope),
            )
        ],
        "diagnostics": [
            item.to_payload()
            for item in sorted(value.diagnostics, key=lambda item: (item.code, item.message))
        ],
        "evidence": [
            item.to_payload()
            for item in sorted(value.evidence, key=_stable_evidence_key)
        ],
    }


@dataclass(frozen=True, slots=True)
class PlanRevision:
    """Immutable canonical plan revision.

    ``plan_revision_id``/``revision_sequence``/``parent_revision_id`` and
    ``created_at`` are storage envelope fields.  A zero/empty envelope is
    accepted only as an append draft; the repository assigns durable identity
    and sequence before writing it.
    """

    schema_version: int
    plan_revision_id: str
    task_id: str
    principal_id: str
    project_id: str
    revision_sequence: int
    parent_revision_id: str | None
    goal_spec_id: str
    goal_spec_digest: str
    workspace_id: str
    repository_id: str
    base_revision: str | None
    context_bundle_id: str
    context_bundle_digest: str
    context_request_digest: str
    repository_generation: str
    index_generation: str
    context_freshness: ContextFreshness
    cognitive_state: AgentCognitiveState
    control_state_version: int
    task_status: str
    planner_schema_version: int
    planner_algorithm_version: str
    planning_input_digest: str
    disposition: PlanDisposition
    summary: str
    steps: tuple[PlanningStep, ...]
    affected_files: tuple[PlanningAffectedFile, ...] = ()
    affected_symbols: tuple[PlanningAffectedSymbol, ...] = ()
    dependency_impacts: tuple[PlanningDependencyImpact, ...] = ()
    verification_intents: tuple[PlanningVerificationIntent, ...] = ()
    risks: tuple[PlanningRisk, ...] = ()
    diagnostics: tuple[PlanningDiagnostic, ...] = ()
    evidence: tuple[PlanningEvidenceRef, ...] = ()
    plan_semantic_digest: str = ""
    created_at: str = ""

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != PLANNING_SCHEMA_VERSION:
            raise PlanningContractError("unsupported plan revision schema_version")
        if type(self.plan_revision_id) is not str:
            raise PlanningContractError("plan_revision_id must be a string")
        if self.plan_revision_id:
            _text(self.plan_revision_id, label="plan_revision_id")
        if type(self.revision_sequence) is not int or self.revision_sequence < 0:
            raise PlanningContractError("revision_sequence must be non-negative")
        if self.revision_sequence == 0 and self.plan_revision_id:
            raise PlanningContractError("draft revision cannot carry a durable id")
        if self.revision_sequence > 0 and not self.plan_revision_id:
            raise PlanningContractError("persisted revision requires a durable id")
        if self.parent_revision_id is not None:
            _text(self.parent_revision_id, label="parent_revision_id")
        _text(self.task_id, label="task_id")
        _text(self.principal_id, label="principal_id")
        _text(self.project_id, label="project_id", allow_empty=True)
        for name in (
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "context_bundle_id",
            "repository_generation",
            "index_generation",
            "planner_algorithm_version",
        ):
            _text(getattr(self, name), label=name)
        _digest(self.goal_spec_digest, label="goal_spec_digest")
        _digest(self.context_bundle_digest, label="context_bundle_digest")
        _digest(self.context_request_digest, label="context_request_digest")
        _digest(self.planning_input_digest, label="planning_input_digest")
        if self.base_revision is not None:
            _text(self.base_revision, label="base_revision")
        if type(self.context_freshness) is not ContextFreshness:
            raise PlanningContractError("context_freshness must be a ContextFreshness")
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise PlanningContractError("cognitive_state must be an AgentCognitiveState")
        if type(self.control_state_version) is not int or self.control_state_version < 0:
            raise PlanningContractError("control_state_version must be non-negative")
        _text(self.task_status, label="task_status")
        if type(self.planner_schema_version) is not int or self.planner_schema_version < 1:
            raise PlanningContractError("planner_schema_version must be positive")
        if type(self.disposition) is not PlanDisposition:
            raise PlanningContractError("disposition must be a PlanDisposition")
        if (
            self.disposition is PlanDisposition.READY
            and self.context_freshness is not ContextFreshness.FRESH
        ):
            raise PlanningContractError(
                "READY plan revisions require a fresh context snapshot"
            )
        if self.disposition is PlanDisposition.READY and not self.steps:
            raise PlanningContractError(
                "READY plan revisions require at least one plan step"
            )
        _text(self.summary, label="summary", limit=_MAX_TEXT)
        steps = _typed_tuple(self.steps, label="steps", item_type=PlanningStep)
        step_ids = [item.step_id for item in steps]
        if len(step_ids) != len(set(step_ids)):
            raise PlanningContractError("step_id values must be unique")
        object.__setattr__(self, "steps", tuple(sorted(steps, key=lambda item: item.step_id)))
        _validate_step_graph(steps)
        for name, item_type in (
            ("affected_files", PlanningAffectedFile),
            ("affected_symbols", PlanningAffectedSymbol),
            ("dependency_impacts", PlanningDependencyImpact),
            ("verification_intents", PlanningVerificationIntent),
            ("risks", PlanningRisk),
            ("diagnostics", PlanningDiagnostic),
            ("evidence", PlanningEvidenceRef),
        ):
            values = _typed_tuple(getattr(self, name), label=name, item_type=item_type)
            if name == "affected_files":
                values = tuple(sorted(values, key=lambda item: item.path))
            elif name == "affected_symbols":
                values = tuple(sorted(values, key=lambda item: (item.relative_path, item.qualified_name, item.symbol_id)))
            elif name == "dependency_impacts":
                values = tuple(sorted(values, key=lambda item: (item.source, item.target, item.relation, item.status)))
            elif name == "verification_intents":
                values = tuple(sorted(values, key=lambda item: (item.verification_type, item.scope, item.command or ())))
            elif name == "risks":
                values = tuple(sorted(values, key=lambda item: (item.level.value, item.category, item.affected_scope)))
            elif name == "diagnostics":
                values = tuple(sorted(values, key=lambda item: (item.code, item.message)))
            else:
                values = tuple(sorted(values, key=_stable_evidence_key))
            object.__setattr__(self, name, values)
        if type(self.created_at) is not str:
            raise PlanningContractError("created_at must be a string")
        if self.created_at:
            _text(self.created_at, label="created_at", limit=128)
        if type(self.plan_semantic_digest) is not str:
            raise PlanningContractError("plan_semantic_digest must be a string")
        expected = canonical_digest(_revision_semantic_payload(self))
        if self.plan_semantic_digest:
            _digest(self.plan_semantic_digest, label="plan_semantic_digest")
            if self.plan_semantic_digest != expected:
                raise PlanningContractError("plan_semantic_digest does not match semantics")
        else:
            object.__setattr__(self, "plan_semantic_digest", expected)

    @property
    def plan_digest(self) -> str:
        """Short compatibility alias for consumers using plan terminology."""
        return self.plan_semantic_digest

    def semantic_payload(self) -> dict[str, object]:
        """Return the deterministic semantic payload covered by the digest."""
        return _revision_semantic_payload(self)

    def canonical_payload(self) -> dict[str, object]:
        """Return the complete bounded storage representation."""
        return {
            **self.semantic_payload(),
            "plan_revision_id": self.plan_revision_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "revision_sequence": self.revision_sequence,
            "parent_revision_id": self.parent_revision_id,
            "created_at": self.created_at,
            "plan_semantic_digest": self.plan_semantic_digest,
        }

    def canonical_json(self) -> str:
        """Serialize the complete revision in the shared canonical format."""
        return canonical_json_bytes(self.canonical_payload()).decode("utf-8")


def _validate_step_graph(steps: tuple[PlanningStep, ...]) -> None:
    """Validate the closed dependency graph carried by one plan revision.

    The legacy planner validator remains the adapter's first line of defense,
    but the durable contract also validates direct callers and decoded rows.
    This keeps a plan revision from becoming an appendable representation of
    a missing-node, self-referential, duplicate, or cyclic execution graph.
    """
    step_by_id = {step.step_id: step for step in steps}
    if len(step_by_id) != len(steps):
        raise PlanningContractError("step_id values must be unique")
    for step in steps:
        missing = sorted(
            dependency
            for dependency in step.dependencies
            if dependency not in step_by_id
        )
        if missing:
            raise PlanningContractError(
                "plan step dependency is missing: " + ",".join(missing)
            )

    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(step_id: str) -> None:
        if step_id in visiting:
            raise PlanningContractError("plan steps contain a dependency cycle")
        if step_id in visited:
            return
        visiting.add(step_id)
        for dependency in step_by_id[step_id].dependencies:
            visit(dependency)
        visiting.remove(step_id)
        visited.add(step_id)

    for step_id in sorted(step_by_id):
        visit(step_id)


def _require_object(value: object, *, label: str) -> dict[str, object]:
    if type(value) is not dict:
        raise PlanningContractError(f"{label} must be an object")
    return value


def _require_list(value: object, *, label: str) -> list[object]:
    """Require a JSON array at the canonical decoding boundary."""
    if type(value) is not list:
        raise PlanningContractError(f"{label} must be an array")
    return value


def _require_string_list(value: object, *, label: str) -> tuple[str, ...]:
    """Require a JSON array whose entries are strings."""
    values = _require_list(value, label=label)
    result: list[str] = []
    for item in values:
        if type(item) is not str:
            raise PlanningContractError(f"{label} must contain strings")
        result.append(item)
    return tuple(result)


def _require_keys(value: dict[str, object], *, label: str, keys: frozenset[str]) -> None:
    if set(value) != keys:
        raise PlanningContractError(f"{label} has an invalid schema")


def _decode_evidence(value: object) -> PlanningEvidenceRef:
    raw = _require_object(value, label="evidence")
    _require_keys(raw, label="evidence", keys=frozenset({"kind", "ref_id", "digest", "relative_path", "symbol_id"}))
    try:
        kind = PlanningEvidenceKind(raw["kind"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanningContractError("invalid planning evidence kind") from exc
    return PlanningEvidenceRef(
        kind=kind,
        ref_id=raw["ref_id"],  # type: ignore[arg-type]
        digest=raw["digest"],  # type: ignore[arg-type]
        relative_path=raw["relative_path"],  # type: ignore[arg-type]
        symbol_id=raw["symbol_id"],  # type: ignore[arg-type]
    )


def _decode_risk(value: object) -> PlanningRisk:
    raw = _require_object(value, label="risk")
    _require_keys(raw, label="risk", keys=frozenset({"level", "category", "description", "affected_scope", "mitigation", "requires_approval"}))
    try:
        level = PlanningRiskLevel(raw["level"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanningContractError("invalid planning risk level") from exc
    return PlanningRisk(
        level=level,
        category=raw["category"],  # type: ignore[arg-type]
        description=raw["description"],  # type: ignore[arg-type]
        affected_scope=_require_string_list(
            raw["affected_scope"], label="affected_scope"
        ),
        mitigation=raw["mitigation"],  # type: ignore[arg-type]
        requires_approval=raw["requires_approval"],  # type: ignore[arg-type]
    )


def _decode_verification(value: object) -> PlanningVerificationIntent:
    raw = _require_object(value, label="verification intent")
    _require_keys(raw, label="verification intent", keys=frozenset({"verification_type", "scope", "expected_result", "required", "risk_level", "command", "evidence"}))
    try:
        level = PlanningRiskLevel(raw["risk_level"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanningContractError("invalid verification risk level") from exc
    command = raw["command"]
    if command is not None:
        command = _require_string_list(command, label="command")
    return PlanningVerificationIntent(
        verification_type=raw["verification_type"],  # type: ignore[arg-type]
        scope=raw["scope"],  # type: ignore[arg-type]
        expected_result=raw["expected_result"],  # type: ignore[arg-type]
        required=raw["required"],  # type: ignore[arg-type]
        risk_level=level,
        command=command,  # type: ignore[arg-type]
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
    )


def _decode_diagnostic(value: object) -> PlanningDiagnostic:
    raw = _require_object(value, label="diagnostic")
    _require_keys(raw, label="diagnostic", keys=frozenset({"code", "severity", "message", "recoverable", "evidence"}))
    return PlanningDiagnostic(
        code=raw["code"],  # type: ignore[arg-type]
        severity=raw["severity"],  # type: ignore[arg-type]
        message=raw["message"],  # type: ignore[arg-type]
        recoverable=raw["recoverable"],  # type: ignore[arg-type]
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
    )


def _decode_step(value: object) -> PlanningStep:
    raw = _require_object(value, label="step")
    _require_keys(raw, label="step", keys=frozenset({"step_id", "title", "description", "operation", "target_files", "target_symbols", "dependencies", "expected_outcome", "verification_requirements", "risk", "requires_approval", "evidence"}))
    try:
        operation = PlanOperation(raw["operation"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanningContractError("invalid plan step operation") from exc
    return PlanningStep(
        step_id=raw["step_id"],  # type: ignore[arg-type]
        title=raw["title"],  # type: ignore[arg-type]
        description=raw["description"],  # type: ignore[arg-type]
        operation=operation,
        target_files=_require_string_list(raw["target_files"], label="target_files"),
        target_symbols=_require_string_list(
            raw["target_symbols"], label="target_symbols"
        ),
        dependencies=_require_string_list(
            raw["dependencies"], label="dependencies"
        ),
        expected_outcome=raw["expected_outcome"],  # type: ignore[arg-type]
        verification_requirements=tuple(
            _decode_verification(item)
            for item in _require_list(
                raw["verification_requirements"], label="verification_requirements"
            )
        ),
        risk=_decode_risk(raw["risk"]),
        requires_approval=raw["requires_approval"],  # type: ignore[arg-type]
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
    )


def _decode_affected_file(value: object) -> PlanningAffectedFile:
    raw = _require_object(value, label="affected file")
    _require_keys(raw, label="affected file", keys=frozenset({"path", "operation", "reason", "confidence", "exists", "language", "evidence", "destination_path"}))
    try:
        operation = PlanOperation(raw["operation"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PlanningContractError("invalid affected-file operation") from exc
    return PlanningAffectedFile(
        path=raw["path"],  # type: ignore[arg-type]
        operation=operation,
        reason=raw["reason"],  # type: ignore[arg-type]
        confidence=raw["confidence"],  # type: ignore[arg-type]
        exists=raw["exists"],  # type: ignore[arg-type]
        language=raw["language"],  # type: ignore[arg-type]
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
        destination_path=raw["destination_path"],  # type: ignore[arg-type]
    )


def _decode_affected_symbol(value: object) -> PlanningAffectedSymbol:
    raw = _require_object(value, label="affected symbol")
    _require_keys(raw, label="affected symbol", keys=frozenset({"symbol_id", "relative_path", "language", "qualified_name", "kind", "evidence"}))
    return PlanningAffectedSymbol(
        symbol_id=raw["symbol_id"],  # type: ignore[arg-type]
        relative_path=raw["relative_path"],  # type: ignore[arg-type]
        language=raw["language"],  # type: ignore[arg-type]
        qualified_name=raw["qualified_name"],  # type: ignore[arg-type]
        kind=raw["kind"],  # type: ignore[arg-type]
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
    )


def _decode_dependency(value: object) -> PlanningDependencyImpact:
    raw = _require_object(value, label="dependency impact")
    _require_keys(raw, label="dependency impact", keys=frozenset({"source", "target", "relation", "status", "reason"}))
    return PlanningDependencyImpact(
        source=raw["source"],  # type: ignore[arg-type]
        target=raw["target"],  # type: ignore[arg-type]
        relation=raw["relation"],  # type: ignore[arg-type]
        status=raw["status"],  # type: ignore[arg-type]
        reason=raw["reason"],  # type: ignore[arg-type]
    )


def _decode_revision(raw: dict[str, object]) -> PlanRevision:
    _require_keys(
        raw,
        label="plan revision",
        keys=frozenset(
            {
                "schema_version",
                "task_id",
                "goal_spec_id",
                "goal_spec_digest",
                "workspace_id",
                "repository_id",
                "base_revision",
                "context_bundle_id",
                "context_bundle_digest",
                "context_request_digest",
                "repository_generation",
                "index_generation",
                "context_freshness",
                "cognitive_state",
                "control_state_version",
                "task_status",
                "planner_schema_version",
                "planner_algorithm_version",
                "planning_input_digest",
                "disposition",
                "summary",
                "steps",
                "affected_files",
                "affected_symbols",
                "dependency_impacts",
                "verification_intents",
                "risks",
                "diagnostics",
                "evidence",
                "plan_revision_id",
                "principal_id",
                "project_id",
                "revision_sequence",
                "parent_revision_id",
                "created_at",
                "plan_semantic_digest",
            }
        ),
    )
    try:
        freshness = ContextFreshness(raw["context_freshness"])
        cognitive_state = AgentCognitiveState.parse(raw["cognitive_state"])  # type: ignore[arg-type]
        disposition = PlanDisposition(raw["disposition"])
    except (TypeError, ValueError) as exc:
        raise PlanningContractError("invalid plan revision enum") from exc
    return PlanRevision(
        schema_version=raw["schema_version"],  # type: ignore[arg-type]
        plan_revision_id=raw["plan_revision_id"],  # type: ignore[arg-type]
        task_id=raw["task_id"],  # type: ignore[arg-type]
        principal_id=raw["principal_id"],  # type: ignore[arg-type]
        project_id=raw["project_id"],  # type: ignore[arg-type]
        revision_sequence=raw["revision_sequence"],  # type: ignore[arg-type]
        parent_revision_id=raw["parent_revision_id"],  # type: ignore[arg-type]
        goal_spec_id=raw["goal_spec_id"],  # type: ignore[arg-type]
        goal_spec_digest=raw["goal_spec_digest"],  # type: ignore[arg-type]
        workspace_id=raw["workspace_id"],  # type: ignore[arg-type]
        repository_id=raw["repository_id"],  # type: ignore[arg-type]
        base_revision=raw["base_revision"],  # type: ignore[arg-type]
        context_bundle_id=raw["context_bundle_id"],  # type: ignore[arg-type]
        context_bundle_digest=raw["context_bundle_digest"],  # type: ignore[arg-type]
        context_request_digest=raw["context_request_digest"],  # type: ignore[arg-type]
        repository_generation=raw["repository_generation"],  # type: ignore[arg-type]
        index_generation=raw["index_generation"],  # type: ignore[arg-type]
        context_freshness=freshness,
        cognitive_state=cognitive_state,
        control_state_version=raw["control_state_version"],  # type: ignore[arg-type]
        task_status=raw["task_status"],  # type: ignore[arg-type]
        planner_schema_version=raw["planner_schema_version"],  # type: ignore[arg-type]
        planner_algorithm_version=raw["planner_algorithm_version"],  # type: ignore[arg-type]
        planning_input_digest=raw["planning_input_digest"],  # type: ignore[arg-type]
        disposition=disposition,
        summary=raw["summary"],  # type: ignore[arg-type]
        steps=tuple(
            _decode_step(item)
            for item in _require_list(raw["steps"], label="steps")
        ),
        affected_files=tuple(
            _decode_affected_file(item)
            for item in _require_list(raw["affected_files"], label="affected_files")
        ),
        affected_symbols=tuple(
            _decode_affected_symbol(item)
            for item in _require_list(raw["affected_symbols"], label="affected_symbols")
        ),
        dependency_impacts=tuple(
            _decode_dependency(item)
            for item in _require_list(
                raw["dependency_impacts"], label="dependency_impacts"
            )
        ),
        verification_intents=tuple(
            _decode_verification(item)
            for item in _require_list(
                raw["verification_intents"], label="verification_intents"
            )
        ),
        risks=tuple(
            _decode_risk(item)
            for item in _require_list(raw["risks"], label="risks")
        ),
        diagnostics=tuple(
            _decode_diagnostic(item)
            for item in _require_list(raw["diagnostics"], label="diagnostics")
        ),
        evidence=tuple(
            _decode_evidence(item)
            for item in _require_list(raw["evidence"], label="evidence")
        ),
        plan_semantic_digest=raw["plan_semantic_digest"],  # type: ignore[arg-type]
        created_at=raw["created_at"],  # type: ignore[arg-type]
    )


def plan_revision_from_canonical_json(
    value: str,
    *,
    expected_digest: str | None = None,
) -> PlanRevision:
    """Decode one strict canonical plan revision from durable storage."""
    if type(value) is not str:
        raise PlanningContractError("canonical plan revision must be text")
    try:
        raw_value = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise PlanningContractError("canonical plan revision JSON is malformed") from exc
    raw = _require_object(raw_value, label="plan revision")
    revision = _decode_revision(raw)
    if expected_digest is not None and revision.plan_semantic_digest != expected_digest:
        raise PlanningContractError("durable plan revision digest mismatch")
    return revision


__all__ = [
    "PLANNER_ALGORITHM_VERSION",
    "PLANNING_SCHEMA_VERSION",
    "PlanDisposition",
    "PlanRevision",
    "PlanningAffectedFile",
    "PlanningAffectedSymbol",
    "PlanningContractError",
    "PlanningDependencyImpact",
    "PlanningDiagnostic",
    "PlanningEvidenceKind",
    "PlanningEvidenceRef",
    "PlanningInput",
    "PlanningRisk",
    "PlanningRiskLevel",
    "PlanningStep",
    "PlanningVerificationIntent",
    "plan_revision_from_canonical_json",
]
