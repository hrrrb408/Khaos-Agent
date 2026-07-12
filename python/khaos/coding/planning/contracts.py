"""Immutable, deterministic contracts for read-only implementation planning."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Protocol


class PlanStatus(str, Enum):
    DRAFT = "draft"; READY = "ready"; BLOCKED = "blocked"; STALE = "stale"
    APPROVED = "approved"; REJECTED = "rejected"; EXECUTING = "executing"
    COMPLETED = "completed"; FAILED = "failed"


class PlanOperation(str, Enum):
    INSPECT = "inspect"; MODIFY = "modify"; CREATE = "create"; DELETE = "delete"
    RENAME = "rename"; TEST = "test"; DOCUMENT = "document"; CONFIGURE = "configure"; UNKNOWN = "unknown"


@dataclass(frozen=True)
class PlanEvidence:
    source: str; repository_id: str; path: str | None = None; symbol_id: str | None = None
    generation: int | None = None; content_hash: str | None = None; query: str = ""
    confidence: float = 0.0; metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class AffectedFile:
    path: str; operation: PlanOperation; reason: str; confidence: float; exists: bool
    language: str | None; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class AffectedSymbol:
    stable_symbol_id: str | None; qualified_name: str; kind: str; path: str
    impact_type: str; confidence: float; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class DependencyImpact:
    source: str; target: str; relation: str; status: str; confidence: float; reason: str

@dataclass(frozen=True)
class VerificationRequirement:
    command: tuple[str, ...] | None; verification_type: str; scope: str; expected_result: str
    required: bool; risk_level: str; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class RiskAssessment:
    level: str; category: str; description: str; affected_scope: tuple[str, ...]
    mitigation: str; requires_approval: bool

@dataclass(frozen=True)
class PlanDiagnostic:
    code: str; severity: str; message: str; recoverable: bool; evidence: tuple[PlanEvidence, ...] = ()

@dataclass(frozen=True)
class PlanStep:
    step_id: str; title: str; description: str; operation: PlanOperation
    target_files: tuple[str, ...]; target_symbols: tuple[str, ...]; depends_on: tuple[str, ...]
    expected_outcome: str; verification_requirements: tuple[VerificationRequirement, ...]
    risk: RiskAssessment; requires_approval: bool; evidence: tuple[PlanEvidence, ...]

@dataclass(frozen=True)
class ImplementationPlan:
    plan_id: str; repository_id: str; task_id: str; workspace_id: str; user_goal: str; normalized_goal: str
    base_sha: str; repository_generation: int; status: PlanStatus; summary: str
    steps: tuple[PlanStep, ...]; affected_files: tuple[AffectedFile, ...] = ()
    affected_symbols: tuple[AffectedSymbol, ...] = (); dependency_impacts: tuple[DependencyImpact, ...] = ()
    verification_requirements: tuple[VerificationRequirement, ...] = (); risks: tuple[RiskAssessment, ...] = ()
    diagnostics: tuple[PlanDiagnostic, ...] = (); evidence: tuple[PlanEvidence, ...] = ()
    content_hash: str = ""; created_at: float = 0.0

    @staticmethod
    def digest(payload: dict[str, Any]) -> str:
        return hashlib.sha256(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

@dataclass(frozen=True)
class PlanValidationResult:
    valid: bool; status: PlanStatus; diagnostics: tuple[PlanDiagnostic, ...] = ()


class PlanningService(Protocol):
    def plan(self, *, repository_id: str, task_id: str, workspace_id: str, user_goal: str, base_sha: str) -> ImplementationPlan: ...
    def validate_plan(self, plan: ImplementationPlan, *, current_head: str, current_repository_generation: int) -> PlanValidationResult: ...
