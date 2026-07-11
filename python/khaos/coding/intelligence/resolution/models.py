"""Conservative repository-level semantic resolution models.

All resolution results distinguish: resolved, ambiguous, unresolved, external, dynamic, invalid.
A ``resolved`` result must have deterministic, reproducible evidence — never a guess.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ResolutionStatus(str, Enum):
    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    UNRESOLVED = "unresolved"
    EXTERNAL = "external"
    DYNAMIC = "dynamic"
    INVALID = "invalid"


@dataclass(frozen=True)
class RepositorySymbol:
    """Stable repository-level symbol with deterministic ID."""

    symbol_id: str
    repository_id: str
    path: str
    language: str
    kind: str
    name: str
    qualified_name: str
    byte_start: int
    byte_end: int
    start_line: int
    generation: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "symbol_id": self.symbol_id,
            "repository_id": self.repository_id,
            "path": self.path,
            "language": self.language,
            "kind": self.kind,
            "name": self.name,
            "qualified_name": self.qualified_name,
            "byte_start": self.byte_start,
            "byte_end": self.byte_end,
            "start_line": self.start_line,
            "generation": self.generation,
        }


@dataclass(frozen=True)
class ResolvedImport:
    source_file: str
    import_module: str
    imported_name: str  # empty string for whole-module import
    alias: str | None
    status: ResolutionStatus
    target_file: str | None
    target_symbol_id: str | None
    confidence: float
    reason: str
    candidate_targets: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "import_module": self.import_module,
            "imported_name": self.imported_name,
            "alias": self.alias,
            "status": self.status.value,
            "target_file": self.target_file,
            "target_symbol_id": self.target_symbol_id,
            "confidence": self.confidence,
            "reason": self.reason,
            "candidate_targets": list(self.candidate_targets),
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ResolvedCallEdge:
    edge_id: str
    source_file: str
    caller_symbol_id: str | None
    call_callee: str
    status: ResolutionStatus
    target_symbol_id: str | None
    target_file: str | None
    confidence: float
    resolution_rule: str
    ambiguity_reason: str | None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_file": self.source_file,
            "caller_symbol_id": self.caller_symbol_id,
            "call_callee": self.call_callee,
            "status": self.status.value,
            "target_symbol_id": self.target_symbol_id,
            "target_file": self.target_file,
            "confidence": self.confidence,
            "resolution_rule": self.resolution_rule,
            "ambiguity_reason": self.ambiguity_reason,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ResolvedReferenceEdge:
    edge_id: str
    source_file: str
    name: str
    reference_kind: str
    status: ResolutionStatus
    target_symbol_id: str | None
    target_file: str | None
    confidence: float
    resolution_rule: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_file": self.source_file,
            "name": self.name,
            "reference_kind": self.reference_kind,
            "status": self.status.value,
            "target_symbol_id": self.target_symbol_id,
            "target_file": self.target_file,
            "confidence": self.confidence,
            "resolution_rule": self.resolution_rule,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ResolutionDiagnostic:
    source_file: str
    code: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_file": self.source_file,
            "code": self.code,
            "severity": self.severity,
            "message": self.message,
        }


@dataclass(frozen=True)
class FileResolutionResult:
    """Per-file resolution output."""

    source_file: str
    generation: int
    symbols: tuple[RepositorySymbol, ...]
    resolved_imports: tuple[ResolvedImport, ...]
    resolved_calls: tuple[ResolvedCallEdge, ...]
    resolved_references: tuple[ResolvedReferenceEdge, ...]
    diagnostics: tuple[ResolutionDiagnostic, ...] = ()


@dataclass
class RepositoryResolutionReport:
    repository_id: str
    resolved_files: list[str] = field(default_factory=list)
    symbol_count: int = 0
    import_count: int = 0
    call_count: int = 0
    reference_count: int = 0
    resolved_imports: int = 0
    resolved_calls: int = 0
    resolved_references: int = 0
    ambiguous_count: int = 0
    unresolved_count: int = 0
    external_count: int = 0
    dynamic_count: int = 0
    invalid_count: int = 0
    diagnostics: list[ResolutionDiagnostic] = field(default_factory=list)
    affected_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    total_duration_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "repository_id": self.repository_id,
            "resolved_files": self.resolved_files,
            "symbol_count": self.symbol_count,
            "import_count": self.import_count,
            "call_count": self.call_count,
            "reference_count": self.reference_count,
            "resolved_imports": self.resolved_imports,
            "resolved_calls": self.resolved_calls,
            "resolved_references": self.resolved_references,
            "ambiguous_count": self.ambiguous_count,
            "unresolved_count": self.unresolved_count,
            "external_count": self.external_count,
            "dynamic_count": self.dynamic_count,
            "invalid_count": self.invalid_count,
            "diagnostics": [d.to_dict() for d in self.diagnostics],
            "affected_files": self.affected_files,
            "skipped_files": self.skipped_files,
            "total_duration_ms": self.total_duration_ms,
        }
