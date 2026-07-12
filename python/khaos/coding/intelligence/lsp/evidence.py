"""Semantic evidence and fused resolution models for optional LSP enrichment.

These models are additive — they do NOT modify the existing
``ResolvedCallEdge``, ``ResolvedReferenceEdge``, or ``ParseResult`` types.
LSP evidence is short-lived and never silently overwrites repository
resolution results.

Fusion ordering (per spec):
    Tree-sitter candidate
    → Repository conservative resolution
    → optional LSP evidence
    → fused result

A ``FusedResolution`` always preserves every contributing ``SemanticEvidence``
so callers can audit how a status was reached. Conflicts are marked
``ambiguous`` or ``conflicting`` — never silently resolved.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceSource(str, Enum):
    """Provenance of a piece of semantic evidence."""

    TREE_SITTER = "tree-sitter"
    REPOSITORY_RESOLUTION = "repository-resolution"
    LSP_DEFINITION = "lsp-definition"
    LSP_REFERENCES = "lsp-references"


class EvidenceType(str, Enum):
    """What kind of semantic fact the evidence represents."""

    DEFINITION = "definition"
    REFERENCE = "reference"
    SYMBOL = "symbol"


class FusionRule(str, Enum):
    """Why a fused status was chosen. Mirrors the spec's resolution rules."""

    REPOSITORY_ONLY = "repository-only"
    LSP_CONFIRMED = "lsp-confirmed"
    LSP_PROMOTED = "lsp-promoted"
    LSP_CONFLICT = "lsp-conflict"
    LSP_AMBIGUOUS = "lsp-ambiguous"
    LSP_EXTERNAL = "lsp-external"
    LSP_UNAVAILABLE = "lsp-unavailable"
    LSP_STALE = "lsp-stale"


@dataclass(frozen=True)
class SemanticEvidence:
    """A single piece of semantic evidence from a named source.

    ``target_range`` is a 4-tuple of code-point columns:
    ``(start_line, start_column, end_line, end_column)`` — zero-based,
    matching :class:`SourceLocation`. It is ``None`` when the evidence
    does not pin a byte range (e.g. an LSP server that returned only a
    symbol id).
    """

    source: EvidenceSource
    evidence_type: EvidenceType
    target_file: str | None
    target_range: tuple[int, int, int, int] | None
    target_symbol_id: str | None
    confidence: float
    server_name: str | None = None
    server_version: str | None = None
    document_version: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.value,
            "evidence_type": self.evidence_type.value,
            "target_file": self.target_file,
            "target_range": list(self.target_range) if self.target_range else None,
            "target_symbol_id": self.target_symbol_id,
            "confidence": self.confidence,
            "server_name": self.server_name,
            "server_version": self.server_version,
            "document_version": self.document_version,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class FusedResolution:
    """Result of fusing repository resolution with optional LSP evidence.

    ``original_status`` is the repository resolution status before fusion.
    ``fused_status`` is the status after applying LSP evidence (which may
    be identical when LSP is unavailable or confirms the repository result).

    ``evidence`` always contains at least one entry (the repository
    resolution itself). When ``depends_on_lsp`` is True, the fused status
    was influenced by LSP evidence.
    """

    original_status: str
    fused_status: str
    target_symbol_id: str | None
    target_file: str | None
    confidence: float
    evidence: tuple[SemanticEvidence, ...]
    conflict_reason: str | None
    resolution_rule: str
    depends_on_lsp: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_status": self.original_status,
            "fused_status": self.fused_status,
            "target_symbol_id": self.target_symbol_id,
            "target_file": self.target_file,
            "confidence": self.confidence,
            "evidence": [e.to_dict() for e in self.evidence],
            "conflict_reason": self.conflict_reason,
            "resolution_rule": self.resolution_rule,
            "depends_on_lsp": self.depends_on_lsp,
        }


@dataclass(frozen=True)
class EvidenceCacheKey:
    """Staleness-bound key for LSP evidence cache entries.

    An evidence entry is only valid while ALL of these match:
    - repository_id / workspace_id (workspace binding)
    - file_path (candidate source file for definitions; target file for references)
    - content_hash (file bytes)
    - file_generation (IndexStore generation)
    - document_version (LSP document version)
    - candidate_range (byte range of the call/reference candidate; or
      target definition byte range for references)
    - server_identity (LSP server name + version)
    - target_symbol_id (for references cache: the target symbol's stable ID.
      ``None`` for definition cache entries.)

    For references cache entries, ``file_path`` / ``content_hash`` /
    ``file_generation`` bind the TARGET file's state, and
    ``target_symbol_id`` binds the specific symbol being queried.
    Different symbols in the same file produce different cache keys.
    """

    repository_id: str
    workspace_id: str
    file_path: str
    content_hash: str
    file_generation: int
    document_version: int
    candidate_range: tuple[int, int]
    server_identity: str
    target_symbol_id: str | None = None


@dataclass(frozen=True)
class EvidenceCacheEntry:
    """A cached LSP evidence result with a creation timestamp for TTL."""

    evidence: tuple[SemanticEvidence, ...]
    created_at: float
    server_identity: str
