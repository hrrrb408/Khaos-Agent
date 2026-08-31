"""Immutable contracts for workspace-bound engineering context.

The context layer is deliberately an evidence projection, not an authority
layer.  A :class:`ContextBundle` can identify files and symbols that appear
relevant to a goal, but it cannot grant filesystem, tool, approval,
verification, or completion authority.

The value objects in this module contain only typed scalar values and tuples
of typed value objects.  JSON dictionaries are constructed only at the
serialization boundary used for deterministic digests; they are never the
canonical in-memory contract.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath

from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

CONTEXT_SCHEMA_VERSION = 1
CONTEXT_INDEX_SCHEMA_VERSION = "m7.2-context-index-v1"
CONTEXT_PARSER_VERSION = "language-registry-v1"
_MAX_ID_LENGTH = 512
_MAX_QUERY_LENGTH = 16 * 1024
_MAX_CONTENT_BYTES = 4 * 1024 * 1024
_MAX_REASON_LENGTH = 256
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_PROTECTED_NAMES = frozenset({".git", ".agents", ".codex", ".khaos"})


class ContextContractError(ValueError):
    """Raised when a context request, document, or bundle is malformed."""


class ContextQueryReason(str, Enum):
    """Why a context retrieval was requested."""

    USER_GOAL = "user_goal"
    EXPLICIT_TARGET = "explicit_target"
    SYMBOL_REFERENCE = "symbol_reference"
    CURRENT_PLAN_STEP = "current_plan_step"
    FAILURE_DIAGNOSIS = "failure_diagnosis"
    REFRESH = "refresh"


class ContextFreshness(str, Enum):
    """Freshness of a bundle relative to its bound workspace snapshot."""

    FRESH = "fresh"
    STALE = "stale"
    MIXED_GENERATION = "mixed_generation"
    UNAVAILABLE = "unavailable"


class ContextSourceKind(str, Enum):
    """Bounded source provenance for a context item."""

    WORKSPACE_SNAPSHOT = "workspace_snapshot"
    PARSER = "parser"
    INDEX = "index"
    LSP = "lsp"


class ContextEvidenceKind(str, Enum):
    """Kinds of non-authoritative repository evidence."""

    FILE_CONTENT = "file_content"
    SYMBOL_DEFINITION = "symbol_definition"
    SYMBOL_REFERENCE = "symbol_reference"
    CALLER = "caller"
    CALLEE = "callee"
    IMPORT = "import"
    REVERSE_IMPORT = "reverse_import"
    RELATED_TEST = "related_test"
    REPOSITORY_CONFIG = "repository_config"
    LEXICAL_SEARCH = "lexical_search"
    STRUCTURAL_SEARCH = "structural_search"
    LSP = "lsp"


def _require_text(
    value: object,
    *,
    label: str,
    allow_empty: bool = False,
    max_length: int = _MAX_ID_LENGTH,
) -> str:
    if type(value) is not str or (not allow_empty and not value):
        raise ContextContractError(f"{label} must be a string")
    if len(value) > max_length:
        raise ContextContractError(f"{label} exceeds its bound")
    if "\x00" in value:
        raise ContextContractError(f"{label} contains a NUL byte")
    return value


def normalize_relative_path(value: str, *, label: str = "relative_path") -> str:
    """Validate and normalize one workspace-relative POSIX path."""
    _require_text(value, label=label)
    candidate = PurePosixPath(value.replace("\\", "/"))
    if candidate.is_absolute() or not candidate.parts:
        raise ContextContractError(f"{label} must be workspace-relative")
    if any(part in {"", ".", ".."} for part in candidate.parts):
        raise ContextContractError(f"{label} is not normalized")
    if any(part.casefold() in _PROTECTED_NAMES for part in candidate.parts):
        raise ContextContractError(f"{label} reaches protected metadata")
    return candidate.as_posix()


def _require_digest(value: object, *, label: str, allow_none: bool = False) -> str | None:
    if value is None and allow_none:
        return None
    if type(value) is not str or not _HEX_DIGEST.fullmatch(value):
        raise ContextContractError(f"{label} must be a SHA-256 hex digest")
    return value


def _require_tuple(value: object, *, label: str) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise ContextContractError(f"{label} must be a tuple")
    return value


def _typed_tuple(
    value: object,
    *,
    label: str,
    item_type: type[object],
) -> tuple[object, ...]:
    values = _require_tuple(value, label=label)
    if any(type(item) is not item_type for item in values):
        raise ContextContractError(f"{label} contains an invalid typed value")
    return values


@dataclass(frozen=True, slots=True)
class ContextTarget:
    """One explicit file or symbol target supplied to a context request."""

    relative_path: str | None = None
    symbol: str | None = None
    symbol_kind: str | None = None
    language: str | None = None

    def __post_init__(self) -> None:
        if self.relative_path is None and self.symbol is None:
            raise ContextContractError("ContextTarget needs a path or symbol")
        if self.relative_path is not None:
            object.__setattr__(
                self,
                "relative_path",
                normalize_relative_path(self.relative_path),
            )
        if self.symbol is not None:
            _require_text(self.symbol, label="symbol")
        if self.symbol_kind is not None:
            _require_text(self.symbol_kind, label="symbol_kind")
        if self.language is not None:
            _require_text(self.language, label="language")


@dataclass(frozen=True, slots=True)
class ContextEvidence:
    """A bounded reference to repository evidence.

    Evidence references are descriptive only.  In particular, no trust or
    authority flag is represented here; the owning subsystem must decide
    whether a reference is suitable for a later policy decision.
    """

    kind: ContextEvidenceKind
    ref_id: str
    subject_path: str | None = None
    digest: str | None = None
    generation: str = ""

    def __post_init__(self) -> None:
        if type(self.kind) is not ContextEvidenceKind:
            raise ContextContractError("kind must be a ContextEvidenceKind")
        _require_text(self.ref_id, label="ref_id")
        if self.subject_path is not None:
            object.__setattr__(
                self,
                "subject_path",
                normalize_relative_path(self.subject_path, label="subject_path"),
            )
        _require_digest(self.digest, label="digest", allow_none=True)
        _require_text(self.generation, label="generation", allow_empty=True)


@dataclass(frozen=True, slots=True)
class ContextSymbol:
    """A generation-bound symbol identity extracted from one file."""

    symbol_id: str
    relative_path: str
    language: str
    qualified_name: str
    kind: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    byte_start: int
    byte_end: int
    content_digest: str
    index_generation: str
    evidence: tuple[ContextEvidence, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.symbol_id, label="symbol_id")
        object.__setattr__(
            self,
            "relative_path",
            normalize_relative_path(self.relative_path),
        )
        for name in ("language", "qualified_name", "kind", "index_generation"):
            _require_text(getattr(self, name), label=name)
        _require_digest(self.content_digest, label="content_digest")
        for name in (
            "start_line",
            "start_column",
            "end_line",
            "end_column",
            "byte_start",
            "byte_end",
        ):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContextContractError(f"{name} must be a non-negative integer")
        if self.byte_end < self.byte_start:
            raise ContextContractError("symbol byte range is inverted")
        values = _typed_tuple(
            self.evidence, label="evidence", item_type=ContextEvidence
        )
        object.__setattr__(self, "evidence", values)


@dataclass(frozen=True, slots=True)
class ContextDocument:
    """A bounded text excerpt tied to a workspace file snapshot."""

    relative_path: str
    language: str
    content: str
    content_digest: str
    file_size: int
    source_kind: ContextSourceKind
    workspace_id: str
    repository_id: str
    base_revision: str | None
    repository_generation: str
    index_generation: str
    excerpt_start: int = 0
    excerpt_end: int = 0
    truncated: bool = False
    relevance_score: int = 0
    evidence: tuple[ContextEvidence, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "relative_path",
            normalize_relative_path(self.relative_path),
        )
        for name in (
            "language",
            "workspace_id",
            "repository_id",
            "repository_generation",
            "index_generation",
        ):
            _require_text(getattr(self, name), label=name)
        _require_digest(self.content_digest, label="content_digest")
        if self.base_revision is not None:
            _require_text(self.base_revision, label="base_revision")
        if type(self.source_kind) is not ContextSourceKind:
            raise ContextContractError("source_kind must be a ContextSourceKind")
        if type(self.content) is not str:
            raise ContextContractError("content must be text")
        if len(self.content.encode("utf-8")) > _MAX_CONTENT_BYTES:
            raise ContextContractError("context document exceeds its content bound")
        for name in ("file_size", "excerpt_start", "excerpt_end", "relevance_score"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ContextContractError(f"{name} must be a non-negative integer")
        if self.excerpt_end < self.excerpt_start:
            raise ContextContractError("document excerpt range is inverted")
        if type(self.truncated) is not bool:
            raise ContextContractError("truncated must be a bool")
        values = _typed_tuple(
            self.evidence, label="evidence", item_type=ContextEvidence
        )
        object.__setattr__(self, "evidence", values)


def _target_payload(target: ContextTarget) -> dict[str, object]:
    return {
        "relative_path": target.relative_path,
        "symbol": target.symbol,
        "symbol_kind": target.symbol_kind,
        "language": target.language,
    }


def _evidence_payload(evidence: ContextEvidence) -> dict[str, object]:
    return {
        "kind": evidence.kind.value,
        "ref_id": evidence.ref_id,
        "subject_path": evidence.subject_path,
        "digest": evidence.digest,
        "generation": evidence.generation,
    }


def _symbol_payload(symbol: ContextSymbol) -> dict[str, object]:
    return {
        "symbol_id": symbol.symbol_id,
        "relative_path": symbol.relative_path,
        "language": symbol.language,
        "qualified_name": symbol.qualified_name,
        "kind": symbol.kind,
        "start_line": symbol.start_line,
        "start_column": symbol.start_column,
        "end_line": symbol.end_line,
        "end_column": symbol.end_column,
        "byte_start": symbol.byte_start,
        "byte_end": symbol.byte_end,
        "content_digest": symbol.content_digest,
        "index_generation": symbol.index_generation,
        "evidence": [
            _evidence_payload(item)
            for item in sorted(symbol.evidence, key=_evidence_sort_key)
        ],
    }


def _document_payload(document: ContextDocument) -> dict[str, object]:
    return {
        "relative_path": document.relative_path,
        "language": document.language,
        "content": document.content,
        "content_digest": document.content_digest,
        "file_size": document.file_size,
        "source_kind": document.source_kind.value,
        "workspace_id": document.workspace_id,
        "repository_id": document.repository_id,
        "base_revision": document.base_revision,
        "repository_generation": document.repository_generation,
        "index_generation": document.index_generation,
        "excerpt_start": document.excerpt_start,
        "excerpt_end": document.excerpt_end,
        "truncated": document.truncated,
        "relevance_score": document.relevance_score,
        "evidence": [
            _evidence_payload(item)
            for item in sorted(document.evidence, key=_evidence_sort_key)
        ],
    }


def _evidence_sort_key(item: ContextEvidence) -> tuple[str, str, str, str, str]:
    return (
        item.kind.value,
        item.ref_id,
        item.subject_path or "",
        item.digest or "",
        item.generation,
    )


def _request_payload(request: ContextRequest) -> dict[str, object]:
    return {
        "schema_version": request.schema_version,
        "task_id": request.task_id,
        "principal_id": request.principal_id,
        "project_id": request.project_id,
        "goal_spec_id": request.goal_spec_id,
        "goal_spec_digest": request.goal_spec_digest,
        "workspace_id": request.workspace_id,
        "repository_id": request.repository_id,
        "base_revision": request.base_revision,
        "query": request.query,
        "reason": request.reason.value,
        "targets": [
            _target_payload(item)
            for item in sorted(
                request.targets,
                key=lambda item: (
                    item.relative_path or "",
                    item.symbol or "",
                    item.symbol_kind or "",
                    item.language or "",
                ),
            )
        ],
        "changed_files": sorted(request.changed_files),
        "token_budget": request.token_budget,
        "max_files": request.max_files,
        "max_symbols": request.max_symbols,
        "max_excerpts": request.max_excerpts,
        "max_bytes": request.max_bytes,
        "max_file_bytes": request.max_file_bytes,
        "max_query_results": request.max_query_results,
        "max_structure_entries": request.max_structure_entries,
        "index_schema_version": request.index_schema_version,
        "parser_version": request.parser_version,
    }


@dataclass(frozen=True, slots=True)
class ContextRequest:
    """Owner- and GoalSpec-bound request for one context snapshot."""

    task_id: str
    principal_id: str
    project_id: str
    goal_spec_id: str
    goal_spec_digest: str
    workspace_id: str
    repository_id: str
    query: str
    base_revision: str | None = None
    reason: ContextQueryReason = ContextQueryReason.USER_GOAL
    targets: tuple[ContextTarget, ...] = ()
    target_files: tuple[str, ...] = ()
    target_symbols: tuple[str, ...] = ()
    changed_files: tuple[str, ...] = ()
    runtime_id: str = ""
    token_budget: int = 12_000
    max_files: int = 16
    max_symbols: int = 128
    max_excerpts: int = 16
    max_bytes: int = 256 * 1024
    max_file_bytes: int = 64 * 1024
    max_query_results: int = 256
    max_structure_entries: int = 512
    index_schema_version: str = CONTEXT_INDEX_SCHEMA_VERSION
    parser_version: str = CONTEXT_PARSER_VERSION
    schema_version: int = CONTEXT_SCHEMA_VERSION
    request_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "task_id",
            "principal_id",
            "project_id",
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "index_schema_version",
            "parser_version",
        ):
            _require_text(getattr(self, name), label=name)
        _require_digest(self.goal_spec_digest, label="goal_spec_digest")
        _require_text(self.query, label="query", allow_empty=True, max_length=_MAX_QUERY_LENGTH)
        if self.base_revision is not None:
            _require_text(self.base_revision, label="base_revision")
        if self.runtime_id:
            _require_text(self.runtime_id, label="runtime_id")
        if type(self.reason) is not ContextQueryReason:
            raise ContextContractError("reason must be a ContextQueryReason")
        _typed_tuple(self.targets, label="targets", item_type=ContextTarget)
        target_values = self.targets
        if type(self.target_files) is not tuple:
            raise ContextContractError("target_files must be a tuple")
        if type(self.target_symbols) is not tuple:
            raise ContextContractError("target_symbols must be a tuple")
        normalized_files = {
            normalize_relative_path(path, label="target_files")
            for path in self.target_files
        }
        normalized_files.update(
            target.relative_path
            for target in target_values
            if target.relative_path is not None
        )
        normalized_symbols = {
            _require_text(symbol, label="target_symbols")
            for symbol in self.target_symbols
        }
        normalized_symbols.update(
            target.symbol for target in target_values if target.symbol is not None
        )
        existing_paths = {
            target.relative_path
            for target in target_values
            if target.relative_path is not None
        }
        existing_symbols = {
            target.symbol for target in target_values if target.symbol is not None
        }
        synthesized_targets = [
            *target_values,
            *(
                ContextTarget(relative_path=path)
                for path in sorted(normalized_files - existing_paths)
            ),
            *(
                ContextTarget(symbol=symbol)
                for symbol in sorted(normalized_symbols - existing_symbols)
            ),
        ]
        target_values = tuple(
            sorted(
                synthesized_targets,
                key=lambda target: (
                    target.relative_path or "",
                    target.symbol or "",
                    target.symbol_kind or "",
                    target.language or "",
                ),
            )
        )
        object.__setattr__(self, "targets", target_values)
        object.__setattr__(self, "target_files", tuple(sorted(normalized_files)))
        object.__setattr__(self, "target_symbols", tuple(sorted(normalized_symbols)))
        if type(self.changed_files) is not tuple:
            raise ContextContractError("changed_files must be a tuple")
        normalized_changed = tuple(
            sorted(
                {
                    normalize_relative_path(path, label="changed_files")
                    for path in self.changed_files
                }
            )
        )
        object.__setattr__(self, "changed_files", normalized_changed)
        if type(self.schema_version) is not int or self.schema_version != CONTEXT_SCHEMA_VERSION:
            raise ContextContractError("unsupported ContextRequest schema_version")
        _validate_positive_bounds(
            (
                ("token_budget", self.token_budget),
                ("max_files", self.max_files),
                ("max_symbols", self.max_symbols),
                ("max_excerpts", self.max_excerpts),
                ("max_bytes", self.max_bytes),
                ("max_file_bytes", self.max_file_bytes),
                ("max_query_results", self.max_query_results),
                ("max_structure_entries", self.max_structure_entries),
            )
        )
        payload = _request_payload(self)
        expected = canonical_digest(payload)
        if self.request_digest:
            _require_digest(self.request_digest, label="request_digest")
            if self.request_digest != expected:
                raise ContextContractError("request_digest does not match request semantics")
        else:
            object.__setattr__(self, "request_digest", expected)

def _validate_positive_bounds(values: tuple[tuple[str, int], ...]) -> None:
    for name, value in values:
        if type(value) is not int or value <= 0:
            raise ContextContractError(f"{name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class ContextBundle:
    """Deterministic, bounded context projection for one request snapshot."""

    bundle_id: str
    task_id: str
    principal_id: str
    project_id: str
    goal_spec_id: str
    goal_spec_digest: str
    workspace_id: str
    repository_id: str
    base_revision: str | None
    request_digest: str
    repository_generation: str
    index_generation: str
    freshness: ContextFreshness
    documents: tuple[ContextDocument, ...] = ()
    symbols: tuple[ContextSymbol, ...] = ()
    evidence: tuple[ContextEvidence, ...] = ()
    structure_paths: tuple[str, ...] = ()
    truncated: bool = False
    truncation_reasons: tuple[str, ...] = ()
    bundle_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "bundle_id",
            "task_id",
            "principal_id",
            "project_id",
            "goal_spec_id",
            "workspace_id",
            "repository_id",
            "request_digest",
            "repository_generation",
            "index_generation",
        ):
            _require_text(getattr(self, name), label=name)
        _require_digest(self.goal_spec_digest, label="goal_spec_digest")
        _require_digest(self.request_digest, label="request_digest")
        if self.base_revision is not None:
            _require_text(self.base_revision, label="base_revision")
        if type(self.freshness) is not ContextFreshness:
            raise ContextContractError("freshness must be a ContextFreshness")
        documents = _typed_tuple(
            self.documents, label="documents", item_type=ContextDocument
        )
        symbols = _typed_tuple(self.symbols, label="symbols", item_type=ContextSymbol)
        evidence = _typed_tuple(self.evidence, label="evidence", item_type=ContextEvidence)
        object.__setattr__(self, "documents", documents)
        object.__setattr__(self, "symbols", symbols)
        object.__setattr__(self, "evidence", evidence)
        if type(self.structure_paths) is not tuple:
            raise ContextContractError("structure_paths must be a tuple")
        object.__setattr__(
            self,
            "structure_paths",
            tuple(
                sorted(
                    {
                        normalize_relative_path(path, label="structure_paths")
                        for path in self.structure_paths
                    }
                )
            ),
        )
        if type(self.truncated) is not bool:
            raise ContextContractError("truncated must be a bool")
        if type(self.truncation_reasons) is not tuple or any(
            type(item) is not str or not item or len(item) > _MAX_REASON_LENGTH
            for item in self.truncation_reasons
        ):
            raise ContextContractError("truncation_reasons must be bounded strings")
        object.__setattr__(
            self,
            "truncation_reasons",
            tuple(sorted(set(self.truncation_reasons))),
        )
        payload = self.semantic_payload
        expected = canonical_digest(payload)
        if self.bundle_digest:
            _require_digest(self.bundle_digest, label="bundle_digest")
            if self.bundle_digest != expected:
                raise ContextContractError("bundle_digest does not match bundle semantics")
        else:
            object.__setattr__(self, "bundle_digest", expected)

    @property
    def semantic_payload(self) -> Mapping[str, object]:
        """Return the canonical digest payload, excluding ``bundle_id``."""
        return {
            "schema_version": CONTEXT_SCHEMA_VERSION,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "request_digest": self.request_digest,
            "repository_generation": self.repository_generation,
            "index_generation": self.index_generation,
            "freshness": self.freshness.value,
            "documents": [
                _document_payload(item)
                for item in sorted(self.documents, key=_document_sort_key)
            ],
            "symbols": [
                _symbol_payload(item)
                for item in sorted(self.symbols, key=_symbol_sort_key)
            ],
            "evidence": [
                _evidence_payload(item)
                for item in sorted(self.evidence, key=_evidence_sort_key)
            ],
            "structure_paths": sorted(self.structure_paths),
            "truncated": self.truncated,
            "truncation_reasons": sorted(set(self.truncation_reasons)),
        }

    def canonical_json(self) -> str:
        """Serialize the bounded bundle in the shared canonical format."""
        return canonical_json_bytes(
            {**self.semantic_payload, "bundle_id": self.bundle_id, "bundle_digest": self.bundle_digest}
        ).decode("utf-8")


def _document_sort_key(item: ContextDocument) -> tuple[int, str, str]:
    return (-item.relevance_score, item.relative_path, item.content_digest)


def _symbol_sort_key(item: ContextSymbol) -> tuple[str, str, int, int, str]:
    return (
        item.relative_path,
        item.qualified_name,
        item.byte_start,
        item.byte_end,
        item.symbol_id,
    )


__all__ = [
    "CONTEXT_INDEX_SCHEMA_VERSION",
    "CONTEXT_PARSER_VERSION",
    "CONTEXT_SCHEMA_VERSION",
    "ContextBundle",
    "ContextContractError",
    "ContextDocument",
    "ContextEvidence",
    "ContextEvidenceKind",
    "ContextFreshness",
    "ContextQueryReason",
    "ContextRequest",
    "ContextSourceKind",
    "ContextSymbol",
    "ContextTarget",
    "normalize_relative_path",
]
