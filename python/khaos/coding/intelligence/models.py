"""Dependency-free parse contracts for coding intelligence.

Lines and columns are zero-based. Columns count Unicode code points, while
byte offsets count UTF-8 bytes. UTF-16/LSP conversion belongs at integration
boundaries and is deliberately not represented by these values.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Literal


@dataclass(frozen=True)
class SourceLocation:
    file_path: str
    start_line: int
    start_column: int
    end_line: int
    end_column: int
    byte_start: int
    byte_end: int


@dataclass(frozen=True)
class Symbol:
    name: str
    kind: str
    qualified_name: str
    location: SourceLocation
    language: str
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def __getitem__(self, key: str) -> Any:
        if key == "line":
            return self.location.start_line + 1
        if key == "signature":
            return self.metadata.get("signature")
        return getattr(self, key)

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except (AttributeError, KeyError):
            return default


@dataclass(frozen=True)
class ImportReference:
    module: str
    imported_names: tuple[str, ...]
    alias: str | None
    location: SourceLocation
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.module


@dataclass(frozen=True)
class CallCandidate:
    callee: str
    caller: str | None
    location: SourceLocation
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ReferenceCandidate:
    name: str
    reference_kind: str
    location: SourceLocation
    source: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ParseDiagnostic:
    code: str
    severity: Literal["info", "warning", "error"]
    message: str
    location: SourceLocation | None
    recoverable: bool
    source: str


@dataclass(frozen=True)
class ParseState:
    """Opaque incremental state owned by an adapter, never a parser object."""

    adapter_source: str
    content_hash: str
    opaque: object | None = field(default=None, repr=False, compare=False)

    def __reduce__(self) -> object:
        raise TypeError("ParseState is process-local and cannot be pickled")

    def safe_summary(self) -> dict[str, Any]:
        value = {"adapter_source": self.adapter_source, "content_hash": self.content_hash}
        opaque = self.opaque
        for name in ("language", "dialect", "generation", "state_version"):
            if opaque is not None and hasattr(opaque, name):
                value[name] = getattr(opaque, name)
        return value


@dataclass(frozen=True)
class ChangedRange:
    start_byte: int
    end_byte: int
    start_line: int
    start_byte_column: int
    end_line: int
    end_byte_column: int


@dataclass(frozen=True)
class ParserMetadata:
    grammar_name: str | None = None
    grammar_version: str | None = None
    grammar_abi: int | None = None
    grammar_dialect: str | None = None
    query_version: str | None = None
    skipped_error_regions: int = 0
    ast_node_count: int = 0
    symbol_query_match_count: int = 0
    import_query_match_count: int = 0
    call_query_match_count: int = 0
    reference_query_match_count: int = 0
    skipped_error_call_count: int = 0
    skipped_error_reference_count: int = 0
    parse_mode: str = "full"
    incremental_used: bool = False
    incremental_generation: int = 0
    previous_content_hash: str | None = None
    changed_range_count: int = 0
    changed_byte_count: int = 0
    changed_ranges: tuple[ChangedRange, ...] = ()
    edit_start_byte: int | None = None
    edit_old_end_byte: int | None = None
    edit_new_end_byte: int | None = None
    full_reparse_reason: str | None = None
    semantic_refresh_mode: str = "full-file"


@dataclass(frozen=True)
class ParseResult:
    language: str
    file_path: str
    symbols: tuple[Symbol, ...] = ()
    imports: tuple[ImportReference, ...] = ()
    calls: tuple[CallCandidate, ...] = ()
    references: tuple[ReferenceCandidate, ...] = ()
    diagnostics: tuple[ParseDiagnostic, ...] = ()
    parser_source: str = "unknown"
    parser_version: str = "unknown"
    content_hash: str = ""
    parse_duration_ms: float = 0.0
    metadata: ParserMetadata = field(default_factory=ParserMetadata)
    parse_state: ParseState | None = field(default=None, repr=False, compare=False)

    @property
    def path(self) -> Path:
        """Compatibility alias for the Phase 0 ``ParsedFile.path`` field."""
        return Path(self.file_path)

    def to_dict(self, *, include_duration: bool = True, include_parse_state: bool = False) -> dict[str, Any]:
        value = asdict(replace(self, parse_state=None))
        value.pop("parse_state", None)
        if not include_duration:
            value.pop("parse_duration_ms", None)
        if include_parse_state:
            value["parse_state"] = self.parse_state.safe_summary() if self.parse_state else None
        return value
