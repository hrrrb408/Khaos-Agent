"""Dependency-free parse contracts for coding intelligence.

Lines and columns are zero-based. Columns count Unicode code points, while
byte offsets count UTF-8 bytes. UTF-16/LSP conversion belongs at integration
boundaries and is deliberately not represented by these values.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
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

    def __str__(self) -> str:
        return self.module


@dataclass(frozen=True)
class CallCandidate:
    callee: str
    caller: str | None
    location: SourceLocation
    source: str
    confidence: float


@dataclass(frozen=True)
class ReferenceCandidate:
    name: str
    reference_kind: str
    location: SourceLocation
    source: str
    confidence: float


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
    opaque: object | None = None


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

    @property
    def path(self) -> Path:
        """Compatibility alias for the Phase 0 ``ParsedFile.path`` field."""
        return Path(self.file_path)

    def to_dict(self, *, include_duration: bool = True) -> dict[str, Any]:
        value = asdict(self)
        if not include_duration:
            value.pop("parse_duration_ms", None)
        return value
