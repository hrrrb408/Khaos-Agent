"""Conservative repository-level semantic resolution.

Provides cross-file import, call, and reference resolution for Python,
JavaScript/TypeScript/TSX, Go, and Rust — without LSP, type inference,
or external dependency resolution.
"""
from khaos.coding.intelligence.resolution.models import (
    FileResolutionResult,
    ResolutionDiagnostic,
    ResolutionStatus,
    RepositoryResolutionReport,
    RepositorySymbol,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
)
from khaos.coding.intelligence.resolution.persistence import (
    apply_resolution_schema,
    commit_file_resolution,
    remove_file_resolution,
)
from khaos.coding.intelligence.resolution.service import ResolutionService
from khaos.coding.intelligence.resolution.symbol_table import (
    RepositorySymbolTable,
    build_symbol_table,
)

__all__ = [
    "FileResolutionResult",
    "RepositoryResolutionReport",
    "RepositorySymbol",
    "RepositorySymbolTable",
    "ResolutionDiagnostic",
    "ResolutionService",
    "ResolutionStatus",
    "ResolvedCallEdge",
    "ResolvedImport",
    "ResolvedReferenceEdge",
    "apply_resolution_schema",
    "build_symbol_table",
    "commit_file_resolution",
    "remove_file_resolution",
]
