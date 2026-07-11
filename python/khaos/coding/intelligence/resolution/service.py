"""Repository-level semantic resolution service.

Orchestrates per-file resolution across Python, JavaScript/TypeScript, Go, and Rust.
Builds a symbol table from IndexStore, resolves imports → calls → references,
and produces a RepositoryResolutionReport.

Integration flow:
  RepositoryIndexer updates file ParseResult
  → IndexStore atomic write
  → ResolutionService receives changed/deleted paths
  → rebuild affected SymbolTable shards
  → recompute imports/calls/references for affected files
  → atomic commit of semantic edges
  → return resolution report

Resolution failure does NOT roll back ParseResult indexing.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.resolution.models import (
    FileResolutionResult,
    ResolutionDiagnostic,
    ResolutionStatus,
    RepositoryResolutionReport,
)
from khaos.coding.intelligence.resolution.symbol_table import (
    RepositorySymbolTable,
    build_symbol_table,
)

logger = logging.getLogger(__name__)


class ResolutionService:
    """Orchestrates conservative repository-level semantic resolution."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def resolve(
        self,
        repository_id: str,
        root: Path | None = None,
        *,
        changed_paths: set[str] | None = None,
        deleted_paths: set[str] | None = None,
        full_rebuild: bool = False,
    ) -> RepositoryResolutionReport:
        """Resolve semantic edges for the repository.

        Args:
            repository_id: The repository identifier.
            root: Optional repository root path (for reading go.mod).
            changed_paths: Set of changed file paths to resolve.
            deleted_paths: Set of deleted file paths to clean up.
            full_rebuild: If True, resolve all files from scratch.
        """
        started = time.perf_counter()
        changed = changed_paths or set()
        deleted = deleted_paths or set()

        # Build symbol table from current IndexStore state
        table = build_symbol_table(self._conn, repository_id)

        # Read Go module path if root is available
        go_module_path: str | None = None
        if root is not None:
            from khaos.coding.intelligence.resolution.go_resolver import read_go_module_path
            go_module_path = read_go_module_path(root)

        # Determine which files to resolve
        if full_rebuild:
            to_resolve = set(table.all_files())
        else:
            # Compute affected files: changed + reverse deps of changed + reverse deps of deleted
            affected = set(changed) | set(deleted)
            affected = table.reverse_dep_closure(affected)
            to_resolve = affected

        # Remove deleted files from the table
        for path in deleted:
            table.remove_file(path)

        report = RepositoryResolutionReport(repository_id=repository_id)
        report.affected_files = sorted(to_resolve)

        # Resolve each file
        for file_path in sorted(to_resolve):
            if not table.has_file(file_path):
                report.skipped_files.append(file_path)
                continue
            try:
                result = self._resolve_file(file_path, table, go_module_path)
                report.resolved_files.append(file_path)
                report.symbol_count += len(result.symbols)
                report.import_count += len(result.resolved_imports)
                report.call_count += len(result.resolved_calls)
                report.reference_count += len(result.resolved_references)
                for edge in result.resolved_imports:
                    self._increment_status(report, edge.status, "import")
                for edge in result.resolved_calls:
                    self._increment_status(report, edge.status, "call")
                for edge in result.resolved_references:
                    self._increment_status(report, edge.status, "reference")
                report.diagnostics.extend(result.diagnostics)
            except (RuntimeError, ValueError, KeyError) as exc:
                logger.warning("Resolution failed for %s: %s", file_path, exc)
                report.diagnostics.append(ResolutionDiagnostic(file_path, "resolution-failed", "warning", str(exc)))

        report.total_duration_ms = (time.perf_counter() - started) * 1000
        return report

    def _resolve_file(
        self,
        file_path: str,
        table: RepositorySymbolTable,
        go_module_path: str | None,
    ) -> FileResolutionResult:
        """Resolve a single file's imports, calls, and references."""
        language = table.file_language(file_path)
        generation = table.file_generation(file_path)
        if language is None:
            return FileResolutionResult(file_path, generation, (), (), (), ())

        # Load persisted parse data for this file
        imports = self._load_imports(table.repository_id, file_path)
        calls = self._load_calls(table.repository_id, file_path)
        references = self._load_references(table.repository_id, file_path)

        # Build RepositorySymbol list for this file
        symbols = tuple(table.symbols_by_file(file_path))

        # Resolve based on language
        if language == "python":
            from khaos.coding.intelligence.resolution.python_resolver import (
                resolve_python_calls,
                resolve_python_imports,
                resolve_python_references,
            )
            resolved_imports = resolve_python_imports(file_path, imports, table, generation)
            resolved_calls = resolve_python_calls(file_path, calls, table, resolved_imports, generation)
            resolved_references = resolve_python_references(file_path, references, table, resolved_imports, generation)
        elif language in ("javascript", "typescript"):
            from khaos.coding.intelligence.resolution.javascript_resolver import (
                resolve_javascript_calls,
                resolve_javascript_imports,
                resolve_javascript_references,
            )
            resolved_imports = resolve_javascript_imports(file_path, imports, table, generation)
            resolved_calls = resolve_javascript_calls(file_path, calls, table, resolved_imports, generation)
            resolved_references = resolve_javascript_references(file_path, references, table, resolved_imports, generation)
        elif language == "go":
            from khaos.coding.intelligence.resolution.go_resolver import (
                resolve_go_calls,
                resolve_go_imports,
                resolve_go_references,
            )
            resolved_imports = resolve_go_imports(file_path, imports, table, generation, go_module_path)
            resolved_calls = resolve_go_calls(file_path, calls, table, resolved_imports, generation)
            resolved_references = resolve_go_references(file_path, references, table, resolved_imports, generation)
        elif language == "rust":
            from khaos.coding.intelligence.resolution.rust_resolver import (
                resolve_rust_calls,
                resolve_rust_imports,
                resolve_rust_references,
            )
            resolved_imports = resolve_rust_imports(file_path, imports, table, generation)
            resolved_calls = resolve_rust_calls(file_path, calls, table, resolved_imports, generation)
            resolved_references = resolve_rust_references(file_path, references, table, resolved_imports, generation)
        else:
            resolved_imports = ()
            resolved_calls = ()
            resolved_references = ()

        return FileResolutionResult(
            source_file=file_path,
            generation=generation,
            symbols=symbols,
            resolved_imports=tuple(resolved_imports),
            resolved_calls=tuple(resolved_calls),
            resolved_references=tuple(resolved_references),
        )

    def _load_imports(self, repository_id: str, path: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload_json FROM code_imports WHERE project_id=? AND path=? ORDER BY import_name",
            (repository_id, path),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _load_calls(self, repository_id: str, path: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload_json FROM code_calls WHERE project_id=? AND path=? ORDER BY ordinal",
            (repository_id, path),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def _load_references(self, repository_id: str, path: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT payload_json FROM code_references WHERE project_id=? AND path=? ORDER BY ordinal",
            (repository_id, path),
        ).fetchall()
        return [json.loads(row[0]) for row in rows]

    @staticmethod
    def _increment_status(report: RepositoryResolutionReport, status: ResolutionStatus, edge_type: str) -> None:
        if status == ResolutionStatus.RESOLVED:
            if edge_type == "import":
                report.resolved_imports += 1
            elif edge_type == "call":
                report.resolved_calls += 1
            elif edge_type == "reference":
                report.resolved_references += 1
        elif status == ResolutionStatus.AMBIGUOUS:
            report.ambiguous_count += 1
        elif status == ResolutionStatus.UNRESOLVED:
            report.unresolved_count += 1
        elif status == ResolutionStatus.EXTERNAL:
            report.external_count += 1
        elif status == ResolutionStatus.DYNAMIC:
            report.dynamic_count += 1
        elif status == ResolutionStatus.INVALID:
            report.invalid_count += 1
