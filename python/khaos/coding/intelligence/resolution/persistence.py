"""Persistent storage for repository semantic resolution edges.

Schema is backward-compatible: new tables are added alongside existing
IndexStore tables. Old ParseResult tables are NOT modified.

Per-file semantic edge updates are atomic — a single transaction deletes
all old edges for the file and inserts new ones. Transaction failure
preserves the previous graph intact.

Generation-based invalidation prevents stale resolution from overwriting
newer results: edges are only written with the file's current generation,
and reads filter by maximum generation.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from typing import Any

from khaos.coding.intelligence.resolution.models import (
    FileResolutionResult,
    ResolutionDiagnostic,
    RepositorySymbol,
    ResolvedCallEdge,
    ResolvedImport,
    ResolvedReferenceEdge,
    StaleResolutionResult,
)

logger = logging.getLogger(__name__)


RESOLUTION_SCHEMA = """
CREATE TABLE IF NOT EXISTS repository_symbols (
    symbol_id TEXT NOT NULL,
    stable_symbol_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    path TEXT NOT NULL,
    language TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    qualified_name TEXT NOT NULL,
    byte_start INTEGER NOT NULL,
    byte_end INTEGER NOT NULL,
    start_line INTEGER NOT NULL,
    generation INTEGER NOT NULL,
    PRIMARY KEY (repository_id, symbol_id)
);
CREATE INDEX IF NOT EXISTS idx_repo_symbols_repo_name ON repository_symbols(repository_id, name);
CREATE INDEX IF NOT EXISTS idx_repo_symbols_repo_path ON repository_symbols(repository_id, path);
CREATE INDEX IF NOT EXISTS idx_repo_symbols_repo_qname ON repository_symbols(repository_id, qualified_name);
CREATE INDEX IF NOT EXISTS idx_repo_symbols_stable ON repository_symbols(repository_id, stable_symbol_id);

CREATE TABLE IF NOT EXISTS resolved_imports (
    repository_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    import_module TEXT NOT NULL,
    imported_name TEXT NOT NULL,
    alias TEXT,
    status TEXT NOT NULL,
    target_file TEXT,
    target_symbol_id TEXT,
    confidence REAL NOT NULL,
    reason TEXT NOT NULL,
    candidate_targets_json TEXT NOT NULL DEFAULT '[]',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    generation INTEGER NOT NULL,
    PRIMARY KEY (repository_id, source_file, import_module, imported_name, alias, generation)
);
CREATE INDEX IF NOT EXISTS idx_resolved_imports_source ON resolved_imports(repository_id, source_file);
CREATE INDEX IF NOT EXISTS idx_resolved_imports_target ON resolved_imports(repository_id, target_file);

CREATE TABLE IF NOT EXISTS resolved_call_edges (
    edge_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    caller_symbol_id TEXT,
    call_callee TEXT NOT NULL,
    status TEXT NOT NULL,
    target_symbol_id TEXT,
    target_file TEXT,
    confidence REAL NOT NULL,
    resolution_rule TEXT NOT NULL,
    ambiguity_reason TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    generation INTEGER NOT NULL,
    PRIMARY KEY (repository_id, edge_id)
);
CREATE INDEX IF NOT EXISTS idx_call_edges_repo_source ON resolved_call_edges(repository_id, source_file);
CREATE INDEX IF NOT EXISTS idx_call_edges_repo_target ON resolved_call_edges(repository_id, target_symbol_id);

CREATE TABLE IF NOT EXISTS resolved_reference_edges (
    edge_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    name TEXT NOT NULL,
    reference_kind TEXT NOT NULL,
    status TEXT NOT NULL,
    target_symbol_id TEXT,
    target_file TEXT,
    confidence REAL NOT NULL,
    resolution_rule TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    generation INTEGER NOT NULL,
    PRIMARY KEY (repository_id, edge_id)
);
CREATE INDEX IF NOT EXISTS idx_ref_edges_repo_source ON resolved_reference_edges(repository_id, source_file);
CREATE INDEX IF NOT EXISTS idx_ref_edges_repo_target ON resolved_reference_edges(repository_id, target_symbol_id);

CREATE TABLE IF NOT EXISTS resolution_diagnostics (
    repository_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    ordinal INTEGER NOT NULL,
    PRIMARY KEY (repository_id, source_file, ordinal)
);
CREATE INDEX IF NOT EXISTS idx_resolution_diag_source ON resolution_diagnostics(repository_id, source_file);

CREATE TABLE IF NOT EXISTS resolution_generation (
    repository_id TEXT NOT NULL,
    source_file TEXT NOT NULL,
    generation INTEGER NOT NULL,
    resolved_at REAL NOT NULL,
    PRIMARY KEY (repository_id, source_file)
);
"""


def _table_primary_key(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names in the primary key of ``table``."""
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})") if row[5]}


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the set of column names in ``table``."""
    return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}


def apply_resolution_schema(conn: sqlite3.Connection) -> None:
    """Apply resolution schema migration. Idempotent and backward-compatible.

    For databases with an older schema (missing ``stable_symbol_id`` column
    or single-column primary keys without ``repository_id``), the affected
    tables are dropped and recreated. This is safe because the resolution
    graph is fully rebuildable from the IndexStore's persisted ParseResult
    data.
    """
    conn.executescript(RESOLUTION_SCHEMA)
    # Migration: ensure repository_symbols has stable_symbol_id and composite PK
    try:
        cols = _table_columns(conn, "repository_symbols")
        if cols and ("stable_symbol_id" not in cols or _table_primary_key(conn, "repository_symbols") != {"repository_id", "symbol_id"}):
            conn.execute("DROP TABLE repository_symbols")
    except sqlite3.OperationalError:
        pass
    # Migration: ensure resolved_call_edges has composite PK (repository_id, edge_id)
    try:
        if _table_primary_key(conn, "resolved_call_edges") != {"repository_id", "edge_id"}:
            conn.execute("DROP TABLE resolved_call_edges")
    except sqlite3.OperationalError:
        pass
    # Migration: ensure resolved_reference_edges has composite PK (repository_id, edge_id)
    try:
        if _table_primary_key(conn, "resolved_reference_edges") != {"repository_id", "edge_id"}:
            conn.execute("DROP TABLE resolved_reference_edges")
    except sqlite3.OperationalError:
        pass
    # Re-create any tables that were dropped
    conn.executescript(RESOLUTION_SCHEMA)
    conn.commit()


def commit_file_resolution(
    conn: sqlite3.Connection,
    repository_id: str,
    result: FileResolutionResult,
) -> None | StaleResolutionResult:
    """Atomically persist a single file's resolution results with exact generation CAS.

    Performs a Compare-And-Swap within a single BEGIN IMMEDIATE transaction:
    1. Queries ``code_files`` for the current file generation.
    2. Queries ``resolution_generation`` for the persisted resolution generation.
    3. Compares ``result.generation`` against both.
    4. Rejects any mismatch without modifying the existing graph.

    Acceptance condition (all must hold):
      - File exists in ``code_files`` (not deleted)
      - ``result.generation == code_files.generation`` (exact match — no future, no stale)
      - ``result.generation >= resolution_generation.generation`` (not older than persisted)

    Rejection reasons (4-way classification):
      - ``file-deleted``: file not in ``code_files``
      - ``stale-code-generation``: ``result.generation < code_files.generation``
      - ``future-code-generation``: ``result.generation > code_files.generation``
      - ``stale-resolution-generation``: ``result.generation < resolution_generation.generation``

    Rejection returns a structured ``StaleResolutionResult`` without mutating
    any tables. On success, old edges for the file are deleted and new ones
    inserted atomically. Transaction failure preserves the previous graph.
    """
    import time

    file_path = result.source_file
    generation = result.generation
    try:
        conn.execute("BEGIN IMMEDIATE")
        # --- CAS: compare generations before writing ---
        code_row = conn.execute(
            "SELECT generation FROM code_files WHERE project_id=? AND path=?",
            (repository_id, file_path),
        ).fetchone()
        code_generation = int(code_row[0]) if code_row else None

        persisted_row = conn.execute(
            "SELECT generation FROM resolution_generation WHERE repository_id=? AND source_file=?",
            (repository_id, file_path),
        ).fetchone()
        persisted_generation = int(persisted_row[0]) if persisted_row else 0

        # Reject if file was deleted from IndexStore
        if code_generation is None:
            conn.rollback()
            return StaleResolutionResult(
                source_file=file_path,
                result_generation=generation,
                code_generation=None,
                persisted_generation=persisted_generation,
                reason="file-deleted",
            )
        # Reject if result is older than current code file generation
        if generation < code_generation:
            conn.rollback()
            return StaleResolutionResult(
                source_file=file_path,
                result_generation=generation,
                code_generation=code_generation,
                persisted_generation=persisted_generation,
                reason="stale-code-generation",
            )
        # Reject if result is newer than current code file generation (speculative future)
        if generation > code_generation:
            conn.rollback()
            return StaleResolutionResult(
                source_file=file_path,
                result_generation=generation,
                code_generation=code_generation,
                persisted_generation=persisted_generation,
                reason="future-code-generation",
            )
        # Reject if result is older than already-persisted resolution generation
        if generation < persisted_generation:
            conn.rollback()
            return StaleResolutionResult(
                source_file=file_path,
                result_generation=generation,
                code_generation=code_generation,
                persisted_generation=persisted_generation,
                reason="stale-resolution-generation",
            )
        # --- CAS passed: proceed with atomic write ---
        # Remove old symbols and edges for this file
        conn.execute("DELETE FROM repository_symbols WHERE repository_id=? AND path=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_imports WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_call_edges WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_reference_edges WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolution_diagnostics WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        # Insert symbols
        conn.executemany(
            "INSERT INTO repository_symbols VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [_symbol_row(s) for s in result.symbols],
        )
        # Insert imports
        conn.executemany(
            "INSERT INTO resolved_imports VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [_import_row(repository_id, file_path, generation, i) for i in result.resolved_imports],
        )
        # Insert call edges
        conn.executemany(
            "INSERT INTO resolved_call_edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [_call_row(repository_id, file_path, generation, e) for e in result.resolved_calls],
        )
        # Insert reference edges
        conn.executemany(
            "INSERT INTO resolved_reference_edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [_reference_row(repository_id, file_path, generation, e) for e in result.resolved_references],
        )
        # Insert diagnostics
        conn.executemany(
            "INSERT INTO resolution_diagnostics VALUES (?,?,?,?,?,?)",
            [_diagnostic_row(repository_id, file_path, idx, d) for idx, d in enumerate(result.diagnostics)],
        )
        # Update generation marker
        conn.execute(
            "INSERT OR REPLACE INTO resolution_generation VALUES (?,?,?,?)",
            (repository_id, file_path, generation, time.time()),
        )
        conn.commit()
        return None
    except (sqlite3.DatabaseError, TypeError, ValueError):
        conn.rollback()
        raise


def remove_file_resolution(conn: sqlite3.Connection, repository_id: str, file_path: str) -> None:
    """Remove all resolution data for a deleted file."""
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM repository_symbols WHERE repository_id=? AND path=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_imports WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_call_edges WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolved_reference_edges WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolution_diagnostics WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        conn.execute("DELETE FROM resolution_generation WHERE repository_id=? AND source_file=?", (repository_id, file_path))
        # Invalidate edges that point TO this file. We keep target_file so the
        # reverse-dependency lookup can still find dependents when the file is
        # later restored — only the *resolved* status is cleared (target_symbol_id
        # is set to NULL because the symbol itself no longer exists). This means
        # no resolved edge points to a missing file (no dangling resolved target),
        # but the dependency relationship is preserved for re-resolution.
        conn.execute(
            "UPDATE resolved_imports SET status='unresolved', target_symbol_id=NULL, confidence=0.4, reason='target-file-deleted' WHERE repository_id=? AND target_file=? AND status='resolved'",
            (repository_id, file_path),
        )
        conn.execute(
            "UPDATE resolved_call_edges SET status='unresolved', target_symbol_id=NULL, confidence=0.4, resolution_rule='target-file-deleted' WHERE repository_id=? AND target_file=? AND status='resolved'",
            (repository_id, file_path),
        )
        conn.execute(
            "UPDATE resolved_reference_edges SET status='unresolved', target_symbol_id=NULL, confidence=0.4, resolution_rule='target-file-deleted' WHERE repository_id=? AND target_file=? AND status='resolved'",
            (repository_id, file_path),
        )
        conn.commit()
    except sqlite3.DatabaseError:
        conn.rollback()
        raise


def file_generation(conn: sqlite3.Connection, repository_id: str, file_path: str) -> int:
    """Get the last persisted generation for a file. Returns 0 if not present."""
    row = conn.execute(
        "SELECT generation FROM resolution_generation WHERE repository_id=? AND source_file=?",
        (repository_id, file_path),
    ).fetchone()
    return int(row[0]) if row else 0


def resolved_imports_for_file(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_imports WHERE repository_id=? AND source_file=? ORDER BY import_module, imported_name",
        (repository_id, file_path),
    ).fetchall()
    return [_import_dict(row) for row in rows]


def call_edges_for_file(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_call_edges WHERE repository_id=? AND source_file=? ORDER BY call_callee",
        (repository_id, file_path),
    ).fetchall()
    return [_call_dict(row) for row in rows]


def reference_edges_for_file(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_reference_edges WHERE repository_id=? AND source_file=? ORDER BY name",
        (repository_id, file_path),
    ).fetchall()
    return [_reference_dict(row) for row in rows]


def callers_of_symbol(conn: sqlite3.Connection, repository_id: str, symbol_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_call_edges WHERE repository_id=? AND target_symbol_id=? ORDER BY source_file, call_callee",
        (repository_id, symbol_id),
    ).fetchall()
    return [_call_dict(row) for row in rows]


def callees_of_symbol(conn: sqlite3.Connection, repository_id: str, symbol_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_call_edges WHERE repository_id=? AND caller_symbol_id=? ORDER BY call_callee",
        (repository_id, symbol_id),
    ).fetchall()
    return [_call_dict(row) for row in rows]


def references_to_symbol(conn: sqlite3.Connection, repository_id: str, symbol_id: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM resolved_reference_edges WHERE repository_id=? AND target_symbol_id=? ORDER BY source_file, name",
        (repository_id, symbol_id),
    ).fetchall()
    return [_reference_dict(row) for row in rows]


def symbol_targets(conn: sqlite3.Connection, repository_id: str, name: str) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM repository_symbols WHERE repository_id=? AND name=? ORDER BY path, qualified_name",
        (repository_id, name),
    ).fetchall()
    return [_symbol_dict(row) for row in rows]


def unresolved_candidates_for_file(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[dict[str, Any]]:
    """Get all unresolved/ambiguous/dynamic edges for a file."""
    results: list[dict[str, Any]] = []
    for row in conn.execute(
        "SELECT 'import' as edge_type, import_module, imported_name, alias, status, reason FROM resolved_imports WHERE repository_id=? AND source_file=? AND status != 'resolved'",
        (repository_id, file_path),
    ).fetchall():
        results.append({"edge_type": "import", "import_module": row[1], "imported_name": row[2], "alias": row[3], "status": row[4], "reason": row[5]})
    for row in conn.execute(
        "SELECT 'call' as edge_type, call_callee, status, resolution_rule, ambiguity_reason FROM resolved_call_edges WHERE repository_id=? AND source_file=? AND status != 'resolved'",
        (repository_id, file_path),
    ).fetchall():
        results.append({"edge_type": "call", "callee": row[1], "status": row[2], "resolution_rule": row[3], "ambiguity_reason": row[4]})
    for row in conn.execute(
        "SELECT 'reference' as edge_type, name, status, resolution_rule FROM resolved_reference_edges WHERE repository_id=? AND source_file=? AND status != 'resolved'",
        (repository_id, file_path),
    ).fetchall():
        results.append({"edge_type": "reference", "name": row[1], "status": row[2], "resolution_rule": row[3]})
    return results


def dependency_files(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[str]:
    """Get files that this file depends on (via resolved imports/calls/references)."""
    targets: set[str] = set()
    for row in conn.execute(
        "SELECT DISTINCT target_file FROM resolved_imports WHERE repository_id=? AND source_file=? AND target_file IS NOT NULL",
        (repository_id, file_path),
    ).fetchall():
        targets.add(row[0])
    for row in conn.execute(
        "SELECT DISTINCT target_file FROM resolved_call_edges WHERE repository_id=? AND source_file=? AND target_file IS NOT NULL",
        (repository_id, file_path),
    ).fetchall():
        targets.add(row[0])
    for row in conn.execute(
        "SELECT DISTINCT target_file FROM resolved_reference_edges WHERE repository_id=? AND source_file=? AND target_file IS NOT NULL",
        (repository_id, file_path),
    ).fetchall():
        targets.add(row[0])
    return sorted(targets)


def reverse_dependency_files(conn: sqlite3.Connection, repository_id: str, file_path: str) -> list[str]:
    """Get files that depend on this file."""
    sources: set[str] = set()
    for row in conn.execute(
        "SELECT DISTINCT source_file FROM resolved_imports WHERE repository_id=? AND target_file=?",
        (repository_id, file_path),
    ).fetchall():
        sources.add(row[0])
    for row in conn.execute(
        "SELECT DISTINCT source_file FROM resolved_call_edges WHERE repository_id=? AND target_file=?",
        (repository_id, file_path),
    ).fetchall():
        sources.add(row[0])
    for row in conn.execute(
        "SELECT DISTINCT source_file FROM resolved_reference_edges WHERE repository_id=? AND target_file=?",
        (repository_id, file_path),
    ).fetchall():
        sources.add(row[0])
    return sorted(sources)


def resolution_counts(conn: sqlite3.Connection, repository_id: str) -> dict[str, int]:
    """Get aggregate counts for the repository."""
    counts: dict[str, int] = {}
    counts["symbols"] = int(conn.execute("SELECT COUNT(*) FROM repository_symbols WHERE repository_id=?", (repository_id,)).fetchone()[0])
    counts["imports"] = int(conn.execute("SELECT COUNT(*) FROM resolved_imports WHERE repository_id=?", (repository_id,)).fetchone()[0])
    counts["call_edges"] = int(conn.execute("SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id=?", (repository_id,)).fetchone()[0])
    counts["reference_edges"] = int(conn.execute("SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id=?", (repository_id,)).fetchone()[0])
    for status in ("resolved", "ambiguous", "unresolved", "external", "dynamic", "invalid"):
        counts[f"imports_{status}"] = int(conn.execute(
            "SELECT COUNT(*) FROM resolved_imports WHERE repository_id=? AND status=?", (repository_id, status)
        ).fetchone()[0])
        counts[f"calls_{status}"] = int(conn.execute(
            "SELECT COUNT(*) FROM resolved_call_edges WHERE repository_id=? AND status=?", (repository_id, status)
        ).fetchone()[0])
        counts[f"references_{status}"] = int(conn.execute(
            "SELECT COUNT(*) FROM resolved_reference_edges WHERE repository_id=? AND status=?", (repository_id, status)
        ).fetchone()[0])
    return counts


def _symbol_row(sym: RepositorySymbol) -> tuple[Any, ...]:
    return (sym.symbol_id, sym.stable_symbol_id, sym.repository_id, sym.path, sym.language, sym.kind, sym.name, sym.qualified_name, sym.byte_start, sym.byte_end, sym.start_line, sym.generation)


def _import_row(repository_id: str, file_path: str, generation: int, imp: ResolvedImport) -> tuple[Any, ...]:
    return (
        repository_id, file_path, imp.import_module, imp.imported_name, imp.alias,
        imp.status.value, imp.target_file, imp.target_symbol_id, imp.confidence,
        imp.reason, json.dumps(list(imp.candidate_targets), ensure_ascii=False),
        json.dumps(imp.metadata, ensure_ascii=False, sort_keys=True), generation,
    )


def _call_row(repository_id: str, file_path: str, generation: int, edge: ResolvedCallEdge) -> tuple[Any, ...]:
    return (
        edge.edge_id, repository_id, file_path, edge.caller_symbol_id, edge.call_callee,
        edge.status.value, edge.target_symbol_id, edge.target_file, edge.confidence,
        edge.resolution_rule, edge.ambiguity_reason,
        json.dumps(edge.metadata, ensure_ascii=False, sort_keys=True), generation,
    )


def _reference_row(repository_id: str, file_path: str, generation: int, edge: ResolvedReferenceEdge) -> tuple[Any, ...]:
    return (
        edge.edge_id, repository_id, file_path, edge.name, edge.reference_kind,
        edge.status.value, edge.target_symbol_id, edge.target_file, edge.confidence,
        edge.resolution_rule, json.dumps(edge.metadata, ensure_ascii=False, sort_keys=True), generation,
    )


def _diagnostic_row(repository_id: str, file_path: str, ordinal: int, diag: ResolutionDiagnostic) -> tuple[Any, ...]:
    return (repository_id, file_path, diag.code, diag.severity, diag.message, ordinal)


def _symbol_dict(row: sqlite3.Row | tuple) -> dict[str, Any]:
    keys = ("symbol_id", "stable_symbol_id", "repository_id", "path", "language", "kind", "name", "qualified_name", "byte_start", "byte_end", "start_line", "generation")
    return dict(zip(keys, row))


def _import_dict(row: sqlite3.Row | tuple) -> dict[str, Any]:
    return {
        "source_file": row[1], "import_module": row[2], "imported_name": row[3], "alias": row[4],
        "status": row[5], "target_file": row[6], "target_symbol_id": row[7], "confidence": row[8],
        "reason": row[9], "candidate_targets": json.loads(row[10]), "metadata": json.loads(row[11]), "generation": row[12],
    }


def _call_dict(row: sqlite3.Row | tuple) -> dict[str, Any]:
    return {
        "edge_id": row[0], "repository_id": row[1], "source_file": row[2], "caller_symbol_id": row[3],
        "call_callee": row[4], "status": row[5], "target_symbol_id": row[6], "target_file": row[7],
        "confidence": row[8], "resolution_rule": row[9], "ambiguity_reason": row[10],
        "metadata": json.loads(row[11]), "generation": row[12],
    }


def _reference_dict(row: sqlite3.Row | tuple) -> dict[str, Any]:
    return {
        "edge_id": row[0], "repository_id": row[1], "source_file": row[2], "name": row[3],
        "reference_kind": row[4], "status": row[5], "target_symbol_id": row[6], "target_file": row[7],
        "confidence": row[8], "resolution_rule": row[9], "metadata": json.loads(row[10]), "generation": row[11],
    }
