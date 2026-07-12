"""Structured query facade over the persistent index.

Old query methods (find_symbols, find_definition, find_dependencies)
continue to work unchanged. New methods operate on the persisted
semantic resolution graph.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.index import IndexStore
from khaos.coding.intelligence.resolution.persistence import (
    call_edges_for_file,
    callers_of_symbol,
    callees_of_symbol,
    dependency_files as _dependency_files,
    reference_edges_for_file,
    references_to_symbol,
    resolved_imports_for_file,
    symbol_targets,
    unresolved_candidates_for_file,
    reverse_dependency_files,
)


class CodeQueryService:
    def __init__(self, store: IndexStore) -> None:
        self.store = store

    async def find_symbols(self, project_id: str, query: str, *, limit: int = 50) -> list[dict]:
        return await self.store.find_symbols(project_id, query, limit=limit)

    async def find_definition(self, project_id: str, name: str) -> dict | None:
        results = await self.store.find_symbols(project_id, name, limit=1)
        return results[0] if results else None

    async def find_dependencies(self, project_id: str, path: Path) -> list[str]:
        return await self.store.imports_for(project_id, path)

    # ---- Semantic resolution graph queries (new, additive) ----

    def find_symbol_targets(self, project_id: str, name: str) -> list[dict[str, Any]]:
        """Find all repository symbols matching a name."""
        return symbol_targets(self.store._conn, project_id, name)

    def find_qualified_symbol_targets(self, project_id: str, qualified_name: str) -> list[dict[str, Any]]:
        """Find exact qualified-name matches without case folding."""
        rows = self.store._conn.execute(
            "SELECT * FROM repository_symbols WHERE repository_id=? AND qualified_name=? ORDER BY path,qualified_name",
            (project_id, qualified_name),
        ).fetchall()
        return [dict(row) for row in rows]

    def indexed_symbol_candidates(self, project_id: str, name: str) -> list[dict[str, Any]]:
        """Read-only fallback when resolution has not produced a graph node."""
        rows = self.store._conn.execute(
            "SELECT path,name,kind FROM code_symbols WHERE project_id=? AND name=? ORDER BY path,line",
            (project_id, name),
        ).fetchall()
        return [dict(row) for row in rows]

    def resolved_imports(self, project_id: str, path: str) -> list[dict[str, Any]]:
        """Get resolved import edges for a file."""
        return resolved_imports_for_file(self.store._conn, project_id, path)

    def callers_of(self, project_id: str, symbol_id: str) -> list[dict[str, Any]]:
        """Find call edges targeting a symbol."""
        return callers_of_symbol(self.store._conn, project_id, symbol_id)

    def callees_of(self, project_id: str, symbol_id: str) -> list[dict[str, Any]]:
        """Find call edges originating from a caller symbol."""
        return callees_of_symbol(self.store._conn, project_id, symbol_id)

    def references_to(self, project_id: str, symbol_id: str) -> list[dict[str, Any]]:
        """Find reference edges targeting a symbol."""
        return references_to_symbol(self.store._conn, project_id, symbol_id)

    def unresolved_candidates(self, project_id: str, path: str) -> list[dict[str, Any]]:
        """Get all unresolved/ambiguous/dynamic edges for a file."""
        return unresolved_candidates_for_file(self.store._conn, project_id, path)

    def dependency_files(self, project_id: str, path: str) -> list[str]:
        """Get files that this file depends on (via resolved edges)."""
        return _dependency_files(self.store._conn, project_id, path)

    def reverse_dependency_files(self, project_id: str, path: str) -> list[str]:
        """Return stable reverse import/call/reference dependencies."""
        return reverse_dependency_files(self.store._conn, project_id, path)

    def reverse_imports_to(self, project_id: str, path: str) -> list[dict[str, Any]]:
        """Return only resolved import edges targeting ``path``.

        Includes ``metadata_json`` so callers can inspect semantic re-export
        evidence (``import_kind=reexport``, ``pub_use=True``) rather than
        guessing from file names.
        """
        rows = self.store._conn.execute(
            "SELECT source_file,import_module,imported_name,alias,status,confidence,reason,target_symbol_id,metadata_json FROM resolved_imports WHERE repository_id=? AND target_file=? ORDER BY source_file,import_module,imported_name,alias",
            (project_id, path),
        ).fetchall()
        import json
        return [dict(row, metadata=json.loads(row[8]) if row[8] else {}) for row in rows]

    def symbol_by_stable_id(self, project_id: str, stable_symbol_id: str) -> dict[str, Any] | None:
        row = self.store._conn.execute(
            "SELECT * FROM repository_symbols WHERE repository_id=? AND stable_symbol_id=?",
            (project_id, stable_symbol_id),
        ).fetchone()
        return dict(row) if row else None

    def call_edges_for_file(self, project_id: str, path: str) -> list[dict[str, Any]]:
        """Get all call edges for a file."""
        return call_edges_for_file(self.store._conn, project_id, path)

    def reference_edges_for_file(self, project_id: str, path: str) -> list[dict[str, Any]]:
        """Get all reference edges for a file."""
        return reference_edges_for_file(self.store._conn, project_id, path)

    def file_evidence(self, project_id: str, path: str) -> dict[str, Any] | None:
        """Read indexed file metadata for evidence-bound consumers.

        This is intentionally read-only and keeps planning clients out of the
        IndexStore connection details.
        """
        row = self.store._conn.execute(
            "SELECT path,language,content_hash,generation FROM code_files WHERE project_id=? AND path=?",
            (project_id, path),
        ).fetchone()
        return dict(row) if row else None

    def associated_tests(
        self,
        repository_id: str,
        *,
        target_files: tuple[str, ...],
        target_symbols: tuple[str, ...] = (),
        max_results: int = 50,
    ) -> "tuple":
        """Bounded test-file association lookup — never scans the whole repository.

        Uses indexed ``path_role`` equality queries (NOT ``LIKE '%test%'``) to
        find test files. Every query is bounded by LIMIT and uses an index seek.

        Evidence priority (each level is bounded by ``max_results``):
        1. Resolved graph edges (import/call/reference) where the source file
           has ``path_role='test'`` — uses indexed joins on target_file/target_symbol_id.
        2. All test files (``path_role='test'``) in the repository — uses the
           ``idx_code_files_role`` index for bounded equality scan.

        Returns a :class:`TestAssociationResult` with full query cost evidence:
        ``sql_queries_issued``, ``sql_rows_returned``, ``indexed_edge_rows_fetched``,
        and ``query_plans`` (EXPLAIN QUERY PLAN output for audit).
        """
        from khaos.coding.planning.contracts import TestAssociationResult

        max_candidates = max_results
        candidates: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        evidence_sources: list[str] = []
        truncated = False
        sql_queries_issued = 0
        sql_rows_returned = 0
        indexed_edge_rows_fetched = 0
        query_plans: list[str] = []

        def _explain(sql: str, params: tuple) -> str:
            """Run EXPLAIN QUERY PLAN and return a compact string."""
            try:
                plan_rows = self.store._conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()
                return " | ".join(str(r[3]) for r in plan_rows)
            except sqlite3.Error:
                return "explain-failed"

        # --- Priority 1: Resolved graph edges where source is a test file ---
        # Uses idx_resolved_imports_target (on target_file) — indexed seek, not scan.
        if target_files:
            placeholders = ",".join("?" * len(target_files))
            sql = (
                f"SELECT DISTINCT ri.source_file, ri.target_file, ri.confidence, ri.reason, 'import' AS edge_type "
                f"FROM resolved_imports ri "
                f"INNER JOIN code_files cf ON cf.project_id = ri.repository_id AND cf.path = ri.source_file "
                f"WHERE ri.repository_id = ? AND ri.target_file IN ({placeholders}) AND cf.path_role = 'test' "
                f"ORDER BY ri.source_file LIMIT ?"
            )
            params = (repository_id, *target_files, max_candidates)
            query_plans.append(f"P1-import: {_explain(sql, params)}")
            rows = self.store._conn.execute(sql, params).fetchall()
            sql_queries_issued += 1
            sql_rows_returned += len(rows)
            indexed_edge_rows_fetched += len(rows)
            for row in rows:
                path = str(row[0])
                if path not in seen_paths:
                    seen_paths.add(path)
                    candidates.append({"path": path, "target_file": row[1], "confidence": float(row[2]),
                                       "reason": str(row[3]), "edge_type": "import", "source": "resolution-graph"})
            if rows:
                evidence_sources.append("resolved-imports")

        if target_symbols:
            placeholders = ",".join("?" * len(target_symbols))
            for table, kind in (("resolved_call_edges", "call"), ("resolved_reference_edges", "reference")):
                sql = (
                    f"SELECT DISTINCT e.source_file, e.target_file, e.target_symbol_id, e.confidence, e.resolution_rule, '{kind}' AS edge_type "
                    f"FROM {table} e "
                    f"INNER JOIN code_files cf ON cf.project_id = e.repository_id AND cf.path = e.source_file "
                    f"WHERE e.repository_id = ? AND e.target_symbol_id IN ({placeholders}) AND cf.path_role = 'test' "
                    f"ORDER BY e.source_file LIMIT ?"
                )
                params = (repository_id, *target_symbols, max_candidates)
                query_plans.append(f"P1-{kind}: {_explain(sql, params)}")
                rows = self.store._conn.execute(sql, params).fetchall()
                sql_queries_issued += 1
                sql_rows_returned += len(rows)
                indexed_edge_rows_fetched += len(rows)
                for row in rows:
                    path = str(row[0])
                    if path not in seen_paths:
                        seen_paths.add(path)
                        candidates.append({"path": path, "target_file": row[1], "confidence": float(row[3]),
                                           "reason": str(row[4]), "edge_type": kind, "source": "resolution-graph"})
                if rows:
                    evidence_sources.append(f"resolved-{kind}-edges")

        # --- Priority 2: All test files via path_role index (equality, not LIKE) ---
        if len(candidates) < max_candidates:
            remaining = max_candidates - len(candidates)
            sql = (
                "SELECT path, language, content_hash, generation FROM code_files "
                "WHERE project_id = ? AND path_role = 'test' ORDER BY path LIMIT ?"
            )
            params = (repository_id, remaining)
            query_plans.append(f"P2-test-role: {_explain(sql, params)}")
            rows = self.store._conn.execute(sql, params).fetchall()
            sql_queries_issued += 1
            sql_rows_returned += len(rows)
            indexed_edge_rows_fetched += len(rows)
            for row in rows:
                path = str(row[0])
                if path not in seen_paths:
                    seen_paths.add(path)
                    candidates.append({"path": path, "language": row[1], "content_hash": row[2],
                                       "generation": row[3], "confidence": 0.5,
                                       "reason": "indexed test-role", "edge_type": "role-index",
                                       "source": "path-role-index"})
            if rows:
                evidence_sources.append("path-role-index")

        if len(candidates) >= max_candidates:
            truncated = True

        candidates.sort(key=lambda c: (c.get("path", ""), c.get("edge_type", "")))
        return TestAssociationResult(
            candidates=tuple(candidates[:max_candidates]),
            status="possible",
            confidence=0.5,
            inspected_candidates=sql_rows_returned,
            max_candidates=max_candidates,
            evidence_sources=tuple(sorted(set(evidence_sources))),
            truncated=truncated,
            sql_queries_issued=sql_queries_issued,
            sql_rows_returned=sql_rows_returned,
            indexed_edge_rows_fetched=indexed_edge_rows_fetched,
            query_plans=tuple(query_plans),
        )

    # ---- Optional LSP evidence fusion queries (Batch 6, additive) ----
    # These methods delegate to an optional LspEvidenceFusionService.
    # When no fusion service is bound, they return repository-only results
    # — they never fail and never depend on LSP availability.

    def fused_definition(
        self,
        project_id: str,
        path: str,
        callee: str,
        byte_start: int,
        byte_end: int,
        *,
        fused_result: Any | None = None,
    ) -> dict[str, Any]:
        """Return a fused definition resolution (repo + optional LSP evidence).

        When ``fused_result`` (a :class:`FusedResolution`) is provided, returns
        its structured breakdown. Otherwise, returns the repository resolution
        for the matching call edge with ``depends_on_lsp=False``.

        This method is synchronous — callers perform the async LSP fusion via
        :class:`LspEvidenceFusionService` and pass the result here for
        structured query output.
        """
        if fused_result is not None:
            if hasattr(fused_result, "to_dict"):
                return fused_result.to_dict()
            if isinstance(fused_result, dict):
                return dict(fused_result)
        edges = self.call_edges_for_file(project_id, path)
        for edge in edges:
            if edge.get("call_callee") == callee:
                return {
                    "original_status": edge["status"],
                    "fused_status": edge["status"],
                    "target_symbol_id": edge.get("target_symbol_id"),
                    "target_file": edge.get("target_file"),
                    "confidence": edge.get("confidence", 0.0),
                    "evidence": [],
                    "conflict_reason": None,
                    "resolution_rule": edge.get("resolution_rule", ""),
                    "depends_on_lsp": False,
                }
        return {
            "original_status": "unresolved",
            "fused_status": "unresolved",
            "target_symbol_id": None,
            "target_file": None,
            "confidence": 0.0,
            "evidence": [],
            "conflict_reason": "no-repository-edge",
            "resolution_rule": "no-candidate",
            "depends_on_lsp": False,
        }

    def explain_resolution(
        self,
        project_id: str,
        path: str,
        edge_id: str,
        *,
        fused_result: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Return an explainable breakdown of a resolution.

        When ``fused_result`` is provided, explains the fused resolution.
        Otherwise, explains the repository resolution for the given edge.
        """
        if fused_result is not None:
            return {
                "original_status": fused_result.get("original_status"),
                "fused_status": fused_result.get("fused_status"),
                "confidence": fused_result.get("confidence"),
                "resolution_rule": fused_result.get("resolution_rule"),
                "conflict_reason": fused_result.get("conflict_reason"),
                "depends_on_lsp": fused_result.get("depends_on_lsp", False),
                "target_symbol_id": fused_result.get("target_symbol_id"),
                "target_file": fused_result.get("target_file"),
                "evidence_count": len(fused_result.get("evidence", [])),
                "evidence_sources": [e.get("source") for e in fused_result.get("evidence", [])],
                "evidence": fused_result.get("evidence", []),
            }
        edges = self.call_edges_for_file(project_id, path)
        for edge in edges:
            if edge.get("edge_id") == edge_id:
                return {
                    "original_status": edge["status"],
                    "fused_status": edge["status"],
                    "confidence": edge.get("confidence"),
                    "resolution_rule": edge.get("resolution_rule", ""),
                    "conflict_reason": edge.get("ambiguity_reason"),
                    "depends_on_lsp": False,
                    "target_symbol_id": edge.get("target_symbol_id"),
                    "target_file": edge.get("target_file"),
                    "evidence_count": 0,
                    "evidence_sources": [],
                    "evidence": [],
                }
        return {"error": "edge-not-found", "edge_id": edge_id}

    def resolution_evidence(
        self,
        project_id: str,
        path: str,
        *,
        fusion_service: Any | None = None,
    ) -> list[dict[str, Any]]:
        """Return all evidence for unresolved/ambiguous edges in a file.

        This is a convenience method for auditing which edges have LSP
        evidence available. When no fusion service is bound, returns the
        repository resolution edges with empty evidence lists.
        """
        edges = self.call_edges_for_file(project_id, path)
        results: list[dict[str, Any]] = []
        for edge in edges:
            if edge["status"] in ("unresolved", "ambiguous"):
                results.append({
                    "edge_id": edge["edge_id"],
                    "callee": edge["call_callee"],
                    "status": edge["status"],
                    "resolution_rule": edge.get("resolution_rule", ""),
                    "evidence": [],
                    "depends_on_lsp": False,
                })
        return results
