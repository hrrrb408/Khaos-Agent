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
        target_languages: set[str] | None = None,
        max_results: int = 50,
        max_sql_queries: int = 10,
        max_indexed_rows: int = 200,
    ) -> "tuple":
        """Bounded test-file association lookup — never scans the whole repository.

        Uses a SINGLE remaining budget shared across ALL query sources:
        ``remaining_candidates``, ``remaining_sql_queries``, ``remaining_indexed_rows``.
        Each query's LIMIT is set to ``min(remaining_candidates, remaining_indexed_rows)``,
        so neither per-candidate nor per-row budget can be exceeded.

        Evidence priority (each level checks remaining budget BEFORE running):
        1. Resolved graph edges (import/call/reference) where the source file
           has ``path_role='test'`` — uses indexed joins on target_file/target_symbol_id.
           Cross-language edges are retained as resolved evidence.
        2. Subject/module key match — indexed equality on computed keys.
           LANGUAGE-ISOLATED: only test files whose language is compatible with
           ``target_languages`` are accepted. The package_key column is reserved
           for future use and is NOT queried in this priority level.

        EXPLAIN QUERY PLAN queries are NOT counted in ``sql_queries_issued`` —
        they are audit-only and excluded from the budget.

        Returns a :class:`TestAssociationResult` with full query cost evidence
        and coverage fields (``has_resolved_test_coverage``, ``possible_test_coverage``).
        """
        from khaos.coding.planning.contracts import TestAssociationResult

        # --- Resolve target languages from code_files if not provided ---
        if target_languages is None and target_files:
            placeholders = ",".join("?" * len(target_files))
            try:
                lang_rows = self.store._conn.execute(
                    f"SELECT DISTINCT language FROM code_files WHERE project_id=? AND path IN ({placeholders})",
                    (repository_id, *target_files),
                ).fetchall()
                target_languages = {str(r[0]) for r in lang_rows if r[0]}
            except sqlite3.OperationalError:
                target_languages = set()
        if target_languages is None:
            target_languages = set()

        # --- Build language compatibility set for heuristic queries ---
        # JS and TypeScript are in the same compatibility group (TS is a
        # superset of JS; they share test tooling). All other languages are
        # strictly isolated — a Go test never associates with a Python target.
        _JS_TS_GROUP = {"javascript", "typescript"}
        heuristic_langs: set[str] = set()
        for lang in target_languages:
            if lang in _JS_TS_GROUP:
                heuristic_langs |= _JS_TS_GROUP
            else:
                heuristic_langs.add(lang)

        remaining_candidates = max_results
        remaining_sql_queries = max_sql_queries
        remaining_indexed_rows = max_indexed_rows
        limit_code: str | None = None

        candidates: list[dict[str, Any]] = []
        seen_paths: set[str] = set()
        evidence_sources: list[str] = []
        sql_queries_issued = 0
        sql_rows_returned = 0
        indexed_edge_rows_fetched = 0
        query_plans: list[str] = []
        has_resolved_test_coverage = False

        def _explain(sql: str, params: tuple) -> str:
            """Run EXPLAIN QUERY PLAN and return a compact string. Not counted in budget."""
            try:
                plan_rows = self.store._conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()
                return " | ".join(str(r[3]) for r in plan_rows)
            except sqlite3.Error:
                return "explain-failed"

        def _query_limit() -> int:
            """Per-query LIMIT = min(remaining_candidates, remaining_indexed_rows)."""
            return min(remaining_candidates, remaining_indexed_rows)

        def _can_continue() -> bool:
            return (remaining_candidates > 0
                    and remaining_sql_queries > 0
                    and remaining_indexed_rows > 0
                    and _query_limit() > 0)

        def _set_limit(code: str) -> None:
            nonlocal limit_code
            if limit_code is None:
                limit_code = code

        def _after_query(rows_returned: int) -> None:
            """Decrement budgets after a query returns rows."""
            nonlocal remaining_sql_queries, remaining_indexed_rows
            remaining_sql_queries -= 1
            remaining_indexed_rows -= rows_returned

        def _accept_candidate(path: str, candidate: dict[str, Any], resolved: bool) -> None:
            nonlocal remaining_candidates, has_resolved_test_coverage
            if path not in seen_paths:
                seen_paths.add(path)
                candidates.append(candidate)
                remaining_candidates -= 1
                if resolved:
                    has_resolved_test_coverage = True

        # --- Priority 1: Resolved graph edges where source is a test file ---
        # Each sub-query uses LIMIT = min(remaining_candidates, remaining_indexed_rows).
        # Cross-language resolved edges are retained (real graph evidence).
        if _can_continue() and target_files:
            ql = _query_limit()
            placeholders = ",".join("?" * len(target_files))
            sql = (
                f"SELECT DISTINCT ri.source_file, ri.target_file, ri.confidence, ri.reason, 'import' AS edge_type "
                f"FROM resolved_imports ri "
                f"INNER JOIN code_files cf ON cf.project_id = ri.repository_id AND cf.path = ri.source_file "
                f"WHERE ri.repository_id = ? AND ri.target_file IN ({placeholders}) AND cf.path_role = 'test' "
                f"ORDER BY ri.source_file LIMIT ?"
            )
            params = (repository_id, *target_files, ql)
            query_plans.append(f"P1-import: {_explain(sql, params)}")
            try:
                rows = self.store._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:
                # resolved_imports table may not exist if resolution hasn't run
                rows = []
            else:
                sql_queries_issued += 1
                sql_rows_returned += len(rows)
                indexed_edge_rows_fetched += len(rows)
                _after_query(len(rows))
            for row in rows:
                path = str(row[0])
                _accept_candidate(path, {"path": path, "target_file": row[1], "confidence": float(row[2]),
                                         "reason": str(row[3]), "edge_type": "import", "source": "resolution-graph"},
                                  resolved=True)
            if rows:
                evidence_sources.append("resolved-imports")
            if not _can_continue():
                _set_limit("max_candidates" if remaining_candidates <= 0
                           else "max_sql_queries" if remaining_sql_queries <= 0
                           else "max_indexed_rows")

        if _can_continue() and target_symbols:
            placeholders = ",".join("?" * len(target_symbols))
            for table, kind in (("resolved_call_edges", "call"), ("resolved_reference_edges", "reference")):
                if not _can_continue():
                    break
                ql = _query_limit()
                sql = (
                    f"SELECT DISTINCT e.source_file, e.target_file, e.target_symbol_id, e.confidence, e.resolution_rule, '{kind}' AS edge_type "
                    f"FROM {table} e "
                    f"INNER JOIN code_files cf ON cf.project_id = e.repository_id AND cf.path = e.source_file "
                    f"WHERE e.repository_id = ? AND e.target_symbol_id IN ({placeholders}) AND cf.path_role = 'test' "
                    f"ORDER BY e.source_file LIMIT ?"
                )
                params = (repository_id, *target_symbols, ql)
                query_plans.append(f"P1-{kind}: {_explain(sql, params)}")
                try:
                    rows = self.store._conn.execute(sql, params).fetchall()
                except sqlite3.OperationalError:
                    # resolved_{call,reference}_edges table may not exist
                    rows = []
                else:
                    sql_queries_issued += 1
                    sql_rows_returned += len(rows)
                    indexed_edge_rows_fetched += len(rows)
                    _after_query(len(rows))
                for row in rows:
                    path = str(row[0])
                    _accept_candidate(path, {"path": path, "target_file": row[1], "confidence": float(row[3]),
                                             "reason": str(row[4]), "edge_type": kind, "source": "resolution-graph"},
                                      resolved=True)
                if rows:
                    evidence_sources.append(f"resolved-{kind}-edges")
                if not _can_continue():
                    _set_limit("max_candidates" if remaining_candidates <= 0
                               else "max_sql_queries" if remaining_sql_queries <= 0
                               else "max_indexed_rows")

        # --- Priority 2: Subject/module key match (target-related, language-isolated) ---
        # Replaces the old "any test file via path_role" fallback.
        # Only test files whose subject/module key matches a target AND whose
        # language is compatible with target_languages are accepted.
        # NOTE: package_key is NOT queried here — the column and index are
        # reserved for future use but not part of the current heuristic.
        if _can_continue() and target_files and heuristic_langs:
            target_subjects = set()
            target_modules = set()
            for tf in target_files:
                normalized = tf.replace("\\", "/")
                filename = normalized.split("/")[-1]
                stem = filename.rsplit(".", 1)[0] if "." in filename else filename
                target_subjects.add(stem)
                module_key = normalized.rsplit(".", 1)[0] if "." in normalized else normalized
                target_modules.add(module_key)
            placeholders_subj = ",".join("?" * len(target_subjects))
            placeholders_mod = ",".join("?" * len(target_modules))
            placeholders_lang = ",".join("?" * len(heuristic_langs))
            ql = _query_limit()
            sql = (
                f"SELECT path, language, content_hash, generation, test_subject_key, module_key "
                f"FROM code_files "
                f"WHERE project_id = ? AND path_role = 'test' "
                f"AND language IN ({placeholders_lang}) "
                f"AND (test_subject_key IN ({placeholders_subj}) OR module_key IN ({placeholders_mod})) "
                f"ORDER BY path LIMIT ?"
            )
            params = (repository_id, *heuristic_langs, *target_subjects, *target_modules, ql)
            query_plans.append(f"P2-subject-key: {_explain(sql, params)}")
            try:
                rows = self.store._conn.execute(sql, params).fetchall()
            except sqlite3.OperationalError:
                # Columns not yet migrated — skip P2 gracefully
                rows = []
            else:
                sql_queries_issued += 1
                sql_rows_returned += len(rows)
                indexed_edge_rows_fetched += len(rows)
                _after_query(len(rows))
            for row in rows:
                path = str(row[0])
                subject_match = str(row[4]) in target_subjects if row[4] else False
                module_match = str(row[5]) in target_modules if row[5] else False
                if subject_match or module_match:
                    _accept_candidate(path, {"path": path, "language": row[1], "content_hash": row[2],
                                             "generation": row[3], "confidence": 0.4,
                                             "reason": "subject/module key match", "edge_type": "subject-key",
                                             "source": "subject-key-match"},
                                      resolved=False)
            if rows:
                evidence_sources.append("subject-key-match")
            if not _can_continue():
                _set_limit("max_candidates" if remaining_candidates <= 0
                           else "max_sql_queries" if remaining_sql_queries <= 0
                           else "max_indexed_rows")

        # Final fallback: if budget was already exhausted at start (e.g. max_sql_queries=0)
        # and no query ran to set limit_code, set it now.
        if limit_code is None and not _can_continue():
            _set_limit("max_candidates" if remaining_candidates <= 0
                       else "max_sql_queries" if remaining_sql_queries <= 0
                       else "max_indexed_rows")

        possible_test_coverage = bool(candidates) and not has_resolved_test_coverage
        truncated = limit_code is not None
        candidates.sort(key=lambda c: (c.get("path", ""), c.get("edge_type", "")))
        return TestAssociationResult(
            candidates=tuple(candidates[:max_results]),
            status="possible",
            confidence=0.5,
            inspected_candidates=sql_rows_returned,
            max_candidates=max_results,
            evidence_sources=tuple(sorted(set(evidence_sources))),
            truncated=truncated,
            sql_queries_issued=sql_queries_issued,
            sql_rows_returned=sql_rows_returned,
            indexed_edge_rows_fetched=indexed_edge_rows_fetched,
            query_plans=tuple(query_plans),
            fetch_budget=max_indexed_rows,
            limit_code=limit_code,
            has_resolved_test_coverage=has_resolved_test_coverage,
            possible_test_coverage=possible_test_coverage,
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
