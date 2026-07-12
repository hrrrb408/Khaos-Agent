"""Structured query facade over the persistent index.

Old query methods (find_symbols, find_definition, find_dependencies)
continue to work unchanged. New methods operate on the persisted
semantic resolution graph.
"""

from __future__ import annotations

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
