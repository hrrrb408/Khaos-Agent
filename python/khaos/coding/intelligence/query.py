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
