"""Structured query facade over the persistent index."""

from __future__ import annotations

from pathlib import Path

from khaos.coding.intelligence.index import IndexStore


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
