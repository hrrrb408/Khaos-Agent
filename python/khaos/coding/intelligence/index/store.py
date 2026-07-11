"""SQLite-backed incremental symbol index."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.registry import LanguageRegistry


SCHEMA = """
CREATE TABLE IF NOT EXISTS code_files (project_id TEXT NOT NULL, path TEXT NOT NULL,
 language TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
 content_hash TEXT NOT NULL, parser_version TEXT NOT NULL, PRIMARY KEY(project_id, path));
CREATE TABLE IF NOT EXISTS code_symbols (project_id TEXT NOT NULL, path TEXT NOT NULL,
 name TEXT NOT NULL, kind TEXT NOT NULL, line INTEGER NOT NULL, signature TEXT,
 source TEXT NOT NULL, PRIMARY KEY(project_id, path, name, line));
CREATE TABLE IF NOT EXISTS code_imports (project_id TEXT NOT NULL, path TEXT NOT NULL,
 import_name TEXT NOT NULL, PRIMARY KEY(project_id, path, import_name));
CREATE INDEX IF NOT EXISTS idx_code_symbols_name ON code_symbols(project_id, name);
"""


class IndexStore:
    """Maintain a project index with atomic per-file refreshes."""

    def __init__(self, database: sqlite3.Connection | str | Path) -> None:
        self._conn = database if isinstance(database, sqlite3.Connection) else sqlite3.connect(str(database))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()
        self._lock = asyncio.Lock()
        self._registry = LanguageRegistry()

    async def close(self) -> None:
        await asyncio.to_thread(self._conn.close)

    async def refresh(self, project_id: str, paths: list[Path], *, force: bool = False) -> dict[str, int]:
        changed = skipped = failed = 0
        async with self._lock:
            for path in paths:
                try:
                    if await self._refresh_file(project_id, path, force=force):
                        changed += 1
                    else:
                        skipped += 1
                except (OSError, UnicodeError, sqlite3.DatabaseError):
                    failed += 1
            self._conn.commit()
        return {"changed": changed, "skipped": skipped, "failed": failed}

    async def _refresh_file(self, project_id: str, path: Path, *, force: bool) -> bool:
        resolved = path.expanduser().resolve()
        adapter = self._registry.for_path(resolved)
        if adapter is None or not resolved.is_file():
            await self.remove(project_id, resolved)
            return False
        stat = resolved.stat()
        content = resolved.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        existing = self._conn.execute("SELECT size, mtime_ns, content_hash FROM code_files WHERE project_id=? AND path=?", (project_id, str(resolved))).fetchone()
        if not force and existing and existing["size"] == stat.st_size and existing["mtime_ns"] == stat.st_mtime_ns and existing["content_hash"] == digest:
            return False
        parsed = adapter.parse(resolved, content)
        self._conn.execute("DELETE FROM code_symbols WHERE project_id=? AND path=?", (project_id, str(resolved)))
        self._conn.execute("DELETE FROM code_imports WHERE project_id=? AND path=?", (project_id, str(resolved)))
        self._conn.execute("DELETE FROM code_files WHERE project_id=? AND path=?", (project_id, str(resolved)))
        self._conn.execute("INSERT INTO code_files VALUES (?, ?, ?, ?, ?, ?, ?)", (project_id, str(resolved), parsed.language, stat.st_size, stat.st_mtime_ns, digest, parsed.parser_version))
        self._conn.executemany("INSERT INTO code_symbols VALUES (?, ?, ?, ?, ?, ?, ?)", [(project_id, str(resolved), str(item.get("name", "")), str(item.get("kind", "unknown")), int(item.get("line", 0)), item.get("signature"), "legacy") for item in parsed.symbols])
        self._conn.executemany("INSERT INTO code_imports VALUES (?, ?, ?)", [(project_id, str(resolved), item.module) for item in parsed.imports])
        return True

    async def remove(self, project_id: str, path: Path) -> None:
        async with self._lock:
            self._conn.execute("DELETE FROM code_symbols WHERE project_id=? AND path=?", (project_id, str(path.expanduser().resolve())))
            self._conn.execute("DELETE FROM code_imports WHERE project_id=? AND path=?", (project_id, str(path.expanduser().resolve())))
            self._conn.execute("DELETE FROM code_files WHERE project_id=? AND path=?", (project_id, str(path.expanduser().resolve())))
            self._conn.commit()

    async def find_symbols(self, project_id: str, query: str, *, limit: int = 50) -> list[dict[str, Any]]:
        async with self._lock:
            rows = self._conn.execute("SELECT project_id, path, name, kind, line, signature, source FROM code_symbols WHERE project_id=? AND name LIKE ? ORDER BY name, path, line LIMIT ?", (project_id, f"%{query}%", limit)).fetchall()
            return [dict(row) for row in rows]

    async def imports_for(self, project_id: str, path: Path) -> list[str]:
        async with self._lock:
            rows = self._conn.execute("SELECT import_name FROM code_imports WHERE project_id=? AND path=? ORDER BY import_name", (project_id, str(path.expanduser().resolve()))).fetchall()
            return [str(row[0]) for row in rows]
