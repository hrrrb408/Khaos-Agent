"""SQLite-backed atomic per-file code intelligence index."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.models import ParseResult
from khaos.coding.intelligence.registry import LanguageRegistry


SCHEMA = """
CREATE TABLE IF NOT EXISTS code_files (project_id TEXT NOT NULL, path TEXT NOT NULL,
 language TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
 content_hash TEXT NOT NULL, parser_version TEXT NOT NULL, parser_source TEXT NOT NULL DEFAULT 'legacy',
 metadata_json TEXT NOT NULL DEFAULT '{}', indexed_at REAL NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(project_id, path));
CREATE TABLE IF NOT EXISTS code_symbols (project_id TEXT NOT NULL, path TEXT NOT NULL,
 name TEXT NOT NULL, kind TEXT NOT NULL, line INTEGER NOT NULL, signature TEXT,
 source TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(project_id, path, name, line));
CREATE TABLE IF NOT EXISTS code_imports (project_id TEXT NOT NULL, path TEXT NOT NULL,
 import_name TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(project_id, path, import_name));
CREATE TABLE IF NOT EXISTS code_calls (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE TABLE IF NOT EXISTS code_references (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE TABLE IF NOT EXISTS code_diagnostics (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json TEXT NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE INDEX IF NOT EXISTS idx_code_symbols_name ON code_symbols(project_id, name);
"""


class IndexStore:
    def __init__(self, database: sqlite3.Connection | str | Path) -> None:
        self._conn = database if isinstance(database, sqlite3.Connection) else sqlite3.connect(str(database), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()
        self._lock = asyncio.Lock()
        self._registry = LanguageRegistry()
        self._closed = False

    def _migrate(self) -> None:
        self._conn.executescript(SCHEMA)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(code_files)")}
        additions = {"parser_source": "TEXT NOT NULL DEFAULT 'legacy'", "metadata_json": "TEXT NOT NULL DEFAULT '{}'", "indexed_at": "REAL NOT NULL DEFAULT 0", "generation": "INTEGER NOT NULL DEFAULT 0"}
        for name, declaration in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE code_files ADD COLUMN {name} {declaration}")
        for table, column in (("code_symbols", "payload_json"), ("code_imports", "payload_json")):
            if column not in {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT NOT NULL DEFAULT '{{}}'")
        self._conn.commit()

    async def close(self) -> None:
        self._closed = True
        await asyncio.to_thread(self._conn.close)

    async def file_record(self, project_id: str, path: str | Path) -> dict[str, Any] | None:
        normalized = str(path)
        async with self._lock:
            row = self._conn.execute("SELECT * FROM code_files WHERE project_id=? AND path=?", (project_id, normalized)).fetchone()
            return dict(row) if row else None

    async def indexed_paths(self, project_id: str) -> set[str]:
        async with self._lock:
            return {str(row[0]) for row in self._conn.execute("SELECT path FROM code_files WHERE project_id=?", (project_id,)).fetchall()}

    async def write_parse_result(self, project_id: str, path: str, result: ParseResult, *, size: int, mtime_ns: int, generation: int) -> None:
        safe = result.to_dict(include_duration=True)
        metadata_json = json.dumps({"parser_source": result.parser_source, "parser_version": result.parser_version, "metadata": safe["metadata"], "diagnostics": safe["diagnostics"]}, ensure_ascii=False, sort_keys=True)
        async with self._lock:
            if self._closed:
                raise RuntimeError("IndexStore is closed")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                for table in ("code_symbols", "code_imports", "code_calls", "code_references", "code_diagnostics", "code_files"):
                    self._conn.execute(f"DELETE FROM {table} WHERE project_id=? AND path=?", (project_id, path))
                self._conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?)", (project_id, path, result.language, size, mtime_ns, result.content_hash, result.parser_version, result.parser_source, metadata_json, time.time(), generation))
                self._conn.executemany("INSERT INTO code_symbols VALUES (?,?,?,?,?,?,?,?)", [(project_id, path, item.name, item.kind, item.location.start_line + 1, item.metadata.get("signature"), item.source, json.dumps(item_to_dict(item), ensure_ascii=False, sort_keys=True)) for item in result.symbols])
                self._conn.executemany("INSERT INTO code_imports VALUES (?,?,?,?)", [(project_id, path, item.module, json.dumps(item_to_dict(item), ensure_ascii=False, sort_keys=True)) for item in result.imports])
                for table, items in (("code_calls", result.calls), ("code_references", result.references), ("code_diagnostics", result.diagnostics)):
                    self._conn.executemany(f"INSERT INTO {table} VALUES (?,?,?,?)", [(project_id, path, index, json.dumps(item_to_dict(item), ensure_ascii=False, sort_keys=True)) for index, item in enumerate(items)])
                self._conn.commit()
            except (sqlite3.DatabaseError, TypeError, ValueError):
                self._conn.rollback()
                raise

    async def refresh(self, project_id: str, paths: list[Path], *, force: bool = False) -> dict[str, int]:
        changed = skipped = failed = 0
        for source in paths:
            try:
                resolved = source.expanduser().resolve()
                if not resolved.is_file() or self._registry.resolve(resolved).supported is False:
                    await self.remove(project_id, resolved)
                    skipped += 1
                    continue
                content = resolved.read_bytes(); stat = resolved.stat(); digest = hashlib.sha256(content).hexdigest()
                existing = await self.file_record(project_id, str(resolved))
                if not force and existing and existing["content_hash"] == digest:
                    skipped += 1; continue
                result = self._registry.parse(file_path=str(resolved), content=content)
                await self.write_parse_result(project_id, str(resolved), result, size=len(content), mtime_ns=stat.st_mtime_ns, generation=int(existing["generation"] + 1) if existing else 1)
                changed += 1
            except (OSError, UnicodeError, sqlite3.DatabaseError, RuntimeError):
                failed += 1
        return {"changed": changed, "skipped": skipped, "failed": failed}

    async def remove(self, project_id: str, path: str | Path) -> None:
        normalized = str(path.expanduser().resolve()) if isinstance(path, Path) else str(path)
        async with self._lock:
            for table in ("code_symbols", "code_imports", "code_calls", "code_references", "code_diagnostics", "code_files"):
                self._conn.execute(f"DELETE FROM {table} WHERE project_id=? AND path=?", (project_id, normalized))
            self._conn.commit()

    async def find_symbols(self, project_id: str, query: str, *, limit: int = 50) -> list[dict[str, Any]]:
        async with self._lock:
            rows = self._conn.execute("SELECT project_id,path,name,kind,line,signature,source FROM code_symbols WHERE project_id=? AND name LIKE ? ORDER BY name,path,line LIMIT ?", (project_id, f"%{query}%", limit)).fetchall()
            return [dict(row) for row in rows]

    async def imports_for(self, project_id: str, path: Path) -> list[str]:
        candidates = (str(path), str(path.expanduser().resolve()))
        async with self._lock:
            rows = self._conn.execute("SELECT import_name FROM code_imports WHERE project_id=? AND path IN (?,?) ORDER BY import_name", (project_id, *candidates)).fetchall()
            return [str(row[0]) for row in rows]

    async def semantic_counts(self, project_id: str, path: str) -> dict[str, int]:
        async with self._lock:
            return {table: int(self._conn.execute(f"SELECT COUNT(*) FROM {table} WHERE project_id=? AND path=?", (project_id, path)).fetchone()[0]) for table in ("code_symbols", "code_imports", "code_calls", "code_references", "code_diagnostics")}


def item_to_dict(item: Any) -> dict[str, Any]:
    from dataclasses import asdict
    return asdict(item)
