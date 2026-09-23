"""SQLite-backed atomic per-file code intelligence index."""
from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

from khaos.coding.intelligence.models import ParseResult
from khaos.coding.intelligence.registry import LanguageRegistry
from khaos.security.protocol_boundary import canonical_digest

SCHEMA = """
CREATE TABLE IF NOT EXISTS code_files (project_id TEXT NOT NULL, path TEXT NOT NULL,
 language TEXT NOT NULL, size INTEGER NOT NULL, mtime_ns INTEGER NOT NULL,
 content_hash TEXT NOT NULL, parser_version TEXT NOT NULL, parser_source TEXT NOT NULL DEFAULT 'legacy',
 metadata_json TEXT NOT NULL DEFAULT '{}', indexed_at REAL NOT NULL DEFAULT 0, generation INTEGER NOT NULL DEFAULT 0,
 path_role TEXT NOT NULL DEFAULT 'source',
 test_subject_key TEXT NOT NULL DEFAULT '',
 module_key TEXT NOT NULL DEFAULT '',
 package_key TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(project_id, path));
CREATE TABLE IF NOT EXISTS code_symbols (project_id TEXT NOT NULL, path TEXT NOT NULL,
 name TEXT NOT NULL, kind TEXT NOT NULL, line INTEGER NOT NULL, signature TEXT,
 source TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(project_id, path, name, line));
CREATE TABLE IF NOT EXISTS code_imports (project_id TEXT NOT NULL, path TEXT NOT NULL,
 import_name TEXT NOT NULL, payload_json TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(project_id, path, import_name));
CREATE TABLE IF NOT EXISTS code_calls (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE TABLE IF NOT EXISTS code_references (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE TABLE IF NOT EXISTS code_diagnostics (project_id TEXT NOT NULL, path TEXT NOT NULL, ordinal INTEGER NOT NULL, payload_json NOT NULL, PRIMARY KEY(project_id,path,ordinal));
CREATE INDEX IF NOT EXISTS idx_code_symbols_name ON code_symbols(project_id, name);

-- M8.1: durable owner-scoped repository generation state.  This is derived
-- intelligence metadata only; it is never read by Permission, Approval,
-- Verification, Recovery, Router, or Completion authority.
CREATE TABLE IF NOT EXISTS repo_intelligence_state (
 workspace_id TEXT NOT NULL,
 repository_id TEXT NOT NULL,
 index_project_id TEXT NOT NULL,
 generation INTEGER NOT NULL,
 manifest_digest TEXT NOT NULL,
 freshness TEXT NOT NULL,
 source_revision TEXT,
 root_identity TEXT NOT NULL,
 pending_paths_json TEXT NOT NULL DEFAULT '[]',
 full_refresh_required INTEGER NOT NULL DEFAULT 0,
 indexed_at REAL NOT NULL DEFAULT 0,
 PRIMARY KEY(workspace_id, repository_id)
);
CREATE INDEX IF NOT EXISTS idx_repo_intelligence_state_project
 ON repo_intelligence_state(index_project_id);
"""


class IndexStore:
    def __init__(self, database: sqlite3.Connection | str | Path) -> None:
        self._conn = database if isinstance(database, sqlite3.Connection) else sqlite3.connect(str(database), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._migrate()
        self._lock = asyncio.Lock()
        self._sync_lock = threading.RLock()
        self._registry = LanguageRegistry()
        self._closed = False

    def _migrate(self) -> None:
        self._conn.executescript(SCHEMA)
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(code_files)")}
        additions = {
            "parser_source": "TEXT NOT NULL DEFAULT 'legacy'",
            "metadata_json": "TEXT NOT NULL DEFAULT '{}'",
            "indexed_at": "REAL NOT NULL DEFAULT 0",
            "generation": "INTEGER NOT NULL DEFAULT 0",
            "path_role": "TEXT NOT NULL DEFAULT 'source'",
            "test_subject_key": "TEXT NOT NULL DEFAULT ''",
            "module_key": "TEXT NOT NULL DEFAULT ''",
            "package_key": "TEXT NOT NULL DEFAULT ''",
        }
        for name, declaration in additions.items():
            if name not in columns:
                self._conn.execute(f"ALTER TABLE code_files ADD COLUMN {name} {declaration}")
        # Ensure indexes exist even on pre-existing databases
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_code_files_role ON code_files(project_id, path_role)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_code_files_subject ON code_files(project_id, test_subject_key)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_code_files_module ON code_files(project_id, module_key)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_code_files_package ON code_files(project_id, package_key)")
        for table, column in (("code_symbols", "payload_json"), ("code_imports", "payload_json")):
            if column not in {row[1] for row in self._conn.execute(f"PRAGMA table_info({table})")}:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT NOT NULL DEFAULT '{{}}'")
        # --- Idempotent backfill migration for path_role and key columns ---
        # Old databases that had rows before path_role/test_subject_key/module_key/
        # package_key were added need backfill so associated_tests() works
        # without requiring a full reindex.
        # PRAGMA user_version tracks whether backfill has run:
        #   0 = not yet backfilled
        #   1 = path_role + keys backfilled
        current_version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if current_version < 1:
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                rows = self._conn.execute("SELECT path FROM code_files").fetchall()
                for row in rows:
                    path = row[0]
                    role = _classify_path_role(path)
                    subject = _compute_test_subject_key(path)
                    module = _compute_module_key(path)
                    package = _compute_package_key(path)
                    self._conn.execute(
                        "UPDATE code_files SET path_role=?, test_subject_key=?, module_key=?, package_key=? WHERE path=?",
                        (role, subject, module, package, path),
                    )
                self._conn.execute("PRAGMA user_version = 1")
                self._conn.commit()
            except sqlite3.DatabaseError:
                self._conn.rollback()
                raise
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
        path_role = _classify_path_role(path)
        test_subject_key = _compute_test_subject_key(path)
        module_key = _compute_module_key(path)
        package_key = _compute_package_key(path)
        async with self._lock:
            if self._closed:
                raise RuntimeError("IndexStore is closed")
            try:
                self._conn.execute("BEGIN IMMEDIATE")
                for table in ("code_symbols", "code_imports", "code_calls", "code_references", "code_diagnostics", "code_files"):
                    self._conn.execute(f"DELETE FROM {table} WHERE project_id=? AND path=?", (project_id, path))
                self._conn.execute("INSERT INTO code_files VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (project_id, path, result.language, size, mtime_ns, result.content_hash, result.parser_version, result.parser_source, metadata_json, time.time(), generation, path_role, test_subject_key, module_key, package_key))
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

    async def file_records(
        self,
        project_id: str,
        *,
        paths: tuple[str, ...] = (),
        limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Return bounded indexed file metadata for intelligence consumers."""
        if type(limit) is not int or limit <= 0:
            raise ValueError("file record limit must be positive")
        async with self._lock:
            if paths:
                placeholders = ",".join("?" for _ in paths)
                rows = self._conn.execute(
                    f"SELECT * FROM code_files WHERE project_id=? AND path IN ({placeholders}) ORDER BY path LIMIT ?",
                    (project_id, *paths, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM code_files WHERE project_id=? ORDER BY path LIMIT ?",
                    (project_id, limit),
                ).fetchall()
            return [dict(row) for row in rows]

    async def symbol_records(
        self,
        project_id: str,
        *,
        query: str = "",
        exact_name: str | None = None,
        paths: tuple[str, ...] = (),
        path_prefix: str = "",
        path_glob: str = "*",
        limit: int = 256,
    ) -> list[dict[str, Any]]:
        """Return indexed semantic symbols with a bounded result set."""
        if type(limit) is not int or limit <= 0:
            raise ValueError("symbol record limit must be positive")
        async with self._lock:
            clauses = ["project_id=?"]
            params: list[object] = [project_id]
            if exact_name is not None:
                clauses.append("name=?")
                params.append(exact_name)
            elif query:
                clauses.append("name LIKE ?")
                params.append(f"%{query}%")
            if paths:
                placeholders = ",".join("?" for _ in paths)
                clauses.append(f"path IN ({placeholders})")
                params.extend(paths)
            if path_prefix:
                clauses.append("(path=? OR substr(path, 1, ?) = ?)")
                params.extend(
                    (path_prefix, len(path_prefix) + 1, f"{path_prefix}/")
                )
            if path_glob != "*":
                glob_prefix = f"{path_prefix.rstrip('/')}/" if path_prefix else ""
                clauses.append("path GLOB ?")
                params.append(f"{glob_prefix}{path_glob}")
            rows = self._conn.execute(
                "SELECT project_id,path,name,kind,line,signature,source,payload_json "
                f"FROM code_symbols WHERE {' AND '.join(clauses)} ORDER BY path,line,name LIMIT ?",
                (*params, limit),
            ).fetchall()
            return [dict(row) for row in rows]

    async def manifest_digest(self, project_id: str) -> str:
        """Digest only persisted index metadata, never a host-path walk."""
        async with self._lock:
            rows = self._conn.execute(
                "SELECT path,language,size,mtime_ns,content_hash,parser_version,parser_source,generation "
                "FROM code_files WHERE project_id=? ORDER BY path",
                (project_id,),
            ).fetchall()
            return canonical_digest(
                [
                    {
                        "path": str(row[0]),
                        "language": str(row[1]),
                        "size": int(row[2]),
                        "mtime_ns": int(row[3]),
                        "content_hash": str(row[4]),
                        "parser_version": str(row[5]),
                        "parser_source": str(row[6]),
                        "generation": int(row[7]),
                    }
                    for row in rows
                ]
            )

    async def semantic_generation_gaps(self, project_id: str) -> int:
        """Count indexed files without an exact persisted resolution marker."""
        async with self._lock:
            row = self._conn.execute(
                """
                SELECT COUNT(*)
                FROM code_files AS files
                LEFT JOIN resolution_generation AS resolutions
                  ON resolutions.repository_id=?
                 AND resolutions.source_file=files.path
                WHERE files.project_id=?
                  AND files.parser_source NOT IN
                      ('metadata', 'rejected', 'unavailable', 'unknown', 'legacy')
                  AND (
                    resolutions.source_file IS NULL
                    OR resolutions.generation != files.generation
                  )
                """,
                (project_id, project_id),
            ).fetchone()
            return int(row[0])

    async def semantic_integrity_gaps(self, project_id: str) -> int:
        """Count semantic rows that cannot be reconciled to the parse index.

        The repository generation projection is only trusted when the parse
        rows, symbol graph, resolution markers, and resolved edges describe
        the same file generations.  This check is deliberately conservative:
        any missing or dangling semantic row causes the next current query to
        rebuild from the bounded source index.
        """
        async with self._lock:
            total = 0
            row = self._conn.execute(
                """
                SELECT COUNT(*)
                FROM code_symbols AS code
                LEFT JOIN repository_symbols AS resolved
                  ON resolved.repository_id=?
                 AND resolved.path=code.path
                 AND resolved.name=code.name
                 AND resolved.start_line=code.line-1
                WHERE code.project_id=? AND resolved.symbol_id IS NULL
                """,
                (project_id, project_id),
            ).fetchone()
            total += int(row[0])
            row = self._conn.execute(
                """
                SELECT COUNT(*)
                FROM repository_symbols AS resolved
                LEFT JOIN code_symbols AS code
                  ON code.project_id=?
                 AND code.path=resolved.path
                 AND code.name=resolved.name
                 AND code.line=resolved.start_line+1
                WHERE resolved.repository_id=? AND code.name IS NULL
                """,
                (project_id, project_id),
            ).fetchone()
            total += int(row[0])
            row = self._conn.execute(
                """
                SELECT COUNT(*)
                FROM repository_symbols AS resolved
                JOIN code_files AS files
                  ON files.project_id=? AND files.path=resolved.path
                WHERE resolved.repository_id=?
                  AND resolved.generation != files.generation
                """,
                (project_id, project_id),
            ).fetchone()
            total += int(row[0])
            row = self._conn.execute(
                """
                SELECT COUNT(*)
                FROM resolution_generation AS markers
                LEFT JOIN code_files AS files
                  ON files.project_id=? AND files.path=markers.source_file
                WHERE markers.repository_id=? AND files.path IS NULL
                """,
                (project_id, project_id),
            ).fetchone()
            total += int(row[0])
            for table in (
                "resolved_imports",
                "resolved_call_edges",
                "resolved_reference_edges",
            ):
                row = self._conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM {table} AS edges
                    LEFT JOIN code_files AS files
                      ON files.project_id=? AND files.path=edges.source_file
                    WHERE edges.repository_id=?
                      AND (
                        files.path IS NULL
                        OR edges.generation != files.generation
                      )
                    """,
                    (project_id, project_id),
                ).fetchone()
                total += int(row[0])
                row = self._conn.execute(
                    f"""
                    SELECT COUNT(*)
                    FROM {table} AS edges
                    LEFT JOIN repository_symbols AS targets
                      ON targets.repository_id=?
                     AND targets.stable_symbol_id=edges.target_symbol_id
                    WHERE edges.repository_id=?
                      AND edges.target_symbol_id IS NOT NULL
                      AND targets.symbol_id IS NULL
                    """,
                    (project_id, project_id),
                ).fetchone()
                total += int(row[0])
            return total

    async def get_repository_state(
        self, workspace_id: str, repository_id: str
    ) -> dict[str, Any] | None:
        """Read one durable workspace/repository generation projection."""
        async with self._lock:
            row = self._conn.execute(
                "SELECT * FROM repo_intelligence_state WHERE workspace_id=? AND repository_id=?",
                (workspace_id, repository_id),
            ).fetchone()
            return dict(row) if row else None

    def mark_repository_state_dirty(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        index_project_id: str,
        root_identity: str,
        pending_paths: tuple[str, ...] = (),
        full_refresh_required: bool = False,
        source_revision: str | None = None,
    ) -> None:
        """Persist a conservative invalidation before derived work resumes.

        Mutation observers are synchronous because they run after a successful
        tool effect.  The durable projection therefore needs a synchronous,
        single-transaction write path: a process crash after the effect but
        before the next async query must not leave a persisted ``current``
        index that can be served as authoritative-looking data.
        """
        payload_paths = set(pending_paths)
        with self._sync_lock:
            if self._closed:
                raise RuntimeError("IndexStore is closed")
            try:
                row = self._conn.execute(
                    "SELECT * FROM repo_intelligence_state WHERE workspace_id=? AND repository_id=?",
                    (workspace_id, repository_id),
                ).fetchone()
                same_identity = bool(
                    row is not None
                    and str(row["root_identity"]) == root_identity
                    and str(row["index_project_id"]) == index_project_id
                )
                if same_identity:
                    if row is None:  # pragma: no cover - defensive narrowing
                        raise ValueError("repository state row disappeared")
                    try:
                        previous_paths = json.loads(row["pending_paths_json"] or "[]")
                        if not isinstance(previous_paths, list) or any(
                            type(item) is not str for item in previous_paths
                        ):
                            raise ValueError("persisted pending paths are malformed")
                        payload_paths.update(previous_paths)
                    except (TypeError, ValueError, json.JSONDecodeError):
                        full_refresh_required = True
                    generation = int(row["generation"])
                    manifest_digest = str(row["manifest_digest"])
                    indexed_at = float(row["indexed_at"] or 0)
                    prior_source_revision = row["source_revision"]
                    prior_full_refresh = bool(row["full_refresh_required"])
                    prior_freshness = str(row["freshness"])
                else:
                    generation = 0
                    manifest_digest = canonical_digest([])
                    indexed_at = 0.0
                    prior_source_revision = None
                    prior_full_refresh = False
                    prior_freshness = "unavailable"

                if type(generation) is not int or generation < 0:
                    raise ValueError("persisted repository generation is malformed")
                freshness = (
                    "unavailable"
                    if not same_identity or prior_freshness == "unavailable"
                    else "stale"
                )
                self._conn.execute(
                    """
                    INSERT INTO repo_intelligence_state (
                        workspace_id, repository_id, index_project_id, generation,
                        manifest_digest, freshness, source_revision, root_identity,
                        pending_paths_json, full_refresh_required, indexed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(workspace_id, repository_id) DO UPDATE SET
                        index_project_id=excluded.index_project_id,
                        generation=excluded.generation,
                        manifest_digest=excluded.manifest_digest,
                        freshness=excluded.freshness,
                        source_revision=excluded.source_revision,
                        root_identity=excluded.root_identity,
                        pending_paths_json=excluded.pending_paths_json,
                        full_refresh_required=excluded.full_refresh_required,
                        indexed_at=excluded.indexed_at
                    """,
                    (
                        workspace_id,
                        repository_id,
                        index_project_id,
                        generation,
                        manifest_digest,
                        freshness,
                        source_revision if source_revision is not None else prior_source_revision,
                        root_identity,
                        json.dumps(sorted(payload_paths), ensure_ascii=False),
                        int(bool(full_refresh_required) or prior_full_refresh or not same_identity),
                        indexed_at,
                    ),
                )
                self._conn.commit()
            except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
                self._conn.rollback()
                raise

    async def save_repository_state(
        self,
        *,
        workspace_id: str,
        repository_id: str,
        index_project_id: str,
        generation: int,
        manifest_digest: str,
        freshness: str,
        source_revision: str | None,
        root_identity: str,
        pending_paths: tuple[str, ...] = (),
        full_refresh_required: bool = False,
        indexed_at: float | None = None,
    ) -> None:
        """Atomically persist one derived generation projection."""
        if type(generation) is not int or generation < 0:
            raise ValueError("repository generation must be non-negative")
        payload = json.dumps(sorted(set(pending_paths)), ensure_ascii=False)
        async with self._lock:
            if self._closed:
                raise RuntimeError("IndexStore is closed")
            self._conn.execute(
                """
                INSERT INTO repo_intelligence_state (
                    workspace_id, repository_id, index_project_id, generation,
                    manifest_digest, freshness, source_revision, root_identity,
                    pending_paths_json, full_refresh_required, indexed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(workspace_id, repository_id) DO UPDATE SET
                    index_project_id=excluded.index_project_id,
                    generation=excluded.generation,
                    manifest_digest=excluded.manifest_digest,
                    freshness=excluded.freshness,
                    source_revision=excluded.source_revision,
                    root_identity=excluded.root_identity,
                    pending_paths_json=excluded.pending_paths_json,
                    full_refresh_required=excluded.full_refresh_required,
                    indexed_at=excluded.indexed_at
                """,
                (
                    workspace_id,
                    repository_id,
                    index_project_id,
                    generation,
                    manifest_digest,
                    freshness,
                    source_revision,
                    root_identity,
                    payload,
                    int(full_refresh_required),
                    time.time() if indexed_at is None else indexed_at,
                ),
            )
            self._conn.commit()


def item_to_dict(item: Any) -> dict[str, Any]:
    from dataclasses import asdict
    return asdict(item)


def _classify_path_role(path: str) -> str:
    """Classify a file path into a role: ``test``, ``source``, or ``fixture``.

    Uses explicit path patterns — NOT substring matching — to determine if a
    file is a test file. This classification is stored in the ``path_role``
    column of ``code_files`` and indexed for bounded equality queries.
    """
    # Normalize to forward slashes for consistent matching
    normalized = path.replace("\\", "/")
    parts = normalized.split("/")
    filename = parts[-1] if parts else normalized
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename

    # Test directories: tests/, test/, spec/, __tests__/, specs/
    for part in parts[:-1]:
        if part in ("tests", "test", "spec", "__tests__", "specs", "__tests__"):
            return "test"
    # Test file prefixes/suffixes: test_*, *_test.*, *_spec.*, *_test.*
    if stem.startswith(("test_", "test-")):
        return "test"
    if stem.endswith(("_test", "-test", "_spec", "-spec", "Test", "Spec")):
        return "test"
    # Go test files: *_test.go (already caught by suffix, but be explicit)
    if filename.endswith("_test.go"):
        return "test"
    # Python __init__.py is a package marker, not a test
    if filename == "__init__.py":
        return "source"
    # Fixtures: files in fixtures/, __fixtures__/, or with .fixture extension
    for part in parts[:-1]:
        if part in ("fixtures", "__fixtures__", "testdata", "test_data"):
            return "fixture"
    return "source"


def _compute_test_subject_key(path: str) -> str:
    """Compute the subject key of a test file for association matching.

    For a test file like ``test_auth.py``, the subject key is ``auth`` —
    the stem with test prefixes/suffixes stripped. For non-test files,
    returns ``""`` (no subject key).

    This key is used by :meth:`CodeQueryService.associated_tests` Priority 2
    to match test files against target files by subject (not by arbitrary
    path-role equality).
    """
    normalized = path.replace("\\", "/")
    filename = normalized.split("/")[-1]
    stem = filename.rsplit(".", 1)[0] if "." in filename else filename
    # Strip test_ prefix
    if stem.startswith("test_"):
        return stem[5:]
    if stem.startswith("test-"):
        return stem[5:]
    # Strip _test suffix
    if stem.endswith("_test"):
        return stem[:-5]
    if stem.endswith("-test"):
        return stem[:-5]
    if stem.endswith("_spec"):
        return stem[:-5]
    if stem.endswith("-spec"):
        return stem[:-5]
    # Go: foo_test.go → foo
    if filename.endswith("_test.go"):
        return stem.removesuffix("_test")
    # Not a test file — no subject key
    return ""


def _compute_module_key(path: str) -> str:
    """Compute the module key of a file for association matching.

    The module key is the path without extension, using ``/`` separators.
    For example, ``auth/login.py`` → ``auth/login``.

    This key is used by :meth:`CodeQueryService.associated_tests` Priority 2
    to match test files against target files by module path.
    """
    normalized = path.replace("\\", "/")
    # Strip extension
    if "." in normalized.split("/")[-1]:
        return normalized.rsplit(".", 1)[0]
    return normalized


def _compute_package_key(path: str) -> str:
    """Compute the package key of a file for association matching.

    The package key is the top-level directory of the file.
    For example, ``auth/login.py`` → ``auth``, ``tests/test_auth.py`` → ``tests``.

    This key is used by :meth:`CodeQueryService.associated_tests` Priority 2
    to match test files against target files by package.
    """
    normalized = path.replace("\\", "/")
    parts = [p for p in normalized.split("/") if p]
    if len(parts) <= 1:
        return ""
    return parts[0]
