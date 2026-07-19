"""Async SQLite database wrapper."""

from __future__ import annotations

import json
import asyncio
import sqlite3
import time
from pathlib import Path
from typing import Any

try:
    import aiosqlite
except ModuleNotFoundError:  # pragma: no cover - exercised only in bare envs
    aiosqlite = None

from khaos.agent.core import Message


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
TELEGRAM_REPLAY_WINDOW = 4096


class _AsyncCursor:
    """Minimal async cursor facade for environments without aiosqlite."""

    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @property
    def lastrowid(self) -> int | None:
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    async def fetchall(self) -> list[sqlite3.Row]:
        return self._cursor.fetchall()

    async def fetchone(self) -> sqlite3.Row | None:
        return self._cursor.fetchone()


class _AsyncSqliteFallback:
    """Tiny sqlite3-backed subset matching the aiosqlite calls used in P0-A."""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _AsyncCursor:
        return _AsyncCursor(self._conn.execute(sql, params))

    async def executescript(self, sql: str) -> None:
        self._conn.executescript(sql)

    async def commit(self) -> None:
        self._conn.commit()

    async def rollback(self) -> None:
        self._conn.rollback()

    async def close(self) -> None:
        self._conn.close()


class Database:
    """Small async database facade used by the P0-A runtime."""

    def __init__(self, path: str | Path = "khaos.db"):
        self.path = str(path)
        self._conn: aiosqlite.Connection | None = None
        self._operation_approval_lock = asyncio.Lock()
        self._turn_event_lock = asyncio.Lock()
        self._webhook_replay_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Open the SQLite connection if it is not already open."""
        if self._conn is None:
            if aiosqlite is None:
                self._conn = _AsyncSqliteFallback(self.path)
            else:
                self._conn = await aiosqlite.connect(self.path)
                self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA foreign_keys = ON")

    async def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def run_migrations(self) -> None:
        """Apply the full P0-A schema."""
        conn = await self._require_conn()
        await conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        await conn.commit()
        # HIGH-3 (batch 3.1.8): ensure lifecycle_version column exists on
        # existing databases (CREATE TABLE IF NOT EXISTS won't add it to
        # a pre-existing table).  See _ensure_scheduled_tasks_lifecycle_version.
        await self._ensure_scheduled_tasks_lifecycle_version()

    async def _ensure_scheduled_tasks_lifecycle_version(self) -> None:
        """Add ``lifecycle_version`` column to legacy ``scheduled_tasks``.

        HIGH-3 (batch 3.1.8): the column was added to ``schema.sql`` for
        new databases, but existing databases created before this batch
        won't have it (``CREATE TABLE IF NOT EXISTS`` is a no-op on an
        existing table).  This helper uses ``ALTER TABLE`` to add the
        column with a default of 0 — matching the schema.sql default.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "lifecycle_version" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks "
                "ADD COLUMN lifecycle_version INTEGER NOT NULL DEFAULT 0"
            )
            await conn.commit()

    async def create_session(self, session_id: str, mode: str = "office") -> None:
        """Create a session if missing and keep its mode current."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO sessions (id, mode)
            VALUES (?, ?)
            ON CONFLICT(id) DO UPDATE SET
                mode = excluded.mode,
                updated_at = datetime('now')
            """,
            (session_id, mode),
        )
        await conn.commit()

    async def consume_webhook_event(
        self,
        channel_id: str,
        platform: str,
        event_id: str,
        issued_at: float,
        expires_at: float | None,
    ) -> bool:
        """Atomically persist one authenticated webhook event exactly once."""
        if not channel_id or not platform or not event_id:
            return False
        conn = await self._require_conn()
        async with self._webhook_replay_lock:
            if platform == "telegram":
                return await self._consume_telegram_update(
                    conn, channel_id, event_id
                )
            now = time.time()
            await conn.execute(
                "DELETE FROM webhook_replay_events "
                "WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO webhook_replay_events (
                    channel_id, platform, event_id, issued_at, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (channel_id, platform, event_id, issued_at, expires_at, now),
            )
            await conn.commit()
            return cursor.rowcount == 1

    async def _consume_telegram_update(
        self, conn: aiosqlite.Connection, channel_id: str, event_id: str
    ) -> bool:
        try:
            update_id = int(event_id)
        except (TypeError, ValueError):
            return False
        if update_id < 0:
            return False
        now = time.time()
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT high_water, seen_json FROM webhook_replay_watermarks "
                "WHERE channel_id = ? AND platform = 'telegram'",
                (channel_id,),
            )
            row = await cursor.fetchone()
            seen: set[int] = set()
            high_water = -1
            if row is not None:
                high_water = int(row["high_water"])
                seen = {int(value) for value in json.loads(row["seen_json"])}
            else:
                legacy = await conn.execute(
                    "SELECT event_id FROM webhook_replay_events "
                    "WHERE channel_id = ? AND platform = 'telegram' "
                    "ORDER BY CAST(event_id AS INTEGER) DESC LIMIT ?",
                    (channel_id, TELEGRAM_REPLAY_WINDOW),
                )
                for legacy_row in await legacy.fetchall():
                    try:
                        seen.add(int(legacy_row["event_id"]))
                    except (TypeError, ValueError):
                        continue
                if seen:
                    high_water = max(seen)
            cutoff = high_water - TELEGRAM_REPLAY_WINDOW + 1
            if update_id in seen or (high_water >= 0 and update_id < cutoff):
                await conn.commit()
                return False
            high_water = max(high_water, update_id)
            cutoff = high_water - TELEGRAM_REPLAY_WINDOW + 1
            seen.add(update_id)
            seen = {value for value in seen if value >= cutoff}
            await conn.execute(
                """
                INSERT INTO webhook_replay_watermarks (
                    channel_id, platform, high_water, seen_json, updated_at
                ) VALUES (?, 'telegram', ?, ?, ?)
                ON CONFLICT(channel_id, platform) DO UPDATE SET
                    high_water = excluded.high_water,
                    seen_json = excluded.seen_json,
                    updated_at = excluded.updated_at
                """,
                (channel_id, high_water, json.dumps(sorted(seen)), now),
            )
            await conn.execute(
                "DELETE FROM webhook_replay_events "
                "WHERE channel_id = ? AND platform = 'telegram'",
                (channel_id,),
            )
            await conn.commit()
            return True
        except Exception:
            await conn.rollback()
            raise

    async def insert_message(self, session_id: str, message: Message) -> int:
        """Persist a chat message and return its row id."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO messages (
                session_id, role, content, tool_calls, tool_call_id, token_count
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                message.role,
                message.content,
                json.dumps(message.tool_calls),
                message.tool_call_id,
                message.token_count,
            ),
        )
        await conn.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?",
            (session_id,),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_messages(self, session_id: str) -> list[Message]:
        """Load persisted messages for a session in chronological order."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT role, content, tool_calls, tool_call_id, token_count
            FROM messages
            WHERE session_id = ?
            ORDER BY created_at, id
            """,
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [
            Message(
                role=str(row["role"]),
                content=str(row["content"]),
                tool_calls=json.loads(str(row["tool_calls"] or "[]")),
                tool_call_id=row["tool_call_id"],
                token_count=int(row["token_count"]),
            )
            for row in rows
        ]

    async def set_config(self, key: str, value: Any) -> None:
        """Persist a JSON configuration value."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO user_config (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now')
            """,
            (key, json.dumps(value)),
        )
        await conn.commit()

    async def get_config(self, key: str, default: Any = None) -> Any:
        """Read a JSON configuration value."""
        conn = await self._require_conn()
        cursor = await conn.execute("SELECT value FROM user_config WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if row is None:
            return default
        return json.loads(str(row["value"]))

    async def insert_permission_rule(
        self,
        pattern: str,
        permission_level: str,
        approval: str,
        mode: str,
    ) -> int:
        """Persist a permission rule and return its row id."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO permissions (pattern, permission_level, approval, mode)
            VALUES (?, ?, ?, ?)
            """,
            (pattern, permission_level, approval, mode),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_permission_rules(self) -> list[dict[str, Any]]:
        """Load permission rules newest first."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, pattern, permission_level, approval, mode,
                   strftime('%s', granted_at) AS granted_at
            FROM permissions
            ORDER BY granted_at DESC, id DESC
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_permission_rule(self, rule_id: int) -> None:
        """Delete a permission rule."""
        conn = await self._require_conn()
        await conn.execute("DELETE FROM permissions WHERE id = ?", (rule_id,))
        await conn.commit()

    async def insert_audit_log(
        self,
        action: str,
        target: str,
        result: str,
        detail: str = "",
        session_id: str | None = None,
    ) -> int:
        """Persist an audit log entry and return its row id."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO audit_log (action, target, result, detail, session_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (action, target, result, detail, session_id),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_audit_logs(self) -> list[dict[str, Any]]:
        """Return audit logs in insertion order."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT action, target, result, detail, session_id
            FROM audit_log
            ORDER BY created_at, id
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def query_audit_logs(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Return audit logs matching the given filters, newest first.

        Filters:
        - ``action``: exact action match (e.g. "write_file", "terminal").
        - ``result``: exact result match (e.g. "success", "denied", "error").
        - ``since``/``until``: inclusive ISO timestamp bounds on ``created_at``.
        - ``limit``: cap on rows (default 100).

        ``created_at`` is stored as ``datetime('now')`` (UTC, 'YYYY-MM-DD HH:MM:SS')
        so lexicographic comparison against ISO-ish strings works.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if result is not None:
            clauses.append("result = ?")
            params.append(result)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("created_at <= ?")
            params.append(until)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await conn.execute(
            f"""
            SELECT id, action, target, result, detail, session_id, created_at
            FROM audit_log
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def upsert_memory(
        self,
        scope: str,
        key: str,
        value: str,
        ttl: int,
        confidence: int,
    ) -> int:
        """Insert or update a memory by scope and key."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO memories (scope, key, value, ttl, confidence)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(scope, key) DO UPDATE SET
                value = excluded.value,
                ttl = excluded.ttl,
                confidence = excluded.confidence,
                updated_at = datetime('now')
            """,
            (scope, key, value, ttl, confidence),
        )
        await conn.commit()
        cursor = await conn.execute(
            "SELECT id FROM memories WHERE scope = ? AND key = ?",
            (scope, key),
        )
        row = await cursor.fetchone()
        return int(row["id"])

    async def get_memory(self, scope: str, key: str) -> dict[str, Any] | None:
        """Fetch one memory by scope and key."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, scope, key, value, ttl, confidence, access_freq, created_at, updated_at
            FROM memories
            WHERE scope = ? AND key = ?
            """,
            (scope, key),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def delete_memory(self, scope: str, key: str) -> None:
        """Delete one memory by scope and key."""
        conn = await self._require_conn()
        await conn.execute("DELETE FROM memories WHERE scope = ? AND key = ?", (scope, key))
        await conn.commit()

    async def delete_memory_by_id(self, memory_id: int) -> None:
        """Delete one memory by id."""
        conn = await self._require_conn()
        await conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        await conn.commit()

    async def list_memories(self, scope: str | None = None) -> list[dict[str, Any]]:
        """List memories, optionally limited to one scope."""
        conn = await self._require_conn()
        if scope is None:
            cursor = await conn.execute(
                """
                SELECT id, scope, key, value, ttl, confidence, access_freq, created_at, updated_at
                FROM memories
                ORDER BY confidence DESC, updated_at DESC, id DESC
                """
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, scope, key, value, ttl, confidence, access_freq, created_at, updated_at
                FROM memories
                WHERE scope = ?
                ORDER BY confidence DESC, updated_at DESC, id DESC
                """,
                (scope,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def search_memories(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Search memories through FTS5."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT m.id, m.scope, m.key, m.value, m.ttl, m.confidence,
                   m.access_freq, m.created_at, m.updated_at
            FROM memory_fts
            JOIN memories AS m ON m.id = memory_fts.rowid
            WHERE memory_fts MATCH ?
            ORDER BY bm25(memory_fts)
            LIMIT ?
            """,
            (query, top_k),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def touch_memory(self, memory_id: int) -> None:
        """Increment memory access frequency."""
        conn = await self._require_conn()
        await conn.execute(
            """
            UPDATE memories
            SET access_freq = access_freq + 1, updated_at = datetime('now')
            WHERE id = ?
            """,
            (memory_id,),
        )
        await conn.commit()

    async def insert_subagent_task(
        self,
        task_id: str,
        parent_session_id: str,
        goal: str,
        context: str,
        tools: str,
        status: str = "pending",
        principal_id: str = "",
    ) -> None:
        """Insert a subagent task row.

        B1: ``principal_id`` is persisted so collect / status queries
        can filter tasks by the authenticated caller.  Empty string is
        the legacy default (rows written before the column existed).

        M3: uses plain ``INSERT`` (NOT ``INSERT ... ON CONFLICT(id) DO
        UPDATE``).  Task IDs are now UUID4 (``task_{uuid.uuid4().hex}``)
        so a collision is virtually impossible — but if one ever
        happens, ``IntegrityError`` is raised instead of silently
        overwriting an old row (which could be another principal's
        history after a process restart reset the old incrementing
        counter).  Callers that legitimately need to update an existing
        row use ``update_subagent_task``.
        """
        conn = await self._require_conn()
        await self._ensure_subagent_tasks_principal_column()
        await conn.execute(
            """
            INSERT INTO subagent_tasks (id, parent_session_id, goal, context, tools, status, principal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (task_id, parent_session_id, goal, context, tools, status, principal_id),
        )
        await conn.commit()

    async def update_subagent_task(
        self,
        task_id: str,
        status: str,
        result: str | None = None,
        error: str | None = None,
        finished: bool = False,
    ) -> int:
        """Update subagent task status/result/error.

        M1 (round-6): returns the number of rows actually updated.
        Callers that need durability (e.g. ``SubAgentSpawner._persist_terminal``)
        MUST treat a zero return as "the row does not exist" — the
        terminal state was NOT persisted.  Previously the method
        returned ``None`` and discarded the cursor, so a zero-row
        ``UPDATE`` (e.g. when spawn was cancelled BEFORE
        ``insert_subagent_task`` ran) was silently treated as success.
        The spawner then cleared ``_pending_persistence`` and shutdown
        returned OK — but the DB had no row at all, so the task
        vanished from every later query.
        """
        conn = await self._require_conn()
        finished_expr = "datetime('now')" if finished else "finished_at"
        cursor = await conn.execute(
            f"""
            UPDATE subagent_tasks
            SET status = ?, result = ?, error = ?, finished_at = {finished_expr}
            WHERE id = ?
            """,
            (status, result, error, task_id),
        )
        await conn.commit()
        return cursor.rowcount or 0

    async def list_subagent_tasks(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        """List subagent tasks.

        B1: when ``principal_id`` is set, only rows owned by that
        principal are returned.  ``None`` preserves the legacy
        "return everything" behaviour.
        """
        conn = await self._require_conn()
        await self._ensure_subagent_tasks_principal_column()
        if principal_id is None:
            cursor = await conn.execute(
                """
                SELECT id, parent_session_id, goal, context, tools, status, result, error, principal_id
                FROM subagent_tasks
                ORDER BY created_at, id
                """
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, parent_session_id, goal, context, tools, status, result, error, principal_id
                FROM subagent_tasks
                WHERE principal_id = ?
                ORDER BY created_at, id
                """,
                (principal_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def _ensure_subagent_tasks_principal_column(self) -> None:
        """B1: idempotently add the ``principal_id`` column to existing
        ``subagent_tasks`` tables (legacy DBs created before this column
        existed).  Fresh DBs get the column from ``schema.sql``.

        Uses PRAGMA table_info to detect the column so the ALTER only
        fires once per database lifetime.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(subagent_tasks)")
        existing = {str(row["name"]) for row in await cursor.fetchall()}
        if "principal_id" not in existing:
            await conn.execute(
                "ALTER TABLE subagent_tasks ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''"
            )
            await conn.commit()

    # ------------------------------------------------------------------
    # Phase 6: session bookmarks + session summary / changed files
    # ------------------------------------------------------------------

    async def save_bookmark(
        self,
        session_id: str,
        name: str,
        description: str = "",
        mode: str = "office",
        project_root: str | None = None,
        summary: str = "",
    ) -> None:
        """保存一个会话书签。

        同一 (session_id, name) 已存在时整体覆盖更新（upsert）。
        """
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO session_bookmarks
                (session_id, name, description, mode, project_root, summary)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, name) DO UPDATE SET
                description  = excluded.description,
                mode         = excluded.mode,
                project_root = excluded.project_root,
                summary      = excluded.summary
            """,
            (session_id, name, description, mode, project_root, summary),
        )
        await conn.commit()

    async def load_bookmark(self, session_id: str, name: str) -> dict[str, Any] | None:
        """加载指定书签。不存在时返回 None。"""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, name, description, mode, project_root,
                   summary, created_at
            FROM session_bookmarks
            WHERE session_id = ? AND name = ?
            """,
            (session_id, name),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_bookmarks(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """列出书签，可按 session 过滤。按创建时间倒序返回。"""
        conn = await self._require_conn()
        if session_id is None:
            cursor = await conn.execute(
                """
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at
                FROM session_bookmarks
                ORDER BY created_at DESC, id DESC
                """
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at
                FROM session_bookmarks
                WHERE session_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (session_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_bookmark(self, session_id: str, name: str) -> None:
        """删除指定书签。不存在的书签静默忽略。"""
        conn = await self._require_conn()
        await conn.execute(
            "DELETE FROM session_bookmarks WHERE session_id = ? AND name = ?",
            (session_id, name),
        )
        await conn.commit()

    async def _ensure_sessions_metadata_column(self, column: str) -> None:
        """幂等地为 sessions 表增加一个 TEXT 列（如 summary / changed_files）。

        使用 PRAGMA 探测列是否已存在，避免 ALTER TABLE 报错。metadata JSON
        字段在 schema.sql 中已存在，这里仅在需要独立列时按需扩展。
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(sessions)")
        existing = {str(row["name"]) for row in await cursor.fetchall()}
        if column not in existing:
            await conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} TEXT")
            await conn.commit()

    async def save_session_summary(self, session_id: str, summary: str) -> None:
        """保存会话摘要到 sessions 表的 summary 列。

        summary 列不存在则 ALTER TABLE 添加（幂等迁移）。同时合并写入
        metadata JSON 的 summary 字段，保持向后兼容。
        """
        conn = await self._require_conn()
        await self._ensure_sessions_metadata_column("summary")
        await conn.execute(
            "UPDATE sessions SET summary = ?, updated_at = datetime('now') WHERE id = ?",
            (summary, session_id),
        )
        # 同步到 metadata JSON，便于旧读取路径访问
        await self._merge_session_metadata(session_id, {"summary": summary})
        await conn.commit()

    async def get_session_summary(self, session_id: str) -> str | None:
        """读取会话摘要。优先读 summary 列，回退到 metadata JSON。"""
        conn = await self._require_conn()
        # summary 列可能不存在（旧库未迁移），用 try 探测。
        try:
            cursor = await conn.execute(
                "SELECT summary FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = await cursor.fetchone()
            if row is not None and row["summary"] is not None:
                return str(row["summary"])
        except sqlite3.OperationalError:
            # 列尚未添加 — 回退到 metadata
            pass
        meta = await self._read_session_metadata(session_id)
        value = meta.get("summary")
        return str(value) if value is not None else None

    async def save_session_changes(self, session_id: str, files: list[str]) -> None:
        """保存会话期间修改的文件列表到 sessions metadata。

        与 summary 共存于一个 JSON metadata 字段中，结构：
        ``{"summary": "...", "changed_files": ["path1", "path2"]}``
        """
        conn = await self._require_conn()
        await self._merge_session_metadata(session_id, {"changed_files": list(files)})
        await conn.commit()

    async def get_session_changes(self, session_id: str) -> list[str]:
        """读取会话修改的文件列表。"""
        meta = await self._read_session_metadata(session_id)
        raw = meta.get("changed_files")
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw]

    async def _read_session_metadata(self, session_id: str) -> dict[str, Any]:
        """读取 sessions.metadata 的 JSON 字典，缺失/损坏时返回空字典。"""
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT metadata FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return {}
        raw = row["metadata"]
        if not raw:
            return {}
        try:
            data = json.loads(str(raw))
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    async def _merge_session_metadata(
        self, session_id: str, updates: dict[str, Any]
    ) -> None:
        """合并写入 sessions.metadata JSON（浅合并）。"""
        conn = await self._require_conn()
        current = await self._read_session_metadata(session_id)
        current.update(updates)
        await conn.execute(
            "UPDATE sessions SET metadata = ?, updated_at = datetime('now') WHERE id = ?",
            (json.dumps(current, ensure_ascii=False), session_id),
        )

    # ------------------------------------------------------------------
    # Hermes batch 1: scheduled (cron) tasks
    # ------------------------------------------------------------------

    async def insert_scheduled_task(
        self,
        name: str,
        prompt: str,
        status: str,
        schedule,
        deliver_to: str = "local",
        meta: dict | None = None,
    ) -> str:
        """Persist a new scheduled task and return its id."""
        import uuid

        conn = await self._require_conn()
        task_id = uuid.uuid4().hex[:12]
        schedule_json = json.dumps(_schedule_to_dict(schedule), ensure_ascii=False)
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        await conn.execute(
            """
            INSERT INTO scheduled_tasks
                (id, name, prompt, status, schedule_config, deliver_to, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (task_id, name, prompt, status, schedule_json, deliver_to, meta_json),
        )
        await conn.commit()
        return task_id

    async def update_scheduled_task_status(
        self, task_id: str, status: str, bump_version: bool = False,
    ) -> int:
        """Update only the status column.

        HIGH-3 (batch 3.1.8): if ``bump_version`` is True, also increments
        ``lifecycle_version``.  Returns the rowcount (1 = success, 0 = no
        such task).  Used by control operations (pause / resume / remove)
        which always win over stale executor writes.
        """
        conn = await self._require_conn()
        if bump_version:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET status = ?, "
                "lifecycle_version = lifecycle_version + 1 WHERE id = ?",
                (status, task_id),
            )
        else:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET status = ? WHERE id = ?",
                (status, task_id),
            )
        await conn.commit()
        return cursor.rowcount

    async def update_scheduled_task(
        self,
        task_id: str,
        status: str | None = None,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
        bump_version: bool = False,
    ) -> int:
        """Update multiple columns.  Returns rowcount (1 = success, 0 = no
        such task).

        HIGH-3 (batch 3.1.8): if ``bump_version`` is True, also increments
        ``lifecycle_version``.  Used by control operations which always
        win over stale executor writes.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in [
            ("status", status),
            ("last_run", last_run),
            ("next_run", next_run),
            ("run_count", run_count),
            ("last_result", last_result),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        if bump_version:
            clauses.append("lifecycle_version = lifecycle_version + 1")
        if not clauses:
            return 1
        params.append(task_id)
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} WHERE id = ?",
            tuple(params),
        )
        await conn.commit()
        return cursor.rowcount

    async def update_scheduled_task_conditional(
        self,
        task_id: str,
        expected_version: int,
        status: str | None = None,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
    ) -> int:
        """Optimistic-concurrency UPDATE for executor terminal writes.

        HIGH-3 (batch 3.1.8): the executor captures ``lifecycle_version``
        at start and passes it as ``expected_version``.  The UPDATE only
        succeeds if the version hasn't changed (no control operation
        happened in between).  Returns rowcount:
          - 1 = success (version matched, state written, version bumped)
          - 0 = version mismatch (a pause / remove / resume happened;
            the stale write is discarded)

        The UPDATE always bumps ``lifecycle_version`` on success so the
        next control operation's unconditional write doesn't accidentally
        re-match a different executor's captured version.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in [
            ("status", status),
            ("last_run", last_run),
            ("next_run", next_run),
            ("run_count", run_count),
            ("last_result", last_result),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        clauses.append("lifecycle_version = lifecycle_version + 1")
        # HIGH-3 (batch 3.1.8): WHERE clause is ``id = ? AND
        # lifecycle_version = ?`` — params MUST be in that order
        # (task_id first, then expected_version).  A previous version
        # had these reversed, which made every conditional UPDATE
        # match 0 rows (id column received an int, lifecycle_version
        # received a string) — silently discarding every executor
        # terminal write as a "version mismatch".
        params.extend([task_id, expected_version])
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
            f"WHERE id = ? AND lifecycle_version = ?",
            tuple(params),
        )
        await conn.commit()
        return cursor.rowcount

    async def list_scheduled_tasks(self) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, name, prompt, status, schedule_config, deliver_to, meta,
                   created_at, last_run, next_run, run_count, last_result, error,
                   lifecycle_version
            FROM scheduled_tasks
            ORDER BY created_at
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_scheduled_task(self, task_id: str) -> dict[str, Any] | None:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,)
        )
        row = await cursor.fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Hermes batch 2: session history FTS5 search
    # ------------------------------------------------------------------

    async def insert_message_fts(
        self,
        session_id: str,
        role: str,
        content: str,
        token_count: int = 0,
        rowid: int | None = None,
    ) -> None:
        """Index a message into messages_fts.

        ``rowid`` should be the messages.id so the FTS row mirrors the base
        row — this lets search results link back to the exact message. When
        omitted, FTS auto-assigns a rowid (still searchable, just not joined).
        """
        conn = await self._require_conn()
        from datetime import datetime as _dt

        created = _dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if rowid is not None:
            await conn.execute(
                "INSERT INTO messages_fts (rowid, session_id, role, content, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (rowid, session_id, role, content, created),
            )
        else:
            await conn.execute(
                "INSERT INTO messages_fts (session_id, role, content, created_at) "
                "VALUES (?, ?, ?, ?)",
                (session_id, role, content, created),
            )
        await conn.commit()

    async def upsert_coding_task(self, task: dict[str, Any]) -> None:
        """Persist the complete JSON-safe state of one coding task."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO coding_tasks (id, goal, status, state_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET goal=excluded.goal,
                status=excluded.status, state_json=excluded.state_json,
                updated_at=excluded.updated_at
            """,
            (task["id"], task["goal"], task["status"], json.dumps(task), task["created_at"], task["updated_at"]),
        )
        await conn.commit()

    async def list_coding_tasks(self) -> list[dict[str, Any]]:
        """Load persisted coding-task state in creation order."""
        conn = await self._require_conn()
        cursor = await conn.execute("SELECT state_json FROM coding_tasks ORDER BY created_at")
        return [json.loads(str(row["state_json"])) for row in await cursor.fetchall()]

    async def search_sessions(
        self, query: str, limit: int = 10, offset: int = 0
    ) -> list[dict[str, Any]]:
        """FTS5 BM25 search across all session messages.

        Returns rows with id, session_id, role, created_at, rank, and a
        snippet() with the matched term highlighted.
        """
        conn = await self._require_conn()
        # snippet: highlight matches with [ ... ]; bm25() rank (lower = better).
        cursor = await conn.execute(
            """
            SELECT rowid AS id, session_id, role, created_at,
                   rank,
                   snippet(messages_fts, 2, '[', ']]', '...', 12) AS snippet
            FROM messages_fts
            WHERE messages_fts MATCH ?
            ORDER BY rank
            LIMIT ? OFFSET ?
            """,
            (query, limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_session_messages(
        self, session_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Return messages for a session, newest-aware pagination."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE session_id = ?
            ORDER BY created_at, id
            LIMIT ? OFFSET ?
            """,
            (session_id, limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_message_window(
        self, session_id: str, message_id: int, window: int = 5
    ) -> list[dict[str, Any]]:
        """Return up to ``window`` messages before and after ``message_id``."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE session_id = ?
            ORDER BY ABS(id - ?), id
            LIMIT ?
            """,
            (session_id, message_id, window * 2 + 1),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        # Re-sort chronologically after the ABS-based proximity selection.
        rows.sort(key=lambda r: r["id"])
        return rows

    async def count_session_messages(self, session_id: str) -> int:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE session_id = ?",
            (session_id,),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def count_messages_before_after(
        self, session_id: str, message_id: int
    ) -> tuple[int, int]:
        """Return (count_before, count_after) relative to ``message_id``."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT "
            "SUM(CASE WHEN id < ? THEN 1 ELSE 0 END) AS before_n, "
            "SUM(CASE WHEN id > ? THEN 1 ELSE 0 END) AS after_n "
            "FROM messages WHERE session_id = ?",
            (message_id, message_id, session_id),
        )
        row = await cursor.fetchone()
        if not row:
            return (0, 0)
        return (int(row["before_n"] or 0), int(row["after_n"] or 0))

    async def list_sessions(
        self, limit: int = 20, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List sessions newest-first, with a message-count + last-message preview."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT s.id, s.mode, s.created_at,
                   (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id) AS message_count,
                   (SELECT content FROM messages m WHERE m.session_id = s.id
                    ORDER BY m.id DESC LIMIT 1) AS preview
            FROM sessions s
            WHERE s.status = 'active'
            ORDER BY s.updated_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def register_operation_approval(
        self,
        *,
        approval_id: str,
        binding_digest: str,
        binding_json: str,
        principal_id: str,
        session_id: str,
        task_id: str,
        workspace_id: str,
        operation: str,
        nonce_hash: str,
        expires_at: float,
        created_at: float,
    ) -> None:
        """Persist an immutable destructive-operation approval challenge."""
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT binding_digest FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                existing = await cursor.fetchone()
                if existing is not None:
                    if str(existing["binding_digest"]) != binding_digest:
                        raise PermissionError(
                            "operation approval id is already bound to another operation"
                        )
                    await conn.commit()
                    return
                await conn.execute(
                    """
                    INSERT INTO operation_approvals (
                        approval_id, binding_digest, binding_json, principal_id,
                        session_id, task_id, workspace_id, operation, nonce_hash,
                        expires_at, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        approval_id, binding_digest, binding_json, principal_id,
                        session_id, task_id, workspace_id, operation, nonce_hash,
                        expires_at, created_at,
                    ),
                )
                await self._insert_operation_event(
                    conn, approval_id, "registered", binding_digest,
                    principal_id, session_id, {}, created_at,
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def start_agent_turn(
        self,
        *,
        turn_id: str,
        attempt_id: str,
        session_id: str,
        task_id: str | None,
        payload: dict[str, Any],
        now: float,
    ) -> None:
        """Create one durable running turn and its first event atomically."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await conn.execute(
                    "INSERT INTO agent_turns(turn_id,attempt_id,session_id,task_id,"
                    "status,last_sequence,started_at) VALUES(?,?,?,?, 'running',1,?)",
                    (turn_id, attempt_id, session_id, task_id, now),
                )
                await conn.execute(
                    "INSERT INTO agent_turn_events VALUES(?,1,'turn.started',?,?)",
                    (turn_id, json.dumps(payload, sort_keys=True), now),
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def append_agent_turn_event(
        self,
        *,
        turn_id: str,
        expected_sequence: int,
        event_type: str,
        payload: dict[str, Any],
        now: float,
        terminal_status: str | None = None,
        error_code: str | None = None,
    ) -> int:
        """Append in sequence; terminal status and event commit together."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT status,last_sequence FROM agent_turns WHERE turn_id=?",
                    (turn_id,),
                )
                row = await cursor.fetchone()
                if (
                    row is None
                    or row["status"] != "running"
                    or int(row["last_sequence"]) != expected_sequence
                ):
                    raise PermissionError(
                        "turn event is late, replayed, or out of sequence"
                    )
                sequence = expected_sequence + 1
                await conn.execute(
                    "INSERT INTO agent_turn_events VALUES(?,?,?,?,?)",
                    (
                        turn_id, sequence, event_type,
                        json.dumps(payload, sort_keys=True), now,
                    ),
                )
                if terminal_status is None:
                    await conn.execute(
                        "UPDATE agent_turns SET last_sequence=? WHERE turn_id=? "
                        "AND status='running' AND last_sequence=?",
                        (sequence, turn_id, expected_sequence),
                    )
                else:
                    if terminal_status not in {"completed", "interrupted", "failed"}:
                        raise ValueError("invalid terminal turn status")
                    await conn.execute(
                        "UPDATE agent_turns SET status=?,last_sequence=?,error_code=?,"
                        "finished_at=? WHERE turn_id=? AND status='running' "
                        "AND last_sequence=?",
                        (
                            terminal_status, sequence, error_code, now,
                            turn_id, expected_sequence,
                        ),
                    )
                await conn.commit()
                return sequence
            except Exception:
                await conn.rollback()
                raise

    async def recover_inflight_agent_turns(self, *, now: float) -> int:
        """Mark crash-left running turns interrupted without inventing success."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT turn_id,last_sequence FROM agent_turns "
                    "WHERE status='running' ORDER BY started_at"
                )
                rows = await cursor.fetchall()
                for row in rows:
                    sequence = int(row["last_sequence"]) + 1
                    await conn.execute(
                        "INSERT INTO agent_turn_events VALUES(?,?,?,?,?)",
                        (
                            row["turn_id"], sequence, "turn.interrupted",
                            json.dumps({"reason": "process-restart"}), now,
                        ),
                    )
                    await conn.execute(
                        "UPDATE agent_turns SET status='interrupted',last_sequence=?,"
                        "error_code='PROCESS_RESTART',finished_at=? WHERE turn_id=? "
                        "AND status='running'",
                        (sequence, now, row["turn_id"]),
                    )
                await conn.commit()
                return len(rows)
            except Exception:
                await conn.rollback()
                raise

    async def list_agent_turn_events(
        self, turn_id: str
    ) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM agent_turn_events WHERE turn_id=? ORDER BY sequence",
            (turn_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def approve_operation_approval(
        self,
        approval_id: str,
        *,
        principal_id: str,
        session_id: str,
        now: float,
    ) -> bool:
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                success = bool(
                    row is not None
                    and row["status"] == "pending"
                    and float(row["expires_at"]) > now
                    and row["principal_id"] == principal_id
                    and row["session_id"] == session_id
                )
                if success:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='approved', approved_at=? "
                        "WHERE approval_id=? AND status='pending'",
                        (now, approval_id),
                    )
                if row is not None:
                    await self._insert_operation_event(
                        conn, approval_id,
                        "approved" if success else "approve-rejected",
                        str(row["binding_digest"]), principal_id, session_id,
                        {}, now,
                    )
                await conn.commit()
                return success
            except Exception:
                await conn.rollback()
                raise

    async def consume_operation_approval(
        self,
        approval_id: str,
        *,
        binding_digest: str,
        principal_id: str,
        session_id: str,
        now: float,
    ) -> bool:
        """Consume once; a mismatch burns any pending/approved capability."""
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                active = bool(
                    row is not None
                    and row["status"] in {"pending", "approved"}
                )
                success = bool(
                    active
                    and row["status"] == "approved"
                    and float(row["expires_at"]) > now
                    and row["binding_digest"] == binding_digest
                    and row["principal_id"] == principal_id
                    and row["session_id"] == session_id
                )
                if active:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='consumed', consumed_at=? "
                        "WHERE approval_id=? AND status IN ('pending','approved')",
                        (now, approval_id),
                    )
                if row is not None:
                    await self._insert_operation_event(
                        conn, approval_id,
                        "consumed" if success else "consume-rejected",
                        binding_digest, principal_id, session_id,
                        {"previous_status": str(row["status"])}, now,
                    )
                await conn.commit()
                return success
            except Exception:
                await conn.rollback()
                raise

    async def cancel_operation_approval(
        self, approval_id: str, *, now: float
    ) -> None:
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                if row is not None and row["status"] in {"pending", "approved"}:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='cancelled', consumed_at=? "
                        "WHERE approval_id=? AND status IN ('pending','approved')",
                        (now, approval_id),
                    )
                    await self._insert_operation_event(
                        conn, approval_id, "cancelled",
                        str(row["binding_digest"]), str(row["principal_id"]),
                        str(row["session_id"]), {}, now,
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def list_operation_approval_events(
        self, approval_id: str
    ) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM operation_approval_events WHERE approval_id=? ORDER BY id",
            (approval_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def _insert_operation_event(
        self,
        conn,
        approval_id: str,
        event_type: str,
        binding_digest: str,
        principal_id: str,
        session_id: str,
        detail: dict[str, Any],
        created_at: float,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO operation_approval_events (
                approval_id, event_type, binding_digest, principal_id,
                session_id, detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_id, event_type, binding_digest, principal_id,
                session_id, json.dumps(detail, sort_keys=True), created_at,
            ),
        )

    async def _require_conn(self):
        if self._conn is None:
            await self.connect()
        assert self._conn is not None
        return self._conn


def _schedule_to_dict(schedule) -> dict[str, Any]:
    """Serialize a ScheduleConfig (dataclass) to a JSON-safe dict."""
    if schedule is None:
        return {}
    if hasattr(schedule, "__dict__"):
        return {k: v for k, v in vars(schedule).items()}
    if isinstance(schedule, dict):
        return schedule
    return {}
