"""Async SQLite database wrapper."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

try:
    import aiosqlite
except ModuleNotFoundError:  # pragma: no cover - exercised only in bare envs
    aiosqlite = None

from khaos.agent.core import Message


SCHEMA_PATH = Path(__file__).with_name("schema.sql")


class _AsyncCursor:
    """Minimal async cursor facade for environments without aiosqlite."""

    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @property
    def lastrowid(self) -> int | None:
        return self._cursor.lastrowid

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

    async def close(self) -> None:
        self._conn.close()


class Database:
    """Small async database facade used by the P0-A runtime."""

    def __init__(self, path: str | Path = "khaos.db"):
        self.path = str(path)
        self._conn: aiosqlite.Connection | None = None

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
    ) -> None:
        """Insert or replace a subagent task row."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO subagent_tasks (id, parent_session_id, goal, context, tools, status)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                goal = excluded.goal,
                context = excluded.context,
                tools = excluded.tools,
                status = excluded.status
            """,
            (task_id, parent_session_id, goal, context, tools, status),
        )
        await conn.commit()

    async def update_subagent_task(
        self,
        task_id: str,
        status: str,
        result: str | None = None,
        error: str | None = None,
        finished: bool = False,
    ) -> None:
        """Update subagent task status/result/error."""
        conn = await self._require_conn()
        finished_expr = "datetime('now')" if finished else "finished_at"
        await conn.execute(
            f"""
            UPDATE subagent_tasks
            SET status = ?, result = ?, error = ?, finished_at = {finished_expr}
            WHERE id = ?
            """,
            (status, result, error, task_id),
        )
        await conn.commit()

    async def list_subagent_tasks(self) -> list[dict[str, Any]]:
        """List subagent tasks."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, parent_session_id, goal, context, tools, status, result, error
            FROM subagent_tasks
            ORDER BY created_at, id
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

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

    async def update_scheduled_task_status(self, task_id: str, status: str) -> None:
        conn = await self._require_conn()
        await conn.execute(
            "UPDATE scheduled_tasks SET status = ? WHERE id = ?",
            (status, task_id),
        )
        await conn.commit()

    async def update_scheduled_task(
        self,
        task_id: str,
        status: str | None = None,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
    ) -> None:
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
        if not clauses:
            return
        params.append(task_id)
        await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} WHERE id = ?",
            tuple(params),
        )
        await conn.commit()

    async def list_scheduled_tasks(self) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, name, prompt, status, schedule_config, deliver_to, meta,
                   created_at, last_run, next_run, run_count, last_result, error
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
