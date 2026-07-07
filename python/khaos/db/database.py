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

    async def _require_conn(self):
        if self._conn is None:
            await self.connect()
        assert self._conn is not None
        return self._conn
