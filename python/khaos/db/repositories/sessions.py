"""Session and message SQL repository.

The repository owns SQL shape and row conversion, but not connection
lifecycle, transaction ownership, or read admission.  ``Database`` remains
the compatibility facade that supplies an already-authorized connection and
lease.  This separation lets callers migrate one domain at a time without a
second SQLite writer.
"""

from __future__ import annotations

import json
from typing import Any

from khaos.agent.core import Message


def _owner_scope(
    clauses: list[str],
    params: list[Any],
    *,
    principal_id: str | None,
    project_id: str | None,
    principal_column: str = "principal_id",
    project_column: str = "project_id",
) -> None:
    """Append optional owner predicates without changing admin semantics."""
    if principal_id is not None:
        clauses.append(f"{principal_column} = ?")
        params.append(principal_id)
    if project_id is not None:
        clauses.append(f"{project_column} = ?")
        params.append(project_id)


class SessionRepository:
    """Read/write SQL for sessions and their messages.

    Every method receives the connection selected by the facade.  It never
    opens a connection, commits, or decides which owner scope is authorized.
    """

    async def insert_message(
        self,
        conn: Any,
        session_id: str,
        message: Message,
        *,
        principal_id: str,
        project_id: str,
    ) -> int:
        """Insert one message and update its session timestamp atomically."""
        cursor = await conn.execute(
            """
            INSERT INTO messages (
                session_id, role, content, tool_calls, tool_call_id,
                token_count, principal_id, project_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                message.role,
                message.content,
                json.dumps(message.tool_calls),
                message.tool_call_id,
                message.token_count,
                principal_id,
                project_id,
            ),
        )
        await conn.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?",
            (session_id,),
        )
        return int(cursor.lastrowid)

    async def list_messages(
        self,
        conn: Any,
        session_id: str,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> list[Message]:
        """Load messages in chronological order and reconstruct ``Message``."""
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        cursor = await conn.execute(
            f"""
            SELECT role, content, tool_calls, tool_call_id, token_count
            FROM messages
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at, id
            """,
            tuple(params),
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

    async def search_sessions(
        self,
        conn: Any,
        query: str,
        limit: int,
        offset: int,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        """Search FTS5 messages, applying owner scope when supplied."""
        if principal_id is None and project_id is None:
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
        else:
            clauses = ["fts.messages_fts MATCH ?"]
            params: list[Any] = [query]
            _owner_scope(
                clauses,
                params,
                principal_id=principal_id,
                project_id=project_id,
                principal_column="m.principal_id",
                project_column="m.project_id",
            )
            params.extend([limit, offset])
            cursor = await conn.execute(
                f"""
                SELECT fts.rowid AS id, fts.session_id, fts.role,
                       fts.created_at, fts.rank,
                       snippet(messages_fts, 2, '[', ']]', '...', 12) AS snippet
                FROM messages_fts AS fts
                JOIN messages AS m ON m.id = fts.rowid
                WHERE {' AND '.join(clauses)}
                ORDER BY fts.rank
                LIMIT ? OFFSET ?
                """,
                tuple(params),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_session_messages(
        self,
        conn: Any,
        session_id: str,
        limit: int,
        offset: int,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        """Return one session's messages with owner-scoped pagination."""
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        params.extend([limit, offset])
        cursor = await conn.execute(
            f"""
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE {' AND '.join(clauses)}
            ORDER BY created_at, id
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_message_window(
        self,
        conn: Any,
        session_id: str,
        message_id: int,
        window: int,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        """Return a chronological window around one message id."""
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        params.extend([message_id, window * 2 + 1])
        cursor = await conn.execute(
            f"""
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE {' AND '.join(clauses)}
            ORDER BY ABS(id - ?), id
            LIMIT ?
            """,
            tuple(params),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        rows.sort(key=lambda row: row["id"])
        return rows

    async def count_session_messages(
        self,
        conn: Any,
        session_id: str,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> int:
        """Count messages in one owner scope."""
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        cursor = await conn.execute(
            f"SELECT COUNT(*) AS n FROM messages WHERE {' AND '.join(clauses)}",
            tuple(params),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def count_messages_before_after(
        self,
        conn: Any,
        session_id: str,
        message_id: int,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> tuple[int, int]:
        """Count messages before and after ``message_id`` in one scope."""
        clauses = ["session_id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        cursor = await conn.execute(
            "SELECT "
            "SUM(CASE WHEN id < ? THEN 1 ELSE 0 END) AS before_n, "
            "SUM(CASE WHEN id > ? THEN 1 ELSE 0 END) AS after_n "
            f"FROM messages WHERE {' AND '.join(clauses)}",
            (message_id, message_id, *params),
        )
        row = await cursor.fetchone()
        if not row:
            return (0, 0)
        return (int(row["before_n"] or 0), int(row["after_n"] or 0))

    async def list_sessions(
        self,
        conn: Any,
        limit: int,
        offset: int,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> list[dict[str, Any]]:
        """List active sessions with owner-scoped count and preview."""
        where_clauses = ["s.status = 'active'"]
        where_params: list[Any] = []
        _owner_scope(
            where_clauses,
            where_params,
            principal_id=principal_id,
            project_id=project_id,
            principal_column="s.principal_id",
            project_column="s.project_id",
        )
        sub_filters: list[str] = []
        if principal_id is not None:
            sub_filters.append("m.principal_id = s.principal_id")
        if project_id is not None:
            sub_filters.append("m.project_id = s.project_id")
        sub_where = (" AND " + " AND ".join(sub_filters)) if sub_filters else ""
        where_params.extend([limit, offset])
        cursor = await conn.execute(
            f"""
            SELECT s.id, s.mode, s.created_at,
                   (SELECT COUNT(*) FROM messages m
                    WHERE m.session_id = s.id{sub_where}) AS message_count,
                   (SELECT content FROM messages m
                    WHERE m.session_id = s.id{sub_where}
                    ORDER BY m.id DESC LIMIT 1) AS preview
            FROM sessions s
            WHERE {' AND '.join(where_clauses)}
            ORDER BY s.updated_at DESC
            LIMIT ? OFFSET ?
            """,
            tuple(where_params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_session(
        self,
        conn: Any,
        session_id: str,
        *,
        principal_id: str | None,
        project_id: str | None,
    ) -> dict[str, Any] | None:
        """Return a session row only when it matches the requested scope."""
        clauses = ["id = ?"]
        params: list[Any] = [session_id]
        _owner_scope(clauses, params, principal_id=principal_id, project_id=project_id)
        cursor = await conn.execute(
            f"""
            SELECT id, mode, principal_id, project_id, status,
                   created_at, updated_at
            FROM sessions
            WHERE {' AND '.join(clauses)}
            """,
            tuple(params),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None


__all__ = ["SessionRepository"]
