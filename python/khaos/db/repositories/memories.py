"""SQL repository for the durable memory tables.

The repository owns memory SQL and row shape.  ``Database`` remains the
connection/lifecycle and transaction owner; this module never opens a second
SQLite connection and never decides principal or project authorization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from khaos.memory.ownership import MemoryVisibility

_SHARED_NAMESPACE = "shared"


class MemorySqlRepository:
    """Execute memory queries through the shared ``Database`` ports."""

    def __init__(self, db: Any) -> None:
        self._db = db

    @property
    def database(self) -> Any:
        """Return the shared Database port for V2 composition only."""

        return self._db

    async def get(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> dict[str, Any] | None:
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT id, scope, key, value, ttl, confidence, access_freq,
                       created_at, updated_at, principal_id, namespace, session_id,
                       project_id
                FROM memories
                WHERE project_id = ? AND namespace = ? AND principal_id = ?
                  AND session_id = ? AND scope = ? AND key = ?
                """,
                (project_id, namespace, principal_id, session_id, scope, key),
            )
            row = await cursor.fetchone()
            return dict(row) if row is not None else None

    async def upsert(
        self,
        scope: str,
        key: str,
        value: str,
        ttl: int,
        confidence: int,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> int:
        async with self._db.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO memories (
                    scope, key, value, ttl, confidence,
                    principal_id, namespace, session_id, project_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id, namespace, principal_id, session_id, scope, key) DO UPDATE SET
                    value = excluded.value,
                    ttl = excluded.ttl,
                    confidence = excluded.confidence,
                    updated_at = datetime('now')
                """,
                (
                    scope,
                    key,
                    value,
                    ttl,
                    confidence,
                    principal_id,
                    namespace,
                    session_id,
                    project_id,
                ),
            )
            cursor = await conn.execute(
                """
                SELECT id FROM memories
                WHERE project_id = ? AND namespace = ? AND principal_id = ?
                  AND session_id = ? AND scope = ? AND key = ?
                """,
                (project_id, namespace, principal_id, session_id, scope, key),
            )
            row = await cursor.fetchone()
            if row is None:
                raise RuntimeError("memory upsert committed without a row")
            return int(row["id"])

    async def delete(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str,
        namespace: str,
        session_id: str,
        project_id: str,
    ) -> None:
        async with self._db.transaction() as conn:
            await conn.execute(
                """
                DELETE FROM memories
                WHERE project_id = ? AND namespace = ? AND principal_id = ?
                  AND session_id = ? AND scope = ? AND key = ?
                """,
                (project_id, namespace, principal_id, session_id, scope, key),
            )

    async def delete_by_id(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> None:
        clauses = ["id = ?", "project_id = ?"]
        params: list[Any] = [memory_id, project_id]
        clauses.extend(self._visibility_clauses(visibility, principal_id, params))
        async with self._db.transaction() as conn:
            await conn.execute(
                f"DELETE FROM memories WHERE {' AND '.join(clauses)}",
                tuple(params),
            )

    async def list(
        self,
        scope: str | None = None,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = ["project_id = ?"]
        params: list[Any] = [project_id]
        if scope is not None:
            clauses.append("scope = ?")
            params.append(scope)
        clauses.extend(self._visibility_clauses(visibility, principal_id, params))
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT id, scope, key, value, ttl, confidence, access_freq,
                       created_at, updated_at, principal_id, namespace, session_id,
                       project_id
                FROM memories
                WHERE {' AND '.join(clauses)}
                ORDER BY confidence DESC, updated_at DESC, id DESC
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def search(
        self,
        query: str,
        top_k: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> list[dict[str, Any]]:
        clauses = [
            "memory_fts MATCH ?",
            "m.project_id = ?",
        ]
        params: list[Any] = [query, project_id]
        clauses.extend(
            self._visibility_clauses(
                visibility,
                principal_id,
                params,
                table_alias="m",
            )
        )
        params.append(top_k)
        async with self._db.read_connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT m.id, m.scope, m.key, m.value, m.ttl, m.confidence,
                       m.access_freq, m.created_at, m.updated_at,
                       m.principal_id, m.namespace, m.session_id, m.project_id
                FROM memory_fts
                JOIN memories AS m ON m.id = memory_fts.rowid
                WHERE {' AND '.join(clauses)}
                ORDER BY bm25(memory_fts)
                LIMIT ?
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def touch(
        self,
        memory_id: int,
        *,
        principal_id: str,
        project_id: str,
        visibility: MemoryVisibility | None = None,
    ) -> None:
        clauses = ["id = ?", "project_id = ?"]
        params: list[Any] = [memory_id, project_id]
        clauses.extend(self._visibility_clauses(visibility, principal_id, params))
        async with self._db.transaction() as conn:
            await conn.execute(
                f"""
                UPDATE memories
                SET access_freq = access_freq + 1, updated_at = datetime('now')
                WHERE {' AND '.join(clauses)}
                """,
                tuple(params),
            )

    @staticmethod
    def _visibility_clauses(
        visibility: MemoryVisibility | None,
        principal_id: str,
        params: list[Any],
        *,
        table_alias: str = "",
    ) -> list[str]:
        """Build one complete ownership/namespace predicate.

        The durable view deliberately includes only ``private`` and
        ``shared`` rows with an empty session id.  Exact session views use the
        caller's principal and one session id, so a row id cannot widen a
        touch/delete operation into another session.
        """

        prefix = f"{table_alias}." if table_alias else ""
        if visibility is None or visibility.namespace is None:
            params.append(principal_id)
            return [
                f"{prefix}namespace IN ('private', 'shared')",
                f"{prefix}session_id = ''",
                f"({prefix}principal_id = ? OR ({prefix}namespace = 'shared' AND {prefix}principal_id = ''))",
            ]

        params.extend([visibility.namespace, visibility.session_id])
        if visibility.namespace == _SHARED_NAMESPACE:
            return [
                f"{prefix}namespace = ?",
                f"{prefix}session_id = ?",
                f"{prefix}principal_id = ''",
            ]

        params.append(principal_id)
        return [
            f"{prefix}namespace = ?",
            f"{prefix}session_id = ?",
            f"{prefix}principal_id = ?",
        ]


__all__ = ["MemorySqlRepository"]
