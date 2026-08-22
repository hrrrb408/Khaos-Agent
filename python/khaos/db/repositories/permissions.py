"""Persistence owner for permission rules and authorization epochs."""

from __future__ import annotations

import asyncio
import json
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol


class PermissionDatabase(Protocol):
    """Minimal transaction/read port used by :class:`PermissionRepository`."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


class PermissionRepository:
    """Own permission SQL, epoch transitions, and their serialization."""

    def __init__(self, database: PermissionDatabase) -> None:
        self._database = database
        self._authorization_lock = asyncio.Lock()

    async def insert_permission_rule(
        self,
        pattern: str,
        permission_level: str,
        approval: str,
        mode: str,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
        policy_digest: str = "",
        generation: int = 0,
        transport_class: str = "interactive",
        grant_lifetime: str = "project_interactive",
        session_id: str = "",
        task_id: str = "",
        workspace_id: str = "",
        expires_at: float | None = None,
        created_by: str = "",
        resource_type: str = "",
        resource_spec: dict[str, Any] | str | None = None,
    ) -> int:
        """Insert a rule and advance its bound authorization epoch."""
        if isinstance(resource_spec, dict):
            resource_spec_value = json.dumps(
                resource_spec,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            )
        else:
            resource_spec_value = str(resource_spec or "")

        async with self._authorization_lock, self._database.transaction() as conn:
            row = await self._authorization_context_row(
                conn, principal_id, project_id
            )
            if row is None:
                epoch = 1
                await conn.execute(
                    "INSERT INTO authorization_contexts "
                    "(principal_id, project_id, policy_digest, epoch) "
                    "VALUES (?, ?, ?, ?)",
                    (principal_id, project_id, policy_digest, epoch),
                )
            else:
                if str(row["policy_digest"]) != policy_digest:
                    raise ValueError(
                        "permission grant policy digest does not match the "
                        "authoritative authorization context"
                    )
                epoch = int(row["epoch"]) + 1
                await conn.execute(
                    "UPDATE authorization_contexts SET epoch = ?, "
                    "updated_at = datetime('now') "
                    "WHERE principal_id = ? AND project_id = ?",
                    (epoch, principal_id, project_id),
                )

            await conn.execute(
                "UPDATE permissions SET generation = ? "
                "WHERE principal_id = ? AND project_id = ? "
                "AND policy_digest = ?",
                (epoch, principal_id, project_id, policy_digest),
            )
            cursor = await conn.execute(
                """
                INSERT INTO permissions (
                    pattern, permission_level, approval, mode,
                    principal_id, project_id, policy_digest, generation,
                    transport_class, grant_lifetime, session_id, task_id,
                    workspace_id, expires_at, created_by,
                    resource_type, resource_spec
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pattern,
                    permission_level,
                    approval,
                    mode,
                    principal_id,
                    project_id,
                    policy_digest,
                    epoch,
                    transport_class,
                    grant_lifetime,
                    session_id,
                    task_id,
                    workspace_id,
                    expires_at,
                    created_by,
                    resource_type,
                    resource_spec_value,
                ),
            )
            return int(cursor.lastrowid)

    async def list_permission_rules(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
        policy_digest: str | None = None,
        generation: int | None = None,
    ) -> list[dict[str, Any]]:
        """Load permission rules newest first with optional owner filters."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("principal_id", principal_id),
            ("project_id", project_id),
            ("policy_digest", policy_digest),
            ("generation", generation),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT id, pattern, permission_level, approval, mode,
                       strftime('%s', granted_at) AS granted_at,
                       principal_id, project_id, policy_digest, generation,
                       transport_class, grant_lifetime, session_id, task_id,
                       workspace_id, expires_at, created_by,
                       resource_type, resource_spec
                FROM permissions
                {where}
                ORDER BY granted_at DESC, id DESC
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def delete_permission_rule(
        self,
        rule_id: int,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
        policy_digest: str | None = None,
    ) -> int:
        """Delete one rule, advancing the scoped epoch when authorized."""
        if principal_id is None or project_id is None or policy_digest is None:
            async with self._database.transaction() as conn:
                cursor = await conn.execute(
                    "DELETE FROM permissions WHERE id = ?"
                    + (" AND principal_id = ?" if principal_id is not None else ""),
                    (rule_id, principal_id)
                    if principal_id is not None
                    else (rule_id,),
                )
                return int(cursor.rowcount or 0)

        async with self._authorization_lock, self._database.transaction() as conn:
            row = await self._authorization_context_row(
                conn, principal_id, project_id
            )
            if row is None or str(row["policy_digest"]) != policy_digest:
                return 0
            cursor = await conn.execute(
                "DELETE FROM permissions WHERE id = ? AND principal_id = ? "
                "AND project_id = ? AND policy_digest = ?",
                (rule_id, principal_id, project_id, policy_digest),
            )
            if not (cursor.rowcount or 0):
                return 0
            epoch = int(row["epoch"]) + 1
            await conn.execute(
                "UPDATE authorization_contexts SET epoch = ?, "
                "updated_at = datetime('now') "
                "WHERE principal_id = ? AND project_id = ?",
                (epoch, principal_id, project_id),
            )
            await conn.execute(
                "UPDATE permissions SET generation = ? "
                "WHERE principal_id = ? AND project_id = ? "
                "AND policy_digest = ?",
                (epoch, principal_id, project_id, policy_digest),
            )
            return int(cursor.rowcount or 0)

    async def bind_authorization_context(
        self, principal_id: str, project_id: str, policy_digest: str
    ) -> int:
        """Bind a policy digest and bump its epoch only when it changes."""
        async with self._authorization_lock, self._database.transaction() as conn:
            row = await self._authorization_context_row(
                conn, principal_id, project_id
            )
            if row is None:
                epoch = 1
                await conn.execute(
                    "INSERT INTO authorization_contexts "
                    "(principal_id, project_id, policy_digest, epoch) "
                    "VALUES (?, ?, ?, ?)",
                    (principal_id, project_id, policy_digest, epoch),
                )
            elif str(row["policy_digest"]) == policy_digest:
                epoch = int(row["epoch"])
            else:
                epoch = int(row["epoch"]) + 1
                await conn.execute(
                    "UPDATE authorization_contexts SET policy_digest = ?, "
                    "epoch = ?, updated_at = datetime('now') "
                    "WHERE principal_id = ? AND project_id = ?",
                    (policy_digest, epoch, principal_id, project_id),
                )
            return epoch

    async def get_authorization_context(
        self, principal_id: str, project_id: str
    ) -> dict[str, Any] | None:
        """Read one principal/project authorization context."""
        async with self._database.read_connection() as conn:
            row = await self._authorization_context_row(
                conn, principal_id, project_id
            )
        return dict(row) if row is not None else None

    @staticmethod
    async def _authorization_context_row(
        conn: Any, principal_id: str, project_id: str
    ) -> Any:
        cursor = await conn.execute(
            "SELECT principal_id, project_id, policy_digest, epoch "
            "FROM authorization_contexts WHERE principal_id = ? "
            "AND project_id = ?",
            (principal_id, project_id),
        )
        return await cursor.fetchone()


__all__ = ["PermissionDatabase", "PermissionRepository"]
