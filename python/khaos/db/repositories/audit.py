"""Durable audit-log persistence and hash-chain verification.

The repository owns audit SQL and canonical hash recomputation.  The
``Database`` facade only supplies the transaction/read ports, so audit
callers cannot accidentally bypass the shared write lock or reader lease.
"""

from __future__ import annotations

import hashlib
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

_AUDIT_GENESIS_PREV = ""
_AUDIT_HASH_FIELDS = (
    "action",
    "target",
    "result",
    "detail",
    "session_id",
    "principal_id",
    "runtime_id",
    "task_id",
    "operation_id",
    "policy_digest",
    "authority_generation",
    "source_transport",
    "project_id",
)


class AuditDatabase(Protocol):
    """Minimal transaction/read port required by :class:`AuditRepository`."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open the shared writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open a query-only reader lease."""
        ...


def _audit_row_hash(
    prev_hash: str,
    action: str,
    target: str,
    result: str,
    detail: str,
    session_id: str | None,
    principal_id: str,
    runtime_id: str | None,
    task_id: str | None,
    operation_id: str | None,
    policy_digest: str | None,
    authority_generation: int | None,
    source_transport: str | None,
    project_id: str,
) -> str:
    """Compute one deterministic audit-chain link."""
    parts = [
        prev_hash,
        str(action),
        str(target),
        str(result),
        str(detail),
        "" if session_id is None else str(session_id),
        str(principal_id),
        "" if runtime_id is None else str(runtime_id),
        "" if task_id is None else str(task_id),
        "" if operation_id is None else str(operation_id),
        "" if policy_digest is None else str(policy_digest),
        "" if authority_generation is None else str(authority_generation),
        "" if source_transport is None else str(source_transport),
        str(project_id),
    ]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


async def _audit_previous_hash(conn: Any) -> str:
    """Return the stored chain link of the most recent audit row."""
    cursor = await conn.execute(
        "SELECT prev_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    )
    row = await cursor.fetchone()
    if row is None:
        return _AUDIT_GENESIS_PREV
    return str(row["prev_hash"] or "")


_AUDIT_COLUMNS = (
    "id, action, target, result, detail, session_id, principal_id, "
    "runtime_id, task_id, operation_id, policy_digest, "
    "authority_generation, source_transport, project_id, prev_hash"
)


class AuditRepository:
    """Own audit inserts, scoped reads, queries, and chain verification."""

    def __init__(self, database: AuditDatabase) -> None:
        self._database = database

    async def insert_audit_log(
        self,
        action: str,
        target: str,
        result: str,
        detail: str = "",
        session_id: str | None = None,
        *,
        principal_id: str = "legacy",
        runtime_id: str | None = None,
        task_id: str | None = None,
        operation_id: str | None = None,
        policy_digest: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
        project_id: str = "",
    ) -> int:
        """Append one attributed audit event to the tamper-evident chain."""
        async with self._database.transaction() as conn:
            previous = await _audit_previous_hash(conn)
            row_hash = _audit_row_hash(
                previous,
                action,
                target,
                result,
                detail,
                session_id,
                principal_id,
                runtime_id,
                task_id,
                operation_id,
                policy_digest,
                authority_generation,
                source_transport,
                project_id,
            )
            cursor = await conn.execute(
                """
                INSERT INTO audit_log (
                    action, target, result, detail, session_id,
                    principal_id, runtime_id, task_id, operation_id,
                    policy_digest, authority_generation, source_transport,
                    project_id, prev_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action,
                    target,
                    result,
                    detail,
                    session_id,
                    principal_id,
                    runtime_id,
                    task_id,
                    operation_id,
                    policy_digest,
                    authority_generation,
                    source_transport,
                    project_id,
                    row_hash,
                ),
            )
            return int(cursor.lastrowid)

    async def list_audit_logs(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return audit events in insertion order, optionally scoped."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (
            ("principal_id", principal_id),
            ("project_id", project_id),
        ):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_log {where} "
                "ORDER BY created_at, id",
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def get_audit_chain_head(
        self, row_id: int | None = None
    ) -> dict[str, Any] | None:
        """Return a recomputed link for the current head or one row."""
        where = "ORDER BY id DESC LIMIT 1" if row_id is None else "WHERE id = ?"
        params = () if row_id is None else (row_id,)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_log {where}", params
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        values = dict(row)
        previous = str(values.get("prev_hash") or "")
        return {
            "id": int(values["id"]),
            "hash": self._row_hash(values, previous),
            "prev_hash": previous,
        }

    async def verify_audit_chain_since(self, row_id: int) -> list[dict[str, Any]]:
        """Verify the chain suffix starting at an anchored row."""
        async with self._database.read_connection() as conn:
            previous_cursor = await conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_log "
                "WHERE id < ? ORDER BY id DESC LIMIT 1",
                (row_id,),
            )
            previous_row = await previous_cursor.fetchone()
            cursor = await conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_log "
                "WHERE id >= ? ORDER BY id",
                (row_id,),
            )
            rows = [dict(row) for row in await cursor.fetchall()]

        expected_prev = (
            "" if previous_row is None else str(previous_row["prev_hash"] or "")
        )
        breaks: list[dict[str, Any]] = []
        for row in rows:
            stored = str(row.get("prev_hash") or "")
            expected = self._row_hash(row, expected_prev)
            if not stored or stored != expected:
                breaks.append({
                    "id": row["id"],
                    "reason": "hash chain suffix link does not match",
                })
            expected_prev = stored
        return breaks

    async def verify_audit_chain(self) -> list[dict[str, Any]]:
        """Replay the complete chain and report every broken link."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"SELECT {_AUDIT_COLUMNS} FROM audit_log ORDER BY id"
            )
            rows = [dict(row) for row in await cursor.fetchall()]

        breaks: list[dict[str, Any]] = []
        expected_prev = ""
        for index, row in enumerate(rows):
            stored = str(row.get("prev_hash") or "")
            if stored == "":
                if index == 0:
                    expected_prev = ""
                    continue
                breaks.append({
                    "id": row["id"],
                    "reason": (
                        "hash chain broken: non-genesis row carries an empty "
                        "prev_hash (possible INSERT-reset forgery)"
                    ),
                })
                expected_prev = stored
                continue
            if stored != self._row_hash(row, expected_prev):
                breaks.append({
                    "id": row["id"],
                    "reason": (
                        "hash chain broken: stored prev_hash does not match "
                        "the recomputed value from the previous link"
                    ),
                })
            expected_prev = stored
        return breaks

    async def query_audit_logs(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return newest-first audit events matching bounded filters."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, value, operator in (
            ("action", action, "="),
            ("result", result, "="),
            ("created_at", since, ">="),
            ("created_at", until, "<="),
            ("principal_id", principal_id, "="),
            ("project_id", project_id, "="),
        ):
            if value is not None:
                clauses.append(f"{column} {operator} ?")
                params.append(value)
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        params.append(limit)
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT id, action, target, result, detail, session_id, created_at,
                       principal_id, runtime_id, task_id, operation_id,
                       policy_digest, authority_generation, source_transport,
                       project_id
                FROM audit_log
                {where}
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    @staticmethod
    def _row_hash(row: dict[str, Any], previous: str) -> str:
        return _audit_row_hash(
            previous,
            str(row["action"]),
            str(row["target"]),
            str(row["result"]),
            str(row.get("detail") or ""),
            row.get("session_id"),
            str(row.get("principal_id") or "legacy"),
            row.get("runtime_id"),
            row.get("task_id"),
            row.get("operation_id"),
            row.get("policy_digest"),
            row.get("authority_generation"),
            row.get("source_transport"),
            str(row.get("project_id") or ""),
        )


__all__ = [
    "AuditDatabase",
    "AuditRepository",
    "_audit_previous_hash",
    "_audit_row_hash",
]
