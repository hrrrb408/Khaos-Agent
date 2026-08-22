"""Durable tool-operation journal persistence.

The runtime operation store owns in-process waiters and result projection.
This repository owns the SQLite row protocol used for claim, terminalization,
effect identity updates, orphan quarantine, and bounded tombstone pruning.
"""

from __future__ import annotations

from contextlib import AbstractAsyncContextManager
from datetime import UTC, datetime
from typing import Any, Protocol

from khaos.time_utils import utc_now_naive


class ToolOperationDatabase(Protocol):
    """Minimal transaction/read port required by the operation repository."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open one atomic writer transaction."""
        ...


class ToolOperationRepository:
    """Own the durable idempotency row protocol."""

    def __init__(self, database: ToolOperationDatabase) -> None:
        self._database = database

    async def claim_tool_operation(
        self,
        *,
        operation_id: str,
        tool_name: str,
        arguments_digest: str,
        effect_id: str,
        owner_token: str,
        principal_id: str = "",
        project_id: str = "",
        session_id: str = "",
        task_id: str = "",
        workspace_id: str = "",
    ) -> dict[str, Any]:
        """Claim or replay one operation under its complete owner scope."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT operation_id, tool_name, arguments_digest, status, "
                "effect_id, effect_status, reconciliation_hint, result_json, "
                "owner_token, principal_id, project_id, session_id, task_id, "
                "workspace_id, created_at, updated_at "
                "FROM tool_operations WHERE operation_id = ?",
                (operation_id,),
            )
            row = await cursor.fetchone()
            if row is not None:
                values = dict(row)
                expected_scope = {
                    "principal_id": principal_id,
                    "project_id": project_id,
                    "session_id": session_id,
                    "task_id": task_id,
                    "workspace_id": workspace_id,
                }
                mismatched_scope = [
                    field
                    for field, expected in expected_scope.items()
                    if str(values.get(field) or "") != str(expected or "")
                ]
                if mismatched_scope:
                    return {
                        "state": "conflict",
                        "conflict_reason": (
                            "operation scope mismatch: "
                            + ", ".join(sorted(mismatched_scope))
                        ),
                        **values,
                    }
                if (
                    values["tool_name"] != tool_name
                    or values["arguments_digest"] != arguments_digest
                ):
                    return {
                        "state": "conflict",
                        "conflict_reason": (
                            "idempotency key was reused with different tool arguments"
                        ),
                        **values,
                    }
                return {"state": "existing", **values}

            now = utc_now_naive().isoformat()
            await conn.execute(
                """
                INSERT INTO tool_operations (
                    operation_id, tool_name, arguments_digest, status,
                    effect_id, effect_status, reconciliation_hint, result_json,
                    owner_token, principal_id, project_id, session_id, task_id,
                    workspace_id, created_at, updated_at
                ) VALUES (?, ?, ?, 'running', ?, ?, '', '', ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    tool_name,
                    arguments_digest,
                    effect_id,
                    "not_started",
                    owner_token,
                    principal_id,
                    project_id,
                    session_id,
                    task_id,
                    workspace_id,
                    now,
                    now,
                ),
            )
            return {
                "state": "claimed",
                "operation_id": operation_id,
                "tool_name": tool_name,
                "arguments_digest": arguments_digest,
                "status": "running",
                "effect_id": effect_id,
                "effect_status": "not_started",
                "reconciliation_hint": "",
                "result_json": "",
                "owner_token": owner_token,
            }

    async def complete_tool_operation(
        self,
        *,
        operation_id: str,
        owner_token: str,
        status: str,
        effect_status: str,
        reconciliation_hint: str = "",
        result_json: str = "",
    ) -> int:
        """Finalize a running operation only for its original owner."""
        if status not in {"completed", "unknown"}:
            raise ValueError(f"invalid tool operation terminal status: {status}")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE tool_operations
                SET status = ?, effect_status = ?, reconciliation_hint = ?,
                    result_json = ?, updated_at = ?
                WHERE operation_id = ? AND owner_token = ? AND status = 'running'
                """,
                (
                    status,
                    effect_status,
                    reconciliation_hint,
                    result_json,
                    utc_now_naive().isoformat(),
                    operation_id,
                    owner_token,
                ),
            )
            return int(cursor.rowcount or 0)

    async def update_tool_operation_effect_id(
        self, *, operation_id: str, owner_token: str, effect_id: str
    ) -> int:
        """Persist an external effect identifier while the row is running."""
        if not effect_id or len(effect_id) > 256 or any(
            char in effect_id for char in "\x00\r\n"
        ):
            raise ValueError("invalid tool operation effect_id")
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE tool_operations
                SET effect_id = ?, updated_at = ?
                WHERE operation_id = ? AND owner_token = ? AND status = 'running'
                """,
                (
                    effect_id,
                    utc_now_naive().isoformat(),
                    operation_id,
                    owner_token,
                ),
            )
            return int(cursor.rowcount or 0)

    async def mark_tool_operation_unknown(
        self,
        *,
        operation_id: str,
        reconciliation_hint: str,
        result_json: str,
    ) -> int:
        """Quarantine an orphaned running operation without replaying it."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE tool_operations
                SET status = 'unknown', effect_status = 'unknown',
                    reconciliation_hint = ?, result_json = ?, updated_at = ?
                WHERE operation_id = ? AND status = 'running'
                """,
                (
                    reconciliation_hint,
                    result_json,
                    utc_now_naive().isoformat(),
                    operation_id,
                ),
            )
            return int(cursor.rowcount or 0)

    async def prune_tool_operations(
        self, *, older_than_seconds: float, now: float, limit: int = 256
    ) -> int:
        """Delete only completed rows proven to have no external effect."""
        cutoff = datetime.fromtimestamp(
            now - max(0.0, older_than_seconds), UTC
        ).replace(tzinfo=None).isoformat()
        bounded_limit = max(1, min(limit, 10_000))
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "SELECT operation_id FROM tool_operations "
                "WHERE status = 'completed' AND effect_status = 'not_applied' "
                "AND updated_at < ? ORDER BY updated_at LIMIT ?",
                (cutoff, bounded_limit),
            )
            operation_ids = [
                str(row["operation_id"]) for row in await cursor.fetchall()
            ]
            if not operation_ids:
                return 0
            placeholders = ",".join("?" for _ in operation_ids)
            deleted = await conn.execute(
                f"DELETE FROM tool_operations WHERE operation_id IN ({placeholders})",
                tuple(operation_ids),
            )
            return int(deleted.rowcount or 0)


__all__ = ["ToolOperationDatabase", "ToolOperationRepository"]
