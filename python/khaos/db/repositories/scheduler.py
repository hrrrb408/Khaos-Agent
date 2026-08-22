"""Durable scheduler persistence owned by the database repository layer.

The scheduler engine owns lifecycle orchestration and in-memory task state.
This module owns the SQL for scheduled tasks, execution leases, lifecycle CAS
transitions, and the scheduler operation journal.  It deliberately consumes
only the database transaction/read ports so the physical connection and
migration lifecycle remain outside the domain repository.
"""

from __future__ import annotations

import json
import uuid
from contextlib import AbstractAsyncContextManager
from typing import Any, Protocol

from khaos.time_utils import utc_now_naive


class SchedulerDatabase(Protocol):
    """Minimal database port required by :class:`SchedulerRepository`."""

    def transaction(self) -> AbstractAsyncContextManager[Any]:
        """Open one atomic writer transaction."""
        ...

    def read_connection(self) -> AbstractAsyncContextManager[Any]:
        """Open one bounded query-only reader lease."""
        ...


def _schedule_to_dict(schedule: Any) -> dict[str, Any]:
    """Convert a schedule value object into JSON-safe storage data."""
    if schedule is None:
        return {}
    if isinstance(schedule, dict):
        return dict(schedule)
    if hasattr(schedule, "__dict__"):
        return dict(vars(schedule))
    return {}


class SchedulerRepository:
    """Own scheduled-task and scheduler-journal SQL."""

    def __init__(self, database: SchedulerDatabase) -> None:
        self._database = database

    async def insert_scheduled_task(
        self,
        name: str,
        prompt: str,
        status: str,
        schedule: Any,
        deliver_to: str = "local",
        meta: dict[str, Any] | None = None,
        *,
        principal_id: str = "",
        next_run: str | None = None,
        project_id: str = "",
        policy_digest: str = "",
    ) -> str:
        """Insert one principal/project-bound scheduled task."""
        if not principal_id:
            raise ValueError("principal_id is required for scheduled task creation")
        task_id = uuid.uuid4().hex[:12]
        async with self._database.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO scheduled_tasks
                    (id, name, prompt, status, schedule_config, deliver_to, meta,
                     principal_id, next_run, project_id, policy_digest)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    name,
                    prompt,
                    status,
                    json.dumps(_schedule_to_dict(schedule), ensure_ascii=False),
                    deliver_to,
                    json.dumps(meta or {}, ensure_ascii=False),
                    principal_id,
                    next_run,
                    project_id,
                    policy_digest,
                ),
            )
        return task_id

    async def update_scheduled_task_status(
        self, task_id: str, status: str, bump_version: bool = False
    ) -> int:
        """Update only status, optionally advancing the lifecycle version."""
        async with self._database.transaction() as conn:
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
            return int(cursor.rowcount or 0)

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
        """Update selected task columns in one transaction."""
        values = {
            "status": status,
            "last_run": last_run,
            "next_run": next_run,
            "run_count": run_count,
            "last_result": last_result,
            "error": error,
        }
        clauses = [f"{column} = ?" for column, value in values.items() if value is not None]
        params = [value for value in values.values() if value is not None]
        if bump_version:
            clauses.append("lifecycle_version = lifecycle_version + 1")
        if not clauses:
            return 1
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                f"UPDATE scheduled_tasks SET {', '.join(clauses)} WHERE id = ?",
                (*params, task_id),
            )
            return int(cursor.rowcount or 0)

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
        """CAS-update executor state without advancing lifecycle version."""
        values = {
            "status": status,
            "last_run": last_run,
            "next_run": next_run,
            "run_count": run_count,
            "last_result": last_result,
            "error": error,
        }
        clauses = [f"{column} = ?" for column, value in values.items() if value is not None]
        if not clauses:
            return 0
        params = [value for value in values.values() if value is not None]
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
                "WHERE id = ? AND lifecycle_version = ?",
                (*params, task_id, expected_version),
            )
            return int(cursor.rowcount or 0)

    async def list_scheduled_tasks(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List tasks with optional independent principal/project scopes."""
        clauses: list[str] = []
        params: list[Any] = []
        for column, value in (("principal_id", principal_id), ("project_id", project_id)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                f"""
                SELECT id, name, prompt, status, schedule_config, deliver_to, meta,
                       created_at, last_run, next_run, run_count, last_result, error,
                       lifecycle_version, principal_id, execution_id, lease_until,
                       policy_digest, project_id
                FROM scheduled_tasks
                {where}
                ORDER BY created_at
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def get_scheduled_task(
        self,
        task_id: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Load one task, hiding rows outside the requested owner scope."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,)
            )
            row = await cursor.fetchone()
        if row is None:
            return None
        result = dict(row)
        if principal_id is not None and result.get("principal_id") != principal_id:
            return None
        if project_id is not None and result.get("project_id") != project_id:
            return None
        return result

    async def claim_scheduled_task(
        self,
        task_id: str,
        *,
        execution_id: str,
        started_at: str,
        lease_until: str,
        expected_version: int,
        expected_principal_id: str | None = None,
        expected_project_id: str | None = None,
        expected_policy_digest: str | None = None,
    ) -> int:
        """Atomically claim a pending task and stamp its durable lease."""
        where = ["id = ?", "status = 'pending'", "lifecycle_version = ?"]
        params: list[Any] = [task_id, expected_version]
        for column, value in (
            ("principal_id", expected_principal_id),
            ("project_id", expected_project_id),
            ("policy_digest", expected_policy_digest),
        ):
            if value is not None:
                where.append(f"{column} = ?")
                params.append(value)
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET status = 'running', execution_id = ?, "
                "lease_until = ?, last_run = ? WHERE " + " AND ".join(where),
                (execution_id, lease_until, started_at, *params),
            )
            return int(cursor.rowcount or 0)

    async def clear_scheduled_task_lease(self, task_id: str, *, execution_id: str) -> int:
        """Clear a lease only when its execution owner still matches."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET execution_id = NULL, lease_until = NULL "
                "WHERE id = ? AND execution_id = ?",
                (task_id, execution_id),
            )
            return int(cursor.rowcount or 0)

    async def recover_expired_leases(self, *, now_iso: str) -> int:
        """Fail closed all running tasks whose durable lease expired."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE scheduled_tasks
                SET status = 'failed', error = 'execution lease expired '
                    || '(process crash during execution; at-least-once disclosure)',
                    execution_id = NULL, lease_until = NULL,
                    lifecycle_version = lifecycle_version + 1
                WHERE status = 'running' AND lease_until IS NOT NULL
                      AND lease_until < ?
                """,
                (now_iso,),
            )
            return int(cursor.rowcount or 0)

    async def recover_all_running_tasks(self) -> int:
        """Fail closed every running task during single-instance startup."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE scheduled_tasks
                SET status = 'failed',
                    error = 'process restart detected - task was running '
                            || 'at startup; single-instance model treats '
                            || 'this as a crash (at-least-once disclosure)',
                    execution_id = NULL, lease_until = NULL,
                    lifecycle_version = lifecycle_version + 1
                WHERE status = 'running'
                """
            )
            return int(cursor.rowcount or 0)

    async def query_running_task_ids(self) -> list[str]:
        """Read running task IDs without mutating their state."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM scheduled_tasks WHERE status = 'running'"
            )
            rows = await cursor.fetchall()
        return [str(row[0]) for row in rows]

    async def query_expired_lease_task_ids(self, *, now_iso: str) -> list[str]:
        """Read expired task IDs before the live executor is revoked."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                "SELECT id FROM scheduled_tasks WHERE status = 'running' "
                "AND lease_until IS NOT NULL AND lease_until < ?",
                (now_iso,),
            )
            rows = await cursor.fetchall()
        return [str(row[0]) for row in rows]

    async def recover_one_expired_lease(self, task_id: str, *, now_iso: str) -> bool:
        """Recover one expired task after its live executor was revoked."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                UPDATE scheduled_tasks
                SET status = 'failed', error = 'execution lease expired '
                    || '(periodic sweep; live executor revoked; '
                    || 'at-least-once disclosure)',
                    execution_id = NULL, lease_until = NULL,
                    lifecycle_version = lifecycle_version + 1
                WHERE id = ? AND status = 'running'
                      AND lease_until IS NOT NULL AND lease_until < ?
                """,
                (task_id, now_iso),
            )
            return int(cursor.rowcount or 0) == 1

    async def finalize_scheduled_task(
        self,
        task_id: str,
        *,
        execution_id: str,
        expected_version: int,
        status: str,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
    ) -> int:
        """CAS-write executor terminal state and clear its lease atomically."""
        values = {
            "last_run": last_run,
            "next_run": next_run,
            "run_count": run_count,
            "last_result": last_result,
            "error": error,
        }
        clauses = ["status = ?", "execution_id = NULL", "lease_until = NULL"]
        params: list[Any] = [status]
        for column, value in values.items():
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
                "WHERE id = ? AND execution_id = ? AND lifecycle_version = ?",
                (*params, task_id, execution_id, expected_version),
            )
            return int(cursor.rowcount or 0)

    async def control_update_scheduled_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        target_version: int,
        status: str,
        next_run: str | None = None,
        error: str | None = None,
    ) -> int:
        """CAS-write a control state transition without clearing a lease."""
        clauses = ["status = ?", "lifecycle_version = ?"]
        params: list[Any] = [status, target_version]
        for column, value in (("next_run", next_run), ("error", error)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
                "WHERE id = ? AND lifecycle_version = ?",
                (*params, task_id, expected_version),
            )
            return int(cursor.rowcount or 0)

    async def control_finalize_scheduled_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        target_version: int,
        status: str,
        next_run: str | None = None,
        error: str | None = None,
    ) -> int:
        """CAS-write a control state transition and clear its lease atomically."""
        clauses = [
            "status = ?",
            "lifecycle_version = ?",
            "execution_id = NULL",
            "lease_until = NULL",
        ]
        params: list[Any] = [status, target_version]
        for column, value in (("next_run", next_run), ("error", error)):
            if value is not None:
                clauses.append(f"{column} = ?")
                params.append(value)
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
                "WHERE id = ? AND lifecycle_version = ?",
                (*params, task_id, expected_version),
            )
            return int(cursor.rowcount or 0)

    async def insert_scheduler_journal_entry(
        self,
        *,
        operation_id: str,
        task_id: str,
        operation_type: str,
        desired_status: str,
        expected_version: int,
        target_version: int,
        principal_id: str = "",
        policy_digest: str = "",
        project_id: str = "",
    ) -> int:
        """Persist one control-operation intent before its CAS transition."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO scheduler_operation_journal
                    (operation_id, task_id, operation_type, desired_status,
                     expected_version, target_version, principal_id,
                     policy_digest, project_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    task_id,
                    operation_type,
                    desired_status,
                    expected_version,
                    target_version,
                    principal_id,
                    policy_digest,
                    project_id,
                    utc_now_naive().isoformat(),
                ),
            )
            return int(cursor.lastrowid or 0)

    async def mark_scheduler_journal_applied(self, operation_id: str) -> int:
        """Mark one journal intent applied, idempotently."""
        async with self._database.transaction() as conn:
            cursor = await conn.execute(
                "UPDATE scheduler_operation_journal SET applied_at = ? "
                "WHERE operation_id = ? AND applied_at IS NULL",
                (utc_now_naive().isoformat(), operation_id),
            )
            return int(cursor.rowcount or 0)

    async def list_pending_scheduler_journal_entries(self) -> list[dict[str, Any]]:
        """Return unapplied journal intents in sequence order."""
        async with self._database.read_connection() as conn:
            cursor = await conn.execute(
                """
                SELECT seq, operation_id, task_id, operation_type,
                       desired_status, expected_version, target_version,
                       principal_id, policy_digest, project_id, created_at
                FROM scheduler_operation_journal
                WHERE applied_at IS NULL
                ORDER BY seq ASC
                """
            )
            rows = await cursor.fetchall()
        return [
            {
                "seq": int(row[0]),
                "operation_id": str(row[1]),
                "task_id": str(row[2]),
                "operation_type": str(row[3]),
                "desired_status": str(row[4]),
                "expected_version": int(row[5]),
                "target_version": int(row[6]),
                "principal_id": str(row[7]),
                "policy_digest": str(row[8]),
                "project_id": str(row[9]),
                "created_at": str(row[10]),
            }
            for row in rows
        ]


__all__ = ["SchedulerDatabase", "SchedulerRepository", "_schedule_to_dict"]
