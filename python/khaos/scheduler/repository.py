"""Persistence port for scheduled tasks.

``CronEngine`` owns orchestration and in-memory lifecycle state; this module
owns the scheduler-facing persistence vocabulary.  The concrete ``Database``
continues to own SQLite transactions and SQL.  Keeping the project scope in
this adapter prevents a caller from accidentally issuing an unscoped read or
write while the storage implementation is migrated independently.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Protocol


class ScheduledTaskDatabase(Protocol):
    """Minimal async database surface consumed by the scheduler repository."""

    def __getattr__(self, name: str) -> Callable[..., Awaitable[Any]]: ...


class ScheduledTaskRepository:
    """Project-scoped adapter around the durable scheduled-task store."""

    def __init__(self, database: ScheduledTaskDatabase | None, *, project_id: str) -> None:
        self._database = database
        self._project_id = project_id

    @property
    def available(self) -> bool:
        """Return whether durable persistence is configured."""
        return self._database is not None

    def _require_database(self) -> ScheduledTaskDatabase:
        if self._database is None:
            raise RuntimeError("scheduled-task persistence is unavailable")
        return self._database

    async def insert_task(
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
        policy_digest: str = "",
    ) -> str:
        return await self._require_database().insert_scheduled_task(
            name,
            prompt,
            status,
            schedule,
            deliver_to,
            meta,
            principal_id=principal_id,
            next_run=next_run,
            project_id=self._project_id,
            policy_digest=policy_digest,
        )

    async def list_tasks(self) -> list[dict[str, Any]]:
        return await self._require_database().list_scheduled_tasks(
            project_id=self._project_id
        )

    async def get_task(self, task_id: str) -> dict[str, Any] | None:
        return await self._require_database().get_scheduled_task(
            task_id, project_id=self._project_id
        )

    async def claim_task(
        self,
        task_id: str,
        *,
        execution_id: str,
        started_at: str,
        lease_until: str,
        expected_version: int,
        principal_id: str,
        policy_digest: str,
        project_id: str | None = None,
    ) -> int:
        return await self._require_database().claim_scheduled_task(
            task_id,
            execution_id=execution_id,
            started_at=started_at,
            lease_until=lease_until,
            expected_version=expected_version,
            expected_principal_id=principal_id,
            expected_project_id=(
                self._project_id if project_id is None else project_id
            ),
            expected_policy_digest=policy_digest,
        )

    async def clear_lease(self, task_id: str, *, execution_id: str) -> int:
        return await self._require_database().clear_scheduled_task_lease(
            task_id, execution_id=execution_id
        )

    async def finalize_task(
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
        return await self._require_database().finalize_scheduled_task(
            task_id,
            execution_id=execution_id,
            expected_version=expected_version,
            status=status,
            last_run=last_run,
            next_run=next_run,
            run_count=run_count,
            last_result=last_result,
            error=error,
        )

    async def control_finalize(
        self,
        task_id: str,
        *,
        expected_version: int,
        target_version: int,
        status: str,
        next_run: str | None = None,
        error: str | None = None,
    ) -> int:
        return await self._require_database().control_finalize_scheduled_task(
            task_id,
            expected_version=expected_version,
            target_version=target_version,
            status=status,
            next_run=next_run,
            error=error,
        )

    async def insert_journal_entry(
        self,
        *,
        operation_id: str,
        task_id: str,
        operation_type: str,
        desired_status: str,
        expected_version: int,
        target_version: int,
        principal_id: str,
        policy_digest: str,
    ) -> int:
        return await self._require_database().insert_scheduler_journal_entry(
            operation_id=operation_id,
            task_id=task_id,
            operation_type=operation_type,
            desired_status=desired_status,
            expected_version=expected_version,
            target_version=target_version,
            principal_id=principal_id,
            policy_digest=policy_digest,
            project_id=self._project_id,
        )

    async def mark_journal_applied(self, operation_id: str) -> int:
        return await self._require_database().mark_scheduler_journal_applied(
            operation_id
        )

    async def list_pending_journal_entries(self) -> list[dict[str, Any]]:
        return await self._require_database().list_pending_scheduler_journal_entries()

    async def query_running_task_ids(self) -> list[str]:
        return await self._require_database().query_running_task_ids()

    async def recover_all_running(self) -> int:
        return await self._require_database().recover_all_running_tasks()

    async def query_expired_lease_task_ids(self, *, now_iso: str) -> list[str]:
        return await self._require_database().query_expired_lease_task_ids(
            now_iso=now_iso
        )

    async def recover_expired(self, *, now_iso: str) -> int:
        return await self._require_database().recover_expired_leases(now_iso=now_iso)

    async def recover_one_expired(self, task_id: str, *, now_iso: str) -> bool:
        return await self._require_database().recover_one_expired_lease(
            task_id, now_iso=now_iso
        )


__all__ = ["ScheduledTaskDatabase", "ScheduledTaskRepository"]
