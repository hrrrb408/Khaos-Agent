"""Application façade joining canonical supervision events and controls."""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Any

from khaos.supervision.contracts import (
    ControlCommandResult,
    CurrentActivity,
    PlanProjection,
    SupervisionActor,
    SupervisionEvent,
    SupervisionEventType,
    SupervisionSeverity,
    TaskSupervisionState,
)
from khaos.supervision.control import (
    RuntimeControlHandle,
    TaskCancellationRequested,
    TaskControlService,
)
from khaos.supervision.repository import TaskSupervisionRepository


class TaskSupervisionService:
    """Typed owner used by AgentLoop and all presentation adapters."""

    def __init__(
        self,
        database: Any | None = None,
        *,
        repository: TaskSupervisionRepository | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        self.repository = repository or TaskSupervisionRepository(database)
        self.control = TaskControlService(
            repository=self.repository, audit_logger=audit_logger
        )

    async def emit(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        event_type: SupervisionEventType | str,
        payload: Mapping[str, object] | None = None,
        repository_generation: int | None = None,
        plan_revision: int | None = None,
        actor: SupervisionActor | str = SupervisionActor.RUNTIME,
        severity: SupervisionSeverity | str = SupervisionSeverity.INFO,
        event_id: str | None = None,
    ) -> SupervisionEvent:
        event = SupervisionEvent(
            event_id=event_id or uuid.uuid4().hex,
            task_id=task_id,
            workspace_id=workspace_id,
            event_type=event_type,
            repository_generation=repository_generation,
            plan_revision=plan_revision,
            actor=actor,
            severity=severity,
            payload=dict(payload or {}),
            principal_id=principal_id,
            project_id=project_id,
        )
        return await self.repository.append(
            event, principal_id=principal_id, project_id=project_id
        )

    async def start_task(
        self, *, task_id: str, workspace_id: str, principal_id: str,
        project_id: str, goal: str,
    ) -> SupervisionEvent:
        await self.control.repository.ensure_control(
            task_id, principal_id=principal_id, project_id=project_id,
            workspace_id=workspace_id,
        )
        return await self.emit(
            task_id=task_id, workspace_id=workspace_id,
            principal_id=principal_id, project_id=project_id,
            event_type=SupervisionEventType.TASK_STARTED,
            payload={"goal": goal, "status": "PLANNING"},
        )

    async def state(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> TaskSupervisionState | None:
        return await self.repository.get_state(
            task_id, principal_id=principal_id, project_id=project_id
        )

    async def events(
        self, task_id: str, *, principal_id: str, project_id: str,
        after_sequence: int = 0, limit: int = 1024,
    ) -> tuple[SupervisionEvent, ...]:
        return await self.repository.list_events(
            task_id, principal_id=principal_id, project_id=project_id,
            after_sequence=after_sequence, limit=limit,
        )

    async def register_runtime(self, **kwargs: Any) -> RuntimeControlHandle:
        return await self.control.register_runtime(**kwargs)

    async def unregister_runtime(self, task_id: str, **kwargs: Any) -> None:
        await self.control.unregister_runtime(task_id, **kwargs)

    async def wait_if_paused(self, task_id: str, **kwargs: Any) -> bool:
        return await self.control.wait_if_paused(task_id, **kwargs)

    async def pause(self, **kwargs: Any) -> ControlCommandResult:
        return await self.control.request_pause(**kwargs)

    async def resume(self, **kwargs: Any) -> ControlCommandResult:
        return await self.control.request_resume(**kwargs)

    async def cancel(self, **kwargs: Any) -> ControlCommandResult:
        return await self.control.request_cancel(**kwargs)

    async def settle_pause(self, **kwargs: Any) -> Any:
        return await self.control.settle_pause(**kwargs)

    async def settle_cancel(self, **kwargs: Any) -> Any:
        return await self.control.settle_cancel(**kwargs)


__all__ = [
    "CurrentActivity",
    "PlanProjection",
    "TaskCancellationRequested",
    "TaskSupervisionService",
]
