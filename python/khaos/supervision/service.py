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

_EXTENSION_EVENT_TYPES = frozenset(
    {
        SupervisionEventType.EXTENSION_DISCOVERED,
        SupervisionEventType.EXTENSION_VALIDATED,
        SupervisionEventType.EXTENSION_STARTED,
        SupervisionEventType.EXTENSION_STOPPED,
        SupervisionEventType.EXTENSION_QUARANTINED,
        SupervisionEventType.CAPABILITY_ADMITTED,
        SupervisionEventType.CAPABILITY_DENIED,
        SupervisionEventType.MCP_CONNECTED,
        SupervisionEventType.MCP_DISCONNECTED,
        SupervisionEventType.MCP_DEGRADED,
        SupervisionEventType.HOOK_INVOKED,
        SupervisionEventType.HOOK_COMPLETED,
        SupervisionEventType.HOOK_FAILED,
        SupervisionEventType.SKILL_ACTIVATED,
        SupervisionEventType.SKILL_DEACTIVATED,
    }
)


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

    async def emit_extension_event(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        event_type: SupervisionEventType | str,
        extension_id: str,
        status: str = "",
        capability_id: str = "",
        reason_code: str = "",
        digest: str = "",
        payload: Mapping[str, object] | None = None,
    ) -> SupervisionEvent:
        """Emit a bounded extension projection through canonical supervision.

        Extension events are a separate projection namespace.  The helper
        rejects canonical task events and never forwards generic ``status``
        or authority-shaped payload keys to the state reducer, so an
        extension cannot mark a task completed, verified, approved, or
        otherwise alter the canonical control state.
        """
        try:
            normalized_event_type = SupervisionEventType(str(event_type))
        except ValueError as exc:
            raise ValueError("extension supervision event type is invalid") from exc
        if normalized_event_type not in _EXTENSION_EVENT_TYPES:
            raise ValueError("extension supervision cannot emit canonical task events")
        if type(extension_id) is not str or not extension_id or "\x00" in extension_id:
            raise ValueError("extension_id is required")
        values: dict[str, object] = {
            "extension_id": extension_id,
        }
        for key, value in (
            ("extension_status", status),
            ("extension_capability_id", capability_id),
            ("extension_reason_code", reason_code),
            ("extension_digest", digest),
        ):
            if value:
                values[key] = value
        if payload:
            for key, value in payload.items():
                if (
                    type(key) is not str
                    or not key.startswith("extension_")
                    or key in {"extension_id", "extension_status", "extension_capability_id", "extension_reason_code", "extension_digest"}
                ):
                    raise ValueError("extension payload keys must use a non-authoritative extension namespace")
                values[key] = value
        return await self.emit(
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=principal_id,
            project_id=project_id,
            event_type=normalized_event_type,
            payload=values,
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
