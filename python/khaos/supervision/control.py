"""Cooperative, durable pause/resume/cancel control for Coding tasks."""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from khaos.supervision.contracts import (
    ControlCommandResult,
    ControlState,
    SupervisionActor,
    SupervisionCommandStatus,
    SupervisionEvent,
    SupervisionEventType,
)
from khaos.supervision.repository import (
    ControlSnapshot,
    TaskSupervisionRepository,
)

logger = logging.getLogger(__name__)


class TaskCancellationRequested(asyncio.CancelledError):
    """Raised at an AgentLoop safe point after a durable cancel request."""


@dataclass(slots=True)
class RuntimeControlHandle:
    """In-memory wake-up handle registered by one active runtime."""

    task_id: str
    workspace_id: str
    principal_id: str
    project_id: str
    runtime_id: str
    runtime_task: asyncio.Task[Any] | None = None
    checkpoint_service: Any = None
    resume_event: asyncio.Event = field(default_factory=asyncio.Event)
    context_needs_rebuild: bool = False
    active: bool = True

    def __post_init__(self) -> None:
        self.resume_event.set()


def _result_from_payload(value: dict[str, object]) -> ControlCommandResult:
    return ControlCommandResult(
        command_id=str(value.get("command_id", "")),
        task_id=str(value.get("task_id", "")),
        status=str(value.get("status", SupervisionCommandStatus.FAILED.value)),
        control_state=str(value.get("control_state", ControlState.RUNNING.value)),
        revision=int(value.get("revision", 0)),
        reason=str(value.get("reason", "")),
    )


class TaskControlService:
    """Own task-scoped control state and runtime wake-up handles.

    The database projection is the authority.  The per-task locks only
    serialize commands for one task and never replace WorkspaceManager,
    ApprovalBroker, child, merge, or CompletionGate ownership.
    """

    def __init__(
        self,
        database: Any | None = None,
        *,
        repository: TaskSupervisionRepository | None = None,
        audit_logger: Any | None = None,
    ) -> None:
        if repository is None and database is None:
            raise ValueError("database or repository is required")
        self.repository = repository or TaskSupervisionRepository(database)
        self.audit_logger = audit_logger
        self._handles: dict[tuple[str, str, str], RuntimeControlHandle] = {}
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self._registry_lock = asyncio.Lock()

    def _key(self, task_id: str, principal_id: str, project_id: str) -> tuple[str, str, str]:
        return task_id, principal_id, project_id

    async def _task_lock(
        self, task_id: str, principal_id: str, project_id: str
    ) -> asyncio.Lock:
        key = self._key(task_id, principal_id, project_id)
        async with self._registry_lock:
            return self._locks.setdefault(key, asyncio.Lock())

    async def _audit(
        self,
        action: str,
        task_id: str,
        principal_id: str,
        project_id: str,
        result: str,
        detail: dict[str, object],
    ) -> None:
        logger.info("task supervision %s task=%s result=%s", action, task_id, result)
        if self.audit_logger is None:
            return
        log = getattr(self.audit_logger, "log", None)
        if not callable(log):
            return
        try:
            await log(
                action,
                f"task:{task_id}",
                result,
                detail,
                task_id=task_id,
                source_transport="supervision",
            )
        except Exception:
            # A secondary audit adapter must not turn a durable control
            # transition into an unreported, half-applied command.
            logger.exception("supervision audit adapter failed for task=%s", task_id)

    async def _event(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        event_type: SupervisionEventType,
        payload: dict[str, object],
        actor: SupervisionActor = SupervisionActor.SYSTEM,
    ) -> SupervisionEvent:
        state = await self.repository.get_state(
            task_id, principal_id=principal_id, project_id=project_id
        )
        event = SupervisionEvent(
            task_id=task_id,
            workspace_id=workspace_id,
            event_type=event_type,
            repository_generation=(state.repository_generation if state else None),
            actor=actor,
            payload=payload,
            principal_id=principal_id,
            project_id=project_id,
        )
        return await self.repository.append(
            event, principal_id=principal_id, project_id=project_id
        )

    async def register_runtime(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        runtime_id: str,
        runtime_task: asyncio.Task[Any] | None = None,
        checkpoint_service: Any = None,
    ) -> RuntimeControlHandle:
        """Register an active runtime and recover durable pause truth."""
        control = await self.repository.ensure_control(
            task_id,
            principal_id=principal_id,
            project_id=project_id,
            workspace_id=workspace_id,
        )
        handle = RuntimeControlHandle(
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=principal_id,
            project_id=project_id,
            runtime_id=runtime_id,
            runtime_task=runtime_task,
            checkpoint_service=checkpoint_service,
        )
        if control.state in {ControlState.PAUSED, ControlState.PAUSING}:
            handle.resume_event.clear()
        elif control.state in {ControlState.CANCELLING, ControlState.CANCELLED}:
            handle.resume_event.set()
        key = self._key(task_id, principal_id, project_id)
        async with self._registry_lock:
            previous = self._handles.get(key)
            if previous is not None and previous.active:
                raise RuntimeError("task already has an active supervision runtime")
            self._handles[key] = handle
        return handle

    async def unregister_runtime(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> None:
        key = self._key(task_id, principal_id, project_id)
        async with self._registry_lock:
            handle = self._handles.pop(key, None)
            if handle is not None:
                handle.active = False
                handle.resume_event.set()

    async def runtime_handle(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> RuntimeControlHandle | None:
        key = self._key(task_id, principal_id, project_id)
        async with self._registry_lock:
            handle = self._handles.get(key)
            return handle if handle is not None and handle.active else None

    async def _load_control(
        self,
        task_id: str,
        *,
        workspace_id: str,
        principal_id: str,
        project_id: str,
    ) -> ControlSnapshot:
        current = await self.repository.get_control(
            task_id, principal_id=principal_id, project_id=project_id
        )
        if current is None:
            return await self.repository.ensure_control(
                task_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_id=workspace_id,
            )
        if current.workspace_id != workspace_id:
            raise PermissionError("control workspace does not match task workspace")
        return current

    async def _command(
        self,
        *,
        action: str,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        desired: ControlState,
        command_id: str,
        expected_revision: int | None,
        active_target: bool,
        reason: str = "",
    ) -> ControlCommandResult:
        lock = await self._task_lock(task_id, principal_id, project_id)
        async with lock:
            current = await self._load_control(
                task_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                project_id=project_id,
            )
            if current.last_command_id == command_id and current.last_result:
                return _result_from_payload(current.last_result)
            if expected_revision is not None and current.revision != expected_revision:
                result = ControlCommandResult(
                    command_id=command_id,
                    task_id=task_id,
                    status=SupervisionCommandStatus.REJECTED_STALE,
                    control_state=current.state,
                    revision=current.revision,
                    reason="control revision is stale",
                )
                await self._audit(
                    action, task_id, principal_id, project_id, "rejected_stale",
                    {"revision": current.revision, "expected_revision": expected_revision},
                )
                return result

            result_status = SupervisionCommandStatus.APPLIED
            target = desired
            if action == "pause":
                if current.state is ControlState.PAUSED:
                    result_status = SupervisionCommandStatus.NOOP
                    target = current.state
                elif current.state in {ControlState.CANCELLING, ControlState.CANCELLED}:
                    result_status = SupervisionCommandStatus.BLOCKED
                    target = current.state
                elif current.state is ControlState.PAUSING:
                    result_status = SupervisionCommandStatus.NOOP
                    target = current.state
                elif active_target:
                    target = ControlState.PAUSING
            elif action == "resume":
                if current.state is ControlState.RUNNING:
                    result_status = SupervisionCommandStatus.NOOP
                    target = current.state
                elif current.state is not ControlState.PAUSED:
                    result_status = SupervisionCommandStatus.BLOCKED
                    target = current.state
            elif action == "cancel":
                if current.state in {ControlState.CANCELLED, ControlState.CANCELLING}:
                    result_status = SupervisionCommandStatus.NOOP
                    target = current.state
                elif active_target:
                    target = ControlState.CANCELLING
                else:
                    target = ControlState.CANCELLED

            result = ControlCommandResult(
                command_id=command_id,
                task_id=task_id,
                status=result_status,
                control_state=target,
                revision=current.revision + (1 if result_status is not SupervisionCommandStatus.NOOP else 0),
                reason=reason,
            )
            if result_status is SupervisionCommandStatus.BLOCKED:
                await self._audit(
                    action, task_id, principal_id, project_id, "blocked",
                    {"control_state": current.state.value, "reason": reason},
                )
                return result
            if result_status is SupervisionCommandStatus.NOOP:
                await self._audit(
                    action, task_id, principal_id, project_id, "noop",
                    {"control_state": current.state.value},
                )
                return result
            updated = await self.repository.compare_and_set_control(
                current,
                expected_revision=current.revision,
                desired_state=target,
                command_id=command_id,
                result=result.to_payload(),
            )
            if updated is None:
                return ControlCommandResult(
                    command_id=command_id,
                    task_id=task_id,
                    status=SupervisionCommandStatus.REJECTED_STALE,
                    control_state=current.state,
                    revision=current.revision,
                    reason="control state changed concurrently",
                )
            handle = await self.runtime_handle(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if action == "resume" and handle is not None:
                handle.context_needs_rebuild = True
                handle.resume_event.set()
            if action == "cancel" and handle is not None:
                handle.resume_event.set()
                runtime_task = handle.runtime_task
                if runtime_task is not None and not runtime_task.done():
                    runtime_task.cancel("task cancellation requested")
            if action == "pause" and handle is not None:
                handle.resume_event.clear()
            if target is ControlState.CANCELLED:
                await self._event(
                    task_id=task_id,
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    event_type=SupervisionEventType.TASK_CANCELLED,
                    payload={"control_state": target.value},
                    actor=SupervisionActor.USER,
                )
            elif target is ControlState.PAUSED:
                await self._event(
                    task_id=task_id,
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    event_type=SupervisionEventType.TASK_PAUSED,
                    payload={"control_state": target.value},
                    actor=SupervisionActor.USER,
                )
            elif action == "resume":
                await self._event(
                    task_id=task_id,
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    event_type=SupervisionEventType.TASK_RESUMED,
                    payload={"control_state": target.value, "context_rebuild_required": True},
                    actor=SupervisionActor.USER,
                )
            else:
                await self._event(
                    task_id=task_id,
                    workspace_id=workspace_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    event_type=SupervisionEventType.CONTROL_REQUESTED,
                    payload={"command": action, "control_state": target.value},
                    actor=SupervisionActor.USER,
                )
            await self._audit(
                action, task_id, principal_id, project_id, "applied",
                {"control_state": target.value, "revision": updated.revision},
            )
            return ControlCommandResult(
                command_id=command_id,
                task_id=task_id,
                status=result_status,
                control_state=updated.state,
                revision=updated.revision,
                reason=reason,
            )

    async def request_pause(
        self, *, task_id: str, workspace_id: str, principal_id: str,
        project_id: str, command_id: str | None = None,
        expected_revision: int | None = None,
    ) -> ControlCommandResult:
        handle = await self.runtime_handle(task_id, principal_id=principal_id, project_id=project_id)
        return await self._command(
            action="pause", task_id=task_id, workspace_id=workspace_id,
            principal_id=principal_id, project_id=project_id,
            desired=ControlState.PAUSING if handle else ControlState.PAUSED,
            command_id=command_id or uuid.uuid4().hex,
            expected_revision=expected_revision, active_target=handle is not None,
        )

    async def request_resume(
        self, *, task_id: str, workspace_id: str, principal_id: str,
        project_id: str, command_id: str | None = None,
        expected_revision: int | None = None,
    ) -> ControlCommandResult:
        return await self._command(
            action="resume", task_id=task_id, workspace_id=workspace_id,
            principal_id=principal_id, project_id=project_id,
            desired=ControlState.RUNNING, command_id=command_id or uuid.uuid4().hex,
            expected_revision=expected_revision,
            active_target=True,
        )

    async def request_cancel(
        self, *, task_id: str, workspace_id: str, principal_id: str,
        project_id: str, command_id: str | None = None,
        expected_revision: int | None = None,
    ) -> ControlCommandResult:
        handle = await self.runtime_handle(task_id, principal_id=principal_id, project_id=project_id)
        return await self._command(
            action="cancel", task_id=task_id, workspace_id=workspace_id,
            principal_id=principal_id, project_id=project_id,
            desired=ControlState.CANCELLING if handle else ControlState.CANCELLED,
            command_id=command_id or uuid.uuid4().hex,
            expected_revision=expected_revision, active_target=handle is not None,
        )

    async def settle_pause(
        self, *, task_id: str, workspace_id: str, principal_id: str, project_id: str
    ) -> ControlSnapshot | None:
        lock = await self._task_lock(task_id, principal_id, project_id)
        async with lock:
            current = await self.repository.get_control(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if current is None or current.state is not ControlState.PAUSING:
                return current
            updated = await self.repository.set_control_state(
                current, expected_revision=current.revision,
                desired_state=ControlState.PAUSED,
            )
            if updated is not None:
                await self._event(
                    task_id=task_id, workspace_id=workspace_id,
                    principal_id=principal_id, project_id=project_id,
                    event_type=SupervisionEventType.TASK_PAUSED,
                    payload={"control_state": ControlState.PAUSED.value},
                )
            return updated

    async def settle_cancel(
        self, *, task_id: str, workspace_id: str, principal_id: str, project_id: str
    ) -> ControlSnapshot | None:
        lock = await self._task_lock(task_id, principal_id, project_id)
        async with lock:
            current = await self.repository.get_control(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if current is None or current.state is ControlState.CANCELLED:
                return current
            if current.state is not ControlState.CANCELLING:
                return current
            updated = await self.repository.set_control_state(
                current, expected_revision=current.revision,
                desired_state=ControlState.CANCELLED,
            )
            if updated is not None:
                await self._event(
                    task_id=task_id, workspace_id=workspace_id,
                    principal_id=principal_id, project_id=project_id,
                    event_type=SupervisionEventType.TASK_CANCELLED,
                    payload={"control_state": ControlState.CANCELLED.value},
                )
            return updated

    async def wait_if_paused(
        self, task_id: str, *, principal_id: str, project_id: str
    ) -> bool:
        """Wait at a safe point and raise if cancellation was requested."""
        control = await self.repository.get_control(
            task_id, principal_id=principal_id, project_id=project_id
        )
        if control is None:
            return False
        if control.state in {ControlState.CANCELLING, ControlState.CANCELLED}:
            raise TaskCancellationRequested("task cancellation requested")
        if control.state is ControlState.PAUSING:
            handle = await self.runtime_handle(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if handle is not None:
                await self.settle_pause(
                    task_id=task_id, workspace_id=handle.workspace_id,
                    principal_id=principal_id, project_id=project_id,
                )
                control = await self.repository.get_control(
                    task_id, principal_id=principal_id, project_id=project_id
                )
        if control is None or control.state is not ControlState.PAUSED:
            return False
        handle = await self.runtime_handle(
            task_id, principal_id=principal_id, project_id=project_id
        )
        if handle is None:
            return False
        await handle.resume_event.wait()
        control = await self.repository.get_control(
            task_id, principal_id=principal_id, project_id=project_id
        )
        if control is not None and control.state in {ControlState.CANCELLING, ControlState.CANCELLED}:
            raise TaskCancellationRequested("task cancellation requested")
        return True


__all__ = [
    "RuntimeControlHandle",
    "TaskCancellationRequested",
    "TaskControlService",
]
