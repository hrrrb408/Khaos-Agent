"""Authenticated coding-task RPC application service."""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict
from collections.abc import AsyncIterator
from typing import Any

from khaos.agent.approval import ApprovalBroker
from khaos.coding.checkpoints.service import CheckpointService
from khaos.coding.task_manager import TaskManager
from khaos.runtime import RequestContext
from khaos.supervision.contracts import SupervisionCommandStatus
from khaos.supervision.service import TaskSupervisionService

logger = logging.getLogger(__name__)


class TaskService:
    """Coding-task RPC service with per-principal TaskManager.

    C-1-5a: previously this service held a server-level
    ``TaskManager(local-uid)`` singleton, which (a) rejected ``create``
    from API principals (fail-closed with a "deferred to A-4-3/A-4-4"
    error) and (b) returned empty ``list``/``get``/``cancel`` results
    for API principals because the cache only held local-uid tasks.

    Now the service holds ``db`` + ``approval_broker`` and constructs
    a per-principal ``TaskManager`` on demand (cached for the
    process lifetime).  Each principal gets an isolated cache loaded
    from the DB, so ``create``/``list``/``get``/``cancel`` all work
    correctly for any authenticated principal.  Cross-principal
    isolation is enforced both by the manager's principal-scoped cache
    AND by the explicit ``task.principal_id != ctx.principal_id``
    checks (defense in depth).
    """

    def __init__(
        self,
        db,
        approval_broker: ApprovalBroker | None = None,
        *,
        supervision_service: TaskSupervisionService | None = None,
        checkpoint_service: CheckpointService | None = None,
    ):
        self.db = db
        self.approval_broker = approval_broker
        self.supervision_service = supervision_service or TaskSupervisionService(db)
        self.checkpoint_service = checkpoint_service
        # Round-4 review Batch 4 (§13.2): per-(principal, project)
        # TaskManager cache with LRU eviction.  Previously the cache was
        # keyed by ``principal_id`` only and lived for the process
        # lifetime — a process with many principals would grow without
        # bound.  Now the key is ``(principal_id, project_id)`` and the
        # cache is bounded by ``_MAX_MANAGERS`` (default 32).  When the
        # limit is reached, the least-recently-used entry is evicted.
        self._managers: OrderedDict[tuple[str, str], TaskManager] = OrderedDict()
        self._MAX_MANAGERS = 32
        # Batch 6.5 (round-6 §十七): service-level cache lock.  Without
        # it, two concurrent ``_manager()`` calls for the same key both
        # observe a cache miss, both build+load a TaskManager, and one
        # overwrites the cache — the loser (with any registered
        # subscribers) is silently dropped, producing two managers for
        # one ``(principal, project)``.  The lock serializes the whole
        # miss → build → load → insert → LRU-evict sequence.
        self._manager_cache_lock = asyncio.Lock()

    @staticmethod
    def _project_id(ctx: RequestContext) -> str:
        """Use the verified project, retaining a legacy test partition."""
        return ctx.project_id or "legacy"

    async def _owned_task(
        self, ctx: RequestContext, task_id: str
    ) -> tuple[TaskManager, Any | None]:
        """Resolve a task only inside the transport owner's manager."""
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return manager, None
        return manager, task

    async def _workspace_binding(
        self, ctx: RequestContext, task_id: str
    ) -> tuple[TaskManager, Any | None, str | None]:
        manager, task = await self._owned_task(ctx, task_id)
        if task is None:
            return manager, None, None
        workspace_id = task.metadata.get("workspace_id")
        if not isinstance(workspace_id, str) or not workspace_id:
            state = await self.supervision_service.state(
                task_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
            )
            workspace_id = state.workspace_id if state is not None else None
        return manager, task, workspace_id

    async def _runtime_checkpoint_service(
        self, ctx: RequestContext, task_id: str
    ) -> CheckpointService | None:
        if self.checkpoint_service is not None:
            return self.checkpoint_service
        handle = await self.supervision_service.control.runtime_handle(
            task_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
        )
        if handle is None:
            return None
        service = handle.checkpoint_service
        return service

    @staticmethod
    def _control_payload(result: Any) -> dict[str, object]:
        status = getattr(result.status, "value", result.status)
        control_state = getattr(result.control_state, "value", result.control_state)
        return {
            "ok": status in {
                SupervisionCommandStatus.APPLIED.value,
                SupervisionCommandStatus.NOOP.value,
            },
            "task_id": result.task_id,
            "command_id": result.command_id,
            "status": status,
            "control_state": control_state,
            "revision": result.revision,
            "reason": result.reason,
        }

    async def _manager(self, ctx: RequestContext) -> TaskManager:
        """Get or create the per-(principal, project) TaskManager.

        Batch 6.5 (round-6 §十七): the entire lookup + build + LRU-evict
        sequence is serialized under ``_manager_cache_lock`` so two
        concurrent callers for the same key cannot race-build two
        managers (split-brain).  Eviction uses the atomic
        ``begin_eviction()`` CAS instead of the unlocked
        ``can_evict()`` + ``aclose()`` two-step, closing the window in
        which a task could go active between the check and the drain.
        """
        key = (ctx.principal_id, ctx.project_id)
        async with self._manager_cache_lock:
            manager = self._managers.get(key)
            if manager is None:
                # LRU eviction: drop the oldest EVICTABLE entry if at
                # capacity.  Round-5 Batch 5.4: a manager with active
                # tasks or live subscribers is NOT evicted.  Batch 6.5:
                # ``can_evict()`` is a cheap unlocked pre-filter, but
                # the authoritative decision is the ``begin_eviction()``
                # CAS (which re-checks under the manager lock and flips
                # ``_closing`` so no new work can arrive in the gap).
                if len(self._managers) >= self._MAX_MANAGERS:
                    evicted = False
                    # Iterate oldest-first (OrderedDict insertion order).
                    for evict_key in list(self._managers.keys()):
                        candidate = self._managers[evict_key]
                        if not candidate.can_evict():
                            continue
                        if not await candidate.begin_eviction():
                            # Lost the CAS (went active / gained a
                            # subscriber / already evicting) — try next.
                            continue
                        await candidate.aclose()
                        self._managers.pop(evict_key, None)
                        logger.debug(
                            "TaskService LRU: evicted manager for %s",
                            evict_key,
                        )
                        evicted = True
                        break
                    if not evicted:
                        logger.warning(
                            "TaskService LRU: cache at capacity (%d) but "
                            "no evictable manager (all have live owners); "
                            "temporarily exceeding limit",
                            len(self._managers),
                        )
                manager = TaskManager(
                    db=self.db, principal_id=ctx.principal_id,
                    project_id=ctx.project_id,
                )
                # This is construction of a live secondary manager, not
                # process-restart recovery.  ``load()`` would persist
                # ACTIVE -> BLOCKED and could interrupt another runtime's
                # task.  Hydration only decodes the physical owner-scoped
                # projection and preserves its lifecycle status exactly.
                await manager.hydrate_projection()
                self._managers[key] = manager
            else:
                # Move to end (most-recently-used).
                self._managers.move_to_end(key)
            return manager

    async def list(self, ctx: RequestContext, active_only: bool = False) -> list[dict]:
        """List tasks — active ones by default, all when ``active_only`` is set.

        C-1-5a: the per-principal TaskManager's cache only contains
        tasks owned by ``ctx.principal_id``, so the caller sees exactly
        their own tasks.  The explicit ``principal_id`` filter is
        defense in depth.
        """
        manager = await self._manager(ctx)
        if active_only:
            return await manager.list_active(
                principal_id=ctx.principal_id,
            )
        return await manager.list_all(
            principal_id=ctx.principal_id,
        )

    async def get(self, ctx: RequestContext, task_id: str) -> dict:
        """Return one task's state, or ``{"error": "not found"}``.

        C-1-5a: a task owned by a different principal is treated as
        ``not found`` — existence is hidden to avoid leaking that
        another principal has work in flight.  (Defense in depth: the
        per-principal cache already excludes foreign tasks.)
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"error": "task not found", "task_id": task_id}
        return task.to_dict()

    async def create(self, ctx: RequestContext, goal: str) -> dict:
        """Create a task owned by ``ctx.principal_id``.

        C-1-5a: the per-principal TaskManager stamps
        ``ctx.principal_id`` on the new task and stores it in the
        caller's cache.  Previously this rejected API principals with
        a "per-principal TaskManager required" error (deferred to
        A-4-3/A-4-4) — C-1-5a fulfills that deferral.
        """
        manager = await self._manager(ctx)
        return (await manager.create(goal)).to_dict()

    async def cancel(self, ctx: RequestContext, task_id: str) -> dict:
        from khaos.coding.task_manager import TransitionResult

        # C-1-5a: hide cross-principal tasks (treat as not found) so
        # an API principal cannot enumerate or cancel another
        # principal's tasks.  (Defense in depth.)
        manager, task, workspace_id = await self._workspace_binding(ctx, task_id)
        if task is None:
            return {"ok": False, "error": "task not found", "task_id": task_id}

        # An active AgentLoop owns the in-flight effect domain.  Its
        # cooperative control path settles the task after critical effects
        # drain; calling TaskManager.cancel here would race that owner.
        active_runtime = await self.supervision_service.control.runtime_handle(
            task_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
        )
        if active_runtime is not None and workspace_id:
            result = await self.supervision_service.cancel(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
            )
            return self._control_payload(result)

        result = await manager.cancel(task_id)
        if result == TransitionResult.NOT_FOUND:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if result == TransitionResult.INVALID_TRANSITION:
            return {"ok": False, "error": "task already terminal", "task_id": task_id}
        # C-2-5 (HIGH 2): ``LEASE_INVALIDATION_FAILED`` means the
        # task's workspace lease could not be released — the
        # TaskManager kept the task in its pre-cancel state so the
        # caller can retry (Batch 2.6 §4 fail-closed).  Previously
        # this fell through to ``{"ok": True}``, silently treating a
        # fail-closed refusal as success: the REST caller saw HTTP 200
        # while the task was still active.  The explicit ``status``
        # field lets the Go client distinguish this from
        # ``INVALID_TRANSITION`` (which maps to 409, not 503).
        if result == TransitionResult.LEASE_INVALIDATION_FAILED:
            return {
                "ok": False,
                "error": "lease invalidation failed",
                "task_id": task_id,
                "status": "lease_invalidation_failed",
            }
        if workspace_id:
            control_result = await self.supervision_service.cancel(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
            )
            response = self._control_payload(control_result)
            response["ok"] = True
            return response
        return {"ok": True, "task_id": task_id}

    async def approve(
        self,
        ctx: RequestContext,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        # Round-14 §2: bind the resolving principal to the transport
        # authority unconditionally.  ``principal_id`` is a payload field
        # and is only trusted when it agrees with ``ctx.principal_id``;
        # an empty payload principal previously skipped the guard and
        # fell through to downstream principal comparisons on the empty
        # string.  Reject an empty transport principal outright so the
        # approval cannot be attributed to nobody.  Also hide
        # cross-principal tasks (treat as not found).
        if not ctx.principal_id:
            return {"ok": False, "error": "transport principal is required", "task_id": task_id}
        if principal_id and principal_id != ctx.principal_id:
            return {
                "ok": False,
                "error": "payload principal_id does not match transport principal",
                "task_id": task_id,
            }
        principal_id = ctx.principal_id
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }

        async def commit() -> bool:
            result = await manager.transition(
                task_id, expected={TaskStatus.BLOCKED},
                target=TaskStatus.RUNNING, pending_approval=None,
                approval_consumption={
                    "tool_call_id": pending.get("tool_call_id", ""),
                    "binding_digest": binding_digest,
                    "principal_id": principal_id,
                    "session_id": session_id,
                    "decision": "approved",
                    "consumed_at": time.time(),
                },
            )
            return result == TransitionResult.UPDATED

        resolved = await self.approval_broker.consume_task_decision_and_commit(
            pending.get("tool_call_id", ""),
            True,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
            commit=commit,
        )
        workspace_id = pending.get("workspace_id") or task.metadata.get("workspace_id")
        if resolved and isinstance(workspace_id, str) and workspace_id:
            await self.supervision_service.emit(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
                event_type="approval.resolved",
                payload={
                    "approval_id": pending.get("tool_call_id", ""),
                    "approval_state": "approved",
                    "resolution": "approved",
                },
                actor="user",
            )
        return {"ok": resolved, "task_id": task_id}

    async def reject(
        self,
        ctx: RequestContext,
        task_id: str,
        principal_id: str = "",
        session_id: str = "",
        binding_digest: str = "",
    ) -> dict:
        from khaos.coding.task_manager import TaskStatus, TransitionResult

        # Round-14 §2: see ``approve`` — bind the resolving principal to
        # the transport authority unconditionally.
        if not ctx.principal_id:
            return {"ok": False, "error": "transport principal is required", "task_id": task_id}
        if principal_id and principal_id != ctx.principal_id:
            return {
                "ok": False,
                "error": "payload principal_id does not match transport principal",
                "task_id": task_id,
            }
        principal_id = ctx.principal_id
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if task.status != TaskStatus.BLOCKED:
            return {"ok": False, "error": f"task is {task.status.value}, not blocked", "task_id": task_id}
        pending = task.metadata.get("pending_approval") or {}
        if (
            not self.approval_broker
            or principal_id != pending.get("principal_id")
            or session_id != pending.get("session_id")
            or binding_digest != pending.get("binding_digest")
        ):
            return {
                "ok": False,
                "error": "approval principal/session/binding mismatch",
                "task_id": task_id,
            }
        async def commit() -> bool:
            result = await manager.transition(
                task_id, expected={TaskStatus.BLOCKED}, target=TaskStatus.FAILED,
                error="rejected by user", pending_approval=None,
                approval_consumption={
                    "tool_call_id": pending.get("tool_call_id", ""),
                    "binding_digest": binding_digest,
                    "principal_id": principal_id,
                    "session_id": session_id,
                    "decision": "rejected",
                    "consumed_at": time.time(),
                },
            )
            return result == TransitionResult.UPDATED

        resolved = await self.approval_broker.consume_task_decision_and_commit(
            pending.get("tool_call_id", ""),
            False,
            principal_id=principal_id,
            session_id=session_id,
            binding_digest=binding_digest,
            commit=commit,
        )
        workspace_id = pending.get("workspace_id") or task.metadata.get("workspace_id")
        if resolved and isinstance(workspace_id, str) and workspace_id:
            await self.supervision_service.emit(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
                event_type="approval.resolved",
                payload={
                    "approval_id": pending.get("tool_call_id", ""),
                    "approval_state": "rejected",
                    "status": "FAILED",
                    "resolution": "rejected",
                },
                actor="user",
                severity="warning",
            )
        return {"ok": resolved, "task_id": task_id}

    async def artifacts(self, ctx: RequestContext, task_id: str) -> list[dict]:
        """Return a task's produced artifacts (files + test results).

        M4 batch 3.1.16A-4-2: cross-principal tasks return an empty
        list (existence hidden) — symmetric with ``get`` / ``cancel``.
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return []
        return ([{"type": "file", "path": path} for path in task.files_modified] + [{"type": "test_result", "data": result} for result in task.test_results])

    async def events(self, ctx: RequestContext, task_id: str):
        """Subscribe to a task's event stream.

        M4 batch 3.1.16A-4-2: previously the dispatcher reached into
        ``task_manager.subscribe`` directly, bypassing the service
        layer — so the principal check on ``ctx`` was never enforced.
        This wrapper hides cross-principal tasks (yields nothing) so
        an API principal cannot subscribe to another principal's
        task events.
        """
        manager = await self._manager(ctx)
        task = await manager.get(task_id)
        if task is None or task.principal_id != ctx.principal_id:
            return
        async for event in manager.subscribe(task_id):
            yield event

    async def supervision(self, ctx: RequestContext, task_id: str) -> dict[str, object]:
        """Return the durable typed supervision projection for one task."""
        _manager, task = await self._owned_task(ctx, task_id)
        if task is None:
            return {"error": "task not found", "task_id": task_id}
        project_id = self._project_id(ctx)
        state = await self.supervision_service.state(
            task_id, principal_id=ctx.principal_id, project_id=project_id
        )
        control = await self.supervision_service.control.repository.get_control(
            task_id, principal_id=ctx.principal_id, project_id=project_id
        )
        if state is None:
            return {
                "task_id": task_id,
                "status": "UNINITIALIZED",
                "control": (
                    {
                        "state": control.state.value,
                        "revision": control.revision,
                        "last_command_id": control.last_command_id,
                        "updated_at": control.updated_at,
                    }
                    if control is not None
                    else None
                ),
            }
        payload = state.to_payload()
        if control is not None:
            payload["control"] = {
                "state": control.state.value,
                "revision": control.revision,
                "last_command_id": control.last_command_id,
                "updated_at": control.updated_at,
            }
        return payload

    async def supervision_events(
        self, ctx: RequestContext, task_id: str, after_sequence: int = 0,
        limit: int = 1024,
    ) -> AsyncIterator[dict[str, object]]:
        """Replay canonical supervision events, owner-scoped and bounded."""
        _manager, task = await self._owned_task(ctx, task_id)
        if task is None:
            return
        events = await self.supervision_service.events(
            task_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            after_sequence=after_sequence,
            limit=limit,
        )
        for event in events:
            yield event.to_payload()

    async def pause(
        self, ctx: RequestContext, task_id: str, command_id: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        """Request a cooperative pause at the next safe point."""
        _manager, task, workspace_id = await self._workspace_binding(ctx, task_id)
        if task is None:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if not workspace_id:
            return {
                "ok": False,
                "task_id": task_id,
                "status": "BLOCKED",
                "error": "task has no bound workspace",
            }
        result = await self.supervision_service.pause(
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            command_id=command_id,
            expected_revision=expected_revision,
        )
        return self._control_payload(result)

    async def resume(
        self, ctx: RequestContext, task_id: str, command_id: str | None = None,
        expected_revision: int | None = None,
    ) -> dict[str, object]:
        """Resume only from a durable PAUSED safe point."""
        _manager, task, workspace_id = await self._workspace_binding(ctx, task_id)
        if task is None:
            return {"ok": False, "error": "task not found", "task_id": task_id}
        if not workspace_id:
            return {
                "ok": False,
                "task_id": task_id,
                "status": "BLOCKED",
                "error": "task has no bound workspace",
            }
        result = await self.supervision_service.resume(
            task_id=task_id,
            workspace_id=workspace_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            command_id=command_id,
            expected_revision=expected_revision,
        )
        return self._control_payload(result)

    async def checkpoint_list(
        self, ctx: RequestContext, task_id: str,
        workspace_id: str | None = None,
    ) -> list[dict[str, object]]:
        """List immutable checkpoint metadata for the caller's task."""
        _manager, task, bound_workspace = await self._workspace_binding(ctx, task_id)
        if task is None:
            return []
        if workspace_id is not None and workspace_id != bound_workspace:
            return []
        service = await self._runtime_checkpoint_service(ctx, task_id)
        project_id = self._project_id(ctx)
        if service is not None:
            checkpoints = await service.list_checkpoints(
                task_id,
                workspace_id=workspace_id or bound_workspace,
                principal_id=ctx.principal_id,
                project_id=project_id,
            )
        else:
            checkpoints = await self.db.checkpoint_repository.list(
                task_id,
                principal_id=ctx.principal_id,
                project_id=project_id,
                workspace_id=workspace_id or bound_workspace,
            )
        return [checkpoint.to_payload(include_snapshot=False) for checkpoint in checkpoints]

    async def checkpoint(
        self, ctx: RequestContext, checkpoint_id: str, task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> dict[str, object]:
        """Inspect one immutable checkpoint under the request owner."""
        if task_id is not None:
            _manager, task, bound_workspace = await self._workspace_binding(ctx, task_id)
            if task is None or (workspace_id is not None and workspace_id != bound_workspace):
                return {"error": "checkpoint not found", "checkpoint_id": checkpoint_id}
        checkpoint = await self.db.checkpoint_repository.get(
            checkpoint_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            task_id=task_id,
            workspace_id=workspace_id,
        )
        if checkpoint is None:
            return {"error": "checkpoint not found", "checkpoint_id": checkpoint_id}
        return checkpoint.to_payload()

    async def create_checkpoint(
        self, ctx: RequestContext, task_id: str, label: str = "",
        kind: str = "USER_CREATED", expected_generation: int | None = None,
        plan_revision: int | None = None,
        verification_evidence_digest: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, object]:
        """Create a bounded checkpoint through the active runtime owner."""
        _manager, task, workspace_id = await self._workspace_binding(ctx, task_id)
        if task is None:
            return {"error": "task not found", "task_id": task_id}
        service = await self._runtime_checkpoint_service(ctx, task_id)
        if service is None or not workspace_id:
            return {
                "ok": False,
                "task_id": task_id,
                "status": "BLOCKED",
                "error": "checkpoint capture requires an active workspace owner",
            }
        checkpoint = await service.create_checkpoint(
            task_id=task_id,
            workspace_id=workspace_id,
            kind=kind,
            label=label,
            expected_generation=expected_generation,
            plan_revision=plan_revision,
            verification_evidence_digest=verification_evidence_digest,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            idempotency_key=idempotency_key,
        )
        return {"ok": True, **checkpoint.to_payload(include_snapshot=False)}

    async def rewind_plan(
        self, ctx: RequestContext, checkpoint_id: str, task_id: str | None = None,
        workspace_id: str | None = None, idempotency_key: str | None = None,
    ) -> dict[str, object]:
        """Build a generation-bound M8.2 rewind plan."""
        # Resolve the checkpoint before selecting a service when the caller
        # omits task_id.  The checkpoint is owner-scoped, so this both avoids
        # guessing a task and lets a live runtime supply the canonical
        # workspace owner for the plan.
        checkpoint = await self.db.checkpoint_repository.get(
            checkpoint_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
            task_id=task_id,
            workspace_id=workspace_id,
        )
        if checkpoint is None:
            return {"error": "checkpoint not found", "checkpoint_id": checkpoint_id}
        resolved_task_id = task_id or checkpoint.task_id
        resolved_workspace_id = workspace_id or checkpoint.workspace_id
        service = await self._runtime_checkpoint_service(ctx, resolved_task_id)
        if service is None:
            service = self.checkpoint_service
        if service is None:
            return {
                "ok": False,
                "status": "BLOCKED",
                "error": "rewind requires the active workspace owner",
                "checkpoint_id": checkpoint_id,
            }
        try:
            plan = await service.build_rewind_plan(
                checkpoint_id,
                principal_id=ctx.principal_id,
                project_id=self._project_id(ctx),
                task_id=resolved_task_id,
                workspace_id=resolved_workspace_id,
                idempotency_key=idempotency_key,
            )
        except LookupError:
            return {"error": "checkpoint not found", "checkpoint_id": checkpoint_id}
        return {"ok": not bool(plan.conflicts), **plan.to_payload(include_transaction_content=False)}

    async def rewind(
        self, ctx: RequestContext, rewind_id: str, task_id: str,
        plan_digest: str | None = None,
    ) -> dict[str, object]:
        """Execute only a stored, digest-matching rewind plan."""
        service = await self._runtime_checkpoint_service(ctx, task_id)
        if service is None:
            return {
                "ok": False,
                "task_id": task_id,
                "status": "BLOCKED",
                "error": "rewind requires the active workspace owner",
            }
        plan = await self.db.checkpoint_repository.get_rewind_plan(
            rewind_id,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
        )
        if plan is None:
            return {"ok": False, "task_id": task_id, "status": "REJECTED_STALE", "error": "rewind plan not found"}
        if plan.task_id != task_id or (plan_digest and plan.plan_digest != plan_digest):
            return {"ok": False, "task_id": task_id, "status": "REJECTED_STALE", "error": "rewind plan binding is stale"}
        result = await service.execute_rewind(
            plan,
            principal_id=ctx.principal_id,
            project_id=self._project_id(ctx),
        )
        return {"ok": result.effect_applied, **result.to_payload()}

__all__ = ["TaskService"]
