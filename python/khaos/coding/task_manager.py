"""Long-running coding-task tracking for observability.

Coding-mode turns can be long (read code → edit → test → fix → re-test). This
module tracks each task's lifecycle so the TUI/Web can surface progress
(``/tasks``, ``/task <id>``) and so the verify-fix loop has a place to record
its fix attempts.

The manager is async-safe (``asyncio.Lock``) so it can be shared between
``AgentLoop`` (which records activity) and the TUI/JSON-line server (which
reads state) without races.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)

#: How many recent test results are retained per task (older ones dropped).
TEST_RESULT_HISTORY = 5


class TaskStatus(Enum):
    """Lifecycle states for a coding task."""

    PENDING = "pending"
    RUNNING = "running"
    BLOCKED = "blocked"  # waiting on a permission approval
    WAITING_TEST = "waiting_test"  # waiting on a test result
    FIXING = "fixing"  # inside the verify-fix loop
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @classmethod
    def parse(cls, value: str) -> "TaskStatus":
        """Parse a status string, raising ``ValueError`` if unknown."""
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(f"unknown task status: {value!r}") from exc


#: Statuses considered "active" (still in flight) for ``list_active``.
ACTIVE_STATUSES = frozenset(
    {
        TaskStatus.PENDING,
        TaskStatus.RUNNING,
        TaskStatus.BLOCKED,
        TaskStatus.WAITING_TEST,
        TaskStatus.FIXING,
    }
)
TERMINAL_STATUSES = frozenset({TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED})


class TransitionResult(Enum):
    """Result of a task lifecycle transition."""

    UPDATED = "updated"
    UNCHANGED = "unchanged"
    NOT_FOUND = "not_found"
    INVALID_TRANSITION = "invalid_transition"
    LEASE_INVALIDATION_FAILED = "lease_invalidation_failed"  # Batch 2.6 §4


@dataclass
class CodingTask:
    """State record for one coding task.

    M4 batch 3.1.16A-3: every task is owned by exactly one principal.
    The ``principal_id`` is stamped at ``TaskManager.create`` time from
    the manager's bound principal and persisted in ``state_json`` so it
    round-trips through ``TaskManager.load``.  It is intentionally NOT
    exposed in the public ``to_dict()`` (TUI / RPC) output — only in
    ``to_dict(include_internal=True)`` — because the principal is an
    ownership invariant, not a display field.  An authenticated
    principal can only ever see tasks they own (filtered at the DB
    layer), so exposing it would be redundant and could mislead callers
    into thinking they can set it.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    goal: str = ""
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    files_modified: list[str] = field(default_factory=list)
    files_viewed: list[str] = field(default_factory=list)
    test_results: list[dict] = field(default_factory=list)
    fix_attempts: int = 0
    error: str | None = None
    metadata: dict = field(default_factory=dict)
    # Hermes batch 3: tool-call trace for skill generation.
    # Each entry: {tool_name, arguments, success}.
    trace: list[dict] = field(default_factory=list)
    event_sequence: int = 0
    # M4 batch 3.1.16A-3: principal-scoped ownership.  Default 'legacy'
    # is fail-closed — a task constructed without a principal is never
    # visible to an authenticated principal's TaskManager.
    principal_id: str = "legacy"

    def touch(self) -> None:
        """Stamp ``updated_at`` to now."""
        self.updated_at = datetime.now()

    def to_dict(self, include_internal: bool = False) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for the TUI / RPC layer.

        ``principal_id`` is included only when ``include_internal=True``
        (persistence path) so it round-trips through ``state_json``.
        The public TUI/RPC view never exposes it.
        """
        data = {
            "id": self.id,
            "goal": self.goal,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "files_modified": self.files_modified,
            "files_viewed": self.files_viewed,
            "test_results": self.test_results[-TEST_RESULT_HISTORY:],
            "fix_attempts": self.fix_attempts,
            "error": self.error,
        }
        if include_internal:
            data["metadata"] = self.metadata
            data["trace"] = self.trace
            data["event_sequence"] = self.event_sequence
            data["principal_id"] = self.principal_id
        return data


class TaskManager:
    """Track all active coding tasks.

    Thread-safe via an ``asyncio.Lock`` so ``AgentLoop`` (recording activity)
    and the TUI / JSON-line server (reading state) can share one instance.

    M4 batch 3.1.16A-3 (CRITICAL): every manager is bound to exactly one
    ``principal_id`` at construction.  All DB reads and writes are scoped
    to that principal — a different principal's tasks are invisible.
    Legacy rows (``principal_id='legacy'``) in the database are filtered
    out by ``list_coding_tasks(principal_id=...)`` and are therefore
    never loaded into the in-memory ``_tasks`` cache.

    The in-memory ``_tasks`` cache is preserved because each manager is
    constructed per-runtime (per ``AgentLoop``), each runtime belongs to
    exactly one principal, and ``load`` is called once at startup — the
    cache is implicitly principal-scoped.  Concurrent runtimes under
    different principals hold separate managers with separate caches;
    concurrent runtimes under the same principal share the database but
    each reload their own cache via ``load``.

    M4 batch 3.1.16A-5-1b (CRITICAL): ``project_id`` is also bound at
    construction and stamped on every persist so coding tasks are
    cryptographically tied to the project that owns them.  The RPC
    dispatcher's drift check (``ctx.project_id !=
    agent._bound_project_id``) is the sole authority — when the manager
    is constructed via ``build_runtime`` the ``project_id`` comes from
    ``RuntimeConfig.project_id`` (set by ``AgentService`` from the
    verified RPC payload), NOT from ``compute_project_id(root)``.
    Note: ``upsert_coding_task``'s ``ON CONFLICT`` clause DOES re-stamp
    ``project_id`` (mirroring ``principal_id``), because a task's
    lifecycle is tied to the runtime that owns it (a re-attach by the
    same principal in the same project is a normal lifecycle event).
    """

    def __init__(
        self,
        max_active: int = 5,
        db: Any = None,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
    ) -> None:
        self._tasks: dict[str, CodingTask] = {}
        self._max_active = max_active
        self._lock = asyncio.Lock()
        self._db = db
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}
        # Batch 2.5 §4: optional lease invalidation hook. When set
        # (by ApprovalRuntime / WorkspaceExecutionLeaseCoordinator),
        # cancel() calls it BEFORE transitioning the task to CANCELLED
        # so the ACTIVE execution lease is released.
        self._lease_invalidation_hook: Any = None
        # Batch 2.6 §5: optional per-workspace mutation fence. When set,
        # cancel() acquires the fence BEFORE lease invalidation so cancel
        # is serialized with active lease acquisition / Batch 3 execution.
        self._mutation_fence: Any = None
        self._execution_scope_resolver: Any = None
        # A3-1: principal binding.  Every task created, loaded, or
        # persisted through this manager is scoped to this principal.
        # ``principal_id='legacy'`` is the fail-closed default — a
        # manager constructed without an authenticated principal can
        # only see its own 'legacy' tasks (which should only exist as
        # migration leftovers, quarantined to ``status='failed'``).
        self._principal_id = principal_id
        # M4 batch 3.1.16A-5-1b: project identity binding.  Every task
        # persisted through this manager is stamped with this project
        # identity.  Default ``''`` ("unbound") matches the schema column
        # default — legacy callers / tests that omit it produce
        # ``project_id=''`` rows which are still visible (no filter is
        # applied on this column yet) but distinguishable from rows
        # stamped by a project-bound runtime.
        self._project_id = project_id

    @property
    def principal_id(self) -> str:
        """M4 batch 3.1.16A-4-2: read-only accessor for the bound
        principal.  ``TaskService`` uses this to decide whether an
        RPC caller (``ctx.principal_id``) is allowed to create tasks
        through this manager.  A mismatch means the server-level
        manager is bound to a different principal (e.g. ``local-uid``)
        than the transport principal — per-principal TaskManager
        construction is required to support that path (deferred to
        A-4-3 / A-4-4).
        """
        return self._principal_id

    def set_lease_invalidation_hook(self, hook: Any) -> None:
        """Register a callable invoked during cancel to release execution leases."""
        self._lease_invalidation_hook = hook

    def set_mutation_fence(self, fence: Any) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence."""
        self._mutation_fence = fence

    def set_execution_scope_resolver(self, resolver: Any) -> None:
        """Install the persisted ACTIVE-lease task/workspace resolver."""
        self._execution_scope_resolver = resolver

    async def load(self) -> None:
        """Restore tasks and mark interrupted in-flight work as blocked.

        M4 batch 3.1.16A-3: only tasks owned by this manager's bound
        principal are loaded.  Legacy rows and other principals' tasks
        are filtered out at the DB layer (``list_coding_tasks``).
        """
        if self._db is None:
            return
        for data in await self._db.list_coding_tasks(principal_id=self._principal_id):
            task = CodingTask(
                id=data["id"], goal=data.get("goal", ""),
                status=TaskStatus.parse(data.get("status", "pending")),
                created_at=datetime.fromisoformat(data["created_at"]),
                updated_at=datetime.fromisoformat(data["updated_at"]),
                files_modified=list(data.get("files_modified", [])),
                files_viewed=list(data.get("files_viewed", [])),
                test_results=list(data.get("test_results", [])),
                fix_attempts=int(data.get("fix_attempts", 0)),
                error=data.get("error"), metadata=dict(data.get("metadata", {})),
                trace=list(data.get("trace", [])),
                event_sequence=int(data.get("event_sequence", 0)),
                # A3-3: preserve the persisted principal.  Pre-A3 rows
                # lack this field and default to 'legacy' (matching the
                # migration helper's quarantine), so they'd be filtered
                # out by ``list_coding_tasks`` anyway — but if a row
                # somehow reached here without a principal, defaulting
                # to 'legacy' keeps the invariant.
                principal_id=data.get("principal_id", self._principal_id),
            )
            if task.status in ACTIVE_STATUSES:
                task.status = TaskStatus.BLOCKED
                task.error = "interrupted by process restart"
                task.touch()
            self._tasks[task.id] = task
            await self._persist(task)

    async def create(self, goal: str) -> CodingTask:
        """Create a new task. Raises if the active-task limit is reached.

        M4 batch 3.1.16A-3: the new task is stamped with this manager's
        bound ``principal_id`` so it is owned by that principal for its
        entire lifecycle.  An authenticated principal can therefore
        never create a task that another principal could see or cancel.
        """
        async with self._lock:
            if self._active_count() >= self._max_active:
                raise RuntimeError(
                    f"max active tasks reached ({self._max_active}); "
                    "complete or cancel an existing task first"
                )
            task = CodingTask(goal=goal, principal_id=self._principal_id)
            self._tasks[task.id] = task
            await self._persist(task)
            logger.info("created coding task %s: %s", task.id, goal[:80])
            return task

    async def get(self, task_id: str) -> CodingTask | None:
        """Return a task by id, or ``None`` if it doesn't exist."""
        async with self._lock:
            return self._tasks.get(task_id)

    async def update_status(
        self, task_id: str, status: TaskStatus | str, **kwargs: Any
    ) -> TransitionResult:
        """Transition a task's status and merge extra fields.

        ``kwargs`` may set any ``CodingTask`` attribute (e.g.
        ``fix_attempts=2``, ``error="..."``).
        """
        resolved = TaskStatus.parse(status) if isinstance(status, str) else status
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                logger.warning("update_status: unknown task %s", task_id)
                return TransitionResult.NOT_FOUND
            if task.status == resolved:
                for key, value in kwargs.items():
                    if hasattr(task, key):
                        setattr(task, key, value)
                    else:
                        task.metadata[key] = value
                if kwargs:
                    task.touch()
                    await self._persist(task)
                return TransitionResult.UNCHANGED
            if task.status in TERMINAL_STATUSES:
                logger.warning("refusing terminal task transition %s -> %s for %s", task.status.value, resolved.value, task_id)
                return TransitionResult.INVALID_TRANSITION
            task.status = resolved
            for key, value in kwargs.items():
                if hasattr(task, key):
                    setattr(task, key, value)
                else:
                    task.metadata[key] = value
            task.touch()
            await self._persist(task)
            return TransitionResult.UPDATED

    async def transition(self, task_id: str, *, expected: set[TaskStatus], target: TaskStatus, **updates: Any) -> TransitionResult:
        """Atomically transition only when current state is expected."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return TransitionResult.NOT_FOUND
            if task.status not in expected:
                return TransitionResult.INVALID_TRANSITION
            task.status = target
            for key, value in updates.items():
                if hasattr(task, key):
                    setattr(task, key, value)
                else:
                    task.metadata[key] = value
            task.touch()
            await self._persist(task)
            return TransitionResult.UPDATED

    async def find_by_pending_tool(self, tool_call_id: str) -> CodingTask | None:
        async with self._lock:
            for task in self._tasks.values():
                pending = task.metadata.get("pending_approval")
                if isinstance(pending, dict) and pending.get("tool_call_id") == tool_call_id:
                    return task
        return None

    async def add_test_result(self, task_id: str, result: dict) -> None:
        """Record one test-run outcome against a task."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                logger.warning("add_test_result: unknown task %s", task_id)
                return
            task.test_results.append(result)
            # Keep only the most recent history to bound memory.
            if len(task.test_results) > TEST_RESULT_HISTORY:
                task.test_results = task.test_results[-TEST_RESULT_HISTORY:]
            task.touch()
            await self._persist(task)

    async def track_file_modified(self, task_id: str, path: str) -> None:
        """Record a file this task modified (deduplicated)."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            if path not in task.files_modified:
                task.files_modified.append(path)
            task.touch()
            await self._persist(task)

    async def track_file_viewed(self, task_id: str, path: str) -> None:
        """Record a file this task read (deduplicated)."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            if path not in task.files_viewed:
                task.files_viewed.append(path)
            task.touch()
            await self._persist(task)

    async def list_active(
        self, *, principal_id: str | None = None,
    ) -> list[dict]:
        """Return all in-flight tasks (not completed/cancelled/failed).

        M4 batch 3.1.16A-4-2: when ``principal_id`` is provided, only
        tasks owned by that principal are returned.  This is a defense-
        in-depth filter — the cache is already scoped to the manager's
        bound principal at load time, but an explicit caller-supplied
        filter ensures that a future code path that mixes principals
        in one cache cannot leak across the boundary.
        """
        async with self._lock:
            return [
                task.to_dict()
                for task in self._tasks.values()
                if task.status in ACTIVE_STATUSES
                and (principal_id is None or task.principal_id == principal_id)
            ]

    async def list_all(
        self, *, principal_id: str | None = None,
    ) -> list[dict]:
        """Return every known task.

        M4 batch 3.1.16A-4-2: see ``list_active`` for the principal
        filter semantics.
        """
        async with self._lock:
            return [
                task.to_dict()
                for task in self._tasks.values()
                if principal_id is None or task.principal_id == principal_id
            ]

    async def cancel(self, task_id: str) -> TransitionResult:
        """Cancel an active task without overwriting a terminal state.

        Batch 2.6 §4: if a lease invalidation hook is registered, calls it
        BEFORE transitioning the task to CANCELLED. If the hook raises,
        cancel FAILS CLOSED — the task does NOT transition to CANCELLED,
        and ``TransitionResult.LEASE_INVALIDATION_FAILED`` is returned.
        The task stays in its current state so cancel can be retried.

        Batch 2.6 §5: if a mutation fence is registered AND the task is
        bound to a workspace, acquires the fence (owner="cancel:{task_id}")
        BEFORE the manager lock so cancel is serialized with active lease
        acquisition / Batch 3 execution / cleanup.

        Invariant: ``TaskStatus`` terminal ⇒ ACTIVE lease count = 0.
        """
        # Batch 2.6 §5: acquire the mutation fence FIRST (outermost lock)
        # if a workspace binding exists. This serializes cancel with
        # lease acquisition and cleanup on the same workspace.
        if self._mutation_fence is not None:
            if self._execution_scope_resolver is None:
                raise RuntimeError("TaskManager execution scope resolver is not configured")
            workspace_id = self._execution_scope_resolver(task_id)
        else:
            workspace_id = None
        if workspace_id is not None:
            async with self._mutation_fence.use(
                workspace_id, owner=f"cancel:{task_id}",
            ):
                return await self._cancel_impl(task_id)
        return await self._cancel_impl(task_id)

    async def _cancel_impl(self, task_id: str) -> TransitionResult:
        """Internal cancel — assumes fence (if any) is already held."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return TransitionResult.NOT_FOUND
            if task.status in TERMINAL_STATUSES:
                return TransitionResult.INVALID_TRANSITION
            # Release any ACTIVE execution lease for this task.
            # Batch 2.6 §4: fail closed on lease invalidation error — do
            # NOT transition to CANCELLED. The task stays in its current
            # state so cancel can be retried after the lease issue is
            # resolved.
            if self._lease_invalidation_hook is not None:
                try:
                    self._lease_invalidation_hook(task_id=task_id)
                except Exception as exc:
                    logger.warning(
                        "lease invalidation failed for task %s; "
                        "cancel refused (fail-closed): %s",
                        task_id, exc,
                    )
                    return TransitionResult.LEASE_INVALIDATION_FAILED
            task.status = TaskStatus.CANCELLED
            task.touch()
            await self._persist(task)
            return TransitionResult.UPDATED

    async def record_trace(self, task_id: str, entry: dict[str, Any]) -> None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.trace.append(entry)
            task.touch()
            await self._persist(task)

    async def _persist(self, task: CodingTask) -> None:
        task.event_sequence += 1
        if self._db is not None:
            # A3-2: stamp the bound principal on every persisted row so
            # ``list_coding_tasks(principal_id=...)`` can filter by it.
            # The task's own ``principal_id`` is the source of truth
            # (set at create time from ``self._principal_id``); we pass
            # it explicitly here so a row can never silently inherit
            # the DB default ('legacy') if a future code path constructs
            # a task with a different principal.
            #
            # M4 batch 3.1.16A-5-1b: stamp the project identity too.
            # ``upsert_coding_task``'s ``ON CONFLICT`` clause re-stamps
            # both ``principal_id`` and ``project_id`` (a task's lifecycle
            # is tied to the runtime that owns it), so passing the
            # manager's bound ``project_id`` here keeps the row's project
            # identity in sync with the runtime that is currently
            # persisting it (e.g. a re-attach after restart).
            await self._db.upsert_coding_task(
                task.to_dict(include_internal=True),
                principal_id=task.principal_id,
                project_id=self._project_id,
            )
        event = {"event_id": uuid.uuid4().hex, "task_id": task.id, "sequence": task.event_sequence, "type": f"task.{task.status.value}", "timestamp": task.updated_at.isoformat(), "payload": task.to_dict()}
        for queue in self._subscribers.get(task.id, []):
            queue.put_nowait(event)

    async def subscribe(self, task_id: str):
        """Yield an initial snapshot and subsequent state-change events."""
        task = await self.get(task_id)
        if task is None:
            raise KeyError(task_id)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        self._subscribers.setdefault(task_id, []).append(queue)
        try:
            yield {"event_id": uuid.uuid4().hex, "task_id": task.id, "sequence": task.event_sequence, "type": "task.snapshot", "timestamp": task.updated_at.isoformat(), "payload": task.to_dict()}
            while True:
                yield await queue.get()
        finally:
            self._subscribers[task_id].remove(queue)

    def _active_count(self) -> int:
        """Count in-flight tasks (callers hold ``self._lock``)."""
        return sum(1 for task in self._tasks.values() if task.status in ACTIVE_STATUSES)
