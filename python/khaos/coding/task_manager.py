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

from khaos.agent.control.goal import GoalSpec
from khaos.agent.control.goal_repository import (
    GoalSpecIntegrityError,
    GoalSpecRepository,
)
from khaos.agent.control.state import (
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.agent.control.state_repository import (
    AgentControlStateRepository,
    CognitiveStateIntegrityError,
    CognitiveTransitionResult,
    CognitiveTransitionStatus,
)
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)

#: How many recent test results are retained per task (older ones dropped).
TEST_RESULT_HISTORY = 5

_GOAL_SPEC_PROTECTED_FIELDS = frozenset(
    {"goal_spec_id", "goal_spec_digest", "goal_spec", "_persisted"}
)
_COGNITIVE_STATE_PROTECTED_FIELDS = frozenset(
    {"cognitive_state", "control_state_version"}
)


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
    def parse(cls, value: str) -> TaskStatus:
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

    id: str = field(default_factory=lambda: uuid.uuid4().hex)
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
    # Round-4 review Batch 4: tracks whether this task has been INSERTed
    # into the DB.  ``_persist`` uses this to choose ``insert_coding_task``
    # (first write) vs ``update_coding_task`` (subsequent writes).  Tasks
    # loaded from the DB via ``load()`` start with ``_persisted=True``.
    # Not included in ``to_dict()`` — it is a runtime-only flag.
    _persisted: bool = field(default=False, repr=False, compare=False)
    # M7.1.2: the canonical declaration is stored in ``agent_goal_specs``.
    # Only its identity/digest are projected into task state JSON; the
    # in-memory value object is resolved from the owner-scoped repository.
    goal_spec_id: str | None = field(default=None, compare=False)
    goal_spec_digest: str | None = field(default=None, compare=False)
    goal_spec: GoalSpec | None = field(default=None, repr=False, compare=False)
    # M7.1.3: this is a read projection of the independent SQL control-state
    # domain.  The database columns, not state_json or this mutable object,
    # are the canonical authority.  Appended after the pre-M7 fields to keep
    # existing positional CodingTask construction source-compatible.
    cognitive_state: AgentCognitiveState = field(
        default=AgentCognitiveState.UNINITIALIZED, compare=False
    )
    control_state_version: int = field(default=0, compare=False)

    def __post_init__(self) -> None:
        """Enforce the task/display projection invariant for new tasks."""
        if type(self.cognitive_state) is not AgentCognitiveState:
            raise ValueError("cognitive_state must be an AgentCognitiveState")
        if (
            type(self.control_state_version) is not int
            or self.control_state_version < 0
        ):
            raise ValueError(
                "control_state_version must be a non-negative integer"
            )
        if self.goal_spec is None:
            if self.goal_spec_id is not None or self.goal_spec_digest is not None:
                raise ValueError(
                    "GoalSpec references require a resolved GoalSpec value"
                )
            return
        if self.goal != self.goal_spec.raw_goal:
            raise ValueError("CodingTask.goal must equal GoalSpec.raw_goal")
        if self.goal_spec_id is None:
            self.goal_spec_id = self.goal_spec.goal_spec_id
        if self.goal_spec_digest is None:
            self.goal_spec_digest = self.goal_spec.semantic_digest
        if (
            self.goal_spec_id != self.goal_spec.goal_spec_id
            or self.goal_spec_digest != self.goal_spec.semantic_digest
        ):
            raise ValueError("CodingTask GoalSpec references do not match GoalSpec")

    def _validate_goal_spec_projection(self) -> None:
        """Reject a mutable task projection that diverged from GoalSpec."""
        if self.goal_spec is None:
            if self.goal_spec_id is not None or self.goal_spec_digest is not None:
                raise ValueError(
                    "GoalSpec references require a resolved GoalSpec value"
                )
            return
        if self.goal != self.goal_spec.raw_goal:
            raise ValueError("CodingTask.goal must equal GoalSpec.raw_goal")
        if (
            self.goal_spec_id != self.goal_spec.goal_spec_id
            or self.goal_spec_digest != self.goal_spec.semantic_digest
        ):
            raise ValueError("CodingTask GoalSpec references do not match GoalSpec")

    def touch(self) -> None:
        """Stamp ``updated_at`` to now."""
        self.updated_at = utc_now_naive()

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
            "cognitive_state": self.cognitive_state.value,
            "control_state_version": self.control_state_version,
        }
        if include_internal:
            data["metadata"] = self.metadata
            data["trace"] = self.trace
            data["event_sequence"] = self.event_sequence
            data["principal_id"] = self.principal_id
            if self.goal_spec_id is not None:
                data["goal_spec_id"] = self.goal_spec_id
            if self.goal_spec_digest is not None:
                data["goal_spec_digest"] = self.goal_spec_digest
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
    Note: Round-4 review Batch 4 replaced ``upsert_coding_task`` with
    ``insert_coding_task`` (Plain INSERT) + ``update_coding_task``
    (Owner-bound UPDATE).  Ownership (``principal_id`` +
    ``project_id``) is now immutable after creation — a re-attach by
    a different runtime raises ``OwnerMismatchError`` instead of
    silently re-stamping.
    """

    def __init__(
        self,
        max_active: int = 5,
        db: Any = None,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
        goal_spec_repository: GoalSpecRepository | None = None,
    ) -> None:
        self._tasks: dict[str, CodingTask] = {}
        self._max_active = max_active
        self._lock = asyncio.Lock()
        self._db = db
        self._subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}
        # Batch 6.5 (round-6 §十七): eviction-in-progress flag.  Once
        # ``begin_eviction()`` atomically sets this under ``self._lock``,
        # new ``create()`` / ``subscribe()`` calls are rejected so the
        # eviction cannot race a task going active or a subscriber
        # registering in the gap between ``can_evict()`` and ``aclose()``.
        self._closing = False
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
        if goal_spec_repository is not None:
            if (
                db is not None
                and goal_spec_repository.database is not db
            ):
                raise ValueError(
                    "GoalSpec repository must share the TaskManager database"
                )
            self._goal_spec_repository = goal_spec_repository
            if db is not None:
                self._agent_control_state_repository = getattr(
                    db, "agent_control_state_repository", None
                ) or AgentControlStateRepository(db)
            else:
                self._agent_control_state_repository = None
        elif db is not None:
            # Database composes one repository instance.  The fallback keeps
            # explicit database test ports compatible without creating a
            # module-global handle or a second physical connection.
            self._goal_spec_repository = getattr(
                db, "goal_spec_repository", None
            ) or GoalSpecRepository(db)
            self._agent_control_state_repository = getattr(
                db, "agent_control_state_repository", None
            ) or AgentControlStateRepository(db)
        else:
            self._goal_spec_repository = None
            self._agent_control_state_repository = None

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

    @property
    def goal_spec_repository(self) -> GoalSpecRepository | None:
        """Return the repository composed for this task manager."""
        return self._goal_spec_repository

    @property
    def agent_control_state_repository(self) -> AgentControlStateRepository | None:
        """Return the owner-scoped cognitive-state CAS repository."""
        return self._agent_control_state_repository

    def set_lease_invalidation_hook(self, hook: Any) -> None:
        """Register a callable invoked during cancel to release execution leases."""
        self._lease_invalidation_hook = hook

    def set_mutation_fence(self, fence: Any) -> None:
        """Batch 2.6 §5: register the shared per-workspace mutation fence."""
        self._mutation_fence = fence

    def set_execution_scope_resolver(self, resolver: Any) -> None:
        """Install the persisted ACTIVE-lease task/workspace resolver."""
        self._execution_scope_resolver = resolver

    async def _decode_persisted_task(
        self, data: dict[str, Any]
    ) -> tuple[CodingTask, TaskStatus]:
        """Decode one owner-scoped row without applying restart semantics.

        ``load`` and ``refresh_projection`` intentionally share this strict
        decoder but have different lifecycle semantics.  The former marks an
        interrupted active task ``BLOCKED``; the latter is read-only cache
        reconciliation and must preserve the physical SQL status exactly.
        """
        task_id = data.get("id")
        goal = data.get("goal", "")
        if type(task_id) is not str or not task_id:
            raise GoalSpecIntegrityError("coding task row has no valid task id")
        if type(goal) is not str:
            raise GoalSpecIntegrityError("coding task row has no valid goal")
        if self._goal_spec_repository is None:
            raise GoalSpecIntegrityError(
                "durable task loading requires a GoalSpec repository"
            )
        goal_spec = await self._goal_spec_repository.get_for_task(
            task_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
        )
        if goal_spec is None:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} has no owner-scoped GoalSpec"
            )
        if goal != goal_spec.raw_goal:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} goal disagrees with canonical GoalSpec"
            )
        persisted_goal_spec_id = data.get("goal_spec_id")
        persisted_goal_spec_digest = data.get("goal_spec_digest")
        if (
            persisted_goal_spec_id is not None
            and persisted_goal_spec_id != goal_spec.goal_spec_id
        ):
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} GoalSpec id projection disagrees"
            )
        if (
            persisted_goal_spec_digest is not None
            and persisted_goal_spec_digest != goal_spec.semantic_digest
        ):
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} GoalSpec digest projection disagrees"
            )
        try:
            cognitive_state = AgentCognitiveState.parse(
                data.get(
                    "cognitive_state",
                    AgentCognitiveState.UNINITIALIZED.value,
                )
            )
        except ValueError as exc:
            raise CognitiveStateIntegrityError(
                f"coding task {task_id!r} has an invalid cognitive state"
            ) from exc
        control_state_version = data.get("control_state_version", 0)
        if (
            type(control_state_version) is not int
            or control_state_version < 0
        ):
            raise CognitiveStateIntegrityError(
                f"coding task {task_id!r} has an invalid control-state version"
            )
        loaded_status = TaskStatus.parse(data.get("status", "pending"))

        list_fields = (
            "files_modified",
            "files_viewed",
            "test_results",
            "trace",
        )
        for field_name in list_fields:
            if type(data.get(field_name, [])) is not list:
                raise GoalSpecIntegrityError(
                    f"coding task {task_id!r} field {field_name!r} is not a list"
                )
        metadata = data.get("metadata", {})
        if type(metadata) is not dict:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} metadata is not an object"
            )
        workspace_id = metadata.get("workspace_id")
        if workspace_id is not None and (
            type(workspace_id) is not str or not workspace_id
        ):
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} workspace projection is malformed"
            )
        fix_attempts = data.get("fix_attempts", 0)
        event_sequence = data.get("event_sequence", 0)
        if (
            type(fix_attempts) is not int
            or fix_attempts < 0
            or type(event_sequence) is not int
            or event_sequence < 0
        ):
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} has invalid counters"
            )
        try:
            created_at = datetime.fromisoformat(data["created_at"])
            updated_at = datetime.fromisoformat(data["updated_at"])
        except (KeyError, TypeError, ValueError) as exc:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} has invalid timestamps"
            ) from exc
        error = data.get("error")
        if error is not None and type(error) is not str:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} error projection is invalid"
            )
        principal_id = data.get("principal_id", self._principal_id)
        if type(principal_id) is not str or not principal_id:
            raise GoalSpecIntegrityError(
                f"coding task {task_id!r} principal projection is invalid"
            )
        task = CodingTask(
            id=task_id,
            goal=goal,
            status=loaded_status,
            created_at=created_at,
            updated_at=updated_at,
            files_modified=list(data.get("files_modified", [])),
            files_viewed=list(data.get("files_viewed", [])),
            test_results=list(data.get("test_results", [])),
            fix_attempts=fix_attempts,
            error=error,
            metadata=dict(metadata),
            trace=list(data.get("trace", [])),
            event_sequence=event_sequence,
            principal_id=principal_id,
            goal_spec_id=goal_spec.goal_spec_id,
            goal_spec_digest=goal_spec.semantic_digest,
            goal_spec=goal_spec,
            cognitive_state=cognitive_state,
            control_state_version=control_state_version,
        )
        task._persisted = True
        return task, loaded_status

    async def load(self) -> None:
        """Restore tasks and mark interrupted in-flight work as blocked.

        M4 batch 3.1.16A-3: only tasks owned by this manager's bound
        principal are loaded.  Legacy rows and other principals' tasks
        are filtered out at the DB layer (``list_coding_tasks``).
        """
        if self._db is None:
            return
        if self._goal_spec_repository is None:
            raise GoalSpecIntegrityError(
                "durable task loading requires a GoalSpec repository"
            )
        for data in await self._db.list_coding_tasks(
            principal_id=self._principal_id,
            project_id=self._project_id,
        ):
            task, loaded_status = await self._decode_persisted_task(data)
            if task.status in ACTIVE_STATUSES:
                task.status = TaskStatus.BLOCKED
                task.error = "interrupted by process restart"
                task.touch()
            self._tasks[task.id] = task
            await self._persist(task, expected_status=loaded_status)

    async def refresh_projection(self, task_id: str) -> CodingTask | None:
        """Refresh one cached task from durable state without lifecycle writes.

        This is intentionally separate from ``load``.  It does not apply the
        process-restart ``ACTIVE -> BLOCKED`` rule, does not persist anything,
        and never treats the in-memory cache as authoritative.  A missing row
        is indistinguishable from an owner-scoped unavailable task.
        """
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be a non-empty string")
        if self._db is None:
            return await self.get(task_id)
        if self._goal_spec_repository is None:
            raise GoalSpecIntegrityError(
                "durable task refresh requires a GoalSpec repository"
            )
        async with self._lock:
            rows = await self._db.list_coding_tasks(
                principal_id=self._principal_id,
                project_id=self._project_id,
            )
            data = next((row for row in rows if row.get("id") == task_id), None)
            if data is None:
                self._tasks.pop(task_id, None)
                return None
            task, _loaded_status = await self._decode_persisted_task(data)
            self._tasks[task.id] = task
        return task

    async def create(self, goal: str) -> CodingTask:
        """Create a new task. Raises if the active-task limit is reached.

        M4 batch 3.1.16A-3: the new task is stamped with this manager's
        bound ``principal_id`` so it is owned by that principal for its
        entire lifecycle.  An authenticated principal can therefore
        never create a task that another principal could see or cancel.
        """
        async with self._lock:
            if self._closing:
                # Batch 6.5 §十七: the manager is mid-eviction — refuse
                # new work so the eviction's ``begin_eviction`` CAS stays
                # valid (no active task can appear after the check).
                raise RuntimeError(
                    "TaskManager is closing (evicted from LRU cache); "
                    "retry against a fresh manager"
                )
            if self._active_count() >= self._max_active:
                raise RuntimeError(
                    f"max active tasks reached ({self._max_active}); "
                    "complete or cancel an existing task first"
                )
            goal_spec = GoalSpec.from_user_goal(goal)
            task = CodingTask(
                goal=goal,
                principal_id=self._principal_id,
                goal_spec=goal_spec,
            )
            self._tasks[task.id] = task
            try:
                if self._db is None:
                    await self._persist(task)
                else:
                    if self._goal_spec_repository is None:
                        raise GoalSpecIntegrityError(
                            "durable task creation requires a GoalSpec repository"
                        )
                    # Database.transaction() owns BEGIN/COMMIT/ROLLBACK. The
                    # task and canonical GoalSpec inserts are nested within
                    # this one transaction; inner repository calls reuse the
                    # same transaction owner and cannot commit independently.
                    async with self._db.transaction():
                        await self._persist(task, emit_event=False)
                        await self._goal_spec_repository.insert(
                            goal_spec,
                            task_id=task.id,
                            principal_id=task.principal_id,
                            project_id=self._project_id,
                        )
            except BaseException:
                # A failed atomic create must not leave a task visible in the
                # manager cache or make the caller believe durable state exists.
                self._tasks.pop(task.id, None)
                task._persisted = False
                raise
            if self._db is not None:
                self._publish_task_event(task)
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
            old_status = task.status
            if task.status == resolved:
                self._apply_task_updates(task, kwargs)
                if kwargs:
                    task.touch()
                    await self._persist(task, expected_status=old_status)
                return TransitionResult.UNCHANGED
            if resolved is TaskStatus.COMPLETED:
                logger.warning(
                    "refusing generic task completion %s -> completed for %s",
                    old_status.value,
                    task_id,
                )
                return TransitionResult.INVALID_TRANSITION
            if old_status in TERMINAL_STATUSES:
                logger.warning("refusing terminal task transition %s -> %s for %s", old_status.value, resolved.value, task_id)
                return TransitionResult.INVALID_TRANSITION
            self._apply_task_updates(task, kwargs)
            task.status = resolved
            task.touch()
            await self._persist(task, expected_status=old_status)
            return TransitionResult.UPDATED

    async def reflect_gate_completion(
        self, task_id: str, *, gate_token: object
    ) -> None:
        """Reflect a database-confirmed Gate projection in this cache.

        ``CompletionGateRepository`` is the lifecycle authority and has
        already committed the owner-scoped SQL CAS before this method is
        called.  The internal token prevents this cache helper from becoming
        a second completion authority: an arbitrary caller cannot set the
        cached status and then cause a normal manager persist to write
        ``completed``.  This method deliberately does not persist or decide a
        transition; it only keeps the current manager projection aligned with
        the committed database result.
        """
        from khaos.agent.control.completion_gate_repository import (
            _COMPLETION_GATE_TOKEN,
        )

        if gate_token is not _COMPLETION_GATE_TOKEN:
            raise PermissionError(
                "task completion cache reflection is owned by CompletionGate"
            )
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.status = TaskStatus.COMPLETED
            task.touch()

    async def transition(self, task_id: str, *, expected: set[TaskStatus], target: TaskStatus, **updates: Any) -> TransitionResult:
        """Atomically transition only when current state is expected."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return TransitionResult.NOT_FOUND
            if task.status not in expected:
                return TransitionResult.INVALID_TRANSITION
            old_status = task.status
            if old_status in TERMINAL_STATUSES and target is not old_status:
                logger.warning(
                    "refusing terminal task transition %s -> %s for %s",
                    old_status.value,
                    target.value,
                    task_id,
                )
                return TransitionResult.INVALID_TRANSITION
            if target is TaskStatus.COMPLETED and old_status is not TaskStatus.COMPLETED:
                logger.warning(
                    "refusing generic task completion %s -> completed for %s",
                    old_status.value,
                    task_id,
                )
                return TransitionResult.INVALID_TRANSITION
            self._apply_task_updates(task, updates)
            task.status = target
            task.touch()
            await self._persist(task, expected_status=old_status)
            return TransitionResult.UPDATED

    async def initialize_cognitive_state(
        self, task_id: str
    ) -> CognitiveTransitionResult:
        """Explicitly initialize a newly started task for the AgentLoop."""
        return await self.transition_cognitive_state(
            task_id,
            target=AgentCognitiveState.UNDERSTANDING,
            expected_state=AgentCognitiveState.UNINITIALIZED,
            expected_version=0,
        )

    async def transition_cognitive_state(
        self,
        task_id: str,
        *,
        target: AgentCognitiveState,
        expected_state: AgentCognitiveState | None = None,
        expected_version: int | None = None,
    ) -> CognitiveTransitionResult:
        """Validate and CAS a task's durable cognitive state.

        The pure state machine is consulted before the SQL repository.  A
        successful database CAS updates only this manager's in-memory
        projection; ordinary task persistence never writes the cognitive
        columns.  A stale result leaves the projection untouched so callers
        must explicitly refresh before making a new decision.
        """
        if type(target) is not AgentCognitiveState:
            raise TypeError("target must be an AgentCognitiveState")
        async with self._lock:
            task = self._tasks.get(task_id)
            resolved_expected_state = (
                expected_state
                if expected_state is not None
                else (
                    task.cognitive_state
                    if task is not None
                    else AgentCognitiveState.UNINITIALIZED
                )
            )
            resolved_expected_version = (
                expected_version
                if expected_version is not None
                else (task.control_state_version if task is not None else 0)
            )
            if type(resolved_expected_state) is not AgentCognitiveState:
                raise TypeError(
                    "expected_state must be an AgentCognitiveState"
                )
            if (
                type(resolved_expected_version) is not int
                or resolved_expected_version < 0
            ):
                raise ValueError(
                    "expected_version must be a non-negative integer"
                )
            if task is None:
                return CognitiveTransitionResult(
                    status=CognitiveTransitionStatus.NOT_FOUND,
                    task_id=task_id,
                    expected_state=resolved_expected_state,
                    expected_version=resolved_expected_version,
                    target_state=target,
                )

            validation = AgentCognitiveStateMachine.validate_transition(
                resolved_expected_state, target
            )
            if validation is CognitiveTransitionValidation.ILLEGAL:
                return CognitiveTransitionResult.illegal_transition(
                    task_id=task_id,
                    current_state=resolved_expected_state,
                    current_version=resolved_expected_version,
                    target_state=target,
                )

            if self._agent_control_state_repository is None:
                # A database-less TaskManager is retained for isolated unit
                # callers.  It has no durable authority, but still follows
                # the same closed graph and version semantics locally.
                if task.status in TERMINAL_STATUSES:
                    return CognitiveTransitionResult(
                        status=CognitiveTransitionStatus.TERMINAL_TASK,
                        task_id=task_id,
                        expected_state=resolved_expected_state,
                        expected_version=resolved_expected_version,
                        target_state=target,
                        current_state=task.cognitive_state,
                        control_state_version=task.control_state_version,
                        task_status=task.status.value,
                    )
                if task.control_state_version != resolved_expected_version:
                    result_status = CognitiveTransitionStatus.STALE_VERSION
                elif task.cognitive_state is not resolved_expected_state:
                    result_status = CognitiveTransitionStatus.STALE_STATE
                elif validation is CognitiveTransitionValidation.UNCHANGED:
                    result_status = CognitiveTransitionStatus.UNCHANGED
                else:
                    task.cognitive_state = target
                    task.control_state_version += 1
                    result_status = CognitiveTransitionStatus.UPDATED
                return CognitiveTransitionResult(
                    status=result_status,
                    task_id=task_id,
                    expected_state=resolved_expected_state,
                    expected_version=resolved_expected_version,
                    target_state=target,
                    current_state=task.cognitive_state,
                    control_state_version=task.control_state_version,
                    task_status=task.status.value,
                )

            result = await self._agent_control_state_repository.compare_and_transition(
                task_id,
                principal_id=self._principal_id,
                project_id=self._project_id,
                expected_state=resolved_expected_state,
                expected_version=resolved_expected_version,
                target_state=target,
            )
            if result.status in {
                CognitiveTransitionStatus.UPDATED,
                CognitiveTransitionStatus.UNCHANGED,
            }:
                if result.current_state is None or result.control_state_version is None:
                    raise CognitiveStateIntegrityError(
                        "successful cognitive transition has no resulting projection"
                    )
                task.cognitive_state = result.current_state
                task.control_state_version = result.control_state_version
            return result

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
            expected_status = task.status
            task.test_results.append(result)
            # Keep only the most recent history to bound memory.
            if len(task.test_results) > TEST_RESULT_HISTORY:
                task.test_results = task.test_results[-TEST_RESULT_HISTORY:]
            task.touch()
            await self._persist(task, expected_status=expected_status)

    async def track_file_modified(self, task_id: str, path: str) -> None:
        """Record a file this task modified (deduplicated)."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            expected_status = task.status
            if path not in task.files_modified:
                task.files_modified.append(path)
            task.touch()
            await self._persist(task, expected_status=expected_status)

    async def track_file_viewed(self, task_id: str, path: str) -> None:
        """Record a file this task read (deduplicated)."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            expected_status = task.status
            if path not in task.files_viewed:
                task.files_viewed.append(path)
            task.touch()
            await self._persist(task, expected_status=expected_status)

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
                except Exception as exc:  # noqa: BLE001 - lease hooks are fail-closed boundaries
                    logger.warning(
                        "lease invalidation failed for task %s; "
                        "cancel refused (fail-closed): %s",
                        task_id, exc,
                    )
                    return TransitionResult.LEASE_INVALIDATION_FAILED
            old_status = task.status
            task.status = TaskStatus.CANCELLED
            task.touch()
            await self._persist(task, expected_status=old_status)
            return TransitionResult.UPDATED

    async def record_trace(self, task_id: str, entry: dict[str, Any]) -> None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            expected_status = task.status
            task.trace.append(entry)
            task.touch()
            await self._persist(task, expected_status=expected_status)

    async def _persist(
        self,
        task: CodingTask,
        *,
        expected_status: TaskStatus | str | None = None,
        emit_event: bool = True,
    ) -> None:
        task._validate_goal_spec_projection()
        if task._persisted and expected_status is None:
            raise ValueError(
                "expected_status is required when persisting an existing task"
            )
        previous_event_sequence = task.event_sequence
        task.event_sequence += 1
        try:
            if self._db is not None:
                # A3-2: stamp the bound principal on every persisted row so
                # ``list_coding_tasks(principal_id=...)`` can filter by it.
                # The task's own ``principal_id`` is the source of truth
                # (set at create time from ``self._principal_id``); we pass
                # it explicitly here so a row can never silently inherit
                # the DB default ('legacy') if a future code path constructs
                # a task with a different principal.
                #
                # Round-4 review Batch 4 (§八): split into Plain INSERT
                # (first write) and lifecycle-CAS UPDATE (subsequent writes).
                # Ownership (principal_id + project_id) is immutable after
                # creation, and the expected status is captured before the
                # caller mutates this in-memory projection.
                task_dict = task.to_dict(include_internal=True)
                if not task._persisted:
                    await self._db.insert_coding_task(
                        task_dict,
                        principal_id=task.principal_id,
                        project_id=self._project_id,
                    )
                    task._persisted = True
                else:
                    if isinstance(expected_status, TaskStatus):
                        expected_status_value = expected_status.value
                    else:
                        expected_status_value = expected_status
                    await self._db.update_coding_task(
                        task_dict,
                        principal_id=task.principal_id,
                        project_id=self._project_id,
                        expected_status=expected_status_value,
                    )
        except BaseException:
            # A failed CAS did not commit this event.  Keep the local event
            # sequence and lifecycle projection aligned with the last
            # committed values; the caller still receives the original
            # typed failure and must explicitly refresh before making
            # another lifecycle decision.  Metadata mutations remain local
            # observations until a later successful persistence operation.
            if isinstance(expected_status, TaskStatus):
                task.status = expected_status
            elif isinstance(expected_status, str):
                try:
                    task.status = TaskStatus.parse(expected_status)
                except ValueError:
                    # The database layer owns validation of raw status
                    # strings; do not mask its original exception here.
                    pass
            task.event_sequence = previous_event_sequence
            raise
        if emit_event:
            self._publish_task_event(task)

    def _publish_task_event(self, task: CodingTask) -> None:
        """Publish a committed task snapshot to subscribers."""
        event = {"event_id": uuid.uuid4().hex, "task_id": task.id, "sequence": task.event_sequence, "type": f"task.{task.status.value}", "timestamp": task.updated_at.isoformat(), "payload": task.to_dict()}
        for queue in self._subscribers.get(task.id, []):
            queue.put_nowait(event)

    @staticmethod
    def _apply_task_updates(
        task: CodingTask, updates: dict[str, Any]
    ) -> None:
        """Apply mutable task updates without bypassing control owners."""
        for key, value in updates.items():
            if key in _GOAL_SPEC_PROTECTED_FIELDS:
                raise ValueError(f"CodingTask field {key!r} is immutable")
            if key in _COGNITIVE_STATE_PROTECTED_FIELDS:
                raise ValueError(
                    f"CodingTask field {key!r} requires the cognitive-state CAS owner"
                )
            if (
                key == "goal"
                and task.goal_spec is not None
                and value != task.goal_spec.raw_goal
            ):
                raise ValueError("CodingTask.goal must equal GoalSpec.raw_goal")
        for key, value in updates.items():
            if hasattr(task, key):
                setattr(task, key, value)
            else:
                task.metadata[key] = value

    async def subscribe(self, task_id: str):
        """Yield an initial snapshot and subsequent state-change events.

        Batch 6.5 (round-6 §十七): the loop now treats a ``task.evicted``
        event as a terminal sentinel and breaks cleanly, so the consumer
        unblocks when the manager is evicted from the LRU cache instead
        of awaiting a queue that will never receive another event.  The
        ``finally`` removes the queue idempotently ( swallowing
        ``ValueError``/``KeyError``) so it cannot race ``aclose()``
        replacing the subscriber list with ``[]``.
        """
        task = await self.get(task_id)
        if task is None:
            raise KeyError(task_id)
        async with self._lock:
            if self._closing:
                raise RuntimeError(
                    "TaskManager is closing (evicted from LRU cache); "
                    "subscription refused"
                )
            queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
            self._subscribers.setdefault(task_id, []).append(queue)
        try:
            yield {"event_id": uuid.uuid4().hex, "task_id": task.id, "sequence": task.event_sequence, "type": "task.snapshot", "timestamp": task.updated_at.isoformat(), "payload": task.to_dict()}
            while True:
                event = await queue.get()
                yield event
                # Batch 6.5 §十七: terminal sentinel — stop after the
                # consumer sees the eviction event.
                if event.get("type") == "task.evicted":
                    break
        finally:
            # Idempotent remove: ``aclose()`` may have replaced this
            # task's subscriber list with ``[]`` already, in which case a
            # bare ``.remove(queue)`` raises ``ValueError``.
            try:
                self._subscribers[task_id].remove(queue)
            except (ValueError, KeyError):
                pass

    def _active_count(self) -> int:
        """Count in-flight tasks (callers hold ``self._lock``)."""
        return sum(1 for task in self._tasks.values() if task.status in ACTIVE_STATUSES)

    def can_evict(self) -> bool:
        """Round-5 Batch 5.4: return ``True`` only if this manager is safe
        to evict from the ``TaskService`` LRU cache.

        A manager is **not** evictable while:
          - It has any task in an ``ACTIVE_STATUSES`` state (a live owner
            may be mid-execution and would lose its in-memory tracking).
          - It has live subscribers (an RPC streaming consumer is
            awaiting state updates — evicting would orphan the queue).

        Evicting a manager with active work would silently drop the
        in-memory cache; the next access would ``load()`` from the DB
        and mark interrupted in-flight tasks as ``blocked``, which is
        a correctness regression for the live owner.  ``TaskService``
        therefore skips non-evictable entries and allows the cache to
        temporarily exceed ``_MAX_MANAGERS`` rather than evicting a
        live owner.

        Batch 6.5 (round-6 §十七): this is a NON-LOCKED fast-path
        pre-filter only.  ``TaskService`` uses it to skip obviously-live
        candidates cheaply, but the authoritative eviction decision is
        the atomic ``begin_eviction()`` CAS, which re-checks the same
        conditions under ``self._lock`` and flips ``_closing`` so no
        task can go active or subscriber register in the gap.
        """
        if self._closing:
            return False
        if any(task.status in ACTIVE_STATUSES for task in self._tasks.values()):
            return False
        return not any(subs for subs in self._subscribers.values())

    async def begin_eviction(self) -> bool:
        """Batch 6.5 (round-6 §十七): atomically check evictability and
        mark the manager closing.

        Returns ``True`` and sets ``self._closing = True`` under
        ``self._lock`` iff the manager has no active tasks and no live
        subscribers.  Once ``_closing`` is set, ``create()`` and
        ``subscribe()`` refuse new work, closing the TOCTOU window that
        existed between the unlocked ``can_evict()`` poll and the
        ``aclose()`` drain.  ``TaskService`` must call this BEFORE
        ``aclose()``/``pop`` and only proceed when it returns ``True``.
        """
        async with self._lock:
            if self._closing:
                # Already mid-eviction (e.g. two concurrent evictors);
                # treat as "not mine to evict".
                return False
            if any(task.status in ACTIVE_STATUSES for task in self._tasks.values()):
                return False
            if any(subs for subs in self._subscribers.values()):
                return False
            self._closing = True
            return True

    async def aclose(self) -> None:
        """Round-5 Batch 5.4: best-effort cleanup when evicted from the
        ``TaskService`` LRU cache.

        Closes all subscriber queues by feeding them a terminal
        ``task.evicted`` event so streaming consumers unblock
        immediately instead of waiting for a queue that will never
        receive another update.  Subscribers are expected to treat any
        unknown/terminal event as a stream-end signal.

        Batch 6.5 (round-6 §十七): ``TaskService`` must call
        ``begin_eviction()`` first and only ``aclose()`` when it returns
        ``True``; ``aclose()`` itself does NOT re-check evictability
        (the CAS already guaranteed no new work can arrive).  It is safe
        to call without ``begin_eviction`` only for final process
        teardown where no concurrency remains.
        """
        async with self._lock:
            for task_id, queues in list(self._subscribers.items()):
                for queue in queues:
                    try:
                        queue.put_nowait(
                            {
                                "event_id": uuid.uuid4().hex,
                                "task_id": task_id,
                                "sequence": 0,
                                "type": "task.evicted",
                                "timestamp": utc_now_naive().isoformat(),
                                "payload": {"reason": "manager_evicted"},
                            }
                        )
                    except asyncio.QueueFull:
                        pass
                self._subscribers[task_id] = []
