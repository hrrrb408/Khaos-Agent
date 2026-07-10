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


@dataclass
class CodingTask:
    """State record for one coding task."""

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

    def touch(self) -> None:
        """Stamp ``updated_at`` to now."""
        self.updated_at = datetime.now()

    def to_dict(self, include_internal: bool = False) -> dict[str, Any]:
        """Serialize to a JSON-safe dict for the TUI / RPC layer."""
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
        return data


class TaskManager:
    """Track all active coding tasks.

    Thread-safe via an ``asyncio.Lock`` so ``AgentLoop`` (recording activity)
    and the TUI / JSON-line server (reading state) can share one instance.
    """

    def __init__(self, max_active: int = 5, db: Any = None) -> None:
        self._tasks: dict[str, CodingTask] = {}
        self._max_active = max_active
        self._lock = asyncio.Lock()
        self._db = db

    async def load(self) -> None:
        """Restore tasks and mark interrupted in-flight work as blocked."""
        if self._db is None:
            return
        for data in await self._db.list_coding_tasks():
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
            )
            if task.status in ACTIVE_STATUSES:
                task.status = TaskStatus.BLOCKED
                task.error = "interrupted by process restart"
                task.touch()
            self._tasks[task.id] = task
            await self._persist(task)

    async def create(self, goal: str) -> CodingTask:
        """Create a new task. Raises if the active-task limit is reached."""
        async with self._lock:
            if self._active_count() >= self._max_active:
                raise RuntimeError(
                    f"max active tasks reached ({self._max_active}); "
                    "complete or cancel an existing task first"
                )
            task = CodingTask(goal=goal)
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
    ) -> None:
        """Transition a task's status and merge extra fields.

        ``kwargs`` may set any ``CodingTask`` attribute (e.g.
        ``fix_attempts=2``, ``error="..."``).
        """
        resolved = TaskStatus.parse(status) if isinstance(status, str) else status
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                logger.warning("update_status: unknown task %s", task_id)
                return
            task.status = resolved
            for key, value in kwargs.items():
                if hasattr(task, key):
                    setattr(task, key, value)
                else:
                    task.metadata[key] = value
            task.touch()
            await self._persist(task)

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

    async def list_active(self) -> list[dict]:
        """Return all in-flight tasks (not completed/cancelled/failed)."""
        async with self._lock:
            return [
                task.to_dict()
                for task in self._tasks.values()
                if task.status in ACTIVE_STATUSES
            ]

    async def list_all(self) -> list[dict]:
        """Return every known task."""
        async with self._lock:
            return [task.to_dict() for task in self._tasks.values()]

    async def cancel(self, task_id: str) -> bool:
        """Mark a task cancelled. Returns False if the task is unknown."""
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return False
            task.status = TaskStatus.CANCELLED
            task.touch()
            await self._persist(task)
            return True

    async def record_trace(self, task_id: str, entry: dict[str, Any]) -> None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return
            task.trace.append(entry)
            task.touch()
            await self._persist(task)

    async def _persist(self, task: CodingTask) -> None:
        if self._db is not None:
            await self._db.upsert_coding_task(task.to_dict(include_internal=True))

    def _active_count(self) -> int:
        """Count in-flight tasks (callers hold ``self._lock``)."""
        return sum(1 for task in self._tasks.values() if task.status in ACTIVE_STATUSES)
