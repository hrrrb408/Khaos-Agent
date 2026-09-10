"""Bounded parallel child scheduler for M8.5."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from khaos.subagents.contracts import (
    ParallelMetrics,
    SubagentAssignment,
    SubagentParallelismPolicy,
    SubagentResult,
    SubagentResultStatus,
    SubagentRole,
)


class SubagentBudgetExceeded(RuntimeError):
    """A child or aggregate scheduler budget was exhausted."""


class SubagentSchedulerError(RuntimeError):
    """A child could not be admitted or did not return a typed result."""


@dataclass(frozen=True, slots=True)
class ChildUsage:
    """Bounded usage counters supplied by the trusted execution adapter."""

    turns: int = 0
    tokens: int = 0
    tool_calls: int = 0
    storage_bytes: int = 0

    def __post_init__(self) -> None:
        for label in ("turns", "tokens", "tool_calls", "storage_bytes"):
            value = getattr(self, label)
            if type(value) is not int or value < 0:
                raise ValueError(f"{label} must be a non-negative integer")


class ChildBudget:
    """Per-child budget handle passed to an execution adapter."""

    def __init__(self, scheduler: BoundedParallelScheduler, assignment_id: str) -> None:
        self._scheduler = scheduler
        self.assignment_id = assignment_id
        self.usage = ChildUsage()

    async def charge(self, usage: ChildUsage) -> None:
        """Atomically charge child and aggregate limits before continuing."""
        policy = self._scheduler.policy
        candidate = ChildUsage(
            turns=self.usage.turns + usage.turns,
            tokens=self.usage.tokens + usage.tokens,
            tool_calls=self.usage.tool_calls + usage.tool_calls,
            storage_bytes=self.usage.storage_bytes + usage.storage_bytes,
        )
        if (
            candidate.turns > policy.max_child_turns
            or candidate.tokens > policy.max_child_tokens
            or candidate.tool_calls > policy.max_child_tool_calls
            or candidate.storage_bytes > policy.max_child_storage_bytes
        ):
            raise SubagentBudgetExceeded("child budget exceeded")
        async with self._scheduler._lock:
            if (
                self._scheduler._aggregate_tokens + usage.tokens
                > policy.max_aggregate_tokens
                or self._scheduler._aggregate_tool_calls + usage.tool_calls
                > policy.max_aggregate_tool_calls
            ):
                raise SubagentBudgetExceeded("aggregate child budget exceeded")
            self._scheduler._aggregate_tokens += usage.tokens
            self._scheduler._aggregate_tool_calls += usage.tool_calls
        self.usage = candidate


class BoundedParallelScheduler:
    """Run independent children with deterministic, fail-closed budgets."""

    def __init__(self, policy: SubagentParallelismPolicy | None = None) -> None:
        self.policy = policy or SubagentParallelismPolicy()
        self._lock = asyncio.Lock()
        self._capacity_changed = asyncio.Condition(self._lock)
        self._active: set[str] = set()
        self._active_mutating = 0
        self._active_research = 0
        self._aggregate_tokens = 0
        self._aggregate_tool_calls = 0
        self._completed = 0
        self._failed = 0
        self._cancelled = 0
        self._stale = 0
        self._conflict = 0
        self._quarantined = 0

    async def run(
        self,
        assignment: SubagentAssignment,
        worker: Callable[[ChildBudget], Awaitable[SubagentResult]],
    ) -> SubagentResult:
        """Admit and run one child; cancellation never leaks the worker."""
        await self._admit(assignment)
        budget = ChildBudget(self, assignment.assignment_id)
        worker_task = asyncio.create_task(
            worker(budget),
            name=f"khaos-m85-child:{assignment.assignment_id}",
        )
        try:
            result = await asyncio.wait_for(
                asyncio.shield(worker_task),
                timeout=self.policy.max_child_duration_seconds,
            )
            if type(result) is not SubagentResult:
                raise SubagentSchedulerError("child returned a non-typed result")
            self._record(result.status)
            return result
        except TimeoutError as exc:
            await self._cancel_worker(worker_task)
            self._record(SubagentResultStatus.FAILED)
            raise SubagentSchedulerError("child duration budget exceeded") from exc
        except asyncio.CancelledError:
            await self._cancel_worker(worker_task)
            self._record(SubagentResultStatus.CANCELLED)
            raise
        except SubagentBudgetExceeded:
            await self._cancel_worker(worker_task)
            self._record(SubagentResultStatus.FAILED)
            raise
        except BaseException:
            if not worker_task.done():
                await self._cancel_worker(worker_task)
            self._record(SubagentResultStatus.FAILED)
            raise
        finally:
            await self._release(assignment)

    async def _admit(self, assignment: SubagentAssignment) -> None:
        async with self._capacity_changed:
            if assignment.assignment_id in self._active:
                raise SubagentSchedulerError("assignment is already active")
            # Capacity is a scheduler queue, not a child failure.  Waiting here
            # gives callers a safe serial fallback when parallelism is capped;
            # only the immutable per-child/aggregate usage budgets fail closed.
            while (
                len(self._active) >= self.policy.max_active_children
                or (
                    assignment.mutating
                    and self._active_mutating >= self.policy.max_mutating_children
                )
                or (
                    assignment.role is SubagentRole.RESEARCH
                    and self._active_research >= self.policy.max_research_children
                )
            ):
                await self._capacity_changed.wait()
                if assignment.assignment_id in self._active:
                    raise SubagentSchedulerError("assignment is already active")
            self._active.add(assignment.assignment_id)
            if assignment.mutating:
                self._active_mutating += 1
            if assignment.role is SubagentRole.RESEARCH:
                self._active_research += 1

    async def _release(self, assignment: SubagentAssignment) -> None:
        async with self._capacity_changed:
            self._active.discard(assignment.assignment_id)
            if assignment.mutating:
                self._active_mutating = max(0, self._active_mutating - 1)
            if assignment.role is SubagentRole.RESEARCH:
                self._active_research = max(0, self._active_research - 1)
            self._capacity_changed.notify_all()

    @staticmethod
    async def _cancel_worker(worker_task: asyncio.Task[object]) -> None:
        """Cancel and drain the adapter task before releasing admission."""
        if worker_task.done():
            try:
                worker_task.result()
            except asyncio.CancelledError:
                return
            except Exception:  # noqa: BLE001 - worker result is already being discarded
                return
        worker_task.cancel()
        try:
            await asyncio.shield(worker_task)
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001 - cancellation drains any worker failure
            return

    def _record(self, status: SubagentResultStatus) -> None:
        if status is SubagentResultStatus.SUCCESS:
            self._completed += 1
        elif status is SubagentResultStatus.CANCELLED:
            self._cancelled += 1
        elif status is SubagentResultStatus.STALE:
            self._stale += 1
        elif status is SubagentResultStatus.CONFLICT:
            self._conflict += 1
        elif status is SubagentResultStatus.QUARANTINED:
            self._quarantined += 1
        else:
            self._failed += 1

    async def metrics(self) -> ParallelMetrics:
        """Return a snapshot for UI/telemetry; it is not control authority."""
        async with self._lock:
            return ParallelMetrics(
                active_children=len(self._active),
                mutating_children=self._active_mutating,
                research_children=self._active_research,
                completed_children=self._completed,
                failed_children=self._failed,
                cancelled_children=self._cancelled,
                stale_children=self._stale,
                conflict_children=self._conflict,
                quarantined_children=self._quarantined,
                aggregate_tokens=self._aggregate_tokens,
                aggregate_tool_calls=self._aggregate_tool_calls,
            )


__all__ = [
    "BoundedParallelScheduler",
    "ChildBudget",
    "ChildUsage",
    "SubagentBudgetExceeded",
    "SubagentSchedulerError",
]
