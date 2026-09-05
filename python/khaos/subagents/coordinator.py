"""Parent-side orchestration for bounded parallel coding children."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import replace
from typing import Any

from khaos.coding.workspace.models import TaskWorkspace
from khaos.subagents.contracts import (
    MAX_CONTEXT_ITEMS,
    ChildWorkspaceBinding,
    ChildWorkspaceState,
    ContextTransferItem,
    ContextTransferPackage,
    MergeCandidate,
    MergePlan,
    MergeResult,
    ParallelSubagentContractError,
    SubagentAssignment,
    SubagentResult,
    SubagentResultStatus,
    validate_assignment_plan,
)
from khaos.subagents.merge import MergeCoordinator
from khaos.subagents.scheduler import (
    BoundedParallelScheduler,
    ChildBudget,
    SubagentBudgetExceeded,
    SubagentSchedulerError,
)
from khaos.subagents.workspace import ChildWorkspaceService

ChildWorker = Callable[
    [SubagentAssignment, ChildWorkspaceBinding, TaskWorkspace, ChildBudget],
    Awaitable[SubagentResult],
]


class SubagentCoordinator:
    """Coordinate independent children while keeping Parent authority local."""

    def __init__(
        self,
        workspace_service: ChildWorkspaceService,
        *,
        scheduler: BoundedParallelScheduler | None = None,
        merge_coordinator: MergeCoordinator | None = None,
        repository: Any | None = None,
    ) -> None:
        self.workspace_service = workspace_service
        self.scheduler = scheduler or BoundedParallelScheduler()
        self.merge_coordinator = merge_coordinator
        self.repository = repository
        self._results: dict[str, SubagentResult] = {}
        self._contexts: dict[str, ContextTransferPackage] = {}
        if self.merge_coordinator is not None:
            # MergeCoordinator owns the pre-publication resource barrier.  The
            # child service remains the sole lifecycle writer for child state.
            self.merge_coordinator.set_child_cleanup(workspace_service.cleanup)

    async def run_parallel(
        self,
        parent_workspace: TaskWorkspace,
        assignments: tuple[SubagentAssignment, ...],
        worker: ChildWorker,
    ) -> tuple[SubagentResult, ...]:
        """Run a validated assignment set and cleanup every child worktree."""
        if not callable(worker):
            raise TypeError("worker must be callable")
        validate_assignment_plan(assignments)
        self._validate_parent_bindings(parent_workspace, assignments)
        for assignment in assignments:
            if self.repository is not None:
                await self.repository.record_assignment(assignment)
                await self.repository.append_event(
                    event_type="assignment_created",
                    payload={
                        "assignment_id": assignment.assignment_id,
                        "assignment_digest": assignment.assignment_digest,
                        "parent_workspace_id": assignment.parent_workspace_id,
                        "base_generation": assignment.base_generation,
                        "base_commit": assignment.base_commit,
                    },
                    assignment_id=assignment.assignment_id,
                )
            self._contexts[assignment.assignment_id] = self._context_package(assignment)

        tasks: dict[str, asyncio.Task[SubagentResult]] = {}
        for assignment in assignments:
            tasks[assignment.assignment_id] = asyncio.create_task(
                self._run_after_dependencies(
                    parent_workspace,
                    assignment,
                    worker,
                    tasks,
                ),
                name=f"khaos-m85-coordinate:{assignment.assignment_id}",
            )
        results: list[SubagentResult] = []
        try:
            results = list(await asyncio.gather(*tasks.values()))
        except asyncio.CancelledError:
            for task in tasks.values():
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)
            raise
        return tuple(sorted(results, key=lambda item: item.assignment_id))

    @staticmethod
    def _validate_parent_bindings(
        parent_workspace: TaskWorkspace,
        assignments: tuple[SubagentAssignment, ...],
    ) -> None:
        """Reject an assignment set before any child Worktree is admitted."""
        parent_head = getattr(parent_workspace, "head_sha", None) or parent_workspace.base_sha
        for assignment in assignments:
            if (
                assignment.parent_task_id != parent_workspace.task_id
                or assignment.parent_workspace_id != parent_workspace.id
                or assignment.parent_principal_id != parent_workspace.principal_id
                or assignment.project_id != parent_workspace.project_id
                or assignment.base_generation != parent_workspace.generation
                or assignment.base_commit != parent_head
            ):
                raise ParallelSubagentContractError(
                    "assignment is not bound to the current parent workspace snapshot"
                )

    async def _run_after_dependencies(
        self,
        parent_workspace: TaskWorkspace,
        assignment: SubagentAssignment,
        worker: ChildWorker,
        tasks: dict[str, asyncio.Task[SubagentResult]],
    ) -> SubagentResult:
        """Wait for simple dependencies without becoming a general DAG engine."""
        for dependency in assignment.dependencies:
            dependency_result = await tasks[dependency]
            if dependency_result.status is not SubagentResultStatus.SUCCESS:
                result = self._failure_result(
                    assignment,
                    None,
                    error_code="dependency_not_satisfied",
                    summary=f"dependency {dependency} did not complete successfully",
                )
                await self._record_result(result)
                return result
        return await self._run_one(parent_workspace, assignment, worker)

    async def _run_one(
        self,
        parent_workspace: TaskWorkspace,
        assignment: SubagentAssignment,
        worker: ChildWorker,
    ) -> SubagentResult:
        binding: ChildWorkspaceBinding | None = None
        child: TaskWorkspace | None = None
        result: SubagentResult | None = None
        try:
            binding, child = await self.workspace_service.create(assignment, parent_workspace)
            if self.repository is not None:
                await self.repository.update_child_state(
                    assignment.assignment_id,
                    ChildWorkspaceState.RUNNING,
                )
                await self.repository.append_event(
                    event_type="child_started",
                    payload={
                        "assignment_id": assignment.assignment_id,
                        "child_workspace_id": child.id,
                        "child_principal_id": assignment.child_principal_id,
                        "base_generation": assignment.base_generation,
                        "base_commit": assignment.base_commit,
                    },
                    assignment_id=assignment.assignment_id,
                )

            async def execute(budget: ChildBudget) -> SubagentResult:
                return await worker(assignment, binding, child, budget)

            result = await self.scheduler.run(assignment, execute)
            result.validate_against(assignment)
        except SubagentBudgetExceeded as exc:
            result = self._failure_result(
                assignment,
                child,
                error_code="budget_exceeded",
                summary=str(exc),
            )
        except SubagentSchedulerError as exc:
            result = self._failure_result(
                assignment,
                child,
                error_code="scheduler_rejected",
                summary=str(exc),
            )
        except asyncio.CancelledError:
            result = self._failure_result(
                assignment,
                child,
                status=SubagentResultStatus.CANCELLED,
                error_code="cancelled",
                summary="child execution was cancelled",
            )
        except Exception as exc:  # noqa: BLE001 - child failures are typed results
            result = self._failure_result(
                assignment,
                child,
                error_code="child_execution_failed",
                summary=str(exc),
            )
        finally:
            if result is None:
                result = self._failure_result(
                    assignment,
                    child,
                    error_code="child_execution_unknown",
                    summary="child execution ended without a typed result",
                )
            if binding is not None:
                try:
                    await self.workspace_service.mark_result(
                        assignment,
                        result.status,
                    )
                except Exception as exc:  # noqa: BLE001 - lifecycle persistence is fail-closed
                    result = replace(
                        result,
                        status=SubagentResultStatus.QUARANTINED,
                        error_code="child_state_persistence_failed",
                        summary=f"child terminal state could not be persisted: {type(exc).__name__}",
                    )
            retain_child = (
                binding is not None
                and assignment.mutating
                and result.status is SubagentResultStatus.SUCCESS
            )
            if binding is not None and not retain_child:
                cleanup = await self.workspace_service.cleanup(
                    assignment,
                    result_status=result.status,
                )
                if cleanup.state is ChildWorkspaceState.QUARANTINED:
                    result = replace(
                        result,
                        status=SubagentResultStatus.QUARANTINED,
                        error_code="child_worktree_quarantined",
                        summary=cleanup.reason or "child Worktree cleanup was not proven",
                    )
            if self.repository is not None:
                await self.repository.record_result(result)
                await self.repository.append_event(
                    event_type=(
                        "child_completed"
                        if result.status is SubagentResultStatus.SUCCESS
                        else "child_failed"
                    ),
                    payload={
                        "assignment_id": assignment.assignment_id,
                        "child_workspace_id": result.child_workspace_id,
                        "status": result.status.value,
                        "result_digest": result.result_digest,
                        "changed_paths": result.changed_paths,
                        "verification_status": result.verification_status,
                    },
                    assignment_id=assignment.assignment_id,
                )
            self._results[assignment.assignment_id] = result
        return result

    async def _record_result(self, result: SubagentResult) -> None:
        """Persist a dependency-skipped result through the same result port."""
        if self.repository is None:
            self._results[result.assignment_id] = result
            return
        await self.repository.record_result(result)
        await self.repository.append_event(
            event_type="child_failed",
            payload={
                "assignment_id": result.assignment_id,
                "status": result.status.value,
                "result_digest": result.result_digest,
                "error_code": result.error_code,
            },
            assignment_id=result.assignment_id,
        )
        self._results[result.assignment_id] = result

    @staticmethod
    def _failure_result(
        assignment: SubagentAssignment,
        child: TaskWorkspace | None,
        *,
        status: SubagentResultStatus = SubagentResultStatus.FAILED,
        error_code: str,
        summary: str,
    ) -> SubagentResult:
        child_workspace_id = child.id if child is not None else "uncreated"
        return SubagentResult(
            assignment_id=assignment.assignment_id,
            parent_task_id=assignment.parent_task_id,
            parent_workspace_id=assignment.parent_workspace_id,
            status=status,
            base_generation=assignment.base_generation,
            base_commit=assignment.base_commit,
            child_workspace_id=child_workspace_id,
            verification_status="not-run",
            error_code=error_code,
            summary=summary[:4096],
        )

    @staticmethod
    def _context_package(assignment: SubagentAssignment) -> ContextTransferPackage:
        context = assignment.context
        if context is None:
            items: tuple[ContextTransferItem, ...] = ()
        else:
            items_list: list[ContextTransferItem] = [
                ContextTransferItem("objective", "parent.assignment", context.objective),
            ]
            for kind, source, values in (
                ("constraint", "parent.constraint", context.constraints),
                ("instruction", "parent.instruction", context.instructions),
                ("diagnostic", "parent.diagnostic", context.diagnostics),
                ("decision", "parent.decision", context.decisions),
                ("path", "parent.selected-path", context.selected_paths),
                ("symbol", "parent.selected-symbol", context.selected_symbols),
            ):
                items_list.extend(ContextTransferItem(kind, source, value) for value in values)
            items = tuple(items_list[:MAX_CONTEXT_ITEMS])
        return ContextTransferPackage(
            assignment_id=assignment.assignment_id,
            parent_task_id=assignment.parent_task_id,
            base_generation=assignment.base_generation,
            base_commit=assignment.base_commit,
            items=items,
        )

    def result_for(self, assignment_id: str) -> SubagentResult | None:
        """Return a bounded result projection for one assignment."""
        return self._results.get(assignment_id)

    def context_for(self, assignment_id: str) -> ContextTransferPackage | None:
        """Return the selected context package, never a parent transcript."""
        return self._contexts.get(assignment_id)

    async def merge(
        self,
        parent_workspace: TaskWorkspace,
        assignments: tuple[SubagentAssignment, ...],
    ) -> tuple[MergePlan, MergeResult]:
        """Plan and execute a merge for successful mutating children only."""
        if self.merge_coordinator is None:
            raise RuntimeError("merge coordinator is not configured")
        candidates = tuple(
            MergeCandidate(assignment, self._results[assignment.assignment_id])
            for assignment in assignments
            if assignment.mutating
            and assignment.assignment_id in self._results
            and self._results[assignment.assignment_id].status is SubagentResultStatus.SUCCESS
        )
        plan = await self.merge_coordinator.plan(parent_workspace, candidates)
        result = await self.merge_coordinator.merge(parent_workspace, plan, candidates)
        return plan, result

    async def cleanup(self, assignments: tuple[SubagentAssignment, ...]) -> None:
        """Explicitly retire retained successful children when no merge follows."""
        for assignment in assignments:
            if assignment.assignment_id not in self._results or not assignment.mutating:
                continue
            await self.workspace_service.cleanup(
                assignment,
                result_status=self._results[assignment.assignment_id].status,
            )


__all__ = ["ChildWorker", "SubagentCoordinator"]
