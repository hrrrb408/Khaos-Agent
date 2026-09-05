"""Isolated child TaskWorkspace lifecycle for M8.5."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceTransition
from khaos.subagents.contracts import (
    ChildWorkspaceBinding,
    ChildWorkspaceState,
    SubagentAssignment,
    SubagentResultStatus,
)


@dataclass(frozen=True, slots=True)
class ChildCleanupResult:
    """Result of one idempotent child-workspace cleanup attempt."""

    assignment_id: str
    state: ChildWorkspaceState
    transition: WorkspaceTransition
    reason: str = ""


class ChildWorkspaceService:
    """Create and retire child worktrees without exposing the parent path."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        *,
        repository: Any | None = None,
    ) -> None:
        self.workspace_manager = workspace_manager
        self.repository = repository
        self._bindings: dict[str, ChildWorkspaceBinding] = {}
        self._cleanup_locks: dict[str, asyncio.Lock] = {}

    @staticmethod
    def _terminal_state(result_status: SubagentResultStatus) -> ChildWorkspaceState:
        return {
            SubagentResultStatus.SUCCESS: ChildWorkspaceState.SUCCESS,
            SubagentResultStatus.FAILED: ChildWorkspaceState.FAILED,
            SubagentResultStatus.CANCELLED: ChildWorkspaceState.CANCELLED,
            SubagentResultStatus.STALE: ChildWorkspaceState.STALE,
            SubagentResultStatus.CONFLICT: ChildWorkspaceState.CONFLICT,
            SubagentResultStatus.QUARANTINED: ChildWorkspaceState.QUARANTINED,
        }[result_status]

    def binding_for(self, assignment_id: str) -> ChildWorkspaceBinding | None:
        """Return an in-process binding without granting filesystem access."""
        return self._bindings.get(assignment_id)

    async def create(
        self,
        assignment: SubagentAssignment,
        parent_workspace: TaskWorkspace,
    ) -> tuple[ChildWorkspaceBinding, TaskWorkspace]:
        """Create one child worktree from a stable parent snapshot.

        The parent is checked under WorkspaceManager's storage fence before
        the child is bootstrapped.  A mutating assignment therefore cannot
        begin from dirty, in-flight, or generation-stale parent state.
        """
        if type(assignment) is not SubagentAssignment:
            raise TypeError("assignment must be a SubagentAssignment")
        if type(parent_workspace) is not TaskWorkspace:
            raise TypeError("parent_workspace must be a TaskWorkspace")
        if parent_workspace.id != assignment.parent_workspace_id:
            raise WorkspaceError("assignment and parent workspace are mismatched")
        if parent_workspace.task_id != assignment.parent_task_id:
            raise WorkspaceError("assignment and parent task are mismatched")
        if parent_workspace.principal_id != assignment.parent_principal_id:
            raise WorkspaceError("assignment parent principal is mismatched")
        if parent_workspace.project_id != assignment.project_id:
            raise WorkspaceError("assignment project is mismatched")
        if not assignment.base_commit:
            raise WorkspaceError("mutating assignment has no base commit")
        existing = self._bindings.get(assignment.assignment_id)
        if existing is not None:
            if existing.base_commit != assignment.base_commit or existing.binding_digest == "":
                raise WorkspaceError("duplicate assignment has a different child binding")
            child = self.workspace_manager.get(existing.child_workspace_id)
            if child is None:
                raise WorkspaceError("durable child binding has no active workspace")
            return existing, child

        child_task_id = f"m85-child-{assignment.assignment_digest[:32]}"
        try:
            # Keep the parent storage fence held through Git worktree creation.
            # A point-in-time stability check followed by an unfenced bootstrap
            # would allow a concurrent Parent edit to race the child base.
            async with self.workspace_manager.stable_workspace_scope(
                parent_workspace.id,
                task_id=parent_workspace.task_id,
                expected_generation=assignment.base_generation,
            ) as snapshot:
                current_head, generation, _ = snapshot
                if (
                    current_head != assignment.base_commit
                    or generation != assignment.base_generation
                ):
                    raise WorkspaceError("parent snapshot is stale before child creation")
                child = await self.workspace_manager.create(
                    parent_workspace.repository_root,
                    child_task_id,
                    base_ref=assignment.base_commit,
                    principal_id=assignment.child_principal_id,
                    project_id=assignment.project_id,
                    creator_runtime_id=assignment.child_runtime_id,
                )
            if child.base_sha != assignment.base_commit:
                raise WorkspaceError("child Worktree was created from the wrong commit")
            binding = ChildWorkspaceBinding(
                assignment_id=assignment.assignment_id,
                parent_task_id=assignment.parent_task_id,
                parent_workspace_id=assignment.parent_workspace_id,
                child_task_id=child.task_id,
                child_workspace_id=child.id,
                child_worktree_path=str(child.worktree_path),
                child_branch=child.branch_name,
                child_principal_id=assignment.child_principal_id,
                child_runtime_id=assignment.child_runtime_id,
                base_generation=assignment.base_generation,
                base_commit=assignment.base_commit,
            )
            self._bindings[assignment.assignment_id] = binding
            try:
                if self.repository is not None:
                    await self.repository.record_binding(assignment, binding)
            except BaseException:
                self._bindings.pop(assignment.assignment_id, None)
                raise
            return binding, child
        except BaseException:
            # A child bootstrap failure must not turn into a leaked worktree.
            # Cleanup is shielded by WorkspaceManager itself and retained as
            # quarantine when the Git owner cannot prove terminal removal.
            if "child" in locals():
                transition = await asyncio.shield(
                    self.workspace_manager.cleanup(child.id, force=True)
                )
                if transition is not WorkspaceTransition.UPDATED:
                    raise WorkspaceError("child Worktree cleanup was quarantined")
            raise

    async def cleanup(
        self,
        assignment: SubagentAssignment,
        *,
        result_status: SubagentResultStatus,
    ) -> ChildCleanupResult:
        """Cleanup a child and retain ownership when proof of removal fails."""
        binding = self._bindings.get(assignment.assignment_id)
        if binding is None:
            return ChildCleanupResult(
                assignment_id=assignment.assignment_id,
                state=ChildWorkspaceState.CLEANED,
                transition=WorkspaceTransition.NOT_FOUND,
                reason="child binding is already absent",
            )
        lock = self._cleanup_locks.setdefault(assignment.assignment_id, asyncio.Lock())
        async with lock:
            current = self.workspace_manager.get(binding.child_workspace_id)
            if current is None:
                state = ChildWorkspaceState.CLEANED
                transition = WorkspaceTransition.NOT_FOUND
            else:
                transition = await asyncio.shield(
                    self.workspace_manager.cleanup(binding.child_workspace_id, force=True)
                )
                if transition is WorkspaceTransition.UPDATED:
                    state = ChildWorkspaceState.CLEANED
                else:
                    state = ChildWorkspaceState.QUARANTINED
            if self.repository is not None:
                terminal_state = self._terminal_state(result_status)
                stored_state = await self.repository.child_state(assignment.assignment_id)
                if (
                    stored_state is ChildWorkspaceState.CLEANED
                    and state is ChildWorkspaceState.QUARANTINED
                ):
                    raise WorkspaceError(
                        "durable child is marked cleaned but Worktree cleanup is not proven"
                    )
                if state is ChildWorkspaceState.CLEANED:
                    if stored_state in {
                        ChildWorkspaceState.UNKNOWN,
                        ChildWorkspaceState.QUARANTINED,
                    }:
                        await self.repository.update_child_state(
                            assignment.assignment_id,
                            ChildWorkspaceState.CLEANED,
                            result_status=result_status,
                        )
                    elif stored_state is not ChildWorkspaceState.CLEANED:
                        terminal_states = {
                            ChildWorkspaceState.SUCCESS,
                            ChildWorkspaceState.FAILED,
                            ChildWorkspaceState.CANCELLED,
                            ChildWorkspaceState.STALE,
                            ChildWorkspaceState.CONFLICT,
                        }
                        if stored_state not in terminal_states:
                            await self.repository.update_child_state(
                                assignment.assignment_id,
                                terminal_state,
                                result_status=result_status,
                            )
                        await self.repository.update_child_state(
                            assignment.assignment_id,
                            ChildWorkspaceState.CLEANED,
                            result_status=result_status,
                        )
                elif stored_state is not ChildWorkspaceState.QUARANTINED:
                    await self.repository.update_child_state(
                        assignment.assignment_id,
                        state,
                        result_status=result_status,
                        reason="cleanup failed" if state is ChildWorkspaceState.QUARANTINED else "",
                    )
                await self.repository.append_event(
                    event_type="child_cleaned",
                    payload={
                        "assignment_id": assignment.assignment_id,
                        "child_workspace_id": binding.child_workspace_id,
                        "state": state.value,
                        "result_status": result_status.value,
                    },
                    assignment_id=assignment.assignment_id,
                )
            return ChildCleanupResult(
                assignment_id=assignment.assignment_id,
                state=state,
                transition=transition,
                reason="cleanup failed" if state is ChildWorkspaceState.QUARANTINED else "",
            )

    async def mark_result(
        self,
        assignment: SubagentAssignment,
        result_status: SubagentResultStatus,
    ) -> None:
        """Persist a terminal child result before optional Worktree retention."""
        if self.repository is None or assignment.assignment_id not in self._bindings:
            return
        await self.repository.update_child_state(
            assignment.assignment_id,
            self._terminal_state(result_status),
            result_status=result_status,
        )

    def assert_child_path(self, assignment_id: str, path: Path) -> None:
        """Reject path use outside the server-created child Worktree."""
        binding = self._bindings.get(assignment_id)
        if binding is None:
            raise WorkspaceError("child binding is unavailable")
        candidate = path.expanduser().absolute()
        root = Path(binding.child_worktree_path).resolve(strict=True)
        try:
            candidate.resolve(strict=False).relative_to(root)
        except ValueError as exc:
            raise WorkspaceError("child path escapes the isolated Worktree") from exc

    def assert_mutation_allowed(self, assignment: SubagentAssignment) -> None:
        """Enforce the assignment access mode at the child tool boundary."""
        if not assignment.mutating:
            raise PermissionError("read-only child cannot request mutating tools")


__all__ = ["ChildCleanupResult", "ChildWorkspaceService"]
