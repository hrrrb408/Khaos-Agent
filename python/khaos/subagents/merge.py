"""Deterministic integration-worktree merge coordination for M8.5."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import Any

from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import (
    TaskWorkspace,
    WorkspaceState,
    WorkspaceTransition,
)
from khaos.security.protocol_boundary import canonical_digest
from khaos.subagents.contracts import (
    MergeCandidate,
    MergeConflictKind,
    MergePlan,
    MergeResult,
    MergeResultStatus,
)

VerificationCallback = Callable[..., Awaitable[object] | object]


def _path_overlap(left: str, right: str) -> bool:
    left_normalized = left.casefold()
    right_normalized = right.casefold()
    return (
        left_normalized == right_normalized
        or left_normalized.startswith(f"{right_normalized}/")
        or right_normalized.startswith(f"{left_normalized}/")
    )


def _verification_passed(value: object) -> bool:
    if type(value) is bool:
        return value
    if isinstance(value, Mapping):
        value = value.get("status")
    status = getattr(value, "status", value)
    status_value = getattr(status, "value", status)
    return isinstance(status_value, str) and status_value.casefold() in {
        "passed",
        "success",
        "verified",
    }


class MergeCoordinator:
    """Plan and publish child artifacts without model-authored merge logic."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        *,
        repository: Any | None = None,
        post_merge_verifier: VerificationCallback | None = None,
        repo_intelligence_refresh: VerificationCallback | None = None,
    ) -> None:
        self.workspace_manager = workspace_manager
        self.repository = repository
        self.post_merge_verifier = post_merge_verifier
        self.repo_intelligence_refresh = repo_intelligence_refresh
        self._parent_locks: dict[str, asyncio.Lock] = {}

    async def plan(
        self,
        parent_workspace: TaskWorkspace,
        candidates: tuple[MergeCandidate, ...],
    ) -> MergePlan:
        """Create a digest-bound deterministic plan after fresh parent checks."""
        if type(candidates) is not tuple:
            raise TypeError("merge candidates must be an immutable tuple")
        parent_head, parent_generation = await self.workspace_manager.require_stable(
            parent_workspace.id,
            task_id=parent_workspace.task_id,
            expected_generation=parent_workspace.generation,
        )
        candidate_ids = tuple(candidate.assignment_id for candidate in candidates)
        ordered = tuple(
            candidate.assignment_id
            for candidate in sorted(
                candidates,
                key=lambda item: (item.assignment.priority, item.assignment_id),
            )
        )
        conflicts: set[tuple[str, str, str]] = set()
        for candidate in candidates:
            result = candidate.result
            if (
                result.parent_task_id != parent_workspace.task_id
                or result.parent_workspace_id != parent_workspace.id
            ):
                conflicts.add(
                    (
                        MergeConflictKind.ASSIGNMENT_MISMATCH.value,
                        candidate.assignment_id,
                        parent_workspace.id,
                    )
                )
            if result.base_generation != parent_generation or result.base_commit != parent_head:
                conflicts.add(
                    (
                        MergeConflictKind.BASE_MISMATCH.value,
                        candidate.assignment_id,
                        parent_head,
                    )
                )
            if not result.changeset_artifact_path:
                conflicts.add(
                    (
                        MergeConflictKind.ARTIFACT_MISSING.value,
                        candidate.assignment_id,
                        candidate.assignment_id,
                    )
                )
        for index, left in enumerate(candidates):
            for right in candidates[index + 1 :]:
                if any(
                    _path_overlap(left_path, right_path)
                    for left_path in left.result.changed_paths
                    for right_path in right.result.changed_paths
                ):
                    conflicts.add(
                        (
                            MergeConflictKind.PATH_OVERLAP.value,
                            left.assignment_id,
                            right.assignment_id,
                        )
                    )
                if set(left.assignment.allowed_symbols) & set(right.assignment.allowed_symbols):
                    conflicts.add(
                        (
                            MergeConflictKind.SYMBOL_OVERLAP.value,
                            left.assignment_id,
                            right.assignment_id,
                        )
                    )
        merge_identity = {
            "parent": parent_workspace.id,
            "head": parent_head,
            "generation": parent_generation,
            "candidates": ordered,
        }
        merge_id = f"m85-{canonical_digest(merge_identity)[:32]}"
        plan = MergePlan(
            merge_id=merge_id,
            parent_task_id=parent_workspace.task_id,
            parent_workspace_id=parent_workspace.id,
            parent_generation=parent_generation,
            parent_base_commit=parent_head,
            candidate_ids=candidate_ids,
            ordered_candidate_ids=ordered,
            conflicts=tuple(sorted(conflicts)),
        )
        if self.repository is not None:
            await self.repository.record_merge_plan(plan)
        await self._event(
            "merge.plan_created",
            {
                "merge_id": plan.merge_id,
                "parent_task_id": plan.parent_task_id,
                "parent_workspace_id": plan.parent_workspace_id,
                "parent_generation": plan.parent_generation,
                "parent_base_commit": plan.parent_base_commit,
                "candidate_ids": plan.ordered_candidate_ids,
                "conflict_count": len(plan.conflicts),
                "plan_digest": plan.plan_digest,
            },
            merge_id=plan.merge_id,
        )
        return plan

    async def create_plan(
        self,
        parent_workspace: TaskWorkspace,
        candidates: tuple[MergeCandidate, ...],
    ) -> MergePlan:
        """Descriptive alias used by callers that prefer an explicit name."""
        return await self.plan(parent_workspace, candidates)

    async def merge(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        candidates: tuple[MergeCandidate, ...],
    ) -> MergeResult:
        """Integrate, verify, and publish a previously planned candidate set."""
        if type(plan) is not MergePlan or type(candidates) is not tuple:
            raise TypeError("merge requires a MergePlan and immutable candidates")
        candidate_by_id = {candidate.assignment_id: candidate for candidate in candidates}
        expected_ids = set(plan.candidate_ids)
        if set(candidate_by_id) != expected_ids:
            return await self._terminal_result(
                plan,
                MergeResultStatus.FAILED,
                reason="merge candidate set does not match the plan",
            )
        if plan.conflicts:
            return await self._terminal_result(
                plan,
                MergeResultStatus.CONFLICT,
                reason="deterministic merge conflict analysis rejected the plan",
                candidates=candidates,
            )
        lock = self._parent_locks.setdefault(parent_workspace.id, asyncio.Lock())
        async with lock:
            try:
                current_head, current_generation = await self.workspace_manager.require_stable(
                    parent_workspace.id,
                    task_id=parent_workspace.task_id,
                    expected_generation=plan.parent_generation,
                )
            except (WorkspaceError, PermissionError) as exc:
                return await self._terminal_result(
                    plan,
                    MergeResultStatus.REJECTED_STALE,
                    reason=str(exc),
                    candidates=candidates,
                )
            if current_head != plan.parent_base_commit or current_generation != plan.parent_generation:
                return await self._terminal_result(
                    plan,
                    MergeResultStatus.REJECTED_STALE,
                    reason="parent generation or HEAD changed after planning",
                    candidates=candidates,
                )
            child_conflicts = await self._validate_child_candidates(
                parent_workspace,
                plan,
                candidates,
            )
            if child_conflicts:
                return await self._terminal_result(
                    plan,
                    MergeResultStatus.CONFLICT,
                    reason="child workspace evidence does not match the merge candidate",
                    candidates=candidates,
                )

            integration: TaskWorkspace | None = None
            published_head: str | None = None
            published_generation: int | None = None
            status = MergeResultStatus.FAILED
            reason = "merge did not complete"
            verification_status = "unknown"
            verification_digest = ""
            cancelled = False
            changed_paths = tuple(
                sorted({path for candidate in candidates for path in candidate.result.changed_paths})
            )
            try:
                integration = await self.workspace_manager.create(
                    parent_workspace.repository_root,
                    f"m85-merge-{plan.plan_digest[:32]}",
                    base_ref=plan.parent_base_commit,
                    principal_id=f"merge:{parent_workspace.principal_id}:{plan.merge_id}",
                    project_id=parent_workspace.project_id,
                    creator_runtime_id=f"merge-runtime:{plan.merge_id}",
                )
                await self.workspace_manager.transition(integration.id, WorkspaceState.RUNNING)
                first = True
                for assignment_id in plan.ordered_candidate_ids:
                    result = candidate_by_id[assignment_id].result
                    await self.workspace_manager.apply_verified_patch(
                        integration.id,
                        Path(result.changeset_artifact_path),
                        result.changeset_artifact_sha256,
                        result.changeset_artifact_length,
                        expected_head=plan.parent_base_commit if first else None,
                        require_clean=first,
                    )
                    first = False
                integration_changeset = await self.workspace_manager.build_changeset(
                    integration.id,
                    base_sha=plan.parent_base_commit,
                )
                integration_head = await self.workspace_manager.commit_in_worktree(
                    integration.id,
                    integration_changeset,
                    f"Khaos M8.5 integration {plan.merge_id}",
                )
                verification = await self._verify(
                    phase="integration",
                    workspace=integration,
                    task_id=integration.task_id,
                    merge_id=plan.merge_id,
                    changed_paths=changed_paths,
                    base_generation=integration.generation,
                    resulting_generation=integration.generation,
                    base_commit=plan.parent_base_commit,
                    resulting_commit=integration_head,
                    principal_id=integration.principal_id,
                    project_id=integration.project_id,
                )
                verification_status = self._verification_label(verification)
                verification_digest = self._verification_digest(verification)
                if not _verification_passed(verification):
                    status = MergeResultStatus.VERIFICATION_FAILED
                    reason = "integration-worktree verification did not pass"
                else:
                    await self._publish_parent(
                        parent_workspace,
                        plan,
                        integration_changeset,
                    )
                    published_head = await self.workspace_manager.current_head(parent_workspace.id)
                    published_generation = parent_workspace.generation
                    parent_verification = await self._verify(
                        phase="parent",
                        workspace=parent_workspace,
                        task_id=parent_workspace.task_id,
                        merge_id=plan.merge_id,
                        changed_paths=changed_paths,
                        base_generation=plan.parent_generation,
                        resulting_generation=published_generation,
                        base_commit=plan.parent_base_commit,
                        resulting_commit=published_head,
                        principal_id=parent_workspace.principal_id,
                        project_id=parent_workspace.project_id,
                    )
                    verification_status = self._verification_label(parent_verification)
                    verification_digest = self._verification_digest(parent_verification)
                    if not _verification_passed(parent_verification):
                        status = MergeResultStatus.VERIFICATION_FAILED
                        reason = "post-merge parent verification did not pass"
                    else:
                        if self.repo_intelligence_refresh is not None:
                            refreshed = self.repo_intelligence_refresh(
                                phase="parent",
                                workspace=parent_workspace,
                                task_id=parent_workspace.task_id,
                                merge_id=plan.merge_id,
                                generation=published_generation,
                                commit=published_head,
                                changed_paths=changed_paths,
                            )
                            if inspect.isawaitable(refreshed):
                                await refreshed
                        status = MergeResultStatus.PUBLISHED
                        reason = "published after integration and parent verification"
            except (WorkspaceError, PermissionError, OSError) as exc:
                reason = str(exc)
                if "apply" in reason.casefold() or "patch" in reason.casefold():
                    status = MergeResultStatus.CONFLICT
            except asyncio.CancelledError:
                reason = "merge was cancelled"
                status = MergeResultStatus.CANCELLED
                cancelled = True
            except Exception as exc:  # noqa: BLE001 - merge is fail-closed
                reason = f"merge coordinator failed: {type(exc).__name__}"
                status = MergeResultStatus.FAILED
            finally:
                if integration is not None:
                    transition = await asyncio.shield(
                        self.workspace_manager.cleanup(integration.id, force=True)
                    )
                    if transition is not WorkspaceTransition.UPDATED:
                        status = MergeResultStatus.QUARANTINED
                        reason = "integration Worktree cleanup is quarantined"
            result = MergeResult(
                merge_id=plan.merge_id,
                status=status,
                parent_task_id=plan.parent_task_id,
                parent_workspace_id=plan.parent_workspace_id,
                expected_parent_head=plan.parent_base_commit,
                expected_parent_generation=plan.parent_generation,
                candidate_ids=plan.ordered_candidate_ids,
                published_head=published_head,
                published_generation=published_generation,
                verification_status=verification_status,
                verification_evidence_digest=verification_digest,
                changed_paths=changed_paths,
                reason=reason,
            )
            await self._record_result(result)
            if cancelled:
                # The integration Worktree and durable result are now settled;
                # returning the typed cancellation keeps the parent caller
                # from mistaking an interrupted merge for an unobserved task.
                return result
            return result

    async def execute(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        candidates: tuple[MergeCandidate, ...],
    ) -> MergeResult:
        """Explicit alias for the merge execution phase."""
        return await self.merge(parent_workspace, plan, candidates)

    async def _publish_parent(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        integration_changeset: Any,
    ) -> None:
        """Apply/commit the final integration artifact under the parent fence."""
        artifact = integration_changeset.artifact
        if artifact is None:
            raise WorkspaceError("integration changeset has no artifact")
        publish_task = asyncio.create_task(
            self._publish_parent_unshielded(
                parent_workspace,
                plan,
                artifact.path,
                artifact.sha256,
                artifact.byte_length,
            ),
            name=f"khaos-m85-publish:{plan.merge_id}",
        )
        try:
            await asyncio.shield(publish_task)
        except asyncio.CancelledError:
            while not publish_task.done():
                try:
                    await asyncio.shield(publish_task)
                except asyncio.CancelledError:
                    continue
            raise

    async def _publish_parent_unshielded(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        artifact_path: Path,
        artifact_sha256: str,
        artifact_length: int,
    ) -> None:
        async with self.workspace_manager.workspace_storage_scope(
            parent_workspace.id,
            parent_workspace.task_id,
        ):
            current_head = await self.workspace_manager.current_head(parent_workspace.id)
            if current_head != plan.parent_base_commit or parent_workspace.generation != plan.parent_generation:
                raise WorkspaceError("parent changed before controlled publish")
            await self.workspace_manager.apply_verified_patch(
                parent_workspace.id,
                artifact_path,
                artifact_sha256,
                artifact_length,
                expected_head=plan.parent_base_commit,
                require_clean=True,
            )
            parent_changeset = await self.workspace_manager.build_changeset(
                parent_workspace.id,
                base_sha=plan.parent_base_commit,
            )
            await self.workspace_manager.commit_current_changeset(
                parent_workspace.id,
                parent_changeset,
                f"Khaos M8.5 publish {plan.merge_id}",
                expected_head=plan.parent_base_commit,
                expected_generation=plan.parent_generation,
            )

    async def _validate_child_candidates(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        candidates: tuple[MergeCandidate, ...],
    ) -> tuple[tuple[str, str, str], ...]:
        """Bind every candidate to live Child-owned state before applying it."""
        conflicts: set[tuple[str, str, str]] = set()
        parent_root = parent_workspace.worktree_path.resolve(strict=False)
        for candidate in candidates:
            assignment = candidate.assignment
            result = candidate.result
            child = self.workspace_manager.get(result.child_workspace_id)
            if child is None:
                conflicts.add(
                    (
                        MergeConflictKind.ASSIGNMENT_MISMATCH.value,
                        assignment.assignment_id,
                        "missing-child-workspace",
                    )
                )
                continue
            expected_task_id = f"m85-child-{assignment.assignment_digest[:32]}"
            child_root = child.worktree_path.resolve(strict=False)
            if (
                child.task_id != expected_task_id
                or child.principal_id != assignment.child_principal_id
                or child.project_id != assignment.project_id
                or child.creator_runtime_id != assignment.child_runtime_id
                or child.base_sha != plan.parent_base_commit
                or child_root == parent_root
                or parent_root in child_root.parents
                or child_root in parent_root.parents
                or child.state in {
                    WorkspaceState.CLEANING,
                    WorkspaceState.CLEANED,
                    WorkspaceState.CANCELLED,
                }
            ):
                conflicts.add(
                    (
                        MergeConflictKind.ASSIGNMENT_MISMATCH.value,
                        assignment.assignment_id,
                        result.child_workspace_id,
                    )
                )
                continue
            try:
                actual_head = await self.workspace_manager.current_head(child.id)
                artifact_files = self.workspace_manager.changeset_artifact_files(
                    child.id,
                    Path(result.changeset_artifact_path),
                )
            except (WorkspaceError, OSError):
                conflicts.add(
                    (
                        MergeConflictKind.ARTIFACT_MISSING.value,
                        assignment.assignment_id,
                        result.child_workspace_id,
                    )
                )
                continue
            if actual_head != result.child_final_commit:
                conflicts.add(
                    (
                        MergeConflictKind.BASE_MISMATCH.value,
                        assignment.assignment_id,
                        actual_head,
                    )
                )
            if tuple(sorted(set(artifact_files))) != result.changed_paths:
                conflicts.add(
                    (
                        MergeConflictKind.ASSIGNMENT_MISMATCH.value,
                        assignment.assignment_id,
                        "artifact-paths",
                    )
                )
        return tuple(sorted(conflicts))

    async def _verify(self, **kwargs: object) -> object:
        if self.post_merge_verifier is None:
            return {"status": "unknown", "reason": "post_merge_verifier is not configured"}
        value = self.post_merge_verifier(**kwargs)
        if inspect.isawaitable(value):
            return await value
        return value

    @staticmethod
    def _verification_label(value: object) -> str:
        if isinstance(value, Mapping):
            raw = value.get("status", "unknown")
        else:
            raw = getattr(value, "status", value)
        return str(getattr(raw, "value", raw))[:128]

    @staticmethod
    def _verification_digest(value: object) -> str:
        if isinstance(value, Mapping):
            digest = value.get("evidence_digest", "")
        else:
            digest = getattr(value, "evidence_digest", "")
        if type(digest) is str and len(digest) == 64:
            return digest
        return canonical_digest({"verification": str(value)[:2048]})

    async def _terminal_result(
        self,
        plan: MergePlan,
        status: MergeResultStatus,
        *,
        reason: str,
        candidates: tuple[MergeCandidate, ...] = (),
    ) -> MergeResult:
        result = MergeResult(
            merge_id=plan.merge_id,
            status=status,
            parent_task_id=plan.parent_task_id,
            parent_workspace_id=plan.parent_workspace_id,
            expected_parent_head=plan.parent_base_commit,
            expected_parent_generation=plan.parent_generation,
            candidate_ids=plan.ordered_candidate_ids,
            changed_paths=tuple(
                sorted({path for candidate in candidates for path in candidate.result.changed_paths})
            ),
            reason=reason,
        )
        await self._record_result(result)
        return result

    async def _record_result(self, result: MergeResult) -> None:
        if self.repository is not None:
            await self.repository.record_merge_result(result)
        await self._event(
            "merge.completed",
            {
                "merge_id": result.merge_id,
                "status": result.status.value,
                "parent_workspace_id": result.parent_workspace_id,
                "published_head": result.published_head,
                "published_generation": result.published_generation,
                "verification_status": result.verification_status,
                "result_digest": result.result_digest,
            },
            merge_id=result.merge_id,
        )
        if result.status is MergeResultStatus.PUBLISHED:
            event_type = "merge_published"
        elif result.status is MergeResultStatus.CONFLICT:
            event_type = "merge_conflict"
        else:
            event_type = "merge_failed"
        await self._event(
            event_type,
            {
                "merge_id": result.merge_id,
                "status": result.status.value,
                "reason": result.reason,
                "result_digest": result.result_digest,
            },
            merge_id=result.merge_id,
        )

    async def _event(
        self,
        event_type: str,
        payload: Mapping[str, object],
        *,
        merge_id: str | None = None,
    ) -> None:
        if self.repository is None:
            return
        await self.repository.append_event(
            event_type=event_type,
            payload=payload,
            merge_id=merge_id,
        )


__all__ = ["MergeCoordinator"]
