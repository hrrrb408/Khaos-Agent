"""Deterministic integration-worktree merge coordination for M8.5."""

from __future__ import annotations

import asyncio
import inspect
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.coding.verification.contracts import VerificationRunStatus
from khaos.coding.verification.evidence import VerificationRun
from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import (
    TaskWorkspace,
    WorkspaceState,
    WorkspaceTransition,
)
from khaos.security.protocol_boundary import canonical_digest
from khaos.subagents.contracts import (
    ChildWorkspaceState,
    MergeCandidate,
    MergeConflictKind,
    MergePlan,
    MergeResult,
    MergeResultStatus,
    PublicationAttestation,
    SubagentResultStatus,
    VerifiedIntegrationArtifact,
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


def _verification_passed(value: object, *, allow_test_double: bool = False) -> bool:
    """Accept only M8.3 typed proof on the production merge path.

    Mapping/bool callbacks remain available only for explicit unit-test
    doubles.  A model-controlled boolean or process prose can never become a
    trusted merge result.
    """
    if type(value) is VerificationRun:
        required_ids = {check.check_id for check in value.plan.required_checks}
        return (
            value.status is VerificationRunStatus.PASSED
            and value.required_checks_passed
            and all(
                item.status.value == "passed" and not item.output_truncated
                for item in value.evidence
                if item.check_id in required_ids
            )
        )
    if not allow_test_double:
        return False
    if type(value) is bool:
        return value
    if isinstance(value, Mapping):
        status = value.get("status")
        status_value = getattr(status, "value", status)
        return isinstance(status_value, str) and status_value.casefold() in {
            "passed",
            "success",
            "verified",
        }
    return False


@dataclass(frozen=True, slots=True)
class _PublishOutcome:
    """Observed effect of the shielded Parent publication."""

    head: str
    generation: int
    cancellation_requested: bool = False
    effect_uncertain: bool = False


class MergeCoordinator:
    """Plan and publish child artifacts without model-authored merge logic."""

    def __init__(
        self,
        workspace_manager: WorkspaceManager,
        *,
        repository: Any | None = None,
        post_merge_verifier: VerificationCallback | None = None,
        repo_intelligence_refresh: VerificationCallback | None = None,
        child_cleanup: VerificationCallback | None = None,
        allow_test_verifier: bool = False,
    ) -> None:
        self.workspace_manager = workspace_manager
        self.repository = repository
        self.post_merge_verifier = post_merge_verifier
        self.repo_intelligence_refresh = repo_intelligence_refresh
        self.child_cleanup = child_cleanup
        self.allow_test_verifier = allow_test_verifier
        self._parent_locks: dict[str, asyncio.Lock] = {}

    def set_child_cleanup(self, callback: VerificationCallback) -> None:
        """Bind the existing ChildWorkspaceService as the lifecycle owner."""
        if not callable(callback):
            raise TypeError("child cleanup callback must be callable")
        self.child_cleanup = callback

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
        ordered_candidates = tuple(
            sorted(
                candidates,
                key=lambda item: (item.assignment.priority, item.assignment_id),
            )
        )
        candidate_ids = tuple(sorted(candidate.assignment_id for candidate in candidates))
        ordered = tuple(candidate.assignment_id for candidate in ordered_candidates)
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
        candidate_bindings = tuple(candidate.binding for candidate in ordered_candidates)
        merge_identity = {
            "parent_task_id": parent_workspace.task_id,
            "parent_workspace_id": parent_workspace.id,
            "parent_base_commit": parent_head,
            "parent_generation": parent_generation,
            "parent_principal_id": parent_workspace.principal_id,
            "parent_project_id": parent_workspace.project_id,
            "candidate_bindings": tuple(
                binding.to_payload() for binding in candidate_bindings
            ),
            "ordered_candidate_ids": ordered,
            "conflicts": tuple(sorted(conflicts)),
            "expected_result": "publish-parent",
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
            parent_principal_id=parent_workspace.principal_id,
            parent_project_id=parent_workspace.project_id,
            candidate_bindings=candidate_bindings,
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
                "parent_principal_id": plan.parent_principal_id,
                "parent_project_id": plan.parent_project_id,
                "parent_generation": plan.parent_generation,
                "parent_base_commit": plan.parent_base_commit,
                "candidate_ids": plan.ordered_candidate_ids,
                "candidate_binding_digests": tuple(
                    binding.binding_digest for binding in plan.candidate_bindings
                ),
                "conflict_count": len(plan.conflicts),
                "plan_digest": plan.plan_digest,
            },
            merge_id=plan.merge_id,
        )
        for binding in plan.candidate_bindings:
            await self._event(
                "merge.candidate_bound",
                {
                    "merge_id": plan.merge_id,
                    "plan_digest": plan.plan_digest,
                    "assignment_id": binding.assignment_id,
                    "assignment_digest": binding.assignment_digest,
                    "result_digest": binding.result_digest,
                    "child_workspace_id": binding.child_workspace_id,
                    "child_final_commit": binding.child_final_commit,
                    "artifact_sha256": binding.changeset_artifact_sha256,
                    "artifact_length": binding.changeset_artifact_length,
                    "changed_paths": binding.changed_paths,
                    "verification_evidence_digest": binding.verification_evidence_digest,
                    "binding_digest": binding.binding_digest,
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
        if (
            plan.parent_task_id != parent_workspace.task_id
            or plan.parent_workspace_id != parent_workspace.id
            or (
                plan.parent_principal_id
                and plan.parent_principal_id != parent_workspace.principal_id
            )
            or (
                plan.parent_project_id
                and plan.parent_project_id != parent_workspace.project_id
            )
            or any(
                candidate.assignment.parent_task_id != parent_workspace.task_id
                or candidate.assignment.parent_workspace_id != parent_workspace.id
                or candidate.assignment.parent_principal_id
                != parent_workspace.principal_id
                or candidate.assignment.project_id != parent_workspace.project_id
                for candidate in candidates
            )
        ):
            return await self._terminal_result(
                plan,
                MergeResultStatus.REJECTED_STALE,
                reason="merge plan parent trust-domain binding does not match the supplied Parent",
                candidates=candidates,
            )
        candidate_by_id = {candidate.assignment_id: candidate for candidate in candidates}
        expected_ids = set(plan.candidate_ids)
        if len(candidate_by_id) != len(candidates) or set(candidate_by_id) != expected_ids:
            return await self._terminal_result(
                plan,
                MergeResultStatus.FAILED,
                reason="merge candidate set does not match the plan",
                candidates=candidates,
            )
        actual_bindings = tuple(
            candidate_by_id[assignment_id].binding
            for assignment_id in plan.ordered_candidate_ids
        )
        if actual_bindings != plan.candidate_bindings:
            return await self._terminal_result(
                plan,
                MergeResultStatus.REJECTED_STALE,
                reason="merge candidate binding drifted after planning",
                candidates=candidates,
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
                child_status = (
                    MergeResultStatus.REJECTED_STALE
                    if any(
                        conflict[0]
                        in {
                            MergeConflictKind.BASE_MISMATCH.value,
                            MergeConflictKind.CANDIDATE_DRIFT.value,
                        }
                        for conflict in child_conflicts
                    )
                    else MergeResultStatus.CONFLICT
                )
                return await self._terminal_result(
                    plan,
                    child_status,
                    reason="child workspace evidence does not match the merge candidate",
                    candidates=candidates,
                )

            integration: TaskWorkspace | None = None
            integration_changeset: Any | None = None
            verified_artifact: VerifiedIntegrationArtifact | None = None
            integration_storage_id = ""
            published_head: str | None = None
            published_generation: int | None = None
            publication_uncertain = False
            publication_started = False
            status = MergeResultStatus.FAILED
            reason = "merge did not complete"
            verification_status = "unknown"
            verification_digest = ""
            parent_verification_digest = ""
            cancelled = False
            cleanup_failed = False
            integration_cleanup_settled = False
            children_cleanup_attempted = False
            attestation: PublicationAttestation | None = None
            changed_paths = tuple(sorted({
                path
                for candidate in candidates
                for path in candidate.result.changed_paths
            }))
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
                    candidate_result = candidate_by_id[assignment_id].result
                    await self.workspace_manager.apply_verified_patch(
                        integration.id,
                        Path(candidate_result.changeset_artifact_path),
                        candidate_result.changeset_artifact_sha256,
                        candidate_result.changeset_artifact_length,
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
                if not _verification_passed(
                    verification,
                    allow_test_double=self.allow_test_verifier,
                ):
                    status = MergeResultStatus.VERIFICATION_FAILED
                    reason = "integration-worktree verification did not pass"
                else:
                    if integration_changeset.artifact is None:
                        raise WorkspaceError(
                            "integration verification requires a durable ChangeSet artifact"
                        )
                    integration_paths = tuple(
                        sorted(set(integration_changeset.changed_files))
                    )
                    if integration_paths != changed_paths:
                        raise WorkspaceError(
                            "integration ChangeSet paths do not match candidate bindings"
                        )
                    integration_tree = await self.workspace_manager.current_tree(
                        integration.id,
                        commit=integration_head,
                    )
                    await self._event(
                        "merge.integration_verified",
                        {
                            "merge_id": plan.merge_id,
                            "plan_digest": plan.plan_digest,
                            "verification_evidence_digest": verification_digest,
                            "verification_plan_digest": self._verification_plan_digest(
                                verification
                            ),
                            "integration_workspace_id": integration.id,
                            "integration_commit": integration_head,
                            "integration_tree_digest": integration_tree,
                            "changed_paths": changed_paths,
                        },
                        merge_id=plan.merge_id,
                    )
                    integration_storage_id = canonical_digest(
                        {
                            "merge_id": plan.merge_id,
                            "purpose": "verified-integration-artifact",
                        }
                    )
                    frozen = await self.workspace_manager.freeze_verified_changeset_artifact(
                        integration.id,
                        integration_changeset,
                        storage_id=integration_storage_id,
                    )
                    verified_artifact = VerifiedIntegrationArtifact(
                        merge_id=plan.merge_id,
                        merge_plan_digest=plan.plan_digest,
                        base_commit=plan.parent_base_commit,
                        resulting_tree=integration_tree,
                        changeset_sha256=frozen.sha256,
                        changeset_length=frozen.byte_length,
                        changed_paths=changed_paths,
                        verification_evidence_digest=verification_digest,
                        verification_plan_digest=self._verification_plan_digest(
                            verification
                        ),
                        artifact_storage_id=integration_storage_id,
                    )
                    await self._event(
                        "merge.integration_artifact_frozen",
                        {
                            "merge_id": plan.merge_id,
                            "plan_digest": plan.plan_digest,
                            "artifact_digest": verified_artifact.artifact_digest,
                            "artifact_storage_id": integration_storage_id,
                            "verification_evidence_digest": verification_digest,
                            "resulting_tree": integration_tree,
                            "artifact_sha256": verified_artifact.changeset_sha256,
                            "artifact_length": verified_artifact.changeset_length,
                            "changed_paths": verified_artifact.changed_paths,
                            "verification_plan_digest": (
                                verified_artifact.verification_plan_digest
                            ),
                        },
                        merge_id=plan.merge_id,
                    )

                    children_cleanup_attempted = True
                    children_clean, child_reason, child_cancelled = (
                        await self._cleanup_children(candidates)
                    )
                    cancelled = cancelled or child_cancelled
                    if not children_clean:
                        cleanup_failed = True
                        status = MergeResultStatus.QUARANTINED
                        reason = child_reason
                    elif cancelled:
                        status = MergeResultStatus.CANCELLED
                        reason = "merge was cancelled after child cleanup"
                    else:
                        transition, cleanup_cancelled = await self._drain_shielded(
                            self.workspace_manager.cleanup(integration.id, force=True),
                            operation="integration cleanup",
                        )
                        cancelled = cancelled or cleanup_cancelled
                        if transition is not WorkspaceTransition.UPDATED:
                            cleanup_failed = True
                            status = MergeResultStatus.QUARANTINED
                            reason = "integration cleanup was not proven before publish"
                        elif cancelled:
                            integration_cleanup_settled = True
                            status = MergeResultStatus.CANCELLED
                            reason = "merge was cancelled after integration cleanup"
                        else:
                            integration_cleanup_settled = True
                            stable_head, stable_generation = (
                                await self.workspace_manager.require_stable(
                                    parent_workspace.id,
                                    task_id=parent_workspace.task_id,
                                    expected_generation=plan.parent_generation,
                                )
                            )
                            if (
                                stable_head != plan.parent_base_commit
                                or stable_generation != plan.parent_generation
                            ):
                                status = MergeResultStatus.REJECTED_STALE
                                reason = "parent changed before the resource barrier"
                            else:
                                await self._event(
                                    "merge.resource_barrier_passed",
                                    {
                                        "merge_id": plan.merge_id,
                                        "plan_digest": plan.plan_digest,
                                        "candidate_binding_digests": tuple(
                                            binding.binding_digest
                                            for binding in plan.candidate_bindings
                                        ),
                                        "artifact_digest": verified_artifact.artifact_digest,
                                    },
                                    merge_id=plan.merge_id,
                                )
                                await self._event(
                                    "merge.parent_publish_started",
                                    {
                                        "merge_id": plan.merge_id,
                                        "plan_digest": plan.plan_digest,
                                        "artifact_digest": verified_artifact.artifact_digest,
                                        "artifact_storage_id": integration_storage_id,
                                        "expected_parent_head": plan.parent_base_commit,
                                        "expected_parent_generation": plan.parent_generation,
                                    },
                                    merge_id=plan.merge_id,
                                )
                                publication_started = True
                                publish = await self._publish_parent(
                                    parent_workspace,
                                    plan,
                                    verified_artifact,
                                )
                                published_head = publish.head
                                published_generation = publish.generation
                                cancelled = cancelled or publish.cancellation_requested
                                publication_uncertain = publish.effect_uncertain
                                await self._event(
                                    "merge.parent_published",
                                    {
                                        "merge_id": plan.merge_id,
                                        "plan_digest": plan.plan_digest,
                                        "published_head": published_head,
                                        "published_generation": published_generation,
                                        "artifact_digest": verified_artifact.artifact_digest,
                                    },
                                    merge_id=plan.merge_id,
                                )

                                parent_audit_passed = False
                                try:
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
                                    verification_status = self._verification_label(
                                        parent_verification
                                    )
                                    parent_verification_digest = self._verification_digest(
                                        parent_verification
                                    )
                                    parent_audit_passed = _verification_passed(
                                        parent_verification,
                                        allow_test_double=self.allow_test_verifier,
                                    )
                                except asyncio.CancelledError:
                                    raise
                                except Exception as exc:  # noqa: BLE001 - audit is fail-closed
                                    verification_status = "infrastructure_error"
                                    parent_verification_digest = canonical_digest(
                                        {
                                            "phase": "parent",
                                            "error": type(exc).__name__,
                                        }
                                    )
                                    reason = (
                                        "Parent consistency audit raised "
                                        f"{type(exc).__name__}"
                                    )

                                try:
                                    observed_head, observed_generation = (
                                        await self.workspace_manager.require_stable(
                                            parent_workspace.id,
                                            task_id=parent_workspace.task_id,
                                            expected_generation=published_generation,
                                        )
                                    )
                                    if observed_head != published_head:
                                        raise WorkspaceError(
                                            "Parent HEAD changed after publication"
                                        )
                                    parent_tree = await self.workspace_manager.current_tree(
                                        parent_workspace.id,
                                        commit=observed_head,
                                    )
                                    attestation = self._build_publication_attestation(
                                        plan,
                                        parent_workspace,
                                        integration,
                                        verified_artifact,
                                        integration_head,
                                        observed_head,
                                        observed_generation,
                                        parent_tree,
                                    )
                                except (WorkspaceError, PermissionError, OSError) as exc:
                                    status = MergeResultStatus.PUBLISHED_QUARANTINED
                                    reason = f"publication attestation failed: {exc}"
                                else:
                                    await self._event(
                                        "merge.publication_attested",
                                        {
                                            "merge_id": plan.merge_id,
                                            "plan_digest": plan.plan_digest,
                                            "attestation_digest": attestation.attestation_digest,
                                            "artifact_digest": verified_artifact.artifact_digest,
                                            "parent_generation": attestation.parent_generation,
                                            "parent_commit": attestation.parent_commit,
                                            "parent_tree_digest": attestation.parent_tree_digest,
                                        },
                                        merge_id=plan.merge_id,
                                    )
                                    if not parent_audit_passed:
                                        status = MergeResultStatus.PUBLISHED_UNVERIFIED
                                        reason = (
                                            reason
                                            if reason != "merge did not complete"
                                            else "published with a failed Parent consistency audit"
                                        )
                                    elif cancelled or publication_uncertain:
                                        status = MergeResultStatus.PUBLISHED_UNVERIFIED
                                        reason = (
                                            "published before cancellation was observed"
                                            if cancelled
                                            else "Parent publication effect was observed after an interrupted commit"
                                        )
                                    else:
                                        try:
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
                                        except asyncio.CancelledError:
                                            raise
                                        except Exception as exc:  # noqa: BLE001 - refresh is post-publish evidence
                                            status = MergeResultStatus.PUBLISHED_UNVERIFIED
                                            reason = (
                                                "published but repository intelligence refresh "
                                                f"failed: {type(exc).__name__}"
                                            )
                                        else:
                                            status = MergeResultStatus.PUBLISHED
                                            reason = (
                                                "published after the pre-publication integration "
                                                "verification and exact-tree attestation"
                                            )
            except (WorkspaceError, PermissionError, OSError) as exc:
                reason = str(exc)
                if published_head is not None:
                    status = MergeResultStatus.PUBLISHED_UNVERIFIED
                    reason = f"Parent publication observed before failure: {reason}"
                elif any(
                    marker in reason.casefold()
                    for marker in (
                        "parent",
                        "generation",
                        "head changed",
                        "stale",
                        "content changed",
                    )
                ):
                    status = MergeResultStatus.REJECTED_STALE
                elif "apply" in reason.casefold() or "patch" in reason.casefold():
                    status = MergeResultStatus.CONFLICT
            except asyncio.CancelledError:
                reason = "merge was cancelled"
                status = (
                    MergeResultStatus.PUBLISHED_UNVERIFIED
                    if published_head is not None
                    else MergeResultStatus.CANCELLED
                )
                cancelled = True
            except Exception as exc:  # noqa: BLE001 - merge is fail-closed
                reason = f"merge coordinator failed: {type(exc).__name__}"
                status = (
                    MergeResultStatus.PUBLISHED_UNVERIFIED
                    if published_head is not None
                    else MergeResultStatus.FAILED
                )
            finally:
                if not children_cleanup_attempted:
                    children_cleanup_attempted = True
                    try:
                        children_clean, child_reason, child_cancelled = (
                            await self._cleanup_children(candidates)
                        )
                        cancelled = cancelled or child_cancelled
                        if not children_clean:
                            cleanup_failed = True
                            reason = child_reason
                    except Exception as exc:  # noqa: BLE001 - retain cleanup ownership
                        cleanup_failed = True
                        reason = f"child cleanup failed: {type(exc).__name__}"
                if integration is not None and not integration_cleanup_settled:
                    try:
                        transition, cleanup_cancelled = await self._drain_shielded(
                            self.workspace_manager.cleanup(integration.id, force=True),
                            operation="integration cleanup",
                        )
                        cancelled = cancelled or cleanup_cancelled
                        if transition is WorkspaceTransition.UPDATED:
                            integration_cleanup_settled = True
                        else:
                            cleanup_failed = True
                            reason = "integration Worktree cleanup is quarantined"
                    except Exception as exc:  # noqa: BLE001 - retain cleanup ownership
                        cleanup_failed = True
                        reason = f"integration cleanup failed: {type(exc).__name__}"
                if integration_storage_id:
                    try:
                        released = await self.workspace_manager.release_verified_artifact(
                            integration_storage_id
                        )
                        if released is not WorkspaceTransition.UPDATED:
                            cleanup_failed = True
                            reason = "verified integration artifact cleanup is quarantined"
                    except Exception as exc:  # noqa: BLE001 - retain cleanup ownership
                        cleanup_failed = True
                        reason = f"verified artifact cleanup failed: {type(exc).__name__}"
                if cleanup_failed:
                    status = (
                        MergeResultStatus.PUBLISHED_QUARANTINED
                        if published_head is not None
                        else MergeResultStatus.QUARANTINED
                    )
                elif publication_started and published_head is None:
                    try:
                        observed_head = await self.workspace_manager.current_head(
                            parent_workspace.id
                        )
                        if observed_head == plan.parent_base_commit:
                            observed_workspace = self.workspace_manager.get(
                                parent_workspace.id
                            )
                            if (
                                observed_workspace is None
                                or observed_workspace.generation
                                != plan.parent_generation
                            ):
                                raise WorkspaceError(
                                    "Parent generation changed during an incomplete publication"
                                )
                            await self.workspace_manager.require_stable(
                                parent_workspace.id,
                                task_id=parent_workspace.task_id,
                                expected_generation=plan.parent_generation,
                            )
                    except (WorkspaceError, PermissionError, OSError):
                        status = MergeResultStatus.QUARANTINED
                        reason = (
                            "Parent publication left an uncommitted or otherwise "
                            "unresolved mutation; recovery is required"
                        )
                elif published_head is None and cancelled:
                    status = MergeResultStatus.CANCELLED
                    reason = reason or "merge was cancelled before publication"
                elif published_head is not None and cancelled and status is MergeResultStatus.PUBLISHED:
                    status = MergeResultStatus.PUBLISHED_UNVERIFIED
                    reason = "published before cancellation was observed"
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
                plan_digest=plan.plan_digest,
                candidate_binding_digests=tuple(
                    binding.binding_digest for binding in plan.candidate_bindings
                ),
                verified_integration_artifact_digest=(
                    verified_artifact.artifact_digest
                    if verified_artifact is not None
                    else ""
                ),
                publication_attestation_digest=(
                    attestation.attestation_digest if attestation is not None else ""
                ),
                parent_verification_evidence_digest=parent_verification_digest,
                reason=reason,
            )
            await self._record_result(result)
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
        artifact: VerifiedIntegrationArtifact,
    ) -> _PublishOutcome:
        """Apply/commit the final integration artifact under the parent fence."""
        if (
            artifact.merge_id != plan.merge_id
            or artifact.merge_plan_digest != plan.plan_digest
            or artifact.base_commit != plan.parent_base_commit
            or not artifact.artifact_storage_id
        ):
            raise WorkspaceError("verified integration artifact is not bound to this plan")
        frozen = await self.workspace_manager.get_verified_artifact(
            artifact.artifact_storage_id
        )
        if (
            frozen.sha256 != artifact.changeset_sha256
            or frozen.byte_length != artifact.changeset_length
        ):
            raise WorkspaceError("verified integration artifact metadata drifted")
        try:
            published, cancellation_requested = await self._drain_shielded(
                self._publish_parent_unshielded(
                    parent_workspace,
                    plan,
                    frozen.path,
                    frozen.sha256,
                    frozen.byte_length,
                ),
                operation="Parent publication",
            )
        except Exception as exc:
            # A trusted Git effect can have crossed the ref CAS immediately
            # before an observation/cleanup exception.  Re-observe the Parent
            # before classifying the outcome; never turn an unknown effect
            # into an ordinary unpublished failure.
            try:
                observed_head = await self.workspace_manager.current_head(
                    parent_workspace.id
                )
                observed_workspace = self.workspace_manager.get(parent_workspace.id)
                if observed_workspace is None:
                    raise WorkspaceError("Parent workspace disappeared during publication")
                observed_generation = observed_workspace.generation
                observed_tree = await self.workspace_manager.current_tree(
                    parent_workspace.id,
                    commit=observed_head,
                )
            except (WorkspaceError, PermissionError, OSError) as observe_exc:
                raise WorkspaceError(
                    "Parent publication effect could not be observed"
                ) from observe_exc
            if (
                observed_head != plan.parent_base_commit
                or observed_generation != plan.parent_generation
            ):
                if observed_tree == artifact.resulting_tree:
                    return _PublishOutcome(
                        head=observed_head,
                        generation=observed_generation,
                        effect_uncertain=True,
                    )
                raise WorkspaceError("parent changed before controlled publish") from exc
            raise
        if type(published) is not str:
            raise WorkspaceError("Parent publication did not return a commit")
        return _PublishOutcome(
            head=published,
            generation=parent_workspace.generation,
            cancellation_requested=cancellation_requested,
        )

    async def _publish_parent_unshielded(
        self,
        parent_workspace: TaskWorkspace,
        plan: MergePlan,
        artifact_path: Path,
        artifact_sha256: str,
        artifact_length: int,
    ) -> str:
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
            return await self.workspace_manager.commit_current_changeset(
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

    async def _drain_shielded(
        self,
        awaitable: Awaitable[object],
        *,
        operation: str,
    ) -> tuple[object, bool]:
        """Drain an owned effect and separately report caller cancellation."""
        task = asyncio.ensure_future(awaitable)
        cancellation_requested = False
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                cancellation_requested = True
        try:
            return task.result(), cancellation_requested
        except asyncio.CancelledError as exc:
            raise WorkspaceError(
                f"{operation} was cancelled before terminal completion"
            ) from exc

    async def _cleanup_children(
        self,
        candidates: tuple[MergeCandidate, ...],
    ) -> tuple[bool, str, bool]:
        """Run the child lifecycle owner before the Parent publication fence."""
        if not candidates:
            return True, "", False
        if self.child_cleanup is None:
            return False, "child cleanup owner is not bound", False
        failures: list[str] = []
        cancellation_requested = False
        for candidate in sorted(candidates, key=lambda item: item.assignment_id):
            try:
                value = self.child_cleanup(
                    candidate.assignment,
                    result_status=SubagentResultStatus.SUCCESS,
                )
                if inspect.isawaitable(value):
                    value, was_cancelled = await self._drain_shielded(
                        value,
                        operation=f"child cleanup {candidate.assignment_id}",
                    )
                    cancellation_requested = cancellation_requested or was_cancelled
                state = getattr(value, "state", None)
                transition = getattr(value, "transition", None)
                state_value = getattr(state, "value", state)
                transition_value = getattr(transition, "value", transition)
                if state_value != ChildWorkspaceState.CLEANED.value or transition_value not in {
                    WorkspaceTransition.UPDATED.value,
                    WorkspaceTransition.NOT_FOUND.value,
                }:
                    failures.append(candidate.assignment_id)
            except Exception as exc:  # noqa: BLE001 - cleanup is fail-closed
                failures.append(f"{candidate.assignment_id}:{type(exc).__name__}")
        if failures:
            return (
                False,
                "child cleanup barrier failed for " + ", ".join(failures),
                cancellation_requested,
            )
        return True, "", cancellation_requested

    @staticmethod
    def _build_publication_attestation(
        plan: MergePlan,
        parent_workspace: TaskWorkspace,
        integration: TaskWorkspace,
        artifact: VerifiedIntegrationArtifact,
        integration_commit: str,
        parent_commit: str,
        parent_generation: int,
        parent_tree: str,
    ) -> PublicationAttestation:
        """Construct only after the live Parent tree has been re-observed."""
        expected_paths = tuple(
            sorted(
                {
                    path
                    for binding in plan.candidate_bindings
                    for path in binding.changed_paths
                }
            )
        )
        if artifact.merge_plan_digest != plan.plan_digest:
            raise WorkspaceError("verified artifact plan digest drifted")
        if artifact.base_commit != plan.parent_base_commit:
            raise WorkspaceError("verified artifact base commit drifted")
        if artifact.changed_paths != expected_paths:
            raise WorkspaceError("verified artifact changed paths drifted")
        if artifact.resulting_tree != parent_tree:
            raise WorkspaceError("Parent tree differs from the verified integration tree")
        return PublicationAttestation(
            merge_id=plan.merge_id,
            integration_workspace_id=integration.id,
            integration_generation=integration.generation,
            integration_commit=integration_commit,
            integration_tree_digest=artifact.resulting_tree,
            parent_workspace_id=parent_workspace.id,
            parent_generation=parent_generation,
            parent_commit=parent_commit,
            parent_tree_digest=parent_tree,
            source_verification_evidence_digest=artifact.verification_evidence_digest,
            merge_plan_digest=plan.plan_digest,
            verification_plan_digest=artifact.verification_plan_digest,
            changed_paths=artifact.changed_paths,
            parent_task_id=parent_workspace.task_id,
            project_id=parent_workspace.project_id,
        )

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
        if type(value) is VerificationRun:
            return value.result_digest
        if isinstance(value, Mapping):
            digest = value.get("evidence_digest", "")
        else:
            digest = getattr(value, "evidence_digest", "")
        if type(digest) is str and len(digest) == 64:
            return digest
        return canonical_digest({"verification": str(value)[:2048]})

    @staticmethod
    def _verification_plan_digest(value: object) -> str:
        if type(value) is VerificationRun:
            return value.plan.plan_digest
        if isinstance(value, Mapping):
            digest = value.get("plan_digest", "")
            if type(digest) is str and len(digest) == 64:
                return digest
        return ""

    async def _terminal_result(
        self,
        plan: MergePlan,
        status: MergeResultStatus,
        *,
        reason: str,
        candidates: tuple[MergeCandidate, ...] = (),
    ) -> MergeResult:
        if self.child_cleanup is not None and candidates:
            try:
                children_clean, child_reason, _ = await self._cleanup_children(candidates)
            except Exception as exc:  # noqa: BLE001 - cleanup is fail-closed
                children_clean = False
                child_reason = f"child cleanup failed: {type(exc).__name__}"
            if not children_clean:
                status = MergeResultStatus.QUARANTINED
                reason = child_reason
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
            plan_digest=plan.plan_digest,
            candidate_binding_digests=tuple(
                binding.binding_digest for binding in plan.candidate_bindings
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
        elif result.status in {
            MergeResultStatus.PUBLISHED_UNVERIFIED,
            MergeResultStatus.PUBLISHED_QUARANTINED,
        }:
            event_type = "merge_published_unverified"
        elif result.status is MergeResultStatus.QUARANTINED:
            event_type = "merge_quarantined"
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
        if result.status in {
            MergeResultStatus.QUARANTINED,
            MergeResultStatus.PUBLISHED_QUARANTINED,
        }:
            await self._event(
                "merge.quarantined",
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
