"""Crash-safe, path-scoped mutation engine for isolated Task Workspaces."""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import threading
import time
import unicodedata
import uuid
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from khaos.coding.planning.approval.models import compute_plan_binding_digest
from khaos.coding.planning.contracts import PlanOperation, PlanStatus
from khaos.coding.planning.execution_models import (
    AttestedPathState,
    ExecutionRunStatus,
    FinalMutationAttestation,
    InitialApprovedEdit,
    InitialPathState,
    InitialWorkspaceAttestation,
    MutationSealTombstone,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
    RollbackFinalAttestation,
    ValidatedRecoveryEvent,
    ValidatedRecoveryJournal,
    WorkspaceMutationResult,
)
from khaos.coding.workspace.models import WorkspaceState
from khaos.coding.planning.safe_workspace_path import (
    SafePathError,
    MutationObjectIdentity,
    WorkspacePathHandle,
)
from khaos.coding.planning.git_state import GitStateInspector
from khaos.coding.planning.recovery_directory import (
    RecoveryDirectory,
    RecoveryDirectoryError,
    RecoveryRootCapability,
)
from khaos.coding.planning.safe_identifiers import (
    SafeRecoveryArtifactName, SafeRecoveryRunId, SafeWorkspaceRelativePath,
    UnsafePersistedIdentifier,
)

MAX_BUNDLE_FILES = 64
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")


class WorkspaceMutationError(RuntimeError):
    """Structured fail-closed planned mutation error."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _resolve_avp_digest(store: Any, context: Any) -> str:
    """Batch 3.1.5 §2: resolve the approved verification plan digest bound to
    the execution's approval request, so the binding digest re-computation
    embeds the same snapshot digest that was frozen at approval time.

    Returns empty string when no request is bound (test paths without a
    configured VerificationSnapshotProvider) — matching the empty digest used
    at request creation time so the binding still matches.
    """
    approval_request_id = ""
    authorization = getattr(context, "authorization", None)
    if authorization is not None:
        approval_request_id = getattr(authorization, "approval_request_id", "") or ""
    if not approval_request_id:
        return ""
    try:
        request = store.get_request(approval_request_id)
    except Exception:
        return ""
    if request is None:
        return ""
    return getattr(request, "approved_verification_plan_digest", "") or ""


class WorkspaceMutationEngine:
    """The sole Batch 3 entry for structured isolated-workspace edits."""

    def __init__(
        self, *, store: Any, plan_repository: Any, workspace_manager: Any,
        context_provider: Any, guard: Any, mutation_fence: Any,
        runtime_capability: Any, call_authority: object,
    ) -> None:
        from khaos.coding.planning.approval.runtime import _consume_runtime_capability

        try:
            self._boot = _consume_runtime_capability(
                runtime_capability, "mutation-engine"
            )
        except PermissionError as exc:
            raise TypeError(
                "WorkspaceMutationEngine requires ApprovalRuntime authority"
            ) from exc
        self._store = store
        self._plans = plan_repository
        self._workspaces = workspace_manager
        self._context_provider = context_provider
        self._guard = guard
        self._fence = mutation_fence
        self.__call_authority = call_authority
        self._session_lock = threading.Lock()
        self._active_path_handle: WorkspacePathHandle | None = None
        self._active_phase: Any = None
        self._active_recovery: RecoveryDirectory | None = None
        self._git_inspector = GitStateInspector()
        self._recovery_capabilities: dict[str, RecoveryRootCapability] = {}

    def apply_bundle(
        self, *, context: Any, bundle: PlannedEditBundle,
        _call_authority: object | None = None,
    ) -> WorkspaceMutationResult:
        """Validate, journal and atomically apply a structured edit bundle."""
        if _call_authority is not self.__call_authority:
            raise PermissionError(
                "WorkspaceMutationEngine is callable only through PlannedExecutionGuard"
            )
        if not self._session_lock.acquire(blocking=False):
            raise WorkspaceMutationError(
                "mutation-session-busy", "another mutation session is active"
            )
        try:
            return self._apply_bundle_locked(context=context, bundle=bundle)
        finally:
            self._session_lock.release()

    def _apply_bundle_locked(
        self, *, context: Any, bundle: PlannedEditBundle
    ) -> WorkspaceMutationResult:
        """Implementation protected by the engine's single-session lock."""
        self._guard.require_active_execution_context(context)
        normalized = bundle.normalized()
        existing = self._store.get_execution_run_by_context(
            context.execution_context_id
        )
        if existing is not None:
            if existing.edit_bundle_digest != normalized.content_digest:
                raise WorkspaceMutationError(
                    "context-bundle-conflict",
                    "execution context is already bound to another bundle",
                )
            return WorkspaceMutationResult(
                existing.execution_run_id, existing.status,
                existing.edit_bundle_digest, (), existing.failure_code, True,
            )

        plan, workspace = self._validate_scope(context, normalized)
        initial_storage_violation = self._storage_violation(workspace)
        if initial_storage_violation is not None:
            raise WorkspaceMutationError(
                str(initial_storage_violation["kind"]),
                "TaskWorkspace storage authority rejected initial state",
            )
        now = time.time()
        run = PlanExecutionRun(
            execution_run_id=f"per_{uuid.uuid4().hex}",
            plan_id=plan.plan_id, plan_content_hash=plan.content_hash,
            approval_request_id=context.authorization.approval_request_id,
            authorization_id=context.authorization_id,
            execution_context_id=context.execution_context_id,
            lease_id=context.lease_id, task_id=context.task_id,
            workspace_id=context.workspace_id, repository_id=context.repository_id,
            base_sha=plan.base_sha, repository_generation=plan.repository_generation,
            binding_digest=context.binding_digest,
            edit_bundle_digest=normalized.content_digest,
            status=ExecutionRunStatus.CREATED, started_at=now, updated_at=now,
            metadata={"edit_count": len(normalized.ordered_edits)},
        )
        run = self._store.create_execution_run(run)
        if run.edit_bundle_digest != normalized.content_digest:
            raise WorkspaceMutationError(
                "authorization-run-conflict", "authorization already has another run"
            )
        self._store.transition_execution_run(
            run.execution_run_id, expected=("created",), target="validating"
        )

        root = workspace.worktree_path.resolve(strict=True)
        before_git = self._git_inspector.snapshot(
            workspace, repository_generation=plan.repository_generation
        )
        stable_git = self._git_inspector.snapshot(
            workspace, repository_generation=plan.repository_generation
        )
        if stable_git != before_git:
            raise WorkspaceMutationError("initial-state-unstable", "initial workspace snapshot drifted")
        initial = self._build_initial_attestation(
            run, context, normalized, before_git,
        )
        self._store.save_initial_workspace_attestation(initial)
        recovery: RecoveryDirectory | None = None
        changed: list[str] = []
        path_handle = WorkspacePathHandle(root)
        self._active_path_handle = path_handle
        try:
            recovery = self._prepare_recovery(workspace, run.execution_run_id)
            self._active_recovery = recovery
            self._store.transition_execution_run(
                run.execution_run_id, expected=("validating",), target="mutating"
            )
            for ordinal, edit in enumerate(normalized.ordered_edits):
                try:
                    self._guard.require_active_execution_context(context)
                except PermissionError as exc:
                    raise WorkspaceMutationError(
                        "execution-context-invalid",
                        "execution was cancelled, expired, or revoked",
                    ) from exc
                state = self._context_provider.current_state(
                    repository_id=context.repository_id, task_id=context.task_id,
                    workspace_id=context.workspace_id,
                )
                if (state.repository_generation != plan.repository_generation
                        or state.head_sha != plan.base_sha):
                    raise WorkspaceMutationError(
                        "live-state-drift", "HEAD or repository generation drifted"
                    )
                self._resolve_safe_path(workspace, edit.path)
                if edit.destination_path:
                    self._resolve_safe_path(workspace, edit.destination_path)
                backup, original_mode = self._journal_edit(
                    run.execution_run_id, ordinal, edit, root, recovery
                )
                self._store.update_edit_event(
                    run.execution_run_id, edit.edit_id,
                    status="mutation-started",
                )
                self._active_phase = (
                    lambda phase, identity=None, run_id=run.execution_run_id,
                    current_edit=edit: self._record_mutation_phase(
                        run_id, current_edit, phase, identity,
                    )
                )
                self._apply_edit(edit, root)
                changed.extend(
                    path for path in (edit.path, edit.destination_path) if path
                )
                after_hash, after_mode, _ = self._current_target(
                    path_handle, edit.destination_path or edit.path
                )
                self._store.update_edit_event(
                    run.execution_run_id, edit.edit_id, status="applied",
                    after_hash=after_hash or "", after_mode=after_mode,
                )

            storage_violation = self._storage_violation(workspace)
            if storage_violation is not None:
                raise WorkspaceMutationError(
                    str(storage_violation["kind"]),
                    "planned mutation exceeded TaskWorkspace storage authority",
                )

            self._guard.require_active_execution_context(context)
            final_state = self._context_provider.current_state(
                repository_id=context.repository_id, task_id=context.task_id,
                workspace_id=context.workspace_id,
            )
            after_git = self._git_inspector.snapshot(
                workspace,
                repository_generation=final_state.repository_generation,
            )
            final_state_after_snapshot = self._context_provider.current_state(
                repository_id=context.repository_id, task_id=context.task_id,
                workspace_id=context.workspace_id,
            )
            if (after_git.head_commit != before_git.head_commit
                    or after_git.head_commit != plan.base_sha):
                raise WorkspaceMutationError("final-head-drift", "HEAD changed during mutation")
            if (final_state.repository_generation != plan.repository_generation
                    or final_state_after_snapshot.repository_generation
                    != plan.repository_generation
                    or after_git.repository_generation != plan.repository_generation):
                raise WorkspaceMutationError(
                    "final-generation-drift", "repository generation changed"
                )
            if after_git.index_digest != before_git.index_digest:
                raise WorkspaceMutationError("staged-index-drift", "Git index changed")
            if after_git.worktree_admin_identity != before_git.worktree_admin_identity:
                raise WorkspaceMutationError("worktree-admin-drift", "worktree admin changed")
            unexpected = self._unexpected_changes(
                self._git_state_map(before_git), self._git_state_map(after_git),
                frozenset(changed)
            )
            if unexpected:
                raise WorkspaceMutationError(
                    "unexpected-workspace-mutation",
                    "workspace changed outside the declared bundle",
                )
            attestation = self._build_final_attestation(
                run, context, normalized, workspace, path_handle, after_git,
            )
            self._store.save_final_mutation_attestation(attestation)
            self._store.transition_execution_run(
                run.execution_run_id, expected=("mutating",), target="sealing",
            )
            journal = self._validated_journal(run)
            journal_digest = journal.canonical_digest
            self._validate_sealing_recovery(
                run, workspace, journal.events,
                journal_digest,
            )
            self._seal_recovery(recovery, workspace.id, run.execution_run_id)
            tombstone_name, tombstone = self._write_seal_tombstone(
                recovery, run, "mutation", attestation.attestation_digest,
                journal_digest,
            )
            self._store.commit_terminal_seal(
                run.execution_run_id, expected_status="sealing",
                terminal_status="mutated",
                seal_digest=self._recovery_seal_digest(run.execution_run_id),
                tombstone_digest=tombstone.tombstone_digest, rollback=False,
            )
            try:
                recovery.delete_tombstone(tombstone_name)
            except OSError:
                pass  # terminal commit is authoritative; safe GC may retry
            return WorkspaceMutationResult(
                run.execution_run_id, ExecutionRunStatus.MUTATED,
                normalized.content_digest, tuple(sorted(set(changed))),
            )
        except Exception as exc:
            code = getattr(exc, "code", "mutation-failed")
            if recovery is None:
                self._store.transition_execution_run(
                    run.execution_run_id, expected=("validating",), target="failed",
                    failure_code=code, completed=True,
                )
                raise
            current_run = self._store.get_execution_run(run.execution_run_id)
            if current_run is not None and current_run.status == ExecutionRunStatus.SEALING:
                self._poison_run(workspace.id, run.execution_run_id, code)
                self._store.transition_execution_run(
                    run.execution_run_id, expected=("sealing",), target="poisoned",
                    failure_code=code, completed=True,
                )
                raise
            if not self._store.list_execution_edit_events(run.execution_run_id):
                self._seal_recovery(recovery, workspace.id, run.execution_run_id)
                self._store.transition_execution_run(
                    run.execution_run_id, expected=(current_run.status.value,),
                    target="failed", failure_code=code, completed=True,
                )
                raise
            try:
                self._rollback(
                    run.execution_run_id, root, recovery,
                    workspace.id, failure_code=code,
                    poison_after=(code == "unexpected-workspace-mutation"),
                )
            finally:
                if self._storage_violation(workspace) is not None:
                    workspace.state = WorkspaceState.FAILED
            raise
        finally:
            self._active_phase = None
            self._active_path_handle = None
            self._active_recovery = None
            if recovery is not None:
                recovery.close()
            path_handle.close()

    def _validate_scope(self, context: Any, bundle: PlannedEditBundle) -> tuple[Any, Any]:
        plan = self._plans.get(context.plan_id)
        if plan is None:
            raise WorkspaceMutationError("plan-not-found", "authoritative plan missing")
        if plan.status != PlanStatus.READY or any(
            item.code in {"graph-truncated", "ambiguous-target"}
            for item in plan.diagnostics
        ):
            raise WorkspaceMutationError("plan-not-executable", "plan is blocked or stale")
        fields = (
            (bundle.plan_id, plan.plan_id, "bundle-plan-mismatch"),
            (bundle.plan_content_hash, plan.content_hash, "bundle-content-mismatch"),
            (bundle.task_id, context.task_id, "bundle-task-mismatch"),
            (bundle.workspace_id, context.workspace_id, "bundle-workspace-mismatch"),
            (bundle.repository_id, context.repository_id, "bundle-repository-mismatch"),
            (bundle.binding_digest, context.binding_digest, "bundle-binding-mismatch"),
        )
        for actual, expected, code in fields:
            if actual != expected:
                raise WorkspaceMutationError(code, code)
        if compute_plan_binding_digest(
            plan,
            approved_verification_plan_digest=_resolve_avp_digest(self._store, context),
        ) != context.binding_digest:
            raise WorkspaceMutationError("plan-binding-drift", "plan binding drifted")
        if not bundle.ordered_edits or len(bundle.ordered_edits) > MAX_BUNDLE_FILES:
            raise WorkspaceMutationError("bundle-file-limit", "invalid bundle file count")
        total = sum(
            len(edit.new_content.encode("utf-8"))
            for edit in bundle.ordered_edits if edit.new_content is not None
        )
        if total > MAX_BUNDLE_BYTES:
            raise WorkspaceMutationError("bundle-byte-limit", "bundle is too large")
        normalized_paths: set[str] = set()
        for edit in bundle.ordered_edits:
            for raw in (edit.path, edit.destination_path):
                if raw:
                    key = unicodedata.normalize("NFC", raw).casefold()
                    if key in normalized_paths:
                        raise WorkspaceMutationError(
                            "path-collision", "case or Unicode path collision"
                        )
                    normalized_paths.add(key)
            self._validate_edit_against_plan(plan, edit)
        workspace = self._workspaces.get(context.workspace_id)
        if workspace is None or workspace.state not in {
            WorkspaceState.READY, WorkspaceState.INDEXING, WorkspaceState.RUNNING,
        }:
            raise WorkspaceMutationError("workspace-inactive", "workspace is not active")
        if workspace.task_id != context.task_id:
            raise WorkspaceMutationError("workspace-task-mismatch", "workspace task mismatch")
        worktree = workspace.worktree_path.resolve(strict=True)
        repository = workspace.repository_root.resolve(strict=True)
        if worktree == repository or repository in worktree.parents:
            raise WorkspaceMutationError(
                "main-worktree-refused", "execution root is not an isolated worktree"
            )
        if workspace.base_sha != plan.base_sha:
            raise WorkspaceMutationError("workspace-base-drift", "workspace base SHA drifted")
        for edit in bundle.ordered_edits:
            self._resolve_safe_path(workspace, edit.path)
            if edit.destination_path:
                source = self._resolve_safe_path(workspace, edit.path)
                destination = self._resolve_safe_path(workspace, edit.destination_path)
                if not self._same_writable_root(workspace, source, destination):
                    raise WorkspaceMutationError(
                        "cross-writable-root", "rename crosses writable roots"
                    )
        return plan, workspace

    def _storage_violation(self, workspace: Any) -> dict[str, object] | None:
        """Use the WorkspaceManager authority for planned mutations too."""
        authority = getattr(self._workspaces, "storage_authority", None)
        baseline = getattr(workspace, "storage_baseline", None)
        limits = getattr(workspace, "storage_limits", None)
        if authority is None or baseline is None or limits is None:
            return {
                "kind": "workspace-observation",
                "observed": "authority-unavailable",
                "limit": "authority-required",
            }
        return authority.assess(
            workspace.worktree_path,
            baseline,
            limits,
        )

    def _validate_edit_against_plan(self, plan: Any, edit: PlannedFileEdit) -> None:
        steps = {step.step_id: step for step in plan.steps}
        step = steps.get(edit.plan_step_id)
        if step is None:
            raise WorkspaceMutationError("plan-step-missing", "edit step is not in plan")
        operation_map = {
            PlannedEditOperation.CREATE: PlanOperation.CREATE,
            PlannedEditOperation.UPDATE: PlanOperation.MODIFY,
            PlannedEditOperation.DELETE: PlanOperation.DELETE,
            PlannedEditOperation.RENAME: PlanOperation.RENAME,
        }
        if step.operation != operation_map[edit.operation]:
            raise WorkspaceMutationError("operation-mismatch", "edit operation differs from plan")
        if edit.operation == PlannedEditOperation.CREATE and edit.expected_exists:
            raise WorkspaceMutationError("create-precondition", "create must expect absence")
        if edit.operation != PlannedEditOperation.CREATE and not edit.expected_exists:
            raise WorkspaceMutationError("exists-precondition", "mutation must expect a file")
        if edit.operation in {PlannedEditOperation.DELETE, PlannedEditOperation.RENAME} and edit.new_content is not None:
            raise WorkspaceMutationError("unexpected-content", "operation does not accept content")
        affected = {item.path: item for item in plan.affected_files}
        declaration = affected.get(edit.path)
        if declaration is None or edit.path not in step.target_files:
            raise WorkspaceMutationError("path-outside-plan", "edit path is outside plan")
        if declaration.operation != operation_map[edit.operation]:
            raise WorkspaceMutationError("operation-mismatch", "affected-file operation differs")
        if edit.operation == PlannedEditOperation.RENAME:
            approved_destination = declaration.destination_path
            if not approved_destination or edit.destination_path != approved_destination:
                raise WorkspaceMutationError(
                    "rename-destination-unapproved", "rename destination is not approved"
                )
        elif edit.destination_path is not None:
            raise WorkspaceMutationError(
                "unexpected-destination", "destination is only valid for rename"
            )

    def _resolve_safe_path(self, workspace: Any, raw: str) -> Path:
        if not raw or raw != raw.strip() or "\\" in raw:
            raise WorkspaceMutationError("unsafe-path", "path must be relative POSIX")
        if (raw.startswith(("/", "//")) or _WINDOWS_DRIVE.match(raw)
                or PureWindowsPath(raw).drive):
            raise WorkspaceMutationError("unsafe-path", "absolute path refused")
        if any(part in {"", ".", ".."} for part in raw.split("/")):
            raise WorkspaceMutationError("unsafe-path", "dot path segment refused")
        pure = PurePosixPath(raw)
        if any(part in {"", ".", ".."} for part in pure.parts):
            raise WorkspaceMutationError("unsafe-path", "dot path segment refused")
        if pure.parts[0].casefold() == ".git" or ".git" in {
            part.casefold() for part in pure.parts
        }:
            raise WorkspaceMutationError("git-admin-path", ".git path refused")
        root = workspace.worktree_path.resolve(strict=True)
        candidate = root.joinpath(*pure.parts)
        current = root
        for part in pure.parts[:-1]:
            current = current / part
            if current.exists() and current.is_symlink():
                raise WorkspaceMutationError("parent-symlink", "parent symlink refused")
            if (current / ".git").exists() and current != root:
                raise WorkspaceMutationError("submodule-path", "submodule path refused")
        if candidate.is_symlink():
            raise WorkspaceMutationError("target-symlink", "target symlink refused")
        try:
            resolved_parent = candidate.parent.resolve(strict=True)
        except FileNotFoundError as exc:
            raise WorkspaceMutationError(
                "parent-missing", "parent directory is not declared"
            ) from exc
        if root != resolved_parent and root not in resolved_parent.parents:
            raise WorkspaceMutationError("workspace-escape", "path escapes worktree")
        writable = [Path(item).resolve(strict=True) for item in workspace.writable_roots]
        if not any(parent == candidate or parent in candidate.parents for parent in writable):
            raise WorkspaceMutationError("outside-writable-root", "path is not writable")
        return candidate

    @staticmethod
    def _same_writable_root(workspace: Any, source: Path, destination: Path) -> bool:
        roots = [Path(item).resolve(strict=True) for item in workspace.writable_roots]
        source_roots = [root for root in roots if root == source or root in source.parents]
        destination_roots = [root for root in roots if root == destination or root in destination.parents]
        return bool(source_roots and destination_roots and source_roots[0] == destination_roots[0])

    def _journal_edit(
        self, run_id: str, ordinal: int, edit: PlannedFileEdit,
        root: Path, recovery: RecoveryDirectory,
    ) -> tuple[str | None, int | None]:
        if self._active_path_handle is None:
            raise WorkspaceMutationError("path-handle-missing", "mutation path handle missing")
        parent = self._active_path_handle.parent(edit.path)
        try:
            info = parent.lstat()
            before_hash = parent.hash_file() if info is not None else None
            before_mode = stat.S_IMODE(info.st_mode) if info is not None else None
            source_bytes = parent.read_file()[0] if info is not None else None
        finally:
            parent.close()
        if edit.operation == PlannedEditOperation.CREATE and (edit.new_mode or 0o600) & ~0o666:
            raise WorkspaceMutationError("mode-escalation", "create mode is unsafe")
        if edit.operation == PlannedEditOperation.UPDATE and edit.new_mode is not None:
            if (edit.new_mode & ~0o777 or edit.new_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                    or (edit.new_mode & 0o111) > ((before_mode or 0) & 0o111)):
                raise WorkspaceMutationError("mode-escalation", "update mode is unsafe")
        artifact = None
        if source_bytes is not None:
            artifact, backup_hash = recovery.create_backup(
                source_bytes, before_mode or 0o600
            )
            if backup_hash != before_hash:
                raise WorkspaceMutationError("backup-hash-mismatch", "backup verification failed")
        try:
            self._store.insert_edit_event(
                event_id=uuid.uuid4().hex, execution_run_id=run_id,
                edit_id=edit.edit_id, ordinal=ordinal,
                operation=edit.operation.value, path=edit.path,
                destination_path=edit.destination_path, before_hash=before_hash,
                before_mode=before_mode, recovery_artifact=artifact,
                planned_after_hash=(
                    "" if edit.operation == PlannedEditOperation.DELETE
                    else edit.new_content_hash or before_hash or ""
                ),
                planned_after_mode=(
                    None if edit.operation == PlannedEditOperation.DELETE
                    else (edit.new_mode if edit.new_mode is not None else
                          (0o600 if edit.operation == PlannedEditOperation.CREATE
                           else before_mode))
                ),
            )
        except Exception:
            if artifact is not None:
                recovery.discard_unreferenced(artifact)
            raise
        return artifact, before_mode

    def _apply_edit(self, edit: PlannedFileEdit, root: Path) -> None:
        handle = self._active_path_handle
        phase = self._active_phase
        if handle is None or phase is None:
            raise WorkspaceMutationError("mutation-session-invalid", "dirfd mutation session missing")
        if edit.encoding.casefold() != "utf-8":
            raise WorkspaceMutationError("encoding-refused", "only UTF-8 is supported")
        if edit.operation == PlannedEditOperation.CREATE:
            if edit.new_content is None:
                raise WorkspaceMutationError("missing-content", "create content missing")
            new_mode = edit.new_mode or 0o600
            if new_mode & ~0o666:
                raise WorkspaceMutationError("mode-escalation", "create mode is not a safe regular-file mode")
            try:
                handle.create(edit.path, edit.new_content.encode("utf-8"), new_mode, phase)
            except (SafePathError, FileExistsError) as exc:
                raise WorkspaceMutationError("create-race", str(exc)) from exc
            return
        parent = handle.parent(edit.path)
        try:
            info = parent.lstat()
            if info is None or not stat.S_ISREG(info.st_mode):
                raise WorkspaceMutationError("target-not-file", "target is not a regular file")
            if info.st_size > MAX_FILE_BYTES:
                raise WorkspaceMutationError("file-size-limit", "target file is too large")
            before_hash = parent.hash_file()
        finally:
            parent.close()
        if edit.expected_content_hash != before_hash:
            raise WorkspaceMutationError("content-hash-drift", "target content hash drifted")
        mode = stat.S_IMODE(info.st_mode)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            raise WorkspaceMutationError("unsafe-existing-mode", "setuid/setgid file refused")
        if edit.expected_mode is not None and edit.expected_mode != mode:
            raise WorkspaceMutationError("mode-drift", "target mode drifted")
        if edit.operation == PlannedEditOperation.UPDATE:
            if edit.new_content is None:
                raise WorkspaceMutationError("missing-content", "update content missing")
            new_mode = mode if edit.new_mode is None else edit.new_mode
            if (new_mode & ~0o777 or new_mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
                    or (new_mode & 0o111) > (mode & 0o111)):
                raise WorkspaceMutationError("mode-escalation", "executable privilege increase refused")
            try:
                handle.update(
                    edit.path, edit.new_content.encode("utf-8"), new_mode,
                    info.st_ino, phase,
                )
            except SafePathError as exc:
                raise WorkspaceMutationError("update-race", str(exc)) from exc
        elif edit.operation == PlannedEditOperation.DELETE:
            try:
                handle.delete(edit.path, info.st_ino, phase)
            except SafePathError as exc:
                raise WorkspaceMutationError("delete-race", str(exc)) from exc
        elif edit.operation == PlannedEditOperation.RENAME:
            if not edit.destination_path:
                raise WorkspaceMutationError("missing-destination", "rename destination missing")
            try:
                handle.rename_no_replace(
                    edit.path, edit.destination_path, info.st_ino, phase
                )
            except FileExistsError as exc:
                raise WorkspaceMutationError("rename-target-exists", "rename target exists") from exc
            except SafePathError as exc:
                raise WorkspaceMutationError("rename-race", str(exc)) from exc

    @staticmethod
    def _object_identity_digest(
        identity: MutationObjectIdentity, *, run_id: str, edit_id: str,
        operation: str, role: str,
    ) -> str:
        payload = {
            "run_id": run_id,
            "edit_id": edit_id,
            "operation": operation,
            "role": role,
            "exists": identity.exists,
            "object_dev": identity.object_dev,
            "object_ino": identity.object_ino,
            "file_type": identity.file_type,
            "source_parent_dev": identity.source_parent_dev,
            "source_parent_ino": identity.source_parent_ino,
            "destination_parent_dev": identity.destination_parent_dev,
            "destination_parent_ino": identity.destination_parent_ino,
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()

    @staticmethod
    def _parent_identity_digest(
        identity: MutationObjectIdentity, *, run_id: str, edit_id: str,
        operation: str, destination: bool = False,
    ) -> str:
        dev = (
            identity.destination_parent_dev if destination
            else identity.source_parent_dev
        )
        ino = (
            identity.destination_parent_ino if destination
            else identity.source_parent_ino
        )
        if not dev or not ino:
            return ""
        payload = {
            "run_id": run_id, "edit_id": edit_id,
            "operation": operation,
            "role": "destination-parent" if destination else "source-parent",
            "dev": dev, "ino": ino,
        }
        return hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()

    def _record_mutation_phase(
        self, run_id: str, edit: PlannedFileEdit, phase: str,
        identity: MutationObjectIdentity | None,
    ) -> None:
        kwargs: dict[str, Any] = {}
        if phase == "filesystem-applied":
            if identity is None:
                raise WorkspaceMutationError(
                    "identity-evidence-missing",
                    "filesystem mutation has no object identity",
                )
            kwargs = {
                "applied_identity_digest": (
                    "" if not identity.exists else self._object_identity_digest(
                        identity, run_id=run_id, edit_id=edit.edit_id,
                        operation=edit.operation.value, role="applied-object",
                    )
                ),
                "applied_parent_identity_digest": self._parent_identity_digest(
                    identity, run_id=run_id, edit_id=edit.edit_id,
                    operation=edit.operation.value,
                ),
                "applied_destination_identity_digest": (
                    self._object_identity_digest(
                        identity, run_id=run_id, edit_id=edit.edit_id,
                        operation=edit.operation.value,
                        role="applied-destination-object",
                    ) if edit.operation == PlannedEditOperation.RENAME else ""
                ),
            }
        self._store.update_edit_event(
            run_id, edit.edit_id, status=phase, **kwargs,
        )

    def _rollback(
        self, run_id: str, root: Path, recovery: RecoveryDirectory, workspace_id: str, *, failure_code: str,
        poison_after: bool = False, recovered: bool = False,
    ) -> None:
        try:
            resume = self._store.begin_or_resume_rollback(
                run_id, failure_code=failure_code,
            )
            if resume.disposition.value == "terminal":
                return
            if resume.disposition.value == "sealing":
                return
            failure_code = resume.failure_code
            current_run = self._store.get_execution_run(run_id)
            baseline = self._require_initial_attestation(current_run)
            journal = self._validated_journal(current_run, allow_partial=True)
            self._validate_recovery_artifacts(journal, baseline, recovery)
            handle = self._active_path_handle or WorkspacePathHandle(root)
            owns_handle = self._active_path_handle is None
            baseline_paths = {item.path: item for item in baseline.declared_states}
            for event in reversed(journal.events):
                phase = event.durable_phase
                if (phase == "rolled-back"
                        and event.rollback_identity_digest
                        and not event.rollback_directory_sync_digest):
                    self._verify_rollback_identity(
                        handle, event, baseline_paths,
                    )
                    event = self._persist_legacy_rollback_filesystem_state(
                        handle, event, expected_phase="rolled-back",
                        failure_code=failure_code,
                    )
                    phase = event.durable_phase
                elif phase == "rolled-back":
                    self._verify_rolled_back_event(
                        handle, event, baseline_paths,
                    )
                    self._store.transition_edit_event(
                        run_id, event.edit_id, expected_phase="rolled-back",
                        target_phase="rolled-back", error_code=failure_code,
                    )
                    continue
                if phase in {"journaled", "mutation-started"}:
                    if not self._event_matches_unchanged_baseline(
                        handle, event, baseline_paths,
                    ):
                        raise WorkspaceMutationError(
                            "identity-evidence-missing",
                            "mutation may have occurred before identity persistence",
                        )
                    self._store.transition_edit_event(
                        run_id, event.edit_id, expected_phase=phase,
                        target_phase="rolled-back", error_code=failure_code,
                    )
                    continue
                if phase in {"filesystem-applied", "directory-synced", "applied"}:
                    self._assert_applied_identity(handle, event)
                    self._store.transition_edit_event(
                        run_id, event.edit_id, expected_phase=phase,
                        target_phase="rollback-started", error_code=failure_code,
                    )
                    event = replace(
                        event, durable_phase="rollback-started",
                        phase_version=event.phase_version + 1,
                    )
                    phase = event.durable_phase
                if (phase == "rollback-started"
                        and event.rollback_identity_digest):
                    self._verify_rollback_identity(
                        handle, event, baseline_paths,
                    )
                    event = self._persist_legacy_rollback_filesystem_state(
                        handle, event, expected_phase="rollback-started",
                        failure_code=failure_code,
                    )
                    phase = event.durable_phase
                elif phase == "rollback-started":
                    if self._event_has_baseline_values(
                        handle, event, baseline_paths,
                    ):
                        raise WorkspaceMutationError(
                            "identity-evidence-missing",
                            "rollback syscall may have completed before identity commit",
                        )
                    self._assert_applied_identity(handle, event)
                    self._rollback_event(
                        handle, event, recovery, baseline_paths[event["path"]],
                        run_id=run_id, failure_code=failure_code,
                    )
                    event = self._reload_recovery_event(run_id, event.edit_id)
                    phase = event.durable_phase
                if phase == "rollback-filesystem-applied":
                    self._verify_rollback_identity(
                        handle, event, baseline_paths,
                    )
                    self._sync_rollback_directories(handle, event)
                    self._store.record_rollback_directory_synced(
                        run_id, event.edit_id, error_code=failure_code,
                    )
                    event = self._reload_recovery_event(run_id, event.edit_id)
                    phase = event.durable_phase
                if phase == "rollback-directory-synced":
                    self._verify_rollback_identity(
                        handle, event, baseline_paths,
                    )
                    self._verify_rollback_parent_identities(handle, event)
                self._store.transition_edit_event(
                    run_id, event.edit_id,
                    expected_phase="rollback-directory-synced",
                    target_phase="rolled-back", error_code=failure_code,
                )
            target = "cancelled" if failure_code == "execution-context-invalid" else "rolled-back"
            if poison_after:
                self._poison_run(workspace_id, run_id, failure_code)
                self._store.transition_execution_run(
                    run_id, expected=("rolling-back",), target="poisoned",
                    failure_code=failure_code, completed=True,
                )
                if owns_handle:
                    handle.close()
                return
            current_run = self._store.get_execution_run(run_id)
            journal = self._validated_journal(current_run, allow_partial=True)
            events, journal_digest = journal.events, journal.canonical_digest
            workspace = self._workspaces.get(workspace_id)
            rollback_attestation = self._store.get_rollback_final_attestation(
                run_id
            )
            if rollback_attestation is None:
                rollback_attestation = self._build_rollback_attestation(
                    current_run, workspace, handle, events, journal_digest,
                    failure_code, baseline,
                )
                self._store.save_rollback_final_attestation(
                    rollback_attestation
                )
            else:
                self._validate_rollback_sealing_recovery(
                    current_run, workspace, events, journal_digest,
                )
            self._store.transition_execution_run(
                run_id, expected=("rolling-back",), target="rollback-sealing",
                failure_code=failure_code,
            )
            self._validate_rollback_sealing_recovery(
                current_run, workspace, events, journal_digest,
            )
            recovery.seal()
            tombstone_name, tombstone = self._write_seal_tombstone(
                recovery, current_run, target,
                rollback_attestation.attestation_digest, journal_digest,
            )
            terminal_args = {
                "execution_run_id": run_id,
                "expected_status": "rollback-sealing",
                "terminal_status": target,
                "seal_digest": self._recovery_seal_digest(run_id),
                "tombstone_digest": tombstone.tombstone_digest,
                "rollback": True,
                "failure_code": failure_code,
            }
            if recovered:
                self._store.commit_recovered_terminal_state(
                    workspace_id=workspace_id, poison_owner=f"run:{run_id}",
                    attestation_digest=rollback_attestation.attestation_digest,
                    **terminal_args,
                )
            else:
                self._store.commit_terminal_seal(**terminal_args)
            try:
                recovery.delete_tombstone(tombstone_name)
            except OSError:
                pass  # terminal commit is authoritative; safe GC may retry
            if owns_handle:
                handle.close()
        except Exception as rollback_error:
            if 'owns_handle' in locals() and owns_handle:
                try:
                    handle.close()
                except OSError:
                    pass
            reason = f"rollback-failed:{type(rollback_error).__name__}"
            self._poison_run(workspace_id, run_id, reason)
            try:
                current = self._store.get_execution_run(run_id)
                self._store.transition_execution_run(
                    run_id, expected=("rolling-back", "rollback-sealing"),
                    target="poisoned",
                    failure_code=current.failure_code if current else failure_code,
                    completed=True,
                )
            except Exception:
                pass
            raise WorkspaceMutationError(reason, "rollback failed") from rollback_error

    def _rollback_event(
        self, handle: WorkspacePathHandle, event: Any,
        recovery: RecoveryDirectory, baseline: InitialPathState, *,
        run_id: str, failure_code: str,
    ) -> None:
        operation = event["operation"]
        before_hash = baseline.content_hash or None
        after_hash = event["after_hash"] or None
        current_hash, current_mode, current_inode = self._current_target(handle, event["path"])
        def record_identity(
            phase: str, identity: MutationObjectIdentity | None = None,
        ) -> None:
            if phase == "directory-synced":
                self._store.record_rollback_directory_synced(
                    run_id, event.edit_id, error_code=failure_code,
                )
                return
            if phase != "filesystem-applied" or identity is None:
                raise WorkspaceMutationError(
                    "rollback-identity-missing", "rollback identity was not observed"
                )
            digest = self._object_identity_digest(
                identity, run_id=run_id, edit_id=event.edit_id,
                operation=event.operation.value, role="rollback-object",
            )
            parent_digest, destination_parent_digest, sync_mask = (
                self._rollback_parent_evidence(identity, event)
            )
            self._store.record_rollback_filesystem_applied(
                run_id, event.edit_id,
                rollback_identity_digest=digest,
                rollback_parent_identity_digest=parent_digest,
                rollback_destination_parent_identity_digest=(
                    destination_parent_digest
                ),
                rollback_sync_mask=sync_mask,
                error_code=failure_code,
            )
        if operation == "create":
            if current_hash != after_hash or current_mode != event["after_mode"]:
                raise WorkspaceMutationError("rollback-third-party", "create target has third-party content")
            handle.delete(event["path"], current_inode, record_identity)
            return
        if operation == "rename":
            destination = event["destination_path"]
            dest_hash, dest_mode, dest_inode = self._current_target(handle, destination)
            if current_hash == before_hash and dest_hash is None:
                return
            if (current_hash is None and dest_hash == after_hash
                    and dest_mode == event["after_mode"]):
                handle.rename_no_replace(
                    destination, event["path"], dest_inode, record_identity,
                )
                return
            raise WorkspaceMutationError("rollback-third-party", "rename state is not known")
        artifact = event["recovery_artifact"]
        if not artifact:
            raise WorkspaceMutationError("rollback-evidence-missing", "backup artifact missing")
        try:
            data = recovery.read(artifact)
        except RecoveryDirectoryError as exc:
            raise WorkspaceMutationError(
                "rollback-evidence-invalid", "backup artifact invalid"
            ) from exc
        if hashlib.sha256(data).hexdigest() != before_hash:
            raise WorkspaceMutationError("rollback-evidence-invalid", "backup artifact invalid")
        mode = int(baseline.mode if baseline.mode is not None else 0o600)
        if operation == "update":
            if (current_hash != after_hash or current_mode != event["after_mode"]
                    or current_inode is None):
                raise WorkspaceMutationError("rollback-third-party", "updated target has third-party content")
            handle.update(event["path"], data, mode, current_inode, record_identity)
        elif operation == "delete":
            if current_hash is not None:
                raise WorkspaceMutationError("rollback-third-party", "deleted target was replaced")
            handle.create(event["path"], data, mode, record_identity)

    @staticmethod
    def _validate_recovery_artifacts(
        journal: ValidatedRecoveryJournal,
        baseline: InitialWorkspaceAttestation,
        recovery: RecoveryDirectory,
    ) -> None:
        """Validate every backup against the persisted baseline before rollback."""
        baseline_paths = {item.path: item for item in baseline.declared_states}
        seen: set[str] = set()
        for event in journal.events:
            if event.operation == PlannedEditOperation.CREATE:
                continue
            if event.artifact is None or event.artifact.value in seen:
                raise WorkspaceMutationError(
                    "rollback-evidence-invalid", "backup artifact binding is invalid"
                )
            seen.add(event.artifact.value)
            expected = baseline_paths[event.path.value]
            try:
                data = recovery.read(event.artifact.value)
            except RecoveryDirectoryError as exc:
                raise WorkspaceMutationError(
                    "rollback-evidence-invalid", "backup artifact cannot be read"
                ) from exc
            if hashlib.sha256(data).hexdigest() != expected.content_hash:
                raise WorkspaceMutationError(
                    "rollback-evidence-invalid", "backup differs from initial baseline"
                )

    @staticmethod
    def _current_target(
        handle: WorkspacePathHandle, relative: str
    ) -> tuple[str | None, int | None, int | None]:
        parent = handle.parent(relative)
        try:
            info = parent.lstat()
            if info is None:
                return None, None, None
            if not stat.S_ISREG(info.st_mode):
                raise WorkspaceMutationError("target-not-file", "target is not a regular file")
            return parent.hash_file(), stat.S_IMODE(info.st_mode), info.st_ino
        finally:
            parent.close()

    @staticmethod
    def _observe_event_identity(
        handle: WorkspacePathHandle, event: Any,
    ) -> MutationObjectIdentity:
        operation = (
            event.operation.value if isinstance(event, ValidatedRecoveryEvent)
            else str(event["operation"])
        )
        source_path = event["path"]
        destination_path = event["destination_path"]
        source_parent = handle.parent(source_path)
        destination_parent = None
        try:
            target_parent = source_parent
            if operation == "rename":
                destination_parent = handle.parent(destination_path)
                target_parent = destination_parent
                if source_parent.lstat() is not None:
                    raise WorkspaceMutationError(
                        "ownership-state-drift", "rename source reappeared"
                    )
            info = target_parent.lstat()
            if info is None:
                return MutationObjectIdentity(
                    False,
                    source_parent_dev=source_parent.identity[0],
                    source_parent_ino=source_parent.identity[1],
                    destination_parent_dev=(
                        destination_parent.identity[0] if destination_parent else 0
                    ),
                    destination_parent_ino=(
                        destination_parent.identity[1] if destination_parent else 0
                    ),
                )
            if not stat.S_ISREG(info.st_mode):
                raise WorkspaceMutationError(
                    "ownership-state-drift", "mutation object is not regular"
                )
            return MutationObjectIdentity(
                True, info.st_dev, info.st_ino, "regular",
                source_parent.identity[0], source_parent.identity[1],
                destination_parent.identity[0] if destination_parent else 0,
                destination_parent.identity[1] if destination_parent else 0,
            )
        finally:
            if destination_parent is not None:
                destination_parent.close()
            source_parent.close()

    def _assert_applied_identity(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
    ) -> MutationObjectIdentity:
        observed = self._observe_event_identity(handle, event)
        operation = event.operation.value
        object_digest = (
            "" if not observed.exists else self._object_identity_digest(
                observed, run_id=event.execution_run_id,
                edit_id=event.edit_id, operation=operation,
                role="applied-object",
            )
        )
        parent_digest = self._parent_identity_digest(
            observed, run_id=event.execution_run_id, edit_id=event.edit_id,
            operation=operation,
        )
        destination_digest = (
            self._object_identity_digest(
                observed, run_id=event.execution_run_id,
                edit_id=event.edit_id, operation=operation,
                role="applied-destination-object",
            ) if operation == "rename" and observed.exists else ""
        )
        if (object_digest != event.applied_identity_digest
                or parent_digest != event.applied_parent_identity_digest
                or destination_digest
                != event.applied_destination_identity_digest):
            raise WorkspaceMutationError(
                "mutation-object-replaced",
                "current object is not the Khaos-owned mutation object",
            )
        return observed

    @staticmethod
    def _inode_identity_digest(identity: MutationObjectIdentity) -> str:
        if not identity.exists:
            return ""
        return hashlib.sha256(
            f"{identity.object_dev}:{identity.object_ino}".encode("utf-8")
        ).hexdigest()

    def _observe_rollback_identity(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
    ) -> MutationObjectIdentity:
        if event.operation != PlannedEditOperation.RENAME:
            return self._observe_event_identity(handle, event)
        source_parent = handle.parent(event.path.value)
        destination_parent = handle.parent(event.destination.value)
        try:
            info = source_parent.lstat()
            if destination_parent.lstat() is not None:
                raise WorkspaceMutationError(
                    "rollback-third-party", "rename destination reappeared"
                )
            if info is None or not stat.S_ISREG(info.st_mode):
                raise WorkspaceMutationError(
                    "rollback-state-drift", "rename source was not restored"
                )
            # Match the raw parent roles observed by rename_no_replace(b -> a).
            return MutationObjectIdentity(
                True, info.st_dev, info.st_ino, "regular",
                destination_parent.identity[0], destination_parent.identity[1],
                source_parent.identity[0], source_parent.identity[1],
            )
        finally:
            destination_parent.close()
            source_parent.close()

    def _rollback_parent_evidence(
        self, identity: MutationObjectIdentity, event: ValidatedRecoveryEvent,
    ) -> tuple[str, str, int]:
        operation = event.operation.value
        source_digest = self._parent_identity_digest(
            identity, run_id=event.execution_run_id, edit_id=event.edit_id,
            operation=operation,
        )
        if not source_digest:
            raise WorkspaceMutationError(
                "rollback-parent-identity-missing",
                "rollback source parent identity was not observed",
            )
        if event.operation != PlannedEditOperation.RENAME:
            return source_digest, "", 1
        destination_digest = self._parent_identity_digest(
            identity, run_id=event.execution_run_id, edit_id=event.edit_id,
            operation=operation, destination=True,
        )
        if not destination_digest:
            raise WorkspaceMutationError(
                "rollback-parent-identity-missing",
                "rollback destination parent identity was not observed",
            )
        source_identity = (
            identity.source_parent_dev, identity.source_parent_ino,
        )
        destination_identity = (
            identity.destination_parent_dev, identity.destination_parent_ino,
        )
        return (
            source_digest, destination_digest,
            1 if source_identity == destination_identity else 3,
        )

    def _persist_legacy_rollback_filesystem_state(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent, *,
        expected_phase: str, failure_code: str,
    ) -> ValidatedRecoveryEvent:
        """Upgrade old ownership-only rollback rows to the sync-required phase."""
        identity = self._observe_rollback_identity(handle, event)
        parent_digest, destination_digest, sync_mask = (
            self._rollback_parent_evidence(identity, event)
        )
        self._store.record_rollback_filesystem_applied(
            event.execution_run_id, event.edit_id,
            rollback_identity_digest=event.rollback_identity_digest,
            rollback_parent_identity_digest=parent_digest,
            rollback_destination_parent_identity_digest=destination_digest,
            rollback_sync_mask=sync_mask, error_code=failure_code,
            expected_phase=expected_phase,
        )
        return self._reload_recovery_event(
            event.execution_run_id, event.edit_id,
        )

    def _reload_recovery_event(
        self, execution_run_id: str, edit_id: str,
    ) -> ValidatedRecoveryEvent:
        run = self._store.get_execution_run(execution_run_id)
        journal = self._validated_journal(run, allow_partial=True)
        for event in journal.events:
            if event.edit_id == edit_id:
                return event
        raise WorkspaceMutationError(
            "recovery-journal-missing", "rollback edit disappeared from journal",
        )

    def _verify_rollback_parent_identities(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
    ) -> MutationObjectIdentity:
        identity = self._observe_rollback_identity(handle, event)
        source_digest, destination_digest, sync_mask = (
            self._rollback_parent_evidence(identity, event)
        )
        if (
            source_digest != event.rollback_parent_identity_digest
            or destination_digest
            != event.rollback_destination_parent_identity_digest
            or sync_mask != event.rollback_sync_mask
        ):
            raise WorkspaceMutationError(
                "rollback-parent-identity-drift",
                "rollback parent directory identity changed",
            )
        return identity

    def _sync_rollback_directories(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
    ) -> None:
        """Idempotently fsync persisted rollback parents via fixed dirfds."""
        self._verify_rollback_parent_identities(handle, event)
        source_path = (
            event.destination.value
            if event.operation == PlannedEditOperation.RENAME
            else event.path.value
        )
        source_parent = handle.parent(source_path)
        destination_parent = None
        try:
            source_parent.revalidate()
            observed = MutationObjectIdentity(
                False,
                source_parent_dev=source_parent.identity[0],
                source_parent_ino=source_parent.identity[1],
            )
            if event.operation == PlannedEditOperation.RENAME:
                destination_parent = handle.parent(event.path.value)
                observed = MutationObjectIdentity(
                    False,
                    source_parent_dev=source_parent.identity[0],
                    source_parent_ino=source_parent.identity[1],
                    destination_parent_dev=destination_parent.identity[0],
                    destination_parent_ino=destination_parent.identity[1],
                )
            source_digest, destination_digest, mask = (
                self._rollback_parent_evidence(observed, event)
            )
            if (
                source_digest != event.rollback_parent_identity_digest
                or destination_digest
                != event.rollback_destination_parent_identity_digest
                or mask != event.rollback_sync_mask
            ):
                raise WorkspaceMutationError(
                    "rollback-parent-identity-drift",
                    "rollback parent changed before directory sync",
                )
            source_parent.fsync()
            if event.rollback_sync_mask & 2:
                if destination_parent is None:
                    raise WorkspaceMutationError(
                        "rollback-sync-scope-invalid",
                        "destination parent sync capability is missing",
                    )
                destination_parent.revalidate()
                destination_parent.fsync()
            self._verify_rollback_identity(
                handle, event,
                {event.path.value: InitialPathState(
                    event.path.value,
                    event.operation != PlannedEditOperation.CREATE,
                    event.before_hash, event.before_mode,
                    "regular" if event.operation != PlannedEditOperation.CREATE
                    else "missing",
                )},
            )
            self._verify_rollback_parent_identities(handle, event)
        finally:
            if destination_parent is not None:
                destination_parent.close()
            source_parent.close()

    def _event_matches_unchanged_baseline(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
        baseline_paths: dict[str, InitialPathState],
    ) -> bool:
        expected = baseline_paths[event.path.value]
        try:
            if event.operation == PlannedEditOperation.RENAME:
                identity = self._observe_rollback_identity(handle, event)
                destination_hash, _, _ = self._current_target(
                    handle, event.destination.value,
                )
                if destination_hash is not None:
                    return False
            else:
                identity = self._observe_event_identity(handle, event)
        except WorkspaceMutationError:
            return False
        if not expected.exists:
            return not identity.exists
        if not identity.exists:
            return False
        content_hash, mode, _ = self._current_target(handle, expected.path)
        return (
            content_hash == expected.content_hash
            and mode == expected.mode
            and self._inode_identity_digest(identity) == expected.identity_digest
        )

    def _event_has_baseline_values(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
        baseline_paths: dict[str, InitialPathState],
    ) -> bool:
        expected = baseline_paths[event.path.value]
        content_hash, mode, _ = self._current_target(handle, event.path.value)
        if expected.exists:
            if content_hash != expected.content_hash or mode != expected.mode:
                return False
        elif content_hash is not None:
            return False
        if event.operation == PlannedEditOperation.RENAME:
            destination_hash, _, _ = self._current_target(
                handle, event.destination.value,
            )
            return destination_hash is None
        return True

    def _verify_rollback_identity(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
        baseline_paths: dict[str, InitialPathState],
    ) -> None:
        identity = self._observe_rollback_identity(handle, event)
        expected = baseline_paths[event.path.value]
        if expected.exists:
            content_hash, mode, _ = self._current_target(handle, expected.path)
            if (not identity.exists or content_hash != expected.content_hash
                    or mode != expected.mode):
                raise WorkspaceMutationError(
                    "rollback-state-drift", "restored object differs from baseline"
                )
        elif identity.exists:
            raise WorkspaceMutationError(
                "rollback-state-drift", "created object remains after rollback"
            )
        digest = self._object_identity_digest(
            identity, run_id=event.execution_run_id, edit_id=event.edit_id,
            operation=event.operation.value, role="rollback-object",
        )
        if digest != event.rollback_identity_digest:
            raise WorkspaceMutationError(
                "rollback-object-replaced",
                "rollback result is not the persisted Khaos-owned object",
            )

    def _verify_rolled_back_event(
        self, handle: WorkspacePathHandle, event: ValidatedRecoveryEvent,
        baseline_paths: dict[str, InitialPathState],
    ) -> None:
        if event.rollback_identity_digest:
            self._verify_rollback_identity(handle, event, baseline_paths)
            return
        if not self._event_matches_unchanged_baseline(
            handle, event, baseline_paths,
        ):
            raise WorkspaceMutationError(
                "rolled-back-state-drift",
                "rolled-back event no longer matches its initial baseline",
            )

    @staticmethod
    def _workspace_state_digest(file_states: tuple[Any, ...]) -> str:
        payload = "|".join(
            f"{state.relative_path}:{state.state_digest}"
            for state in sorted(file_states, key=lambda item: item.relative_path)
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _git_state_map(snapshot: Any) -> dict[str, str]:
        return {state.relative_path: state.state_digest for state in snapshot.file_states}

    def _attested_states(
        self, handle: WorkspacePathHandle, events: tuple[Any, ...],
    ) -> tuple[AttestedPathState, ...]:
        states: list[AttestedPathState] = []
        for event in events:
            if not isinstance(event, ValidatedRecoveryEvent):
                raise WorkspaceMutationError(
                    "attestation-journal-invalid",
                    "final attestation requires validated ownership evidence",
                )
            operation = event["operation"]
            expected_hash = event["after_hash"] or ""
            expected_mode = event["after_mode"]
            if operation == "delete":
                self._assert_applied_identity(handle, event)
                content_hash, mode, _ = self._current_target(handle, event["path"])
                if content_hash is not None:
                    raise WorkspaceMutationError(
                        "declared-state-drift", "deleted path reappeared"
                    )
                states.append(AttestedPathState(
                    event["path"], False, parent_identity_digest=
                    event.applied_parent_identity_digest,
                ))
                continue
            if operation == "rename":
                source_hash, _, _ = self._current_target(handle, event["path"])
                if source_hash is not None:
                    raise WorkspaceMutationError(
                        "declared-state-drift", "rename source still exists"
                    )
                states.append(AttestedPathState(event["path"], False))
                target_path = event["destination_path"]
            else:
                target_path = event["path"]
            content_hash, mode, _ = self._current_target(handle, target_path)
            if content_hash != expected_hash or mode != expected_mode:
                raise WorkspaceMutationError(
                    "declared-state-drift", "declared path hash or mode drifted"
                )
            self._assert_applied_identity(handle, event)
            identity_digest = (
                event.applied_destination_identity_digest
                if operation == "rename" else event.applied_identity_digest
            )
            states.append(AttestedPathState(
                target_path, True, content_hash, mode, "regular",
                identity_digest, event.applied_parent_identity_digest,
            ))
        return tuple(sorted(states, key=lambda state: state.path))

    def _build_final_attestation(
        self, run: PlanExecutionRun, context: Any, bundle: PlannedEditBundle,
        workspace: Any, handle: WorkspacePathHandle, git_state: Any,
    ) -> FinalMutationAttestation:
        journal = self._validated_journal(run)
        events = journal.events
        if len(events) != len(bundle.ordered_edits):
            raise WorkspaceMutationError(
                "attestation-journal-missing", "final journal is incomplete"
            )
        states = self._attested_states(handle, events)
        final_git = self._git_inspector.snapshot(
            workspace, repository_generation=git_state.repository_generation,
        )
        if final_git != git_state:
            raise WorkspaceMutationError(
                "final-attestation-drift", "repository changed during final attestation"
            )
        return FinalMutationAttestation(
            execution_run_id=run.execution_run_id,
            bundle_digest=bundle.content_digest,
            ordered_states=states, path_state_digest="",
            head=final_git.head_commit, generation=final_git.repository_generation,
            index_digest=final_git.index_digest,
            worktree_admin_digest=final_git.worktree_admin_identity,
            workspace_state_digest=self._workspace_state_digest(final_git.file_states),
            execution_context_id=context.execution_context_id,
            lease_id=context.lease_id, binding_digest=context.binding_digest,
            attested_at=time.time(),
        ).normalized()

    def _build_initial_attestation(self, run: PlanExecutionRun, context: Any,
                                   bundle: PlannedEditBundle, git_state: Any) -> InitialWorkspaceAttestation:
        by_path = {item.relative_path: item for item in git_state.file_states}
        paths = sorted({path for edit in bundle.ordered_edits
                        for path in (edit.path, edit.destination_path) if path})
        states = []
        for path in paths:
            item = by_path.get(path)
            states.append(InitialPathState(
                path, item is not None, item.content_hash if item else "",
                item.mode if item else None, item.file_type if item else "missing",
                item.identity_digest if item else "",
            ))
        workspace_states = tuple(InitialPathState(
            item.relative_path, True, item.content_hash, item.mode,
            item.file_type, item.identity_digest,
        ) for item in git_state.file_states)
        approved_edits = []
        for edit in bundle.ordered_edits:
            source = by_path.get(edit.path)
            after_hash = ""
            after_mode = None
            if edit.operation == PlannedEditOperation.CREATE:
                after_hash = edit.new_content_hash or ""
                after_mode = edit.new_mode if edit.new_mode is not None else 0o600
            elif edit.operation == PlannedEditOperation.UPDATE:
                after_hash = edit.new_content_hash or ""
                after_mode = edit.new_mode if edit.new_mode is not None else (
                    source.mode if source else None
                )
            elif edit.operation == PlannedEditOperation.RENAME:
                after_hash = source.content_hash if source else ""
                after_mode = source.mode if source else None
            approved_edits.append(InitialApprovedEdit(
                edit.edit_id, edit.operation, edit.path, edit.destination_path,
                after_hash, after_mode,
            ))
        return InitialWorkspaceAttestation(
            run.execution_run_id, run.plan_id, run.edit_bundle_digest,
            context.execution_context_id, context.lease_id, context.binding_digest,
            run.task_id, run.workspace_id, run.repository_id, git_state.head_commit,
            git_state.repository_generation, git_state.index_digest,
            git_state.worktree_admin_identity,
            self._workspace_state_digest(git_state.file_states), tuple(states),
            workspace_states, time.time(), approved_edits=tuple(approved_edits),
        ).normalized()

    def _require_initial_attestation(self, run: PlanExecutionRun) -> InitialWorkspaceAttestation:
        try:
            value = self._store.get_initial_workspace_attestation(run.execution_run_id)
        except RuntimeError as exc:
            raise WorkspaceMutationError("initial-attestation-invalid", "initial baseline invalid") from exc
        if value is None or (value.plan_id, value.bundle_digest, value.context_id,
                             value.lease_id, value.binding_digest) != (
            run.plan_id, run.edit_bundle_digest, run.execution_context_id,
            run.lease_id, run.binding_digest,
        ):
            raise WorkspaceMutationError("initial-attestation-missing", "initial baseline missing")
        return value

    def _build_rollback_attestation(
        self, run: PlanExecutionRun, workspace: Any, handle: WorkspacePathHandle,
        events: tuple[Any, ...], journal_digest: str, reason: str,
        baseline: InitialWorkspaceAttestation,
    ) -> RollbackFinalAttestation:
        state = self._context_provider.current_state(
            repository_id=run.repository_id, task_id=run.task_id,
            workspace_id=run.workspace_id,
        )
        git_state = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        current_states = {item.relative_path: item for item in git_state.file_states}
        states: list[AttestedPathState] = []
        for expected in baseline.declared_states:
            current = current_states.get(expected.path)
            if not expected.exists:
                if current is not None:
                    raise WorkspaceMutationError(
                        "rollback-attestation-drift",
                        "baseline-missing declared path now exists",
                    )
                states.append(AttestedPathState(expected.path, False))
                continue
            if (current is None or current.file_type != expected.file_type
                    or current.content_hash != expected.content_hash
                    or current.mode != expected.mode):
                raise WorkspaceMutationError(
                    "rollback-attestation-drift",
                    "declared path differs from initial baseline",
                )
            states.append(AttestedPathState(
                expected.path, True, expected.content_hash, expected.mode,
            ))
        declared_paths = {item.path for item in baseline.declared_states}
        baseline_undeclared = {
            item.path: item for item in baseline.workspace_states
            if item.path not in declared_paths
        }
        current_undeclared = {
            path: item for path, item in current_states.items()
            if path not in declared_paths
        }
        undeclared_equal = set(baseline_undeclared) == set(current_undeclared) and all(
            (before.content_hash, before.mode, before.file_type, before.identity_digest) ==
            (current_undeclared[path].content_hash, current_undeclared[path].mode,
             current_undeclared[path].file_type, current_undeclared[path].identity_digest)
            for path, before in baseline_undeclared.items()
        )
        if (git_state.head_commit != baseline.head
                or git_state.repository_generation != baseline.generation
                or git_state.index_digest != baseline.index_digest
                or git_state.worktree_admin_identity != baseline.worktree_admin_identity
                or not undeclared_equal):
            raise WorkspaceMutationError(
                "rollback-workspace-drift", "workspace did not return to persisted baseline"
            )
        return RollbackFinalAttestation(
            execution_run_id=run.execution_run_id,
            bundle_digest=run.edit_bundle_digest,
            ordered_states=tuple(states), path_state_digest="",
            head=git_state.head_commit, generation=git_state.repository_generation,
            index_digest=git_state.index_digest,
            worktree_admin_digest=git_state.worktree_admin_identity,
            workspace_state_digest=self._workspace_state_digest(git_state.file_states),
            execution_context_id=run.execution_context_id,
            lease_id=run.lease_id, binding_digest=run.binding_digest,
            attested_at=time.time(), rollback_reason=reason,
            journal_digest=journal_digest,
        ).normalized()

    def _validate_sealing_recovery(
        self, run: PlanExecutionRun, workspace: Any, events: tuple[Any, ...],
        journal_digest: str,
    ) -> FinalMutationAttestation:
        try:
            attestation = self._store.get_final_mutation_attestation(
                run.execution_run_id
            )
        except RuntimeError as exc:
            raise WorkspaceMutationError(
                "attestation-invalid", "final attestation failed integrity validation"
            ) from exc
        if attestation is None:
            raise WorkspaceMutationError(
                "attestation-missing", "sealing run has no final attestation"
            )
        if (attestation.execution_run_id != run.execution_run_id
                or attestation.bundle_digest != run.edit_bundle_digest
                or attestation.execution_context_id != run.execution_context_id
                or attestation.lease_id != run.lease_id
                or attestation.binding_digest != run.binding_digest):
            raise WorkspaceMutationError(
                "attestation-binding-mismatch", "attestation binding drifted"
            )
        handle = WorkspacePathHandle(workspace.worktree_path.resolve(strict=True))
        try:
            states = self._attested_states(handle, events)
        finally:
            handle.close()
        if tuple(state.canonical() for state in states) != tuple(
            state.canonical() for state in attestation.ordered_states
        ):
            raise WorkspaceMutationError(
                "attestation-state-drift", "declared final state drifted"
            )
        state = self._context_provider.current_state(
            repository_id=run.repository_id, task_id=run.task_id,
            workspace_id=run.workspace_id,
        )
        git_state = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        if (git_state.head_commit != attestation.head
                or git_state.repository_generation != attestation.generation
                or git_state.index_digest != attestation.index_digest
                or git_state.worktree_admin_identity != attestation.worktree_admin_digest
                or self._workspace_state_digest(git_state.file_states)
                != attestation.workspace_state_digest):
            raise WorkspaceMutationError(
                "attestation-repository-drift", "repository state drifted after attestation"
            )
        return attestation

    def _validate_rollback_sealing_recovery(
        self, run: PlanExecutionRun, workspace: Any, events: tuple[Any, ...],
        journal_digest: str,
    ) -> RollbackFinalAttestation:
        try:
            attestation = self._store.get_rollback_final_attestation(
                run.execution_run_id
            )
        except RuntimeError as exc:
            raise WorkspaceMutationError(
                "rollback-attestation-invalid", "rollback attestation is invalid"
            ) from exc
        if attestation is None or attestation.journal_digest != journal_digest:
            raise WorkspaceMutationError(
                "rollback-attestation-missing", "rollback proof is missing"
            )
        if (attestation.bundle_digest != run.edit_bundle_digest
                or attestation.execution_context_id != run.execution_context_id
                or attestation.lease_id != run.lease_id
                or attestation.binding_digest != run.binding_digest):
            raise WorkspaceMutationError(
                "rollback-attestation-binding", "rollback proof binding drifted"
            )
        baseline = self._require_initial_attestation(run)
        baseline_states = tuple(sorted((
            AttestedPathState(
                item.path, item.exists, item.content_hash if item.exists else "",
                item.mode if item.exists else None,
            ) for item in baseline.declared_states
        ), key=lambda item: item.path))
        if tuple(item.canonical() for item in attestation.ordered_states) != tuple(
            item.canonical() for item in baseline_states
        ):
            raise WorkspaceMutationError(
                "rollback-attestation-baseline",
                "rollback proof differs from initial baseline",
            )
        handle = WorkspacePathHandle(workspace.worktree_path.resolve(strict=True))
        try:
            actual: list[AttestedPathState] = []
            for expected in attestation.ordered_states:
                content_hash, mode, _ = self._current_target(handle, expected.path)
                actual.append(AttestedPathState(
                    expected.path, content_hash is not None, content_hash or "", mode,
                ))
        finally:
            handle.close()
        if tuple(item.canonical() for item in actual) != tuple(
            item.canonical() for item in attestation.ordered_states
        ):
            raise WorkspaceMutationError(
                "rollback-attestation-drift", "rollback final paths drifted"
            )
        state = self._context_provider.current_state(
            repository_id=run.repository_id, task_id=run.task_id,
            workspace_id=run.workspace_id,
        )
        git_state = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        if (git_state.head_commit != attestation.head
                or git_state.repository_generation != attestation.generation
                or git_state.index_digest != attestation.index_digest
                or git_state.worktree_admin_identity != attestation.worktree_admin_digest
                or self._workspace_state_digest(git_state.file_states)
                != attestation.workspace_state_digest):
            raise WorkspaceMutationError(
                "rollback-repository-drift", "rollback repository state drifted"
            )
        return attestation

    def _poison_run(self, workspace_id: str, run_id: str, reason: str) -> None:
        owner = f"run:{run_id}"
        self._fence.poison(workspace_id, reason, owner=owner)
        self._store.add_workspace_poison_scope(
            workspace_id, owner=owner, reason=reason
        )

    def _validated_journal(self, run: PlanExecutionRun, *, allow_partial: bool = False) -> ValidatedRecoveryJournal:
        try:
            safe_run = SafeRecoveryRunId.parse(run.execution_run_id)
            rows = self._store.list_execution_edit_events(run.execution_run_id)
            if not rows:
                raise UnsafePersistedIdentifier("execution journal is missing")
            persisted_count, actual_count = self._store.execution_journal_progress(
                run.execution_run_id
            )
            if persisted_count != actual_count or actual_count != len(rows):
                raise UnsafePersistedIdentifier("journal progress mismatch")
            if not isinstance(run.metadata.get("edit_count"), int) or isinstance(run.metadata.get("edit_count"), bool):
                raise UnsafePersistedIdentifier("edit count missing")
            expected_count = run.metadata["edit_count"]
            if expected_count <= 0 or (len(rows) > expected_count
                    or (not allow_partial and expected_count != len(rows))):
                raise UnsafePersistedIdentifier("journal event count mismatch")
            ordinals = [row["ordinal"] for row in rows]
            if any(not isinstance(item, int) for item in ordinals) or ordinals != list(range(len(rows))):
                raise UnsafePersistedIdentifier("journal ordinals are not contiguous")
            if len({row["edit_id"] for row in rows}) != len(rows):
                raise UnsafePersistedIdentifier("journal edit ids are not unique")
            baseline = self._require_initial_attestation(run)
            baseline_paths = {item.path: item for item in baseline.declared_states}
            approved_edits = {item.edit_id: item for item in baseline.approved_edits}
            if len(approved_edits) != expected_count:
                raise UnsafePersistedIdentifier("approved edit baseline is incomplete")
            events: list[ValidatedRecoveryEvent] = []
            seen_paths: set[str] = set()
            seen_artifacts: set[str] = set()
            hash_re = re.compile(r"^[0-9a-f]{64}$")
            phases = {
                "journaled", "mutation-started", "filesystem-applied",
                "directory-synced", "applied", "rollback-started",
                "rollback-filesystem-applied", "rollback-directory-synced",
                "rolled-back",
            }
            for row in rows:
                try: operation = PlannedEditOperation(row["operation"])
                except ValueError:
                    raise UnsafePersistedIdentifier("journal operation invalid")
                if row["path"] != unicodedata.normalize("NFC", row["path"]):
                    raise UnsafePersistedIdentifier("journal path is not NFC")
                path = SafeWorkspaceRelativePath.parse(row["path"])
                destination = row["destination_path"]
                if destination is not None:
                    if destination != unicodedata.normalize("NFC", destination):
                        raise UnsafePersistedIdentifier("journal destination is not NFC")
                    destination = SafeWorkspaceRelativePath.parse(destination)
                artifact = row["recovery_artifact"]
                if artifact is not None:
                    artifact = SafeRecoveryArtifactName.parse(artifact)
                before_hash, after_hash = row["before_hash"] or "", row["after_hash"] or ""
                before_mode, after_mode = row["before_mode"], row["after_mode"]
                for digest in (before_hash, after_hash):
                    if digest and not hash_re.fullmatch(digest): raise UnsafePersistedIdentifier("journal hash invalid")
                for mode in (before_mode, after_mode):
                    if mode is not None and (type(mode) is not int or mode < 0 or mode > 0o777):
                        raise UnsafePersistedIdentifier("journal mode invalid")
                if row["status"] not in phases: raise UnsafePersistedIdentifier("durable phase invalid")
                phase_version = row["phase_version"]
                identity_version = row["identity_version"]
                identity_fields = tuple(str(row[name] or "") for name in (
                    "applied_identity_digest",
                    "applied_parent_identity_digest",
                    "applied_destination_identity_digest",
                    "rollback_identity_digest",
                ))
                rollback_parent_fields = tuple(str(row[name] or "") for name in (
                    "rollback_parent_identity_digest",
                    "rollback_destination_parent_identity_digest",
                    "rollback_directory_sync_digest",
                ))
                if any(
                    value and not hash_re.fullmatch(value)
                    for value in identity_fields + rollback_parent_fields
                ):
                    raise UnsafePersistedIdentifier("identity digest invalid")
                rollback_sync_mask = row["rollback_sync_mask"]
                rollback_synced_at = row["rollback_synced_at"]
                if (type(rollback_sync_mask) is not int
                        or rollback_sync_mask not in {0, 1, 3}):
                    raise UnsafePersistedIdentifier("rollback sync mask invalid")
                if (rollback_synced_at is not None
                        and (not isinstance(rollback_synced_at, (int, float))
                             or isinstance(rollback_synced_at, bool)
                             or rollback_synced_at <= 0)):
                    raise UnsafePersistedIdentifier("rollback sync time invalid")
                phase_versions = {
                    "journaled": frozenset({0}),
                    "mutation-started": frozenset({1}),
                    "filesystem-applied": frozenset({2}),
                    "directory-synced": frozenset({3}),
                    "applied": frozenset({4}),
                    "rollback-started": frozenset({3, 4, 5}),
                    "rollback-filesystem-applied": frozenset({4, 5, 6, 7}),
                    "rollback-directory-synced": frozenset({5, 6, 7, 8}),
                    "rolled-back": frozenset({1, 2, 4, 5, 6, 7, 8}),
                }
                if (type(phase_version) is not int
                        or phase_version not in phase_versions[row["status"]]):
                    raise UnsafePersistedIdentifier("durable phase version invalid")
                if (type(identity_version) is not int
                        or identity_version not in {0, 1, 2, 3}):
                    raise UnsafePersistedIdentifier("identity version invalid")
                applied_phases = {
                    "filesystem-applied", "directory-synced", "applied",
                    "rollback-started", "rollback-filesystem-applied",
                    "rollback-directory-synced",
                }
                requires_applied_identity = (
                    row["status"] in applied_phases
                    or (row["status"] == "rolled-back" and phase_version > 2)
                )
                if requires_applied_identity:
                    if identity_version < 1 or not identity_fields[1]:
                        raise UnsafePersistedIdentifier("applied identity evidence missing")
                    if operation != PlannedEditOperation.DELETE and not identity_fields[0]:
                        raise UnsafePersistedIdentifier("applied object identity missing")
                    if (operation == PlannedEditOperation.RENAME
                            and not identity_fields[2]):
                        raise UnsafePersistedIdentifier("rename identity evidence missing")
                elif identity_version != 0 or any(identity_fields):
                    raise UnsafePersistedIdentifier("premature identity evidence")
                rollback_phase = row["status"]
                has_rollback_identity = bool(identity_fields[3])
                has_parent_evidence = bool(rollback_parent_fields[0])
                has_sync_evidence = bool(rollback_parent_fields[2])
                if has_sync_evidence:
                    expected_sync_digest = (
                        self._store._rollback_directory_sync_digest(
                            execution_run_id=run.execution_run_id,
                            edit_id=row["edit_id"],
                            parent_identity_digest=rollback_parent_fields[0],
                            destination_parent_identity_digest=(
                                rollback_parent_fields[1]
                            ),
                            sync_mask=rollback_sync_mask,
                        )
                    )
                    if rollback_parent_fields[2] != expected_sync_digest:
                        raise UnsafePersistedIdentifier(
                            "rollback directory sync digest mismatch"
                        )
                if rollback_phase in {
                    "rollback-filesystem-applied", "rollback-directory-synced",
                }:
                    if (identity_version < 2 or not has_rollback_identity
                            or not has_parent_evidence
                            or rollback_sync_mask not in {1, 3}):
                        raise UnsafePersistedIdentifier(
                            "rollback filesystem evidence missing"
                        )
                    if (operation == PlannedEditOperation.RENAME
                            and not rollback_parent_fields[1]):
                        raise UnsafePersistedIdentifier(
                            "rename rollback parent evidence missing"
                        )
                    if (operation != PlannedEditOperation.RENAME
                            and (rollback_parent_fields[1]
                                 or rollback_sync_mask != 1)):
                        raise UnsafePersistedIdentifier(
                            "rollback parent scope invalid"
                        )
                if rollback_phase == "rollback-filesystem-applied":
                    if (has_sync_evidence or rollback_synced_at is not None
                            or identity_version != 2):
                        raise UnsafePersistedIdentifier(
                            "premature rollback sync evidence"
                        )
                elif rollback_phase == "rollback-directory-synced":
                    if (not has_sync_evidence or rollback_synced_at is None
                            or identity_version != 3):
                        raise UnsafePersistedIdentifier(
                            "rollback directory sync evidence missing"
                        )
                elif rollback_phase == "rolled-back" and phase_version > 2:
                    if not has_rollback_identity:
                        raise UnsafePersistedIdentifier(
                            "rollback identity evidence missing"
                        )
                    # Batch 3.0.6 terminal rows remain readable.  Incomplete
                    # runs are upgraded and fsynced before terminalization.
                    if identity_version == 3:
                        if (not has_parent_evidence or not has_sync_evidence
                                or rollback_synced_at is None
                                or rollback_sync_mask not in {1, 3}
                                or (operation == PlannedEditOperation.RENAME
                                    and not rollback_parent_fields[1])
                                or (operation != PlannedEditOperation.RENAME
                                    and (rollback_parent_fields[1]
                                         or rollback_sync_mask != 1))):
                            raise UnsafePersistedIdentifier(
                                "rollback directory sync evidence missing"
                            )
                    elif identity_version != 2:
                        raise UnsafePersistedIdentifier(
                            "rollback identity version invalid"
                        )
                elif has_rollback_identity or identity_version == 2:
                    if rollback_phase != "rollback-started":
                        raise UnsafePersistedIdentifier(
                            "rollback identity phase mismatch"
                        )
                    if (has_parent_evidence or rollback_parent_fields[1]
                            or has_sync_evidence or rollback_sync_mask
                            or rollback_synced_at is not None):
                        raise UnsafePersistedIdentifier(
                            "legacy rollback evidence is inconsistent"
                        )
                elif (has_parent_evidence or rollback_parent_fields[1]
                      or has_sync_evidence or rollback_sync_mask
                      or rollback_synced_at is not None):
                    raise UnsafePersistedIdentifier(
                        "rollback evidence appears before rollback syscall"
                    )
                if operation == PlannedEditOperation.CREATE:
                    valid = not before_hash and before_mode is None and artifact is None and destination is None and after_hash and after_mode is not None
                elif operation == PlannedEditOperation.UPDATE:
                    valid = bool(before_hash and after_hash and before_mode is not None and after_mode is not None and artifact and destination is None)
                elif operation == PlannedEditOperation.DELETE:
                    valid = bool(before_hash and before_mode is not None and artifact and not after_hash and after_mode is None and destination is None)
                else:
                    valid = bool(before_hash and before_mode is not None and after_hash and after_mode is not None and artifact and destination and destination.value != path.value)
                if not valid: raise UnsafePersistedIdentifier("operation journal fields invalid")
                before = baseline_paths.get(path.value)
                approved = approved_edits.get(row["edit_id"])
                if approved is None or (
                    approved.operation != operation
                    or approved.path != path.value
                    or approved.destination_path
                    != (destination.value if destination else None)
                    or approved.after_hash != after_hash
                    or approved.after_mode != after_mode
                ):
                    raise UnsafePersistedIdentifier("journal edit exceeds approved baseline")
                if operation == PlannedEditOperation.CREATE:
                    if before is None or before.exists or before.file_type != "missing":
                        raise UnsafePersistedIdentifier("create source existed in baseline")
                else:
                    if (before is None or not before.exists
                            or before.file_type != "regular"
                            or before_hash != before.content_hash
                            or before_mode != before.mode):
                        raise UnsafePersistedIdentifier("journal before state differs from baseline")
                if operation == PlannedEditOperation.RENAME:
                    destination_before = baseline_paths.get(destination.value)
                    if (destination_before is None or destination_before.exists
                            or destination_before.file_type != "missing"):
                        raise UnsafePersistedIdentifier("rename destination existed in baseline")
                if artifact is not None:
                    if artifact.value in seen_artifacts:
                        raise UnsafePersistedIdentifier("recovery artifact is reused")
                    seen_artifacts.add(artifact.value)
                keys = [path.value.casefold()] + ([destination.value.casefold()] if destination else [])
                if any(key in seen_paths for key in keys): raise UnsafePersistedIdentifier("journal path conflict")
                seen_paths.update(keys)
                events.append(ValidatedRecoveryEvent(
                    row["ordinal"], row["edit_id"], operation, path, destination,
                    before_hash, after_hash, before_mode, after_mode, artifact,
                    row["status"], phase_version, *identity_fields,
                    identity_version, run.execution_run_id,
                    *rollback_parent_fields[:2], rollback_sync_mask,
                    rollback_parent_fields[2], rollback_synced_at,
                ))
        except (UnsafePersistedIdentifier, TypeError, ValueError) as exc:
            raise WorkspaceMutationError(
                "recovery-journal-invalid", "persisted recovery journal is invalid"
            ) from exc
        canonical = [event.__dict__ | {
            "operation": event.operation.value, "path": event.path.value,
            "destination": event.destination.value if event.destination else None,
            "artifact": event.artifact.value if event.artifact else None,
        } for event in events]
        digest = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str,
        ).encode("utf-8")).hexdigest()
        return ValidatedRecoveryJournal(safe_run, tuple(events), digest)

    def _recover_zero_journal_run(
        self, run: PlanExecutionRun, workspace: Any, owner: str,
    ) -> RecoveryDirectory:
        """Terminalize only a proven crash before the first durable edit."""
        baseline = self._require_initial_attestation(run)
        persisted_count, actual_count = self._store.execution_journal_progress(
            run.execution_run_id
        )
        if persisted_count != 0 or actual_count != 0:
            raise WorkspaceMutationError(
                "zero-journal-progress-mismatch", "journal progress is not zero"
            )
        recovery = self._open_recovery(
            workspace, run.execution_run_id, (), allow_missing_run=True,
        )
        if recovery.run_entries():
            raise WorkspaceMutationError(
                "zero-journal-recovery-evidence",
                "unknown recovery evidence exists without a journal",
            )
        for kind in ("mutation", "rolled-back", "cancelled", "failed"):
            if recovery.tombstone_exists(self._tombstone_name(
                run.execution_run_id, kind
            )):
                raise WorkspaceMutationError(
                    "zero-journal-tombstone", "terminal evidence already exists"
                )
        state = self._context_provider.current_state(
            repository_id=run.repository_id, task_id=run.task_id,
            workspace_id=run.workspace_id,
        )
        first = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        second = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        if first != second:
            raise WorkspaceMutationError(
                "zero-journal-state-unstable", "workspace state is unstable"
            )
        current_states = tuple(InitialPathState(
            item.relative_path, True, item.content_hash, item.mode,
            item.file_type, item.identity_digest,
        ) for item in first.file_states)
        if (first.head_commit != baseline.head
                or first.repository_generation != baseline.generation
                or first.index_digest != baseline.index_digest
                or first.worktree_admin_identity
                != baseline.worktree_admin_identity
                or self._workspace_state_digest(first.file_states)
                != baseline.workspace_state_digest
                or current_states != baseline.workspace_states):
            raise WorkspaceMutationError(
                "zero-journal-workspace-drift",
                "workspace differs from initial baseline",
            )
        if recovery.run_exists:
            recovery.seal()
        terminal = (
            "cancelled" if run.failure_code == "execution-context-invalid"
            else "failed"
        )
        self._store.commit_recovered_no_mutation(
            execution_run_id=run.execution_run_id,
            workspace_id=run.workspace_id, poison_owner=owner,
            expected_status=run.status.value, terminal_status=terminal,
            baseline_digest=baseline.attestation_digest,
        )
        return recovery

    def recover_incomplete_runs(self) -> tuple[str, ...]:
        """Startup scan: quarantine incomplete runs; recover only intact journals."""
        recovered: list[str] = []
        for run in self._store.list_incomplete_execution_runs():
            reason = "startup-incomplete-execution"
            owner = f"run:{run.execution_run_id}"
            self._poison_run(run.workspace_id, run.execution_run_id, reason)
            workspace = self._workspaces.get(run.workspace_id)
            if workspace is None:
                continue
            recovery: RecoveryDirectory | None = None
            with self._fence.use_sync(
                run.workspace_id, owner=f"recovery:{run.execution_run_id}"
            ):
                try:
                    if not self._store.list_execution_edit_events(
                        run.execution_run_id
                    ):
                        recovery = self._recover_zero_journal_run(
                            run, workspace, owner,
                        )
                        self._fence.clear_poison(run.workspace_id, owner=owner)
                        recovered.append(run.execution_run_id)
                        continue
                    journal = self._validated_journal(run)
                    events, journal_digest = journal.events, journal.canonical_digest
                    for event in events:
                        self._resolve_safe_path(workspace, event["path"])
                        if event["destination_path"]:
                            self._resolve_safe_path(
                                workspace, event["destination_path"]
                            )
                    recovery = self._open_recovery(
                        workspace, run.execution_run_id, events,
                        allow_missing_run=run.status in {
                            ExecutionRunStatus.SEALING,
                            ExecutionRunStatus.ROLLBACK_SEALING,
                        },
                    )
                    self._active_recovery = recovery
                    if run.status == ExecutionRunStatus.SEALING:
                        attestation = self._validate_sealing_recovery(
                            run, workspace, events, journal_digest,
                        )
                        if recovery.run_exists:
                            self._seal_recovery(
                                recovery, run.workspace_id, run.execution_run_id,
                            )
                            tombstone_name, tombstone = self._write_seal_tombstone(
                                recovery, run, "mutation",
                                attestation.attestation_digest, journal_digest,
                            )
                        else:
                            tombstone_name, tombstone = self._read_seal_tombstone(
                                recovery, run, "mutation",
                                attestation.attestation_digest, journal_digest,
                            )
                        self._store.commit_recovered_terminal_state(
                            execution_run_id=run.execution_run_id,
                            workspace_id=run.workspace_id, poison_owner=owner,
                            expected_status="sealing",
                            terminal_status="mutated",
                            seal_digest=self._recovery_seal_digest(run.execution_run_id),
                            tombstone_digest=tombstone.tombstone_digest,
                            rollback=False,
                            attestation_digest=attestation.attestation_digest,
                        )
                        try:
                            recovery.delete_tombstone(tombstone_name)
                        except OSError:
                            pass
                    elif run.status == ExecutionRunStatus.ROLLBACK_SEALING:
                        attestation = self._validate_rollback_sealing_recovery(
                            run, workspace, events, journal_digest,
                        )
                        final_status = (
                            "cancelled" if run.failure_code == "execution-context-invalid"
                            else "rolled-back"
                        )
                        if recovery.run_exists:
                            recovery.seal()
                            tombstone_name, tombstone = self._write_seal_tombstone(
                                recovery, run, final_status,
                                attestation.attestation_digest, journal_digest,
                            )
                        else:
                            tombstone_name, tombstone = self._read_seal_tombstone(
                                recovery, run, final_status,
                                attestation.attestation_digest, journal_digest,
                            )
                        self._store.commit_recovered_terminal_state(
                            execution_run_id=run.execution_run_id,
                            workspace_id=run.workspace_id, poison_owner=owner,
                            expected_status="rollback-sealing",
                            terminal_status=final_status,
                            seal_digest=self._recovery_seal_digest(run.execution_run_id),
                            tombstone_digest=tombstone.tombstone_digest,
                            rollback=True, failure_code=run.failure_code,
                            attestation_digest=attestation.attestation_digest,
                        )
                        try:
                            recovery.delete_tombstone(tombstone_name)
                        except OSError:
                            pass
                    else:
                        self._rollback(
                            run.execution_run_id,
                            workspace.worktree_path.resolve(strict=True), recovery,
                            run.workspace_id, failure_code="startup-recovery",
                            recovered=True,
                        )
                    self._fence.clear_poison(run.workspace_id, owner=owner)
                    recovered.append(run.execution_run_id)
                except Exception as exc:
                    current = self._store.get_execution_run(run.execution_run_id)
                    if current is not None and current.status not in {
                        ExecutionRunStatus.POISONED, ExecutionRunStatus.MUTATED,
                    }:
                        try:
                            self._store.transition_execution_run(
                                run.execution_run_id,
                                expected=(current.status.value,), target="poisoned",
                                failure_code=getattr(exc, "code", "recovery-evidence-invalid"),
                                completed=True,
                            )
                        except Exception:
                            pass
                finally:
                    self._active_recovery = None
                    if recovery is not None:
                        recovery.close()
        return tuple(recovered)

    def _prepare_recovery(self, workspace: Any, run_id: str) -> RecoveryDirectory:
        container = self._validate_recovery_container(workspace)
        capability = self._recovery_capabilities.get(workspace.id)
        if capability is None:
            capability = RecoveryRootCapability(container)
            self._recovery_capabilities[workspace.id] = capability
        try:
            return RecoveryDirectory(container, run_id, create=True, root_capability=capability)
        except (OSError, RecoveryDirectoryError) as exc:
            raise WorkspaceMutationError(
                "recovery-root-invalid", "recovery directory cannot be created safely"
            ) from exc

    def _open_recovery(
        self, workspace: Any, run_id: str, events: tuple[Any, ...],
        *, allow_missing_run: bool = False,
    ) -> RecoveryDirectory:
        container = self._validate_recovery_container(workspace)
        capability = self._recovery_capabilities.get(workspace.id)
        if capability is None:
            capability = RecoveryRootCapability(container)
            self._recovery_capabilities[workspace.id] = capability
        allowed = frozenset(
            row["recovery_artifact"] for row in events if row["recovery_artifact"]
        )
        try:
            return RecoveryDirectory(
                container, run_id, create=False, allowed_artifacts=allowed,
                allow_missing_run=allow_missing_run,
                root_capability=capability,
            )
        except (OSError, RecoveryDirectoryError) as exc:
            raise WorkspaceMutationError(
                "recovery-root-invalid", "recovery directory cannot be opened safely"
            ) from exc

    def _seal_recovery(
        self, recovery: RecoveryDirectory, workspace_id: str, run_id: str,
    ) -> None:
        try:
            recovery.seal()
        except Exception as exc:
            reason = f"recovery-cleanup-failed:{type(exc).__name__}"
            self._poison_run(workspace_id, run_id, reason)
            raise WorkspaceMutationError(reason, "recovery cleanup failed") from exc

    @staticmethod
    def _validate_recovery_container(workspace: Any) -> Path:
        configured = getattr(workspace, "recovery_root", None)
        if configured is None:
            raise WorkspaceMutationError(
                "recovery-root-unconfigured", "workspace recovery root is not configured"
            )
        worktree = workspace.worktree_path.resolve(strict=True)
        repository = workspace.repository_root.resolve(strict=True)
        container = Path(configured)
        if not container.is_absolute():
            raise WorkspaceMutationError("recovery-root-symlink", "recovery container parent is unsafe")
        current = Path(container.anchor)
        for part in container.parent.parts[1:]:
            current /= part
            if current.is_symlink():
                raise WorkspaceMutationError(
                    "recovery-root-symlink", "recovery container ancestor is symlinked"
                )
        resolved_parent = container.parent.resolve(strict=True)
        resolved = resolved_parent / container.name
        if worktree == resolved or worktree in resolved.parents or resolved in worktree.parents:
            raise WorkspaceMutationError("recovery-inside-worktree", "recovery is inside worktree")
        if repository == resolved or repository in resolved.parents or resolved in repository.parents:
            raise WorkspaceMutationError("recovery-inside-repository", "recovery is inside repository")
        git_marker = worktree / ".git"
        if git_marker.is_file():
            text = git_marker.read_text(encoding="utf-8", errors="strict").strip()
            if text.startswith("gitdir:"):
                admin = (worktree / text.split(":", 1)[1].strip()).resolve(strict=False)
                if admin == resolved or admin in resolved.parents or resolved in admin.parents:
                    raise WorkspaceMutationError(
                        "recovery-inside-git-admin", "recovery intersects Git admin root"
                    )
        return resolved

    def _recovery_seal_digest(self, run_id: str) -> str:
        events = self._store.list_execution_edit_events(run_id)
        payload = "|".join(
            f"{row['edit_id']}:{row['status']}:{row['before_hash'] or ''}:"
            f"{row['after_hash'] or ''}" for row in events
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @staticmethod
    def _tombstone_name(run_id: str, seal_kind: str) -> str:
        digest = hashlib.sha256(f"{run_id}:{seal_kind}".encode("utf-8")).hexdigest()
        return f"seal-{digest[:32]}.json"

    def _write_seal_tombstone(
        self, recovery: RecoveryDirectory, run: PlanExecutionRun,
        seal_kind: str, attestation_digest: str, journal_digest: str,
    ) -> tuple[str, MutationSealTombstone]:
        tombstone = MutationSealTombstone(
            execution_run_id=run.execution_run_id, seal_kind=seal_kind,
            bundle_digest=run.edit_bundle_digest,
            attestation_digest=attestation_digest,
            journal_digest=journal_digest,
            recovery_container_identity=recovery.container_identity,
            sealed_at=time.time(),
        ).normalized()
        name = self._tombstone_name(run.execution_run_id, seal_kind)
        payload = {
            **{key: value for key, value in tombstone.__dict__.items()},
        }
        recovery.write_tombstone(name, payload)
        return name, tombstone

    def _read_seal_tombstone(
        self, recovery: RecoveryDirectory, run: PlanExecutionRun,
        seal_kind: str, attestation_digest: str, journal_digest: str,
    ) -> tuple[str, MutationSealTombstone]:
        name = self._tombstone_name(run.execution_run_id, seal_kind)
        try:
            payload = recovery.read_tombstone(name)
            value = MutationSealTombstone(**payload).normalized()
        except (OSError, TypeError, ValueError, RecoveryDirectoryError) as exc:
            raise WorkspaceMutationError(
                "seal-tombstone-invalid", "terminal seal tombstone is invalid"
            ) from exc
        if (value.execution_run_id != run.execution_run_id
                or value.seal_kind != seal_kind
                or value.bundle_digest != run.edit_bundle_digest
                or value.attestation_digest != attestation_digest
                or value.journal_digest != journal_digest
                or value.recovery_container_identity != recovery.container_identity
                or value.tombstone_digest != payload.get("tombstone_digest")):
            raise WorkspaceMutationError(
                "seal-tombstone-invalid", "terminal seal tombstone binding mismatch"
            )
        return name, value

    @staticmethod
    def _unexpected_changes(
        before: dict[str, str], after: dict[str, str], allowed: frozenset[str]
    ) -> tuple[str, ...]:
        changed = {
            path for path in set(before) | set(after)
            if before.get(path) != after.get(path)
        }
        return tuple(sorted(changed - allowed))

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
