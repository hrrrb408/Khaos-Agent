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
    MutationSealTombstone,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
    RollbackFinalAttestation,
    WorkspaceMutationResult,
)
from khaos.coding.workspace.models import WorkspaceState
from khaos.coding.planning.safe_workspace_path import (
    SafePathError,
    WorkspacePathHandle,
)
from khaos.coding.planning.git_state import GitStateInspector
from khaos.coding.planning.recovery_directory import (
    RecoveryDirectory,
    RecoveryDirectoryError,
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
                self._active_phase = lambda phase, run_id=run.execution_run_id, edit_id=edit.edit_id: self._store.update_edit_event(
                    run_id, edit_id, status=phase,
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
            _, journal_digest = self._validated_journal(run)
            self._validate_sealing_recovery(
                run, workspace, self._store.list_execution_edit_events(run.execution_run_id),
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
            self._rollback(
                run.execution_run_id, root, recovery,
                workspace.id, failure_code=code,
                poison_after=(code == "unexpected-workspace-mutation"),
                baseline_git=before_git,
            )
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
        if compute_plan_binding_digest(plan) != context.binding_digest:
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

    def _rollback(
        self, run_id: str, root: Path, recovery: RecoveryDirectory, workspace_id: str, *, failure_code: str,
        poison_after: bool = False, baseline_git: Any | None = None,
    ) -> None:
        try:
            current_run = self._store.get_execution_run(run_id)
            self._store.transition_execution_run(
                run_id, expected=(current_run.status.value,), target="rolling-back",
                failure_code=failure_code,
            )
            handle = self._active_path_handle or WorkspacePathHandle(root)
            owns_handle = self._active_path_handle is None
            for event in reversed(self._store.list_execution_edit_events(run_id)):
                self._rollback_event(handle, event, recovery)
                current_hash, current_mode, _ = self._current_target(handle, event["path"])
                self._store.update_edit_event(
                    run_id, event["edit_id"], status="rolled-back",
                    after_hash=current_hash or "", after_mode=current_mode,
                    error_code=failure_code,
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
            events, journal_digest = self._validated_journal(current_run)
            workspace = self._workspaces.get(workspace_id)
            rollback_attestation = self._build_rollback_attestation(
                current_run, workspace, handle, events, journal_digest,
                failure_code, baseline_git,
            )
            self._store.save_rollback_final_attestation(rollback_attestation)
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
            self._store.commit_terminal_seal(
                run_id, expected_status="rollback-sealing",
                terminal_status=target,
                seal_digest=self._recovery_seal_digest(run_id),
                tombstone_digest=tombstone.tombstone_digest, rollback=True,
                failure_code=failure_code,
            )
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
                self._store.transition_execution_run(
                    run_id, expected=("rolling-back", "rollback-sealing"),
                    target="poisoned", failure_code=reason, completed=True,
                )
            except Exception:
                pass
            raise WorkspaceMutationError(reason, "rollback failed") from rollback_error

    def _rollback_event(
        self, handle: WorkspacePathHandle, event: Any,
        recovery: RecoveryDirectory,
    ) -> None:
        operation = event["operation"]
        before_hash = event["before_hash"] or None
        after_hash = event["after_hash"] or None
        current_hash, current_mode, current_inode = self._current_target(handle, event["path"])
        no_phase = lambda phase: None
        if operation == "create":
            if current_hash is None:
                return
            if current_hash != after_hash or current_mode != event["after_mode"]:
                raise WorkspaceMutationError("rollback-third-party", "create target has third-party content")
            handle.delete(event["path"], current_inode, no_phase)
            return
        if operation == "rename":
            destination = event["destination_path"]
            dest_hash, dest_mode, dest_inode = self._current_target(handle, destination)
            if current_hash == before_hash and dest_hash is None:
                return
            if (current_hash is None and dest_hash == after_hash
                    and dest_mode == event["after_mode"]):
                handle.rename_no_replace(destination, event["path"], dest_inode, no_phase)
                return
            if (current_hash == before_hash and dest_hash == after_hash
                    and dest_mode == event["after_mode"]):
                handle.delete(destination, dest_inode, no_phase)
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
        if current_hash == before_hash:
            return
        mode = int(event["before_mode"] or 0o600)
        if operation == "update":
            if (current_hash != after_hash or current_mode != event["after_mode"]
                    or current_inode is None):
                raise WorkspaceMutationError("rollback-third-party", "updated target has third-party content")
            handle.update(event["path"], data, mode, current_inode, no_phase)
        elif operation == "delete":
            if current_hash is not None:
                raise WorkspaceMutationError("rollback-third-party", "deleted target was replaced")
            handle.create(event["path"], data, mode, no_phase)

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
            operation = event["operation"]
            expected_hash = event["after_hash"] or ""
            expected_mode = event["after_mode"]
            if operation == "delete":
                content_hash, mode, _ = self._current_target(handle, event["path"])
                if content_hash is not None:
                    raise WorkspaceMutationError(
                        "declared-state-drift", "deleted path reappeared"
                    )
                states.append(AttestedPathState(event["path"], False))
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
            states.append(AttestedPathState(target_path, True, content_hash, mode))
        return tuple(sorted(states, key=lambda state: state.path))

    def _build_final_attestation(
        self, run: PlanExecutionRun, context: Any, bundle: PlannedEditBundle,
        workspace: Any, handle: WorkspacePathHandle, git_state: Any,
    ) -> FinalMutationAttestation:
        events = self._store.list_execution_edit_events(run.execution_run_id)
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

    def _build_rollback_attestation(
        self, run: PlanExecutionRun, workspace: Any, handle: WorkspacePathHandle,
        events: tuple[Any, ...], journal_digest: str, reason: str,
        baseline_git: Any | None,
    ) -> RollbackFinalAttestation:
        states: list[AttestedPathState] = []
        for event in events:
            operation = event["operation"]
            source_hash, source_mode, _ = self._current_target(handle, event["path"])
            if operation == "create":
                if source_hash is not None:
                    raise WorkspaceMutationError("rollback-attestation-drift", "created path remains")
                states.append(AttestedPathState(event["path"], False))
                continue
            if source_hash != (event["before_hash"] or "") or source_mode != event["before_mode"]:
                raise WorkspaceMutationError("rollback-attestation-drift", "before state mismatch")
            states.append(AttestedPathState(event["path"], True, source_hash, source_mode))
            if operation == "rename":
                dest_hash, _, _ = self._current_target(handle, event["destination_path"])
                if dest_hash is not None:
                    raise WorkspaceMutationError("rollback-attestation-drift", "rename destination remains")
                states.append(AttestedPathState(event["destination_path"], False))
        state = self._context_provider.current_state(
            repository_id=run.repository_id, task_id=run.task_id,
            workspace_id=run.workspace_id,
        )
        git_state = self._git_inspector.snapshot(
            workspace, repository_generation=state.repository_generation,
        )
        if baseline_git is not None:
            declared = frozenset(
                path for event in events
                for path in (event["path"], event["destination_path"]) if path
            )
            if (git_state.head_commit != baseline_git.head_commit
                    or git_state.repository_generation != baseline_git.repository_generation
                    or git_state.index_digest != baseline_git.index_digest
                    or git_state.worktree_admin_identity != baseline_git.worktree_admin_identity
                    or self._unexpected_changes(
                        self._git_state_map(baseline_git),
                        self._git_state_map(git_state), declared,
                    )):
                raise WorkspaceMutationError(
                    "rollback-workspace-drift", "workspace did not return to its initial state"
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

    def _validated_journal(
        self, run: PlanExecutionRun,
    ) -> tuple[tuple[Any, ...], str]:
        try:
            SafeRecoveryRunId.parse(run.execution_run_id)
            events = self._store.list_execution_edit_events(run.execution_run_id)
            if not events:
                raise UnsafePersistedIdentifier("execution journal is missing")
            ordinals = [int(row["ordinal"]) for row in events]
            if ordinals != list(range(len(events))):
                raise UnsafePersistedIdentifier("journal ordinals are not contiguous")
            if len({row["edit_id"] for row in events}) != len(events):
                raise UnsafePersistedIdentifier("journal edit ids are not unique")
            expected_count = int(run.metadata.get("edit_count", 0))
            if expected_count and expected_count != len(events):
                raise UnsafePersistedIdentifier("journal event count mismatch")
            canonical: list[dict[str, Any]] = []
            for row in events:
                operation = str(row["operation"])
                if operation not in {item.value for item in PlannedEditOperation}:
                    raise UnsafePersistedIdentifier("journal operation invalid")
                path = SafeWorkspaceRelativePath.parse(row["path"]).value
                destination = row["destination_path"]
                if destination is not None:
                    destination = SafeWorkspaceRelativePath.parse(destination).value
                if operation == "rename" and destination is None:
                    raise UnsafePersistedIdentifier("rename destination missing")
                artifact = row["recovery_artifact"]
                if artifact is not None:
                    artifact = SafeRecoveryArtifactName.parse(artifact).value
                canonical.append({
                    "ordinal": int(row["ordinal"]), "edit_id": row["edit_id"],
                    "operation": operation, "path": path,
                    "destination": destination, "before_hash": row["before_hash"] or "",
                    "after_hash": row["after_hash"] or "",
                    "before_mode": row["before_mode"], "after_mode": row["after_mode"],
                    "artifact": artifact,
                })
        except (UnsafePersistedIdentifier, TypeError, ValueError) as exc:
            raise WorkspaceMutationError(
                "recovery-journal-invalid", "persisted recovery journal is invalid"
            ) from exc
        digest = hashlib.sha256(json.dumps(
            canonical, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return events, digest

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
                    events, journal_digest = self._validated_journal(run)
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
                        self._store.commit_terminal_seal(
                            run.execution_run_id, expected_status="sealing",
                            terminal_status="mutated",
                            seal_digest=self._recovery_seal_digest(run.execution_run_id),
                            tombstone_digest=tombstone.tombstone_digest,
                            rollback=False,
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
                        self._store.commit_terminal_seal(
                            run.execution_run_id, expected_status="rollback-sealing",
                            terminal_status=final_status,
                            seal_digest=self._recovery_seal_digest(run.execution_run_id),
                            tombstone_digest=tombstone.tombstone_digest,
                            rollback=True, failure_code=run.failure_code,
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
                        )
                    self._fence.clear_poison(run.workspace_id, owner=owner)
                    self._store.clear_workspace_poison_scope(
                        run.workspace_id, owner=owner
                    )
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
        try:
            return RecoveryDirectory(container, run_id, create=True)
        except (OSError, RecoveryDirectoryError) as exc:
            raise WorkspaceMutationError(
                "recovery-root-invalid", "recovery directory cannot be created safely"
            ) from exc

    def _open_recovery(
        self, workspace: Any, run_id: str, events: tuple[Any, ...],
        *, allow_missing_run: bool = False,
    ) -> RecoveryDirectory:
        container = self._validate_recovery_container(workspace)
        allowed = frozenset(
            row["recovery_artifact"] for row in events if row["recovery_artifact"]
        )
        try:
            return RecoveryDirectory(
                container, run_id, create=False, allowed_artifacts=allowed,
                allow_missing_run=allow_missing_run,
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
