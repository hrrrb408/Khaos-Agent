"""Crash-safe, path-scoped mutation engine for isolated Task Workspaces."""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import time
import unicodedata
import uuid
from dataclasses import replace
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from khaos.coding.planning.approval.models import compute_plan_binding_digest
from khaos.coding.planning.contracts import PlanOperation, PlanStatus
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
    WorkspaceMutationResult,
)
from khaos.coding.workspace.models import WorkspaceState

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

    def apply_bundle(
        self, *, context: Any, bundle: PlannedEditBundle,
        _call_authority: object | None = None,
    ) -> WorkspaceMutationResult:
        """Validate, journal and atomically apply a structured edit bundle."""
        if _call_authority is not self.__call_authority:
            raise PermissionError(
                "WorkspaceMutationEngine is callable only through PlannedExecutionGuard"
            )
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
        before = self._snapshot_workspace(root)
        recovery: Path | None = None
        completed: list[tuple[PlannedFileEdit, Path | None, int | None]] = []
        changed: list[str] = []
        try:
            recovery = self._prepare_recovery(workspace, run.execution_run_id)
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
                self._apply_edit(edit, root)
                completed.append((edit, backup, original_mode))
                changed.extend(
                    path for path in (edit.path, edit.destination_path) if path
                )
                after_path = root / (edit.destination_path or edit.path)
                after_hash = (
                    self._hash_file(after_path) if after_path.is_file() else ""
                )
                after_mode = (
                    stat.S_IMODE(after_path.stat().st_mode)
                    if after_path.exists() else None
                )
                self._store.update_edit_event(
                    run.execution_run_id, edit.edit_id, status="applied",
                    after_hash=after_hash, after_mode=after_mode,
                )

            after = self._snapshot_workspace(root)
            unexpected = self._unexpected_changes(
                before, after, frozenset(changed)
            )
            if unexpected:
                raise WorkspaceMutationError(
                    "unexpected-workspace-mutation",
                    "workspace changed outside the declared bundle",
                )
            self._store.transition_execution_run(
                run.execution_run_id, expected=("mutating",), target="mutated",
                completed=True,
            )
            self._seal_recovery(recovery, workspace.id, run.execution_run_id)
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
            self._rollback(
                run.execution_run_id, completed, root, recovery,
                workspace.id, failure_code=code,
                poison_after=(code == "unexpected-workspace-mutation"),
            )
            raise

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
        root: Path, recovery: Path,
    ) -> tuple[Path | None, int | None]:
        path = root / edit.path
        before_hash = self._hash_file(path) if path.is_file() else None
        before_mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else None
        backup = None
        artifact = None
        if path.is_file():
            backup = recovery / f"{ordinal:04d}-{uuid.uuid4().hex}.bak"
            self._copy_durable(path, backup, before_mode or 0o600)
            if self._hash_file(backup) != before_hash:
                raise WorkspaceMutationError("backup-hash-mismatch", "backup verification failed")
            artifact = backup.name
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
        )
        self._fsync_directory(recovery)
        return backup, before_mode

    def _apply_edit(self, edit: PlannedFileEdit, root: Path) -> None:
        path = root / edit.path
        if edit.encoding.casefold() != "utf-8":
            raise WorkspaceMutationError("encoding-refused", "only UTF-8 is supported")
        if edit.operation == PlannedEditOperation.CREATE:
            if path.exists() or edit.expected_exists:
                raise WorkspaceMutationError("create-precondition", "create target exists")
            if edit.new_content is None:
                raise WorkspaceMutationError("missing-content", "create content missing")
            self._atomic_write(path, edit.new_content, edit.new_mode or 0o600, None)
            return
        if not path.is_file():
            raise WorkspaceMutationError("target-not-file", "target is not a regular file")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise WorkspaceMutationError("file-size-limit", "target file is too large")
        before_hash = self._hash_file(path)
        if edit.expected_content_hash != before_hash:
            raise WorkspaceMutationError("content-hash-drift", "target content hash drifted")
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & (stat.S_ISUID | stat.S_ISGID):
            raise WorkspaceMutationError("unsafe-existing-mode", "setuid/setgid file refused")
        if edit.expected_mode is not None and edit.expected_mode != mode:
            raise WorkspaceMutationError("mode-drift", "target mode drifted")
        if edit.operation == PlannedEditOperation.UPDATE:
            if edit.new_content is None:
                raise WorkspaceMutationError("missing-content", "update content missing")
            new_mode = mode if edit.new_mode is None else edit.new_mode
            if new_mode & (stat.S_ISUID | stat.S_ISGID) or (new_mode & 0o111) > (mode & 0o111):
                raise WorkspaceMutationError("mode-escalation", "executable privilege increase refused")
            inode = path.stat().st_ino
            self._atomic_write(path, edit.new_content, new_mode, inode)
        elif edit.operation == PlannedEditOperation.DELETE:
            path.unlink()
            self._fsync_directory(path.parent)
        elif edit.operation == PlannedEditOperation.RENAME:
            if not edit.destination_path:
                raise WorkspaceMutationError("missing-destination", "rename destination missing")
            destination = root / edit.destination_path
            if destination.exists():
                raise WorkspaceMutationError("rename-target-exists", "rename target exists")
            if path.name.casefold() == destination.name.casefold():
                temporary = path.parent / f".khaos-rename-{uuid.uuid4().hex}"
                os.rename(path, temporary)
                try:
                    os.rename(temporary, destination)
                except Exception:
                    os.rename(temporary, path)
                    raise
            else:
                os.rename(path, destination)
            self._fsync_directory(path.parent)

    def _atomic_write(
        self, path: Path, content: str, mode: int, expected_inode: int | None
    ) -> None:
        if not path.parent.is_dir():
            raise WorkspaceMutationError("parent-missing", "parent directory missing")
        descriptor, temp_name = tempfile.mkstemp(
            prefix=".khaos-edit-", dir=path.parent
        )
        temporary = Path(temp_name)
        try:
            os.fchmod(descriptor, mode & 0o777)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(content.encode("utf-8"))
                stream.flush()
                os.fsync(stream.fileno())
            if expected_inode is not None:
                if not path.is_file() or path.stat().st_ino != expected_inode:
                    raise WorkspaceMutationError("inode-drift", "target changed during write")
            elif path.exists():
                raise WorkspaceMutationError("create-race", "create target appeared")
            os.replace(temporary, path)
            self._fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _rollback(
        self, run_id: str, completed: list[tuple[PlannedFileEdit, Path | None, int | None]],
        root: Path, recovery: Path, workspace_id: str, *, failure_code: str,
        poison_after: bool = False,
    ) -> None:
        try:
            self._store.transition_execution_run(
                run_id, expected=("validating", "mutating"), target="rolling-back",
                failure_code=failure_code,
            )
            for edit, backup, original_mode in reversed(completed):
                path = root / edit.path
                destination = root / edit.destination_path if edit.destination_path else None
                if edit.operation == PlannedEditOperation.CREATE:
                    if path.is_file():
                        path.unlink()
                elif edit.operation == PlannedEditOperation.RENAME:
                    if destination is not None and destination.is_file() and not path.exists():
                        os.rename(destination, path)
                elif backup is not None:
                    self._restore_backup(backup, path, original_mode or 0o600)
                self._store.update_edit_event(
                    run_id, edit.edit_id, status="rolled-back",
                    after_hash=self._hash_file(path) if path.is_file() else "",
                    after_mode=(stat.S_IMODE(path.stat().st_mode) if path.exists() else None),
                    error_code=failure_code,
                )
            target = (
                "poisoned" if poison_after else
                "cancelled" if failure_code == "execution-context-invalid" else
                "rolled-back"
            )
            self._store.transition_execution_run(
                run_id, expected=("rolling-back",), target=target,
                failure_code=failure_code, completed=True,
            )
            if poison_after:
                self._fence.poison(workspace_id, failure_code)
                self._store.poison_workspace(
                    workspace_id, run_id, reason=failure_code
                )
            else:
                self._seal_recovery(recovery, workspace_id, run_id)
        except Exception as rollback_error:
            reason = f"rollback-failed:{type(rollback_error).__name__}"
            self._fence.poison(workspace_id, reason)
            try:
                self._store.poison_workspace(workspace_id, run_id, reason=reason)
                self._store.transition_execution_run(
                    run_id, expected=("rolling-back", "mutating", "validating"),
                    target="poisoned", failure_code=reason, completed=True,
                )
            except Exception:
                pass
            raise WorkspaceMutationError(reason, "rollback failed") from rollback_error

    def recover_incomplete_runs(self) -> tuple[str, ...]:
        """Startup scan: quarantine incomplete runs; recover only intact journals."""
        recovered: list[str] = []
        persisted_poison = dict(self._store.list_poisoned_workspaces())
        for run in self._store.list_incomplete_execution_runs():
            reason = "startup-incomplete-execution"
            self._fence.poison(run.workspace_id, reason)
            if run.workspace_id not in persisted_poison:
                self._store.poison_workspace(
                    run.workspace_id, run.execution_run_id, reason=reason
                )
            workspace = self._workspaces.get(run.workspace_id)
            if workspace is None:
                continue
            recovery = self._recovery_root(workspace, run.execution_run_id)
            events = self._store.list_execution_edit_events(run.execution_run_id)
            if not recovery.is_dir() or not events:
                continue
            try:
                root = workspace.worktree_path.resolve(strict=True)
                if run.status != ExecutionRunStatus.ROLLING_BACK:
                    self._store.transition_execution_run(
                        run.execution_run_id,
                        expected=(run.status.value,), target="rolling-back",
                        failure_code="startup-recovery",
                    )
                for event in reversed(events):
                    path = root / event["path"]
                    operation = event["operation"]
                    artifact = event["recovery_artifact"]
                    if operation == "create":
                        if path.is_file():
                            if self._hash_file(path) != event["after_hash"]:
                                raise WorkspaceMutationError(
                                    "recovery-corrupt", "created file drifted"
                                )
                            path.unlink()
                    elif operation == "rename":
                        destination = root / event["destination_path"]
                        if (path.is_file()
                                and self._hash_file(path) == event["before_hash"]
                                and not destination.exists()):
                            continue
                        if (not destination.is_file()
                                or self._hash_file(destination) != event["after_hash"]):
                            raise WorkspaceMutationError(
                                "recovery-corrupt", "rename destination drifted"
                            )
                        if path.exists():
                            raise WorkspaceMutationError(
                                "recovery-corrupt", "rename source unexpectedly exists"
                            )
                        os.rename(destination, path)
                    elif artifact:
                        backup = recovery / artifact
                        if not backup.is_file() or self._hash_file(backup) != event["before_hash"]:
                            raise WorkspaceMutationError("recovery-corrupt", "recovery artifact corrupt")
                        if path.is_file() and self._hash_file(path) == event["before_hash"]:
                            continue
                        if operation == "update" and (
                            not path.is_file() or self._hash_file(path) != event["after_hash"]
                        ):
                            raise WorkspaceMutationError(
                                "recovery-corrupt", "updated file drifted"
                            )
                        if operation == "delete" and path.exists():
                            raise WorkspaceMutationError(
                                "recovery-corrupt", "deleted path was replaced"
                            )
                        self._restore_backup(backup, path, event["before_mode"] or 0o600)
                self._store.transition_execution_run(
                    run.execution_run_id,
                    expected=("rolling-back",),
                    target="rolled-back", failure_code="startup-recovery", completed=True,
                )
                self._seal_recovery(recovery, run.workspace_id, run.execution_run_id)
                self._fence.clear_poison(run.workspace_id)
                self._store.recover_poisoned_workspace(
                    run.workspace_id, force=True
                )
                recovered.append(run.execution_run_id)
            except Exception:
                try:
                    self._store.transition_execution_run(
                        run.execution_run_id,
                        expected=("rolling-back",),
                        target="poisoned", failure_code="recovery-evidence-invalid",
                        completed=True,
                    )
                except Exception:
                    pass
                continue
        return tuple(recovered)

    @staticmethod
    def _prepare_recovery(workspace: Any, run_id: str) -> Path:
        recovery = WorkspaceMutationEngine._recovery_root(workspace, run_id)
        recovery.mkdir(parents=True, mode=0o700, exist_ok=False)
        os.chmod(recovery, 0o700)
        WorkspaceMutationEngine._fsync_directory(recovery.parent)
        return recovery

    @staticmethod
    def _recovery_root(workspace: Any, run_id: str) -> Path:
        return workspace.worktree_path.parent / ".khaos-recovery" / run_id

    def _seal_recovery(self, recovery: Path, workspace_id: str, run_id: str) -> None:
        try:
            shutil.rmtree(recovery)
            if recovery.parent.is_dir() and not any(recovery.parent.iterdir()):
                recovery.parent.rmdir()
        except Exception as exc:
            reason = f"recovery-cleanup-failed:{type(exc).__name__}"
            self._fence.poison(workspace_id, reason)
            self._store.poison_workspace(workspace_id, run_id, reason=reason)
            raise WorkspaceMutationError(reason, "recovery cleanup failed") from exc

    @staticmethod
    def _copy_durable(source: Path, destination: Path, mode: int) -> None:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
                shutil.copyfileobj(reader, writer)
                writer.flush()
                os.fsync(writer.fileno())
            os.chmod(destination, mode & 0o777)
        except Exception:
            if destination.exists():
                destination.unlink()
            raise

    def _restore_backup(self, backup: Path, target: Path, mode: int) -> None:
        data = backup.read_bytes()
        descriptor, temp_name = tempfile.mkstemp(prefix=".khaos-restore-", dir=target.parent)
        temporary = Path(temp_name)
        try:
            os.fchmod(descriptor, mode & 0o777)
            with os.fdopen(descriptor, "wb") as writer:
                writer.write(data)
                writer.flush()
                os.fsync(writer.fileno())
            os.replace(temporary, target)
            self._fsync_directory(target.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    @staticmethod
    def _snapshot_workspace(root: Path) -> dict[str, str]:
        snapshot: dict[str, str] = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root).as_posix()
            if relative == ".git" or relative.startswith(".git/"):
                continue
            if path.is_symlink():
                snapshot[relative] = f"symlink:{os.readlink(path)}"
            elif path.is_file():
                snapshot[relative] = WorkspaceMutationEngine._hash_file(path)
        git_marker = root / ".git"
        if git_marker.is_file():
            snapshot["@git-admin"] = WorkspaceMutationEngine._hash_file(git_marker)
        return snapshot

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
