"""Generation-bound checkpoint capture and controlled rewind service."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import stat
import uuid
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from khaos.coding.checkpoints.contracts import (
    CheckpointKind,
    RewindExecutionResult,
    RewindPlan,
    TaskCheckpoint,
)
from khaos.coding.checkpoints.repository import CheckpointRepository
from khaos.coding.edit_transaction import (
    EditOperation,
    EditOperationKind,
    EditTransaction,
    EditTransactionResult,
)
from khaos.coding.workspace.boundary import SafeWorkspaceFS, WorkspaceBoundaryError
from khaos.coding.workspace.models import WorkspaceState
from khaos.security.protocol_boundary import canonical_digest
from khaos.supervision.contracts import (
    ControlState,
    SupervisionActor,
    SupervisionCommandStatus,
    SupervisionEventType,
)
from khaos.supervision.service import TaskSupervisionService

logger = logging.getLogger(__name__)

MAX_CHECKPOINTS_PER_TASK = 64
MAX_SNAPSHOT_FILES = 256
MAX_SNAPSHOT_BYTES = 16 * 1024 * 1024
MAX_REWIND_OPERATIONS = 64


def _digest_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _value(value: object, name: str, default: object = None) -> object:
    return getattr(value, name, default)


@asynccontextmanager
async def _workspace_scope(
    workspace_manager: Any, workspace_id: str, task_id: str
) -> AsyncIterator[Any]:
    scope = getattr(workspace_manager, "workspace_storage_scope", None)
    if callable(scope):
        async with scope(workspace_id, task_id) as workspace:
            yield workspace
        return
    workspace = workspace_manager.get(workspace_id)
    if workspace is None or getattr(workspace, "task_id", task_id) != task_id:
        raise PermissionError("workspace/task binding is invalid")
    yield workspace


class CheckpointService:
    """Capture immutable workspace snapshots and rewind through M8.2."""

    def __init__(
        self,
        workspace_manager: Any,
        edit_transaction_service: Any,
        checkpoint_repository: CheckpointRepository | None = None,
        supervision_service: TaskSupervisionService | None = None,
        verification_coordinator: Any | None = None,
        repo_intelligence: Any | None = None,
        parallel_subagent_repository: Any | None = None,
        *,
        database: Any | None = None,
        principal_id: str = "",
        project_id: str = "",
        runtime_id: str = "",
        audit_logger: Any | None = None,
    ) -> None:
        if workspace_manager is None:
            raise ValueError("workspace_manager is required")
        self.workspace_manager = workspace_manager
        self.edit_transaction_service = edit_transaction_service
        if checkpoint_repository is None:
            if database is None:
                raise ValueError("checkpoint_repository or database is required")
            checkpoint_repository = CheckpointRepository(database)
        self.repository = checkpoint_repository
        if supervision_service is None:
            if database is None:
                raise ValueError("supervision_service or database is required")
            supervision_service = TaskSupervisionService(database, audit_logger=audit_logger)
        self.supervision = supervision_service
        self.verification_coordinator = verification_coordinator
        self.repo_intelligence = repo_intelligence
        self.parallel_subagent_repository = parallel_subagent_repository
        self.principal_id = principal_id
        self.project_id = project_id
        self.runtime_id = runtime_id
        self.audit_logger = audit_logger
        self._locks: dict[tuple[str, str, str], asyncio.Lock] = {}
        self._locks_guard = asyncio.Lock()

    async def _lock_for(self, task_id: str, principal_id: str, project_id: str) -> asyncio.Lock:
        key = task_id, principal_id, project_id
        async with self._locks_guard:
            return self._locks.setdefault(key, asyncio.Lock())

    def _owner(self, principal_id: str | None, project_id: str | None) -> tuple[str, str]:
        resolved_principal = principal_id or self.principal_id
        resolved_project = project_id or self.project_id
        if not resolved_principal or not resolved_project:
            raise PermissionError("checkpoint owner identity is required")
        return resolved_principal, resolved_project

    async def _audit(
        self, action: str, task_id: str, principal_id: str, project_id: str,
        result: str, detail: dict[str, object],
    ) -> None:
        if self.audit_logger is None:
            return
        log = getattr(self.audit_logger, "log", None)
        if not callable(log):
            return
        try:
            await log(
                action,
                f"task:{task_id}",
                result,
                detail,
                task_id=task_id,
                source_transport="checkpoint",
            )
        except Exception:
            logger.exception("checkpoint audit adapter failed for task=%s", task_id)

    async def _finish_rewind(
        self,
        plan: RewindPlan,
        result: RewindExecutionResult,
        *,
        principal_id: str,
        project_id: str,
    ) -> RewindExecutionResult:
        """Persist one terminal rewind result and return the durable winner."""
        await self.repository.finish_rewind(
            plan,
            result,
            principal_id=principal_id,
            project_id=project_id,
        )
        persisted = await self.repository.get_rewind_result(
            plan.rewind_id, principal_id=principal_id, project_id=project_id
        )
        return persisted or result

    async def _snapshot(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        expected_generation: int | None = None,
    ) -> tuple[Any, dict[str, dict[str, object]]]:
        async with _workspace_scope(self.workspace_manager, workspace_id, task_id) as workspace:
            if (
                getattr(workspace, "principal_id", None) != principal_id
                or getattr(workspace, "project_id", None) != project_id
            ):
                raise PermissionError("workspace owner does not match checkpoint owner")
            state = _value(workspace, "state")
            if state in {
                WorkspaceState.FAILED,
                WorkspaceState.CANCELLED,
                WorkspaceState.CLEANING,
                WorkspaceState.CLEANED,
            } or getattr(state, "value", state) in {
                "failed", "cancelled", "cleaning", "cleaned",
            }:
                raise PermissionError("workspace is not available for checkpointing")
            generation = _value(workspace, "generation")
            if type(generation) is not int or generation <= 0:
                raise RuntimeError("workspace generation is invalid")
            if expected_generation is not None and generation != expected_generation:
                raise RuntimeError("workspace generation is stale")
            if int(_value(workspace, "change_artifact_reservations", 0) or 0) != 0:
                raise RuntimeError("workspace has an active ChangeSet capture")
            filesystem = SafeWorkspaceFS(workspace.worktree_path)
            snapshot: dict[str, dict[str, object]] = {}
            try:
                paths = filesystem.iter_files(
                    max_entries=MAX_SNAPSHOT_FILES,
                    max_depth=64,
                )
                for relative in paths:
                    info = filesystem.lstat(relative)
                    if info is None:
                        raise WorkspaceBoundaryError("snapshot target disappeared")
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise WorkspaceBoundaryError("snapshot target is not a regular file")
                    content = filesystem.read_bytes(relative, max_bytes=4 * 1024 * 1024)
                    encoded_size = len(base64.b64encode(content))
                    existing_size = sum(
                        len(item.get("content_b64", ""))
                        for item in snapshot.values()
                    )
                    if existing_size + encoded_size > MAX_SNAPSHOT_BYTES:
                        raise WorkspaceBoundaryError("checkpoint snapshot exceeds its byte bound")
                    snapshot[relative] = {
                        "digest": _digest_bytes(content),
                        "size": len(content),
                        "mode": stat.S_IMODE(info.st_mode) & 0o777,
                        "content_b64": base64.b64encode(content).decode("ascii"),
                    }
            finally:
                filesystem.close()
        return workspace, snapshot

    async def _head_tree(self, workspace_id: str, snapshot: Mapping[str, object]) -> tuple[str, str]:
        head_reader = getattr(self.workspace_manager, "current_head", None)
        tree_reader = getattr(self.workspace_manager, "current_tree", None)
        if callable(head_reader):
            head = await head_reader(workspace_id)
        else:
            head = canonical_digest({"workspace_id": workspace_id, "snapshot": snapshot})
        if callable(tree_reader):
            tree = await tree_reader(workspace_id, commit=head)
        else:
            tree = canonical_digest(snapshot)
        return str(head), str(tree)

    async def create_checkpoint(
        self,
        *,
        task_id: str,
        workspace_id: str,
        kind: CheckpointKind | str = CheckpointKind.USER_CREATED,
        label: str = "",
        expected_generation: int | None = None,
        plan_revision: int | None = None,
        verification_evidence_digest: str | None = None,
        known_state: bool = False,
        principal_id: str | None = None,
        project_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> TaskCheckpoint:
        """Capture a stable, bounded snapshot; never silently captures drift."""
        owner_principal, owner_project = self._owner(principal_id, project_id)
        lock = await self._lock_for(task_id, owner_principal, owner_project)
        async with lock:
            state = await self.supervision.state(
                task_id, principal_id=owner_principal, project_id=owner_project
            )
            workspace, snapshot = await self._snapshot(
                task_id=task_id, workspace_id=workspace_id,
                principal_id=owner_principal, project_id=owner_project,
                expected_generation=expected_generation,
            )
            known = dict(state.known_file_digests) if state else {}
            current = {path: str(meta["digest"]) for path, meta in snapshot.items()}
            if known and not known_state and current != known:
                raise RuntimeError("workspace differs from durable known state")
            if not known and not known_state:
                require_stable = getattr(self.workspace_manager, "require_stable", None)
                if callable(require_stable):
                    await require_stable(
                        workspace_id, task_id=task_id,
                        expected_generation=getattr(workspace, "generation", None),
                    )
            head, tree = await self._head_tree(workspace_id, snapshot)
            generation = int(workspace.generation)
            resolved_kind = kind if isinstance(kind, CheckpointKind) else CheckpointKind(str(kind))
            snapshot_digest = canonical_digest(snapshot)
            identity = {
                "task_id": task_id,
                "workspace_id": workspace_id,
                "project_id": owner_project,
                "generation": generation,
                "head": head,
                "tree": tree,
                "kind": resolved_kind.value,
                "label": label,
                "snapshot_digest": snapshot_digest,
                "idempotency_key": idempotency_key or "",
            }
            checkpoint_id = f"cp-{canonical_digest(identity)[:32]}"
            checkpoint = TaskCheckpoint(
                checkpoint_id=checkpoint_id,
                task_id=task_id,
                workspace_id=workspace_id,
                project_id=owner_project,
                repository_generation=generation,
                head_commit=head,
                tree_digest=tree,
                task_revision=state.revision if state else 0,
                plan_revision=plan_revision,
                verification_evidence_digest=verification_evidence_digest,
                checkpoint_kind=resolved_kind,
                label=label,
                snapshot_digest=snapshot_digest,
                snapshot=snapshot,
            )
            existing = await self.repository.create(
                checkpoint, principal_id=owner_principal
            )
            await self.supervision.emit(
                task_id=task_id, workspace_id=workspace_id,
                principal_id=owner_principal, project_id=owner_project,
                event_type=SupervisionEventType.CHECKPOINT_CREATED,
                repository_generation=generation,
                payload={
                    "checkpoint_id": existing.checkpoint_id,
                    "checkpoint_kind": existing.checkpoint_kind.value,
                    "checkpoint_digest": existing.checkpoint_digest,
                    "snapshot_digest": existing.snapshot_digest,
                    "file_count": len(existing.snapshot),
                    "changed_paths": sorted(existing.snapshot),
                },
                actor=SupervisionActor.USER if resolved_kind is CheckpointKind.USER_CREATED else SupervisionActor.SYSTEM,
            )
            await self.supervision.emit(
                task_id=task_id, workspace_id=workspace_id,
                principal_id=owner_principal, project_id=owner_project,
                event_type=SupervisionEventType.WORKSPACE_OBSERVED,
                repository_generation=generation,
                payload={
                    "known_file_digests": current,
                    "changed_paths": sorted(current),
                },
            )
            await self._audit(
                "checkpoint.create", task_id, owner_principal, owner_project,
                "success", {
                    "checkpoint_id": existing.checkpoint_id,
                    "checkpoint_digest": existing.checkpoint_digest,
                    "repository_generation": generation,
                    "file_count": len(existing.snapshot),
                },
            )
            return existing

    async def list_checkpoints(
        self, task_id: str, *, workspace_id: str | None = None,
        principal_id: str | None = None, project_id: str | None = None,
    ) -> tuple[TaskCheckpoint, ...]:
        owner_principal, owner_project = self._owner(principal_id, project_id)
        return await self.repository.list(
            task_id, principal_id=owner_principal, project_id=owner_project,
            workspace_id=workspace_id,
        )

    async def checkpoint(
        self, checkpoint_id: str, *, principal_id: str | None = None,
        project_id: str | None = None, task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> TaskCheckpoint | None:
        owner_principal, owner_project = self._owner(principal_id, project_id)
        return await self.repository.get(
            checkpoint_id, principal_id=owner_principal,
            project_id=owner_project, task_id=task_id, workspace_id=workspace_id,
        )

    async def record_known_transaction(
        self, result: EditTransactionResult, *, task_id: str | None = None,
        principal_id: str | None = None, project_id: str | None = None,
    ) -> None:
        """Project only digests from an applied M8.2 result; never source text."""
        if not task_id:
            raise ValueError("task_id is required to project an edit result")
        await self.record_transaction(
            task_id,
            result,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def record_transaction(
        self, task_id: str, result: EditTransactionResult, *,
        principal_id: str | None = None, project_id: str | None = None,
    ) -> None:
        owner_principal, owner_project = self._owner(principal_id, project_id)
        state = await self.supervision.state(
            task_id, principal_id=owner_principal, project_id=owner_project
        )
        known = dict(state.known_file_digests) if state else {}
        changed: list[str] = []
        for operation in result.operations:
            changed.append(operation.path)
            if operation.operation is EditOperationKind.DELETE:
                known.pop(operation.path, None)
            elif operation.operation is EditOperationKind.RENAME:
                known.pop(operation.path, None)
                if operation.destination_path and operation.after_digest:
                    known[operation.destination_path] = operation.after_digest
            elif operation.after_exists and operation.after_digest:
                known[operation.path] = operation.after_digest
            else:
                known.pop(operation.path, None)
        await self.supervision.emit(
            task_id=task_id, workspace_id=result.workspace_id,
            principal_id=owner_principal, project_id=owner_project,
            event_type=SupervisionEventType.EDIT_APPLIED,
            repository_generation=result.resulting_generation,
            payload={
                "transaction_id": result.transaction_id,
                "transaction_digest": result.transaction_digest,
                "changed_paths": sorted(set(changed)),
                "known_file_digests": known,
            },
        )

    async def _parallel_barrier(
        self, task_id: str, workspace_id: str, *, principal_id: str, project_id: str
    ) -> bool:
        repository = self.parallel_subagent_repository
        if repository is None:
            return False
        checker = getattr(repository, "has_active_for_parent", None)
        if callable(checker):
            return bool(await checker(
                task_id, workspace_id=workspace_id,
                project_id=project_id, principal_id=principal_id,
            ))
        incomplete = getattr(repository, "incomplete", None)
        if callable(incomplete):
            records = await incomplete()
            return any(
                item.get("parent_task_id") == task_id
                or item.get("parent_workspace_id") == workspace_id
                for item in records
                if isinstance(item, dict)
            )
        return False

    async def build_rewind_plan(
        self, checkpoint_id: str, *, principal_id: str | None = None,
        project_id: str | None = None, task_id: str | None = None,
        workspace_id: str | None = None, idempotency_key: str | None = None,
    ) -> RewindPlan:
        owner_principal, owner_project = self._owner(principal_id, project_id)
        checkpoint = await self.repository.get(
            checkpoint_id, principal_id=owner_principal, project_id=owner_project,
            task_id=task_id, workspace_id=workspace_id,
        )
        if checkpoint is None:
            raise LookupError("checkpoint not found")
        actual_task = task_id or checkpoint.task_id
        actual_workspace = workspace_id or checkpoint.workspace_id
        lock = await self._lock_for(actual_task, owner_principal, owner_project)
        async with lock:
            state = await self.supervision.state(
                actual_task, principal_id=owner_principal, project_id=owner_project
            )
            control = await self.supervision.control.repository.get_control(
                actual_task, principal_id=owner_principal, project_id=owner_project
            )
            barriers: list[str] = []
            handle = await self.supervision.control.runtime_handle(
                actual_task, principal_id=owner_principal, project_id=owner_project
            )
            if handle is not None:
                barriers.append("active runtime")
            if control is not None and control.state in {
                ControlState.CANCELLING, ControlState.CANCELLED,
            }:
                barriers.append(f"control state {control.state.value}")
            if state is not None:
                if state.active_subagents:
                    barriers.append("active subagents")
                if state.merge_state not in {"none", "completed", "idle"}:
                    barriers.append("active merge")
                if state.approval_state not in {"none", "resolved", "approved"}:
                    barriers.append("pending approval")
            if await self._parallel_barrier(
                actual_task, actual_workspace,
                principal_id=owner_principal, project_id=owner_project,
            ):
                barriers.append("active child or merge record")
            workspace, current_snapshot = await self._snapshot(
                task_id=actual_task, workspace_id=actual_workspace,
                principal_id=owner_principal, project_id=owner_project,
            )
            source_generation = int(workspace.generation)
            source_head, source_tree = await self._head_tree(actual_workspace, current_snapshot)
            known = dict(state.known_file_digests) if state else {}
            current = {path: str(meta["digest"]) for path, meta in current_snapshot.items()}
            target = {
                path: str(meta["digest"])
                for path, meta in checkpoint.snapshot.items()
            }
            user_drift: list[str] = []
            conflicts: list[str] = list(barriers)
            preserved: list[str] = []
            operations: list[EditOperation] = []

            if state is None:
                conflicts.append("durable known workspace state is unavailable")
            for path in sorted(set(current) | set(target) | set(known)):
                current_digest = current.get(path)
                known_digest = known.get(path)
                target_meta = checkpoint.snapshot.get(path)
                target_digest = target.get(path)
                if known_digest is not None:
                    if current_digest != known_digest and current_digest != target_digest:
                        user_drift.append(path)
                        conflicts.append(f"user drift: {path}")
                elif current_digest is not None and current_digest != target_digest:
                    # Files outside the durable model-owned set are user
                    # drift by default.  Preserve them; only a target with the
                    # same path would require an overwrite and therefore
                    # becomes a fail-closed conflict.
                    preserved.append(path)
                    if target_meta is not None:
                        conflicts.append(f"unowned path collision: {path}")

                if current_digest == target_digest:
                    continue
                if target_meta is not None:
                    raw = target_meta.get("content_b64")
                    try:
                        content = base64.b64decode(str(raw), validate=True).decode("utf-8")
                    except (ValueError, UnicodeDecodeError) as exc:
                        conflicts.append(f"non-text checkpoint content: {path}")
                        logger.debug("checkpoint content decode failed for %s: %s", path, exc)
                        continue
                    if current_digest is None:
                        operation = EditOperation(
                            operation=EditOperationKind.CREATE,
                            path=path,
                            content=content,
                        )
                    else:
                        operation = EditOperation(
                            operation=EditOperationKind.UPDATE,
                            path=path,
                            expected_exists=True,
                            expected_digest=current_digest,
                            content=content,
                        )
                    operations.append(operation)
                elif current_digest is not None:
                    if known_digest is not None and current_digest == known_digest:
                        operations.append(EditOperation(
                            operation=EditOperationKind.DELETE,
                            path=path,
                            expected_exists=True,
                            expected_digest=current_digest,
                        ))
                    else:
                        preserved.append(path)
            candidate_affected = tuple(
                sorted({operation.path for operation in operations}
                       | {operation.destination_path for operation in operations if operation.destination_path})
            )
            if len(operations) > MAX_REWIND_OPERATIONS:
                conflicts.append("rewind operation count exceeds its bound")
                operations = []
            transaction = None
            if operations and not conflicts:
                transaction = EditTransaction(
                    transaction_id=f"rewind-tx-{uuid.uuid4().hex}",
                    workspace_id=actual_workspace,
                    base_generation=source_generation,
                    operations=tuple(operations),
                    intent=f"controlled rewind to checkpoint {checkpoint.checkpoint_id}",
                )
            elif operations and conflicts:
                # Keep a descriptive plan but do not retain executable writes
                # behind a blocked conflict plan.
                operations = []
            affected = candidate_affected
            rewind_identity = {
                "task_id": actual_task,
                "workspace_id": actual_workspace,
                "project_id": owner_project,
                "source_generation": source_generation,
                "source_head": source_head,
                "source_tree": source_tree,
                "source_snapshot_digest": canonical_digest(current_snapshot),
                "checkpoint_id": checkpoint.checkpoint_id,
                "checkpoint_digest": checkpoint.checkpoint_digest,
                "idempotency_key": idempotency_key or "",
            }
            rewind_id = f"rw-{canonical_digest(rewind_identity)[:32]}"
            plan = RewindPlan(
                rewind_id=rewind_id,
                task_id=actual_task,
                workspace_id=actual_workspace,
                project_id=owner_project,
                source_generation=source_generation,
                source_head=source_head,
                source_tree=source_tree,
                target_checkpoint_id=checkpoint.checkpoint_id,
                target_checkpoint_digest=checkpoint.checkpoint_digest,
                target_generation=checkpoint.repository_generation,
                target_head=checkpoint.head_commit,
                target_tree=checkpoint.tree_digest,
                affected_paths=affected,
                preserved_paths=tuple(sorted(set(preserved))),
                user_drift=tuple(sorted(set(user_drift))),
                conflicts=tuple(sorted(set(conflicts))),
                transaction=transaction,
                transaction_digest=transaction.transaction_digest if transaction else None,
                expected_resulting_generation=source_generation + 1,
                status="blocked" if conflicts else ("noop" if not transaction else "planned"),
                source_snapshot_digest=canonical_digest(current_snapshot),
            )
            stored = await self.repository.create_rewind_plan(
                plan, principal_id=owner_principal
            )
            await self.supervision.emit(
                task_id=actual_task, workspace_id=actual_workspace,
                principal_id=owner_principal, project_id=owner_project,
                event_type=SupervisionEventType.WORKSPACE_OBSERVED,
                repository_generation=source_generation,
                payload={
                    "rewind_id": stored.rewind_id,
                    "rewind_status": stored.status,
                    "target_checkpoint_id": checkpoint.checkpoint_id,
                    "affected_paths": list(stored.affected_paths),
                    "preserved_paths": list(stored.preserved_paths),
                    "conflict_count": len(stored.conflicts),
                },
                actor=SupervisionActor.USER,
            )
            await self._audit(
                "checkpoint.rewind.plan", actual_task, owner_principal, owner_project,
                "blocked" if stored.conflicts else "success",
                {
                    "rewind_id": stored.rewind_id,
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "plan_digest": stored.plan_digest,
                    "conflict_count": len(stored.conflicts),
                },
            )
            return stored

    async def execute_rewind(
        self, plan: RewindPlan, *, principal_id: str | None = None,
        project_id: str | None = None, idempotency_key: str | None = None,
    ) -> RewindExecutionResult:
        owner_principal, owner_project = self._owner(principal_id, project_id)
        if plan.project_id != owner_project:
            raise PermissionError("rewind plan belongs to another project")
        stored = await self.repository.get_rewind_plan(
            plan.rewind_id, principal_id=owner_principal, project_id=owner_project
        )
        if stored is None or stored.plan_digest != plan.plan_digest:
            return RewindExecutionResult(
                rewind_id=plan.rewind_id, task_id=plan.task_id,
                status=SupervisionCommandStatus.REJECTED_STALE,
                effect_applied=False, reason="rewind plan is not current",
            )
        previous = await self.repository.get_rewind_result(
            plan.rewind_id, principal_id=owner_principal, project_id=owner_project
        )
        if previous is not None:
            return previous
        lock = await self._lock_for(plan.task_id, owner_principal, owner_project)
        async with lock:
            checkpoint = await self.repository.get(
                plan.target_checkpoint_id, principal_id=owner_principal,
                project_id=owner_project, task_id=plan.task_id,
                workspace_id=plan.workspace_id,
            )
            if checkpoint is None or checkpoint.checkpoint_digest != plan.target_checkpoint_digest:
                result = RewindExecutionResult(
                    rewind_id=plan.rewind_id, task_id=plan.task_id,
                    status=SupervisionCommandStatus.REJECTED_STALE,
                    effect_applied=False, reason="checkpoint identity is stale",
                )
                return await self._finish_rewind(
                    plan, result, principal_id=owner_principal,
                    project_id=owner_project,
                )
            if plan.conflicts or plan.transaction is None:
                status = SupervisionCommandStatus.NOOP if plan.status == "noop" else SupervisionCommandStatus.BLOCKED
                result = RewindExecutionResult(
                    rewind_id=plan.rewind_id, task_id=plan.task_id,
                    status=status, effect_applied=False,
                    reason="; ".join(plan.conflicts) if plan.conflicts else "checkpoint already matches workspace",
                )
                return await self._finish_rewind(
                    plan, result, principal_id=owner_principal,
                    project_id=owner_project,
                )
            handle = await self.supervision.control.runtime_handle(
                plan.task_id, principal_id=owner_principal, project_id=owner_project
            )
            if handle is not None:
                result = RewindExecutionResult(
                    rewind_id=plan.rewind_id, task_id=plan.task_id,
                    status=SupervisionCommandStatus.BLOCKED, effect_applied=False,
                    reason="active runtime must reach a safe barrier",
                )
                return await self._finish_rewind(
                    plan, result, principal_id=owner_principal,
                    project_id=owner_project,
                )
            workspace, snapshot = await self._snapshot(
                task_id=plan.task_id, workspace_id=plan.workspace_id,
                principal_id=owner_principal, project_id=owner_project,
                expected_generation=plan.source_generation,
            )
            current_head, current_tree = await self._head_tree(plan.workspace_id, snapshot)
            current_snapshot_digest = canonical_digest(snapshot)
            if (
                current_head != plan.source_head
                or current_tree != plan.source_tree
                or (
                    plan.source_snapshot_digest
                    and current_snapshot_digest != plan.source_snapshot_digest
                )
            ):
                result = RewindExecutionResult(
                    rewind_id=plan.rewind_id, task_id=plan.task_id,
                    status=SupervisionCommandStatus.REJECTED_STALE, effect_applied=False,
                    reason="workspace changed since rewind planning",
                )
                return await self._finish_rewind(
                    plan, result, principal_id=owner_principal,
                    project_id=owner_project,
                )
            try:
                applied = await self.edit_transaction_service.apply(
                    plan.transaction,
                    workspace_manager=self.workspace_manager,
                    task_id=plan.task_id,
                    workspace_id=plan.workspace_id,
                    principal_id=owner_principal,
                    project_id=owner_project,
                    runtime_id=self.runtime_id or getattr(workspace, "creator_runtime_id", ""),
                )
            except Exception as exc:  # noqa: BLE001 - rewind must fail closed
                result = RewindExecutionResult(
                    rewind_id=plan.rewind_id, task_id=plan.task_id,
                    status=SupervisionCommandStatus.FAILED, effect_applied=False,
                    reason=f"rewind transaction failed: {type(exc).__name__}",
                )
                return await self._finish_rewind(
                    plan, result, principal_id=owner_principal,
                    project_id=owner_project,
                )
            if not isinstance(applied, EditTransactionResult):
                raise TypeError("EditTransactionService returned an invalid result")
            await self.record_transaction(
                plan.task_id, applied, principal_id=owner_principal, project_id=owner_project
            )
            verification_status = "unknown"
            verification_failed = False
            if self.verification_coordinator is not None:
                invalidate = getattr(self.verification_coordinator, "invalidate", None)
                if callable(invalidate):
                    invalidate(plan.task_id)
                try:
                    run = await self.verification_coordinator.verify_after_edit(
                        applied, task_id=plan.task_id, workspace=workspace,
                        transaction=plan.transaction,
                        principal_id=owner_principal, project_id=owner_project,
                    )
                    verification_status = str(getattr(getattr(run, "status", None), "value", getattr(run, "status", "unknown")))
                    verification_failed = verification_status not in {"passed", "success", "completed"}
                except Exception as exc:  # noqa: BLE001 - verification is fail closed
                    verification_status = "failed"
                    verification_failed = True
                    logger.warning("fresh rewind verification failed: %s", exc)
            await self.supervision.emit(
                task_id=plan.task_id, workspace_id=plan.workspace_id,
                principal_id=owner_principal, project_id=owner_project,
                event_type=SupervisionEventType.CHECKPOINT_RESTORED,
                repository_generation=applied.resulting_generation,
                payload={
                    "rewind_id": plan.rewind_id,
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "checkpoint_digest": checkpoint.checkpoint_digest,
                    "transaction_id": applied.transaction_id,
                    "transaction_digest": applied.transaction_digest,
                    "changed_paths": [operation.path for operation in applied.operations],
                    "verification_status": verification_status,
                },
                actor=SupervisionActor.RECOVERY,
                severity="warning" if verification_failed else "info",
            )
            result = RewindExecutionResult(
                rewind_id=plan.rewind_id, task_id=plan.task_id,
                status=SupervisionCommandStatus.FAILED if verification_failed else SupervisionCommandStatus.APPLIED,
                effect_applied=True,
                resulting_generation=applied.resulting_generation,
                verification_status=verification_status,
                reason="effect applied; fresh verification failed" if verification_failed else "rewind applied",
            )
            result = await self._finish_rewind(
                plan,
                result,
                principal_id=owner_principal,
                project_id=owner_project,
            )
            await self._audit(
                "checkpoint.rewind.execute", plan.task_id, owner_principal, owner_project,
                "error" if verification_failed else "success",
                {
                    "rewind_id": plan.rewind_id,
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "result_digest": result.result_digest,
                    "effect_applied": True,
                    "verification_status": verification_status,
                },
            )
            return result

    build_plan = build_rewind_plan
    rewind = execute_rewind
    create = create_checkpoint
    list = list_checkpoints
    inspect = checkpoint
    plan = build_rewind_plan


__all__ = [
    "MAX_CHECKPOINTS_PER_TASK",
    "MAX_SNAPSHOT_BYTES",
    "MAX_SNAPSHOT_FILES",
    "CheckpointService",
]
