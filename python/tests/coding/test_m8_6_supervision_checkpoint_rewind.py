"""M8.6 regression tests for supervision, control, and rewind boundaries."""

from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest
from khaos.coding.checkpoints.service import CheckpointService
from khaos.coding.edit_transaction import (
    EditOperation,
    EditOperationKind,
    EditOperationResult,
    EditTransaction,
    EditTransactionResult,
)
from khaos.coding.workspace.models import (
    TaskWorkspace,
    WorkspaceState,
    WorkspaceTransition,
)
from khaos.db import Database
from khaos.security.protocol_boundary import canonical_json_bytes
from khaos.subagents.contracts import (
    AssignmentContext,
    ChildWorkspaceBinding,
    ChildWorkspaceState,
    SubagentAccessMode,
    SubagentAssignment,
    SubagentResult,
    SubagentResultStatus,
    SubagentRole,
)
from khaos.subagents.coordinator import SubagentCoordinator
from khaos.subagents.workspace import ChildCleanupResult
from khaos.supervision.contracts import (
    ControlState,
    SupervisionContractError,
    SupervisionEvent,
    SupervisionEventType,
)
from khaos.supervision.repository import SupervisionIntegrityError
from khaos.supervision.service import TaskSupervisionService


async def _database(tmp_path: Path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


@pytest.mark.asyncio
async def test_supervision_projection_is_typed_owner_scoped_and_restart_safe(tmp_path: Path):
    db = await _database(tmp_path)
    try:
        service = TaskSupervisionService(db)
        await service.start_task(
            task_id="task-1", workspace_id="workspace-1",
            principal_id="principal-a", project_id="project-a", goal="inspect",
        )
        await service.emit(
            task_id="task-1", workspace_id="workspace-1",
            principal_id="principal-a", project_id="project-a",
            event_type=SupervisionEventType.EDIT_PROPOSED,
            payload={"changed_paths": ["src/main.py"], "activity": {
                "operation": "edit", "kind": "file", "stage": "proposed",
                "scope": ["src/main.py"],
            }},
        )

        events = await service.events(
            "task-1", principal_id="principal-a", project_id="project-a"
        )
        assert [event.sequence for event in events] == [1, 2]
        assert events[-1].payload["changed_paths"] == ["src/main.py"]

        restarted = TaskSupervisionService(db)
        state = await restarted.state(
            "task-1", principal_id="principal-a", project_id="project-a"
        )
        assert state is not None
        assert state.sequence == 2
        assert state.status.value == "EDITING"
        assert state.changed_paths == ("src/main.py",)
        assert await restarted.state(
            "task-1", principal_id="principal-b", project_id="project-a"
        ) is None
    finally:
        await db.close()


def test_supervision_event_rejects_source_and_output_fields():
    with pytest.raises(SupervisionContractError):
        SupervisionEvent(
            task_id="task-1", workspace_id="workspace-1",
            event_type=SupervisionEventType.CONTEXT_PREPARED,
            payload={"stdout": "must not persist"},
        )


@pytest.mark.asyncio
async def test_untrusted_verification_prose_cannot_make_task_ready(tmp_path: Path):
    db = await _database(tmp_path)
    try:
        service = TaskSupervisionService(db)
        owner = {
            "task_id": "task-no-false-green",
            "workspace_id": "workspace-no-false-green",
            "principal_id": "principal-a",
            "project_id": "project-a",
        }
        await service.start_task(**owner, goal="verify")
        await service.emit(
            **owner,
            event_type=SupervisionEventType.VERIFICATION_PROGRESS,
            payload={
                "verification_state": "passed",
                "summary": "model prose claims that all tests passed",
            },
        )
        state = await service.state(
            owner["task_id"], principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        assert state is not None
        assert state.status.value == "VERIFYING"
        assert state.completion_eligibility == "unknown"
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_supervision_replay_fails_closed_on_history_gap_or_digest_tamper(
    tmp_path: Path,
):
    db = await _database(tmp_path)
    try:
        service = TaskSupervisionService(db)
        owner = {
            "task_id": "task-integrity",
            "workspace_id": "workspace-integrity",
            "principal_id": "principal-a",
            "project_id": "project-a",
        }
        await service.start_task(**owner, goal="integrity")
        await service.emit(
            **owner,
            event_type=SupervisionEventType.CONTEXT_PREPARED,
            payload={"status": "INVESTIGATING"},
        )
        gap_event = SupervisionEvent(
            event_id="gap-event",
            task_id=owner["task_id"],
            workspace_id=owner["workspace_id"],
            sequence=99,
            event_type=SupervisionEventType.CONTEXT_PREPARED,
            payload={"status": "INVESTIGATING"},
            principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        async with db.transaction() as conn:
            await conn.execute(
                "INSERT INTO task_supervision_events ("
                "event_id, task_id, workspace_id, principal_id, project_id, "
                "sequence, event_type, repository_generation, plan_revision, "
                "actor, severity, payload_json, event_digest, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    gap_event.event_id,
                    gap_event.task_id,
                    gap_event.workspace_id,
                    gap_event.principal_id,
                    gap_event.project_id,
                    gap_event.sequence,
                    gap_event.event_type.value,
                    gap_event.repository_generation,
                    gap_event.plan_revision,
                    gap_event.actor.value,
                    gap_event.severity.value,
                    canonical_json_bytes(dict(gap_event.payload)).decode("utf-8"),
                    gap_event.event_digest,
                    gap_event.created_at,
                ),
            )
        with pytest.raises(SupervisionIntegrityError):
            await service.events(
                owner["task_id"], principal_id=owner["principal_id"],
                project_id=owner["project_id"],
            )

        # Restore the history row through a fresh task and tamper only the
        # projection digest.  The reader must reject the durable projection.
        await service.start_task(
            task_id="task-digest", workspace_id="workspace-digest",
            principal_id=owner["principal_id"], project_id=owner["project_id"],
            goal="digest",
        )
        async with db.transaction() as conn:
            await conn.execute(
                "UPDATE task_supervision_states SET state_digest = ? "
                "WHERE task_id = ? AND principal_id = ? AND project_id = ?",
                ("0" * 64, "task-digest", owner["principal_id"], owner["project_id"]),
            )
        with pytest.raises(SupervisionIntegrityError):
            await service.state(
                "task-digest", principal_id=owner["principal_id"],
                project_id=owner["project_id"],
            )
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_pause_resume_cancel_are_durable_idempotent_and_cooperative(tmp_path: Path):
    db = await _database(tmp_path)
    try:
        service = TaskSupervisionService(db)
        owner = {
            "task_id": "task-control",
            "workspace_id": "workspace-control",
            "principal_id": "principal-a",
            "project_id": "project-a",
        }
        await service.start_task(**owner, goal="control")
        await service.register_runtime(**owner, runtime_id="runtime-1")

        first = await service.pause(**owner, command_id="pause-1")
        duplicate = await service.pause(**owner, command_id="pause-1")
        assert first.status.value == "APPLIED"
        assert first.control_state is ControlState.PAUSING
        assert duplicate.to_payload() == first.to_payload()

        waiting = asyncio.create_task(service.wait_if_paused(
            owner["task_id"],
            principal_id=owner["principal_id"], project_id=owner["project_id"],
        ))
        paused = None
        for _ in range(20):
            await asyncio.sleep(0)
            paused = await service.control.repository.get_control(
                owner["task_id"], principal_id=owner["principal_id"],
                project_id=owner["project_id"],
            )
            if paused is not None and paused.state is ControlState.PAUSED:
                break
        assert paused is not None
        assert paused.state is ControlState.PAUSED
        resumed = await service.resume(
            **owner, command_id="resume-1", expected_revision=paused.revision
        )
        assert resumed.status.value == "APPLIED"
        assert await waiting is True

        stale = await service.resume(
            **owner, command_id="resume-stale", expected_revision=paused.revision
        )
        assert stale.status.value == "REJECTED_STALE"

        await service.unregister_runtime(
            owner["task_id"], principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )

        async def worker() -> None:
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                await service.settle_cancel(**owner)
                raise

        runtime_task = asyncio.create_task(worker())
        await service.register_runtime(
            **owner, runtime_id="runtime-2", runtime_task=runtime_task
        )
        cancelled = await service.cancel(**owner, command_id="cancel-1")
        assert cancelled.status.value == "APPLIED"
        with pytest.raises(asyncio.CancelledError):
            await runtime_task
        control = await service.control.repository.get_control(
            owner["task_id"], principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        assert control is not None
        assert control.state is ControlState.CANCELLED
    finally:
        await db.close()


class _SupervisionChildWorkspaceService:
    """Small lifecycle double; the coordinator remains the tested owner."""

    async def create(
        self, assignment: SubagentAssignment, parent: TaskWorkspace
    ) -> tuple[ChildWorkspaceBinding, TaskWorkspace]:
        child = TaskWorkspace(
            id=f"child-{assignment.assignment_id}",
            task_id=f"child-task-{assignment.assignment_id}",
            repository_root=parent.repository_root,
            worktree_path=parent.worktree_path,
            base_ref=parent.base_sha,
            base_sha=parent.base_sha,
            branch_name=f"child/{assignment.assignment_id}",
            state=WorkspaceState.READY,
            principal_id=assignment.child_principal_id,
            project_id=assignment.project_id,
        )
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
        return binding, child

    async def mark_result(
        self, _assignment: SubagentAssignment, _status: SubagentResultStatus
    ) -> None:
        return None

    async def cleanup(
        self,
        assignment: SubagentAssignment,
        *,
        result_status: SubagentResultStatus,
    ) -> ChildCleanupResult:
        return ChildCleanupResult(
            assignment_id=assignment.assignment_id,
            state=ChildWorkspaceState.CLEANED,
            transition=WorkspaceTransition.UPDATED,
            reason="test cleanup",
        )


@pytest.mark.asyncio
async def test_parallel_child_lifecycle_projects_typed_supervision_state(
    tmp_path: Path,
):
    db = await _database(tmp_path)
    try:
        parent = TaskWorkspace(
            id="parent-supervision",
            task_id="task-subagents",
            repository_root=tmp_path,
            worktree_path=tmp_path,
            base_ref="HEAD",
            base_sha="a" * 40,
            branch_name="parent-supervision",
            state=WorkspaceState.READY,
            principal_id="principal-a",
            project_id="project-a",
        )
        context = AssignmentContext(
            parent_task_id=parent.task_id,
            parent_workspace_id=parent.id,
            objective="review a bounded child",
            selected_paths=("README.md",),
            base_generation=parent.generation,
            base_commit=parent.base_sha,
        )
        assignment = SubagentAssignment(
            parent_task_id=parent.task_id,
            parent_workspace_id=parent.id,
            role=SubagentRole.REVIEW,
            objective="review a bounded child",
            allowed_paths=("README.md",),
            allowed_symbols=(),
            access_mode=SubagentAccessMode.READ_ONLY,
            base_generation=parent.generation,
            base_commit=parent.base_sha,
            context_digest=context.context_digest,
            parent_principal_id=parent.principal_id,
            project_id=parent.project_id,
            assignment_id="assignment-supervision",
            context=context,
        )
        supervision = TaskSupervisionService(db)
        await supervision.start_task(
            task_id=parent.task_id,
            workspace_id=parent.id,
            principal_id=parent.principal_id,
            project_id=parent.project_id,
            goal="subagent supervision",
        )
        coordinator = SubagentCoordinator(_SupervisionChildWorkspaceService())
        coordinator.set_supervision_service(supervision)

        async def worker(
            current: SubagentAssignment, _binding, child: TaskWorkspace, _budget
        ) -> SubagentResult:
            return SubagentResult(
                assignment_id=current.assignment_id,
                parent_task_id=current.parent_task_id,
                parent_workspace_id=current.parent_workspace_id,
                status=SubagentResultStatus.FAILED,
                base_generation=current.base_generation,
                base_commit=current.base_commit,
                child_workspace_id=child.id,
                verification_status="not-run",
                error_code="test_failure",
            )

        results = await coordinator.run_parallel(parent, (assignment,), worker)
        assert results[0].status is SubagentResultStatus.FAILED
        events = await supervision.events(
            parent.task_id,
            principal_id=parent.principal_id,
            project_id=parent.project_id,
        )
        event_types = [event.event_type for event in events]
        assert SupervisionEventType.SUBAGENT_STARTED in event_types
        assert SupervisionEventType.SUBAGENT_FINISHED in event_types
        state = await supervision.state(
            parent.task_id,
            principal_id=parent.principal_id,
            project_id=parent.project_id,
        )
        assert state is not None
        assert state.active_subagents == ()
        assert state.activity is None
        assert state.status.value == "READY"
    finally:
        await db.close()


class _FakeWorkspaceManager:
    def __init__(self, workspace: TaskWorkspace) -> None:
        self.workspace = workspace

    def get(self, workspace_id: str) -> TaskWorkspace | None:
        return self.workspace if self.workspace.id == workspace_id else None

    async def current_head(self, _workspace_id: str) -> str:
        return "a" * 40

    async def current_tree(self, _workspace_id: str, *, commit: str) -> str:
        assert commit == "a" * 40
        return "b" * 40

    async def require_stable(self, *_args: object, **_kwargs: object) -> None:
        return None


class _FakeEditService:
    def __init__(self, manager: _FakeWorkspaceManager) -> None:
        self.manager = manager
        self.calls = 0

    async def apply(self, transaction: EditTransaction, **_kwargs: object) -> EditTransactionResult:
        self.calls += 1
        operation = transaction.operations[0]
        target = self.manager.workspace.worktree_path / operation.path
        target.write_text(operation.content or "", encoding="utf-8")
        self.manager.workspace.generation += 1
        after_digest = hashlib.sha256(target.read_bytes()).hexdigest()
        operation_result = EditOperationResult(
            index=0,
            operation=operation.operation,
            path=operation.path,
            destination_path=operation.destination_path,
            before_exists=True,
            after_exists=True,
            before_digest=operation.expected_digest,
            after_digest=after_digest,
        )
        return EditTransactionResult(
            transaction_id=transaction.transaction_id,
            workspace_id=transaction.workspace_id,
            base_generation=transaction.base_generation,
            resulting_generation=self.manager.workspace.generation,
            transaction_digest=transaction.transaction_digest,
            before_workspace_digest="c" * 64,
            after_workspace_digest="d" * 64,
            operations=(operation_result,),
        )


def _model_result(
    transaction: EditTransaction, *, before: str, after: str, generation: int
) -> EditTransactionResult:
    return EditTransactionResult(
        transaction_id=transaction.transaction_id,
        workspace_id=transaction.workspace_id,
        base_generation=transaction.base_generation,
        resulting_generation=generation,
        transaction_digest=transaction.transaction_digest,
        before_workspace_digest="c" * 64,
        after_workspace_digest="d" * 64,
        operations=(EditOperationResult(
            index=0,
            operation=EditOperationKind.UPDATE,
            path="tracked.txt",
            destination_path=None,
            before_exists=True,
            after_exists=True,
            before_digest=hashlib.sha256(before.encode()).hexdigest(),
            after_digest=hashlib.sha256(after.encode()).hexdigest(),
        ),),
    )


@pytest.mark.asyncio
async def test_checkpoint_rewind_uses_edit_transaction_and_preserves_unowned_files(tmp_path: Path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    tracked = worktree / "tracked.txt"
    tracked.write_text("before", encoding="utf-8")
    workspace = TaskWorkspace(
        id="workspace-rewind", task_id="task-rewind",
        repository_root=tmp_path, worktree_path=worktree,
        base_ref="main", base_sha="a" * 40, branch_name="task-rewind",
        state=WorkspaceState.READY,
        principal_id="principal-a", project_id="project-a",
    )
    manager = _FakeWorkspaceManager(workspace)
    edits = _FakeEditService(manager)
    db = await _database(tmp_path)
    try:
        supervision = TaskSupervisionService(db)
        owner = {
            "task_id": "task-rewind",
            "workspace_id": "workspace-rewind",
            "principal_id": "principal-a",
            "project_id": "project-a",
        }
        await supervision.start_task(**owner, goal="rewind")
        checkpoints = CheckpointService(
            manager, edits, db.checkpoint_repository, supervision,
        )
        checkpoint = await checkpoints.create_checkpoint(
            **owner, kind="USER_CREATED", known_state=True,
        )

        transaction = EditTransaction(
            transaction_id="model-tx", workspace_id=owner["workspace_id"],
            base_generation=1,
            operations=(EditOperation(
                operation=EditOperationKind.UPDATE, path="tracked.txt",
                expected_exists=True,
                expected_digest=hashlib.sha256(b"before").hexdigest(),
                content="after",
            ),),
        )
        await checkpoints.record_known_transaction(
            _model_result(transaction, before="before", after="after", generation=2),
            task_id=owner["task_id"], principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        tracked.write_text("after", encoding="utf-8")
        workspace.generation = 2
        unowned = worktree / "user.txt"
        unowned.write_text("keep me", encoding="utf-8")

        plan = await checkpoints.build_rewind_plan(
            checkpoint.checkpoint_id, principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        assert plan.conflicts == ()
        assert plan.source_snapshot_digest
        assert plan.affected_paths == ("tracked.txt",)
        assert plan.preserved_paths == ("user.txt",)

        result = await checkpoints.execute_rewind(
            plan, principal_id=owner["principal_id"], project_id=owner["project_id"]
        )
        assert result.status.value == "APPLIED"
        assert result.effect_applied is True
        assert edits.calls == 1
        assert tracked.read_text(encoding="utf-8") == "before"
        assert unowned.read_text(encoding="utf-8") == "keep me"
        assert workspace.generation == 3

        restarted = CheckpointService(
            manager, edits, db.checkpoint_repository, TaskSupervisionService(db),
        )
        persisted = await restarted.repository.get_rewind_result(
            plan.rewind_id, principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        assert persisted is not None
        assert persisted.result_digest == result.result_digest
    finally:
        await db.close()


@pytest.mark.asyncio
async def test_rewind_rejects_uncommitted_drift_before_edit_effect(tmp_path: Path):
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    tracked = worktree / "tracked.txt"
    tracked.write_text("before", encoding="utf-8")
    workspace = TaskWorkspace(
        id="workspace-stale", task_id="task-stale", repository_root=tmp_path,
        worktree_path=worktree, base_ref="main", base_sha="a" * 40,
        branch_name="task-stale", state=WorkspaceState.READY,
        principal_id="principal-a", project_id="project-a",
    )
    manager = _FakeWorkspaceManager(workspace)
    edits = _FakeEditService(manager)
    db = await _database(tmp_path)
    try:
        supervision = TaskSupervisionService(db)
        owner = {
            "task_id": "task-stale", "workspace_id": "workspace-stale",
            "principal_id": "principal-a", "project_id": "project-a",
        }
        await supervision.start_task(**owner, goal="stale")
        checkpoints = CheckpointService(manager, edits, db.checkpoint_repository, supervision)
        checkpoint = await checkpoints.create_checkpoint(
            **owner, kind="USER_CREATED", known_state=True,
        )
        # Establish a model-owned current state without changing Git HEAD/tree.
        transaction = EditTransaction(
            transaction_id="stale-model-tx", workspace_id=owner["workspace_id"],
            base_generation=1,
            operations=(EditOperation(
                operation=EditOperationKind.UPDATE, path="tracked.txt",
                expected_exists=True,
                expected_digest=hashlib.sha256(b"before").hexdigest(),
                content="after",
            ),),
        )
        await checkpoints.record_known_transaction(
            _model_result(transaction, before="before", after="after", generation=2),
            task_id=owner["task_id"], principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        tracked.write_text("after", encoding="utf-8")
        workspace.generation = 2
        plan = await checkpoints.build_rewind_plan(
            checkpoint.checkpoint_id, principal_id=owner["principal_id"],
            project_id=owner["project_id"],
        )
        tracked.write_text("user drift", encoding="utf-8")
        result = await checkpoints.execute_rewind(
            plan, principal_id=owner["principal_id"], project_id=owner["project_id"]
        )
        assert result.status.value == "REJECTED_STALE"
        assert result.effect_applied is False
        assert edits.calls == 0
        assert tracked.read_text(encoding="utf-8") == "user drift"
    finally:
        await db.close()
