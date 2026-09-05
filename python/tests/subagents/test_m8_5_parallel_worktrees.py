"""M8.5 contract, isolation, budget, and deterministic merge coverage."""

from __future__ import annotations

import asyncio
import hashlib
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from khaos.coding.edit_transaction import (
    EditOperation,
    EditTransaction,
    EditTransactionService,
)
from khaos.coding.execution import ExecutionResult
from khaos.coding.verification.evidence import VerificationObservationStore
from khaos.coding.verification.service import AutonomousVerificationCoordinator
from khaos.coding.workspace.errors import WorkspaceError
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceTransition
from khaos.subagents.contracts import (
    AssignmentContext,
    ChildWorkspaceBinding,
    ChildWorkspaceState,
    MergeCandidate,
    MergeCandidateBinding,
    MergePlan,
    MergeResult,
    MergeResultStatus,
    ParallelSubagentContractError,
    PublicationAttestation,
    SubagentAccessMode,
    SubagentAssignment,
    SubagentParallelismPolicy,
    SubagentResult,
    SubagentResultStatus,
    SubagentRole,
    validate_assignment_plan,
)
from khaos.subagents.coordinator import SubagentCoordinator
from khaos.subagents.merge import MergeCoordinator
from khaos.subagents.recovery import ParallelSubagentRecovery
from khaos.subagents.scheduler import (
    BoundedParallelScheduler,
    ChildUsage,
    SubagentBudgetExceeded,
    SubagentSchedulerError,
)
from khaos.subagents.workspace import ChildCleanupResult, ChildWorkspaceService


def _repo(path: Path) -> Path:
    path.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=path, check=True)
    (path / "README.md").write_text("base\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=path, check=True)
    subprocess.run(["git", "commit", "-qm", "base"], cwd=path, check=True)
    return path


def _assignment(
    parent: TaskWorkspace,
    assignment_id: str,
    path: str,
    *,
    role: SubagentRole = SubagentRole.IMPLEMENTATION,
    priority: int = 0,
) -> SubagentAssignment:
    context = AssignmentContext(
        parent_task_id=parent.task_id,
        parent_workspace_id=parent.id,
        objective=f"implement {path}",
        constraints=("use the typed edit transaction",),
        selected_paths=(path,),
        base_generation=parent.generation,
        base_commit=parent.base_sha,
    )
    access = (
        SubagentAccessMode.READ_ONLY
        if role in {SubagentRole.RESEARCH, SubagentRole.REVIEW}
        else SubagentAccessMode.MUTATING
    )
    return SubagentAssignment(
        parent_task_id=parent.task_id,
        parent_workspace_id=parent.id,
        role=role,
        objective=f"implement {path}",
        allowed_paths=(path,),
        allowed_symbols=(),
        access_mode=access,
        base_generation=parent.generation,
        base_commit=parent.base_sha,
        context_digest=context.context_digest,
        parent_principal_id=parent.principal_id,
        project_id=parent.project_id,
        assignment_id=assignment_id,
        priority=priority,
        context=context,
    )


def _result_without_artifact(
    assignment: SubagentAssignment,
    *,
    status: SubagentResultStatus = SubagentResultStatus.SUCCESS,
) -> SubagentResult:
    return SubagentResult(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        status=status,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
        child_workspace_id="child",
        verification_status="passed",
    )


async def _materialized_candidate(
    manager: WorkspaceManager,
    service: ChildWorkspaceService,
    parent: TaskWorkspace,
    assignment: SubagentAssignment,
    *,
    content: str = "child\n",
) -> tuple[MergeCandidate, TaskWorkspace]:
    """Create one real child result/artifact for authority-bound tests."""
    _binding, child = await service.create(assignment, parent)
    transaction = EditTransaction(
        f"materialize-{assignment.assignment_id}",
        child.id,
        child.generation,
        (
            EditOperation(
                "create",
                assignment.allowed_paths[0],
                expected_exists=False,
                content=content,
            ),
        ),
    )
    await EditTransactionService().apply(
        transaction,
        workspace_manager=manager,
        task_id=child.task_id,
        workspace_id=child.id,
        principal_id=child.principal_id,
        project_id=child.project_id,
        runtime_id=child.creator_runtime_id,
    )
    changeset = await manager.build_changeset(child.id)
    commit = await manager.commit_in_worktree(
        child.id,
        changeset,
        f"materialize {assignment.assignment_id}",
    )
    assert changeset.artifact is not None
    result = SubagentResult(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        status=SubagentResultStatus.SUCCESS,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
        child_workspace_id=child.id,
        child_final_commit=commit,
        changed_paths=assignment.allowed_paths,
        change_digest=changeset.content_hash,
        changeset_artifact_path=str(changeset.artifact.path),
        changeset_artifact_sha256=changeset.artifact.sha256,
        changeset_artifact_length=changeset.artifact.byte_length,
        verification_status="passed",
        verification_evidence_digest="a" * 64,
    )
    return MergeCandidate(assignment, result), child


async def _new_parent(tmp_path: Path, task_id: str) -> tuple[WorkspaceManager, TaskWorkspace]:
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        task_id,
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    return manager, parent


def test_m85_assignment_is_digest_bound_and_roles_do_not_grant_mutation() -> None:
    context = AssignmentContext(
        "task",
        "workspace",
        "inspect",
        base_generation=1,
        base_commit="a" * 40,
    )
    assignment = SubagentAssignment(
        "task",
        "workspace",
        SubagentRole.RESEARCH,
        "inspect",
        ("src",),
        (),
        SubagentAccessMode.READ_ONLY,
        base_commit="a" * 40,
        context_digest=context.context_digest,
        assignment_id="research-1",
        parent_principal_id="owner",
        project_id="project",
        context=context,
    )
    assert assignment.child_principal_id == "subagent:owner:research-1"
    assert assignment.mutating is False
    with pytest.raises((AttributeError, TypeError)):
        assignment.objective = "changed"  # type: ignore[misc]
    with pytest.raises(ParallelSubagentContractError):
        SubagentAssignment(
            "task",
            "workspace",
            SubagentRole.RESEARCH,
            "inspect",
            ("src",),
            (),
            SubagentAccessMode.MUTATING,
            base_commit="a" * 40,
            context_digest=context.context_digest,
            assignment_id="research-2",
            parent_principal_id="owner",
            project_id="project",
            context=context,
        )


def test_m85_plan_rejects_cycles_and_overlapping_mutating_scopes() -> None:
    context = AssignmentContext("task", "workspace", "work", base_commit="a" * 40)
    common = {
        "parent_task_id": "task",
        "parent_workspace_id": "workspace",
        "role": SubagentRole.IMPLEMENTATION,
        "objective": "work",
        "allowed_symbols": (),
        "access_mode": SubagentAccessMode.MUTATING,
        "base_commit": "a" * 40,
        "context_digest": context.context_digest,
        "parent_principal_id": "owner",
        "project_id": "project",
        "context": context,
    }
    left = SubagentAssignment(allowed_paths=("src",), assignment_id="left", **common)
    right = SubagentAssignment(allowed_paths=("src/app.py",), assignment_id="right", **common)
    with pytest.raises(ParallelSubagentContractError, match="overlapping"):
        validate_assignment_plan((left, right))
    cycle_left = SubagentAssignment(
        allowed_paths=("left",), assignment_id="cycle-left", dependencies=("cycle-right",), **common
    )
    cycle_right = SubagentAssignment(
        allowed_paths=("right",), assignment_id="cycle-right", dependencies=("cycle-left",), **common
    )
    with pytest.raises(ParallelSubagentContractError, match="cycle"):
        validate_assignment_plan((cycle_left, cycle_right))


@pytest.mark.asyncio
async def test_m85_scheduler_bounds_active_children_and_usage() -> None:
    scheduler = BoundedParallelScheduler(
        SubagentParallelismPolicy(
            max_active_children=1,
            max_mutating_children=1,
            max_research_children=1,
            max_child_tokens=2,
            max_aggregate_tokens=2,
        )
    )
    context = AssignmentContext("task", "workspace", "work", base_commit="a" * 40)
    assignment = SubagentAssignment(
        "task",
        "workspace",
        SubagentRole.IMPLEMENTATION,
        "work",
        ("src",),
        (),
        SubagentAccessMode.MUTATING,
        base_commit="a" * 40,
        context_digest=context.context_digest,
        assignment_id="budget-1",
        parent_principal_id="owner",
        project_id="project",
        context=context,
    )
    entered = asyncio.Event()
    release = asyncio.Event()

    async def worker(budget):
        await budget.charge(ChildUsage(tokens=1))
        entered.set()
        await release.wait()
        return _result_without_artifact(assignment)

    running = asyncio.create_task(scheduler.run(assignment, worker))
    await entered.wait()
    with pytest.raises(SubagentSchedulerError):
        await scheduler.run(assignment, worker)
    release.set()
    await running
    with pytest.raises(SubagentBudgetExceeded):
        await scheduler.run(
            assignment,
            lambda budget: budget.charge(ChildUsage(tokens=2)),  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_m85_scheduler_uses_serial_fallback_when_active_cap_is_reached() -> None:
    parent = TaskWorkspace(
        id="parent",
        task_id="parent-task",
        repository_root=Path("/repo"),
        worktree_path=Path("/worktree"),
        base_ref="HEAD",
        base_sha="a" * 40,
        branch_name="khaos/task/parent-task",
        principal_id="owner",
        project_id="project",
    )
    first = _assignment(parent, "serial-first", "one.txt")
    second = _assignment(parent, "serial-second", "two.txt")
    scheduler = BoundedParallelScheduler(
        SubagentParallelismPolicy(max_active_children=1, max_mutating_children=1)
    )
    first_started = asyncio.Event()
    first_release = asyncio.Event()
    second_started = asyncio.Event()

    async def worker(assignment, _budget):
        if assignment.assignment_id == first.assignment_id:
            first_started.set()
            await first_release.wait()
        else:
            second_started.set()
        return _result_without_artifact(assignment, status=SubagentResultStatus.FAILED)

    first_task = asyncio.create_task(
        scheduler.run(first, lambda budget: worker(first, budget))
    )
    await first_started.wait()
    second_task = asyncio.create_task(
        scheduler.run(second, lambda budget: worker(second, budget))
    )
    await asyncio.sleep(0)
    assert second_started.is_set() is False
    first_release.set()
    await asyncio.gather(first_task, second_task)
    assert second_started.is_set() is True


def test_m85_context_transfer_is_bounded_and_has_no_transcript() -> None:
    context = AssignmentContext(
        "task",
        "workspace",
        "objective",
        constraints=tuple(f"constraint-{index}" for index in range(64)),
        instructions=tuple(f"instruction-{index}" for index in range(64)),
        diagnostics=tuple(f"diagnostic-{index}" for index in range(64)),
        decisions=tuple(f"decision-{index}" for index in range(64)),
        base_commit="a" * 40,
    )
    assignment = SubagentAssignment(
        "task",
        "workspace",
        SubagentRole.IMPLEMENTATION,
        "objective",
        ("src",),
        (),
        SubagentAccessMode.MUTATING,
        base_commit="a" * 40,
        context_digest=context.context_digest,
        assignment_id="bounded-context",
        parent_principal_id="owner",
        project_id="project",
        context=context,
    )
    package = SubagentCoordinator._context_package(assignment)
    assert len(package.items) <= 64
    assert all(item.source != "parent.transcript" for item in package.items)
    assert all(len(item.value.encode("utf-8")) <= 16 * 1024 for item in package.items)


def test_m85_publication_attestation_requires_exact_tree_equality() -> None:
    with pytest.raises(ParallelSubagentContractError, match="tree equality"):
        PublicationAttestation(
            merge_id="merge",
            integration_workspace_id="integration",
            integration_generation=1,
            integration_commit="a" * 40,
            integration_tree_digest="b" * 40,
            parent_workspace_id="parent",
            parent_generation=2,
            parent_commit="c" * 40,
            parent_tree_digest="d" * 40,
            source_verification_evidence_digest="e" * 64,
        )


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_dirty_parent_rejects_child_without_losing_user_edit(tmp_path: Path) -> None:
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-dirty",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    transaction = EditTransaction(
        "user-edit",
        parent.id,
        parent.generation,
        (EditOperation("create", "user.txt", expected_exists=False, content="keep\n"),),
    )
    await EditTransactionService().apply(
        transaction,
        workspace_manager=manager,
        task_id=parent.task_id,
        workspace_id=parent.id,
        principal_id=parent.principal_id,
        project_id=parent.project_id,
        runtime_id=parent.creator_runtime_id,
    )
    assignment = _assignment(parent, "dirty-child", "child.txt")
    service = ChildWorkspaceService(manager)
    try:
        with pytest.raises(WorkspaceError, match="dirty|uncommitted"):
            await service.create(assignment, parent)
        assert (parent.worktree_path / "user.txt").read_text(encoding="utf-8") == "keep\n"
        assert service.binding_for(assignment.assignment_id) is None
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_cancelled_child_is_drained_and_cleaned(tmp_path: Path) -> None:
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-cancel",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    assignment = _assignment(parent, "cancel-child", "cancel.txt")
    service = ChildWorkspaceService(manager)
    coordinator = SubagentCoordinator(service)
    started = asyncio.Event()
    never = asyncio.Event()

    async def worker(_assignment, _binding, _child, _budget):
        started.set()
        await never.wait()
        raise AssertionError("cancelled child worker unexpectedly completed")

    running = asyncio.create_task(coordinator.run_parallel(parent, (assignment,), worker))
    try:
        await started.wait()
        running.cancel()
        with pytest.raises(asyncio.CancelledError):
            await running
        binding = service.binding_for(assignment.assignment_id)
        assert binding is not None
        child = manager.get(binding.child_workspace_id)
        assert child is not None and child.state.value == "cleaned"
        assert (parent.worktree_path / "cancel.txt").exists() is False
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
async def test_m85_durable_child_state_is_monotonic_and_events_are_append_only(
    tmp_path: Path,
) -> None:
    from khaos.db.database import Database

    database = Database(tmp_path / "parallel.db")
    await database.connect()
    await database.run_migrations()
    parent = TaskWorkspace(
        id="parent",
        task_id="parent-task",
        repository_root=tmp_path,
        worktree_path=tmp_path,
        base_ref="HEAD",
        base_sha="a" * 40,
        branch_name="khaos/task/parent-task",
        principal_id="owner",
        project_id="project",
    )
    assignment = _assignment(parent, "durable-child", "one.txt")
    binding = ChildWorkspaceBinding(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        child_task_id="child-task",
        child_workspace_id="child-workspace",
        child_worktree_path=str(tmp_path / "child-worktree"),
        child_branch="khaos/task/child-task",
        child_principal_id=assignment.child_principal_id,
        child_runtime_id=assignment.child_runtime_id,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
    )
    repository = database.parallel_subagent_repository
    await repository.record_assignment(assignment)
    await repository.record_binding(assignment, binding)
    assert await repository.child_state(assignment.assignment_id) is ChildWorkspaceState.READY
    await repository.update_child_state(assignment.assignment_id, ChildWorkspaceState.RUNNING)
    await repository.update_child_state(assignment.assignment_id, ChildWorkspaceState.SUCCESS)
    await repository.update_child_state(
        assignment.assignment_id,
        ChildWorkspaceState.CLEANED,
        result_status=SubagentResultStatus.SUCCESS,
    )
    await repository.update_child_state(
        assignment.assignment_id,
        ChildWorkspaceState.CLEANED,
        result_status=SubagentResultStatus.SUCCESS,
    )
    assert await repository.child_state(assignment.assignment_id) is ChildWorkspaceState.CLEANED
    with pytest.raises(RuntimeError, match="invalid parallel child state transition"):
        await repository.update_child_state(assignment.assignment_id, ChildWorkspaceState.READY)
    await repository.append_event(
        event_type="test_event",
        payload={"assignment_id": assignment.assignment_id},
        assignment_id=assignment.assignment_id,
    )
    with pytest.raises(Exception, match="append-only"):
        async with database.transaction() as conn:
            await conn.execute(
                "UPDATE agent_parallel_events SET event_type = 'tampered' WHERE event_type = 'test_event'"
            )
    await database.close()


@pytest.mark.asyncio
async def test_m85_restart_recovery_marks_unfinished_child_unknown(tmp_path: Path) -> None:
    from khaos.db.database import Database

    database = Database(tmp_path / "recovery.db")
    await database.connect()
    await database.run_migrations()
    parent = TaskWorkspace(
        id="parent",
        task_id="parent-task",
        repository_root=tmp_path,
        worktree_path=tmp_path,
        base_ref="HEAD",
        base_sha="a" * 40,
        branch_name="khaos/task/parent-task",
        principal_id="owner",
        project_id="project",
    )
    assignment = _assignment(parent, "restart-child", "restart.txt")
    binding = ChildWorkspaceBinding(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        child_task_id="restart-task",
        child_workspace_id="restart-workspace",
        child_worktree_path=str(tmp_path / "restart-worktree"),
        child_branch="khaos/task/restart-task",
        child_principal_id=assignment.child_principal_id,
        child_runtime_id=assignment.child_runtime_id,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
    )
    repository = database.parallel_subagent_repository
    await repository.record_assignment(assignment)
    await repository.record_binding(assignment, binding)
    await repository.update_child_state(assignment.assignment_id, ChildWorkspaceState.RUNNING)
    report = await ParallelSubagentRecovery(repository).reconcile()
    assert report.inspected == 1
    assert report.marked_unknown == 1
    assert await repository.child_state(assignment.assignment_id) is ChildWorkspaceState.UNKNOWN
    with pytest.raises(RuntimeError, match="invalid parallel child state transition"):
        await repository.update_child_state(assignment.assignment_id, ChildWorkspaceState.SUCCESS)
    await repository.update_child_state(
        assignment.assignment_id,
        ChildWorkspaceState.QUARANTINED,
        reason="cleanup requires recovery",
    )
    recovery = await ParallelSubagentRecovery(repository).reconcile()
    assert recovery.inspected == 1
    assert recovery.marked_unknown == 0
    assert recovery.quarantined == 1
    assert await repository.child_state(assignment.assignment_id) is ChildWorkspaceState.QUARANTINED
    await database.close()


@pytest.mark.asyncio
async def test_m85_durable_merge_replay_preserves_first_terminal_projection(
    tmp_path: Path,
) -> None:
    from khaos.db.database import Database

    database = Database(tmp_path / "merge-replay.db")
    await database.connect()
    await database.run_migrations()
    repository = database.parallel_subagent_repository
    plan = MergePlan(
        merge_id="durable-merge-replay",
        parent_task_id="parent-task",
        parent_workspace_id="parent-workspace",
        parent_generation=1,
        parent_base_commit="a" * 40,
        candidate_ids=(),
        ordered_candidate_ids=(),
    )
    await repository.record_merge_plan(plan)
    published = MergeResult(
        merge_id=plan.merge_id,
        status=MergeResultStatus.PUBLISHED,
        parent_task_id=plan.parent_task_id,
        parent_workspace_id=plan.parent_workspace_id,
        expected_parent_head=plan.parent_base_commit,
        expected_parent_generation=plan.parent_generation,
        candidate_ids=(),
        published_head="b" * 40,
        published_generation=2,
        plan_digest=plan.plan_digest,
    )
    await repository.record_merge_result(published)
    replay = MergeResult(
        merge_id=plan.merge_id,
        status=MergeResultStatus.REJECTED_STALE,
        parent_task_id=plan.parent_task_id,
        parent_workspace_id=plan.parent_workspace_id,
        expected_parent_head=plan.parent_base_commit,
        expected_parent_generation=plan.parent_generation,
        candidate_ids=(),
        plan_digest=plan.plan_digest,
        reason="old plan replay",
    )
    await repository.record_merge_result(replay)
    async with database.read_connection() as conn:
        cursor = await conn.execute(
            "SELECT state, result_digest FROM agent_parallel_merge_records WHERE merge_id = ?",
            (plan.merge_id,),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row["state"] == MergeResultStatus.PUBLISHED.value
    assert row["result_digest"] == published.result_digest
    await database.close()


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parallel_children_use_isolated_worktrees_and_republish_after_verification(
    tmp_path: Path,
) -> None:
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-task",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    assignments = (
        _assignment(parent, "child-a", "one.txt", priority=1),
        _assignment(parent, "child-b", "two.txt", priority=2),
    )
    service = ChildWorkspaceService(manager)
    verifier_calls: list[str] = []

    async def verifier(**kwargs):
        verifier_calls.append(str(kwargs["phase"]))
        return {"status": "passed", "evidence_digest": "b" * 64}

    merge = MergeCoordinator(
        manager,
        post_merge_verifier=verifier,
        allow_test_verifier=True,
    )
    coordinator = SubagentCoordinator(
        service,
        scheduler=BoundedParallelScheduler(
            SubagentParallelismPolicy(max_active_children=2, max_mutating_children=2)
        ),
        merge_coordinator=merge,
    )

    async def worker(assignment, binding, child, budget):
        assert Path(binding.child_worktree_path) == child.worktree_path
        assert child.worktree_path != parent.worktree_path
        assert child.principal_id == assignment.child_principal_id
        transaction = EditTransaction(
            f"tx-{assignment.assignment_id}",
            child.id,
            child.generation,
            (
                EditOperation(
                    "create",
                    assignment.allowed_paths[0],
                    expected_exists=False,
                    content=f"{assignment.assignment_id}\n",
                ),
            ),
        )
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=child.task_id,
            workspace_id=child.id,
            principal_id=child.principal_id,
            project_id=child.project_id,
            runtime_id=child.creator_runtime_id,
        )
        await budget.charge(ChildUsage(turns=1, tokens=1, tool_calls=1))
        changeset = await manager.build_changeset(child.id)
        commit = await manager.commit_in_worktree(
            child.id,
            changeset,
            f"child {assignment.assignment_id}",
        )
        assert changeset.artifact is not None
        return SubagentResult(
            assignment_id=assignment.assignment_id,
            parent_task_id=assignment.parent_task_id,
            parent_workspace_id=assignment.parent_workspace_id,
            status=SubagentResultStatus.SUCCESS,
            base_generation=assignment.base_generation,
            base_commit=assignment.base_commit,
            child_workspace_id=child.id,
            child_final_commit=commit,
            changed_paths=assignment.allowed_paths,
            change_digest=changeset.content_hash,
            changeset_artifact_path=str(changeset.artifact.path),
            changeset_artifact_sha256=changeset.artifact.sha256,
            changeset_artifact_length=changeset.artifact.byte_length,
            verification_status="passed",
            verification_evidence_digest="b" * 64,
        )

    try:
        results = await coordinator.run_parallel(parent, assignments, worker)
        assert {result.status for result in results} == {SubagentResultStatus.SUCCESS}
        for result in results:
            assert result.child_workspace_id != parent.id
        assert (parent.worktree_path / "one.txt").exists() is False
        assert (parent.worktree_path / "two.txt").exists() is False

        plan, merged = await coordinator.merge(parent, assignments)
        assert plan.ordered_candidate_ids == ("child-a", "child-b")
        assert merged.status is MergeResultStatus.PUBLISHED
        assert merged.published_generation == 2
        assert (parent.worktree_path / "one.txt").read_text(encoding="utf-8") == "child-a\n"
        assert (parent.worktree_path / "two.txt").read_text(encoding="utf-8") == "child-b\n"
        assert verifier_calls == ["integration", "parent"]
        assert all(
            manager.get(result.child_workspace_id) is not None
            and manager.get(result.child_workspace_id).state.value == "cleaned"
            for result in results
        )
    finally:
        transition = await manager.cleanup(parent.id, force=True)
        assert transition is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_merge_reuses_shared_m83_verification_for_both_worktrees(
    tmp_path: Path,
) -> None:
    repository = _repo(tmp_path / "repo")
    (repository / "src").mkdir()
    (repository / "tests").mkdir()
    (repository / "src" / "app.py").write_text(
        "def app():\n    return 1\n", encoding="utf-8"
    )
    (repository / "tests" / "test_app.py").write_text(
        "def test_app():\n    assert True\n", encoding="utf-8"
    )
    (repository / "pyproject.toml").write_text(
        "[tool.pytest]\n[tool.ruff]\n", encoding="utf-8"
    )
    await asyncio.to_thread(
        subprocess.run, ["git", "add", "."], cwd=repository, check=True
    )
    await asyncio.to_thread(
        subprocess.run,
        ["git", "commit", "-qm", "python base"],
        cwd=repository,
        check=True,
    )
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-m83",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    assignment = _assignment(parent, "m83-child", "one.py")

    class VerificationExecution:
        def __init__(self) -> None:
            self.requests = []

        async def execute(self, request):
            self.requests.append(request)
            return ExecutionResult("m83-exec", "completed", 0, "", "", 1, {})

        async def terminate(self, execution_id: str) -> None:
            del execution_id

    execution = VerificationExecution()
    verification = AutonomousVerificationCoordinator(
        execution_service=execution,
        evidence_store=VerificationObservationStore(),
        principal_id="owner",
        project_id="project",
    )
    merge = MergeCoordinator(
        manager,
        post_merge_verifier=verification.verify_after_merge,
    )
    coordinator = SubagentCoordinator(
        ChildWorkspaceService(manager),
        merge_coordinator=merge,
    )

    async def worker(assignment, _binding, child, _budget):
        transaction = EditTransaction(
            "m83-child-edit",
            child.id,
            child.generation,
            (
                EditOperation(
                    "create",
                    "one.py",
                    expected_exists=False,
                    content="value = 1\n",
                ),
            ),
        )
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=child.task_id,
            workspace_id=child.id,
            principal_id=child.principal_id,
            project_id=child.project_id,
            runtime_id=child.creator_runtime_id,
        )
        changeset = await manager.build_changeset(child.id)
        commit = await manager.commit_in_worktree(child.id, changeset, "child edit")
        assert changeset.artifact is not None
        return SubagentResult(
            assignment_id=assignment.assignment_id,
            parent_task_id=assignment.parent_task_id,
            parent_workspace_id=assignment.parent_workspace_id,
            status=SubagentResultStatus.SUCCESS,
            base_generation=assignment.base_generation,
            base_commit=assignment.base_commit,
            child_workspace_id=child.id,
            child_final_commit=commit,
            changed_paths=("one.py",),
            change_digest=changeset.content_hash,
            changeset_artifact_path=str(changeset.artifact.path),
            changeset_artifact_sha256=changeset.artifact.sha256,
            changeset_artifact_length=changeset.artifact.byte_length,
            verification_status="passed",
            verification_evidence_digest="d" * 64,
        )

    try:
        results = await coordinator.run_parallel(parent, (assignment,), worker)
        _plan, merged = await coordinator.merge(parent, (assignment,))
        assert results[0].status is SubagentResultStatus.SUCCESS
        assert merged.status is MergeResultStatus.PUBLISHED
        assert len(execution.requests) >= 2
        impact = verification.impact_for_task(parent.task_id)
        assert impact is not None and impact.operations == ("merge",)
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_stale_parent_rejects_merge_without_parent_mutation(tmp_path: Path) -> None:
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-stale",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    assignment = _assignment(parent, "stale-child", "stale.txt")
    service = ChildWorkspaceService(manager)
    _binding, child = await service.create(assignment, parent)
    result = SubagentResult(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        status=SubagentResultStatus.SUCCESS,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
        child_workspace_id=child.id,
        child_final_commit=child.base_sha,
        changed_paths=("stale.txt",),
        change_digest="c" * 64,
        changeset_artifact_path=str(manager.root / "missing.patch"),
        changeset_artifact_sha256="c" * 64,
        changeset_artifact_length=1,
        verification_status="passed",
        verification_evidence_digest="c" * 64,
    )
    candidate = MergeCandidate(assignment, result)
    coordinator = MergeCoordinator(manager, post_merge_verifier=lambda **_: True)
    plan = await coordinator.plan(parent, (candidate,))

    transaction = EditTransaction(
        "parent-drift",
        parent.id,
        parent.generation,
        (
            EditOperation("create", "parent.txt", expected_exists=False, content="drift\n"),
        ),
    )
    await EditTransactionService().apply(
        transaction,
        workspace_manager=manager,
        task_id=parent.task_id,
        workspace_id=parent.id,
        principal_id=parent.principal_id,
        project_id=parent.project_id,
        runtime_id=parent.creator_runtime_id,
    )
    try:
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.REJECTED_STALE
        assert (parent.worktree_path / "parent.txt").read_text(encoding="utf-8") == "drift\n"
        assert (parent.worktree_path / "stale.txt").exists() is False
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.FAILED)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_merge_rejects_artifact_paths_outside_assignment_claim(
    tmp_path: Path,
) -> None:
    """A forged result cannot hide an out-of-scope file inside its artifact."""
    repository = _repo(tmp_path / "repo")
    manager = WorkspaceManager(tmp_path / "worktrees")
    parent = await manager.create(
        repository,
        "parent-artifact-scope",
        principal_id="owner",
        project_id="project",
        creator_runtime_id="parent-runtime",
    )
    assignment = _assignment(parent, "artifact-scope-child", "one.txt")
    service = ChildWorkspaceService(manager)
    _binding, child = await service.create(assignment, parent)
    transaction = EditTransaction(
        "out-of-scope-child-edit",
        child.id,
        child.generation,
        (
            EditOperation("create", "one.txt", expected_exists=False, content="one\n"),
            EditOperation("create", "two.txt", expected_exists=False, content="two\n"),
        ),
    )
    await EditTransactionService().apply(
        transaction,
        workspace_manager=manager,
        task_id=child.task_id,
        workspace_id=child.id,
        principal_id=child.principal_id,
        project_id=child.project_id,
        runtime_id=child.creator_runtime_id,
    )
    changeset = await manager.build_changeset(child.id)
    commit = await manager.commit_in_worktree(child.id, changeset, "child scope test")
    assert changeset.artifact is not None
    forged = SubagentResult(
        assignment_id=assignment.assignment_id,
        parent_task_id=assignment.parent_task_id,
        parent_workspace_id=assignment.parent_workspace_id,
        status=SubagentResultStatus.SUCCESS,
        base_generation=assignment.base_generation,
        base_commit=assignment.base_commit,
        child_workspace_id=child.id,
        child_final_commit=commit,
        changed_paths=("one.txt",),
        change_digest=changeset.content_hash,
        changeset_artifact_path=str(changeset.artifact.path),
        changeset_artifact_sha256=changeset.artifact.sha256,
        changeset_artifact_length=changeset.artifact.byte_length,
        verification_status="passed",
        verification_evidence_digest="e" * 64,
    )
    candidate = MergeCandidate(assignment, forged)
    coordinator = MergeCoordinator(manager, post_merge_verifier=lambda **_: True)
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.CONFLICT
        assert (parent.worktree_path / "one.txt").exists() is False
        assert (parent.worktree_path / "two.txt").exists() is False
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.CONFLICT)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_plan_is_deterministic_and_binds_complete_candidate_identity(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "plan-determinism")
    service = ChildWorkspaceService(manager)
    first_assignment = _assignment(parent, "binding-first", "one.txt", priority=2)
    second_assignment = _assignment(parent, "binding-second", "two.txt", priority=1)
    first, _ = await _materialized_candidate(
        manager, service, parent, first_assignment, content="first\n"
    )
    second, _ = await _materialized_candidate(
        manager, service, parent, second_assignment, content="second\n"
    )
    coordinator = MergeCoordinator(manager)
    try:
        plans = [
            await coordinator.plan(
                parent,
                (first, second) if index % 2 == 0 else (second, first),
            )
            for index in range(10)
        ]
        assert plans[0].plan_digest == plans[1].plan_digest
        assert plans[0].merge_id == plans[1].merge_id
        assert plans[0].ordered_candidate_ids == ("binding-second", "binding-first")
        assert all(
            isinstance(binding, MergeCandidateBinding)
            for binding in plans[0].candidate_bindings
        )
        assert tuple(
            binding.result_digest for binding in plans[0].candidate_bindings
        ) == (second.result.result_digest, first.result.result_digest)
    finally:
        await service.cleanup(first_assignment, result_status=SubagentResultStatus.SUCCESS)
        await service.cleanup(second_assignment, result_status=SubagentResultStatus.SUCCESS)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_merge_rejects_every_candidate_binding_substitution(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "binding-substitution")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "binding-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)
    coordinator = MergeCoordinator(manager)
    plan = await coordinator.plan(parent, (candidate,))
    original_head = await manager.current_head(parent.id)

    result = candidate.result
    substitutions = (
        {"summary": "substituted result"},
        {"child_final_commit": "b" * 40},
        {"changeset_artifact_path": str(manager.root / "substituted.patch")},
        {"changeset_artifact_sha256": "b" * 64},
        {"changeset_artifact_length": result.changeset_artifact_length + 1},
        {"change_digest": "b" * 64},
        {"changed_paths": ()},
        {"verification_evidence_digest": "b" * 64},
    )
    try:
        for mutation in substitutions:
            mutated_result = replace(result, result_digest="", **mutation)
            mutated_candidate = MergeCandidate(assignment, mutated_result)
            merged = await coordinator.merge(parent, plan, (mutated_candidate,))
            assert merged.status is MergeResultStatus.REJECTED_STALE
            assert merged.published_head is None
            assert merged.plan_digest == plan.plan_digest
            assert await manager.current_head(parent.id) == original_head
            assert parent.generation == plan.parent_generation

        substituted_assignment = replace(
            assignment,
            objective="assignment substitution",
            assignment_digest="",
        )
        mutated_candidate = MergeCandidate(substituted_assignment, result)
        merged = await coordinator.merge(parent, plan, (mutated_candidate,))
        assert merged.status is MergeResultStatus.REJECTED_STALE
        assert await manager.current_head(parent.id) == original_head
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.SUCCESS)
        # The substituted assignment is never admitted as a live child, so it
        # shares the original child only for this test's cleanup seam.
        del child
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_child_head_drift_after_planning_is_rejected(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "child-head-drift")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "child-head-drift-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    original_head = await manager.current_head(parent.id)
    try:
        plan = await coordinator.plan(parent, (candidate,))
        drift = EditTransaction(
            "child-head-drift-edit",
            child.id,
            child.generation,
            (
                EditOperation(
                    "update",
                    "one.txt",
                    expected_exists=True,
                    expected_digest=hashlib.sha256(
                        (child.worktree_path / "one.txt").read_bytes()
                    ).hexdigest(),
                    content="drifted child\n",
                ),
            ),
        )
        await EditTransactionService().apply(
            drift,
            workspace_manager=manager,
            task_id=child.task_id,
            workspace_id=child.id,
            principal_id=child.principal_id,
            project_id=child.project_id,
            runtime_id=child.creator_runtime_id,
        )
        drift_changeset = await manager.build_changeset(
            child.id,
            base_sha=candidate.result.child_final_commit,
        )
        drift_head = await manager.commit_in_worktree(
            child.id,
            drift_changeset,
            "child head drift",
        )
        assert drift_head != candidate.result.child_final_commit

        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.REJECTED_STALE
        assert merged.published_head is None
        assert await manager.current_head(parent.id) == original_head
        assert parent.generation == plan.parent_generation
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.SUCCESS)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
@pytest.mark.parametrize("verification_status", ("failed", "timed_out", "infrastructure_error"))
async def test_m85_integration_verification_failure_never_publishes_parent(
    tmp_path: Path,
    verification_status: str,
) -> None:
    manager, parent = await _new_parent(tmp_path, "integration-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "integration-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)

    async def verifier(**_kwargs):
        return {"status": verification_status, "evidence_digest": "f" * 64}

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=verifier,
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    original_head = await manager.current_head(parent.id)
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.VERIFICATION_FAILED
        assert merged.published_head is None
        assert await manager.current_head(parent.id) == original_head
        assert parent.generation == plan.parent_generation
        assert (parent.worktree_path / "one.txt").exists() is False
        assert manager.get(child.id) is not None
        assert manager.get(child.id).state is not None
        assert manager.get(child.id).state.value == "cleaned"
        assert not manager._verified_artifacts
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_cleanup_failure_quarantines_without_parent_publication(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "cleanup-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "cleanup-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)

    async def failing_cleanup(assignment, *, result_status):
        del result_status
        return ChildCleanupResult(
            assignment_id=assignment.assignment_id,
            state=ChildWorkspaceState.QUARANTINED,
            transition=WorkspaceTransition.FAILED,
            reason="injected cleanup failure",
        )

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=failing_cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.QUARANTINED
        assert merged.published_head is None
        assert parent.generation == plan.parent_generation
        assert (parent.worktree_path / "one.txt").exists() is False
        assert manager.get(child.id) is not None
        assert manager._verified_artifacts == {}
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.SUCCESS)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_frozen_artifact_tamper_is_quarantined_before_parent_apply(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "artifact-tamper")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "tamper-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_get = manager.get_verified_artifact
    saved: list[tuple[str, Path, bytes]] = []

    async def tampering_get(storage_id: str):
        artifact = await original_get(storage_id)
        payload = artifact.path.read_bytes()
        saved.append((storage_id, artifact.path, payload))
        artifact.path.write_bytes(b"x" * len(payload))
        return artifact

    monkeypatch.setattr(manager, "get_verified_artifact", tampering_get)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.QUARANTINED
        assert merged.published_head is None
        assert parent.generation == plan.parent_generation
        assert (parent.worktree_path / "one.txt").exists() is False
        assert saved
        assert manager._verified_artifacts
    finally:
        for storage_id, path, payload in saved:
            path.write_bytes(payload)
            assert await manager.release_verified_artifact(storage_id) is WorkspaceTransition.UPDATED
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parent_audit_failure_reports_published_unverified_with_attestation(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "parent-audit-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "audit-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)

    async def verifier(**kwargs):
        if kwargs["phase"] == "integration":
            return {"status": "passed", "evidence_digest": "a" * 64}
        return {"status": "failed", "evidence_digest": "b" * 64}

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=verifier,
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.PUBLISHED_UNVERIFIED
        assert merged.published_head is not None
        assert merged.published_generation == plan.parent_generation + 1
        assert merged.verified_integration_artifact_digest
        assert merged.publication_attestation_digest
        assert merged.verification_evidence_digest == "a" * 64
        assert merged.parent_verification_evidence_digest == "b" * 64
        assert (parent.worktree_path / "one.txt").read_text(encoding="utf-8") == "child\n"
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parent_tree_drift_after_publish_is_published_quarantined(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "parent-tree-drift")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "tree-drift-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)

    async def verifier(**kwargs):
        if kwargs["phase"] == "parent":
            transaction = EditTransaction(
                "post-publish-drift",
                parent.id,
                parent.generation,
                (
                    EditOperation(
                        "create",
                        "drift.txt",
                        expected_exists=False,
                        content="untrusted drift\n",
                    ),
                ),
            )
            await EditTransactionService().apply(
                transaction,
                workspace_manager=manager,
                task_id=parent.task_id,
                workspace_id=parent.id,
                principal_id=parent.principal_id,
                project_id=parent.project_id,
                runtime_id=parent.creator_runtime_id,
            )
        return {"status": "passed", "evidence_digest": "a" * 64}

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=verifier,
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.PUBLISHED_QUARANTINED
        assert merged.published_head is not None
        assert merged.publication_attestation_digest == ""
        assert (parent.worktree_path / "drift.txt").read_text(encoding="utf-8") == "untrusted drift\n"
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_cancellation_during_child_cleanup_drains_without_publish(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "cleanup-cancel")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "cleanup-cancel-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_cleanup(assignment, *, result_status):
        entered.set()
        await release.wait()
        return await service.cleanup(assignment, result_status=result_status)

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=delayed_cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        running = asyncio.create_task(coordinator.merge(parent, plan, (candidate,)))
        await entered.wait()
        running.cancel()
        release.set()
        merged = await running
        assert merged.status is MergeResultStatus.CANCELLED
        assert merged.published_head is None
        assert parent.generation == plan.parent_generation
        assert manager.get(child.id) is not None
        assert manager.get(child.id).state.value == "cleaned"
    finally:
        if manager.get(child.id) is not None and manager.get(child.id).state.value != "cleaned":
            await service.cleanup(assignment, result_status=SubagentResultStatus.SUCCESS)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parent_cas_drift_after_artifact_freeze_rejects_publish(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "parent-cas-drift")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "cas-drift-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_head = await manager.current_head(parent.id)
    plan = None

    async def drift_parent_during_cleanup(assignment, *, result_status):
        cleanup_result = await service.cleanup(assignment, result_status=result_status)
        assert plan is not None
        transaction = EditTransaction(
            "parent-cas-drift-edit",
            parent.id,
            parent.generation,
            (
                EditOperation(
                    "create",
                    "drift.txt",
                    expected_exists=False,
                    content="concurrent parent change\n",
                ),
            ),
        )
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=parent.task_id,
            workspace_id=parent.id,
            principal_id=parent.principal_id,
            project_id=parent.project_id,
            runtime_id=parent.creator_runtime_id,
        )
        drift_changeset = await manager.build_changeset(parent.id, base_sha=original_head)
        await manager.commit_in_worktree(
            parent.id,
            drift_changeset,
            "concurrent parent change",
        )
        return cleanup_result

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=drift_parent_during_cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.REJECTED_STALE
        assert merged.published_head is None
        assert await manager.current_head(parent.id) != original_head
        assert parent.generation == plan.parent_generation + 1
        assert (parent.worktree_path / "one.txt").exists() is False
        assert (parent.worktree_path / "drift.txt").read_text(encoding="utf-8") == "concurrent parent change\n"
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parent_drift_before_publish_effect_is_not_reported_as_published(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "parent-drift-before-effect")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "parent-drift-before-effect-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_publish = MergeCoordinator._publish_parent_unshielded
    drifted = False

    async def publish_after_concurrent_drift(
        coordinator: MergeCoordinator,
        parent_workspace: TaskWorkspace,
        plan,
        artifact_path: Path,
        artifact_sha256: str,
        artifact_length: int,
    ) -> str:
        nonlocal drifted
        if not drifted:
            drifted = True
            transaction = EditTransaction(
                "parent-drift-before-effect-edit",
                parent.id,
                parent.generation,
                (
                    EditOperation(
                        "create",
                        "drift.txt",
                        expected_exists=False,
                        content="concurrent parent change\n",
                    ),
                ),
            )
            await EditTransactionService().apply(
                transaction,
                workspace_manager=manager,
                task_id=parent.task_id,
                workspace_id=parent.id,
                principal_id=parent.principal_id,
                project_id=parent.project_id,
                runtime_id=parent.creator_runtime_id,
            )
            drift_changeset = await manager.build_changeset(
                parent.id,
                base_sha=parent.base_sha,
            )
            await manager.commit_in_worktree(
                parent.id,
                drift_changeset,
                "concurrent parent change",
            )
        return await original_publish(
            coordinator,
            parent_workspace,
            plan,
            artifact_path,
            artifact_sha256,
            artifact_length,
        )

    monkeypatch.setattr(
        MergeCoordinator,
        "_publish_parent_unshielded",
        publish_after_concurrent_drift,
    )
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.REJECTED_STALE
        assert merged.published_head is None
        assert await manager.current_head(parent.id) != plan.parent_base_commit
        assert (parent.worktree_path / "drift.txt").read_text(encoding="utf-8") == (
            "concurrent parent change\n"
        )
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_parent_uncommitted_publish_failure_is_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "parent-uncommitted-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "parent-uncommitted-failure-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_commit = manager.commit_current_changeset

    async def failing_parent_commit(
        workspace_id: str,
        changeset,
        message: str,
        *,
        expected_head: str,
        expected_generation: int,
    ) -> str:
        if workspace_id == parent.id:
            raise WorkspaceError("injected Parent commit failure")
        return await original_commit(
            workspace_id,
            changeset,
            message,
            expected_head=expected_head,
            expected_generation=expected_generation,
        )

    monkeypatch.setattr(manager, "commit_current_changeset", failing_parent_commit)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.QUARANTINED
        assert merged.published_head is None
        assert await manager.current_head(parent.id) == plan.parent_base_commit
        assert (parent.worktree_path / "one.txt").read_text(encoding="utf-8") == "child\n"
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_integration_cleanup_failure_quarantines_before_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "integration-cleanup-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "integration-cleanup-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_cleanup = manager.cleanup
    integration_ids: list[str] = []

    async def failing_integration_cleanup(workspace_id: str, *, force: bool = False):
        workspace = manager.get(workspace_id)
        if workspace is not None and workspace.task_id.startswith("m85-merge-"):
            integration_ids.append(workspace_id)
            return WorkspaceTransition.FAILED
        return await original_cleanup(workspace_id, force=force)

    monkeypatch.setattr(manager, "cleanup", failing_integration_cleanup)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.QUARANTINED
        assert merged.published_head is None
        assert parent.generation == plan.parent_generation
        assert (parent.worktree_path / "one.txt").exists() is False
        assert integration_ids
    finally:
        monkeypatch.undo()
        for integration_id in set(integration_ids):
            assert await original_cleanup(integration_id, force=True) is WorkspaceTransition.UPDATED
        assert await original_cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_cancellation_during_integration_cleanup_drains_without_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "integration-cleanup-cancel")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "integration-cancel-child", "one.txt")
    candidate, child = await _materialized_candidate(manager, service, parent, assignment)
    original_cleanup = manager.cleanup
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_integration_cleanup(workspace_id: str, *, force: bool = False):
        workspace = manager.get(workspace_id)
        if workspace is not None and workspace.task_id.startswith("m85-merge-"):
            entered.set()
            await release.wait()
        return await original_cleanup(workspace_id, force=force)

    monkeypatch.setattr(manager, "cleanup", delayed_integration_cleanup)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        running = asyncio.create_task(coordinator.merge(parent, plan, (candidate,)))
        await entered.wait()
        running.cancel()
        release.set()
        merged = await running
        assert merged.status is MergeResultStatus.CANCELLED
        assert merged.published_head is None
        assert parent.generation == plan.parent_generation
        assert manager.get(child.id) is not None
        assert manager.get(child.id).state.value == "cleaned"
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
        assert await original_cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_cancellation_after_parent_cas_reports_publication_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, parent = await _new_parent(tmp_path, "publish-cancel")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "publish-cancel-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    original_commit = manager.commit_current_changeset
    entered = asyncio.Event()
    release = asyncio.Event()

    async def delayed_parent_commit(
        workspace_id: str,
        changeset,
        message: str,
        *,
        expected_head: str,
        expected_generation: int,
    ):
        if workspace_id == parent.id:
            entered.set()
            await release.wait()
        return await original_commit(
            workspace_id,
            changeset,
            message,
            expected_head=expected_head,
            expected_generation=expected_generation,
        )

    monkeypatch.setattr(manager, "commit_current_changeset", delayed_parent_commit)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        running = asyncio.create_task(coordinator.merge(parent, plan, (candidate,)))
        await entered.wait()
        running.cancel()
        release.set()
        merged = await running
        assert merged.status is MergeResultStatus.PUBLISHED_UNVERIFIED
        assert merged.published_head is not None
        assert merged.publication_attestation_digest
        assert (parent.worktree_path / "one.txt").read_text(encoding="utf-8") == "child\n"
    finally:
        if not running.done():
            running.cancel()
            await asyncio.gather(running, return_exceptions=True)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_post_publish_refresh_failure_is_not_plain_published(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "refresh-failure")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "refresh-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)

    async def refresh(**_kwargs):
        raise RuntimeError("refresh unavailable")

    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        repo_intelligence_refresh=refresh,
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        merged = await coordinator.merge(parent, plan, (candidate,))
        assert merged.status is MergeResultStatus.PUBLISHED_UNVERIFIED
        assert merged.published_head is not None
        assert merged.publication_attestation_digest
        assert (parent.worktree_path / "one.txt").exists()
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_double_publish_and_old_plan_replay_are_rejected(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "double-publish")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "double-publish-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    coordinator = MergeCoordinator(
        manager,
        post_merge_verifier=lambda **_kwargs: {
            "status": "passed",
            "evidence_digest": "a" * 64,
        },
        child_cleanup=service.cleanup,
        allow_test_verifier=True,
    )
    try:
        plan = await coordinator.plan(parent, (candidate,))
        first = await coordinator.merge(parent, plan, (candidate,))
        assert first.status is MergeResultStatus.PUBLISHED
        assert first.published_head is not None
        assert first.published_generation == plan.parent_generation + 1
        first_head = await manager.current_head(parent.id)
        second = await coordinator.merge(parent, plan, (candidate,))
        assert second.status is MergeResultStatus.REJECTED_STALE
        assert second.published_head is None
        assert await manager.current_head(parent.id) == first_head
        assert parent.generation == first.published_generation
    finally:
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED


@pytest.mark.asyncio
@pytest.mark.posix_host
@pytest.mark.requires_trusted_git
async def test_m85_merge_replay_across_parent_workspace_and_project_is_rejected(
    tmp_path: Path,
) -> None:
    manager, parent = await _new_parent(tmp_path, "replay-parent-a")
    other_root = tmp_path / "other"
    other_root.mkdir()
    other_manager, other_parent = await _new_parent(other_root, "replay-parent-b")
    service = ChildWorkspaceService(manager)
    assignment = _assignment(parent, "replay-child", "one.txt")
    candidate, _child = await _materialized_candidate(manager, service, parent, assignment)
    coordinator = MergeCoordinator(manager, child_cleanup=service.cleanup)
    try:
        plan = await coordinator.plan(parent, (candidate,))
        other_head = await other_manager.current_head(other_parent.id)
        replayed = await coordinator.merge(other_parent, plan, (candidate,))
        assert replayed.status is MergeResultStatus.REJECTED_STALE
        assert replayed.published_head is None
        assert await other_manager.current_head(other_parent.id) == other_head

        project_replay = replace(parent, project_id="different-project")
        project_head = await manager.current_head(parent.id)
        replayed = await coordinator.merge(project_replay, plan, (candidate,))
        assert replayed.status is MergeResultStatus.REJECTED_STALE
        assert replayed.published_head is None
        assert await manager.current_head(parent.id) == project_head
    finally:
        await service.cleanup(assignment, result_status=SubagentResultStatus.SUCCESS)
        assert await manager.cleanup(parent.id, force=True) is WorkspaceTransition.UPDATED
        assert await other_manager.cleanup(other_parent.id, force=True) is WorkspaceTransition.UPDATED
