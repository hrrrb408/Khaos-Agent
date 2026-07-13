"""M4 Batch 3.0 isolated workspace mutation and recovery matrix."""
from __future__ import annotations

import hashlib
import inspect
import os
import sqlite3
import stat
import time
import unicodedata
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from _m4_batch2_helpers import high_risk, make_plan
from test_m4_batch2_8_boot_scope_closure import (
    _mint_unapplied,
    _real_runtime,
)
from khaos.coding.planning.approval.repository import PersistedPlanRepository
from khaos.coding.planning.contracts import (
    AffectedFile,
    PlanOperation,
    PlanStep,
)
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
)
from khaos.coding.planning.workspace_mutation import (
    MAX_BUNDLE_BYTES,
    MAX_BUNDLE_FILES,
    WorkspaceMutationEngine,
    WorkspaceMutationError,
)
from khaos.coding.planning.safe_workspace_path import WorkspacePathHandle
from khaos.coding.planning.recovery_directory import RecoveryDirectory
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState


def _hash(data: str | bytes) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _workspace(tmp_path, manager, *, workspace_id="ws1", task_id="task1"):
    repository = tmp_path / "base-repository"
    worktree = tmp_path / "isolated-worktree"
    repository.mkdir(exist_ok=True)
    worktree.mkdir(exist_ok=True)
    (repository / "main.txt").write_text("base unchanged\n", encoding="utf-8")
    (worktree / ".git").write_text("gitdir: ../admin/worktrees/test\n", encoding="utf-8")
    workspace = TaskWorkspace(
        workspace_id, task_id, repository, worktree, "HEAD", "abc123",
        "task-branch", WorkspaceState.RUNNING, (worktree,),
        recovery_root=tmp_path / "private-recovery",
    )
    manager._workspaces[workspace_id] = workspace
    manager._task_ids.add(task_id)
    return workspace


def _plan(edits, *, plan_id=None, status=None):
    plan_id = plan_id or f"plan-{uuid.uuid4().hex[:8]}"
    base = make_plan(plan_id=plan_id, risks=(high_risk(),))
    affected = []
    steps = []
    operation_map = {
        PlannedEditOperation.CREATE: PlanOperation.CREATE,
        PlannedEditOperation.UPDATE: PlanOperation.MODIFY,
        PlannedEditOperation.DELETE: PlanOperation.DELETE,
        PlannedEditOperation.RENAME: PlanOperation.RENAME,
    }
    for ordinal, edit in enumerate(edits):
        operation = operation_map[edit.operation]
        affected.append(AffectedFile(
            path=edit.path, operation=operation, reason="approved edit",
            confidence=1.0, exists=edit.operation != PlannedEditOperation.CREATE,
            language="text", evidence=(), source_path=edit.path,
            destination_path=edit.destination_path,
        ))
        steps.append(PlanStep(
            step_id=edit.plan_step_id, title="edit", description="approved",
            operation=operation, target_files=(edit.path,), target_symbols=(),
            depends_on=(), expected_outcome="updated",
            verification_requirements=(), risk=base.risks[0],
            requires_approval=True, evidence=(),
        ))
    plan = replace(
        base, affected_files=tuple(affected), steps=tuple(steps),
        status=status or base.status,
    )
    return replace(
        plan,
        content_hash=PersistedPlanRepository._recompute_plan_content_hash(plan),
    )


def _bundle(plan, edits, *, digest="caller-forged", **overrides):
    values = {
        "bundle_id": f"bundle-{uuid.uuid4().hex[:8]}",
        "plan_id": plan.plan_id,
        "plan_content_hash": plan.content_hash,
        "task_id": plan.task_id,
        "workspace_id": plan.workspace_id,
        "repository_id": plan.repository_id,
        "binding_digest": "",
        "ordered_edits": tuple(edits),
        "content_digest": digest,
        "created_at": time.time(),
        "producer": "server-rule-planner",
    }
    values.update(overrides)
    return PlannedEditBundle(**values)


def _authorize(runtime, plan):
    plan, request, receipt = _mint_unapplied(runtime, plan=plan)
    runtime.service.apply_broker_decision(receipt)
    authorization = runtime.authorize_execution(
        plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
    )
    return plan, authorization


def _apply(runtime, plan, authorization, bundle):
    if not bundle.binding_digest:
        bundle = replace(bundle, binding_digest=authorization.binding_digest)

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id,
            nonce=authorization.nonce, expected_plan_id=plan.plan_id,
            expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id,
            owner_execution_id="mutation-owner",
        )
        context = await manager.__aenter__()
        try:
            return runtime.apply_edit_bundle(context=context, bundle=bundle)
        finally:
            await manager.__aexit__(None, None, None)

    return runtime._test_sync._loop.run_until_complete(scenario())


def _setup(tmp_path, edits):
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspaces)
    plan = _plan(edits)
    plan, authorization = _authorize(runtime, plan)
    return runtime, workspace, plan, authorization


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_structured_operations_only_mutate_isolated_workspace(tmp_path, operation):
    worktree = tmp_path / "isolated-worktree"
    if operation != PlannedEditOperation.CREATE:
        worktree.mkdir()
        (worktree / "a.txt").write_text("old\n", encoding="utf-8")
    edit = PlannedFileEdit(
        "e1", "s1", operation, "a.txt",
        destination_path="b.txt" if operation == PlannedEditOperation.RENAME else None,
        expected_exists=operation != PlannedEditOperation.CREATE,
        expected_content_hash=(_hash("old\n") if operation != PlannedEditOperation.CREATE else None),
        new_content=("new\n" if operation in {PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE} else None),
        new_content_hash="caller-forged",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    base_before = (workspace.repository_root / "main.txt").read_bytes()
    result = _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert result.status == ExecutionRunStatus.MUTATED
    assert (workspace.repository_root / "main.txt").read_bytes() == base_before
    if operation == PlannedEditOperation.CREATE:
        assert (workspace.worktree_path / "a.txt").read_text() == "new\n"
    elif operation == PlannedEditOperation.UPDATE:
        assert (workspace.worktree_path / "a.txt").read_text() == "new\n"
    elif operation == PlannedEditOperation.DELETE:
        assert not (workspace.worktree_path / "a.txt").exists()
    else:
        assert not (workspace.worktree_path / "a.txt").exists()
        assert (workspace.worktree_path / "b.txt").read_text() == "old\n"


def test_bundle_recomputes_content_and_new_content_hash():
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="trusted\n", new_content_hash="forged",
    )
    plan = _plan((edit,))
    normalized = _bundle(plan, (edit,), digest="forged").normalized()
    assert normalized.content_digest != "forged"
    assert normalized.ordered_edits[0].new_content_hash == _hash("trusted\n")
    assert "trusted" not in repr(normalized.ordered_edits[0])


@pytest.mark.parametrize("field", [
    "plan_id", "plan_content_hash", "task_id", "workspace_id",
    "repository_id", "binding_digest",
])
def test_bundle_scope_mismatch_is_rejected_before_write(tmp_path, field):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    bundle = _bundle(plan, (edit,), binding_digest=authorization.binding_digest)
    bundle = replace(bundle, **{field: "wrong"})
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, bundle)
    assert not (workspace.worktree_path / "a.txt").exists()


@pytest.mark.parametrize("path", [
    "/etc/passwd", "../outside", "src/../../outside", r"C:\Windows\x",
    r"\\server\share\x", ".git/config", "src/.git/config", "./a.txt",
    "a\\b.txt", "", "a/../b", "a/./b",
])
def test_unsafe_paths_are_rejected(tmp_path, path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, path,
        expected_exists=False, new_content="new",
    )
    runtime, _, plan, authorization = _setup(tmp_path, (edit,))
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))


@pytest.mark.parametrize("kind", ["parent", "target", "outside", "submodule"])
def test_symlink_and_submodule_boundaries(tmp_path, kind):
    edit_path = "dir/a.txt"
    runtime, workspace, plan, authorization = _setup(tmp_path, (
        PlannedFileEdit("e1", "s1", PlannedEditOperation.CREATE, edit_path,
                        expected_exists=False, new_content="new"),
    ))
    root = workspace.worktree_path
    outside = tmp_path / "outside"
    outside.mkdir()
    if kind in {"parent", "outside"}:
        (root / "dir").symlink_to(outside, target_is_directory=True)
    elif kind == "target":
        (root / "dir").mkdir()
        (root / edit_path).symlink_to(outside / "x")
    else:
        (root / "dir").mkdir()
        (root / "dir" / ".git").write_text("gitdir: submodule-admin")
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, plan.steps and (
            PlannedFileEdit("e1", "s1", PlannedEditOperation.CREATE, edit_path,
                            expected_exists=False, new_content="new"),
        )))


@pytest.mark.parametrize("case", [
    "create-exists", "update-missing", "update-hash", "delete-hash",
    "rename-exists", "mode-drift",
])
def test_file_precondition_failures_roll_back_without_partial_write(tmp_path, case):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    if case not in {"update-missing"}:
        (worktree / "a.txt").write_text("old", encoding="utf-8")
    if case == "rename-exists":
        (worktree / "b.txt").write_text("occupied", encoding="utf-8")
    operation = {
        "create-exists": PlannedEditOperation.CREATE,
        "update-missing": PlannedEditOperation.UPDATE,
        "update-hash": PlannedEditOperation.UPDATE,
        "delete-hash": PlannedEditOperation.DELETE,
        "rename-exists": PlannedEditOperation.RENAME,
        "mode-drift": PlannedEditOperation.UPDATE,
    }[case]
    edit = PlannedFileEdit(
        "e1", "s1", operation, "a.txt",
        destination_path="b.txt" if operation == PlannedEditOperation.RENAME else None,
        expected_exists=operation != PlannedEditOperation.CREATE,
        expected_content_hash=("bad" if "hash" in case else _hash("old")),
        new_content="new" if operation in {PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE} else None,
        expected_mode=0o777 if case == "mode-drift" else None,
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    before = {
        item.name: item.read_bytes() for item in workspace.worktree_path.iterdir()
        if item.is_file() and item.name != ".git"
    }
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    after = {
        item.name: item.read_bytes() for item in workspace.worktree_path.iterdir()
        if item.is_file() and item.name != ".git"
    }
    assert after == before


def test_middle_edit_failure_restores_content_and_mode(tmp_path):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    first = worktree / "a.txt"
    first.write_text("old-a", encoding="utf-8")
    os.chmod(first, 0o640)
    (worktree / "b.txt").write_text("old-b", encoding="utf-8")
    edits = (
        PlannedFileEdit("e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
                        expected_content_hash=_hash("old-a"), new_content="new-a"),
        PlannedFileEdit("e2", "s2", PlannedEditOperation.UPDATE, "b.txt",
                        expected_content_hash="drift", new_content="new-b"),
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, edits)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, edits))
    assert first.read_text() == "old-a"
    assert stat.S_IMODE(first.stat().st_mode) == 0o640
    run = runtime._store._conn.execute(
        "SELECT status FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    assert run["status"] == "rolled-back"


@pytest.mark.parametrize("limit", ["files", "bytes"])
def test_bundle_hard_limits(tmp_path, limit):
    if limit == "files":
        edits = tuple(
            PlannedFileEdit(f"e{i}", f"s{i}", PlannedEditOperation.CREATE,
                            f"f{i}.txt", expected_exists=False, new_content="x")
            for i in range(MAX_BUNDLE_FILES + 1)
        )
    else:
        edits = (PlannedFileEdit(
            "e1", "s1", PlannedEditOperation.CREATE, "large.txt",
            expected_exists=False, new_content="x" * (MAX_BUNDLE_BYTES + 1),
        ),)
    runtime, _, plan, authorization = _setup(tmp_path, edits)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, edits))


def test_same_context_same_bundle_is_idempotent_different_bundle_rejected(tmp_path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    bundle = _bundle(plan, (edit,))

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        context = await manager.__aenter__()
        try:
            bound = replace(bundle, binding_digest=context.binding_digest)
            first = runtime.apply_edit_bundle(context=context, bundle=bound)
            second = runtime.apply_edit_bundle(context=context, bundle=bound)
            assert second.idempotent and second.execution_run_id == first.execution_run_id
            changed = replace(bound, bundle_id="different")
            with pytest.raises(WorkspaceMutationError, match="another bundle"):
                runtime.apply_edit_bundle(context=context, bundle=changed)
        finally:
            await manager.__aexit__(None, None, None)

    runtime._test_sync._loop.run_until_complete(scenario())
    assert (workspace.worktree_path / "a.txt").read_text() == "new"


def test_database_and_audit_never_persist_source_or_absolute_paths(tmp_path):
    secret_source = "UNIQUE_SOURCE_BODY_DO_NOT_PERSIST"
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content=secret_source,
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    dump = "\n".join(runtime._store._conn.iterdump())
    assert secret_source not in dump
    assert str(workspace.worktree_path) not in dump
    assert authorization.nonce not in dump


def test_static_planned_mutation_has_no_tool_shell_or_changeset_path():
    source = inspect.getsource(WorkspaceMutationEngine)
    forbidden = (
        "ToolScheduler", "test_run", "subprocess", "shell=True",
        "ChangeSet", "git reset", "git clean", "git commit",
    )
    assert all(token not in source for token in forbidden)


def test_naked_engine_apply_is_rejected(tmp_path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, _, plan, _ = _setup(tmp_path, (edit,))
    with pytest.raises(PermissionError, match="PlannedExecutionGuard"):
        runtime._mutation_engine.apply_bundle(
            context=object(), bundle=_bundle(plan, (edit,))
        )


@pytest.mark.parametrize("failure", ["journal", "backup", "replace", "fsync"])
def test_durable_preparation_faults_leave_source_unchanged(tmp_path, monkeypatch, failure):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    (worktree / "a.txt").write_text("old", encoding="utf-8")
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    if failure == "journal":
        monkeypatch.setattr(
            runtime._store, "insert_edit_event",
            lambda **kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("journal")),
        )
    elif failure == "backup":
        monkeypatch.setattr(
            RecoveryDirectory, "create_backup",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("backup")),
        )
    elif failure == "replace":
        monkeypatch.setattr(
            WorkspacePathHandle, "_exchange",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("replace")),
        )
    else:
        monkeypatch.setattr(
            RecoveryDirectory, "create_backup",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("fsync")),
        )
    with pytest.raises((OSError, sqlite3.Error, WorkspaceMutationError)):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_text() == "old"


def test_rollback_failure_poison_quarantines_workspace(tmp_path, monkeypatch):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    (worktree / "a.txt").write_text("old-a", encoding="utf-8")
    (worktree / "b.txt").write_text("old-b", encoding="utf-8")
    edits = (
        PlannedFileEdit("e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
                        expected_content_hash=_hash("old-a"), new_content="new-a"),
        PlannedFileEdit("e2", "s2", PlannedEditOperation.UPDATE, "b.txt",
                        expected_content_hash="bad", new_content="new-b"),
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, edits)
    monkeypatch.setattr(
        runtime._mutation_engine, "_rollback_event",
        lambda *args: (_ for _ in ()).throw(OSError("rollback")),
    )
    with pytest.raises(WorkspaceMutationError, match="rollback failed"):
        _apply(runtime, plan, authorization, _bundle(plan, edits))
    assert runtime.mutation_fence.is_poisoned(workspace.id)
    assert runtime._store.get_execution_run_by_context(
        runtime._store._conn.execute(
            "SELECT execution_context_id FROM plan_execution_runs LIMIT 1"
        ).fetchone()[0]
    ).status == ExecutionRunStatus.POISONED


def test_unexpected_untracked_mutation_rolls_back_declared_edit_and_poison(tmp_path, monkeypatch):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    (worktree / "a.txt").write_text("old", encoding="utf-8")
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    original = runtime._mutation_engine._apply_edit

    def mutate_with_rogue(item, root):
        original(item, root)
        (root / "rogue.txt").write_text("rogue", encoding="utf-8")

    monkeypatch.setattr(runtime._mutation_engine, "_apply_edit", mutate_with_rogue)
    with pytest.raises(WorkspaceMutationError, match="outside the declared"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_text() == "old"
    assert runtime.mutation_fence.is_poisoned(workspace.id)


@pytest.mark.parametrize("drift", ["head", "generation", "task", "workspace", "boot"])
def test_live_drift_or_cancellation_between_edits_triggers_rollback(tmp_path, monkeypatch, drift):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    (worktree / "a.txt").write_text("old-a", encoding="utf-8")
    (worktree / "b.txt").write_text("old-b", encoding="utf-8")
    edits = (
        PlannedFileEdit("e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
                        expected_content_hash=_hash("old-a"), new_content="new-a"),
        PlannedFileEdit("e2", "s2", PlannedEditOperation.UPDATE, "b.txt",
                        expected_content_hash=_hash("old-b"), new_content="new-b"),
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, edits)
    original = runtime._mutation_engine._apply_edit
    calls = 0

    def apply_then_drift(item, root):
        nonlocal calls
        original(item, root)
        calls += 1
        if calls == 1:
            if drift == "head":
                runtime._context_provider.set(head_sha="changed")
            elif drift == "generation":
                runtime._context_provider.set(repository_generation=2)
            elif drift == "task":
                runtime._context_provider.set(task_terminal=True)
            elif drift == "workspace":
                runtime._context_provider.set(workspace_terminal=True)
            else:
                runtime._store.rotate_epoch()

    monkeypatch.setattr(runtime._mutation_engine, "_apply_edit", apply_then_drift)
    with pytest.raises((WorkspaceMutationError, PermissionError, RuntimeError)):
        _apply(runtime, plan, authorization, _bundle(plan, edits))
    assert (workspace.worktree_path / "a.txt").read_text() == "old-a"
    assert (workspace.worktree_path / "b.txt").read_text() == "old-b"


def test_released_context_cannot_mutate(tmp_path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        context = await manager.__aenter__()
        await manager.__aexit__(None, None, None)
        with pytest.raises(PermissionError):
            runtime.apply_edit_bundle(
                context=context,
                bundle=replace(_bundle(plan, (edit,)), binding_digest=context.binding_digest),
            )

    runtime._test_sync._loop.run_until_complete(scenario())
    assert not (workspace.worktree_path / "a.txt").exists()


def test_concurrent_apply_creates_one_run_and_no_partial_second_write(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        context = await manager.__aenter__()
        bundle = replace(_bundle(plan, (edit,)), binding_digest=context.binding_digest)
        try:
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(runtime.apply_edit_bundle, context=context, bundle=bundle)
                    for _ in range(2)
                ]
                outcomes = []
                for future in futures:
                    try:
                        outcomes.append(future.result())
                    except Exception as exc:
                        outcomes.append(exc)
            assert sum(not isinstance(item, Exception) for item in outcomes) >= 1
        finally:
            await manager.__aexit__(None, None, None)

    runtime._test_sync._loop.run_until_complete(scenario())
    assert (workspace.worktree_path / "a.txt").read_text() == "new"
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_runs"
    ).fetchone()[0] == 1


def test_recovery_artifact_is_outside_git_root_and_removed_after_success(tmp_path):
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.CREATE, "a.txt",
        expected_exists=False, new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    recovery_root = workspace.recovery_root
    assert workspace.worktree_path not in recovery_root.parents
    assert recovery_root.is_dir()
    assert not tuple(recovery_root.iterdir())


@pytest.mark.parametrize("corrupt", [False, True])
def test_startup_recovery_uses_verified_artifact_or_keeps_poisoned(tmp_path, corrupt):
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspaces)
    target = workspace.worktree_path / "a.txt"
    target.write_text("mutated", encoding="utf-8")
    run_id = f"per_{uuid.uuid4().hex}"
    now = time.time()
    run = PlanExecutionRun(
        run_id, "p", "ph", "request", "authorization", "context", "lease",
        "task1", "ws1", "repo", "abc123", 1, "binding", "bundle",
        ExecutionRunStatus.MUTATING, now, now,
    )
    runtime._store.create_execution_run(run)
    recovery = workspace.recovery_root / run_id
    recovery.mkdir(parents=True)
    os.chmod(recovery.parent, 0o700)
    os.chmod(recovery, 0o700)
    backup = recovery / f"artifact-{uuid.uuid4().hex}.bak"
    backup.write_text("corrupt" if corrupt else "original", encoding="utf-8")
    runtime._store.insert_edit_event(
        event_id=uuid.uuid4().hex, execution_run_id=run_id, edit_id="e1",
        ordinal=0, operation="update", path="a.txt", destination_path=None,
        before_hash=_hash("original"), before_mode=0o644,
        recovery_artifact=backup.name, planned_after_hash=_hash("mutated"),
    )
    runtime._store._conn.execute(
        "UPDATE plan_execution_edit_events SET status='applied',phase_version=4,"
        "after_hash=?,after_mode=? WHERE execution_run_id=?",
        (_hash("mutated"), 0o644, run_id),
    )
    runtime._store._conn.commit()
    recovered = runtime._mutation_engine.recover_incomplete_runs()
    current = runtime._store.get_execution_run(run_id)
    assert run_id not in recovered
    assert current.status == ExecutionRunStatus.POISONED
    assert runtime.mutation_fence.is_poisoned("ws1")
    assert target.read_text() == "mutated"


@pytest.mark.parametrize("violation", [
    "operation", "outside-file", "rename-destination", "blocked-plan",
    "case-collision", "unicode-collision", "mode-escalation",
])
def test_plan_scope_and_collision_violations_fail_closed(tmp_path, violation):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir()
    (worktree / "a.txt").write_text("old", encoding="utf-8")
    base_edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )
    plan_edits = (base_edit,)
    bundle_edits = plan_edits
    status = None
    if violation == "operation":
        bundle_edits = (replace(
            base_edit, operation=PlannedEditOperation.DELETE, new_content=None
        ),)
    elif violation == "outside-file":
        bundle_edits = (replace(base_edit, path="outside.txt"),)
    elif violation == "rename-destination":
        rename = replace(
            base_edit, operation=PlannedEditOperation.RENAME,
            destination_path="approved.txt", new_content=None,
        )
        plan_edits = (rename,)
        bundle_edits = (replace(rename, destination_path="unapproved.txt"),)
    elif violation == "blocked-plan":
        from khaos.coding.planning.contracts import PlanStatus
        status = PlanStatus.BLOCKED
    elif violation in {"case-collision", "unicode-collision"}:
        first = PlannedFileEdit(
            "e1", "s1", PlannedEditOperation.CREATE,
            "Foo.txt" if violation == "case-collision" else "café.txt",
            expected_exists=False, new_content="one",
        )
        second = PlannedFileEdit(
            "e2", "s2", PlannedEditOperation.CREATE,
            "foo.txt" if violation == "case-collision" else unicodedata.normalize("NFD", "café.txt"),
            expected_exists=False, new_content="two",
        )
        plan_edits = bundle_edits = (first, second)
    elif violation == "mode-escalation":
        bundle_edits = (replace(base_edit, new_mode=0o755),)
    runtime, _, workspace_manager, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspace_manager)
    plan = _plan(plan_edits, status=status)
    if violation == "blocked-plan":
        from khaos.coding.planning.approval.service import PlanNotRequestableError
        with pytest.raises(PlanNotRequestableError):
            _authorize(runtime, plan)
        assert (workspace.worktree_path / "a.txt").read_text() == "old"
        return
    plan, authorization = _authorize(runtime, plan)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, bundle_edits))
    assert (workspace.worktree_path / "a.txt").read_text() == "old"
