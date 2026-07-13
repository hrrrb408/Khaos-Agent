"""M4 Batch 3.0.1 durability, no-replace and recovery closure matrix."""
from __future__ import annotations

import asyncio
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from test_m4_batch2_8_boot_scope_closure import _real_runtime
from test_m4_batch3_0_workspace_mutation import (
    _apply, _authorize, _bundle, _hash, _plan, _setup, _workspace,
)
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus, PlanExecutionRun, PlannedEditOperation, PlannedFileEdit,
)
from khaos.coding.planning.git_state import GitStateSnapshot
from khaos.coding.planning.safe_workspace_path import (
    SafeParentDirectory, WorkspacePathHandle,
)
from khaos.coding.planning.workspace_mutation import WorkspaceMutationError


def _operation_edit(tmp_path, operation):
    root = tmp_path / "isolated-worktree"
    root.mkdir()
    if operation != PlannedEditOperation.CREATE:
        (root / "a.txt").write_text("old", encoding="utf-8")
    return PlannedFileEdit(
        "e1", "s1", operation, "a.txt",
        destination_path="b.txt" if operation == PlannedEditOperation.RENAME else None,
        expected_exists=operation != PlannedEditOperation.CREATE,
        expected_content_hash=_hash("old") if operation != PlannedEditOperation.CREATE else None,
        new_content="new" if operation in {PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE} else None,
    )


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_post_mutation_parent_fsync_fault_rolls_back_current_edit(tmp_path, monkeypatch, operation):
    edit = _operation_edit(tmp_path, operation)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    original = SafeParentDirectory.fsync
    calls = 0

    def fail_once(parent):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("post-mutation-fsync")
        return original(parent)

    monkeypatch.setattr(SafeParentDirectory, "fsync", fail_once)
    with pytest.raises(OSError, match="post-mutation-fsync"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert not (workspace.worktree_path / "b.txt").exists()
    if operation == PlannedEditOperation.CREATE:
        assert not (workspace.worktree_path / "a.txt").exists()
    else:
        assert (workspace.worktree_path / "a.txt").read_text() == "old"
    phases = [row[0] for row in runtime._store._conn.execute(
        "SELECT status FROM plan_execution_edit_events ORDER BY ordinal"
    )]
    assert phases == ["rolled-back"]


@pytest.mark.parametrize("phase", ["filesystem-applied", "directory-synced"])
def test_durable_phase_journal_fault_uses_disk_state_for_rollback(tmp_path, monkeypatch, phase):
    edit = _operation_edit(tmp_path, PlannedEditOperation.UPDATE)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    original = runtime._store.update_edit_event
    failed = False

    def fault(run_id, edit_id, **kwargs):
        nonlocal failed
        if kwargs.get("status") == phase and not failed:
            failed = True
            raise sqlite3.OperationalError(f"{phase}-journal")
        return original(run_id, edit_id, **kwargs)

    monkeypatch.setattr(runtime._store, "update_edit_event", fault)
    expected_error = (
        WorkspaceMutationError if phase == "filesystem-applied"
        else sqlite3.OperationalError
    )
    with pytest.raises(expected_error):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    expected_content = "new" if phase == "filesystem-applied" else "old"
    expected_status = "poisoned" if phase == "filesystem-applied" else "rolled-back"
    assert (workspace.worktree_path / "a.txt").read_text() == expected_content
    assert runtime._store._conn.execute(
        "SELECT status FROM plan_execution_runs"
    ).fetchone()[0] == expected_status


@pytest.mark.parametrize("boundary", [
    "before-sealing", "sealing-with-artifacts", "partial-delete", "deleted-before-terminal",
])
def test_recovery_seal_crash_boundaries_are_deterministic(tmp_path, boundary):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, manager)
    run_id = f"per_{uuid.uuid4().hex}"
    now = time.time()
    status = ExecutionRunStatus.MUTATING if boundary == "before-sealing" else ExecutionRunStatus.SEALING
    run = PlanExecutionRun(
        run_id, "p", "ph", "r", f"a-{run_id}", f"c-{run_id}", "l",
        "task1", "ws1", "repo", "abc123", 1, "binding", "bundle",
        status, now, now,
    )
    runtime._store.create_execution_run(run)
    recovery = workspace.recovery_root / run_id
    if boundary != "deleted-before-terminal":
        recovery.mkdir(parents=True)
        os.chmod(recovery.parent, 0o700)
        os.chmod(recovery, 0o700)
        if boundary != "before-sealing":
            (recovery / "artifact").write_text("x", encoding="utf-8")
        if boundary == "partial-delete":
            (recovery / "artifact").unlink()
    if boundary == "before-sealing":
        runtime._store.insert_edit_event(
            event_id=uuid.uuid4().hex, execution_run_id=run_id, edit_id="e1",
            ordinal=0, operation="create", path="a.txt", destination_path=None,
            before_hash=None, before_mode=None, recovery_artifact=None,
            planned_after_hash=_hash("new"),
        )
    recovered = runtime._mutation_engine.recover_incomplete_runs()
    current = runtime._store.get_execution_run(run_id)
    if boundary == "before-sealing":
        assert current.status == ExecutionRunStatus.POISONED
    else:
        assert current.status == ExecutionRunStatus.POISONED
        assert current.execution_run_id not in recovered


def test_seal_failure_never_leaves_mutated(tmp_path, monkeypatch):
    edit = _operation_edit(tmp_path, PlannedEditOperation.CREATE)
    runtime, _, plan, authorization = _setup(tmp_path, (edit,))
    monkeypatch.setattr(
        runtime._mutation_engine, "_seal_recovery",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("seal")),
    )
    with pytest.raises(OSError, match="seal"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert runtime._store._conn.execute(
        "SELECT status FROM plan_execution_runs"
    ).fetchone()[0] == "poisoned"


def test_create_destination_race_is_true_no_replace(tmp_path, monkeypatch):
    edit = _operation_edit(tmp_path, PlannedEditOperation.CREATE)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    ready = threading.Event()
    done = threading.Event()
    original = WorkspacePathHandle._write_temp

    def pause(parent, content, mode):
        name = original(parent, content, mode)
        ready.set(); assert done.wait(2)
        return name

    monkeypatch.setattr(WorkspacePathHandle, "_write_temp", staticmethod(pause))
    competitor = threading.Thread(target=lambda: (
        ready.wait(2), (workspace.worktree_path / "a.txt").write_text("competitor"), done.set()
    ))
    competitor.start()
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    competitor.join()
    assert (workspace.worktree_path / "a.txt").read_text() == "competitor"


def test_rename_destination_race_is_true_no_replace(tmp_path, monkeypatch):
    edit = _operation_edit(tmp_path, PlannedEditOperation.RENAME)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    ready = threading.Event(); done = threading.Event()
    original = os.link

    def racing_link(src, dst, **kwargs):
        if dst == "b.txt":
            ready.set(); assert done.wait(2)
        return original(src, dst, **kwargs)

    monkeypatch.setattr("khaos.coding.planning.safe_workspace_path.os.link", racing_link)
    competitor = threading.Thread(target=lambda: (
        ready.wait(2), (workspace.worktree_path / "b.txt").write_text("competitor"), done.set()
    ))
    competitor.start()
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    competitor.join()
    assert (workspace.worktree_path / "a.txt").read_text() == "old"
    assert (workspace.worktree_path / "b.txt").read_text() == "competitor"


@pytest.mark.parametrize("swap", ["parent", "target"])
def test_dirfd_rejects_parent_or_target_symlink_swap(tmp_path, monkeypatch, swap):
    root = tmp_path / "isolated-worktree"; root.mkdir()
    (root / "dir").mkdir(); (root / "dir" / "a.txt").write_text("old")
    outside = tmp_path / "outside"; outside.mkdir(); (outside / "victim").write_text("outside")
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "dir/a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    if swap == "parent":
        original = SafeParentDirectory.revalidate; fired = False
        def revalidate(parent):
            nonlocal fired
            if not fired:
                fired = True
                (root / "dir").rename(root / "dir-real")
                (root / "dir").symlink_to(outside, target_is_directory=True)
            return original(parent)
        monkeypatch.setattr(SafeParentDirectory, "revalidate", revalidate)
    else:
        original = WorkspacePathHandle._exchange
        def exchange(fd, left, right):
            target = root / "dir" / "a.txt"
            if target.exists() and not target.is_symlink():
                target.unlink(); target.symlink_to(outside / "victim")
            return original(fd, left, right)
        monkeypatch.setattr(WorkspacePathHandle, "_exchange", staticmethod(exchange))
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (outside / "victim").read_text() == "outside"


def test_cross_directory_rename_fsyncs_both_parents(tmp_path, monkeypatch):
    root = tmp_path / "isolated-worktree"; root.mkdir()
    (root / "one").mkdir(); (root / "two").mkdir()
    (root / "one" / "a.txt").write_text("old")
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.RENAME, "one/a.txt",
        destination_path="two/b.txt", expected_content_hash=_hash("old"),
    )
    runtime, _, plan, authorization = _setup(tmp_path, (edit,))
    identities = []
    original = SafeParentDirectory.fsync
    def record(parent): identities.append(parent.identity); return original(parent)
    monkeypatch.setattr(SafeParentDirectory, "fsync", record)
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert len(set(identities)) >= 2


@pytest.mark.parametrize("drift", ["head", "generation", "index", "admin", "extra-file"])
def test_final_git_and_live_state_drift_rolls_back(tmp_path, monkeypatch, drift):
    edit = _operation_edit(tmp_path, PlannedEditOperation.UPDATE)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    inspector = runtime._mutation_engine._git_inspector
    original = inspector.snapshot; calls = 0
    def snapshot(ws, *, repository_generation):
        nonlocal calls
        value = original(ws, repository_generation=repository_generation); calls += 1
        if calls == 2:
            if drift == "head": value = replace(value, head_commit="other")
            elif drift == "generation":
                runtime._context_provider.set(repository_generation=2)
                value = replace(value, repository_generation=2)
            elif drift == "index": value = replace(value, index_digest="changed")
            elif drift == "admin": value = replace(value, worktree_admin_identity="changed")
            else:
                (workspace.worktree_path / "rogue.txt").write_text("rogue")
                value = original(ws, repository_generation=repository_generation)
        return value
    monkeypatch.setattr(inspector, "snapshot", snapshot)
    with pytest.raises((WorkspaceMutationError, PermissionError)):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_text() == "old"


@pytest.mark.parametrize("mode", [0o755, 0o4755, 0o1755, 0o711])
def test_create_executable_or_dangerous_modes_are_refused(tmp_path, mode):
    edit = replace(
        _operation_edit(tmp_path, PlannedEditOperation.CREATE), new_mode=mode
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    with pytest.raises(WorkspaceMutationError, match="mode"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert not (workspace.worktree_path / "a.txt").exists()


@pytest.mark.parametrize("operation", ["create", "rename"])
def test_rollback_does_not_destroy_third_party_content(tmp_path, monkeypatch, operation):
    edit = _operation_edit(
        tmp_path,
        PlannedEditOperation.CREATE if operation == "create" else PlannedEditOperation.RENAME,
    )
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    original = runtime._store.update_edit_event; injected = False
    def fault(run_id, edit_id, **kwargs):
        nonlocal injected
        if kwargs.get("status") == "filesystem-applied" and not injected:
            injected = True
            if operation == "create":
                target = workspace.worktree_path / "a.txt"; target.unlink(); target.write_text("third-party")
            else:
                (workspace.worktree_path / "a.txt").write_text("third-party")
            raise sqlite3.OperationalError("phase")
        return original(run_id, edit_id, **kwargs)
    monkeypatch.setattr(runtime._store, "update_edit_event", fault)
    with pytest.raises(WorkspaceMutationError, match="rollback failed"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_text() == "third-party"
    assert runtime.mutation_fence.is_poisoned("ws1")


def test_scoped_recovery_does_not_clear_unrelated_poison(tmp_path):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, manager)
    runtime.mutation_fence.poison("ws1", "lease-release", owner="lease:l1")
    runtime._store.add_workspace_poison_scope("ws1", owner="lease:l1", reason="lease-release")
    run_id = f"per_{uuid.uuid4().hex}"; now = time.time()
    runtime._store.create_execution_run(PlanExecutionRun(
        run_id, "p", "h", "r", f"a-{run_id}", f"c-{run_id}", "l", "task1",
        "ws1", "repo", "abc123", 1, "b", "d", ExecutionRunStatus.SEALING,
        now, now,
    ))
    recovered = runtime._mutation_engine.recover_incomplete_runs()
    assert run_id not in recovered
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED
    scopes = runtime._store.list_workspace_poison_scopes("ws1")
    assert any(owner == "lease:l1" for _, owner, _ in scopes)
    assert runtime.mutation_fence.is_poisoned("ws1")


def test_recovery_root_symlink_is_fail_closed(tmp_path):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, manager)
    run_id = f"per_{uuid.uuid4().hex}"; now = time.time()
    runtime._store.create_execution_run(PlanExecutionRun(
        run_id, "p", "h", "r", f"a-{run_id}", f"c-{run_id}", "l", "task1",
        "ws1", "repo", "abc123", 1, "b", "d", ExecutionRunStatus.MUTATING,
        now, now,
    ))
    container = workspace.worktree_path.parent / ".khaos-recovery"; container.mkdir()
    outside = tmp_path / "outside-recovery"; outside.mkdir()
    (container / run_id).symlink_to(outside, target_is_directory=True)
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED


def test_no_execution_side_channels_or_base_repository_changes(tmp_path):
    edit = _operation_edit(tmp_path, PlannedEditOperation.CREATE)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    before = (workspace.repository_root / "main.txt").read_bytes()
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.repository_root / "main.txt").read_bytes() == before
    source = (Path(__file__).parents[2] / "khaos/coding/planning/safe_workspace_path.py").read_text()
    assert all(word not in source for word in ("subprocess", "terminal", "test_run", "ChangeSet", "git commit", "git push"))
