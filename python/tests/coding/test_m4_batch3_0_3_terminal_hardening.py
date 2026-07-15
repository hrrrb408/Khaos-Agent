"""Batch 3.0.3 terminal tombstone and persisted-input hardening matrix."""
from __future__ import annotations

import os
import sqlite3
import time
import uuid

import pytest

from khaos.coding.planning.execution_models import (
    ExecutionRunStatus, PlanExecutionRun, PlannedEditOperation, PlannedFileEdit,
)
from khaos.coding.planning.recovery_directory import RecoveryDirectory
from khaos.coding.planning.safe_workspace_path import WorkspacePathHandle
from khaos.coding.planning.workspace_mutation import WorkspaceMutationError

from test_m4_batch3_0_workspace_mutation import (
    _apply, _bundle, _hash, _real_runtime, _setup, _workspace,
)


def _update(tmp_path):
    root = tmp_path / "isolated-worktree"
    root.mkdir(exist_ok=True)
    (root / "a.txt").write_text("old", encoding="utf-8")
    return PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )


def _mutation_tombstone_crash(tmp_path, monkeypatch):
    edit = _update(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    monkeypatch.setattr(
        runtime._store, "commit_terminal_seal",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("terminal-commit")
        ),
    )
    with pytest.raises(sqlite3.OperationalError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    run = runtime._store._conn.execute(
        "SELECT execution_run_id FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()[0]
    runtime._store._conn.execute(
        "UPDATE plan_execution_runs SET status='sealing',completed_at=NULL WHERE execution_run_id=?",
        (run,),
    )
    runtime._store._conn.commit()
    return runtime, workspace, run


def test_missing_run_directory_with_valid_mutation_tombstone_recovers(tmp_path, monkeypatch):
    runtime, workspace, run_id = _mutation_tombstone_crash(tmp_path, monkeypatch)
    monkeypatch.undo()
    assert not (workspace.recovery_root / run_id).exists()
    assert tuple(workspace.recovery_root.glob("seal-*.json"))
    assert run_id in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.MUTATED


@pytest.mark.parametrize("corruption", ["missing", "json", "digest"])
def test_missing_or_corrupt_tombstone_never_guesses_terminal(tmp_path, monkeypatch, corruption):
    runtime, workspace, run_id = _mutation_tombstone_crash(tmp_path, monkeypatch)
    monkeypatch.undo()
    tombstone = next(workspace.recovery_root.glob("seal-*.json"))
    if corruption == "missing": tombstone.unlink()
    elif corruption == "json": tombstone.write_text("{", encoding="utf-8")
    else:
        text = tombstone.read_text(encoding="utf-8")
        tombstone.write_text(text.replace('"tombstone_digest":"', '"tombstone_digest":"bad'), encoding="utf-8")
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED


def test_terminal_seal_marker_status_and_audit_commit_atomically(tmp_path):
    edit = _update(tmp_path)
    runtime, _, plan, authorization = _setup(tmp_path, (edit,))
    result = _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    row = runtime._store._conn.execute(
        "SELECT status,recovery_sealed_at,terminal_tombstone_digest FROM plan_execution_runs "
        "WHERE execution_run_id=?", (result.execution_run_id,),
    ).fetchone()
    audit = runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_audit_events WHERE execution_run_id=? "
        "AND event_type='terminal-seal-committed'", (result.execution_run_id,),
    ).fetchone()[0]
    assert row[0] == "mutated" and row[1] is not None and row[2] and audit == 1


def _rollback_tombstone_crash(tmp_path, monkeypatch):
    edit = _update(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original_apply = engine._apply_edit
    def fail_after_apply(item, root):
        original_apply(item, root)
        raise OSError("rollback")
    monkeypatch.setattr(engine, "_apply_edit", fail_after_apply)
    monkeypatch.setattr(
        runtime._store, "commit_terminal_seal",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            sqlite3.OperationalError("terminal-commit")
        ),
    )
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    run_id = runtime._store._conn.execute(
        "SELECT execution_run_id FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()[0]
    runtime._store._conn.execute(
        "UPDATE plan_execution_runs SET status='rollback-sealing',completed_at=NULL "
        "WHERE execution_run_id=?", (run_id,),
    )
    runtime._store._conn.commit()
    return runtime, workspace, run_id


def test_missing_run_directory_with_valid_rollback_tombstone_recovers(tmp_path, monkeypatch):
    runtime, workspace, run_id = _rollback_tombstone_crash(tmp_path, monkeypatch)
    monkeypatch.undo()
    assert not (workspace.recovery_root / run_id).exists()
    assert run_id in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.ROLLED_BACK


def test_rollback_tombstone_corruption_keeps_quarantine(tmp_path, monkeypatch):
    runtime, workspace, run_id = _rollback_tombstone_crash(tmp_path, monkeypatch)
    monkeypatch.undo()
    tombstone = next(workspace.recovery_root.glob("seal-*.json"))
    tombstone.write_text("{}", encoding="utf-8")
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED


@pytest.mark.parametrize("field,value", [
    ("path", "../../outside"), ("path", "/tmp/outside"),
    ("destination_path", "../outside"),
    ("recovery_artifact", "../secret"),
    ("recovery_artifact", "dir/secret"),
    ("operation", "execute"), ("ordinal", 2),
])
def test_corrupt_journal_is_rejected_before_any_path_or_artifact_access(
    tmp_path, monkeypatch, field, value,
):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, manager)
    run_id = f"per_{uuid.uuid4().hex}"
    now = time.time()
    runtime._store.create_execution_run(PlanExecutionRun(
        run_id, "p", "h", "r", f"a-{run_id}", f"c-{run_id}", "l",
        "task1", "ws1", "repo", "abc123", 1, "b", "d",
        ExecutionRunStatus.MUTATING, now, now, metadata={"edit_count": 1},
    ))
    runtime._store.insert_edit_event(
        event_id=uuid.uuid4().hex, execution_run_id=run_id, edit_id="e1",
        ordinal=0, operation="update", path="a.txt", destination_path=None,
        before_hash=_hash("old"), before_mode=0o644,
        recovery_artifact=f"artifact-{uuid.uuid4().hex}.bak",
        planned_after_hash=_hash("new"), planned_after_mode=0o644,
    )
    runtime._store._conn.execute(
        f"UPDATE plan_execution_edit_events SET {field}=? WHERE execution_run_id=?",
        (value, run_id),
    )
    runtime._store._conn.commit()
    touched = False
    original_parent = WorkspacePathHandle.parent
    original_recovery = RecoveryDirectory.__init__
    def parent(*args, **kwargs):
        nonlocal touched; touched = True
        return original_parent(*args, **kwargs)
    def recovery(*args, **kwargs):
        nonlocal touched; touched = True
        return original_recovery(*args, **kwargs)
    monkeypatch.setattr(WorkspacePathHandle, "parent", parent)
    monkeypatch.setattr(RecoveryDirectory, "__init__", recovery)
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert not touched
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED


def test_corrupt_run_id_is_rejected_before_recovery_open(tmp_path, monkeypatch):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    _workspace(tmp_path, manager)
    run_id = f"per_{uuid.uuid4().hex}"; now = time.time()
    runtime._store.create_execution_run(PlanExecutionRun(
        run_id, "p", "h", "r", "a", "c", "l", "task1", "ws1", "repo",
        "abc123", 1, "b", "d", ExecutionRunStatus.MUTATING, now, now,
    ))
    runtime._store.insert_edit_event(
        event_id=uuid.uuid4().hex, execution_run_id=run_id, edit_id="e1", ordinal=0,
        operation="create", path="a.txt", destination_path=None, before_hash=None,
        before_mode=None, recovery_artifact=None, planned_after_hash=_hash("new"),
    )
    runtime._store._conn.execute(
        "UPDATE plan_execution_runs SET execution_run_id='../run' WHERE execution_run_id=?",
        (run_id,),
    )
    runtime._store._conn.execute(
        "UPDATE plan_execution_edit_events SET execution_run_id='../run' WHERE execution_run_id=?",
        (run_id,),
    )
    runtime._store._conn.commit()
    monkeypatch.setattr(
        RecoveryDirectory, "__init__",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("opened")),
    )
    assert runtime._mutation_engine.recover_incomplete_runs() == ()


def test_duplicate_journal_ordinal_is_rejected_before_workspace_access(tmp_path, monkeypatch):
    runtime, _, manager, _ = _real_runtime(tmp_path)
    _workspace(tmp_path, manager)
    run_id = f"per_{uuid.uuid4().hex}"; now = time.time()
    runtime._store.create_execution_run(PlanExecutionRun(
        run_id, "p", "h", "r", "a", "c", "l", "task1", "ws1", "repo",
        "abc123", 1, "b", "d", ExecutionRunStatus.MUTATING, now, now,
        metadata={"edit_count": 2},
    ))
    for edit_id in ("e1", "e2"):
        runtime._store.insert_edit_event(
            event_id=uuid.uuid4().hex, execution_run_id=run_id, edit_id=edit_id,
            ordinal=0, operation="create", path=f"{edit_id}.txt",
            destination_path=None, before_hash=None, before_mode=None,
            recovery_artifact=None, planned_after_hash=_hash("new"),
        )
    monkeypatch.setattr(
        WorkspacePathHandle, "parent",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("accessed")),
    )
    assert runtime._mutation_engine.recover_incomplete_runs() == ()


@pytest.mark.parametrize("kind", ["tracked-mode", "untracked-mode", "symlink", "inode"])
def test_undeclared_mode_type_or_inode_drift_blocks_sealing(tmp_path, monkeypatch, kind):
    edit = _update(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    other = workspace.worktree_path / "other.txt"
    other.write_text("same", encoding="utf-8")
    original = runtime._mutation_engine._apply_edit
    def mutate(item, root):
        original(item, root)
        if kind in {"tracked-mode", "untracked-mode"}: os.chmod(other, 0o755)
        elif kind == "symlink":
            other.unlink(); other.symlink_to("a.txt")
        else:
            data = other.read_bytes(); other.unlink(); other.write_bytes(data)
    monkeypatch.setattr(runtime._mutation_engine, "_apply_edit", mutate)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_final_attestations"
    ).fetchone()[0] == 0


def test_main_repository_remains_byte_identical_and_no_side_channels(tmp_path):
    edit = _update(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    before = {p.relative_to(workspace.repository_root): p.read_bytes()
              for p in workspace.repository_root.rglob("*") if p.is_file()}
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    after = {p.relative_to(workspace.repository_root): p.read_bytes()
             for p in workspace.repository_root.rglob("*") if p.is_file()}
    assert before == after
