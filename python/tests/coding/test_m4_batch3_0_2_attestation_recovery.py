"""Batch 3.0.2 rollback seal, attestation, and recovery-root matrix."""
from __future__ import annotations

import os
import sqlite3
from dataclasses import replace

import pytest

from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    PlannedEditOperation,
    PlannedFileEdit,
)
from khaos.coding.planning.recovery_directory import RecoveryDirectory
from khaos.coding.planning.workspace_mutation import WorkspaceMutationError

from test_m4_batch3_0_workspace_mutation import (
    _apply,
    _bundle,
    _hash,
    _setup,
)
from test_m4_batch3_0_1_durability_closure import _operation_edit


def _update_edit(tmp_path):
    worktree = tmp_path / "isolated-worktree"
    worktree.mkdir(exist_ok=True)
    (worktree / "a.txt").write_text("old", encoding="utf-8")
    return PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
        expected_content_hash=_hash("old"), new_content="new",
    )


@pytest.mark.parametrize("fault", ["delete", "parent-fsync", "audit", "db-commit"])
def test_rollback_seal_fault_poison_retains_evidence(tmp_path, monkeypatch, fault):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original_apply = engine._apply_edit

    def fail_after_apply(item, root):
        original_apply(item, root)
        raise OSError("force-rollback")

    monkeypatch.setattr(engine, "_apply_edit", fail_after_apply)
    if fault in {"delete", "parent-fsync"}:
        monkeypatch.setattr(
            RecoveryDirectory, "seal",
            lambda self: (_ for _ in ()).throw(OSError(fault)),
        )
    else:
        monkeypatch.setattr(
            runtime._store, "commit_terminal_seal",
            lambda *args, **kwargs: (_ for _ in ()).throw(
                sqlite3.OperationalError(fault)
            ),
        )
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    row = runtime._store._conn.execute(
        "SELECT status FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    assert row[0] == "poisoned"
    assert runtime.mutation_fence.is_poisoned(workspace.id)
    assert any(workspace.recovery_root.rglob("*.bak")) or any(
        workspace.recovery_root.glob("seal-*.json")
    )


def test_successful_rollback_is_sealed_before_terminal(tmp_path, monkeypatch):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    monkeypatch.setattr(
        runtime._mutation_engine, "_apply_edit",
        lambda *_args: (_ for _ in ()).throw(OSError("before-mutation")),
    )
    with pytest.raises(OSError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    row = runtime._store._conn.execute(
        "SELECT status,rollback_sealed_at,rollback_seal_digest "
        "FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    assert row[0] == "rolled-back" and row[1] is not None and row[2]
    assert not tuple(workspace.recovery_root.iterdir())


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_declared_path_final_drift_never_attests_or_overwrites_third_party(
    tmp_path, monkeypatch, operation,
):
    edit = _operation_edit(tmp_path, operation)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    inspector = runtime._mutation_engine._git_inspector
    original = inspector.snapshot
    calls = 0

    def snapshot(ws, *, repository_generation):
        nonlocal calls
        calls += 1
        if calls == 2:
            target = ws.worktree_path / (edit.destination_path or edit.path)
            if operation == PlannedEditOperation.DELETE:
                target.write_text("third-party", encoding="utf-8")
            else:
                target.write_text("third-party", encoding="utf-8")
        return original(ws, repository_generation=repository_generation)

    monkeypatch.setattr(inspector, "snapshot", snapshot)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    target = workspace.worktree_path / (edit.destination_path or edit.path)
    assert target.read_text(encoding="utf-8") == "third-party"
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_final_attestations"
    ).fetchone()[0] == 0


def test_declared_final_mode_drift_is_quarantined(tmp_path, monkeypatch):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    inspector = runtime._mutation_engine._git_inspector
    original = inspector.snapshot
    calls = 0

    def snapshot(ws, *, repository_generation):
        nonlocal calls
        calls += 1
        if calls == 2:
            os.chmod(ws.worktree_path / "a.txt", 0o600)
        return original(ws, repository_generation=repository_generation)

    monkeypatch.setattr(inspector, "snapshot", snapshot)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert os.stat(workspace.worktree_path / "a.txt").st_mode & 0o777 == 0o600


def _crashed_sealing_run(tmp_path, monkeypatch):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    original_seal = runtime._mutation_engine._seal_recovery
    monkeypatch.setattr(
        runtime._mutation_engine, "_seal_recovery",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("crash")),
    )
    with pytest.raises(OSError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    row = runtime._store._conn.execute(
        "SELECT execution_run_id FROM plan_execution_runs ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
    run_id = row[0]
    runtime._store._conn.execute(
        "UPDATE plan_execution_runs SET status='sealing',completed_at=NULL WHERE execution_run_id=?",
        (run_id,),
    )
    runtime._store._conn.commit()
    return runtime, workspace, run_id, original_seal


@pytest.mark.parametrize("corruption", ["missing", "digest", "journal", "file"])
def test_sealing_recovery_requires_complete_attestation(
    tmp_path, monkeypatch, corruption,
):
    runtime, workspace, run_id, _ = _crashed_sealing_run(tmp_path, monkeypatch)
    if corruption == "missing":
        runtime._store._conn.execute(
            "DELETE FROM plan_execution_final_attestations WHERE execution_run_id=?",
            (run_id,),
        )
    elif corruption == "digest":
        runtime._store._conn.execute(
            "UPDATE plan_execution_final_attestations SET attestation_digest='bad' "
            "WHERE execution_run_id=?", (run_id,),
        )
    elif corruption == "journal":
        runtime._store._conn.execute(
            "DELETE FROM plan_execution_edit_events WHERE execution_run_id=?", (run_id,),
        )
    else:
        (workspace.worktree_path / "a.txt").write_text("drift", encoding="utf-8")
    runtime._store._conn.commit()
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.recovery_root / run_id).exists()


@pytest.mark.parametrize("drift", ["head", "generation", "index", "admin"])
def test_sealing_recovery_rechecks_repository_state(tmp_path, monkeypatch, drift):
    runtime, workspace, run_id, _ = _crashed_sealing_run(tmp_path, monkeypatch)
    inspector = runtime._mutation_engine._git_inspector
    original = inspector.snapshot

    def snapshot(ws, *, repository_generation):
        value = original(ws, repository_generation=repository_generation)
        if drift == "head": return replace(value, head_commit="other")
        if drift == "generation": return replace(value, repository_generation=2)
        if drift == "index": return replace(value, index_digest="other")
        return replace(value, worktree_admin_identity="other")

    monkeypatch.setattr(inspector, "snapshot", snapshot)
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED


def test_valid_attested_sealing_run_recovers_to_mutated(tmp_path, monkeypatch):
    runtime, workspace, run_id, original_seal = _crashed_sealing_run(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(runtime._mutation_engine, "_seal_recovery", original_seal)
    assert run_id in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.MUTATED
    assert not (workspace.recovery_root / run_id).exists()


def test_recovery_artifact_symlink_replacement_is_fail_closed(tmp_path, monkeypatch):
    runtime, workspace, run_id, original_seal = _crashed_sealing_run(
        tmp_path, monkeypatch
    )
    monkeypatch.setattr(runtime._mutation_engine, "_seal_recovery", original_seal)
    event = runtime._store.list_execution_edit_events(run_id)[0]
    artifact = workspace.recovery_root / run_id / event["recovery_artifact"]
    artifact.unlink()
    outside = tmp_path / "outside-backup"
    outside.write_text("old", encoding="utf-8")
    artifact.symlink_to(outside)
    assert run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run_id).status == ExecutionRunStatus.POISONED
    assert outside.read_text(encoding="utf-8") == "old"


def test_recovery_root_inside_repository_fails_before_journal_or_backup(tmp_path):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    workspace.recovery_root = workspace.repository_root / ".private-recovery"
    before = (workspace.worktree_path / "a.txt").read_bytes()
    with pytest.raises(WorkspaceMutationError, match="inside repository"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_bytes() == before
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_edit_events"
    ).fetchone()[0] == 0
    assert not workspace.recovery_root.exists()


def test_recovery_parent_symlink_is_rejected(tmp_path):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    real = tmp_path / "real-recovery-parent"
    real.mkdir()
    link = tmp_path / "recovery-link"
    link.symlink_to(real, target_is_directory=True)
    workspace.recovery_root = link / "private"
    with pytest.raises(WorkspaceMutationError, match="symlink"):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))


def test_unknown_recovery_file_is_never_recursively_deleted(tmp_path, monkeypatch):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original = engine._build_final_attestation

    def inject_unknown(*args, **kwargs):
        value = original(*args, **kwargs)
        (engine._active_recovery.path / "unknown").write_text("keep", encoding="utf-8")
        return value

    monkeypatch.setattr(engine, "_build_final_attestation", inject_unknown)
    with pytest.raises(WorkspaceMutationError):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert any(path.name == "unknown" for path in workspace.recovery_root.rglob("unknown"))


@pytest.mark.parametrize("fault", ["backup-fsync", "journal-commit"])
def test_backup_or_journal_durability_fault_causes_zero_workspace_mutation(
    tmp_path, monkeypatch, fault,
):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    if fault == "backup-fsync":
        monkeypatch.setattr(
            RecoveryDirectory, "create_backup",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fsync")),
        )
    else:
        monkeypatch.setattr(
            runtime._store, "insert_edit_event",
            lambda **_kwargs: (_ for _ in ()).throw(sqlite3.OperationalError("journal")),
        )
    with pytest.raises((OSError, sqlite3.Error, WorkspaceMutationError)):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    assert (workspace.worktree_path / "a.txt").read_text(encoding="utf-8") == "old"


def test_main_repository_and_side_channel_boundaries_remain_unchanged(tmp_path):
    edit = _update_edit(tmp_path)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    before = {
        path.relative_to(workspace.repository_root): path.read_bytes()
        for path in workspace.repository_root.rglob("*") if path.is_file()
    }
    _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    after = {
        path.relative_to(workspace.repository_root): path.read_bytes()
        for path in workspace.repository_root.rglob("*") if path.is_file()
    }
    assert before == after
