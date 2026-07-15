"""Batch 3.0.7 durable rollback directory-sync restart matrix."""
from __future__ import annotations

import os
import sqlite3
import threading

import pytest

from test_m4_batch3_0_6_rollback_ownership import (
    _crash_after_applied,
    _restart_runtime,
)
from test_m4_batch3_0_workspace_mutation import (
    _apply,
    _bundle,
    _hash,
    _setup,
)
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    PlannedEditOperation,
    PlannedFileEdit,
)
from khaos.coding.planning.safe_workspace_path import (
    SafeParentDirectory,
    WorkspacePathHandle,
)
from khaos.coding.planning.workspace_mutation import WorkspaceMutationError


def _crash_after_custom_edit(tmp_path, edit):
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original_build = engine._build_final_attestation
    original_rollback = engine._rollback
    engine._build_final_attestation = lambda *args, **kwargs: (_ for _ in ()).throw(
        RuntimeError("crash-before-final-attestation")
    )
    engine._rollback = lambda *args, **kwargs: (_ for _ in ()).throw(
        SystemExit("simulated-process-crash")
    )
    try:
        with pytest.raises(SystemExit):
            _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    finally:
        engine._build_final_attestation = original_build
        engine._rollback = original_rollback
    run = runtime._store.get_execution_run(
        runtime._store._conn.execute(
            "SELECT execution_run_id FROM plan_execution_runs"
        ).fetchone()[0]
    )
    return runtime, workspace, run


def _invoke_rollback(runtime, workspace, run):
    engine = runtime._mutation_engine
    journal = engine._validated_journal(run, allow_partial=True)
    recovery = engine._open_recovery(
        workspace, run.execution_run_id, journal.events,
    )
    try:
        engine._rollback(
            run.execution_run_id,
            workspace.worktree_path.resolve(strict=True),
            recovery,
            workspace.id,
            failure_code="rollback-fsync-fault",
            recovered=True,
        )
    finally:
        recovery.close()


def _syscall_name(operation):
    return {
        PlannedEditOperation.CREATE: "delete",
        PlannedEditOperation.UPDATE: "update",
        PlannedEditOperation.DELETE: "create",
        PlannedEditOperation.RENAME: "rename_no_replace",
    }[operation]


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_parent_fsync_fault_persists_filesystem_phase_and_restart_only_resyncs(
    tmp_path, monkeypatch, operation,
):
    runtime, workspace, run = _crash_after_applied(tmp_path, operation)
    repository_before = {
        path.relative_to(workspace.repository_root): path.read_bytes()
        for path in workspace.repository_root.rglob("*") if path.is_file()
    }
    syscall_name = _syscall_name(operation)
    original_syscall = getattr(WorkspacePathHandle, syscall_name)
    original_fsync = SafeParentDirectory.fsync
    counts = {"syscall": 0, "fsync": 0}

    def counted_syscall(self, *args, **kwargs):
        counts["syscall"] += 1
        return original_syscall(self, *args, **kwargs)

    def failed_fsync(self):
        counts["fsync"] += 1
        raise OSError("injected rollback parent fsync fault")

    monkeypatch.setattr(WorkspacePathHandle, syscall_name, counted_syscall)
    monkeypatch.setattr(SafeParentDirectory, "fsync", failed_fsync)
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)

    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rollback-filesystem-applied"
    assert event["rollback_identity_digest"]
    assert event["rollback_parent_identity_digest"]
    assert not event["rollback_directory_sync_digest"]
    assert runtime._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.POISONED
    )
    assert counts["syscall"] == 1
    assert (workspace.recovery_root / run.execution_run_id).exists()

    monkeypatch.setattr(SafeParentDirectory, "fsync", original_fsync)
    restarted = _restart_runtime(tmp_path, runtime)
    final = restarted._store.list_execution_edit_events(run.execution_run_id)[0]
    assert final["status"] == "rolled-back"
    assert final["rollback_directory_sync_digest"]
    assert final["rollback_synced_at"] > 0
    assert counts["syscall"] == 1
    assert repository_before == {
        path.relative_to(workspace.repository_root): path.read_bytes()
        for path in workspace.repository_root.rglob("*") if path.is_file()
    }


def _cross_directory_rename_crash(tmp_path):
    worktree = tmp_path / "isolated-worktree"
    (worktree / "source").mkdir(parents=True)
    (worktree / "destination").mkdir()
    (worktree / "source" / "a.txt").write_text("old", encoding="utf-8")
    edit = PlannedFileEdit(
        "e1", "s1", PlannedEditOperation.RENAME,
        "source/a.txt", destination_path="destination/b.txt",
        expected_content_hash=_hash("old"),
    )
    return _crash_after_custom_edit(tmp_path, edit)


@pytest.mark.parametrize("failed_parent", ["source", "destination"])
def test_cross_directory_rename_fsync_fault_resyncs_both_without_replay(
    tmp_path, monkeypatch, failed_parent,
):
    runtime, workspace, run = _cross_directory_rename_crash(tmp_path)
    original_rename = WorkspacePathHandle.rename_no_replace
    original_fsync = SafeParentDirectory.fsync
    calls = {"rename": 0, "fsync": []}

    def counted_rename(self, *args, **kwargs):
        calls["rename"] += 1
        return original_rename(self, *args, **kwargs)

    def selective_fsync(self):
        calls["fsync"].append(self.parts)
        ordinal = len(calls["fsync"])
        if (failed_parent == "source" and ordinal == 1) or (
            failed_parent == "destination" and ordinal == 2
        ):
            raise OSError("injected cross-directory fsync fault")
        return original_fsync(self)

    monkeypatch.setattr(
        WorkspacePathHandle, "rename_no_replace", counted_rename,
    )
    monkeypatch.setattr(SafeParentDirectory, "fsync", selective_fsync)
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rollback-filesystem-applied"
    assert event["rollback_sync_mask"] == 3
    assert event["rollback_destination_parent_identity_digest"]
    assert calls["rename"] == 1

    calls["fsync"].clear()
    def tracking_fsync(self):
        calls["fsync"].append(self.parts)
        return original_fsync(self)

    monkeypatch.setattr(SafeParentDirectory, "fsync", tracking_fsync)
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.ROLLED_BACK
    )
    assert calls["rename"] == 1
    assert {("destination",), ("source",)} <= set(calls["fsync"])


def test_same_directory_rename_has_one_unique_sync_requirement(tmp_path, monkeypatch):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.RENAME,
    )
    original_fsync = SafeParentDirectory.fsync
    monkeypatch.setattr(
        SafeParentDirectory, "fsync",
        lambda self: (_ for _ in ()).throw(OSError("sync fault")),
    )
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["rollback_sync_mask"] == 1
    assert event["rollback_destination_parent_identity_digest"]
    monkeypatch.setattr(SafeParentDirectory, "fsync", original_fsync)


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_directory_synced_phase_crash_restarts_without_syscall_replay(
    tmp_path, monkeypatch, operation,
):
    runtime, workspace, run = _crash_after_applied(tmp_path, operation)
    original_transition = runtime._store.transition_edit_event
    syscall_name = _syscall_name(operation)
    original_syscall = getattr(WorkspacePathHandle, syscall_name)
    calls = {"syscall": 0}

    def counted_syscall(self, *args, **kwargs):
        calls["syscall"] += 1
        return original_syscall(self, *args, **kwargs)

    def crash_before_rolled_back(*args, **kwargs):
        if kwargs.get("expected_phase") == "rollback-directory-synced":
            raise SystemExit("crash-before-rolled-back-cas")
        return original_transition(*args, **kwargs)

    monkeypatch.setattr(WorkspacePathHandle, syscall_name, counted_syscall)
    monkeypatch.setattr(
        runtime._store, "transition_edit_event", crash_before_rolled_back,
    )
    with pytest.raises(SystemExit):
        _invoke_rollback(runtime, workspace, run)
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rollback-directory-synced"
    assert calls["syscall"] == 1

    monkeypatch.setattr(
        runtime._store, "transition_edit_event", original_transition,
    )
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.ROLLED_BACK
    )
    assert calls["syscall"] == 1


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
@pytest.mark.parametrize("failure", ["error", "crash"])
def test_fsync_success_but_sync_phase_commit_failure_retries_only_fsync(
    tmp_path, monkeypatch, failure, operation,
):
    runtime, workspace, run = _crash_after_applied(tmp_path, operation)
    original_record = runtime._store.record_rollback_directory_synced
    syscall_name = _syscall_name(operation)
    original_syscall = getattr(WorkspacePathHandle, syscall_name)
    calls = {"syscall": 0}

    def counted_syscall(self, *args, **kwargs):
        calls["syscall"] += 1
        return original_syscall(self, *args, **kwargs)

    def fail_sync_commit(*args, **kwargs):
        if failure == "crash":
            raise SystemExit("crash-before-directory-sync-cas")
        raise RuntimeError("directory-sync-cas-fault")

    monkeypatch.setattr(WorkspacePathHandle, syscall_name, counted_syscall)
    monkeypatch.setattr(
        runtime._store, "record_rollback_directory_synced", fail_sync_commit,
    )
    expected = SystemExit if failure == "crash" else WorkspaceMutationError
    with pytest.raises(expected):
        _invoke_rollback(runtime, workspace, run)
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rollback-filesystem-applied"
    assert not event["rollback_directory_sync_digest"]
    assert calls["syscall"] == 1

    monkeypatch.setattr(
        runtime._store, "record_rollback_directory_synced", original_record,
    )
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.ROLLED_BACK
    )
    assert calls["syscall"] == 1


@pytest.mark.parametrize("drift", ["object", "parent"])
def test_fsync_retry_rejects_object_or_parent_identity_drift(
    tmp_path, monkeypatch, drift,
):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    original_fsync = SafeParentDirectory.fsync
    monkeypatch.setattr(
        SafeParentDirectory, "fsync",
        lambda self: (_ for _ in ()).throw(OSError("sync fault")),
    )
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    target = workspace.worktree_path / "a.txt"
    if drift == "object":
        replacement = workspace.worktree_path / "replacement.tmp"
        replacement.write_text("old", encoding="utf-8")
        os.replace(replacement, target)
    else:
        parked = workspace.worktree_path.with_name("parked-worktree")
        workspace.worktree_path.rename(parked)
        workspace.worktree_path.mkdir()
        os.link(parked / "a.txt", target)
    monkeypatch.setattr(SafeParentDirectory, "fsync", original_fsync)
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.POISONED
    )


def test_run_poisoned_during_directory_sync_cannot_become_rolled_back(
    tmp_path, monkeypatch,
):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    original_fsync = SafeParentDirectory.fsync

    def fsync_then_poison(self):
        original_fsync(self)
        runtime._store.transition_execution_run(
            run.execution_run_id, expected=("rolling-back",),
            target="poisoned", failure_code="concurrent-workspace-poison",
            completed=True,
        )

    monkeypatch.setattr(SafeParentDirectory, "fsync", fsync_then_poison)
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rollback-filesystem-applied"
    assert not event["rollback_directory_sync_digest"]
    assert runtime._store.get_execution_run(run.execution_run_id).status == (
        ExecutionRunStatus.POISONED
    )


@pytest.mark.parametrize(
    ("legacy_phase", "legacy_version"),
    [("rollback-started", 5), ("rolled-back", 6)],
)
def test_legacy_incomplete_rollback_identity_is_resynced_before_terminal(
    tmp_path, monkeypatch, legacy_phase, legacy_version,
):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    original_fsync = SafeParentDirectory.fsync
    monkeypatch.setattr(
        SafeParentDirectory, "fsync",
        lambda self: (_ for _ in ()).throw(OSError("sync fault")),
    )
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    runtime._store._conn.execute(
        "UPDATE plan_execution_edit_events SET status=?,"
        "phase_version=?,identity_version=2,"
        "rollback_parent_identity_digest='',"
        "rollback_destination_parent_identity_digest='',rollback_sync_mask=0 "
        "WHERE execution_run_id=?",
        (legacy_phase, legacy_version, run.execution_run_id),
    )
    runtime._store._conn.commit()
    monkeypatch.setattr(SafeParentDirectory, "fsync", original_fsync)
    restarted = _restart_runtime(tmp_path, runtime)
    event = restarted._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rolled-back"
    assert event["rollback_directory_sync_digest"]


def test_directory_sync_phase_cas_is_single_transition_across_connections(
    tmp_path, monkeypatch,
):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    monkeypatch.setattr(
        SafeParentDirectory, "fsync",
        lambda self: (_ for _ in ()).throw(OSError("sync fault")),
    )
    with pytest.raises(WorkspaceMutationError):
        _invoke_rollback(runtime, workspace, run)
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="rollback-fsync-fault",
    )
    database = runtime._store._conn.execute("PRAGMA database_list").fetchone()[2]
    barrier = threading.Barrier(2)
    results = []

    def transition():
        from khaos.coding.planning.approval import PlanApprovalStore

        store = PlanApprovalStore(sqlite3.connect(
            database, check_same_thread=False,
        ))
        barrier.wait()
        results.append(store.record_rollback_directory_synced(
            run.execution_run_id, "e1", error_code="rollback-fsync-fault",
        ))

    threads = [threading.Thread(target=transition) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(set(results)) == 1
    row = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert row["status"] == "rollback-directory-synced"
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_audit_events "
        "WHERE execution_run_id=? AND event_type='rollback-directory-synced'",
        (run.execution_run_id,),
    ).fetchone()[0] == 1


def test_rollback_sync_schema_migration_is_atomic_on_failure(tmp_path):
    from khaos.coding.planning.approval import PlanApprovalStore

    database = tmp_path / "rollback-sync-migration.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE plan_execution_edit_events ("
        "event_id TEXT PRIMARY KEY, execution_run_id TEXT NOT NULL,"
        "edit_id TEXT NOT NULL, ordinal INTEGER NOT NULL,operation TEXT NOT NULL,"
        "path TEXT NOT NULL,destination_path TEXT,before_hash TEXT,after_hash TEXT,"
        "before_mode INTEGER,after_mode INTEGER,status TEXT NOT NULL,"
        "phase_version INTEGER NOT NULL DEFAULT 0,"
        "applied_identity_digest TEXT NOT NULL DEFAULT '',"
        "applied_parent_identity_digest TEXT NOT NULL DEFAULT '',"
        "applied_destination_identity_digest TEXT NOT NULL DEFAULT '',"
        "rollback_identity_digest TEXT NOT NULL DEFAULT '',"
        "identity_version INTEGER NOT NULL DEFAULT 0,error_code TEXT NOT NULL DEFAULT '',"
        "recovery_artifact TEXT,created_at REAL NOT NULL,updated_at REAL NOT NULL)"
    )
    connection.commit()
    alters = {"count": 0}

    def deny_second_event_alter(action, first, second, database_name, trigger):
        if action == sqlite3.SQLITE_ALTER_TABLE and second == (
            "plan_execution_edit_events"
        ):
            alters["count"] += 1
            if alters["count"] == 2:
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    connection.set_authorizer(deny_second_event_alter)
    with pytest.raises(sqlite3.DatabaseError):
        PlanApprovalStore(connection)
    connection.set_authorizer(None)
    columns = {
        row[1] for row in connection.execute(
            "PRAGMA table_info(plan_execution_edit_events)"
        )
    }
    assert "rollback_parent_identity_digest" not in columns
    assert "rollback_destination_parent_identity_digest" not in columns
