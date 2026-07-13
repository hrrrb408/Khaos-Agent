"""Batch 3.0.6 restart-idempotent rollback and object ownership matrix."""
from __future__ import annotations

import os
import sqlite3
import stat
import threading
import uuid
from dataclasses import replace

import pytest

from _m4_batch2_helpers import FakeContextProvider, SyncBroker
from test_m4_batch2_5_runtime_authority import DeepFakePlanningService
from test_m4_batch2_8_boot_scope_closure import _real_runtime
from test_m4_batch3_0_5_baseline_recovery import _phase_store
from test_m4_batch3_0_workspace_mutation import (
    _apply, _bundle, _hash, _setup,
)
from khaos.coding.intelligence.index.repository import RepositoryIndexer
from khaos.coding.intelligence.index.store import IndexStore
from khaos.coding.planning.approval import (
    ApprovalRuntime, PersistedPlanRepository, PlanApprovalStore,
)
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus, PlannedEditOperation, PlannedFileEdit,
    RollbackResumeDisposition,
)
from khaos.coding.task_manager import TaskManager
from khaos.coding.planning.safe_workspace_path import WorkspacePathHandle


def test_legacy_edit_event_schema_migrates_before_recovery_index(tmp_path):
    database = tmp_path / "legacy-edit-events.sqlite"
    connection = sqlite3.connect(database)
    connection.execute(
        "CREATE TABLE plan_execution_edit_events ("
        "event_id TEXT PRIMARY KEY, execution_run_id TEXT NOT NULL, "
        "edit_id TEXT NOT NULL, ordinal INTEGER NOT NULL, "
        "status TEXT NOT NULL, phase_version INTEGER NOT NULL DEFAULT 0)"
    )
    connection.commit()
    store = PlanApprovalStore(connection)

    columns = {
        row[1] for row in store._conn.execute(
            "PRAGMA table_info(plan_execution_edit_events)"
        )
    }
    indexes = {
        row[1] for row in store._conn.execute(
            "PRAGMA index_list(plan_execution_edit_events)"
        )
    }
    assert {
        "applied_identity_digest", "applied_parent_identity_digest",
        "applied_destination_identity_digest", "rollback_identity_digest",
        "identity_version",
    } <= columns
    assert "idx_plan_execution_edit_events_recovery" in indexes


def _edit_for(tmp_path, operation):
    root = tmp_path / "isolated-worktree"
    if operation != PlannedEditOperation.CREATE:
        root.mkdir(exist_ok=True)
        (root / "a.txt").write_text("old", encoding="utf-8")
        os.chmod(root / "a.txt", 0o644)
    return PlannedFileEdit(
        "e1", "s1", operation, "a.txt",
        destination_path=(
            "b.txt" if operation == PlannedEditOperation.RENAME else None
        ),
        expected_exists=operation != PlannedEditOperation.CREATE,
        expected_content_hash=(
            None if operation == PlannedEditOperation.CREATE else _hash("old")
        ),
        new_content=(
            "new" if operation in {
                PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE,
            } else None
        ),
    )


def _crash_after_applied(tmp_path, operation):
    edit = _edit_for(tmp_path, operation)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original_build = engine._build_final_attestation
    original_rollback = engine._rollback

    def crash_before_attestation(*args, **kwargs):
        raise RuntimeError("crash-before-final-attestation")

    def stop_before_rollback(*args, **kwargs):
        raise SystemExit("simulated-process-crash")

    engine._build_final_attestation = crash_before_attestation
    engine._rollback = stop_before_rollback
    try:
        with pytest.raises(SystemExit, match="simulated-process-crash"):
            _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    finally:
        engine._build_final_attestation = original_build
        engine._rollback = original_rollback
    run = runtime._store.get_execution_run_by_context(
        runtime._store._conn.execute(
            "SELECT execution_context_id FROM plan_execution_runs"
        ).fetchone()[0]
    )
    event = runtime._store.list_execution_edit_events(run.execution_run_id)[0]
    assert run.status == ExecutionRunStatus.MUTATING
    assert event["status"] == "applied"
    assert event["identity_version"] == 1
    assert event["applied_parent_identity_digest"]
    return runtime, workspace, run


def _restart_runtime(tmp_path, previous):
    db_path = previous._store._conn.execute("PRAGMA database_list").fetchone()[2]
    store = PlanApprovalStore(sqlite3.connect(db_path, check_same_thread=False))
    manager = previous._mutation_engine._workspaces
    index_store = IndexStore(sqlite3.connect(
        tmp_path / f"restart-index-{uuid.uuid4().hex}.sqlite",
        check_same_thread=False,
    ))
    runtime = ApprovalRuntime(
        store=store, broker=SyncBroker().real,
        context_provider=FakeContextProvider(),
        plan_repository=PersistedPlanRepository(store),
        planning_service=DeepFakePlanningService(),
        task_manager=TaskManager(), workspace_manager=manager,
        repository_indexer=RepositoryIndexer(index_store),
    )
    runtime.initialize()
    return runtime


def _replace_same_content(path, content):
    old_inode = path.stat().st_ino if path.exists() else None
    temporary = path.with_name(f"third-party-{uuid.uuid4().hex}.tmp")
    temporary.write_text(content, encoding="utf-8")
    os.chmod(temporary, 0o644)
    os.replace(temporary, path)
    assert old_inode is None or path.stat().st_ino != old_inode
    return path.stat().st_ino


def test_run_rollback_begin_resume_preserves_first_reason_and_single_audit(tmp_path):
    runtime, _, run = _crash_after_applied(tmp_path, PlannedEditOperation.UPDATE)
    first = runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="first-reason",
    )
    same = runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="first-reason",
    )
    different = runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="different-reason",
    )
    assert first.disposition == RollbackResumeDisposition.STARTED
    assert same.disposition == RollbackResumeDisposition.RESUMED
    assert different.failure_code == "first-reason"
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_audit_events "
        "WHERE execution_run_id=? AND event_type='rollback-started'",
        (run.execution_run_id,),
    ).fetchone()[0] == 1


def test_run_rolling_back_crash_resumes_on_restart_and_second_restart_is_stable(tmp_path):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="restart-test",
    )
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK
    assert (workspace.worktree_path / "a.txt").read_text() == "old"
    restarted_again = _restart_runtime(tmp_path, restarted)
    assert restarted_again._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK


def test_rollback_started_event_resumes_without_replaying_completed_work(tmp_path):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="rollback-started-crash",
    )
    runtime._store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="applied",
        target_phase="rollback-started", error_code="rollback-started-crash",
    )
    restarted = _restart_runtime(tmp_path, runtime)
    event = restarted._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rolled-back"
    assert event["rollback_identity_digest"]
    assert (workspace.worktree_path / "a.txt").read_text() == "old"


def test_rolled_back_event_same_reason_is_idempotent_and_different_reason_conflicts(tmp_path):
    _, store, run = _phase_store(tmp_path)
    store.begin_or_resume_rollback(run.execution_run_id, failure_code="reason-a")
    store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="journaled",
        target_phase="rolled-back", error_code="reason-a",
    )
    before = store.list_execution_edit_events(run.execution_run_id)[0]
    store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="rolled-back",
        target_phase="rolled-back", error_code="reason-a",
    )
    after = store.list_execution_edit_events(run.execution_run_id)[0]
    assert after["phase_version"] == before["phase_version"]
    with pytest.raises(RuntimeError, match="changed state"):
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase="rolled-back",
            target_phase="rolled-back", error_code="reason-b",
        )


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_same_content_third_party_replacement_is_never_rolled_back(tmp_path, operation):
    runtime, workspace, run = _crash_after_applied(tmp_path, operation)
    target = workspace.worktree_path / (
        "b.txt" if operation == PlannedEditOperation.RENAME else "a.txt"
    )
    if operation == PlannedEditOperation.DELETE:
        target = workspace.worktree_path / "a.txt"
        third_party_inode = _replace_same_content(target, "old")
    else:
        content = "new" if operation in {
            PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE,
        } else "old"
        third_party_inode = _replace_same_content(target, content)
    restarted = _restart_runtime(tmp_path, runtime)
    current = restarted._store.get_execution_run(run.execution_run_id)
    assert current.status == ExecutionRunStatus.POISONED
    assert target.exists() and target.stat().st_ino == third_party_inode
    assert target.read_text() == (
        "new" if operation in {
            PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE,
        } else "old"
    )
    recovery = workspace.recovery_root / run.execution_run_id
    assert recovery.exists()
    if operation != PlannedEditOperation.CREATE:
        assert tuple(recovery.iterdir())


@pytest.mark.parametrize("operation", list(PlannedEditOperation))
def test_final_attestation_rejects_same_content_new_inode(tmp_path, monkeypatch, operation):
    edit = _edit_for(tmp_path, operation)
    runtime, workspace, plan, authorization = _setup(tmp_path, (edit,))
    engine = runtime._mutation_engine
    original = engine._build_final_attestation

    def replace_then_attest(*args, **kwargs):
        target = workspace.worktree_path / (
            "b.txt" if operation == PlannedEditOperation.RENAME else "a.txt"
        )
        if operation == PlannedEditOperation.DELETE:
            _replace_same_content(target, "old")
        else:
            _replace_same_content(
                target,
                "new" if operation in {
                    PlannedEditOperation.CREATE, PlannedEditOperation.UPDATE,
                } else "old",
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(engine, "_build_final_attestation", replace_then_attest)
    with pytest.raises(Exception):
        _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    run = runtime._store._conn.execute(
        "SELECT status FROM plan_execution_runs"
    ).fetchone()
    assert run["status"] == "poisoned"


def test_filesystem_applied_identity_survives_phase_return_crash(tmp_path):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    runtime._store._conn.execute(
        "UPDATE plan_execution_edit_events SET status='filesystem-applied',"
        "phase_version=2 WHERE execution_run_id=?", (run.execution_run_id,),
    )
    runtime._store._conn.commit()
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK
    assert (workspace.worktree_path / "a.txt").read_text() == "old"


@pytest.mark.parametrize("completed_phase", ["rollback-started", "rolled-back"])
def test_restart_resumes_after_rollback_syscall_without_replaying(tmp_path, completed_phase):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    engine = runtime._mutation_engine
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="rollback-syscall-crash",
    )
    current = runtime._store.get_execution_run(run.execution_run_id)
    journal = engine._validated_journal(current, allow_partial=True)
    baseline = engine._require_initial_attestation(current)
    recovery = engine._open_recovery(
        workspace, run.execution_run_id, journal.events,
    )
    handle = WorkspacePathHandle(workspace.worktree_path.resolve(strict=True))
    try:
        event = journal.events[0]
        runtime._store.transition_edit_event(
            run.execution_run_id, event.edit_id, expected_phase="applied",
            target_phase="rollback-started",
            error_code="rollback-syscall-crash",
        )
        event = replace(
            event, durable_phase="rollback-started",
            phase_version=event.phase_version + 1,
        )
        engine._rollback_event(
            handle, event, recovery,
            {item.path: item for item in baseline.declared_states}[event.path.value],
            run_id=run.execution_run_id,
            failure_code="rollback-syscall-crash",
        )
        if completed_phase == "rolled-back":
            runtime._store.transition_edit_event(
                run.execution_run_id, event.edit_id,
                expected_phase="rollback-started", target_phase="rolled-back",
                error_code="rollback-syscall-crash",
            )
    finally:
        handle.close()
        recovery.close()
    restored_inode = (workspace.worktree_path / "a.txt").stat().st_ino
    restarted = _restart_runtime(tmp_path, runtime)
    event = restarted._store.list_execution_edit_events(run.execution_run_id)[0]
    assert event["status"] == "rolled-back"
    assert restarted._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK
    assert (workspace.worktree_path / "a.txt").stat().st_ino == restored_inode


def test_rolled_back_object_replaced_before_restart_is_not_accepted(tmp_path):
    runtime, workspace, run = _crash_after_applied(
        tmp_path, PlannedEditOperation.UPDATE,
    )
    engine = runtime._mutation_engine
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="rolled-back-replacement",
    )
    current = runtime._store.get_execution_run(run.execution_run_id)
    journal = engine._validated_journal(current, allow_partial=True)
    baseline = engine._require_initial_attestation(current)
    recovery = engine._open_recovery(workspace, run.execution_run_id, journal.events)
    handle = WorkspacePathHandle(workspace.worktree_path.resolve(strict=True))
    try:
        event = journal.events[0]
        runtime._store.transition_edit_event(
            run.execution_run_id, event.edit_id, expected_phase="applied",
            target_phase="rollback-started",
            error_code="rolled-back-replacement",
        )
        event = replace(event, durable_phase="rollback-started", phase_version=5)
        engine._rollback_event(
            handle, event, recovery,
            {item.path: item for item in baseline.declared_states}[event.path.value],
            run_id=run.execution_run_id,
            failure_code="rolled-back-replacement",
        )
        runtime._store.transition_edit_event(
            run.execution_run_id, event.edit_id,
            expected_phase="rollback-started", target_phase="rolled-back",
            error_code="rolled-back-replacement",
        )
    finally:
        handle.close()
        recovery.close()
    third_party_inode = _replace_same_content(
        workspace.worktree_path / "a.txt", "old",
    )
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.worktree_path / "a.txt").stat().st_ino == third_party_inode


def test_restart_completes_mixed_applied_rollback_started_and_rolled_back_events(tmp_path):
    root = tmp_path / "isolated-worktree"
    root.mkdir()
    edits = []
    for name in ("a.txt", "b.txt", "c.txt"):
        (root / name).write_text("old", encoding="utf-8")
        edits.append(PlannedFileEdit(
            f"edit-{name[0]}", f"step-{name[0]}",
            PlannedEditOperation.UPDATE, name,
            expected_content_hash=_hash("old"), new_content="new",
        ))
    runtime, workspace, plan, authorization = _setup(tmp_path, tuple(edits))
    engine = runtime._mutation_engine
    original_build, original_rollback = (
        engine._build_final_attestation, engine._rollback,
    )
    engine._build_final_attestation = lambda *args, **kwargs: (_ for _ in ()).throw(
        RuntimeError("mixed-phase-crash")
    )
    engine._rollback = lambda *args, **kwargs: (_ for _ in ()).throw(
        SystemExit("mixed-phase-stop")
    )
    try:
        with pytest.raises(SystemExit):
            _apply(runtime, plan, authorization, _bundle(plan, tuple(edits)))
    finally:
        engine._build_final_attestation = original_build
        engine._rollback = original_rollback
    run = runtime._store.get_execution_run(
        runtime._store._conn.execute(
            "SELECT execution_run_id FROM plan_execution_runs"
        ).fetchone()[0]
    )
    runtime._store.begin_or_resume_rollback(
        run.execution_run_id, failure_code="mixed-phase-crash",
    )
    run = runtime._store.get_execution_run(run.execution_run_id)
    journal = engine._validated_journal(run, allow_partial=True)
    baseline = engine._require_initial_attestation(run)
    recovery = engine._open_recovery(workspace, run.execution_run_id, journal.events)
    handle = WorkspacePathHandle(workspace.worktree_path.resolve(strict=True))
    try:
        for event, complete in (
            (journal.events[1], False), (journal.events[2], True),
        ):
            runtime._store.transition_edit_event(
                run.execution_run_id, event.edit_id, expected_phase="applied",
                target_phase="rollback-started", error_code="mixed-phase-crash",
            )
            if complete:
                event = replace(
                    event, durable_phase="rollback-started",
                    phase_version=event.phase_version + 1,
                )
                engine._rollback_event(
                    handle, event, recovery,
                    {item.path: item for item in baseline.declared_states}[
                        event.path.value
                    ],
                    run_id=run.execution_run_id,
                    failure_code="mixed-phase-crash",
                )
                runtime._store.transition_edit_event(
                    run.execution_run_id, event.edit_id,
                    expected_phase="rollback-started", target_phase="rolled-back",
                    error_code="mixed-phase-crash",
                )
    finally:
        handle.close()
        recovery.close()
    restarted = _restart_runtime(tmp_path, runtime)
    assert restarted._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK
    assert {
        row["status"] for row in restarted._store.list_execution_edit_events(
            run.execution_run_id
        )
    } == {"rolled-back"}
    assert all((workspace.worktree_path / name).read_text() == "old" for name in (
        "a.txt", "b.txt", "c.txt",
    ))


def test_run_rollback_begin_uses_sqlite_cas_across_connections(tmp_path):
    path, store, run = _phase_store(tmp_path)
    barrier = threading.Barrier(2)
    results = []

    def begin():
        local = PlanApprovalStore(sqlite3.connect(path, check_same_thread=False))
        barrier.wait()
        result = local.begin_or_resume_rollback(
            run.execution_run_id, failure_code="race-reason",
        )
        results.append(result.disposition.value)

    threads = [threading.Thread(target=begin) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(results) == ["resumed", "started"]
    assert store._conn.execute(
        "SELECT COUNT(*) FROM plan_execution_audit_events WHERE event_type='rollback-started'"
    ).fetchone()[0] == 1
