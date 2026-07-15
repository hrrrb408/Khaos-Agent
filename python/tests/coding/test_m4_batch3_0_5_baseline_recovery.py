"""Batch 3.0.5 baseline-bound rollback and zero-journal recovery matrix."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
import uuid
from dataclasses import replace
from types import SimpleNamespace

import pytest

from khaos.coding.planning.approval.store import PlanApprovalStore
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    InitialPathState,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
)
from khaos.coding.planning.safe_workspace_path import MutationObjectIdentity
from test_m4_batch2_8_boot_scope_closure import _real_runtime
from test_m4_batch3_0_workspace_mutation import _hash, _workspace


def _run(*, status=ExecutionRunStatus.CREATED, edit_count=1):
    now = time.time()
    return PlanExecutionRun(
        f"per_{uuid.uuid4().hex}", "plan", "plan-hash", "request",
        f"authorization-{uuid.uuid4().hex}", f"context-{uuid.uuid4().hex}",
        "lease", "task1", "ws1", "repo", "abc123", 1, "binding",
        "bundle", status, now, now, metadata={"edit_count": edit_count},
    )


def _bundle(run, edit):
    return PlannedEditBundle(
        "bundle", run.plan_id, run.plan_content_hash, run.task_id,
        run.workspace_id, run.repository_id, run.binding_digest, (edit,),
    ).normalized()


def _baseline_runtime(tmp_path, *, operation=PlannedEditOperation.UPDATE,
                      destination_exists=False, with_journal=True):
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    workspace = _workspace(tmp_path, workspaces)
    source = workspace.worktree_path / "a.txt"
    source.write_text("old", encoding="utf-8")
    os.chmod(source, 0o644)
    if destination_exists:
        (workspace.worktree_path / "b.txt").write_text("occupied", encoding="utf-8")
    edit = PlannedFileEdit(
        "e1", "s1", operation, "a.txt",
        destination_path="b.txt" if operation == PlannedEditOperation.RENAME else None,
        expected_content_hash=_hash("old"),
        new_content="new" if operation == PlannedEditOperation.UPDATE else None,
    ).normalized()
    run = replace(_run(), edit_bundle_digest=_bundle(_run(), edit).content_digest)
    # The bundle digest is independent of run id; rebuild with the real run binding.
    bundle = _bundle(run, edit)
    run = replace(run, edit_bundle_digest=bundle.content_digest)
    runtime._store.create_execution_run(run)
    runtime._store.transition_execution_run(
        run.execution_run_id, expected=("created",), target="validating",
    )
    git_state = runtime._mutation_engine._git_inspector.snapshot(
        workspace, repository_generation=1,
    )
    context = SimpleNamespace(
        execution_context_id=run.execution_context_id, lease_id=run.lease_id,
        binding_digest=run.binding_digest,
    )
    baseline = runtime._mutation_engine._build_initial_attestation(
        run, context, bundle, git_state,
    )
    runtime._store.save_initial_workspace_attestation(baseline)
    if not with_journal:
        return runtime, workspace, run, baseline, None
    runtime._store.transition_execution_run(
        run.execution_run_id, expected=("validating",), target="mutating",
    )
    recovery = runtime._mutation_engine._prepare_recovery(
        workspace, run.execution_run_id,
    )
    artifact, _ = recovery.create_backup(b"old", 0o644)
    after_hash = "" if operation == PlannedEditOperation.DELETE else (
        _hash("new") if operation == PlannedEditOperation.UPDATE else _hash("old")
    )
    after_mode = None if operation == PlannedEditOperation.DELETE else 0o644
    runtime._store.insert_edit_event(
        event_id=uuid.uuid4().hex, execution_run_id=run.execution_run_id,
        edit_id="e1", ordinal=0, operation=operation.value, path="a.txt",
        destination_path=edit.destination_path, before_hash=_hash("old"),
        before_mode=0o644, recovery_artifact=artifact,
        planned_after_hash=after_hash, planned_after_mode=after_mode,
    )
    runtime._store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="journaled",
        target_phase="mutation-started",
    )
    if operation == PlannedEditOperation.UPDATE:
        source.write_text("new", encoding="utf-8")
        os.chmod(source, 0o644)
    elif operation == PlannedEditOperation.DELETE:
        source.unlink()
    else:
        if not destination_exists:
            source.rename(workspace.worktree_path / "b.txt")
    source_parent = source.parent.stat()
    destination_parent = (
        (workspace.worktree_path / "b.txt").parent.stat()
        if operation == PlannedEditOperation.RENAME else None
    )
    target = workspace.worktree_path / (
        "b.txt" if operation == PlannedEditOperation.RENAME else "a.txt"
    )
    target_info = target.stat() if target.exists() else None
    identity = MutationObjectIdentity(
        target_info is not None,
        target_info.st_dev if target_info else 0,
        target_info.st_ino if target_info else 0,
        "regular" if target_info else "missing",
        source_parent.st_dev, source_parent.st_ino,
        destination_parent.st_dev if destination_parent else 0,
        destination_parent.st_ino if destination_parent else 0,
    )
    runtime._mutation_engine._record_mutation_phase(
        run.execution_run_id, edit, "filesystem-applied", identity,
    )
    phase = "filesystem-applied"
    for target in ("directory-synced", "applied"):
        runtime._store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase=phase,
            target_phase=target,
        )
        phase = target
    recovery.close()
    return runtime, workspace, run, baseline, artifact


def _corrupt_sqlite(runtime, sql, params):
    path = runtime._store._conn.execute("PRAGMA database_list").fetchone()[2]
    conn = sqlite3.connect(path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize(("field", "value"), [
    ("before_hash", "0" * 64),
    ("before_mode", 0o600),
    ("before_mode", 0o777),
])
def test_sqlite_journal_before_state_must_match_baseline(tmp_path, field, value):
    runtime, workspace, run, _, _ = _baseline_runtime(tmp_path)
    _corrupt_sqlite(
        runtime,
        f"UPDATE plan_execution_edit_events SET {field}=? WHERE execution_run_id=?",
        (value, run.execution_run_id),
    )
    assert run.execution_run_id not in runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.worktree_path / "a.txt").read_text() == "new"


def test_sqlite_baseline_type_mismatch_is_rejected(tmp_path):
    runtime, workspace, run, baseline, _ = _baseline_runtime(tmp_path)
    states = tuple(replace(item, file_type="symlink") if item.path == "a.txt" else item
                   for item in baseline.declared_states)
    corrupt = replace(baseline, declared_states=states, attestation_digest="").normalized()
    payload = {
        **corrupt.__dict__,
        "declared_states": [item.__dict__ for item in corrupt.declared_states],
        "workspace_states": [item.__dict__ for item in corrupt.workspace_states],
        "approved_edits": [item.canonical() for item in corrupt.approved_edits],
    }
    _corrupt_sqlite(runtime, "UPDATE plan_execution_initial_attestations SET "
                    "canonical_json=?,attestation_digest=? WHERE execution_run_id=?",
                    (json.dumps(payload, sort_keys=True, separators=(",", ":")),
                     corrupt.attestation_digest, run.execution_run_id))
    _corrupt_sqlite(runtime, "UPDATE plan_execution_runs SET initial_attestation_digest=? "
                    "WHERE execution_run_id=?",
                    (corrupt.attestation_digest, run.execution_run_id))
    runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.worktree_path / "a.txt").read_text() == "new"


@pytest.mark.parametrize("operation", [
    PlannedEditOperation.UPDATE,
    PlannedEditOperation.DELETE,
    PlannedEditOperation.RENAME,
])
def test_recovery_artifact_must_hash_to_initial_baseline(tmp_path, operation):
    runtime, workspace, run, _, artifact = _baseline_runtime(
        tmp_path, operation=operation,
    )
    artifact_path = workspace.recovery_root / run.execution_run_id / artifact
    artifact_path.write_bytes(b"tampered")
    before = {
        path.name: path.read_bytes() for path in workspace.worktree_path.iterdir()
        if path.name != ".git"
    }
    runtime._mutation_engine.recover_incomplete_runs()
    after = {
        path.name: path.read_bytes() for path in workspace.worktree_path.iterdir()
        if path.name != ".git"
    }
    assert before == after
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED


def test_rename_destination_existing_in_baseline_is_rejected(tmp_path):
    runtime, workspace, run, _, _ = _baseline_runtime(
        tmp_path, operation=PlannedEditOperation.RENAME,
        destination_exists=True,
    )
    runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.worktree_path / "b.txt").read_text() == "occupied"


def test_matching_corrupt_journal_and_artifact_do_not_override_baseline(tmp_path):
    runtime, workspace, run, _, artifact = _baseline_runtime(tmp_path)
    corrupt_hash = _hash("corrupt")
    (workspace.recovery_root / run.execution_run_id / artifact).write_text("corrupt")
    _corrupt_sqlite(
        runtime,
        "UPDATE plan_execution_edit_events SET before_hash=? WHERE execution_run_id=?",
        (corrupt_hash, run.execution_run_id),
    )
    runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert (workspace.worktree_path / "a.txt").read_text() == "new"


def test_zero_journal_unchanged_workspace_terminalizes_atomically(tmp_path):
    runtime, _, run, _, _ = _baseline_runtime(tmp_path, with_journal=False)
    recovered = runtime._mutation_engine.recover_incomplete_runs()
    current = runtime._store.get_execution_run(run.execution_run_id)
    assert recovered == (run.execution_run_id,)
    assert current.status == ExecutionRunStatus.FAILED
    assert current.failure_code == "no-mutation-crash"
    assert runtime._store.list_workspace_poison_scopes("ws1") == ()


@pytest.mark.parametrize("drift", [
    "declared", "unknown-artifact", "generation", "head", "index",
])
def test_zero_journal_with_evidence_of_change_stays_poisoned(tmp_path, drift):
    runtime, workspace, run, _, _ = _baseline_runtime(tmp_path, with_journal=False)
    if drift == "declared":
        (workspace.worktree_path / "a.txt").write_text("changed")
    elif drift == "unknown-artifact":
        recovery = workspace.recovery_root / run.execution_run_id
        recovery.mkdir(parents=True)
        os.chmod(recovery.parent, 0o700)
        os.chmod(recovery, 0o700)
        (recovery / f"artifact-{uuid.uuid4().hex}.bak").write_text("unknown")
    elif drift == "generation":
        runtime._context_provider.set(repository_generation=2)
    elif drift == "head":
        runtime._mutation_engine._workspaces._workspaces[workspace.id] = replace(
            workspace, base_sha="different-head",
        )
    else:
        admin = tmp_path / "admin" / "worktrees" / "test"
        admin.mkdir(parents=True)
        (admin / "index").write_bytes(b"changed-index")
    runtime._mutation_engine.recover_incomplete_runs()
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.POISONED
    assert runtime._store.list_workspace_poison_scopes("ws1")


def test_normal_startup_rollback_terminalizes_with_run_poison_removed(tmp_path):
    runtime, workspace, run, _, _ = _baseline_runtime(tmp_path)
    recovered = runtime._mutation_engine.recover_incomplete_runs()
    assert recovered == (run.execution_run_id,)
    assert runtime._store.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.ROLLED_BACK
    assert (workspace.worktree_path / "a.txt").read_text() == "old"
    assert runtime._store.list_workspace_poison_scopes("ws1") == ()


def test_recovered_terminal_transaction_survives_store_reopen(tmp_path):
    runtime, _, run, _, _ = _baseline_runtime(tmp_path, with_journal=False)
    runtime._mutation_engine.recover_incomplete_runs()
    db_path = runtime._store._conn.execute("PRAGMA database_list").fetchone()[2]
    reopened = PlanApprovalStore(sqlite3.connect(db_path))
    assert reopened.get_execution_run(run.execution_run_id).status == ExecutionRunStatus.FAILED
    assert reopened.list_workspace_poison_scopes("ws1") == ()


@pytest.mark.parametrize("fault", ["audit", "poison-delete"])
def test_zero_journal_terminal_and_poison_are_one_transaction(tmp_path, monkeypatch, fault):
    runtime, _, run, _, _ = _baseline_runtime(tmp_path, with_journal=False)
    if fault == "audit":
        original = runtime._store._insert_execution_audit

        def fail_audit(*args, **kwargs):
            if args[1] == "recovered-no-mutation-committed":
                raise sqlite3.OperationalError("audit fault")
            return original(*args, **kwargs)

        monkeypatch.setattr(runtime._store, "_insert_execution_audit", fail_audit)
    else:
        runtime._store._conn.execute(
            "CREATE TRIGGER fail_run_poison_delete BEFORE DELETE ON "
            "workspace_mutation_poison_scopes BEGIN SELECT RAISE(ABORT,'delete fault'); END"
        )
    runtime._mutation_engine.recover_incomplete_runs()
    current = runtime._store.get_execution_run(run.execution_run_id)
    assert current.status == ExecutionRunStatus.POISONED
    assert runtime._store.list_workspace_poison_scopes("ws1")


def _phase_store(tmp_path):
    path = tmp_path / "phase.sqlite"
    store = PlanApprovalStore(sqlite3.connect(path, check_same_thread=False))
    run = _run(status=ExecutionRunStatus.MUTATING)
    store.create_execution_run(run)
    store.insert_edit_event(
        event_id=uuid.uuid4().hex, execution_run_id=run.execution_run_id,
        edit_id="e1", ordinal=0, operation="update", path="a.txt",
        destination_path=None, before_hash=_hash("old"), before_mode=0o644,
        recovery_artifact=f"artifact-{uuid.uuid4().hex}.bak",
        planned_after_hash=_hash("new"), planned_after_mode=0o644,
    )
    return path, store, run


def test_edit_phase_skip_and_backward_transition_are_rejected(tmp_path):
    _, store, run = _phase_store(tmp_path)
    with pytest.raises(RuntimeError, match="phase transition"):
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase="journaled",
            target_phase="filesystem-applied",
        )
    store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="journaled",
        target_phase="mutation-started",
    )
    with pytest.raises(RuntimeError, match="phase transition"):
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase="mutation-started",
            target_phase="journaled",
        )


def test_applied_phase_cannot_rewrite_after_state(tmp_path):
    _, store, run = _phase_store(tmp_path)
    phase = "journaled"
    for target in ("mutation-started", "filesystem-applied", "directory-synced", "applied"):
        identity = {}
        if target == "filesystem-applied":
            identity = {
                "applied_identity_digest": "1" * 64,
                "applied_parent_identity_digest": "2" * 64,
            }
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase=phase,
            target_phase=target, **identity,
        )
        phase = target
    with pytest.raises(RuntimeError, match="changed state"):
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase="applied",
            target_phase="applied", after_hash="f" * 64,
        )


def test_rolled_back_phase_requires_rollback_run(tmp_path):
    _, store, run = _phase_store(tmp_path)
    with pytest.raises(RuntimeError, match="rollback run"):
        store.transition_edit_event(
            run.execution_run_id, "e1", expected_phase="journaled",
            target_phase="rolled-back",
        )


def test_edit_phase_compare_and_swap_allows_one_concurrent_winner(tmp_path):
    path, store, run = _phase_store(tmp_path)
    barrier = threading.Barrier(2)
    outcomes = []

    def advance():
        local = PlanApprovalStore(sqlite3.connect(path, check_same_thread=False))
        barrier.wait()
        try:
            local.transition_edit_event(
                run.execution_run_id, "e1", expected_phase="journaled",
                target_phase="mutation-started",
            )
            outcomes.append("ok")
        except RuntimeError:
            outcomes.append("conflict")

    threads = [threading.Thread(target=advance) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["conflict", "ok"]
    row = store.list_execution_edit_events(run.execution_run_id)[0]
    assert (row["status"], row["phase_version"]) == ("mutation-started", 1)


def test_same_edit_phase_retry_is_idempotent(tmp_path):
    _, store, run = _phase_store(tmp_path)
    store.transition_edit_event(
        run.execution_run_id, "e1", expected_phase="journaled",
        target_phase="journaled",
    )
    row = store.list_execution_edit_events(run.execution_run_id)[0]
    assert (row["status"], row["phase_version"]) == ("journaled", 0)
