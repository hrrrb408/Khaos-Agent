"""M4 Batch 3.1.6.1 single-success and artifact-integrity closure."""
from __future__ import annotations

import hashlib
import os
import socket
import sqlite3
import stat
import time
from dataclasses import replace

import pytest

from test_m4_batch3_1_trusted_verification import (
    _ConfigurableExitBackend,
    _cleanup_proof,
    _fault_matrix_runtime,
    _finalize_test_store,
    _mutated_store,
    _profile,
    _run_verification,
    _running_store,
    _verification_run,
)
from khaos.coding.planning.execution_models import ExecutionRunStatus
from khaos.coding.planning.trusted_verification import ArtifactRootCapability
from khaos.coding.planning.verification_execution_models import (
    VerificationRunStatus,
    VerificationStepStatus,
)
from khaos.coding.planning.verification_store import VerificationExecutionStore
from khaos.coding.planning.approval import PlanApprovalStore


@pytest.mark.parametrize("source", [
    VerificationRunStatus.RUNNING,
    VerificationRunStatus.FINALIZING,
])
def test_transition_run_cannot_enter_passed(tmp_path, source):
    approval, store = _running_store(tmp_path)
    if source == VerificationRunStatus.FINALIZING:
        store.transition_run(
            "verify1", expected=(VerificationRunStatus.RUNNING,),
            target=VerificationRunStatus.FINALIZING,
        )
    with pytest.raises(RuntimeError, match="finalize_success"):
        store.transition_run(
            "verify1", expected=(source,), target=VerificationRunStatus.PASSED,
        )
    assert store.get_run("verify1").status == source
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING


def test_finish_step_and_run_cannot_write_success(tmp_path):
    approval, store = _running_store(tmp_path)
    step = replace(
        store.list_steps("verify1")[0],
        status=VerificationStepStatus.PASSED, exit_code=0,
    )
    with pytest.raises(RuntimeError, match="finalize_success"):
        store.finish_step_and_run(step)
    assert store.list_steps("verify1")[0].status == VerificationStepStatus.RUNNING
    assert store.get_run("verify1").status == VerificationRunStatus.RUNNING
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING


@pytest.mark.parametrize("table,status", [
    ("plan_verification_runs", "passed"),
    ("plan_execution_runs", "verified"),
])
def test_direct_sql_success_state_is_rejected(tmp_path, table, status):
    approval, store = _running_store(tmp_path)
    key = "verification_run_id='verify1'" if table == "plan_verification_runs" else "execution_run_id='run1'"
    with pytest.raises(sqlite3.IntegrityError, match="finalization|matching passed"):
        approval._conn.execute(
            f"UPDATE {table} SET status=? WHERE {key}", (status,),
        )
    approval._conn.rollback()
    assert store.get_run("verify1").status == VerificationRunStatus.RUNNING
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING


@pytest.mark.parametrize("table,status,key", [
    ("plan_verification_runs", "passed", "verification_run_id='verify1'"),
    ("plan_execution_runs", "verified", "execution_run_id='run1'"),
])
def test_independent_sqlite_connection_cannot_bypass_success_guard(
    tmp_path, table, status, key,
):
    database_path = tmp_path / "state.sqlite"
    approval, store = _mutated_store(tmp_path)
    store.create_run(_verification_run())
    store.transition_run(
        "verify1", expected=(VerificationRunStatus.CREATED,),
        target=VerificationRunStatus.VALIDATING,
    )
    store.transition_run(
        "verify1", expected=(VerificationRunStatus.VALIDATING,),
        target=VerificationRunStatus.PREPARING_SANDBOX,
    )
    store.transition_run("verify1", expected=(VerificationRunStatus.PREPARING_SANDBOX,), target=VerificationRunStatus.RUNNING)
    attacker = sqlite3.connect(database_path)
    try:
        with pytest.raises(sqlite3.DatabaseError):
            attacker.execute(f"UPDATE {table} SET status=? WHERE {key}", (status,))
            attacker.commit()
        attacker.rollback()
    finally:
        attacker.close()
    assert store.get_run("verify1").status == VerificationRunStatus.RUNNING
    assert approval.get_execution_run("run1").status == ExecutionRunStatus.VERIFYING


def test_finalize_success_second_state_failure_rolls_back_both(tmp_path):
    store, verification_run_id, execution_run_id = _finalize_test_store(tmp_path)
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-atomic",
        disposable_workspace_identity="instance:manifest",
        canonical_workspace_final_digest="canonical",
    )
    store.persist_cleanup_proof(proof)
    store._conn.execute(
        "CREATE TRIGGER fail_verified_write BEFORE UPDATE OF status "
        "ON plan_execution_runs WHEN NEW.status='verified' "
        "BEGIN SELECT RAISE(ABORT, 'injected verified failure'); END"
    )
    store._conn.commit()
    with pytest.raises(sqlite3.IntegrityError, match="injected verified failure"):
        store.finalize_success(
            step=None, verification_run_id=verification_run_id,
            execution_run_id=execution_run_id,
            workspace_id=proof.disposable_workspace_id,
            cleanup_proof=proof,
        )
    assert store.get_run(verification_run_id).status == VerificationRunStatus.FINALIZING
    assert store._approval_store.get_execution_run(execution_run_id).status == ExecutionRunStatus.VERIFYING


def test_finalize_success_rejects_proof_from_another_run(tmp_path):
    store, verification_run_id, execution_run_id = _finalize_test_store(tmp_path)
    persisted = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-bound",
    )
    store.persist_cleanup_proof(persisted)
    foreign = _cleanup_proof(
        verification_run_id="another-run",
        disposable_workspace_id="dvw-bound",
    )
    with pytest.raises(RuntimeError, match="another run"):
        store.finalize_success(
            step=None, verification_run_id=verification_run_id,
            execution_run_id=execution_run_id,
            workspace_id="dvw-bound", cleanup_proof=foreign,
        )
    assert store.get_run(verification_run_id).status == VerificationRunStatus.FINALIZING
    assert store._approval_store.get_execution_run(execution_run_id).status == ExecutionRunStatus.VERIFYING


def test_cleanup_proof_insert_is_run_scoped_idempotent(tmp_path):
    store, _, _ = _finalize_test_store(tmp_path)
    proof = _cleanup_proof(verification_run_id="verify1")
    first_id = store.persist_cleanup_proof(proof)
    same_id = store.persist_cleanup_proof(
        replace(proof, created_at=proof.created_at + 10),
    )
    assert first_id == same_id
    assert store._conn.execute(
        "SELECT COUNT(*) FROM verification_cleanup_proofs "
        "WHERE verification_run_id='verify1'"
    ).fetchone()[0] == 1


def test_cleanup_proof_different_content_conflicts(tmp_path):
    store, _, _ = _finalize_test_store(tmp_path)
    store.persist_cleanup_proof(_cleanup_proof(verification_run_id="verify1"))
    conflicting = _cleanup_proof(
        verification_run_id="verify1", disposable_workspace_id="different",
    )
    with pytest.raises(RuntimeError, match="immutable conflict"):
        store.persist_cleanup_proof(conflicting)
    assert store._conn.execute(
        "SELECT COUNT(*) FROM verification_cleanup_proofs "
        "WHERE verification_run_id='verify1'"
    ).fetchone()[0] == 1


@pytest.mark.parametrize("operation", ["UPDATE", "DELETE"])
def test_cleanup_proof_sql_mutation_is_rejected(tmp_path, operation):
    store, _, _ = _finalize_test_store(tmp_path)
    store.persist_cleanup_proof(_cleanup_proof(verification_run_id="verify1"))
    statement = (
        "UPDATE verification_cleanup_proofs SET cleanup_digest='forged' "
        "WHERE verification_run_id='verify1'"
        if operation == "UPDATE" else
        "DELETE FROM verification_cleanup_proofs WHERE verification_run_id='verify1'"
    )
    with pytest.raises(sqlite3.IntegrityError, match="immutable|cannot be deleted"):
        store._conn.execute(statement)
    store._conn.rollback()
    assert store.get_cleanup_proof_for_run("verify1") is not None


def test_cleanup_proof_duplicate_migration_fails_closed(tmp_path):
    connection = sqlite3.connect(tmp_path / "duplicates.sqlite")
    connection.execute(
        "CREATE TABLE verification_cleanup_proofs ("
        "cleanup_proof_id TEXT PRIMARY KEY,verification_run_id TEXT NOT NULL,"
        "disposable_workspace_id TEXT NOT NULL,disposable_workspace_identity TEXT NOT NULL,"
        "disposable_cleaned_at REAL NOT NULL,sandbox_instance_ids_json TEXT NOT NULL,"
        "sandbox_absence_digests_json TEXT NOT NULL,artifact_ids_json TEXT NOT NULL,"
        "artifact_seal_digests_json TEXT NOT NULL,canonical_workspace_final_digest TEXT NOT NULL,"
        "cleanup_digest TEXT NOT NULL,created_at REAL NOT NULL)"
    )
    for ordinal in (1, 2):
        connection.execute(
            "INSERT INTO verification_cleanup_proofs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (f"proof-{ordinal}", "duplicate-run", "workspace", "identity", 1.0,
             "[]", "[]", "[]", "[]", "canonical", f"digest-{ordinal}",
             float(ordinal)),
        )
    connection.commit()
    approval_store = PlanApprovalStore(connection)
    with pytest.raises(RuntimeError, match="duplicate runs"):
        VerificationExecutionStore(approval_store)
    assert connection.execute(
        "SELECT COUNT(*) FROM verification_cleanup_proofs"
    ).fetchone()[0] == 2


def _completed_verification(tmp_path):
    backend = _ConfigurableExitBackend(_profile(), exit_code=0)
    runtime, mutation = _fault_matrix_runtime(tmp_path, backend=backend)
    result = runtime._test_sync._loop.run_until_complete(
        _run_verification(runtime, mutation)
    )
    assert result.status == VerificationRunStatus.PASSED
    store = runtime._verification_store
    run = store.get_run(result.verification_run_id)
    execution = runtime._store.get_execution_run(mutation.execution_run_id)
    assert execution.status == ExecutionRunStatus.VERIFIED
    artifact = store.list_artifacts_for_run(run.verification_run_id)[0]
    store._conn.execute(
        "UPDATE plan_verification_runs SET status='finalizing',completed_at=NULL "
        "WHERE verification_run_id=?", (run.verification_run_id,),
    )
    store._conn.execute(
        "UPDATE plan_execution_runs SET status='verifying',completed_at=NULL "
        "WHERE execution_run_id=?", (execution.execution_run_id,),
    )
    store._conn.commit()
    return runtime, backend, run, execution, artifact


def _artifact_path(runtime, artifact_id):
    return runtime._verification_runner._artifact_capability.root_path / f"{artifact_id}.log"


@pytest.mark.parametrize("attack", [
    "fifo", "socket", "directory", "symlink", "hardlink", "mode",
    "owner-evidence", "size", "digest", "same-content-new-inode", "missing",
])
def test_finalizing_recovery_rejects_artifact_attacks(tmp_path, attack):
    runtime, backend, run, execution, artifact = _completed_verification(tmp_path)
    path = _artifact_path(runtime, artifact["artifact_id"])
    payload = path.read_bytes()
    socket_handle = None
    if attack == "fifo":
        path.unlink(); os.mkfifo(path, 0o600)
    elif attack == "socket":
        path.unlink(); socket_handle = socket.socket(socket.AF_UNIX)
        # macOS exposes /tmp as a symlink to /private/tmp.  Use the resolved
        # writable temporary root so sandbox path policy does not reject the
        # socket bind before the artifact verifier sees the real socket.
        short_socket = f"/private/tmp/khaos-art-{os.getpid()}-{time.time_ns()}"
        try:
            socket_handle.bind(short_socket)
        except PermissionError:
            socket_handle.close()
            pytest.skip("host sandbox forbids creating UNIX sockets")
        os.rename(short_socket, path)
    elif attack == "directory":
        path.unlink(); path.mkdir(mode=0o700)
    elif attack == "symlink":
        target = tmp_path / "outside-artifact"; target.write_bytes(payload)
        path.unlink(); path.symlink_to(target)
    elif attack == "hardlink":
        source = tmp_path / "hardlink-source"; source.write_bytes(payload)
        source.chmod(0o600); path.unlink(); os.link(source, path)
    elif attack == "mode":
        path.chmod(0o640)
    elif attack == "owner-evidence":
        runtime._verification_store._conn.execute(
            "UPDATE plan_verification_artifacts SET artifact_uid=artifact_uid+1 "
            "WHERE artifact_id=?", (artifact["artifact_id"],),
        ); runtime._verification_store._conn.commit()
    elif attack == "size":
        runtime._verification_store._conn.execute(
            "UPDATE plan_verification_artifacts SET byte_length=byte_length+1 "
            "WHERE artifact_id=?", (artifact["artifact_id"],),
        ); runtime._verification_store._conn.commit()
    elif attack == "digest":
        runtime._verification_store._conn.execute(
            "UPDATE plan_verification_artifacts SET content_digest=? "
            "WHERE artifact_id=?", (hashlib.sha256(b"wrong").hexdigest(), artifact["artifact_id"]),
        ); runtime._verification_store._conn.commit()
    elif attack == "same-content-new-inode":
        replacement = path.with_suffix(".replacement")
        replacement.write_bytes(payload); replacement.chmod(0o600)
        os.replace(replacement, path)
    elif attack == "missing":
        path.unlink()
    calls_before = len(backend.calls)
    started = time.monotonic()
    try:
        runtime._verification_runner._recover_finalizing_runs()
    finally:
        if socket_handle is not None:
            socket_handle.close()
    assert time.monotonic() - started < 2.0
    assert len(backend.calls) == calls_before
    assert runtime._verification_store.get_run(run.verification_run_id).status == VerificationRunStatus.ERRORED
    assert runtime._store.get_execution_run(execution.execution_run_id).status == ExecutionRunStatus.VERIFICATION_ERROR


def test_artifact_basename_swap_during_read_is_rejected(tmp_path, monkeypatch):
    runtime, backend, run, execution, artifact = _completed_verification(tmp_path)
    path = _artifact_path(runtime, artifact["artifact_id"])
    payload = path.read_bytes()
    import khaos.coding.planning.trusted_verification as module
    original_read = module.os.read
    swapped = False

    def swapping_read(fd, amount):
        nonlocal swapped
        data = original_read(fd, amount)
        if data and not swapped:
            swapped = True
            replacement = path.with_suffix(".swap")
            replacement.write_bytes(payload)
            replacement.chmod(0o600)
            os.replace(replacement, path)
        return data

    monkeypatch.setattr(module.os, "read", swapping_read)
    calls_before = len(backend.calls)
    runtime._verification_runner._recover_finalizing_runs()
    assert swapped
    assert len(backend.calls) == calls_before
    assert runtime._verification_store.get_run(run.verification_run_id).status == VerificationRunStatus.ERRORED
    assert runtime._store.get_execution_run(execution.execution_run_id).status == ExecutionRunStatus.VERIFICATION_ERROR


def test_artifact_parent_path_symlink_swap_is_rejected(tmp_path):
    runtime, backend, run, execution, artifact = _completed_verification(tmp_path)
    capability = runtime._verification_runner._artifact_capability
    original_root = capability.root_path
    moved_root = original_root.with_name(f"{original_root.name}-moved")
    original_root.rename(moved_root)
    original_root.symlink_to(moved_root, target_is_directory=True)
    calls_before = len(backend.calls)
    runtime._verification_runner._recover_finalizing_runs()
    assert len(backend.calls) == calls_before
    assert runtime._verification_store.get_run(run.verification_run_id).status == VerificationRunStatus.ERRORED
    assert runtime._store.get_execution_run(execution.execution_run_id).status == ExecutionRunStatus.VERIFICATION_ERROR


def test_artifact_id_cannot_escape_storage_root(tmp_path):
    root = tmp_path / "artifact-root"; root.mkdir(mode=0o700)
    outside = tmp_path / "outside.log"; outside.write_bytes(b"secret")
    with ArtifactRootCapability.open(root) as capability:
        assert not capability.verify_sealed_artifact(
            "../outside", expected_digest=hashlib.sha256(b"secret").hexdigest(),
            expected_size=6, expected_dev=0, expected_ino=0,
            expected_uid=os.getuid(), expected_gid=os.getgid(),
            expected_mode=0o600, expected_nlink=1,
        )
    assert outside.read_bytes() == b"secret"
