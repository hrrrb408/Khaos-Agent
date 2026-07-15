"""M4 Batch 3.1.6.2 verification write-authority closure."""
from __future__ import annotations

import os
import hashlib
import json
import shutil
import sqlite3
import subprocess
import sys
import uuid
import inspect
from pathlib import Path

import pytest

from khaos.coding.planning.execution_models import ExecutionRunStatus
from khaos.coding.planning.verification_authority import (
    PROTECTED_SCHEMA_OBJECTS,
    VERIFICATION_AUTHORITIES,
    VerificationReadHandle,
    VerificationWriteAuthority,
    VerificationWriteCapability,
)
from khaos.coding.planning.verification_execution_models import (
    VerificationRunStatus,
)
from khaos.coding.planning.verification_store import VerificationExecutionStore
import khaos.coding.planning.verification_store as verification_store_module
from test_m4_batch3_1_trusted_verification import (
    _cleanup_proof,
    _finalize_test_store,
)


def _authority_store(tmp_path, *, runtime_id=None, boot_id=None):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    runtime_id = runtime_id or f"runtime-{uuid.uuid4().hex}"
    boot_id = boot_id or f"boot-{uuid.uuid4().hex}"
    store, verification_run_id, execution_run_id = _finalize_test_store(tmp_path)
    database_path = Path(
        store._conn.execute("PRAGMA database_list").fetchone()[2]
    )
    authority = VERIFICATION_AUTHORITIES.issue(
        store._conn, runtime_id=runtime_id, boot_id=boot_id,
    )
    store.bind_write_authority(authority)
    return store, authority, database_path, verification_run_id, execution_run_id


def _assert_not_success(store, verification_run_id, execution_run_id):
    assert store.get_run(verification_run_id).status != VerificationRunStatus.PASSED
    assert (
        store._approval_store.get_execution_run(execution_run_id).status
        != ExecutionRunStatus.VERIFIED
    )


def test_authority_and_capability_cannot_be_constructed():
    with pytest.raises(TypeError):
        VerificationWriteAuthority()
    with pytest.raises(TypeError):
        VerificationWriteCapability()


def test_production_store_has_no_finalization_udf_registration():
    source = inspect.getsource(verification_store_module)
    assert "khaos_verification_finalization_guard" not in source
    assert "create_function(" not in source


def test_schema_manifest_explicitly_covers_all_security_trigger_families():
    for prefix in ("trg_execution_", "trg_vse_", "trg_vcp_"):
        assert any(name.startswith(prefix) for name in PROTECTED_SCHEMA_OBJECTS)
    assert PROTECTED_SCHEMA_OBJECTS["plan_execution_runs"] == "table"
    assert PROTECTED_SCHEMA_OBJECTS["verification_success_evidence"] == "table"


def test_read_handle_recomputes_all_canonical_success_bindings():
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        "CREATE TABLE plan_verification_runs(verification_run_id TEXT,"
        "execution_run_id TEXT,status TEXT);"
        "CREATE TABLE plan_execution_runs(execution_run_id TEXT,status TEXT);"
        "CREATE TABLE verification_success_evidence(verification_run_id TEXT,"
        "execution_run_id TEXT,cleanup_proof_id TEXT,cleanup_digest TEXT,"
        "authority_instance_id TEXT,runtime_id TEXT,boot_id TEXT,"
        "payload_digest TEXT);"
    )
    connection.execute(
        "INSERT INTO plan_verification_runs VALUES ('vr','er','passed')"
    )
    connection.execute("INSERT INTO plan_execution_runs VALUES ('er','verified')")
    connection.execute(
        "INSERT INTO verification_success_evidence VALUES "
        "('vr','er','proof','transplanted-cleanup','authority','runtime','boot',"
        "'authority-accepted-old-digest')"
    )

    class FakeAuthority:
        def verify_storage(self):
            return None

        def require_success(self, run_id, digest):
            assert run_id == "vr"
            assert digest == "authority-accepted-old-digest"

    reader = VerificationReadHandle(connection, FakeAuthority())
    with pytest.raises(PermissionError, match="digest mismatch"):
        reader.verification_status("vr")
    with pytest.raises(PermissionError, match="digest mismatch"):
        reader.execution_status("er")
    reader.close()


def test_authority_ledger_runs_in_distinct_process(tmp_path):
    _, authority, _, _, _ = _authority_store(tmp_path)
    assert authority.authority_process_id != os.getpid()
    authority.close()


def test_authority_ledger_is_durable_hash_chained_and_boot_scoped(tmp_path):
    _store, first, database_path, _, _ = _authority_store(
        tmp_path, runtime_id="runtime-ledger", boot_id="boot-one",
    )
    ledger_path = first.ledger_path
    first.authorize_cleanup_proof("proof", "run", "digest")
    first.close()
    assert ledger_path.exists()

    next_connection = sqlite3.connect(database_path)
    next_connection.row_factory = sqlite3.Row
    second = VERIFICATION_AUTHORITIES.issue(
        next_connection, runtime_id="runtime-ledger", boot_id="boot-two",
    )
    with pytest.raises(PermissionError, match="not authority-issued"):
        second.require_cleanup_proof("proof", "run", "digest")
    second.close()

    ledger = sqlite3.connect(f"file:{ledger_path}?mode=ro", uri=True)
    rows = ledger.execute(
        "SELECT boot_id,payload_json,previous_hash,event_hash "
        "FROM authority_events ORDER BY sequence"
    ).fetchall()
    assert {row[0] for row in rows} == {"boot-one", "boot-two"}
    previous_hash = "0" * 64
    for _, payload, stored_previous, stored_hash in rows:
        assert stored_previous == previous_hash
        expected = hashlib.sha256(
            f"{previous_hash}\n{payload}".encode("utf-8")
        ).hexdigest()
        assert stored_hash == expected
        previous_hash = stored_hash
    ledger.close()


def test_same_boot_authority_cannot_be_issued_twice(tmp_path):
    store, authority, _, _, _ = _authority_store(
        tmp_path, runtime_id="runtime-a", boot_id="boot-a",
    )
    with pytest.raises(PermissionError, match="already issued"):
        VERIFICATION_AUTHORITIES.issue(
            store._conn, runtime_id="runtime-a", boot_id="boot-a",
        )
    authority.close()


def test_ipc_capability_replay_is_rejected(tmp_path):
    _, authority, _, _, _ = _authority_store(tmp_path)
    with pytest.raises(PermissionError, match="lacks authority evidence"):
        authority._rpc("require-success", "missing", "missing")
    # The legitimate request was rejected semantically but consumed sequence 1.
    authority._ipc_connection.send((
        authority._ipc_capability, 1, "require-success",
        ("missing", "missing"),
    ))
    accepted, error = authority._ipc_connection.recv()
    assert not accepted
    assert "replay" in error
    authority.close()


def test_cross_runtime_ipc_capability_is_rejected(tmp_path):
    _, first, _, _, _ = _authority_store(tmp_path / "first")
    _, second, _, _, _ = _authority_store(tmp_path / "second")
    second._ipc_connection.send((
        first._ipc_capability, 1, "require-success", ("x", "y"),
    ))
    accepted, error = second._ipc_connection.recv()
    assert not accepted
    assert "capability" in error
    first.close()
    second.close()


@pytest.mark.parametrize("mode", ["rw", "rwc"])
def test_independent_connection_cannot_write_authority_database(tmp_path, mode):
    store, authority, database_path, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    attacker = sqlite3.connect(
        f"file:{database_path}?mode={mode}", uri=True, timeout=0.05,
    )
    attacker.create_function(
        "khaos_verification_finalization_guard", 2, lambda *_: 1,
    )
    with pytest.raises(sqlite3.OperationalError, match="readonly|locked"):
        attacker.execute(
            "UPDATE plan_verification_runs SET status='passed' "
            "WHERE verification_run_id=?", (verification_run_id,),
        )
        attacker.commit()
    attacker.rollback()
    attacker.close()
    _assert_not_success(store, verification_run_id, execution_run_id)
    authority.close()


def test_writer_opened_before_authority_cannot_write_after_activation(tmp_path):
    store, verification_run_id, execution_run_id = _finalize_test_store(tmp_path)
    database_path = Path(
        store._conn.execute("PRAGMA database_list").fetchone()[2]
    )
    preopened = sqlite3.connect(database_path, timeout=0.05)
    authority = VERIFICATION_AUTHORITIES.issue(
        store._conn,
        runtime_id=f"runtime-{uuid.uuid4().hex}",
        boot_id=f"boot-{uuid.uuid4().hex}",
    )
    store.bind_write_authority(authority)

    with pytest.raises(sqlite3.OperationalError, match="locked"):
        preopened.execute(
            "UPDATE plan_verification_runs SET status='passed' "
            "WHERE verification_run_id=?", (verification_run_id,),
        )
        preopened.commit()
    preopened.rollback()
    preopened.close()
    _assert_not_success(store, verification_run_id, execution_run_id)
    authority.close()


def test_active_preopened_writer_makes_authority_start_fail_closed(tmp_path):
    store, _, _ = _finalize_test_store(tmp_path)
    database_path = Path(
        store._conn.execute("PRAGMA database_list").fetchone()[2]
    )
    attacker = sqlite3.connect(database_path, timeout=0.05)
    attacker.execute("BEGIN IMMEDIATE")
    attacker.execute(
        "UPDATE plan_verification_runs SET failure_code='attacker-active'"
    )
    try:
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            VERIFICATION_AUTHORITIES.issue(
                store._conn,
                runtime_id=f"runtime-{uuid.uuid4().hex}",
                boot_id=f"boot-{uuid.uuid4().hex}",
            )
    finally:
        attacker.rollback()
        attacker.close()


@pytest.mark.parametrize("attack_kind", [
    "drop-trigger", "writable-schema", "create-table", "attach",
])
def test_independent_connection_cannot_mutate_schema_or_attach(
    tmp_path, attack_kind,
):
    store, authority, database_path, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    attacker = sqlite3.connect(
        f"file:{database_path}?mode=rw", uri=True, timeout=0.05,
    )
    if attack_kind == "writable-schema":
        attacker.execute("PRAGMA writable_schema=ON")
        attack_sql = (
            "UPDATE sqlite_master SET sql='forged' "
            "WHERE name='plan_verification_runs'"
        )
    elif attack_kind == "attach":
        attached = tmp_path / "attached.sqlite"
        with pytest.raises(sqlite3.OperationalError, match="locked"):
            attacker.execute(f"ATTACH DATABASE '{attached}' AS forged")
        attacker.close()
        _assert_not_success(store, verification_run_id, execution_run_id)
        authority.close()
        return
    elif attack_kind == "drop-trigger":
        attack_sql = "DROP TRIGGER trg_verification_passed_guard"
    else:
        attack_sql = "CREATE TABLE forged(value TEXT)"
    with pytest.raises(sqlite3.OperationalError):
        attacker.execute(attack_sql)
        attacker.commit()
    attacker.rollback()
    attacker.close()
    _assert_not_success(store, verification_run_id, execution_run_id)
    authority.close()


def test_udf_spoof_and_forged_cleanup_proof_fail_in_real_subprocess(tmp_path):
    store, authority, database_path, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    script = """
import sqlite3,sys
p,vr,er=sys.argv[1:]
c=sqlite3.connect(f'file:{p}?mode=rw',uri=True,timeout=0.05)
c.create_function('khaos_verification_finalization_guard',2,lambda *_:1)
statements=[
 (\"INSERT INTO verification_cleanup_proofs VALUES ('fake',?, 'w','i',1,'[]','[]','[]','[]','c','d',1)\",(vr,)),
 (\"UPDATE plan_verification_runs SET status='passed' WHERE verification_run_id=?\",(vr,)),
 (\"UPDATE plan_execution_runs SET status='verified' WHERE execution_run_id=?\",(er,)),
 (\"DROP TRIGGER trg_verification_passed_guard\",()),
]
failed=0
for sql,args in statements:
 try:
  c.execute(sql,args);c.commit()
 except sqlite3.DatabaseError:
  c.rollback();failed+=1
print(failed)
sys.exit(0 if failed==len(statements) else 9)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(database_path),
         verification_run_id, execution_run_id],
        capture_output=True, text=True, timeout=10, check=False,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "4"
    _assert_not_success(store, verification_run_id, execution_run_id)
    authority.close()


def test_read_handle_exposes_only_fixed_read_queries(tmp_path):
    store, authority, _, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    reader = store.open_readonly()
    assert reader.verification_status(verification_run_id) == "finalizing"
    assert reader.execution_status(execution_run_id) == "verifying"
    assert not hasattr(reader, "execute")
    assert not hasattr(reader, "cursor")
    reader.close()
    authority.close()


def test_read_handle_rejects_forged_success_cache(tmp_path):
    store, authority, _, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-forged-cache",
    )
    store._conn.execute(
        "INSERT INTO verification_cleanup_proofs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("forged-cache-proof", proof.verification_run_id,
         proof.disposable_workspace_id, proof.disposable_workspace_identity,
         proof.disposable_cleaned_at,
         json.dumps(list(proof.sandbox_instance_ids)),
         json.dumps(list(proof.sandbox_absence_digests)),
         json.dumps(list(proof.artifact_ids)),
         json.dumps(list(proof.artifact_seal_digests)),
         proof.canonical_workspace_final_digest, proof.cleanup_digest,
         proof.created_at),
    )
    store._conn.execute(
        "UPDATE plan_verification_runs SET status='passed' "
        "WHERE verification_run_id=?", (verification_run_id,),
    )
    store._conn.execute(
        "UPDATE plan_execution_runs SET status='verified' "
        "WHERE execution_run_id=?", (execution_run_id,),
    )
    store._conn.commit()
    reader = store.open_readonly()
    with pytest.raises(PermissionError, match="lacks authority evidence"):
        reader.verification_status(verification_run_id)
    with pytest.raises(PermissionError, match="lacks authority evidence"):
        reader.execution_status(execution_run_id)
    reader.close()
    authority.close()


def test_direct_forged_cleanup_proof_is_not_authority_accepted(tmp_path):
    store, authority, _, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-forged",
    )
    store._conn.execute(
        "INSERT INTO verification_cleanup_proofs VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        ("attacker-proof", proof.verification_run_id,
         proof.disposable_workspace_id, proof.disposable_workspace_identity,
         proof.disposable_cleaned_at,
         json.dumps(list(proof.sandbox_instance_ids)),
         json.dumps(list(proof.sandbox_absence_digests)),
         json.dumps(list(proof.artifact_ids)),
         json.dumps(list(proof.artifact_seal_digests)),
         proof.canonical_workspace_final_digest, proof.cleanup_digest,
         proof.created_at),
    )
    store._conn.commit()
    with pytest.raises(PermissionError, match="not authority-issued"):
        store.finalize_success(
            step=None, verification_run_id=verification_run_id,
            execution_run_id=execution_run_id,
            workspace_id="dvw-forged", cleanup_proof=proof,
        )
    _assert_not_success(store, verification_run_id, execution_run_id)
    authority.close()


def test_schema_trigger_tamper_is_detected_before_trusted_read(tmp_path):
    store, authority, _, verification_run_id, _ = _authority_store(tmp_path)
    store._conn.execute("DROP TRIGGER trg_verification_passed_guard")
    store._conn.commit()
    with pytest.raises(PermissionError, match="schema/trigger digest drift"):
        store.get_run(verification_run_id)
    authority.close()


def test_authority_process_crash_rolls_back_cleanup_proof_insert(tmp_path):
    store, authority, _, verification_run_id, _ = _authority_store(tmp_path)
    authority._authority_process.terminate()
    authority._authority_process.join(timeout=5)
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-crash",
    )
    with pytest.raises(PermissionError, match="revoked"):
        store.persist_cleanup_proof(proof)
    assert store.get_cleanup_proof_for_run(verification_run_id) is None
    with pytest.raises(PermissionError, match="revoked"):
        authority.close()


@pytest.mark.parametrize("suffix", ["", "-wal"])
def test_database_and_sidecar_inode_replacement_fail_closed(tmp_path, suffix):
    store, authority, database_path, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    target = Path(f"{database_path}{suffix}")
    replacement = target.with_name(f"{target.name}.replacement")
    shutil.copyfile(target, replacement)
    replacement.chmod(0o400)
    os.replace(replacement, target)
    with pytest.raises(PermissionError, match="identity drift"):
        store.get_run(verification_run_id)
    assert (
        store._approval_store.get_execution_run(execution_run_id).status
        != ExecutionRunStatus.VERIFIED
    )


def test_unexpected_exclusive_mode_shm_sidecar_fails_closed(tmp_path):
    store, authority, database_path, verification_run_id, _ = _authority_store(tmp_path)
    if "-shm" not in authority._absent_objects:
        pytest.skip("SQLite build uses a pinned shm inode in exclusive mode")
    Path(f"{database_path}-shm").write_bytes(b"forged")
    with pytest.raises(PermissionError, match="unexpected sidecar"):
        store.get_run(verification_run_id)


def test_database_parent_symlink_swap_fails_closed(tmp_path):
    root = tmp_path / "authority-root"
    root.mkdir()
    store, authority, database_path, verification_run_id, _ = _authority_store(root)
    moved = root.with_name("authority-root-moved")
    root.rename(moved)
    root.symlink_to(moved, target_is_directory=True)
    with pytest.raises(PermissionError, match="parent directory replaced"):
        store.get_run(verification_run_id)


def test_database_parent_mode_drift_fails_closed(tmp_path):
    root = tmp_path / "authority-root"
    root.mkdir(mode=0o700)
    store, authority, _, verification_run_id, _ = _authority_store(root)
    expected_mode = authority._parent_identity.mode
    root.chmod(expected_mode ^ 0o040)
    try:
        with pytest.raises(PermissionError, match="parent identity drift"):
            store.get_run(verification_run_id)
    finally:
        root.chmod(expected_mode)
        authority.close()


def test_authority_finalize_records_trusted_success(tmp_path):
    store, authority, _, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-authority",
    )
    store.persist_cleanup_proof(proof)
    store.finalize_success(
        step=None, verification_run_id=verification_run_id,
        execution_run_id=execution_run_id,
        workspace_id="dvw-authority", cleanup_proof=proof,
    )
    assert store.get_run(verification_run_id).status == VerificationRunStatus.PASSED
    assert (
        store._approval_store.get_execution_run(execution_run_id).status
        == ExecutionRunStatus.VERIFIED
    )
    authority.close()


def test_new_boot_quarantines_unanchored_historical_success(tmp_path):
    store, authority, database_path, verification_run_id, execution_run_id = (
        _authority_store(tmp_path)
    )
    proof = _cleanup_proof(
        verification_run_id=verification_run_id,
        disposable_workspace_id="dvw-history",
    )
    store.persist_cleanup_proof(proof)
    store.finalize_success(
        step=None, verification_run_id=verification_run_id,
        execution_run_id=execution_run_id,
        workspace_id="dvw-history", cleanup_proof=proof,
    )
    authority.close()
    reopened = sqlite3.connect(database_path)
    reopened.row_factory = sqlite3.Row
    approval = store._approval_store.__class__(reopened)
    next_store = VerificationExecutionStore(approval)
    next_authority = VERIFICATION_AUTHORITIES.issue(
        reopened, runtime_id="runtime-b", boot_id="boot-b",
    )
    next_store.bind_write_authority(next_authority)
    assert next_store.get_run(verification_run_id).status == VerificationRunStatus.ERRORED
    assert (
        approval.get_execution_run(execution_run_id).status
        == ExecutionRunStatus.VERIFICATION_ERROR
    )
    next_authority.close()


def test_old_authority_rejects_after_shutdown(tmp_path):
    store, authority, _, verification_run_id, _ = _authority_store(tmp_path)
    authority.close()
    with pytest.raises(PermissionError, match="revoked"):
        store.get_run(verification_run_id)
