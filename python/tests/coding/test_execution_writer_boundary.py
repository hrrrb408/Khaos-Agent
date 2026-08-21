"""Contract tests for the planned-execution write boundary."""

import sqlite3
from unittest.mock import Mock

from khaos.coding.planning.approval.execution_journal_writer import (
    PlanExecutionJournalWriter,
)
from khaos.coding.planning.approval.execution_read_model import PlanExecutionReadModel
from khaos.coding.planning.approval.execution_writer import PlanExecutionWriter
from khaos.coding.planning.approval.schema import APPROVAL_SCHEMA, upgrade_schema
from khaos.coding.planning.approval.store import PlanApprovalStore


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(APPROVAL_SCHEMA)
    upgrade_schema(connection)
    return connection


def _insert_run(connection: sqlite3.Connection, *, status: str = "mutating") -> None:
    connection.execute(
        """
        INSERT INTO plan_execution_runs (
            execution_run_id, plan_id, plan_content_hash, approval_request_id,
            authorization_id, execution_context_id, lease_id, task_id,
            workspace_id, repository_id, base_sha, repository_generation,
            binding_digest, edit_bundle_digest, status, started_at, updated_at,
            metadata_json
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            "run-1", "plan-1", "plan-hash", "request-1", "auth-1", "context-1",
            "lease-1", "task-1", "workspace-1", "repo-1", "base", 1,
            "binding", "bundle", status, 1.0, 1.0, "{}",
        ),
    )
    connection.commit()


def test_store_installs_one_execution_writer_and_delegates_compatibility_methods() -> None:
    store = PlanApprovalStore(_connection())
    assert isinstance(store._execution_writer, PlanExecutionWriter)
    assert isinstance(store._execution_journal_writer, PlanExecutionJournalWriter)
    writer = Mock()
    marker = object()
    writer.create_execution_run.return_value = marker
    writer.begin_or_resume_rollback.return_value = marker
    store._execution_writer = writer
    journal_writer = Mock()
    journal_writer.record_rollback_directory_synced.return_value = "digest"
    store._execution_journal_writer = journal_writer

    assert store.create_execution_run(marker) is marker
    store.transition_execution_run(
        "run", expected=("created",), target="validating", completed=False
    )
    assert store.begin_or_resume_rollback("run", failure_code="failure") is marker
    store.mark_execution_recovery_sealed("run", seal_digest="seal")
    store.mark_execution_rollback_sealed("run", seal_digest="rollback-seal")
    store.save_final_mutation_attestation(marker)
    store.save_initial_workspace_attestation(marker)
    store.save_rollback_final_attestation(marker)
    store.commit_terminal_seal(
        "run", expected_status="sealing", terminal_status="mutated",
        seal_digest="seal", tombstone_digest="tombstone", rollback=False,
    )
    store.commit_recovered_terminal_state(
        workspace_id="workspace", poison_owner="owner", execution_run_id="run",
        rollback=False, attestation_digest="attestation", expected_status="sealing",
        terminal_status="mutated", seal_digest="seal", tombstone_digest="tombstone",
    )
    store.commit_recovered_no_mutation(
        execution_run_id="run", workspace_id="workspace", poison_owner="owner",
        expected_status="validating", terminal_status="cancelled",
        baseline_digest="baseline",
    )
    store._insert_execution_audit(
        "run", "compatibility-audit", result="ok", correlation_id="correlation"
    )
    store.insert_edit_event(
        event_id="event", execution_run_id="run", edit_id="edit", ordinal=0,
        operation="write", path="file", destination_path=None, before_hash=None,
        before_mode=None, recovery_artifact=None,
    )
    store.transition_edit_event(
        "run", "edit", expected_phase="journaled", target_phase="mutation-started"
    )
    store.record_rollback_filesystem_applied(
        "run", "edit", rollback_identity_digest="identity",
        rollback_parent_identity_digest="parent",
        rollback_destination_parent_identity_digest="", rollback_sync_mask=1,
        error_code="failure",
    )
    assert store.record_rollback_directory_synced(
        "run", "edit", error_code="failure"
    ) == "digest"
    store.update_edit_event("run", "edit", status="applied")

    writer.create_execution_run.assert_called_once_with(marker)
    writer.transition_execution_run.assert_called_once_with(
        "run", expected=("created",), target="validating", failure_code="", completed=False
    )
    writer.begin_or_resume_rollback.assert_called_once_with(
        "run", failure_code="failure", now=None
    )
    writer.mark_execution_recovery_sealed.assert_called_once_with(
        "run", seal_digest="seal"
    )
    writer.mark_execution_rollback_sealed.assert_called_once_with(
        "run", seal_digest="rollback-seal"
    )
    writer.save_final_mutation_attestation.assert_called_once_with(marker)
    writer.save_initial_workspace_attestation.assert_called_once_with(marker)
    writer.save_rollback_final_attestation.assert_called_once_with(marker)
    writer.commit_terminal_seal.assert_called_once_with(
        "run", expected_status="sealing", terminal_status="mutated",
        seal_digest="seal", tombstone_digest="tombstone", rollback=False,
        failure_code="",
    )
    writer.commit_recovered_terminal_state.assert_called_once_with(
        workspace_id="workspace", poison_owner="owner", execution_run_id="run",
        rollback=False, attestation_digest="attestation", expected_status="sealing",
        terminal_status="mutated", seal_digest="seal", tombstone_digest="tombstone",
    )
    writer.commit_recovered_no_mutation.assert_called_once_with(
        execution_run_id="run", workspace_id="workspace", poison_owner="owner",
        expected_status="validating", terminal_status="cancelled",
        baseline_digest="baseline", failure_code="no-mutation-crash",
    )
    writer._insert_execution_audit.assert_called_once_with(
        "run", "compatibility-audit", operation="", path="", before_hash="",
        after_hash="", result="ok", error_code="", correlation_id="correlation",
    )
    journal_writer.insert_edit_event.assert_called_once_with(
        event_id="event", execution_run_id="run", edit_id="edit", ordinal=0,
        operation="write", path="file", destination_path=None, before_hash=None,
        before_mode=None, recovery_artifact=None, planned_after_hash="",
        planned_after_mode=None,
    )
    journal_writer.transition_edit_event.assert_called_once_with(
        "run", "edit", expected_phase="journaled", target_phase="mutation-started",
        after_hash=None, after_mode=None, error_code="",
        applied_identity_digest=None, applied_parent_identity_digest=None,
        applied_destination_identity_digest=None,
    )
    journal_writer.record_rollback_filesystem_applied.assert_called_once_with(
        "run", "edit", rollback_identity_digest="identity",
        rollback_parent_identity_digest="parent",
        rollback_destination_parent_identity_digest="", rollback_sync_mask=1,
        error_code="failure", expected_phase="rollback-started",
    )
    journal_writer.record_rollback_directory_synced.assert_called_once_with(
        "run", "edit", error_code="failure"
    )
    journal_writer.update_edit_event.assert_called_once_with(
        "run", "edit", status="applied", after_hash=None, after_mode=None,
        error_code="", applied_identity_digest=None,
        applied_parent_identity_digest=None,
        applied_destination_identity_digest=None,
    )


def test_execution_writer_owns_run_transition_and_keeps_connection_open() -> None:
    connection = _connection()
    _insert_run(connection)
    read_model = PlanExecutionReadModel(connection)
    writer = PlanExecutionWriter(connection, read_model)

    writer.transition_execution_run(
        "run-1", expected=("mutating",), target="sealing"
    )

    row = connection.execute(
        "SELECT status FROM plan_execution_runs WHERE execution_run_id='run-1'"
    ).fetchone()
    audit = connection.execute(
        "SELECT event_type,result FROM plan_execution_audit_events "
        "WHERE execution_run_id='run-1'"
    ).fetchone()
    assert row["status"] == "sealing"
    assert (audit["event_type"], audit["result"]) == ("run-transition", "sealing")
    assert connection.execute("SELECT 1").fetchone()[0] == 1


def test_execution_journal_writer_owns_journal_cas_and_keeps_connection_open() -> None:
    connection = _connection()
    _insert_run(connection)
    writer = PlanExecutionJournalWriter(connection)

    writer.insert_edit_event(
        event_id="event-1",
        execution_run_id="run-1",
        edit_id="edit-1",
        ordinal=0,
        operation="write",
        path="file.txt",
        destination_path=None,
        before_hash="before",
        before_mode=0o644,
        recovery_artifact="artifact",
    )
    writer.transition_edit_event(
        "run-1",
        "edit-1",
        expected_phase="journaled",
        target_phase="mutation-started",
    )

    row = connection.execute(
        "SELECT status,phase_version FROM plan_execution_edit_events "
        "WHERE execution_run_id='run-1' AND edit_id='edit-1'"
    ).fetchone()
    assert (row["status"], row["phase_version"]) == ("mutation-started", 1)
    assert connection.execute("SELECT 1").fetchone()[0] == 1


def test_store_audit_compatibility_hook_remains_dynamic_for_writer() -> None:
    store = PlanApprovalStore(_connection())
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args: object, **kwargs: object) -> None:
        events.append((args, kwargs))

    store._insert_execution_audit = capture  # type: ignore[method-assign]
    store._execution_writer._audit_writer(
        "run", "writer-event", result="ok", correlation_id="correlation"
    )

    assert events == [
        (("run", "writer-event"), {"result": "ok", "correlation_id": "correlation"})
    ]
