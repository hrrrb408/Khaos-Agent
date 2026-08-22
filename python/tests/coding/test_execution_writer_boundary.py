"""Contract tests for the planned-execution write boundary."""

import sqlite3

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


def test_store_exposes_one_execution_writer_and_journal_owner() -> None:
    store = PlanApprovalStore(_connection())
    assert isinstance(store.execution_writer, PlanExecutionWriter)
    assert isinstance(store.execution_journal_writer, PlanExecutionJournalWriter)
    assert not hasattr(store, "create_execution_run")
    assert not hasattr(store, "insert_edit_event")


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


def test_execution_writer_audit_hook_is_owned_by_writer() -> None:
    store = PlanApprovalStore(_connection())
    events: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def capture(*args: object, **kwargs: object) -> None:
        events.append((args, kwargs))

    store.execution_writer._audit_writer = capture
    store.execution_writer._audit_writer(
        "run", "writer-event", result="ok", correlation_id="correlation"
    )

    assert events == [
        (("run", "writer-event"), {"result": "ok", "correlation_id": "correlation"})
    ]
