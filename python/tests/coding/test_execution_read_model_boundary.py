"""Contract tests for the planned-execution read-model boundary."""

import sqlite3

import pytest

from khaos.coding.planning.approval.execution_read_model import PlanExecutionReadModel
from khaos.coding.planning.approval.schema import APPROVAL_SCHEMA, upgrade_schema
from khaos.coding.planning.approval.store import PlanApprovalStore


class _ReadOnlyConnection:
    """Expose only the operations a read model is allowed to use."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def commit(self) -> None:  # pragma: no cover - called only on violation
        raise AssertionError("read model must not commit")

    def rollback(self) -> None:  # pragma: no cover - called only on violation
        raise AssertionError("read model must not roll back")

    def close(self) -> None:  # pragma: no cover - called only on violation
        raise AssertionError("read model must not close its connection")


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


def test_store_exposes_dedicated_execution_read_owner_without_delegates() -> None:
    connection = _connection()
    store = PlanApprovalStore(connection)

    read_model = store.execution_read_model
    assert isinstance(read_model, PlanExecutionReadModel)
    assert not hasattr(store, "get_execution_run")
    assert not hasattr(store, "create_execution_run")
    assert read_model.get_execution_run_by_context("missing") is None
    assert read_model.get_execution_run("missing") is None
    assert read_model.list_incomplete_execution_runs() == ()
    assert read_model.list_execution_edit_events("missing") == ()
    with pytest.raises(RuntimeError, match="execution run not found"):
        read_model.execution_journal_progress("missing")
    assert read_model.get_initial_workspace_attestation("missing") is None
    assert read_model.get_final_mutation_attestation("missing") is None
    assert read_model.get_rollback_final_attestation("missing") is None


def test_execution_read_model_never_owns_lifecycle_or_writes() -> None:
    connection = _connection()
    read_model = PlanExecutionReadModel(_ReadOnlyConnection(connection))

    assert read_model.get_execution_run("missing") is None
    assert read_model.list_incomplete_execution_runs() == ()
    assert read_model.list_execution_edit_events("missing") == ()
    with pytest.raises(RuntimeError, match="execution run not found"):
        read_model.execution_journal_progress("missing")
    assert read_model.get_initial_workspace_attestation("missing") is None
    assert read_model.get_final_mutation_attestation("missing") is None
    assert read_model.get_rollback_final_attestation("missing") is None


def test_verified_execution_read_requires_authority_when_configured() -> None:
    connection = _connection()
    _insert_run(connection, status="verified")
    read_model = PlanExecutionReadModel(connection)

    with pytest.raises(PermissionError, match="without authority"):
        read_model.get_execution_run(
            "run-1", authoritative_verification_reads_required=True
        )

    verified_ids: list[str] = []
    execution = read_model.get_execution_run(
        "run-1",
        verification_success_verifier=verified_ids.append,
        authoritative_verification_reads_required=True,
    )
    assert execution is not None
    assert verified_ids == ["run-1"]
