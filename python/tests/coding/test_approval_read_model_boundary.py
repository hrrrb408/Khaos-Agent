"""Contract tests for the plan approval read-model boundary."""

import sqlite3

from khaos.coding.planning.approval.read_model import PlanApprovalReadModel
from khaos.coding.planning.approval.schema import APPROVAL_SCHEMA, upgrade_schema
from khaos.coding.planning.approval.store import PlanApprovalStore


class _ReadOnlyConnection:
    """Expose only the operations a read model is allowed to use."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def execute(self, *args, **kwargs):
        return self._connection.execute(*args, **kwargs)

    def commit(self) -> None:  # pragma: no cover - called only on a violation
        raise AssertionError("read model must not commit")

    def close(self) -> None:  # pragma: no cover - called only on a violation
        raise AssertionError("read model must not close its connection")


def _connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.executescript(APPROVAL_SCHEMA)
    upgrade_schema(connection)
    return connection


def test_read_model_owns_request_and_authorization_queries() -> None:
    connection = _connection()
    store = PlanApprovalStore(connection)
    read_model = store.approval_read_model
    assert isinstance(read_model, PlanApprovalReadModel)
    assert not hasattr(store, "get_request")
    assert not hasattr(store, "get_authorization")
    assert read_model.get_request("missing") is None
    assert read_model.get_authorization("missing") is None
    assert read_model.list_decisions("missing") == []
    assert read_model.list_audit_events() == []
    assert read_model.list_authorizations_for_plan("missing") == []
    assert read_model.list_registering_or_pending() == []
    assert read_model.list_requests_for_task("missing") == []
    assert read_model.find_request_by_plan_binding("missing", "digest") is None


def test_read_model_never_owns_connection_lifecycle_or_writes() -> None:
    connection = _connection()
    read_model = PlanApprovalReadModel(_ReadOnlyConnection(connection))

    assert read_model.get_request("missing") is None
    assert read_model.get_request_by_broker("missing") is None
    assert read_model.get_authorization("missing") is None
    assert read_model.list_decisions("missing") == []
    assert read_model.list_audit_events() == []
    assert read_model.list_authorizations_for_plan("missing") == []
    assert read_model.list_registering_or_pending() == []
    assert read_model.list_requests_for_task("missing") == []
    assert read_model.find_request_by_plan_binding("missing", "digest") is None
