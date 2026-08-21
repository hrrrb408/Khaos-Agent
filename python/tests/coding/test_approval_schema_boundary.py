"""Contract tests for the plan approval schema/migration owner."""

import sqlite3

import khaos.coding.planning.approval.store as approval_store
from khaos.coding.planning.approval.schema import (
    APPROVAL_SCHEMA,
    upgrade_schema,
)
from khaos.coding.planning.approval.store import (
    APPROVAL_SCHEMA as LEGACY_APPROVAL_SCHEMA,
)
from khaos.coding.planning.approval.store import (
    PlanApprovalStore,
)


def test_store_keeps_only_an_explicit_schema_compatibility_export() -> None:
    assert LEGACY_APPROVAL_SCHEMA is APPROVAL_SCHEMA
    assert not hasattr(approval_store, "_post_schema")


def test_schema_owner_is_idempotent_and_creates_all_authority_tables() -> None:
    connection = sqlite3.connect(":memory:")
    connection.executescript(APPROVAL_SCHEMA)
    upgrade_schema(connection)
    upgrade_schema(connection)

    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    assert {
        "plan_approval_requests",
        "plan_approval_receipts",
        "plan_execution_authorizations",
        "plan_execution_runs",
        "plan_execution_edit_events",
        "plan_execution_leases",
    } <= tables


def test_store_uses_schema_owner_during_initialization() -> None:
    store = PlanApprovalStore(sqlite3.connect(":memory:"))
    assert store._conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name='plan_snapshots'"
    ).fetchone() is not None
