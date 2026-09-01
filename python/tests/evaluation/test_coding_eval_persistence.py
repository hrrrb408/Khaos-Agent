from __future__ import annotations

import pytest

from khaos.db import Database
from khaos.db.migrations._registry import (
    MIGRATIONS,
    compute_manifest_checksum,
    verify_source_integrity,
)


@pytest.mark.asyncio
async def test_m8_coding_ledger_migration_is_idempotent_and_append_only() -> None:
    database = Database(":memory:")
    await database.connect()
    try:
        await database.run_migrations()
        await database.run_migrations()

        async with database.read_connection() as connection:
            schema_version = await (
                await connection.execute(
                    "SELECT MAX(version) FROM schema_migrations"
                )
            ).fetchone()
            ledger = await (
                await connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'table' AND name = 'coding_evaluation_runs'"
                )
            ).fetchone()
            triggers = await (
                await connection.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type = 'trigger' AND "
                    "name LIKE 'trg_coding_evaluation_runs_immutable_%' "
                    "ORDER BY name"
                )
            ).fetchall()

        assert schema_version[0] == 27
        assert ledger is not None
        assert [row[0] for row in triggers] == [
            "trg_coding_evaluation_runs_immutable_delete",
            "trg_coding_evaluation_runs_immutable_update",
        ]
    finally:
        await database.close()


def test_m8_coding_ledger_migration_source_is_pinned() -> None:
    verify_source_integrity()
    migration = next(item for item in MIGRATIONS if item.version == 27)
    assert compute_manifest_checksum(migration) == migration.sha256
