import asyncio
import sqlite3

import pytest

from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_VERSION


async def test_migration_records_version_and_checksum(tmp_path):
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_conn()
    row = await (
        await conn.execute(
            "SELECT version, name, checksum, app_version "
            "FROM schema_migrations"
        )
    ).fetchone()
    assert row["version"] == SCHEMA_MIGRATION_VERSION
    assert row["name"] == "initial_versioned_schema"
    assert len(row["checksum"]) == 64
    assert row["app_version"]
    await db.close()


async def test_migration_rejects_unknown_future_version(tmp_path):
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()
    await conn.execute(
        "INSERT INTO schema_migrations VALUES "
        "(999, 'future', 'future', datetime('now'), '999')"
    )
    await conn.commit()

    with pytest.raises(RuntimeError, match="newer than this Khaos build"):
        await db.run_migrations()
    await db.close()


async def test_migration_rejects_checksum_drift(tmp_path):
    db = Database(tmp_path / "state.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()
    await conn.execute(
        "UPDATE schema_migrations SET checksum='tampered' WHERE version=?",
        (SCHEMA_MIGRATION_VERSION,),
    )
    await conn.commit()

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        await db.run_migrations()
    await db.close()


async def test_migration_failure_rolls_back_entire_schema(
    tmp_path, monkeypatch
):
    db = Database(tmp_path / "state.db")
    await db.connect()

    async def fail_mid_migration():
        conn = await db._require_conn()
        await conn.execute("CREATE TABLE must_rollback(value TEXT)")
        raise RuntimeError("injected migration crash")

    monkeypatch.setattr(
        db, "_ensure_messages_project_id_column", fail_mid_migration
    )
    with pytest.raises(RuntimeError, match="injected migration crash"):
        await db.run_migrations()

    conn = await db._require_conn()
    names = {
        row["name"]
        for row in await (
            await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        ).fetchall()
    }
    assert "must_rollback" not in names
    assert "sessions" not in names
    assert "schema_migrations" not in names
    await db.close()


async def test_concurrent_migration_startup_has_one_ledger_row(tmp_path):
    path = tmp_path / "state.db"
    first = Database(path)
    second = Database(path)
    await first.connect()
    await second.connect()

    await asyncio.gather(first.run_migrations(), second.run_migrations())

    conn = await first._require_conn()
    row = await (
        await conn.execute(
            "SELECT COUNT(*) AS n, MAX(version) AS version "
            "FROM schema_migrations"
        )
    ).fetchone()
    assert row["n"] == 1
    assert row["version"] == SCHEMA_MIGRATION_VERSION
    await first.close()
    await second.close()


async def test_legacy_database_is_backed_up_before_migration(tmp_path):
    path = tmp_path / "state.db"
    legacy = sqlite3.connect(path)
    legacy.execute("CREATE TABLE legacy_evidence(value TEXT)")
    legacy.execute("INSERT INTO legacy_evidence VALUES ('preserve-me')")
    legacy.commit()
    legacy.close()

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    await db.close()

    backup_path = tmp_path / "state.db.pre-migration-v1.bak"
    assert backup_path.is_file()
    backup = sqlite3.connect(backup_path)
    try:
        row = backup.execute("SELECT value FROM legacy_evidence").fetchone()
        assert row == ("preserve-me",)
        assert backup.execute(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type='table' AND name='schema_migrations'"
        ).fetchone() == (0,)
    finally:
        backup.close()
