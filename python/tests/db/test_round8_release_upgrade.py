"""Round 8 upgrade proof using a database produced by main@19a2b538."""

from __future__ import annotations

import shutil
import sqlite3
from pathlib import Path

import pytest

from khaos.db.database import Database


OLD_V6_CHECKSUM = "7bd6cb4e51936c81d3c29ab9b8902f04203374d80d588732e97157b265de8038"


@pytest.mark.asyncio
async def test_real_main_19a2b538_database_upgrades_without_rewriting_provenance(
    tmp_path: Path,
) -> None:
    fixture = (
        Path(__file__).resolve().parents[1]
        / "fixtures/migrations/main-19a2b538-v6.db"
    )
    path = tmp_path / "upgraded.db"
    shutil.copyfile(fixture, path)

    db = Database(path)
    await db.connect()
    await db.run_migrations()
    await db.close()

    raw = sqlite3.connect(path)
    try:
        ledger = raw.execute(
            "SELECT version,name,checksum FROM schema_migrations ORDER BY version"
        ).fetchall()
        # Round-15 A-2: v9 (audit_log INSERT genesis guard) is now the chain tip.
        assert ledger[-1][0] == 9
        assert ledger[5] == (
            6,
            "round6_batch64_immutable_migration_chain",
            OLD_V6_CHECKSUM,
        )
        assert raw.execute(
            "SELECT mode,summary FROM sessions WHERE id='round8-session'"
        ).fetchone() == ("coding", "preserve me")
        assert raw.execute(
            "SELECT content FROM messages WHERE session_id='round8-session'"
        ).fetchone() == ("historic message",)
        assert raw.execute(
            "SELECT value FROM memories WHERE key='historic-key'"
        ).fetchone() == ("historic-value",)
        assert raw.execute(
            "SELECT status FROM coding_tasks WHERE id='round8-task'"
        ).fetchone() == ("completed",)
    finally:
        raw.close()
