"""Independent local anchor coverage for the SQLite audit chain."""

import json
import os
import sqlite3
from pathlib import Path

import pytest

import khaos.audit.logger as logger_module
from khaos.audit import AuditAnchorError, AuditLogger, resolve_safe_audit_anchor_path
from khaos.db import Database


async def _database(tmp_path: Path) -> Database:
    database = Database(tmp_path / "audit.db")
    await database.connect()
    await database.run_migrations()
    return database


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd,
    reason="platform has no dirfd-relative open/mkdir support",
)
async def test_audit_anchor_tracks_and_reopens_chain_head(tmp_path, monkeypatch):
    trusted = tmp_path / "home" / ".khaos" / "audit"
    trusted.parent.parent.mkdir(mode=0o700)
    monkeypatch.setattr(logger_module, "AUDIT_LOG_TRUSTED_DIR", trusted)
    database = await _database(tmp_path)
    anchor_path = resolve_safe_audit_anchor_path("project-a")
    audit = AuditLogger(
        database,
        anchor_path=anchor_path,
        project_id="project-a",
    )
    await audit.verify_anchor()
    assert await audit.log("one", "target", "success") == 1
    assert await audit.log("two", "target", "success") == 2
    audit.close()
    await database.close()

    anchor = json.loads(
        (trusted / anchor_path).read_text(encoding="utf-8").splitlines()[-1]
    )
    assert anchor["head_id"] == 2
    assert len(anchor["head_hash"]) == 64

    reopened = await _database(tmp_path)
    second = AuditLogger(
        reopened,
        anchor_path=anchor_path,
        project_id="project-a",
    )
    await second.verify_anchor()
    second.close()
    await reopened.close()


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd,
    reason="platform has no dirfd-relative open/mkdir support",
)
async def test_audit_anchor_detects_database_rollback(tmp_path, monkeypatch):
    trusted = tmp_path / "home" / ".khaos" / "audit"
    trusted.parent.parent.mkdir(mode=0o700)
    monkeypatch.setattr(logger_module, "AUDIT_LOG_TRUSTED_DIR", trusted)
    database = await _database(tmp_path)
    anchor_path = resolve_safe_audit_anchor_path("project-a")
    audit = AuditLogger(database, anchor_path=anchor_path, project_id="project-a")
    await audit.log("one", "target", "success")
    await audit.log("two", "target", "success")
    audit.close()
    await database.close()

    raw = sqlite3.connect(tmp_path / "audit.db")
    raw.execute("DROP TRIGGER IF EXISTS trg_audit_log_append_only_delete")
    raw.execute("DELETE FROM audit_log WHERE id = 2")
    raw.commit()
    raw.close()

    rolled_back = await _database(tmp_path)
    with pytest.raises(AuditAnchorError, match="rolled back|does not match"):
        broken = AuditLogger(
            rolled_back,
            anchor_path=anchor_path,
            project_id="project-a",
        )
        try:
            await broken.verify_anchor()
        finally:
            broken.close()
    await rolled_back.close()


@pytest.mark.skipif(
    os.open not in os.supports_dir_fd or os.mkdir not in os.supports_dir_fd,
    reason="platform has no dirfd-relative open/mkdir support",
)
async def test_audit_anchor_detects_anchor_tampering(tmp_path, monkeypatch):
    trusted = tmp_path / "home" / ".khaos" / "audit"
    trusted.parent.parent.mkdir(mode=0o700)
    monkeypatch.setattr(logger_module, "AUDIT_LOG_TRUSTED_DIR", trusted)
    database = await _database(tmp_path)
    anchor_path = resolve_safe_audit_anchor_path("project-a")
    audit = AuditLogger(database, anchor_path=anchor_path, project_id="project-a")
    await audit.log("one", "target", "success")
    audit.close()
    await database.close()

    anchor_file = trusted / anchor_path
    value = json.loads(anchor_file.read_text(encoding="utf-8").splitlines()[-1])
    value["head_hash"] = "0" * 64
    anchor_file.write_text(json.dumps(value), encoding="utf-8")

    tampered = await _database(tmp_path)
    with pytest.raises(AuditAnchorError, match="does not match"):
        broken = AuditLogger(
            tampered,
            anchor_path=anchor_path,
            project_id="project-a",
        )
        try:
            await broken.verify_anchor()
        finally:
            broken.close()
    await tampered.close()
