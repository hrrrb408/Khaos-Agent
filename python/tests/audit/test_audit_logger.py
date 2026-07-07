"""Tests for AuditLogger and Database.query_audit_logs."""

from __future__ import annotations

from khaos.audit import AuditLogger
from khaos.db import Database


async def _db(tmp_path):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    return db


async def test_log_and_query_roundtrip(tmp_path):
    db = await _db(tmp_path)
    await db.create_session("s1")
    audit = AuditLogger(db)

    row_id = await audit.log("write_file", "/tmp/x", "success", {"size": 42}, session_id="s1")
    entries = await audit.query()

    assert row_id > 0
    assert len(entries) == 1
    entry = entries[0]
    assert entry.action == "write_file"
    assert entry.target == "/tmp/x"
    assert entry.result == "success"
    assert entry.detail == {"size": 42}
    assert entry.session_id == "s1"
    await db.close()


async def test_query_filters_by_action(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    await audit.log("write_file", "/a", "success")
    await audit.log("terminal", "ls", "success")
    await audit.log("terminal", "rm", "error", {"err": "nope"})

    entries = await audit.query(action="terminal")

    assert [e.action for e in entries] == ["terminal", "terminal"]
    await db.close()


async def test_query_filters_by_result(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    await audit.log("terminal", "ok", "success")
    await audit.log("terminal", "bad", "error")

    denied = await audit.query(result="error")

    assert len(denied) == 1
    assert denied[0].target == "bad"
    await db.close()


async def test_query_returns_newest_first(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    await audit.log("a", "t1", "success")
    await audit.log("a", "t2", "success")
    await audit.log("a", "t3", "success")

    entries = await audit.query()

    # Newest first -> t3, t2, t1.
    assert [e.target for e in entries] == ["t3", "t2", "t1"]
    await db.close()


async def test_log_permission_and_tool_helpers(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)

    await audit.log_permission("terminal", "rm -rf /", approved=False, reason="dangerous")
    await audit.log_tool("read_file", "/etc/hosts", success=True, duration_ms=12)

    denied = await audit.query(result="denied")
    ok = await audit.query(result="success")

    assert len(denied) == 1
    assert denied[0].detail["reason"] == "dangerous"
    assert ok[0].detail["duration_ms"] == 12
    await db.close()


async def test_query_respects_limit(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    for i in range(5):
        await audit.log("a", f"t{i}", "success")

    entries = await audit.query(limit=2)

    assert len(entries) == 2
    # Limit returns the newest 2.
    assert entries[0].target == "t4"
    await db.close()


async def test_query_time_range(tmp_path):
    db = await _db(tmp_path)
    audit = AuditLogger(db)
    await audit.log("a", "old", "success")
    await audit.log("a", "new", "success")

    # since in the future returns nothing; since far in the past returns all.
    future = "2999-01-01 00:00:00"
    past = "2000-01-01 00:00:00"

    assert await audit.query(since=future) == []
    assert len(await audit.query(since=past, limit=10)) == 2
    await db.close()


async def test_log_failure_does_not_raise(tmp_path):
    """A write failure must not propagate (audit is best-effort)."""
    db = await _db(tmp_path)

    class BoomDB:
        async def insert_audit_log(self, **kwargs):
            raise RuntimeError("db is down")

    audit = AuditLogger(BoomDB())

    row_id = await audit.log("a", "t", "success")  # must not raise

    assert row_id == -1
    await db.close()
