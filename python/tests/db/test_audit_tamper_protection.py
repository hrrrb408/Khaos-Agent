"""Round-14 §4: audit_log tamper-evidence (hash chain + append-only triggers).

These tests pin the two defenses added against a compromised process
rewriting its own audit trail:

1. ``BEFORE DELETE`` / ``BEFORE UPDATE`` triggers abort any direct mutation.
2. A ``prev_hash`` hash chain makes tampering *detectable* even if the
   triggers are bypassed — :meth:`Database.verify_audit_chain` reports
   broken links.
"""

import sqlite3

import pytest

from khaos.db import Database


async def _fresh_db(tmp_path) -> Database:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1", mode="office")
    return db


@pytest.mark.asyncio
async def test_append_only_trigger_blocks_delete(tmp_path):
    db = await _fresh_db(tmp_path)
    rid = await db.insert_audit_log(
        "read_file", "/tmp/a", "success", "{}", "s1", principal_id="legacy"
    )
    await db.close()

    raw = sqlite3.connect(str(tmp_path / "khaos.db"))
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            raw.execute("DELETE FROM audit_log WHERE id=?", (rid,))
            raw.commit()
    finally:
        raw.close()


@pytest.mark.asyncio
async def test_append_only_trigger_blocks_update(tmp_path):
    db = await _fresh_db(tmp_path)
    rid = await db.insert_audit_log(
        "read_file", "/tmp/a", "success", "{}", "s1", principal_id="legacy"
    )
    await db.close()

    raw = sqlite3.connect(str(tmp_path / "khaos.db"))
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            raw.execute(
                "UPDATE audit_log SET result=? WHERE id=?", ("denied", rid)
            )
            raw.commit()
    finally:
        raw.close()


@pytest.mark.asyncio
async def test_hash_chain_links_rows(tmp_path):
    db = await _fresh_db(tmp_path)
    await db.insert_audit_log("a", "t1", "success", "{}", "s1", principal_id="legacy")
    await db.insert_audit_log("a", "t2", "success", "{}", "s1", principal_id="legacy")
    logs = await db.list_audit_logs()
    assert len(logs) == 2
    # Each row carries a non-empty hash; the second differs from the first
    # because its input includes the first row's hash.
    assert logs[0]["prev_hash"]
    assert logs[1]["prev_hash"]
    assert logs[0]["prev_hash"] != logs[1]["prev_hash"]
    await db.close()


@pytest.mark.asyncio
async def test_verify_audit_chain_reports_intact(tmp_path):
    db = await _fresh_db(tmp_path)
    for i in range(5):
        await db.insert_audit_log(
            "a", f"t{i}", "success", "{}", "s1", principal_id="legacy"
        )
    breaks = await db.verify_audit_chain()
    assert breaks == []
    await db.close()


@pytest.mark.asyncio
async def test_verify_audit_chain_detects_forged_row(tmp_path):
    """A row inserted outside :meth:`insert_audit_log` (so its prev_hash does
    not extend the chain) must be reported as a broken link."""
    db = await _fresh_db(tmp_path)
    await db.insert_audit_log("a", "t1", "success", "{}", "s1", principal_id="legacy")
    await db.insert_audit_log("a", "t2", "success", "{}", "s1", principal_id="legacy")
    await db.close()

    raw = sqlite3.connect(str(tmp_path / "khaos.db"))
    # Drop the append-only trigger to simulate an attacker who bypassed it,
    # then insert a forged row with a bogus prev_hash and restore the chain
    # shape so only the *content* mismatch is detected.
    raw.execute("DROP TRIGGER trg_audit_log_append_only_update")
    raw.execute("DROP TRIGGER trg_audit_log_append_only_delete")
    raw.execute(
        "INSERT INTO audit_log (action, target, result, detail, session_id, "
        "principal_id, project_id, prev_hash) VALUES "
        "('forged', 'x', 'success', '{}', 's1', 'legacy', '', 'bogus-hash')"
    )
    raw.commit()
    raw.close()

    db2 = Database(tmp_path / "khaos.db")
    await db2.connect()
    breaks = await db2.verify_audit_chain()
    assert len(breaks) == 1
    assert "broken" in breaks[0]["reason"]
    await db2.close()


@pytest.mark.asyncio
async def test_insert_reset_trigger_blocks_non_genesis_empty_prev_hash(tmp_path):
    """Round-15 A-2: the BEFORE INSERT trigger refuses a row whose
    ``prev_hash`` is empty unless the table is empty (the genesis row).
    A forged INSERT-reset that would hide prior tampering is aborted at the
    DB layer."""
    db = await _fresh_db(tmp_path)
    await db.insert_audit_log("a", "t1", "success", "{}", "s1", principal_id="legacy")
    await db.close()

    raw = sqlite3.connect(str(tmp_path / "khaos.db"))
    # Drop only the DELETE/UPDATE triggers (the INSERT guard must stay).
    raw.execute("DROP TRIGGER trg_audit_log_append_only_update")
    raw.execute("DROP TRIGGER trg_audit_log_append_only_delete")
    with pytest.raises(sqlite3.IntegrityError, match="genesis row"):
        raw.execute(
            "INSERT INTO audit_log (action, target, result, detail, session_id, "
            "principal_id, project_id, prev_hash) VALUES "
            "('forged-reset', 'x', 'success', '{}', 's1', 'legacy', '', '')"
        )
        raw.commit()
    raw.close()


@pytest.mark.asyncio
async def test_verify_chain_flags_non_genesis_empty_prev_as_break(tmp_path):
    """Round-15 A-2: defense-in-depth — even if an attacker bypasses the
    INSERT trigger, ``verify_audit_chain`` reports a non-genesis row with an
    empty ``prev_hash`` as a break (not a trusted reset)."""
    db = await _fresh_db(tmp_path)
    await db.insert_audit_log("a", "t1", "success", "{}", "s1", principal_id="legacy")
    await db.close()

    raw = sqlite3.connect(str(tmp_path / "khaos.db"))
    # Bypass ALL triggers to simulate a trigger-bypass attack, then INSERT a
    # forged reset row (the verifier must still catch it).
    raw.execute("DROP TRIGGER trg_audit_log_append_only_update")
    raw.execute("DROP TRIGGER trg_audit_log_append_only_delete")
    raw.execute("DROP TRIGGER trg_audit_log_genesis_guard")
    raw.execute(
        "INSERT INTO audit_log (action, target, result, detail, session_id, "
        "principal_id, project_id, prev_hash) VALUES "
        "('forged-reset', 'x', 'success', '{}', 's1', 'legacy', '', '')"
    )
    raw.commit()
    raw.close()

    db2 = Database(tmp_path / "khaos.db")
    await db2.connect()
    breaks = await db2.verify_audit_chain()
    assert len(breaks) == 1
    assert "non-genesis" in breaks[0]["reason"] or "empty" in breaks[0]["reason"]
    await db2.close()
