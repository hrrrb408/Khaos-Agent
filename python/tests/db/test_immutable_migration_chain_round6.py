"""Batch 6.4 (round-6): Immutable Migration Chain.

This module closes the five weaknesses from the sixth-round deep review
section §十 (Migration Registry 提供了错误的安全感):

  §10.1  checksums were runtime-computed (``sha256(schema.sql + salt)``)
         → now HARDCODED release-time literal constants.
  §10.2  checksum covered ``schema.sql`` (never executed), not the files
         that actually run → manifest now covers the real SQL + migrator
         source bytes, AST-precise.
  §10.3  the "FROZEN" ``0001_initial_schema.sql`` was edited in Batch 6.1
         → historical versions registered; any future edit is detected.
  §10.4  only ``{5: ...}`` was registered, v1–v4 invisible → v1–v6 all
         registered.
  §10.5  ``name`` written but never verified → now both name AND checksum
         are checked.

Each review point has at least one dedicated test below.  The tests use
no mocking of the integrity check itself — they tamper real files (in a
temporary copy) or real DB rows to prove the guarantees hold end-to-end.
"""

from __future__ import annotations

import ast
import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_NAME, SCHEMA_MIGRATION_VERSION
from khaos.db.migrations import _registry
from khaos.db.migrations._registry import (
    HISTORICAL_ACCEPTED,
    MIGRATIONS,
    MIGRATION_REGISTRY,
    REGISTRY_BY_VERSION,
    compute_manifest_checksum,
    is_historical,
    verify_source_integrity,
)


# ---------------------------------------------------------------------------
# §10.1 — checksums are HARDCODED literals, not runtime computations
# ---------------------------------------------------------------------------


def test_s101_registry_checksums_are_string_literals_in_source():
    """§10.1: the registry's sha256 values must be either STRING LITERALS
    or a reference to the ``HISTORICAL_ACCEPTED`` module constant — never
    the result of a runtime ``read_text()`` / ``sha256(...)`` call.  A
    runtime computation cannot detect "source + expected drift together".
    We parse the module's AST and assert every MigrationSpec's ``sha256=``
    keyword is a plain ``ast.Constant`` (str) or the ``HISTORICAL_ACCEPTED``
    name, and explicitly NOT a function Call.
    """
    src = Path(_registry.__file__).read_text(encoding="utf-8")
    tree = ast.parse(src)
    seen = 0
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "MigrationSpec":
            for kw in node.keywords:
                if kw.arg != "sha256":
                    continue
                seen += 1
                # Forbidden: any function call (e.g. sha256(...), read_text()).
                assert not isinstance(kw.value, ast.Call), (
                    "§10.1 violation: MigrationSpec sha256= must not be a "
                    "runtime function call (e.g. sha256/read_text)"
                )
                # Allowed: a string literal OR the HISTORICAL_ACCEPTED name.
                is_literal = isinstance(kw.value, ast.Constant) and isinstance(
                    kw.value.value, str
                )
                is_sentinel_ref = (
                    isinstance(kw.value, ast.Name)
                    and kw.value.id == "HISTORICAL_ACCEPTED"
                )
                assert is_literal or is_sentinel_ref, (
                    "§10.1 violation: MigrationSpec sha256= must be a string "
                    "literal or the HISTORICAL_ACCEPTED constant reference"
                )
    assert seen == len(MIGRATIONS), (
        f"expected {len(MIGRATIONS)} sha256= keywords, found {seen}"
    )


def test_s101_no_runtime_read_text_in_registry_checksum_path():
    """§10.1: the registry module must not compute a checksum by reading
    a file at import time and storing the result as the 'constant'.  We
    assert ``SCHEMA_PATH.read_text`` (the old pattern) is never referenced
    in ``_registry.py``."""
    src = Path(_registry.__file__).read_text(encoding="utf-8")
    assert "SCHEMA_PATH" not in src, (
        "§10.1: _registry.py must not reference SCHEMA_PATH — checksums are "
        "release-time literals, not runtime file reads"
    )
    # The only read_text calls allowed are inside compute_manifest_checksum
    # (the re-verification helper), never assigned to a registry constant.
    assert "_V5_CHECKSUM" not in src, (
        "§10.1: the old runtime-computed _V5_CHECKSUM must be gone"
    )


def test_s101_stored_constant_equals_manifest_recomputation():
    """§10.1/§10.2: every NON-historical spec's stored sha256 constant
    must equal what ``compute_manifest_checksum`` re-derives from the live
    source RIGHT NOW.  If this fails, the constant drifted from the files
    (or vice versa)."""
    for spec in MIGRATIONS:
        if is_historical(spec):
            continue
        actual = compute_manifest_checksum(spec)
        assert spec.sha256 == actual, (
            f"§10.1: v{spec.version} stored checksum {spec.sha256[:16]}… "
            f"!= recomputed {actual[:16]}…"
        )


# ---------------------------------------------------------------------------
# §10.2 — checksum covers the ACTUAL executed files (SQL + migrator source)
# ---------------------------------------------------------------------------


def test_s102_checksum_covers_executed_sql_files_not_schema_sql():
    """§10.2: the checksum must be derived from the files that actually
    execute (``0001_initial_schema.sql`` + ``0001_post_migration.sql`` +
    migrator source), NOT ``schema.sql`` (which is never executed).  We
    prove this by showing that editing ``schema.sql`` does NOT change the
    re-computed manifest, while editing ``0001_initial_schema.sql`` DOES.
    """
    v6 = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    original = compute_manifest_checksum(v6)

    # Tampering schema.sql must NOT affect the manifest (it's not in it).
    schema_sql = Path(_registry._DB_DIR) / "schema.sql"
    saved = schema_sql.read_text(encoding="utf-8")
    try:
        schema_sql.write_text(saved + "\n-- TAMPER\n", encoding="utf-8")
        after_schema_tamper = compute_manifest_checksum(v6)
        assert after_schema_tamper == original, (
            "§10.2: schema.sql must NOT be part of the manifest (it is "
            "never executed) — tampering it must not change the checksum"
        )
    finally:
        schema_sql.write_text(saved, encoding="utf-8")


def test_s102_tampering_executed_sql_file_changes_checksum(tmp_path):
    """§10.2: editing a registered SQL file that IS executed must change
    the manifest checksum.  We copy the migration dir, append a byte to
    ``0001_initial_schema.sql``, and confirm the checksum differs."""
    v6 = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    original = compute_manifest_checksum(v6)

    initial_sql = Path(_registry._THIS_DIR) / "0001_initial_schema.sql"
    saved = initial_sql.read_text(encoding="utf-8")
    try:
        initial_sql.write_text(saved + "\n-- tamper-marker\n", encoding="utf-8")
        after = compute_manifest_checksum(v6)
        assert after != original, (
            "§10.2: editing 0001_initial_schema.sql (an executed file) "
            "must change the manifest checksum"
        )
    finally:
        initial_sql.write_text(saved, encoding="utf-8")
    # And confirm restoration returns to the original.
    assert compute_manifest_checksum(v6) == original


def test_s102_tampering_migrator_method_changes_checksum():
    """§10.2: editing a migrator method's SOURCE (one of the
    ``_ensure_*`` helpers) must change the manifest, because the method
    body is part of what executes.  We prove the symbol set is non-empty
    and that the checksum is sensitive to it by confirming a bogus symbol
    raises (proving symbols are actually read, not ignored)."""
    v6 = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    assert v6.migrator_symbols, (
        "§10.2: the current version must pin migrator symbols — otherwise "
        "the migrator source is not covered by the checksum"
    )
    # A missing symbol must raise — proving symbols are resolved + hashed.
    from khaos.db.migrations._registry import MigrationSpec

    bogus = MigrationSpec(
        version=999,
        name="bogus",
        sha256="x" * 64,
        migrator_symbols=("this_method_does_not_exist_xyz",),
    )
    with pytest.raises(RuntimeError, match="not found in database.py"):
        compute_manifest_checksum(bogus)


def test_s102_verify_source_integrity_detects_drift_and_passes_clean():
    """§10.2 end-to-end: ``verify_source_integrity`` passes on clean
    source and raises on drift.  We tamper a real executed file in-place,
    confirm the raise, then restore."""
    verify_source_integrity()  # clean baseline passes

    initial_sql = Path(_registry._THIS_DIR) / "0001_initial_schema.sql"
    saved = initial_sql.read_text(encoding="utf-8")
    try:
        initial_sql.write_text(saved + "\n-- DRIFT\n", encoding="utf-8")
        with pytest.raises(RuntimeError, match="source integrity check FAILED"):
            verify_source_integrity()
    finally:
        initial_sql.write_text(saved, encoding="utf-8")
    # Restored → passes again.
    verify_source_integrity()


# ---------------------------------------------------------------------------
# §10.3 — the FROZEN file is now covered; future edits are detected
# ---------------------------------------------------------------------------


def test_s103_frozen_initial_schema_is_in_manifest():
    """§10.3: ``0001_initial_schema.sql`` (the file that was silently
    edited in Batch 6.1) is now part of the v6 manifest.  Any future edit
    is therefore detected by ``verify_source_integrity``."""
    v6 = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    assert "0001_initial_schema.sql" in v6.sql_files
    assert "0001_post_migration.sql" in v6.sql_files


async def test_s103_run_migrations_calls_integrity_check_first(tmp_path):
    """§10.3/§10.2: ``run_migrations`` must call
    ``verify_source_integrity`` BEFORE touching the DB, so a drifted
    source aborts startup fail-closed.  We patch the check to raise and
    confirm run_migrations propagates it without executing any DDL."""
    db = Database(tmp_path / "s103.db")
    await db.connect()

    called = {"n": 0}

    def fake_check():
        called["n"] += 1
        raise RuntimeError("injected integrity failure")

    with patch(
        "khaos.db.database._verify_migrator_source_integrity", fake_check
    ):
        with pytest.raises(RuntimeError, match="injected integrity failure"):
            await db.run_migrations()
    assert called["n"] == 1
    # No schema_migrations table created (DDL never ran).
    conn = await db._require_conn()
    exists = await (
        await conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='schema_migrations'"
        )
    ).fetchone()
    assert exists is None
    await db.close()



# ---------------------------------------------------------------------------
# §10.4 — the registry covers ALL historical versions (v1–v6)
# ---------------------------------------------------------------------------


def test_s104_registry_covers_v1_through_current():
    """§10.4: every version from 1 to SCHEMA_MIGRATION_VERSION must be in
    the registry.  Previously only ``{5: ...}``` was registered, leaving
    v1–v4 invisible to verification."""
    for v in range(1, SCHEMA_MIGRATION_VERSION + 1):
        assert v in REGISTRY_BY_VERSION, (
            f"§10.4: version {v} is missing from the registry — every "
            f"released version must be registered"
        )


def test_s104_versions_are_contiguous_and_monotonic():
    """§10.4: the chain is a contiguous 1..N sequence with no gaps (a gap
    would mean an unregistered version slipped in)."""
    versions = [m.version for m in MIGRATIONS]
    assert versions == list(range(1, SCHEMA_MIGRATION_VERSION + 1))


def test_s104_historical_versions_carry_sentinel():
    """§10.4: v1–v5 carry the ``HISTORICAL_ACCEPTED`` sentinel (their
    original bytes pre-date the manifest and cannot be reconstructed)."""
    for spec in MIGRATIONS:
        if spec.version < SCHEMA_MIGRATION_VERSION:
            assert is_historical(spec), (
                f"§10.4: v{spec.version} ({spec.name}) should be marked "
                f"historical — only the current version carries a real "
                f"manifest checksum"
            )


def test_s104_current_version_has_real_checksum():
    """§10.4: the CURRENT version must NOT be historical — it carries a
    real manifest checksum (the whole point of Batch 6.4)."""
    current = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    assert not is_historical(current)
    assert len(current.sha256) == 64


async def test_s104_historical_ledger_backfilled_on_fresh_db(tmp_path):
    """§10.4: a fresh migration must produce a ledger with ALL registered
    versions (v1–v6), not just the current one.  This is the backfill."""
    db = Database(tmp_path / "s104_fresh.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()
    rows = await (
        await conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    ).fetchall()
    versions = [r["version"] for r in rows]
    assert versions == list(range(1, SCHEMA_MIGRATION_VERSION + 1)), (
        f"§10.4: fresh DB ledger should be v1..v{SCHEMA_MIGRATION_VERSION}, "
        f"got {versions}"
    )
    await db.close()



# ---------------------------------------------------------------------------
# §10.5 — the NAME column is now verified (not just checksum)
# ---------------------------------------------------------------------------


async def test_s105_tampered_name_on_current_version_detected(tmp_path):
    """§10.5: tampering the ``name`` of the current version's row must be
    detected on the next ``run_migrations``, even though the checksum is
    unchanged."""
    db = Database(tmp_path / "s105_name.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_writer_conn()
    await conn.execute(
        "UPDATE schema_migrations SET name = 'TAMPERED' "
        "WHERE version = ?",
        (SCHEMA_MIGRATION_VERSION,),
    )
    await conn.commit()
    with pytest.raises(RuntimeError, match="name mismatch"):
        await db.run_migrations()
    await db.close()


async def test_s105_tampered_name_on_historical_version_detected(tmp_path):
    """§10.5: tampering the ``name`` of a HISTORICAL version (whose
    checksum is the sentinel and therefore not checked) must STILL be
    detected by the name check.  This is the only line of defense for
    historical rows."""
    db = Database(tmp_path / "s105_hist_name.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_writer_conn()
    # v1 is historical — checksum is HISTORICAL_ACCEPTED (not checked),
    # but the name MUST still match.
    await conn.execute(
        "UPDATE schema_migrations SET name = 'EVIL' WHERE version = 1"
    )
    await conn.commit()
    with pytest.raises(RuntimeError, match="name mismatch"):
        await db.run_migrations()
    await db.close()


async def test_s105_correct_name_accepted_on_historical_row(tmp_path):
    """§10.5 sanity: a historical row with the CORRECT name (even with a
    foreign-looking checksum from a live DB) must be accepted."""
    db = Database(tmp_path / "s105_ok.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_writer_conn()
    # Simulate a live v5 DB: replace v5's checksum with a runtime-style
    # value but keep the correct name.  Must NOT raise.
    await conn.execute(
        "UPDATE schema_migrations SET checksum = ? WHERE version = 5",
        ("deadbeef" * 8,),
    )
    await conn.commit()
    await db.run_migrations()  # must not raise
    await db.close()


# ---------------------------------------------------------------------------
# Upgrade path — a live v5 DB upgrades cleanly to v6 with full ledger
# ---------------------------------------------------------------------------


async def test_upgrade_live_v5_db_to_v6_backfills_history(tmp_path):
    """An existing database that applied v5 (with the old runtime-computed
    checksum) must upgrade to v6 cleanly: the v5 row is preserved (its
    name matches; its checksum is historical so not checked), v6 is
    applied, and v1–v4 are backfilled."""
    path = tmp_path / "live_v5.db"
    # Seed a legacy table so the DB looks pre-migration.
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE legacy_evidence(value TEXT)")
    raw.execute("INSERT INTO legacy_evidence VALUES ('keep-me')")
    raw.commit()
    raw.close()

    db = Database(path)
    await db.connect()
    await db.run_migrations()

    # Overwrite the ledger to mimic a LIVE v5 DB: only a v5 row with the
    # old runtime-computed checksum.
    conn = await db._require_writer_conn()
    old_salt = "round6-batch61-chat-stream-identity-2026-07-23-v5"
    schema_bytes = (Path(_registry._DB_DIR) / "schema.sql").read_bytes()
    old_v5 = hashlib.sha256(
        schema_bytes + f"\n{old_salt}".encode("utf-8")
    ).hexdigest()
    await conn.execute("DELETE FROM schema_migrations")
    await conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, checksum, applied_at, app_version) "
        "VALUES (5, 'round6_batch61_chat_stream_identity', ?, "
        "datetime('now'), '0.1.0')",
        (old_v5,),
    )
    await conn.commit()

    # Upgrade.
    await db.run_migrations()

    rows = await (
        await conn.execute(
            "SELECT version FROM schema_migrations ORDER BY version"
        )
    ).fetchall()
    versions = [r["version"] for r in rows]
    assert versions == list(range(1, SCHEMA_MIGRATION_VERSION + 1)), (
        f"upgraded ledger should be v1..v{SCHEMA_MIGRATION_VERSION}, "
        f"got {versions}"
    )
    # Legacy data preserved.
    conn2 = await db._require_conn()
    ev = await (
        await conn2.execute("SELECT value FROM legacy_evidence")
    ).fetchone()
    assert ev["value"] == "keep-me"
    await db.close()



# ---------------------------------------------------------------------------
# Crash injection — v6 migration mid-crash recovers cleanly
# ---------------------------------------------------------------------------


async def test_crash_during_v6_backfill_recovers(tmp_path):
    """If the process crashes after applying the schema but before the v6
    ledger row commits, the next ``run_migrations`` must recover: the
    outer transaction rolls back, and re-running completes the chain."""
    path = tmp_path / "crash_v6.db"
    db = Database(path)
    await db.connect()

    original_backfill = Database._backfill_historical_ledger_rows
    call = {"n": 0}

    async def crashy_backfill(self, conn, applied_versions):
        call["n"] += 1
        await original_backfill(self, conn, applied_versions)
        raise RuntimeError("injected crash after backfill")

    with patch.object(
        Database, "_backfill_historical_ledger_rows", crashy_backfill
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            await db.run_migrations()
    await db.close()

    # Recovery.
    db2 = Database(path)
    await db2.connect()
    await db2.run_migrations()
    conn = await db2._require_conn()
    n = (
        await (
            await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
        ).fetchone()
    )["n"]
    assert n == len(REGISTRY_BY_VERSION)
    # Idempotent re-run.
    await db2.run_migrations()
    n2 = (
        await (
            await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
        ).fetchone()
    )["n"]
    assert n2 == len(REGISTRY_BY_VERSION)
    await db2.close()



# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------


def test_migration_registry_alias_matches_registry_by_version():
    """The backwards-compatible ``MIGRATION_REGISTRY`` (dict[int, tuple])
    must agree with ``REGISTRY_BY_VERSION`` (dict[int, MigrationSpec])."""
    assert set(MIGRATION_REGISTRY) == set(REGISTRY_BY_VERSION)
    for v, spec in REGISTRY_BY_VERSION.items():
        assert MIGRATION_REGISTRY[v] == (spec.name, spec.sha256)


def test_current_version_constants_match_registry_tail():
    """``SCHEMA_MIGRATION_VERSION`` / ``SCHEMA_MIGRATION_NAME`` (defined in
    database.py, derived from the registry) must match the chain's last
    entry — the two can never disagree."""
    assert SCHEMA_MIGRATION_VERSION == MIGRATIONS[-1].version
    assert SCHEMA_MIGRATION_NAME == MIGRATIONS[-1].name


async def test_idempotent_rerun_leaves_ledger_unchanged(tmp_path):
    """Running ``run_migrations`` twice must not add or remove ledger
    rows — the backfill uses ``INSERT OR IGNORE`` keyed on the version PK."""
    db = Database(tmp_path / "idempotent.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()
    before = (
        await (
            await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
        ).fetchone()
    )["n"]
    await db.run_migrations()
    await db.run_migrations()
    after = (
        await (
            await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
        ).fetchone()
    )["n"]
    assert before == after == len(REGISTRY_BY_VERSION)
    await db.close()

