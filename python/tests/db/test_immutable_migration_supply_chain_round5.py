"""Round-5 Batch 5.5: Immutable Migration Registry + Supply Chain.

Covers:
  - H-12: Immutable Migration Registry — every applied row whose
    version is in ``MIGRATION_REGISTRY`` is verified on every
    startup, not just the latest version.  This catches a tampered
    historical migration that would previously go undetected once a
    newer version was applied.
  - Crash Injection: a migration interrupted mid-way (process crash /
    exception) must leave the DB in a state from which the next
    ``run_migrations()`` recovers cleanly and completes the schema.
  - Registry invariants: the registry covers the current schema
    version, checksums are 64-char SHA-256, and the constant matches
    what ``run_migrations()`` records.

The supply-chain CI workflow (``.github/workflows/supply-chain-audit.yml``)
and the Python lockfile (``python/requirements-lock.txt``) are verified
by separate CI jobs; this module covers the runtime invariants they
depend on.
"""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.db import Database
from khaos.db.database import (
    MIGRATION_REGISTRY,
    SCHEMA_MIGRATION_NAME,
    SCHEMA_MIGRATION_SALT,
    SCHEMA_MIGRATION_VERSION,
    SCHEMA_PATH,
)


# ---------------------------------------------------------------------------
# H-12: Immutable Migration Registry invariants
# ---------------------------------------------------------------------------


def test_h12_registry_covers_current_schema_version():
    """The registry MUST contain an entry for the current
    ``SCHEMA_MIGRATION_VERSION`` — otherwise the immutable-verify
    guarantee has a hole for the version that is actually applied
    today."""
    assert SCHEMA_MIGRATION_VERSION in MIGRATION_REGISTRY, (
        f"MIGRATION_REGISTRY is missing entry for current version "
        f"{SCHEMA_MIGRATION_VERSION} — every released migration "
        f"must be registered with a frozen checksum"
    )
    name, checksum = MIGRATION_REGISTRY[SCHEMA_MIGRATION_VERSION]
    assert name == SCHEMA_MIGRATION_NAME
    # SHA-256 hex digest
    assert len(checksum) == 64
    assert all(c in "0123456789abcdef" for c in checksum)


def test_h12_registry_checksum_matches_runtime_computation():
    """The frozen registry checksum for the current version MUST equal
    what ``run_migrations()`` computes at runtime from ``schema.sql`` +
    the salt.  If this fails, either the registry or the schema file
    drifted — both are release-time artifacts and must agree."""
    expected = hashlib.sha256(
        f"{SCHEMA_PATH.read_text(encoding='utf-8')}\n{SCHEMA_MIGRATION_SALT}".encode(
            "utf-8"
        )
    ).hexdigest()
    _, registry_checksum = MIGRATION_REGISTRY[SCHEMA_MIGRATION_VERSION]
    assert registry_checksum == expected, (
        "MIGRATION_REGISTRY checksum for the current version does not "
        "match the runtime computation from schema.sql + salt.  The "
        "registry is FROZEN — if schema.sql legitimately changed, "
        "you must bump SCHEMA_MIGRATION_VERSION and add a NEW entry, "
        "not edit the existing checksum."
    )


def test_h12_registry_entries_are_immutable_constants():
    """Every registry entry must be a 64-char lowercase hex SHA-256
    digest paired with a non-empty name.  This is a structural
    invariant — the registry is a release-time artifact and must not
    contain placeholders or empty values."""
    assert MIGRATION_REGISTRY, "MIGRATION_REGISTRY must not be empty"
    for version, (name, checksum) in MIGRATION_REGISTRY.items():
        assert isinstance(version, int) and version > 0
        assert isinstance(name, str) and name
        assert isinstance(checksum, str) and len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)


# ---------------------------------------------------------------------------
# H-12: tampering a historical (non-latest) registry entry is detected
# ---------------------------------------------------------------------------


async def test_h12_detects_tampered_historical_registry_entry(
    tmp_path, monkeypatch
):
    """H-12 core guarantee: a tampered historical migration is detected
    even when a newer version is the latest applied row.

    Pre-H-12, only ``applied[-1]`` was checked, so tampering an older
    version went undetected once a newer version was applied.  This
    test simulates that scenario by inserting a fake older version
    (v3 < v4) into ``schema_migrations`` with a wrong checksum, then
    temporarily registering v3 in ``MIGRATION_REGISTRY`` with the
    correct checksum.  The mismatch must be detected.
    """
    db = Database(tmp_path / "h12_hist.db")
    await db.connect()
    await db.run_migrations()

    # Insert a fake historical row v3 (v3 < v4 so the "newer than
    # build" guard does not trip).  v4 remains the latest applied row.
    conn = await db._require_writer_conn()
    tampered_checksum = "a" * 64  # wrong
    await conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, checksum, applied_at, app_version) "
        "VALUES (3, 'fake_v3', ?, datetime('now'), '0.0.3')",
        (tampered_checksum,),
    )
    await conn.commit()

    # Temporarily register v3 with a DIFFERENT (correct) checksum.
    # The H-12 verify loop must now catch the mismatch on v3 even
    # though v4 is the latest row.
    from khaos.db import database as db_module

    correct_checksum = "b" * 64
    monkeypatch.setitem(
        db_module.MIGRATION_REGISTRY,
        3,
        ("fake_v3", correct_checksum),
    )

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        await db.run_migrations()
    await db.close()


async def test_h12_skips_unregistered_historical_versions(tmp_path):
    """Sanity check: a historical version NOT in the registry is
    skipped (not verified).  This is the forward-compat path — old
    databases may have pre-registry versions that we cannot verify
    after the fact."""
    db = Database(tmp_path / "h12_skip.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_writer_conn()
    # Insert a fake v2 (not in registry) with an obviously wrong
    # checksum.  run_migrations() must NOT raise on this row.
    await conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, checksum, applied_at, app_version) "
        "VALUES (2, 'pre_registry', 'definitely_not_a_sha256', "
        "datetime('now'), '0.0.1')",
    )
    await conn.commit()

    # Should not raise — v2 is not in the registry, so it is skipped.
    await db.run_migrations()
    await db.close()


async def test_h12_tampered_latest_version_still_detected(tmp_path):
    """Regression: tampering the latest version (which IS in the
    registry) must still be detected.  This is the pre-H-12 behavior
    and must continue to work after the H-12 change."""
    db = Database(tmp_path / "h12_latest.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_writer_conn()
    await conn.execute(
        "UPDATE schema_migrations SET checksum='tampered' "
        "WHERE version=?",
        (SCHEMA_MIGRATION_VERSION,),
    )
    await conn.commit()

    with pytest.raises(RuntimeError, match="checksum mismatch"):
        await db.run_migrations()
    await db.close()


# ---------------------------------------------------------------------------
# Crash Injection: migration interrupted mid-way, recovery resumes cleanly
# ---------------------------------------------------------------------------


async def test_crash_injection_during_legacy_upgrades_recovers(tmp_path):
    """Crash injection: a migration that crashes mid-way (during
    ``_run_legacy_schema_upgrades``) must roll back the outer
    ``BEGIN IMMEDIATE`` transaction, and the next ``run_migrations()``
    on a fresh connection must complete the schema cleanly.

    This models a process crash (SIGKILL / OOM / power loss) during
    migration: SQLite's WAL + the wrapping transaction guarantee that
    no partial DDL survives, so recovery is idempotent.
    """
    db_path = tmp_path / "crash_legacy.db"

    # Phase 1: start migration, crash during _run_legacy_schema_upgrades.
    db = Database(db_path)
    await db.connect()

    original_upgrades = db._run_legacy_schema_upgrades

    async def crashy_upgrades() -> None:
        # Run the real upgrades first so we are genuinely mid-migration
        # when the crash happens.
        await original_upgrades()
        raise RuntimeError("injected crash mid-migration")

    with patch.object(db, "_run_legacy_schema_upgrades", crashy_upgrades):
        with pytest.raises(RuntimeError, match="injected crash mid-migration"):
            await db.run_migrations()
    await db.close()

    # Phase 2: reopen on a fresh connection and re-run migrations.
    # The crashed transaction must have rolled back, leaving no
    # schema_migrations row, so the migration re-runs from scratch.
    db2 = Database(db_path)
    await db2.connect()
    await db2.run_migrations()  # must NOT raise

    # Verify the schema is complete and the ledger has exactly one row.
    conn = await db2._require_conn()
    ledger_rows = await (
        await conn.execute(
            "SELECT version, name, checksum FROM schema_migrations "
            "ORDER BY version"
        )
    ).fetchall()
    assert len(ledger_rows) == 1
    assert ledger_rows[0]["version"] == SCHEMA_MIGRATION_VERSION
    assert ledger_rows[0]["name"] == SCHEMA_MIGRATION_NAME

    # Spot-check that key tables exist (migration completed).
    table_names = {
        row["name"]
        for row in await (
            await conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%'"
            )
        ).fetchall()
    }
    for required in ("sessions", "messages", "memories", "schema_migrations"):
        assert required in table_names, (
            f"recovery migration did not create table {required!r}"
        )
    await db2.close()


async def test_crash_injection_during_initial_schema_recovers(tmp_path):
    """Crash injection: a migration that crashes during the initial
    ``CREATE TABLE`` phase (before any ``_ensure_*`` helper runs) must
    also recover cleanly.

    This is the earliest possible crash point — no DDL has committed
    yet, so the next run_migrations() starts from an empty schema.
    """
    db_path = tmp_path / "crash_initial.db"

    db = Database(db_path)
    await db.connect()

    # ``_execute_schema_statements`` is a @staticmethod, so it is
    # accessed as a plain function (no __func__).
    original_execute = Database._execute_schema_statements
    call_count = {"n": 0}

    async def crashy_execute(conn, script: str) -> None:
        call_count["n"] += 1
        # First call is the initial schema (CREATE TABLE).  Crash
        # before any DDL runs to simulate a mid-script crash at the
        # earliest possible point.
        if call_count["n"] == 1:
            raise RuntimeError("injected crash during initial schema")
        # Subsequent calls (post-migration indexes) run normally.
        await original_execute(conn, script)

    # Wrap in staticmethod because the original is a @staticmethod —
    # otherwise the descriptor protocol binds ``self`` and the call
    # signature breaks.
    with patch.object(
        Database,
        "_execute_schema_statements",
        staticmethod(crashy_execute),
    ):
        with pytest.raises(
            RuntimeError, match="injected crash during initial schema"
        ):
            await db.run_migrations()
    await db.close()

    # Recovery: reopen and re-run.
    db2 = Database(db_path)
    await db2.connect()
    await db2.run_migrations()

    conn = await db2._require_conn()
    ledger = await (
        await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
    ).fetchone()
    assert ledger["n"] == 1
    await db2.close()


async def test_crash_injection_then_idempotent_rerun(tmp_path):
    """After a crash + recovery, a third ``run_migrations()`` must be
    a no-op (idempotent).  This proves the recovery left the ledger
    in a consistent state — not partially applied."""
    db_path = tmp_path / "crash_idempotent.db"

    # Phase 1: crash mid-migration.
    db = Database(db_path)
    await db.connect()

    async def crash_mid_upgrade() -> None:
        raise RuntimeError("injected crash")

    with patch.object(
        db, "_run_legacy_schema_upgrades", crash_mid_upgrade
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            await db.run_migrations()
    await db.close()

    # Phase 2: recover.
    db2 = Database(db_path)
    await db2.connect()
    await db2.run_migrations()

    # Phase 3: re-run must be a no-op (no exception, no new ledger row).
    await db2.run_migrations()
    conn = await db2._require_conn()
    ledger = await (
        await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
    ).fetchone()
    assert ledger["n"] == 1
    await db2.close()


async def test_crash_injection_concurrent_recovery_safe(tmp_path):
    """Concurrent recovery: two processes opening the same crashed
    DB and both calling ``run_migrations()`` must converge on exactly
    one ledger row (the second caller sees the schema is already
    applied and returns early).

    This models a deployment where the agent is restarted and two
    workers race to recover the DB.
    """
    db_path = tmp_path / "crash_concurrent.db"

    # Phase 1: crash mid-migration on a single connection.
    db = Database(db_path)
    await db.connect()

    async def crash_mid_upgrade() -> None:
        raise RuntimeError("injected crash")

    with patch.object(
        db, "_run_legacy_schema_upgrades", crash_mid_upgrade
    ):
        with pytest.raises(RuntimeError, match="injected crash"):
            await db.run_migrations()
    await db.close()

    # Phase 2: two fresh connections both try to recover.
    db_a = Database(db_path)
    db_b = Database(db_path)
    await db_a.connect()
    await db_b.connect()

    await asyncio.gather(db_a.run_migrations(), db_b.run_migrations())

    # Exactly one ledger row, regardless of who won the race.
    conn = await db_a._require_conn()
    ledger = await (
        await conn.execute("SELECT COUNT(*) AS n FROM schema_migrations")
    ).fetchone()
    assert ledger["n"] == 1
    await db_a.close()
    await db_b.close()


# ---------------------------------------------------------------------------
# Supply-chain artifacts: structural sanity (CI runs the actual scanners)
# ---------------------------------------------------------------------------


def test_python_lockfile_exists_and_is_non_empty():
    """The Python dependency lockfile must exist and contain at least
    the core runtime dependencies.  The supply-chain CI job
    (``pip-audit``) scans this file — if it is missing or empty, the
    job has nothing to audit."""
    lockfile = (
        Path(__file__).resolve().parents[2]
        / "requirements-lock.txt"
    )
    assert lockfile.is_file(), (
        "python/requirements-lock.txt is missing — supply-chain CI "
        "job has nothing to scan"
    )
    content = lockfile.read_text(encoding="utf-8")
    # Must pin at least the core runtime deps from pyproject.toml.
    for required_dep in (
        "aiosqlite==",
        "httpx==",
        "cryptography==",
        "PyYAML==",
        "google-re2==",
    ):
        assert required_dep in content, (
            f"requirements-lock.txt is missing pinned {required_dep!r}"
        )


def test_supply_chain_workflow_exists():
    """The supply-chain audit workflow file must exist and define all
    three language-layer audit jobs."""
    workflow = (
        Path(__file__).resolve().parents[3]
        / ".github"
        / "workflows"
        / "supply-chain-audit.yml"
    )
    assert workflow.is_file(), (
        ".github/workflows/supply-chain-audit.yml is missing"
    )
    content = workflow.read_text(encoding="utf-8")
    for required_job in ("pip-audit", "cargo-audit", "govulncheck"):
        assert required_job in content, (
            f"supply-chain-audit.yml is missing the {required_job} job"
        )
