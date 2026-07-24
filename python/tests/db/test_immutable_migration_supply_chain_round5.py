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
from pathlib import Path
from unittest.mock import patch

import pytest

from khaos.db import Database
from khaos.db.database import (
    MIGRATION_REGISTRY,
    SCHEMA_MIGRATION_NAME,
    SCHEMA_MIGRATION_VERSION,
)
from khaos.db.migrations._registry import REGISTRY_BY_VERSION

# Batch 6.4: the ledger now carries one row per registered version.  Tests
# that previously asserted a single-row ledger assert this count instead.
_EXPECTED_LEDGER_ROWS = len(REGISTRY_BY_VERSION)


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
    """Batch 6.4 superseded the round-5 runtime-computation model.

    The registry checksum for the current version is now a HARDCODED
    release-time literal constant (review §10.1), and it must equal what
    ``compute_manifest_checksum`` re-derives from the *actual executed
    bytes* (the SQL files + migrator source — review §10.2), NOT a runtime
    hash of ``schema.sql`` (which was never executed).  This test asserts
    the new contract: the stored constant agrees with the manifest
    re-computation.  If it fails, either the registry constant drifted or
    a registered file was edited without bumping the version.
    """
    from khaos.db.migrations._registry import (
        REGISTRY_BY_VERSION,
        compute_manifest_checksum,
        is_historical,
    )

    spec = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    # Historical versions have no reproducible manifest; skip them.
    assert not is_historical(spec), (
        "the CURRENT version must carry a real manifest checksum, not "
        "the historical sentinel"
    )
    assert spec.sha256 == compute_manifest_checksum(spec), (
        "the hardcoded registry checksum for the current version does not "
        "match the manifest re-computation.  The registry is FROZEN — if a "
        "registered file legitimately changed, bump SCHEMA_MIGRATION_VERSION "
        "and add a NEW entry, do not edit the existing checksum."
    )


def test_h12_registry_entries_are_immutable_constants():
    """Every registry entry must be either a 64-char lowercase hex SHA-256
    digest (a real manifest checksum) or the documented historical sentinel
    (for pre-manifest versions verified by name only).  Paired with a
    non-empty name.  This is a structural invariant — the registry is a
    release-time artifact and must not contain placeholders or empty values."""
    from khaos.db.migrations._registry import HISTORICAL_ACCEPTED

    assert MIGRATION_REGISTRY, "MIGRATION_REGISTRY must not be empty"
    for version, (name, checksum) in MIGRATION_REGISTRY.items():
        assert isinstance(version, int) and version > 0
        assert isinstance(name, str) and name
        if checksum == HISTORICAL_ACCEPTED:
            # Documented carve-out: pre-manifest version, verified by name.
            continue
        assert isinstance(checksum, str) and len(checksum) == 64
        assert all(c in "0123456789abcdef" for c in checksum)


# ---------------------------------------------------------------------------
# H-12: tampering a historical (non-latest) registry entry is detected
# ---------------------------------------------------------------------------


async def test_h12_detects_tampered_historical_registry_entry(
    tmp_path
):
    """Batch 6.4 core guarantee: a tampered historical migration NAME is
    detected even when a newer version is the latest applied row.

    v1–v5 are registered as ``HISTORICAL_ACCEPTED`` — their checksums
    cannot be reproduced, so they are verified by NAME ONLY (review §10.5).
    This test tampers a historical version's NAME and confirms the verify
    loop catches it even though v6 is the latest applied row.  (The
    pre-H-12 bug only checked ``applied[-1]``, so this would have slipped
    through.)
    """
    db = Database(tmp_path / "h12_hist.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_writer_conn()
    # Tamper v3's name (v3 < v6 so the "newer than build" guard does not
    # trip).  v6 remains the latest applied row.
    await conn.execute(
        "UPDATE schema_migrations SET name = 'TAMPERED' WHERE version = 3"
    )
    await conn.commit()

    # The verify loop must catch the NAME mismatch on v3 even though v6
    # is the latest row.
    with pytest.raises(RuntimeError, match="name mismatch"):
        await db.run_migrations()
    await db.close()


async def test_h12_skips_unregistered_historical_versions(tmp_path):
    """Sanity check: a version NOT in the registry is skipped (not
    verified).  This is the forward-compat path — a database may carry an
    extra version unknown to this build."""
    db = Database(tmp_path / "h12_skip.db")
    await db.connect()
    await db.run_migrations()

    conn = await db._require_writer_conn()
    # Insert a fake version 0 (not in registry, and below the current
    # version so the "newer than build" guard does not trip) with an
    # obviously wrong checksum.  run_migrations() must NOT raise on it.
    await conn.execute(
        "INSERT INTO schema_migrations "
        "(version, name, checksum, applied_at, app_version) "
        "VALUES (0, 'pre_registry', 'definitely_not_a_sha256', "
        "datetime('now'), '0.0.1')",
    )
    await conn.commit()

    # Should not raise — version 0 is not in the registry, so it is skipped.
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

    # Verify the schema is complete and the ledger has the full chain.
    conn = await db2._require_conn()
    ledger_rows = await (
        await conn.execute(
            "SELECT version, name, checksum FROM schema_migrations "
            "ORDER BY version"
        )
    ).fetchall()
    # Batch 6.4: one row per registered version after recovery.
    assert len(ledger_rows) == _EXPECTED_LEDGER_ROWS
    assert ledger_rows[-1]["version"] == SCHEMA_MIGRATION_VERSION
    assert ledger_rows[-1]["name"] == SCHEMA_MIGRATION_NAME

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
    assert ledger["n"] == _EXPECTED_LEDGER_ROWS
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
    assert ledger["n"] == _EXPECTED_LEDGER_ROWS
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
    assert ledger["n"] == _EXPECTED_LEDGER_ROWS
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
