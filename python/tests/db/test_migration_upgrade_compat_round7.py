"""Batch 7.1 (round-7): Migration Upgrade Compatibility.

Closes review §五 / §十六 (Critical): the Batch 6.4 registry used wrong
canonical names for v1–v4, so a live database produced by a real release
commit would ``RuntimeError("name mismatch")`` on upgrade — i.e. current
main could not start a user's existing database.

The real release names (confirmed via git history of ``SCHEMA_MIGRATION_NAME``
on origin/main) are:

  v1 = initial_versioned_schema            (commit f4432c4)
  v2 = f02_memory_project_unique            (commit 4458da4)
  v3 = round5_chat_stream_state_machine     (commit d87347d)
  v4 = round5_batch53_owner_context_closure (commit 39a3a97)
  v5 = round6_batch61_chat_stream_identity  (commit 11d947a)

Batch 6.4 wrote DIFFERENT (wrong) names for v1–v4 in the registry, and its
synthetic-backfill ledger rows used those wrong names.  This module proves:

  1. A DB carrying ANY real release name upgrades cleanly to current.
  2. A DB carrying the Batch-6.4 wrong (synthetic) name ALSO upgrades
     (the ``accepted_historical_names`` alias accepts it — no data loss).
  3. The synthetic-backfill rows are marked ``app_version='synthetic-backfill'``
     so they are distinguishable from real release rows (review §十九).
  4. Tampered/unknown names are still rejected (the alias set is closed).
"""

from __future__ import annotations

import sqlite3

import pytest

from khaos.db import Database
from khaos.db.database import SCHEMA_MIGRATION_VERSION
from khaos.db.migrations._registry import MIGRATIONS, REGISTRY_BY_VERSION


# The real release names, keyed by version.  Source: git history of
# ``SCHEMA_MIGRATION_NAME`` on origin/main (see the Batch 7.1 commit msg).
REAL_RELEASE_NAMES = {
    1: "initial_versioned_schema",
    2: "f02_memory_project_unique",
    3: "round5_chat_stream_state_machine",
    4: "round5_batch53_owner_context_closure",
    5: "round6_batch61_chat_stream_identity",
}

# The WRONG names Batch 6.4 used for synthetic backfill of v1–v4.
BATCH64_WRONG_NAMES = {
    1: "initial_schema_v1",
    2: "memories_project_unique_f03",
    3: "principal_modes_project_pk_intermediate",
    4: "principal_modes_project_id_pk_h09",
}


def _seed_legacy_db(path, version: int, name: str) -> None:
    """Create a DB that looks like it was produced by the release that
    wrote ``schema_migrations(version, name, ...)`` — a legacy table +
    the ledger row.  This models a real user database at upgrade time."""
    raw = sqlite3.connect(path)
    raw.execute("CREATE TABLE legacy_evidence(value TEXT)")
    raw.execute("INSERT INTO legacy_evidence VALUES ('preserve-me')")
    raw.execute(
        "CREATE TABLE schema_migrations ("
        "version INTEGER PRIMARY KEY, name TEXT NOT NULL, "
        "checksum TEXT NOT NULL, applied_at TEXT NOT NULL, "
        "app_version TEXT NOT NULL)"
    )
    raw.execute(
        "INSERT INTO schema_migrations VALUES (?, ?, 'legacy-checksum', "
        "datetime('now'), '0.1.0')",
        (version, name),
    )
    raw.commit()
    raw.close()


# ---------------------------------------------------------------------------
# Critical fix: every REAL release name upgrades cleanly
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version,real_name", sorted(REAL_RELEASE_NAMES.items()))
async def test_s5_real_release_name_upgrades_cleanly(tmp_path, version, real_name):
    """§五/§十六 core fix: a DB carrying the real release name for
    ``version`` must upgrade to current WITHOUT a name-mismatch error.

    Pre-Batch-7.1 this failed for v1–v4 because the registry's canonical
    name differed from the release name.  Now the canonical name IS the
    release name, so this passes directly.
    """
    path = tmp_path / f"real_v{version}.db"
    _seed_legacy_db(str(path), version, real_name)
    db = Database(path)
    await db.connect()
    await db.run_migrations()  # must NOT raise
    conn = await db._require_conn()
    # Upgraded to current, ledger complete.
    max_v = (
        await (await conn.execute("SELECT MAX(version) AS v FROM schema_migrations")).fetchone()
    )["v"]
    assert max_v == SCHEMA_MIGRATION_VERSION
    # The original release row is preserved with its real name + app_version.
    orig = await (
        await conn.execute(
            "SELECT name, app_version FROM schema_migrations WHERE version=?",
            (version,),
        )
    ).fetchone()
    assert orig["name"] == real_name
    assert orig["app_version"] == "0.1.0", (
        "the real release row must keep its own app_version, not be "
        "overwritten with synthetic-backfill"
    )
    # Legacy data preserved.
    ev = (await (await conn.execute("SELECT value FROM legacy_evidence")).fetchone())[0]
    assert ev == "preserve-me"
    await db.close()


# ---------------------------------------------------------------------------
# No data loss: Batch-6.4 synthetic-backfill (wrong-name) DBs also upgrade
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("version,wrong_name", sorted(BATCH64_WRONG_NAMES.items()))
async def test_s5_batch64_wrong_synthetic_name_still_upgrades(
    tmp_path, version, wrong_name
):
    """Defense-in-depth: a DB that received Batch 6.4's synthetic backfill
    (which used the wrong canonical names) must STILL upgrade — the
    ``accepted_historical_names`` alias accepts the old wrong name so no
    user is locked out by the fix."""
    path = tmp_path / f"synthetic_v{version}.db"
    _seed_legacy_db(str(path), version, wrong_name)
    db = Database(path)
    await db.connect()
    await db.run_migrations()  # must NOT raise — alias accepts wrong name
    conn = await db._require_conn()
    max_v = (
        await (await conn.execute("SELECT MAX(version) AS v FROM schema_migrations")).fetchone()
    )["v"]
    assert max_v == SCHEMA_MIGRATION_VERSION
    await db.close()


# ---------------------------------------------------------------------------
# §十九: synthetic backfill rows are marked honestly
# ---------------------------------------------------------------------------


async def test_s19_synthetic_backfill_rows_marked_distinctly(tmp_path):
    """§十九: when a fresh DB is migrated, the v1–v5 ledger rows inserted
    by ``_backfill_historical_ledger_rows`` must carry
    ``app_version='synthetic-backfill'`` so an audit can tell them apart
    from rows a real release actually wrote.  The CURRENT version's row
    keeps the real app_version."""
    db = Database(tmp_path / "fresh.db")
    await db.connect()
    await db.run_migrations()
    conn = await db._require_conn()
    rows = await (
        await conn.execute(
            "SELECT version, app_version FROM schema_migrations ORDER BY version"
        )
    ).fetchall()
    for r in rows:
        if r["version"] < SCHEMA_MIGRATION_VERSION:
            assert r["app_version"] == "synthetic-backfill", (
                f"v{r['version']} backfill row must be marked "
                f"synthetic-backfill, got {r['app_version']!r}"
            )
        else:
            # The current version's row is real (written by run_migrations).
            assert r["app_version"] != "synthetic-backfill", (
                f"current version v{r['version']} must NOT be marked synthetic"
            )
    await db.close()


# ---------------------------------------------------------------------------
# Tamper detection still works (alias set is closed)
# ---------------------------------------------------------------------------


async def test_s5_unknown_name_still_rejected(tmp_path):
    """The alias set is CLOSED — a name that is neither canonical nor in
    ``accepted_historical_names`` is still rejected (tamper detection)."""
    path = tmp_path / "tampered.db"
    _seed_legacy_db(str(path), 4, "totally-fabricated-name")
    db = Database(path)
    await db.connect()
    with pytest.raises(RuntimeError, match="name mismatch"):
        await db.run_migrations()
    await db.close()


# ---------------------------------------------------------------------------
# Registry structure: canonical names match real release names
# ---------------------------------------------------------------------------


def test_s5_registry_canonical_names_match_real_release():
    """The registry's canonical ``name`` for each historical version must
    equal the real release name (so new backfill writes the correct one).
    This is a structural guard against re-introducing the Batch-6.4 bug."""
    for version, real_name in REAL_RELEASE_NAMES.items():
        spec = REGISTRY_BY_VERSION[version]
        assert spec.name == real_name, (
            f"v{version} canonical name {spec.name!r} != real release "
            f"name {real_name!r}"
        )


def test_s5_batch64_wrong_names_are_in_alias_set():
    """Each Batch-6.4 wrong name must be in the corresponding version's
    ``accepted_historical_names`` (so those DBs are not orphaned)."""
    for version, wrong_name in BATCH64_WRONG_NAMES.items():
        spec = REGISTRY_BY_VERSION[version]
        assert wrong_name in spec.accepted_historical_names, (
            f"v{version} wrong name {wrong_name!r} is not in the alias set "
            f"— Batch-6.4 synthetic DBs would fail to upgrade"
        )


def test_s5_v6_has_no_aliases():
    """v6+ must have an EMPTY alias set — the canonical name is the only
    accepted one (aliases are a historical-version carve-out only)."""
    current = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
    assert current.accepted_historical_names == ()
