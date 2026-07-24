"""Batch 6.4 (round-6): Immutable Migration Registry.

This module is the single source of truth for the migration chain's
immutability contract.  It closes review §10.1–§10.5:

  §10.1  checksums were *runtime-computed* (``sha256(schema.sql + salt)``
         on every import) → now **hardcoded release-time literal constants**.
  §10.2  checksum covered ``schema.sql`` (never executed), not the files
         that actually run (``0001_*.sql`` + ``_ensure_*`` migrators +
         ``0001_post_*.sql``) → the manifest now covers **exactly the bytes
         that execute**, via AST-precise extraction of the migrator methods.
  §10.3  the "FROZEN" ``0001_initial_schema.sql`` was modified in Batch 6.1
         → historical versions are registered as-is; the file is re-blessed
         as a v1 frozen artifact and any future edit is detected because
         it changes the manifest hash.
  §10.4  only ``{5: ...}`` was in the registry, v1–v4 invisible → v1–v6
         are all registered.
  §10.5  ``name`` was written but never verified → ``verify_applied`` now
         compares both ``name`` and ``checksum``.

Immutability model
------------------
Each ``MigrationSpec`` pins a version to:

  * its ``name`` (the human-readable migration identifier),
  * a **hardcoded ``sha256`` hex literal** computed once, at release time,
    over the *actual executed bytes* (SQL files + the migrator source slice),
  * the list of files / source symbols those bytes come from.

At startup ``verify_source_integrity()`` re-hashes the manifest and raises
``RuntimeError`` (fail-closed) if it no longer matches the hardcoded
constant.  This is what makes the chain *immutable*: editing any registered
file is a detectable failure, not a silent drift.

Historical versions v1–v4 cannot be reconstructed after the fact (their
original bytes were merged into the cumulative migrator).  They are
registered with ``sha256 = HISTORICAL_ACCEPTED`` and ``verify_applied``
only checks their ``name`` (not the checksum) — this is the documented
"accepted as-is" carve-out.  From v5 onward every version carries a real
manifest hash.

The registry is intentionally dependency-free (stdlib only) so it can be
imported before the async DB layer exists.
"""

from __future__ import annotations

import ast
import hashlib
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

# Directory layout.  ``_registry.py`` lives in ``khaos/db/migrations/``;
# the SQL files are its siblings and ``database.py`` is the parent dir.
_THIS_DIR = Path(__file__).resolve().parent
_DB_DIR = _THIS_DIR.parent
_DATABASE_PY = _DB_DIR / "database.py"
_INITIAL_SCHEMA_SQL = _THIS_DIR / "0001_initial_schema.sql"
_POST_MIGRATION_SQL = _THIS_DIR / "0001_post_migration.sql"

# Sentinel recorded for historical versions whose original bytes can no
# longer be reconstructed (they pre-date the manifest checksum).  ``verify``
# matches the string exactly — a DB row carrying this value is accepted for
# the documented historical versions only.
HISTORICAL_ACCEPTED = "historical-accepted-pre-manifest"

# Salt bound into every checksum.  Changing it invalidates every released
# version, so it is itself frozen.
_CHECKSUM_SALT = "khaos-migration-chain-immutable-2026-07-24"


@dataclass(frozen=True)
class MigrationSpec:
    """One immutable entry in the migration chain.

    Attributes:
        version: integer schema version (1-based, monotonic).
        name: human-readable identifier recorded in ``schema_migrations.name``.
        sha256: **hardcoded** release-time hex digest over the manifest
            bytes (or ``HISTORICAL_ACCEPTED`` for pre-manifest versions).
        sql_files: SQL files whose bytes are part of this version's manifest.
        migrator_symbols: names of methods on ``Database`` (in ``database.py``)
            whose AST source is part of this version's manifest.  Empty for
            SQL-only or ledger-backfill migrations.
    """

    version: int
    name: str
    sha256: str
    sql_files: tuple[str, ...] = ()
    migrator_symbols: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Manifest computation — re-hashes the *actual executed bytes* so a drift
# in any registered file is detectable at startup.
# ---------------------------------------------------------------------------


def _read_sql(name: str) -> str:
    path = _THIS_DIR / name
    return path.read_text(encoding="utf-8")


def _extract_symbol_source(symbol_names: tuple[str, ...]) -> str:
    """Return the concatenated source of the named ``Database`` methods.

    Extraction is AST-precise: we parse ``database.py`` once and slice out
    each named ``def``/``class``/``AsyncFunctionDef`` by its AST span.  This
    means editing *other* methods in ``database.py`` does not perturb the
    checksum — only the migrator methods themselves are covered, which is
    exactly the "checksum covers the migrator" contract from review §10.2.
    """
    if not symbol_names:
        return ""
    source = _DATABASE_PY.read_text(encoding="utf-8")
    tree = ast.parse(source)
    wanted = set(symbol_names)
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        # FunctionDef / AsyncFunctionDef / ClassDef all carry ``name``.
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name in wanted and node.name not in found:
                seg = ast.get_source_segment(source, node)
                if seg is not None:
                    found[node.name] = seg
    missing = wanted - found.keys()
    if missing:
        raise RuntimeError(
            f"migration manifest references migrator symbols not found in "
            f"database.py: {sorted(missing)}"
        )
    # Deterministic order: by the symbol list (not dict iteration order),
    # so renames in the list change the hash but file reordering does not.
    return "\n\n".join(found[name] for name in symbol_names)


def compute_manifest_checksum(spec: MigrationSpec) -> str:
    """Re-compute the manifest checksum for *spec* from the live source.

    Returns the sha256 hex digest over ``sql_files`` bytes + migrator symbol
    source + the frozen salt.  This must equal ``spec.sha256`` at startup
    (for non-historical specs); a mismatch means a registered file drifted.
    """
    parts: list[str] = []
    for sql_name in spec.sql_files:
        parts.append(f"--- SQL: {sql_name} ---\n{_read_sql(sql_name)}")
    if spec.migrator_symbols:
        migrator_src = _extract_symbol_source(spec.migrator_symbols)
        parts.append(f"--- MIGRATOR SYMBOLS: {','.join(spec.migrator_symbols)} ---\n{migrator_src}")
    parts.append(f"--- SALT ---\n{_CHECKSUM_SALT}")
    payload = "\n\n".join(parts).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def is_historical(spec: MigrationSpec) -> bool:
    """True for pre-manifest versions whose bytes cannot be reconstructed."""
    return spec.sha256 == HISTORICAL_ACCEPTED


# ---------------------------------------------------------------------------
# The immutable chain.
#
# v1–v4 are historical: their original SQL was merged into the cumulative
# ``0001_initial_schema.sql`` + ``_run_legacy_schema_upgrades()`` and can no
# longer be isolated, so they carry ``HISTORICAL_ACCEPTED`` and are verified
# by name only.  v5+ carry a real manifest hash computed at release time.
#
# The migrator symbols list (v5) pins the *complete* set of ``_ensure_*``
# helpers + the runner + the connection facade that actually execute.  Any
# edit to one of those methods changes ``compute_manifest_checksum`` and is
# detected by ``verify_source_integrity``.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# The migrator symbol set + SQL files that constitute the *current* schema
# application.  This manifest is attached to v6 — the FIRST version whose
# checksum genuinely covers the executed bytes (review §10.2).  v1–v5 are
# registered as ``HISTORICAL_ACCEPTED`` because their original bytes were
# computed via the now-removed runtime ``sha256(schema.sql + salt)`` path
# (review §10.1) and cannot be reconstructed; they are verified by name only.
#
# From v6 onward, editing ANY of these SQL files or migrator methods changes
# ``compute_manifest_checksum`` and is detected at startup by
# ``verify_source_integrity``.  To change the schema, add a NEW MigrationSpec
# (v7+) — never edit a registered file.
# ---------------------------------------------------------------------------

# The migrator symbols: everything ``_run_legacy_schema_upgrades`` calls,
# plus the runner, the post/initial schema executor, the backup helper, and
# the commit-suppressing connection facade.  Editing any of these methods
# is a schema change and must bump the version.
_IMMUTABLE_MIGRATOR_SYMBOLS: tuple[str, ...] = (
    "_MigrationConnection",
    "_run_legacy_schema_upgrades",
    "_backup_before_migration",
    "_execute_schema_statements",
    "_ensure_scheduled_tasks_lifecycle_version",
    "_ensure_scheduled_tasks_principal_and_lease",
    "_ensure_permissions_principal_columns",
    "_ensure_authorization_contexts",
    "_ensure_memories_principal_columns",
    "_ensure_audit_log_principal_columns",
    "_ensure_coding_tasks_principal_columns",
    "_ensure_scheduled_tasks_generation_columns",
    "_ensure_sessions_principal_column",
    "_ensure_messages_principal_column",
    "_ensure_agent_turns_principal_column",
    "_ensure_session_bookmarks_principal_column",
    "_ensure_sessions_project_id_column",
    "_ensure_messages_project_id_column",
    "_ensure_agent_turns_project_id_column",
    "_ensure_session_bookmarks_project_id_column",
    "_ensure_memories_project_id_column",
    "_ensure_audit_log_project_id_column",
    "_ensure_coding_tasks_project_id_column",
    "_ensure_scheduler_journal_project_id_column",
    "_ensure_subagent_tasks_principal_column",
    "_ensure_sessions_metadata_column",
    "_ensure_memories_project_id_unique",
    "_ensure_session_identity_invariants",
    "_ensure_principal_modes_project_id_pk",
    "_ensure_chat_streams_stream_id_pk",
    "_ensure_table_project_id_column",
)


MIGRATIONS: tuple[MigrationSpec, ...] = (
    MigrationSpec(
        version=1,
        name="initial_schema_v1",
        sha256=HISTORICAL_ACCEPTED,
    ),
    MigrationSpec(
        version=2,
        name="memories_project_unique_f03",
        sha256=HISTORICAL_ACCEPTED,
    ),
    MigrationSpec(
        version=3,
        name="principal_modes_project_pk_intermediate",
        sha256=HISTORICAL_ACCEPTED,
    ),
    MigrationSpec(
        version=4,
        name="principal_modes_project_id_pk_h09",
        sha256=HISTORICAL_ACCEPTED,
    ),
    MigrationSpec(
        version=5,
        name="round6_batch61_chat_stream_identity",
        # Historical: v5 was applied with the runtime-computed
        # ``sha256(schema.sql + salt)`` checksum (review §10.1).  Live v5
        # DBs therefore store a checksum we cannot reproduce from the
        # current source, so v5 is verified by NAME ONLY.  v6 is the first
        # version with a real manifest checksum.
        sha256=HISTORICAL_ACCEPTED,
    ),
    MigrationSpec(
        version=6,
        name="round6_batch64_immutable_migration_chain",
        # v6 is the FIRST immutable version.  Its checksum covers the
        # *actual executed bytes*: the two split SQL files + every
        # migrator method that ``run_migrations`` invokes.  Editing any of
        # them is detected by ``verify_source_integrity``.  Computed once
        # at release time and recorded here as a LITERAL.
        sha256="7bd6cb4e51936c81d3c29ab9b8902f04203374d80d588732e97157b265de8038",
        sql_files=("0001_initial_schema.sql", "0001_post_migration.sql"),
        migrator_symbols=_IMMUTABLE_MIGRATOR_SYMBOLS,
    ),
)


REGISTRY_BY_VERSION: dict[int, MigrationSpec] = {
    m.version: m for m in MIGRATIONS
}

# Backwards-compatible alias: older code imported ``MIGRATION_REGISTRY``
# as ``dict[int, tuple[str, str]]``.  We keep the same shape so callers
# that only need ``(name, checksum)`` do not have to change.
MIGRATION_REGISTRY: dict[int, tuple[str, str]] = {
    m.version: (m.name, m.sha256) for m in MIGRATIONS
}

CURRENT_VERSION: int = MIGRATIONS[-1].version
CURRENT_NAME: str = MIGRATIONS[-1].name


def verify_source_integrity() -> None:
    """Fail-closed startup self-check.

    Re-hash every non-historical migration's manifest and raise
    ``RuntimeError`` if any registered file has drifted from its release-time
    constant.  Historical versions (``sha256 == HISTORICAL_ACCEPTED``) are
    skipped — their bytes are unrecoverable by design.

    Called once at the top of ``run_migrations``.
    """
    drifts: list[str] = []
    for spec in MIGRATIONS:
        if is_historical(spec):
            continue
        actual = compute_manifest_checksum(spec)
        if actual != spec.sha256:
            drifts.append(
                f"v{spec.version} ({spec.name}): expected {spec.sha256[:12]}…, "
                f"got {actual[:12]}…"
            )
    if drifts:
        raise RuntimeError(
            "migration source integrity check FAILED — a registered "
            "migration file/migrator has drifted from its release-time "
            "checksum:\n  " + "\n  ".join(drifts) + "\n"
            "If this is an intentional schema change, bump the version and "
            "add a NEW MigrationSpec instead of editing a frozen one."
        )


__all__ = [
    "HISTORICAL_ACCEPTED",
    "MIGRATIONS",
    "MIGRATION_REGISTRY",
    "MigrationSpec",
    "REGISTRY_BY_VERSION",
    "CURRENT_VERSION",
    "CURRENT_NAME",
    "compute_manifest_checksum",
    "is_historical",
    "verify_source_integrity",
]
