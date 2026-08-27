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
        name: the CANONICAL human-readable identifier.  For v6+ this is
            the ONLY accepted name.  New ledger rows are written with it.
        sha256: **hardcoded** release-time hex digest over the manifest
            bytes (or ``HISTORICAL_ACCEPTED`` for pre-manifest versions).
        sql_files: SQL files whose bytes are part of this version's manifest.
        migrator_symbols: names of methods on ``Database`` (in ``database.py``)
            whose AST source is part of this version's manifest.  Empty for
            SQL-only or ledger-backfill migrations.
        accepted_historical_names: names a live DB row may carry for this
            version BESIDES ``name``.  Batch 7.1 (round-7 §五/§十六): the
            real release commits wrote names that differed from the
            canonical ones originally guessed in Batch 6.4, so an upgrade
            would ``RuntimeError`` on name mismatch.  This alias set lets
            verification accept both the real release name and the
            Batch-6.4 synthetic-backfill name.  Empty for v6+ (canonical
            name is the only accepted one).
        accepted_released_checksums: immutable checksum values written by
            earlier public releases for this same version.  This is a closed
            compatibility set, not a wildcard: the canonical ``sha256`` is
            still used for new rows and source-integrity verification.
    """

    version: int
    name: str
    sha256: str
    sql_files: tuple[str, ...] = ()
    migrator_symbols: tuple[str, ...] = field(default_factory=tuple)
    accepted_historical_names: tuple[str, ...] = field(default_factory=tuple)
    accepted_released_checksums: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------
# Manifest computation — re-hashes the *actual executed bytes* so a drift
# in any registered file is detectable at startup.
# ---------------------------------------------------------------------------


def _read_normalized_text(path: Path) -> str:
    """Read UTF-8 source with checkout-independent line endings.

    Git's Windows checkout may materialize LF files as CRLF.  The migration
    executor decodes SQL as text, so the integrity manifest must bind the
    resulting text rather than a host-specific checkout representation.
    """
    return (
        path.read_bytes()
        .decode("utf-8")
        .replace("\r\n", "\n")
        .replace("\r", "\n")
    )


def _read_sql(name: str) -> str:
    return _read_normalized_text(_THIS_DIR / name)


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
    source = _read_normalized_text(_DATABASE_PY)
    tree = ast.parse(source)
    wanted = set(symbol_names)
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        # FunctionDef / AsyncFunctionDef / ClassDef all carry ``name``.
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name in wanted
            and node.name not in found
        ):
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
#
# The generic runner and ledger verifier are deliberately NOT members of a
# historical version manifest.  They dispatch every version and therefore
# must evolve when v7/v8 are added; binding them to v6 is what changed the
# released v6 checksum and broke real upgrades in round 8.
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
        name="initial_versioned_schema",
        sha256=HISTORICAL_ACCEPTED,
        # Batch 7.1: the real release name (commit f4432c4) is the
        # canonical one.  ``initial_schema_v1`` was the wrong name Batch
        # 6.4 used for synthetic backfill; accept it so those DBs upgrade.
        accepted_historical_names=("initial_schema_v1",),
    ),
    MigrationSpec(
        version=2,
        name="f02_memory_project_unique",
        sha256=HISTORICAL_ACCEPTED,
        # Real release name (commit 4458da4).  Batch 6.4 guessed
        # ``memories_project_unique_f03`` for synthetic backfill.
        accepted_historical_names=("memories_project_unique_f03",),
    ),
    MigrationSpec(
        version=3,
        name="round5_chat_stream_state_machine",
        sha256=HISTORICAL_ACCEPTED,
        # Real release name (commit d87347d).  Batch 6.4 guessed
        # ``principal_modes_project_pk_intermediate`` for synthetic backfill.
        accepted_historical_names=("principal_modes_project_pk_intermediate",),
    ),
    MigrationSpec(
        version=4,
        name="round5_batch53_owner_context_closure",
        sha256=HISTORICAL_ACCEPTED,
        # Real release name (commit 39a3a97) — THIS was the Critical bug
        # from round-7 §五/§十六: Batch 6.4 wrote
        # ``principal_modes_project_id_pk_h09``, which would make every
        # live v4 DB fail name verification on upgrade.
        accepted_historical_names=("principal_modes_project_id_pk_h09",),
    ),
    MigrationSpec(
        version=5,
        name="round6_batch61_chat_stream_identity",
        # Historical: v5 was applied with the runtime-computed
        # ``sha256(schema.sql + salt)`` checksum (review §10.1).  Live v5
        # DBs therefore store a checksum we cannot reproduce from the
        # current source, so v5 is verified by NAME ONLY.  v6 is the first
        # version with a real manifest checksum.  The name was correct in
        # Batch 6.4, so no alias is needed.
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
        #
        # Batch 9.7c (round-9 §二十三.2): the migrator-symbol list had a
        # duplicate ``_MigrationConnection`` entry (cosmetic —
        # _extract_symbol_source dedupes via a dict — but it polluted the
        # manifest header and implied the tuple was hand-maintained without
        # a uniqueness guard).  Removing the duplicate restores the
        # checksum to the originally-released ``7bd6cb4e…`` value.  The
        # post-duplicate ``cefd37b7…`` value is retained in
        # accepted_released_checksums so databases created during that
        # window remain upgradeable.
        sha256="7bd6cb4e51936c81d3c29ab9b8902f04203374d80d588732e97157b265de8038",
        # main@19a2b538 wrote this checksum before the generic migration
        # runner was (incorrectly) added to the v6 manifest.  Real databases
        # must retain that provenance and remain upgradeable.
        accepted_released_checksums=(
            "89ea4c434b13f30f0cd1e1be6f1c4189b3edd6909132d78e11397737850dd0e7",
            # Post-duplicate (round-8) value; retained for upgrade compat.
            "cefd37b7bb3176619521d1bac798eec4081f5b2f4ad878f5e6b51c63bdc9b728",
        ),
        sql_files=("0001_initial_schema.sql", "0001_post_migration.sql"),
        migrator_symbols=_IMMUTABLE_MIGRATOR_SYMBOLS,
    ),
    MigrationSpec(
        version=7,
        name="round7_batch72_chat_replay_protocol",
        # Batch 7.2 (round-7 §十四): add the session-global ``event_id``
        # column to ``chat_stream_events`` so session-wide replay has a
        # true monotonic cursor (the stream-local ``sequence`` collided
        # across streams and missed events on reconnect).  v7's manifest
        # covers ONLY the v7 delta migrators — the v6 aggregate stays
        # frozen.  Computed at release time and recorded as a LITERAL.
        sha256="541e4dcaf2acdabc4378d68b41d60b9dde36c79395b0fc135c421cc635cad906",
        migrator_symbols=("_apply_v7_upgrades", "_ensure_chat_event_id_column"),
        accepted_released_checksums=(
            "28992f0190d75b671b6bc37090b51e92eb0c8b541b92ab8a23064095cf7f7954",
        ),
    ),
    MigrationSpec(
        version=8,
        name="round14_audit_log_tamper_protection",
        # Round-14 §4: add tamper-evident protection to ``audit_log``.
        # ``_apply_v8_upgrades`` adds the ``prev_hash`` column (hash chain)
        # and the append-only BEFORE DELETE / BEFORE UPDATE triggers, and
        # backfills ``prev_hash`` for pre-existing rows.  This closes the
        # gap where any process with DB write access could silently
        # DELETE/UPDATE audit rows to erase its tracks (review P0-1).
        # v8's manifest covers ONLY the v8 delta migrators — the v6
        # aggregate + v7 deltas stay frozen.  Computed at release time and
        # recorded as a LITERAL.
        sha256="ce99d4ed950175940a33d706c97e512259bfc9acaf69804119e820879dbfaf43",
        migrator_symbols=("_apply_v8_upgrades", "_ensure_audit_log_tamper_protection"),
    ),
    MigrationSpec(
        version=9,
        name="round15_audit_log_insert_guard",
        # Round-15 A-2: closes the INSERT-reset bypass of the v8 hash chain.
        # A ``BEFORE INSERT`` trigger refuses a row whose ``prev_hash`` is
        # empty unless the table is empty (the genesis row), so an attacker
        # with a write connection cannot INSERT a forged "genesis reset" to
        # hide prior tampering.  v9's manifest covers ONLY the v9 delta
        # migrators — v6/v7/v8 stay frozen.  Computed at release time and
        # recorded as a LITERAL.
        sha256="2e588da9aa02f4e15ce3ec71b07947c340796224f8b9f4116d2d677ac574b121",
        migrator_symbols=("_apply_v9_upgrades", "_ensure_audit_log_insert_guard"),
    ),
    MigrationSpec(
        version=10,
        name="round16_permission_rule_scope_closure",
        # Phase-1 Authority Scope Closure: persistent permission grants carry
        # explicit transport/lifetime/session/task/workspace fields. The
        # checksum is filled from the release-time manifest after this
        # migrator is finalized.
        sha256="e113a2177c9996412416aa28702eaea9f145ed8f75b590711b14104c36982d1b",
        migrator_symbols=(
            "_apply_v10_upgrades",
            "_ensure_permissions_scope_columns",
        ),
    ),
    MigrationSpec(
        version=11,
        name="round17_typed_permission_resource_rules",
        # P1-4: relaxing permission rules carry a typed resource family and
        # canonical JSON spec; ambiguous legacy globs are quarantined.
        # Filled from the release-time manifest after the migrator is final.
        sha256="571f42922d0b2044606c064a492d54e99b0c0efeea163135712d637280e72d22",
        migrator_symbols=(
            "_apply_v11_upgrades",
            "_ensure_permission_resource_columns",
        ),
    ),
    MigrationSpec(
        version=12,
        name="round18_durable_tool_operation_journal",
        # Filled from the release-time manifest after the v12 migrator is
        # finalized.  The literal is intentionally checked by
        # ``verify_source_integrity`` before a database is opened.
        sha256="a4268656f3d72b9bd36d54dbd828e9ddea15625e0123c9dbc280f8168d4b2a1a",
        migrator_symbols=(
            "_apply_v12_upgrades",
            "_ensure_tool_operations_table",
        ),
    ),
    MigrationSpec(
        version=13,
        name="memory_v2_temporal_provenance_infrastructure",
        # Memory V2 keeps the historical ``memories`` projection available
        # for compatibility, while the event ledger and derived graph become
        # the canonical source for the new Broker path.
        sha256="ebef2081c36a81dcfbf3e2ccb60d9a2464347c97bd93259524890d21e12a72a7",
        sql_files=("0013_memory_v2.sql",),
        migrator_symbols=("_apply_v13_upgrades",),
    ),
    MigrationSpec(
        version=14,
        name="memory_v2_operational_surfaces",
        # Filled from the release-time manifest after the v14 schema and
        # supersession-column migrator are finalized.  The checksum is a
        # literal so a future edit must create v15 instead of silently
        # changing an already-applied schema contract.
        sha256="2ce1c79380510e75549f44c46844e246b8a7fdc24a9f63dfa9fd1198123d9db2",
        sql_files=("0014_memory_v2_operational_surfaces.sql",),
        migrator_symbols=(
            "_apply_v14_upgrades",
            "_ensure_memory_nodes_superseded_at",
        ),
    ),
    MigrationSpec(
        version=15,
        name="memory_v2_production_closure",
        # Filled from the release-time manifest after the v15 migrator is
        # finalized.  The literal is intentionally pinned so later changes
        # require a new migration version.
        sha256="403f49122b9ba57221e4ea6ada0e2ed3ff7b728f340482438f467d150499e657",
        sql_files=("0015_memory_v2_closure.sql",),
        migrator_symbols=("_apply_v15_upgrades",),
    ),
    MigrationSpec(
        version=16,
        name="m7_1_2_goal_spec_durable_contract",
        # Release-time manifest over the v16 SQL and backfill migrator.
        sha256="2901e287a0e73f78276169e37e8f842f80d4b02a44fa31f12faaf189cc8821fc",
        sql_files=("0016_goal_specs.sql",),
        migrator_symbols=("_apply_v16_upgrades", "_backfill_legacy_goal_specs"),
    ),
    MigrationSpec(
        version=17,
        name="m7_1_3_agent_cognitive_state_cas",
        # Release-time manifest over the additive v17 SQL and its idempotent
        # column migrator.  Future edits must add a new migration version.
        sha256="6405eca2774dcf12592d0ff9069021f4d6fc27984084858d0c36c980be55484e",
        sql_files=("0017_agent_cognitive_state.sql",),
        migrator_symbols=(
            "_apply_v17_upgrades",
            "_ensure_coding_tasks_cognitive_state_columns",
        ),
    ),
    MigrationSpec(
        version=18,
        name="m7_1_4_completion_decision_ledger",
        # Release-time manifest over the additive v18 SQL and migrator.  The
        # literal is intentionally pinned so later changes require a new
        # migration version.
        sha256="ceeff204ab946b1efc1a2177cedf49042f4b9d019d1eb39658dc0c591dc95f17",
        sql_files=("0018_completion_decisions.sql",),
        migrator_symbols=("_apply_v18_upgrades",),
    ),
    MigrationSpec(
        version=19,
        name="m7_3_deterministic_plan_revisions",
        # Release-time manifest over the additive v19 SQL and migrator.
        sha256="c0568e0d408215aeed18a6b4a84ff2777b1ed7b9c4534dc2acfaa4ecb23f5f7a",
        sql_files=("0019_plan_revisions.sql",),
        migrator_symbols=("_apply_v19_upgrades",),
    ),
    MigrationSpec(
        version=20,
        name="m7_3_atomic_plan_publication_fence",
        # Release-time manifest over the additive v20 index artifact and its
        # idempotent physical-column migrator.  Future changes must add a new
        # migration version instead of editing this contract.
        sha256="696b84f04e5a2d9a08f244ccbdf6c917c3aa3605ecea1f4ea63dd4b2e5026bc8",
        sql_files=("0020_plan_publication_fence.sql",),
        migrator_symbols=(
            "_apply_v20_upgrades",
            "_ensure_coding_tasks_published_plan_revision_column",
        ),
    ),
    MigrationSpec(
        version=21,
        name="m7_4_trusted_verification_assessments",
        # Release-time manifest over the additive M7.4 assessment ledger and
        # its migration owner.  Future edits require a new migration version.
        sha256="8db1179cfb689f23aba89511c89d73583a9442ebc0b26fb3ad9a62547c3239c0",
        sql_files=("0021_trusted_verification_assessments.sql",),
        migrator_symbols=("_apply_v21_upgrades",),
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
    "CURRENT_NAME",
    "CURRENT_VERSION",
    "HISTORICAL_ACCEPTED",
    "MIGRATIONS",
    "MIGRATION_REGISTRY",
    "REGISTRY_BY_VERSION",
    "MigrationSpec",
    "compute_manifest_checksum",
    "is_historical",
    "verify_source_integrity",
]
