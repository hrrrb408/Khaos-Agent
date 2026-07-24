"""Batch 6.4 (round-6): Immutable Migration Chain.

This package holds the FROZEN migration artifacts plus the immutable
registry that pins them.  The chain is defined in ``_registry.py``; the
SQL files here are the v1 frozen bytes whose integrity the registry
enforces.

Current chain (see ``_registry.MIGRATIONS``):

  v1 = ``0001_initial_schema.sql`` (CREATE TABLE) +
       ``_run_legacy_schema_upgrades()`` (ALTER TABLE ADD COLUMN) +
       ``0001_post_migration.sql`` (CREATE INDEX / TRIGGER)
       — historical (accepted as-is)
  v2 = F-02/F-03 memories project_unique rebuild + split files
       — historical (accepted as-is)
  v3 = principal_modes project_pk intermediate
       — historical (accepted as-is)
  v4 = H-09 principal_modes(project_id, principal_id, session_id) PK
       — historical (accepted as-is)
  v5 = Batch 6.1 chat_streams keyed by stream_id
       — historical (its runtime-computed checksum cannot be reproduced)
  v6 = Batch 6.4 immutable migration chain + historical ledger backfill
       — FIRST version with a real manifest checksum (covers the actual
         executed SQL + migrator source bytes; review §10.1/§10.2)

Immutability contract
---------------------
Once a version's SQL files or migrator symbols are recorded in
``_registry.py`` with a release-time sha256 constant, they are FROZEN.
Editing any registered file is detected at startup by
``_registry.verify_source_integrity()`` (fail-closed).  To change the
schema, add a NEW ``MigrationSpec`` (v7+) — never edit a frozen file or
reuse a version number.

Historical versions (v1–v5) carry the ``HISTORICAL_ACCEPTED`` sentinel
checksum because their original bytes pre-date the manifest and cannot be
reconstructed; ``run_migrations`` verifies their NAME only (review §10.5).

Batch 7.1 (round-7 §五/§十六/§十九):
  - Each historical version's canonical ``name`` is the one the REAL
    release commit wrote (confirmed via git history).  An
    ``accepted_historical_names`` alias set also accepts the wrong names
    Batch 6.4 used for synthetic backfill, so those DBs still upgrade.
  - The v1–v5 ledger rows on a fresh DB are SYNTHETIC backfill (written
    by ``_backfill_historical_ledger_rows`` for completeness) — they were
    never individually applied by a real release runner.  They are marked
    ``app_version='synthetic-backfill'`` so an audit can tell them apart
    from rows a real release actually wrote.  A live v4/v5 DB keeps its
    own real ``app_version``.

``schema.sql`` (in the parent ``db/`` dir) is retained only for tooling
that reads the aggregate schema; it is NOT executed at runtime and is NOT
the checksum source.
"""
