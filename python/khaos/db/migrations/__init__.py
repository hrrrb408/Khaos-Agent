"""F-03: Versioned migration chain.

Migration files in this directory are FROZEN after release.  Future schema
changes must add new versioned files (``0003_xxx.sql``, ``0004_xxx.sql``,
etc.) rather than modifying existing ones.

Current chain:
  v2 = ``0001_initial_schema.sql`` (tables) + ``_run_legacy_schema_upgrades()``
       (column additions for old DBs) + ``0001_post_migration.sql`` (indexes
       and triggers).

The v2 checksum is computed from ``schema.sql`` (the pre-split single file)
+ ``SCHEMA_MIGRATION_SALT`` for backward compatibility with databases that
already have a v2 ledger row.  The split files produce an identical schema;
they just fix the execution order so indexes are created AFTER column
additions (F-03 bug fix).
"""
