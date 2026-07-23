"""M4 batch 3.1.16A-5-2 — Trusted State Migration CLI.

Backfills ``project_id`` on legacy rows left behind by A-5-1a/A-5-1b.

Background
----------
A-5-1a added the ``project_id TEXT NOT NULL DEFAULT ''`` column to 8
tables (sessions, messages, agent_turns, memories, audit_log,
session_bookmarks, coding_tasks, scheduler_operation_journal).
A-5-1b stamps the *live* project_id on every new write, but legacy
rows written before A-5-1b keep the fail-closed default ``''`` — they
are visible to operators but cannot participate in cross-project
forensic queries and will be rejected by future project-scoped
filters.

A-5-2 provides a CLI tool to reclaim those legacy rows by stamping
the state DB's owning project_id on every empty row.  Because the
trusted state DB lives at ``~/.khaos/state/<project-id>/state.db``
(A-1 state-root), every row in a given DB *belongs to* that DB's
project by construction — the backfill is the natural completion of
the project-identity closure.

Scope
-----
The 8 A-5-1a tables are backfilled.  ``permissions`` (A-2) and
``scheduled_tasks`` (B-1) already had their own migration helpers
that quarantine legacy rows; they are out of scope for A-5-2.

The backfill is a one-shot, idempotent UPDATE per table:

.. code-block:: sql

    UPDATE <table> SET project_id = ? WHERE project_id = ''

Re-running on an already-backfilled DB is a no-op (0 rows updated
per table).  The tool is safe to run on a live DB (SQLite row-level
locking; writes are briefly held per table).

CLI
---
.. code-block:: bash

    khaos migrate project-identity \\
        [--project-root PATH]   # default: CWD
        [--db PATH]             # override state DB path
        [--dry-run]             # preview only, no writes
        [--yes]                 # skip confirmation prompt
        [--table NAME]          # backfill only one table (repeatable)

Exit codes: 0 success / 2 argument error / 3 state-root violation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from khaos.db.database import Database
from khaos.db.state_root import (
    StateRootError,
    open_state_db_safely,
    project_id as compute_project_id,
    resolve_state_db_path,
)

logger = logging.getLogger(__name__)


#: The 8 A-5-1a tables that received the ``project_id`` column.
#: Order matters for the audit trail: ``audit_log`` is backfilled LAST
#: so the migration's own audit entry (written before the backfill
#: completes) does not get re-stamped by the backfill itself.
A_5_1A_TABLES: tuple[str, ...] = (
    "sessions",
    "messages",
    "agent_turns",
    "memories",
    "session_bookmarks",
    "coding_tasks",
    "scheduler_operation_journal",
    "audit_log",
)


@dataclass
class BackfillReport:
    """Per-table result of a backfill run.

    ``rows_updated`` is the number of rows actually written when
    ``dry_run=False``; for ``dry_run=True`` it is the number of rows
    that *would* be updated (count of ``project_id=''`` rows).
    """

    table: str
    rows_updated: int
    dry_run: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "table": self.table,
            "rows_updated": self.rows_updated,
            "dry_run": self.dry_run,
        }


@dataclass
class BackfillResult:
    """Aggregate result of a backfill run."""

    project_id: str
    project_root: str
    db_path: str
    dry_run: bool
    reports: list[BackfillReport]

    @property
    def total_rows(self) -> int:
        return sum(r.rows_updated for r in self.reports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "project_root": self.project_root,
            "db_path": str(self.db_path),
            "dry_run": self.dry_run,
            "total_rows": self.total_rows,
            "tables": [r.to_dict() for r in self.reports],
        }


class MigrationError(Exception):
    """Raised when the backfill cannot proceed (e.g. schema mismatch)."""


async def count_legacy_rows(db: Database, table: str) -> int:
    """Count rows in ``table`` with ``project_id=''``.

    Used by ``--dry-run`` to preview the would-update count without
    taking a write lock.
    """
    _validate_table_name(table)
    conn = await db._require_conn()
    cursor = await conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE project_id = ''",
    )
    row = await cursor.fetchone()
    await cursor.close()
    return int(row[0]) if row else 0


async def backfill_table(
    db: Database,
    table: str,
    project_id: str,
    *,
    commit: bool = True,
) -> int:
    """Backfill ``project_id`` on legacy rows in ``table``.

    Returns the number of rows updated.  Idempotent: re-running on a
    backfilled table returns 0.
    """
    _validate_table_name(table)
    if not project_id:
        raise MigrationError(
            "project_id must be non-empty for backfill "
            "(use compute_project_id(project_root))"
        )
    conn = await db._require_conn()
    cursor = await conn.execute(
        f"UPDATE {table} SET project_id = ? WHERE project_id = ''",
        (project_id,),
    )
    if commit:
        await conn.commit()
    rowcount = int(cursor.rowcount or 0)
    await cursor.close()
    return rowcount


async def run_backfill(
    db: Database,
    project_root: Path,
    *,
    tables: list[str] | None = None,
    dry_run: bool = False,
) -> BackfillResult:
    """Run the project_id backfill on ``db``.

    Parameters
    ----------
    db:
        Open Database with migrations applied.  Caller is responsible
        for ``connect()`` / ``run_migrations()`` / ``close()``.
    project_root:
        The project root whose ``project_id`` will be stamped on
        legacy rows.  Resolved to ``realpath`` before hashing so
        symlink-equivalent paths produce the same id.
    tables:
        Optional subset of A-5-1a tables to backfill.  ``None``
        (default) backfills all 8 tables.  Unknown table names raise
        ``MigrationError``.
    dry_run:
        When ``True``, only counts legacy rows per table; no writes.

    Returns
    -------
    BackfillResult
        Per-table report.  ``project_id`` is the computed id;
        ``project_root`` is the resolved realpath string.
    """
    target_tables = list(tables) if tables else list(A_5_1A_TABLES)
    for t in target_tables:
        _validate_table_name(t)

    resolved_root = Path(project_root).resolve()
    pid = compute_project_id(resolved_root)

    reports: list[BackfillReport] = []
    if dry_run:
        for table in target_tables:
            count = await count_legacy_rows(db, table)
            reports.append(BackfillReport(table, count, dry_run=True))
    else:
        conn = await db._require_conn()
        await conn.execute("PRAGMA defer_foreign_keys = ON")
        await conn.execute("BEGIN IMMEDIATE")
        try:
            for table in target_tables:
                updated = await backfill_table(
                    db, table, pid, commit=False,
                )
                reports.append(BackfillReport(table, updated, dry_run=False))
                logger.info(
                    "backfill: %s — %d rows stamped with project_id=%s",
                    table, updated, pid,
                )
            await conn.commit()
        except Exception:
            await conn.rollback()
            raise

    return BackfillResult(
        project_id=pid,
        project_root=str(resolved_root),
        db_path=getattr(db, "path", ""),
        dry_run=dry_run,
        reports=reports,
    )


def _validate_table_name(table: str) -> None:
    """Reject unknown table names to prevent SQL injection via f-string.

    The backfill uses parameterized queries for the ``project_id``
    value but constructs the table name via f-string (SQLite does not
    support parameterized table names).  This guard ensures only the
    8 A-5-1a tables are accepted.
    """
    if table not in A_5_1A_TABLES:
        raise MigrationError(
            f"unknown table {table!r}; expected one of {A_5_1A_TABLES}"
        )


def resolve_backfill_db_path(
    project_root: Path, explicit_db: str | Path | None = None,
) -> Path:
    """Resolve the state DB path for the backfill.

    Wraps ``resolve_state_db_path`` + ``open_state_db_safely`` so the
    CLI handler can stay thin.  Raises ``StateRootError`` if the
    resolved path violates state-root policy.
    """
    raw = resolve_state_db_path(project_root, explicit_db)
    return open_state_db_safely(raw)
