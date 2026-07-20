"""Async SQLite database wrapper."""

from __future__ import annotations

import json
import asyncio
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import aiosqlite
except ModuleNotFoundError:  # pragma: no cover - exercised only in bare envs
    aiosqlite = None

from khaos.agent.core import Message


SCHEMA_PATH = Path(__file__).with_name("schema.sql")
TELEGRAM_REPLAY_WINDOW = 4096


class _AsyncCursor:
    """Minimal async cursor facade for environments without aiosqlite."""

    def __init__(self, cursor: sqlite3.Cursor):
        self._cursor = cursor

    @property
    def lastrowid(self) -> int | None:
        return self._cursor.lastrowid

    @property
    def rowcount(self) -> int:
        return self._cursor.rowcount

    async def fetchall(self) -> list[sqlite3.Row]:
        return self._cursor.fetchall()

    async def fetchone(self) -> sqlite3.Row | None:
        return self._cursor.fetchone()


class _AsyncSqliteFallback:
    """Tiny sqlite3-backed subset matching the aiosqlite calls used in P0-A."""

    def __init__(self, path: str):
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _AsyncCursor:
        return _AsyncCursor(self._conn.execute(sql, params))

    async def executescript(self, sql: str) -> None:
        self._conn.executescript(sql)

    async def commit(self) -> None:
        self._conn.commit()

    async def rollback(self) -> None:
        self._conn.rollback()

    async def close(self) -> None:
        self._conn.close()


class Database:
    """Small async database facade used by the P0-A runtime."""

    def __init__(self, path: str | Path = "khaos.db"):
        self.path = str(path)
        self._conn: aiosqlite.Connection | None = None
        self._operation_approval_lock = asyncio.Lock()
        self._turn_event_lock = asyncio.Lock()
        self._webhook_replay_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Open the SQLite connection if it is not already open."""
        if self._conn is None:
            if aiosqlite is None:
                self._conn = _AsyncSqliteFallback(self.path)
            else:
                self._conn = await aiosqlite.connect(self.path)
                self._conn.row_factory = aiosqlite.Row
            await self._conn.execute("PRAGMA foreign_keys = ON")

    async def close(self) -> None:
        """Close the SQLite connection."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None

    async def run_migrations(self) -> None:
        """Apply the full P0-A schema."""
        conn = await self._require_conn()
        await conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
        await conn.commit()
        # HIGH-3 (batch 3.1.8): ensure lifecycle_version column exists on
        # existing databases (CREATE TABLE IF NOT EXISTS won't add it to
        # a pre-existing table).  See _ensure_scheduled_tasks_lifecycle_version.
        await self._ensure_scheduled_tasks_lifecycle_version()
        # M4 batch 3.1.10: ensure principal_id, execution_id, lease_until
        # columns exist on existing databases.
        await self._ensure_scheduled_tasks_principal_and_lease()
        # M4 batch 3.1.16A-2: principal partitioning for permissions,
        # memories, audit_log + new principal_modes table.
        await self._ensure_permissions_principal_columns()
        await self._ensure_memories_principal_columns()
        await self._ensure_audit_log_principal_columns()
        # M4 batch 3.1.16A-3: principal-scoped ownership for coding_tasks.
        await self._ensure_coding_tasks_principal_columns()

    async def _ensure_scheduled_tasks_lifecycle_version(self) -> None:
        """Add ``lifecycle_version`` column to legacy ``scheduled_tasks``.

        HIGH-3 (batch 3.1.8): the column was added to ``schema.sql`` for
        new databases, but existing databases created before this batch
        won't have it (``CREATE TABLE IF NOT EXISTS`` is a no-op on an
        existing table).  This helper uses ``ALTER TABLE`` to add the
        column with a default of 0 — matching the schema.sql default.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "lifecycle_version" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks "
                "ADD COLUMN lifecycle_version INTEGER NOT NULL DEFAULT 0"
            )
            await conn.commit()

    async def _ensure_scheduled_tasks_principal_and_lease(self) -> None:
        """Add ``principal_id``, ``execution_id``, ``lease_until`` columns.

        M4 batch 3.1.10: the columns were added to ``schema.sql`` for
        new databases, but existing databases created before this batch
        won't have them (``CREATE TABLE IF NOT EXISTS`` is a no-op on
        an existing table).  This helper uses ``ALTER TABLE`` to add
        them with defaults matching schema.sql.

        ``principal_id`` defaults to ``'legacy'`` — existing rows are
        NOT visible to any authenticated principal (fail-closed).  The
        server bootstrap may optionally re-claim them for a specific
        principal, but the default is to hide them.

        M4 batch 3.1.12 (HIGH-2): legacy tasks (those with
        ``principal_id = 'legacy'``) are now QUARANTINED at migration
        time — ``status`` is set to ``'failed'`` and ``error`` records
        the quarantine reason.  Previously the migration comment
        claimed legacy tasks were "hidden", but ``CronEngine`` loads
        ALL tasks and the executor only rejected EMPTY principal —
        so ``'legacy'`` (non-empty) tasks would execute as a synthetic
        principal with no real owner.  Quarantine is fail-closed: an
        admin must explicitly re-claim the task with a real principal
        (via a future ``cron_claim`` tool) before it can run again.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
        columns = {row[1] for row in await cursor.fetchall()}
        added = False
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            added = True
        if "execution_id" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks ADD COLUMN execution_id TEXT"
            )
            added = True
        if "lease_until" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks ADD COLUMN lease_until TEXT"
            )
            added = True
        if added:
            await conn.commit()
        # M4 batch 3.1.12 (HIGH-2): quarantine legacy tasks.  Run
        # unconditionally (not just when columns were added) so a DB
        # that had the columns added by an earlier 3.1.10 run but
        # wasn't quarantined is also caught up.  The UPDATE is a no-op
        # if no legacy tasks exist or they're already quarantined.
        # NOTE: ``enabled`` is an in-memory field only (not a DB
        # column) — the quarantine is enforced by ``status='failed'``
        # (tick loop only fires ``pending`` tasks) and by
        # ``_execute_task`` rejecting ``principal_id='legacy'``.
        await conn.execute(
            """
            UPDATE scheduled_tasks
            SET status = 'failed',
                error = 'quarantined: legacy migration - task has no '
                        || 'authenticated owner; an admin must re-claim '
                        || 'it with a real principal before it can run',
                execution_id = NULL,
                lease_until = NULL
            WHERE principal_id = 'legacy'
              AND status != 'failed'
            """
        )
        await conn.commit()

    async def _ensure_permissions_principal_columns(self) -> None:
        """M4 batch 3.1.16A-2 (CRITICAL #3): add ``principal_id``,
        ``project_id``, ``policy_digest``, ``generation`` columns to
        ``permissions`` for principal-scoped rule matching.

        Legacy rows (pre-A-2) get ``principal_id='legacy'`` and are
        never matched by authenticated principals — ``list_permission_rules``
        filters by ``principal_id = ?`` when called with a principal.

        No quarantine UPDATE is needed because legacy rows are filtered
        out by the ``WHERE principal_id = ?`` clause in
        ``list_permission_rules`` — they simply never match.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(permissions)")
        columns = {row[1] for row in await cursor.fetchall()}
        added = False
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE permissions "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            added = True
        if "project_id" not in columns:
            await conn.execute(
                "ALTER TABLE permissions ADD COLUMN project_id TEXT NOT NULL DEFAULT ''"
            )
            added = True
        if "policy_digest" not in columns:
            await conn.execute(
                "ALTER TABLE permissions ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''"
            )
            added = True
        if "generation" not in columns:
            await conn.execute(
                "ALTER TABLE permissions ADD COLUMN generation INTEGER NOT NULL DEFAULT 0"
            )
            added = True
        if added:
            await conn.commit()
        # Principal-scoped lookup index (idempotent).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_permissions_principal "
            "ON permissions(principal_id, project_id, mode, permission_level)"
        )
        await conn.commit()

    async def _ensure_memories_principal_columns(self) -> None:
        """M4 batch 3.1.16A-2 (CRITICAL #5): add ``principal_id``,
        ``namespace``, ``session_id`` columns to ``memories`` and
        rebuild the UNIQUE constraint from ``(scope, key)`` to
        ``(namespace, principal_id, session_id, scope, key)``.

        SQLite cannot ALTER a UNIQUE constraint, so the table is
        rebuilt: old data is backed up, the table is dropped and
        recreated with the new schema, FTS5 + triggers are rebuilt,
        and legacy rows are re-inserted with ``principal_id='legacy'``
        and ``namespace='private'``.  Legacy rows are never loaded by
        authenticated principals — ``list_memories`` and
        ``search_memories`` filter by ``principal_id`` when called
        with one.

        The rebuild is wrapped in a single transaction; if any step
        fails the whole migration rolls back and the original table
        is preserved.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(memories)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "principal_id" in columns:
            return  # Already migrated
        # Backup old data.
        await conn.execute("CREATE TABLE _memories_backup AS SELECT * FROM memories")
        # Drop old table, FTS, and triggers (triggers are dropped
        # automatically when the table is dropped).
        await conn.execute("DROP TABLE IF EXISTS memories")
        await conn.execute("DROP TABLE IF EXISTS memory_fts")
        # Create new table with principal partitioning.
        await conn.execute(
            """
            CREATE TABLE memories (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                scope        TEXT NOT NULL,
                key          TEXT NOT NULL,
                value        TEXT NOT NULL,
                ttl          INTEGER NOT NULL DEFAULT 604800,
                confidence   INTEGER NOT NULL DEFAULT 2,
                access_freq  INTEGER NOT NULL DEFAULT 0,
                created_at   TEXT NOT NULL DEFAULT (datetime('now')),
                updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
                principal_id TEXT NOT NULL DEFAULT 'legacy',
                namespace    TEXT NOT NULL DEFAULT 'private',
                session_id   TEXT NOT NULL DEFAULT '',
                UNIQUE(namespace, principal_id, session_id, scope, key)
            )
            """
        )
        # Migrate old data (quarantine as legacy).
        await conn.execute(
            """
            INSERT INTO memories (
                id, scope, key, value, ttl, confidence, access_freq,
                created_at, updated_at, principal_id, namespace, session_id
            )
            SELECT id, scope, key, value, ttl, confidence, access_freq,
                   created_at, updated_at, 'legacy', 'private', ''
            FROM _memories_backup
            """
        )
        # Recreate FTS5 table.
        await conn.execute(
            """
            CREATE VIRTUAL TABLE memory_fts USING fts5(
                key,
                value,
                content=memories,
                content_rowid=id,
                tokenize='unicode61'
            )
            """
        )
        # Reindex FTS5 from migrated data.
        await conn.execute(
            "INSERT INTO memory_fts(rowid, key, value) SELECT id, key, value FROM memories"
        )
        # Recreate triggers.
        await conn.execute(
            """
            CREATE TRIGGER memory_ai AFTER INSERT ON memories BEGIN
                INSERT INTO memory_fts(rowid, key, value) VALUES (new.id, new.key, new.value);
            END
            """
        )
        await conn.execute(
            """
            CREATE TRIGGER memory_ad AFTER DELETE ON memories BEGIN
                INSERT INTO memory_fts(memory_fts, rowid, key, value)
                VALUES('delete', old.id, old.key, old.value);
            END
            """
        )
        await conn.execute(
            """
            CREATE TRIGGER memory_au AFTER UPDATE ON memories BEGIN
                INSERT INTO memory_fts(memory_fts, rowid, key, value)
                VALUES('delete', old.id, old.key, old.value);
                INSERT INTO memory_fts(rowid, key, value)
                VALUES (new.id, new.key, new.value);
            END
            """
        )
        # Cleanup backup.
        await conn.execute("DROP TABLE _memories_backup")
        await conn.commit()

    async def _ensure_audit_log_principal_columns(self) -> None:
        """M4 batch 3.1.16A-2 (HIGH #19): add ``principal_id``,
        ``runtime_id``, ``task_id``, ``operation_id``, ``policy_digest``,
        ``authority_generation``, ``source_transport`` columns to
        ``audit_log`` for principal attribution.

        Legacy rows (pre-A-2) get ``principal_id='legacy'`` and remain
        queryable — audit is append-only, so quarantine is not needed.
        New queries can filter by ``principal_id`` for attribution.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(audit_log)")
        columns = {row[1] for row in await cursor.fetchall()}
        added = False
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE audit_log "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            added = True
        if "runtime_id" not in columns:
            await conn.execute("ALTER TABLE audit_log ADD COLUMN runtime_id TEXT")
            added = True
        if "task_id" not in columns:
            await conn.execute("ALTER TABLE audit_log ADD COLUMN task_id TEXT")
            added = True
        if "operation_id" not in columns:
            await conn.execute("ALTER TABLE audit_log ADD COLUMN operation_id TEXT")
            added = True
        if "policy_digest" not in columns:
            await conn.execute("ALTER TABLE audit_log ADD COLUMN policy_digest TEXT")
            added = True
        if "authority_generation" not in columns:
            await conn.execute(
                "ALTER TABLE audit_log ADD COLUMN authority_generation INTEGER"
            )
            added = True
        if "source_transport" not in columns:
            await conn.execute(
                "ALTER TABLE audit_log ADD COLUMN source_transport TEXT"
            )
            added = True
        if added:
            await conn.commit()
        # Principal-scoped audit lookup index (idempotent).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_log_principal "
            "ON audit_log(principal_id, created_at)"
        )
        await conn.commit()

    async def _ensure_coding_tasks_principal_columns(self) -> None:
        """M4 batch 3.1.16A-3 (CRITICAL): add ``principal_id`` column to
        ``coding_tasks`` for principal-scoped ownership.

        Legacy rows (pre-A-3) get ``principal_id='legacy'`` and are
        QUARANTINED at migration time — ``status`` is set to ``'failed'``
        and ``error`` records the quarantine reason.  This mirrors the
        ``scheduled_tasks`` legacy quarantine from batch 3.1.12 (HIGH-2):
        an unauthenticated task with no real owner must never execute or
        surface to an authenticated principal's TaskManager.

        Quarantine is enforced by:
        - ``list_coding_tasks`` filtering by ``WHERE principal_id = ?``
          so legacy rows are invisible to authenticated principals.
        - ``TaskManager.load`` only loading rows for the bound principal.
        - ``TaskManager.create`` stamping the bound principal on every
          new task, so post-A3 tasks can never inherit 'legacy'.

        The UPDATE runs unconditionally (not just when the column is
        added) so a DB that had the column added by an earlier partial
        run but wasn't quarantined is also caught up.  The UPDATE is a
        no-op if no legacy tasks exist or they're already quarantined.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(coding_tasks)")
        columns = {row[1] for row in await cursor.fetchall()}
        added = False
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE coding_tasks "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            added = True
        if added:
            await conn.commit()
        # Principal-scoped lookup index (idempotent).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_coding_tasks_principal "
            "ON coding_tasks(principal_id, status)"
        )
        await conn.commit()
        # M4 batch 3.1.16A-3: quarantine legacy tasks.  Run unconditionally
        # so a DB that had the column added by an earlier partial run but
        # wasn't quarantined is also caught up.  The UPDATE is a no-op if
        # no legacy tasks exist or they're already quarantined.
        #
        # ``status='failed'`` is the fail-closed signal: ``TaskManager.load``
        # only loads rows scoped to the bound principal (so legacy rows are
        # invisible anyway), but if a future bug ever causes a legacy row
        # to be loaded, ``status='failed'`` ensures it cannot enter the
        # active lifecycle (``ACTIVE_STATUSES`` excludes ``FAILED``).
        #
        # ``state_json`` is patched in-place so the in-memory ``error``
        # field round-trips through ``TaskManager.load`` correctly.
        legacy_rows = await conn.execute(
            "SELECT id, state_json FROM coding_tasks "
            "WHERE principal_id = 'legacy' AND status != 'failed'"
        )
        legacy_rows = await legacy_rows.fetchall()
        if legacy_rows:
            for row in legacy_rows:
                try:
                    state = json.loads(str(row["state_json"]))
                except (json.JSONDecodeError, TypeError):
                    state = {}
                state["status"] = "failed"
                state["error"] = (
                    "quarantined: legacy migration - task has no "
                    "authenticated owner; an admin must re-claim it "
                    "with a real principal before it can run"
                )
                await conn.execute(
                    "UPDATE coding_tasks SET status = 'failed', "
                    "state_json = ?, updated_at = ? WHERE id = ?",
                    (json.dumps(state), datetime.now().isoformat(), row["id"]),
                )
            await conn.commit()

    async def create_session(self, session_id: str, mode: str = "office") -> None:
        """Create a session if missing and keep its mode current."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO sessions (id, mode)
            VALUES (?, ?)
            ON CONFLICT(id) DO UPDATE SET
                mode = excluded.mode,
                updated_at = datetime('now')
            """,
            (session_id, mode),
        )
        await conn.commit()

    async def consume_webhook_event(
        self,
        channel_id: str,
        platform: str,
        event_id: str,
        issued_at: float,
        expires_at: float | None,
    ) -> bool:
        """Atomically persist one authenticated webhook event exactly once."""
        if not channel_id or not platform or not event_id:
            return False
        conn = await self._require_conn()
        async with self._webhook_replay_lock:
            if platform == "telegram":
                return await self._consume_telegram_update(
                    conn, channel_id, event_id
                )
            now = time.time()
            await conn.execute(
                "DELETE FROM webhook_replay_events "
                "WHERE expires_at IS NOT NULL AND expires_at < ?",
                (now,),
            )
            cursor = await conn.execute(
                """
                INSERT OR IGNORE INTO webhook_replay_events (
                    channel_id, platform, event_id, issued_at, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (channel_id, platform, event_id, issued_at, expires_at, now),
            )
            await conn.commit()
            return cursor.rowcount == 1

    async def _consume_telegram_update(
        self, conn: aiosqlite.Connection, channel_id: str, event_id: str
    ) -> bool:
        try:
            update_id = int(event_id)
        except (TypeError, ValueError):
            return False
        if update_id < 0:
            return False
        now = time.time()
        await conn.execute("BEGIN IMMEDIATE")
        try:
            cursor = await conn.execute(
                "SELECT high_water, seen_json FROM webhook_replay_watermarks "
                "WHERE channel_id = ? AND platform = 'telegram'",
                (channel_id,),
            )
            row = await cursor.fetchone()
            seen: set[int] = set()
            high_water = -1
            if row is not None:
                high_water = int(row["high_water"])
                seen = {int(value) for value in json.loads(row["seen_json"])}
            else:
                legacy = await conn.execute(
                    "SELECT event_id FROM webhook_replay_events "
                    "WHERE channel_id = ? AND platform = 'telegram' "
                    "ORDER BY CAST(event_id AS INTEGER) DESC LIMIT ?",
                    (channel_id, TELEGRAM_REPLAY_WINDOW),
                )
                for legacy_row in await legacy.fetchall():
                    try:
                        seen.add(int(legacy_row["event_id"]))
                    except (TypeError, ValueError):
                        continue
                if seen:
                    high_water = max(seen)
            cutoff = high_water - TELEGRAM_REPLAY_WINDOW + 1
            if update_id in seen or (high_water >= 0 and update_id < cutoff):
                await conn.commit()
                return False
            high_water = max(high_water, update_id)
            cutoff = high_water - TELEGRAM_REPLAY_WINDOW + 1
            seen.add(update_id)
            seen = {value for value in seen if value >= cutoff}
            await conn.execute(
                """
                INSERT INTO webhook_replay_watermarks (
                    channel_id, platform, high_water, seen_json, updated_at
                ) VALUES (?, 'telegram', ?, ?, ?)
                ON CONFLICT(channel_id, platform) DO UPDATE SET
                    high_water = excluded.high_water,
                    seen_json = excluded.seen_json,
                    updated_at = excluded.updated_at
                """,
                (channel_id, high_water, json.dumps(sorted(seen)), now),
            )
            await conn.execute(
                "DELETE FROM webhook_replay_events "
                "WHERE channel_id = ? AND platform = 'telegram'",
                (channel_id,),
            )
            await conn.commit()
            return True
        except Exception:
            await conn.rollback()
            raise

    async def insert_message(self, session_id: str, message: Message) -> int:
        """Persist a chat message and return its row id."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO messages (
                session_id, role, content, tool_calls, tool_call_id, token_count
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                session_id,
                message.role,
                message.content,
                json.dumps(message.tool_calls),
                message.tool_call_id,
                message.token_count,
            ),
        )
        await conn.execute(
            "UPDATE sessions SET updated_at = datetime('now') WHERE id = ?",
            (session_id,),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_messages(self, session_id: str) -> list[Message]:
        """Load persisted messages for a session in chronological order."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT role, content, tool_calls, tool_call_id, token_count
            FROM messages
            WHERE session_id = ?
            ORDER BY created_at, id
            """,
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [
            Message(
                role=str(row["role"]),
                content=str(row["content"]),
                tool_calls=json.loads(str(row["tool_calls"] or "[]")),
                tool_call_id=row["tool_call_id"],
                token_count=int(row["token_count"]),
            )
            for row in rows
        ]

    async def set_config(self, key: str, value: Any) -> None:
        """Persist a JSON configuration value."""
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO user_config (key, value)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = datetime('now')
            """,
            (key, json.dumps(value)),
        )
        await conn.commit()

    async def get_config(self, key: str, default: Any = None) -> Any:
        """Read a JSON configuration value."""
        conn = await self._require_conn()
        cursor = await conn.execute("SELECT value FROM user_config WHERE key = ?", (key,))
        row = await cursor.fetchone()
        if row is None:
            return default
        return json.loads(str(row["value"]))

    async def get_principal_mode(
        self,
        principal_id: str,
        session_id: str = "",
        default: str = "office",
    ) -> str:
        """M4 batch 3.1.16A-2: read principal-scoped mode.

        Lookup order:
        1. (principal_id, session_id) — session-specific override
        2. (principal_id, '')         — principal default
        3. ``default`` (typically 'office')
        """
        conn = await self._require_conn()
        if session_id:
            cursor = await conn.execute(
                "SELECT mode FROM principal_modes WHERE principal_id = ? AND session_id = ?",
                (principal_id, session_id),
            )
            row = await cursor.fetchone()
            if row is not None:
                return str(row["mode"])
        cursor = await conn.execute(
            "SELECT mode FROM principal_modes WHERE principal_id = ? AND session_id = ''",
            (principal_id,),
        )
        row = await cursor.fetchone()
        if row is not None:
            return str(row["mode"])
        return default

    async def set_principal_mode(
        self,
        principal_id: str,
        mode: str,
        session_id: str = "",
    ) -> None:
        """M4 batch 3.1.16A-2: persist principal-scoped mode.

        When ``session_id`` is empty, sets the principal's default
        mode.  When non-empty, sets a session-specific override.
        """
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO principal_modes (principal_id, session_id, mode)
            VALUES (?, ?, ?)
            ON CONFLICT(principal_id, session_id) DO UPDATE SET
                mode = excluded.mode,
                updated_at = datetime('now')
            """,
            (principal_id, session_id, mode),
        )
        await conn.commit()

    async def insert_permission_rule(
        self,
        pattern: str,
        permission_level: str,
        approval: str,
        mode: str,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
        policy_digest: str = "",
        generation: int = 0,
    ) -> int:
        """Persist a permission rule and return its row id.

        M4 batch 3.1.16A-2: ``principal_id``, ``project_id``,
        ``policy_digest`` and ``generation`` scope the rule to a
        specific principal/project/policy.  Legacy callers that omit
        them get ``principal_id='legacy'`` — the rule is stored but
        never matched by authenticated principals.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO permissions (
                pattern, permission_level, approval, mode,
                principal_id, project_id, policy_digest, generation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (pattern, permission_level, approval, mode,
             principal_id, project_id, policy_digest, generation),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_permission_rules(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Load permission rules newest first.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, only
        rules belonging to that principal are returned (legacy rows
        with ``principal_id='legacy'`` are excluded).  When
        ``principal_id`` is ``None`` (default), all rules are returned
        — this preserves the legacy admin/inspection behaviour.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        if principal_id is not None:
            clauses.append("principal_id = ?")
            params.append(principal_id)
        if project_id is not None:
            clauses.append("project_id = ?")
            params.append(project_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await conn.execute(
            f"""
            SELECT id, pattern, permission_level, approval, mode,
                   strftime('%s', granted_at) AS granted_at,
                   principal_id, project_id, policy_digest, generation
            FROM permissions
            {where}
            ORDER BY granted_at DESC, id DESC
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_permission_rule(
        self,
        rule_id: int,
        *,
        principal_id: str | None = None,
    ) -> int:
        """Delete a permission rule.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, the
        rule is only deleted if it belongs to that principal — this
        prevents a principal from revoking another principal's rules.
        Returns the number of rows deleted (0 if the rule doesn't
        exist or belongs to a different principal).
        """
        conn = await self._require_conn()
        if principal_id is not None:
            cursor = await conn.execute(
                "DELETE FROM permissions WHERE id = ? AND principal_id = ?",
                (rule_id, principal_id),
            )
        else:
            cursor = await conn.execute(
                "DELETE FROM permissions WHERE id = ?", (rule_id,)
            )
        await conn.commit()
        return cursor.rowcount or 0

    async def insert_audit_log(
        self,
        action: str,
        target: str,
        result: str,
        detail: str = "",
        session_id: str | None = None,
        *,
        principal_id: str = "legacy",
        runtime_id: str | None = None,
        task_id: str | None = None,
        operation_id: str | None = None,
        policy_digest: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> int:
        """Persist an audit log entry and return its row id.

        M4 batch 3.1.16A-2: ``principal_id`` and optional context
        fields (``runtime_id``, ``task_id``, ``operation_id``,
        ``policy_digest``, ``authority_generation``,
        ``source_transport``) are stamped on every entry for
        attribution.  Legacy callers that omit them get
        ``principal_id='legacy'``.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            INSERT INTO audit_log (
                action, target, result, detail, session_id,
                principal_id, runtime_id, task_id, operation_id,
                policy_digest, authority_generation, source_transport
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (action, target, result, detail, session_id,
             principal_id, runtime_id, task_id, operation_id,
             policy_digest, authority_generation, source_transport),
        )
        await conn.commit()
        return int(cursor.lastrowid)

    async def list_audit_logs(self) -> list[dict[str, Any]]:
        """Return audit logs in insertion order."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT action, target, result, detail, session_id,
                   principal_id, runtime_id, task_id, operation_id,
                   policy_digest, authority_generation, source_transport
            FROM audit_log
            ORDER BY created_at, id
            """
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def query_audit_logs(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        *,
        principal_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return audit logs matching the given filters, newest first.

        Filters:
        - ``action``: exact action match (e.g. "write_file", "terminal").
        - ``result``: exact result match (e.g. "success", "denied", "error").
        - ``since``/``until``: inclusive ISO timestamp bounds on ``created_at``.
        - ``limit``: cap on rows (default 100).
        - ``principal_id``: only entries stamped with this principal.

        ``created_at`` is stored as ``datetime('now')`` (UTC, 'YYYY-MM-DD HH:MM:SS')
        so lexicographic comparison against ISO-ish strings works.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        if action is not None:
            clauses.append("action = ?")
            params.append(action)
        if result is not None:
            clauses.append("result = ?")
            params.append(result)
        if since is not None:
            clauses.append("created_at >= ?")
            params.append(since)
        if until is not None:
            clauses.append("created_at <= ?")
            params.append(until)
        if principal_id is not None:
            clauses.append("principal_id = ?")
            params.append(principal_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        cursor = await conn.execute(
            f"""
            SELECT id, action, target, result, detail, session_id, created_at,
                   principal_id, runtime_id, task_id, operation_id,
                   policy_digest, authority_generation, source_transport
            FROM audit_log
            {where}
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def upsert_memory(
        self,
        scope: str,
        key: str,
        value: str,
        ttl: int,
        confidence: int,
        *,
        principal_id: str = "legacy",
        namespace: str = "private",
        session_id: str = "",
    ) -> int:
        """Insert or update a memory by (namespace, principal_id, session_id, scope, key).

        M4 batch 3.1.16A-2: memories are partitioned by
        ``(namespace, principal_id, session_id)``.  Legacy callers that
        omit them get ``principal_id='legacy'`` — the memory is stored
        but never loaded by authenticated principals.
        """
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO memories (
                scope, key, value, ttl, confidence,
                principal_id, namespace, session_id
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(namespace, principal_id, session_id, scope, key) DO UPDATE SET
                value = excluded.value,
                ttl = excluded.ttl,
                confidence = excluded.confidence,
                updated_at = datetime('now')
            """,
            (scope, key, value, ttl, confidence,
             principal_id, namespace, session_id),
        )
        await conn.commit()
        cursor = await conn.execute(
            """
            SELECT id FROM memories
            WHERE namespace = ? AND principal_id = ? AND session_id = ?
              AND scope = ? AND key = ?
            """,
            (namespace, principal_id, session_id, scope, key),
        )
        row = await cursor.fetchone()
        return int(row["id"])

    async def get_memory(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str = "legacy",
        namespace: str = "private",
        session_id: str = "",
    ) -> dict[str, Any] | None:
        """Fetch one memory by (namespace, principal_id, session_id, scope, key)."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, scope, key, value, ttl, confidence, access_freq,
                   created_at, updated_at, principal_id, namespace, session_id
            FROM memories
            WHERE namespace = ? AND principal_id = ? AND session_id = ?
              AND scope = ? AND key = ?
            """,
            (namespace, principal_id, session_id, scope, key),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def delete_memory(
        self,
        scope: str,
        key: str,
        *,
        principal_id: str = "legacy",
        namespace: str = "private",
        session_id: str = "",
    ) -> None:
        """Delete one memory by (namespace, principal_id, session_id, scope, key)."""
        conn = await self._require_conn()
        await conn.execute(
            """
            DELETE FROM memories
            WHERE namespace = ? AND principal_id = ? AND session_id = ?
              AND scope = ? AND key = ?
            """,
            (namespace, principal_id, session_id, scope, key),
        )
        await conn.commit()

    async def delete_memory_by_id(self, memory_id: int) -> None:
        """Delete one memory by id."""
        conn = await self._require_conn()
        await conn.execute("DELETE FROM memories WHERE id = ?", (memory_id,))
        await conn.commit()

    async def list_memories(
        self,
        scope: str | None = None,
        *,
        principal_id: str | None = None,
        namespace: str | None = None,
    ) -> list[dict[str, Any]]:
        """List memories, optionally filtered by scope/principal/namespace.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, only
        memories belonging to that principal (or project-shared with
        ``namespace='shared'``) are returned.  Legacy rows with
        ``principal_id='legacy'`` are excluded.  When ``principal_id``
        is ``None`` (default), all memories are returned — this
        preserves the legacy admin/inspection behaviour.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        if scope is not None:
            clauses.append("scope = ?")
            params.append(scope)
        if principal_id is not None:
            # Include the principal's private memories AND project-shared
            # memories (namespace='shared', principal_id='').
            clauses.append(
                "(principal_id = ? OR (namespace = 'shared' AND principal_id = ''))"
            )
            params.append(principal_id)
        if namespace is not None:
            clauses.append("namespace = ?")
            params.append(namespace)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        cursor = await conn.execute(
            f"""
            SELECT id, scope, key, value, ttl, confidence, access_freq,
                   created_at, updated_at, principal_id, namespace, session_id
            FROM memories
            {where}
            ORDER BY confidence DESC, updated_at DESC, id DESC
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def search_memories(
        self,
        query: str,
        top_k: int = 5,
        *,
        principal_id: str | None = None,
        namespace: str | None = None,
    ) -> list[dict[str, Any]]:
        """Search memories through FTS5.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, only
        memories belonging to that principal (or project-shared) are
        returned.  Legacy rows are excluded.
        """
        conn = await self._require_conn()
        clauses: list[str] = ["memory_fts MATCH ?"]
        params: list[Any] = [query]
        if principal_id is not None:
            clauses.append(
                "(m.principal_id = ? OR (m.namespace = 'shared' AND m.principal_id = ''))"
            )
            params.append(principal_id)
        if namespace is not None:
            clauses.append("m.namespace = ?")
            params.append(namespace)
        where = " AND ".join(clauses)
        params.append(top_k)
        cursor = await conn.execute(
            f"""
            SELECT m.id, m.scope, m.key, m.value, m.ttl, m.confidence,
                   m.access_freq, m.created_at, m.updated_at,
                   m.principal_id, m.namespace, m.session_id
            FROM memory_fts
            JOIN memories AS m ON m.id = memory_fts.rowid
            WHERE {where}
            ORDER BY bm25(memory_fts)
            LIMIT ?
            """,
            tuple(params),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def touch_memory(self, memory_id: int) -> None:
        """Increment memory access frequency."""
        conn = await self._require_conn()
        await conn.execute(
            """
            UPDATE memories
            SET access_freq = access_freq + 1, updated_at = datetime('now')
            WHERE id = ?
            """,
            (memory_id,),
        )
        await conn.commit()

    async def insert_subagent_task(
        self,
        task_id: str,
        parent_session_id: str,
        goal: str,
        context: str,
        tools: str,
        status: str = "pending",
        principal_id: str = "",
    ) -> None:
        """Insert a subagent task row.

        B1: ``principal_id`` is persisted so collect / status queries
        can filter tasks by the authenticated caller.  Empty string is
        the legacy default (rows written before the column existed).

        M3: uses plain ``INSERT`` (NOT ``INSERT ... ON CONFLICT(id) DO
        UPDATE``).  Task IDs are now UUID4 (``task_{uuid.uuid4().hex}``)
        so a collision is virtually impossible — but if one ever
        happens, ``IntegrityError`` is raised instead of silently
        overwriting an old row (which could be another principal's
        history after a process restart reset the old incrementing
        counter).  Callers that legitimately need to update an existing
        row use ``update_subagent_task``.
        """
        conn = await self._require_conn()
        await self._ensure_subagent_tasks_principal_column()
        await conn.execute(
            """
            INSERT INTO subagent_tasks (id, parent_session_id, goal, context, tools, status, principal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (task_id, parent_session_id, goal, context, tools, status, principal_id),
        )
        await conn.commit()

    async def update_subagent_task(
        self,
        task_id: str,
        status: str,
        result: str | None = None,
        error: str | None = None,
        finished: bool = False,
    ) -> int:
        """Update subagent task status/result/error.

        M1 (round-6): returns the number of rows actually updated.
        Callers that need durability (e.g. ``SubAgentSpawner._persist_terminal``)
        MUST treat a zero return as "the row does not exist" — the
        terminal state was NOT persisted.  Previously the method
        returned ``None`` and discarded the cursor, so a zero-row
        ``UPDATE`` (e.g. when spawn was cancelled BEFORE
        ``insert_subagent_task`` ran) was silently treated as success.
        The spawner then cleared ``_pending_persistence`` and shutdown
        returned OK — but the DB had no row at all, so the task
        vanished from every later query.
        """
        conn = await self._require_conn()
        finished_expr = "datetime('now')" if finished else "finished_at"
        cursor = await conn.execute(
            f"""
            UPDATE subagent_tasks
            SET status = ?, result = ?, error = ?, finished_at = {finished_expr}
            WHERE id = ?
            """,
            (status, result, error, task_id),
        )
        await conn.commit()
        return cursor.rowcount or 0

    async def list_subagent_tasks(self, principal_id: str | None = None) -> list[dict[str, Any]]:
        """List subagent tasks.

        B1: when ``principal_id`` is set, only rows owned by that
        principal are returned.  ``None`` preserves the legacy
        "return everything" behaviour.
        """
        conn = await self._require_conn()
        await self._ensure_subagent_tasks_principal_column()
        if principal_id is None:
            cursor = await conn.execute(
                """
                SELECT id, parent_session_id, goal, context, tools, status, result, error, principal_id
                FROM subagent_tasks
                ORDER BY created_at, id
                """
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, parent_session_id, goal, context, tools, status, result, error, principal_id
                FROM subagent_tasks
                WHERE principal_id = ?
                ORDER BY created_at, id
                """,
                (principal_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def _ensure_subagent_tasks_principal_column(self) -> None:
        """B1: idempotently add the ``principal_id`` column to existing
        ``subagent_tasks`` tables (legacy DBs created before this column
        existed).  Fresh DBs get the column from ``schema.sql``.

        Uses PRAGMA table_info to detect the column so the ALTER only
        fires once per database lifetime.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(subagent_tasks)")
        existing = {str(row["name"]) for row in await cursor.fetchall()}
        if "principal_id" not in existing:
            await conn.execute(
                "ALTER TABLE subagent_tasks ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''"
            )
            await conn.commit()

    # ------------------------------------------------------------------
    # Phase 6: session bookmarks + session summary / changed files
    # ------------------------------------------------------------------

    async def save_bookmark(
        self,
        session_id: str,
        name: str,
        description: str = "",
        mode: str = "office",
        project_root: str | None = None,
        summary: str = "",
    ) -> None:
        """保存一个会话书签。

        同一 (session_id, name) 已存在时整体覆盖更新（upsert）。
        """
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO session_bookmarks
                (session_id, name, description, mode, project_root, summary)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id, name) DO UPDATE SET
                description  = excluded.description,
                mode         = excluded.mode,
                project_root = excluded.project_root,
                summary      = excluded.summary
            """,
            (session_id, name, description, mode, project_root, summary),
        )
        await conn.commit()

    async def load_bookmark(self, session_id: str, name: str) -> dict[str, Any] | None:
        """加载指定书签。不存在时返回 None。"""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, name, description, mode, project_root,
                   summary, created_at
            FROM session_bookmarks
            WHERE session_id = ? AND name = ?
            """,
            (session_id, name),
        )
        row = await cursor.fetchone()
        return dict(row) if row is not None else None

    async def list_bookmarks(self, session_id: str | None = None) -> list[dict[str, Any]]:
        """列出书签，可按 session 过滤。按创建时间倒序返回。"""
        conn = await self._require_conn()
        if session_id is None:
            cursor = await conn.execute(
                """
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at
                FROM session_bookmarks
                ORDER BY created_at DESC, id DESC
                """
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at
                FROM session_bookmarks
                WHERE session_id = ?
                ORDER BY created_at DESC, id DESC
                """,
                (session_id,),
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def delete_bookmark(self, session_id: str, name: str) -> None:
        """删除指定书签。不存在的书签静默忽略。"""
        conn = await self._require_conn()
        await conn.execute(
            "DELETE FROM session_bookmarks WHERE session_id = ? AND name = ?",
            (session_id, name),
        )
        await conn.commit()

    async def _ensure_sessions_metadata_column(self, column: str) -> None:
        """幂等地为 sessions 表增加一个 TEXT 列（如 summary / changed_files）。

        使用 PRAGMA 探测列是否已存在，避免 ALTER TABLE 报错。metadata JSON
        字段在 schema.sql 中已存在，这里仅在需要独立列时按需扩展。
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(sessions)")
        existing = {str(row["name"]) for row in await cursor.fetchall()}
        if column not in existing:
            await conn.execute(f"ALTER TABLE sessions ADD COLUMN {column} TEXT")
            await conn.commit()

    async def save_session_summary(self, session_id: str, summary: str) -> None:
        """保存会话摘要到 sessions 表的 summary 列。

        summary 列不存在则 ALTER TABLE 添加（幂等迁移）。同时合并写入
        metadata JSON 的 summary 字段，保持向后兼容。
        """
        conn = await self._require_conn()
        await self._ensure_sessions_metadata_column("summary")
        await conn.execute(
            "UPDATE sessions SET summary = ?, updated_at = datetime('now') WHERE id = ?",
            (summary, session_id),
        )
        # 同步到 metadata JSON，便于旧读取路径访问
        await self._merge_session_metadata(session_id, {"summary": summary})
        await conn.commit()

    async def get_session_summary(self, session_id: str) -> str | None:
        """读取会话摘要。优先读 summary 列，回退到 metadata JSON。"""
        conn = await self._require_conn()
        # summary 列可能不存在（旧库未迁移），用 try 探测。
        try:
            cursor = await conn.execute(
                "SELECT summary FROM sessions WHERE id = ?",
                (session_id,),
            )
            row = await cursor.fetchone()
            if row is not None and row["summary"] is not None:
                return str(row["summary"])
        except sqlite3.OperationalError:
            # 列尚未添加 — 回退到 metadata
            pass
        meta = await self._read_session_metadata(session_id)
        value = meta.get("summary")
        return str(value) if value is not None else None

    async def save_session_changes(self, session_id: str, files: list[str]) -> None:
        """保存会话期间修改的文件列表到 sessions metadata。

        与 summary 共存于一个 JSON metadata 字段中，结构：
        ``{"summary": "...", "changed_files": ["path1", "path2"]}``
        """
        conn = await self._require_conn()
        await self._merge_session_metadata(session_id, {"changed_files": list(files)})
        await conn.commit()

    async def get_session_changes(self, session_id: str) -> list[str]:
        """读取会话修改的文件列表。"""
        meta = await self._read_session_metadata(session_id)
        raw = meta.get("changed_files")
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw]

    async def _read_session_metadata(self, session_id: str) -> dict[str, Any]:
        """读取 sessions.metadata 的 JSON 字典，缺失/损坏时返回空字典。"""
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT metadata FROM sessions WHERE id = ?",
            (session_id,),
        )
        row = await cursor.fetchone()
        if row is None:
            return {}
        raw = row["metadata"]
        if not raw:
            return {}
        try:
            data = json.loads(str(raw))
        except (TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    async def _merge_session_metadata(
        self, session_id: str, updates: dict[str, Any]
    ) -> None:
        """合并写入 sessions.metadata JSON（浅合并）。"""
        conn = await self._require_conn()
        current = await self._read_session_metadata(session_id)
        current.update(updates)
        await conn.execute(
            "UPDATE sessions SET metadata = ?, updated_at = datetime('now') WHERE id = ?",
            (json.dumps(current, ensure_ascii=False), session_id),
        )

    # ------------------------------------------------------------------
    # Hermes batch 1: scheduled (cron) tasks
    # ------------------------------------------------------------------

    async def insert_scheduled_task(
        self,
        name: str,
        prompt: str,
        status: str,
        schedule,
        deliver_to: str = "local",
        meta: dict | None = None,
        *,
        principal_id: str = "",
        next_run: str | None = None,
    ) -> str:
        """Persist a new scheduled task and return its id.

        M4 batch 3.1.10:
          - ``principal_id`` is REQUIRED (non-empty).  Every task is
            bound to its creator; list / pause / resume / remove filter
            on it.  Empty principal is rejected — fail-closed.
          - ``next_run`` is now persisted atomically with the INSERT.
            Previously the engine computed ``next_run`` in memory but
            did NOT pass it here, so the DB row's ``next_run`` stayed
            NULL until the first execution — a restart before the first
            fire left the task permanently stuck (tick skips tasks with
            ``next_run IS NULL``).
        """
        import uuid

        if not principal_id:
            raise ValueError("principal_id is required for scheduled task creation")
        conn = await self._require_conn()
        task_id = uuid.uuid4().hex[:12]
        schedule_json = json.dumps(_schedule_to_dict(schedule), ensure_ascii=False)
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        await conn.execute(
            """
            INSERT INTO scheduled_tasks
                (id, name, prompt, status, schedule_config, deliver_to, meta,
                 principal_id, next_run)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (task_id, name, prompt, status, schedule_json, deliver_to, meta_json,
             principal_id, next_run),
        )
        await conn.commit()
        return task_id

    async def update_scheduled_task_status(
        self, task_id: str, status: str, bump_version: bool = False,
    ) -> int:
        """Update only the status column.

        HIGH-3 (batch 3.1.8): if ``bump_version`` is True, also increments
        ``lifecycle_version``.  Returns the rowcount (1 = success, 0 = no
        such task).  Used by control operations (pause / resume / remove)
        which always win over stale executor writes.
        """
        conn = await self._require_conn()
        if bump_version:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET status = ?, "
                "lifecycle_version = lifecycle_version + 1 WHERE id = ?",
                (status, task_id),
            )
        else:
            cursor = await conn.execute(
                "UPDATE scheduled_tasks SET status = ? WHERE id = ?",
                (status, task_id),
            )
        await conn.commit()
        return cursor.rowcount

    async def update_scheduled_task(
        self,
        task_id: str,
        status: str | None = None,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
        bump_version: bool = False,
    ) -> int:
        """Update multiple columns.  Returns rowcount (1 = success, 0 = no
        such task).

        HIGH-3 (batch 3.1.8): if ``bump_version`` is True, also increments
        ``lifecycle_version``.  Used by control operations which always
        win over stale executor writes.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in [
            ("status", status),
            ("last_run", last_run),
            ("next_run", next_run),
            ("run_count", run_count),
            ("last_result", last_result),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        if bump_version:
            clauses.append("lifecycle_version = lifecycle_version + 1")
        if not clauses:
            return 1
        params.append(task_id)
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} WHERE id = ?",
            tuple(params),
        )
        await conn.commit()
        return cursor.rowcount

    async def update_scheduled_task_conditional(
        self,
        task_id: str,
        expected_version: int,
        status: str | None = None,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
    ) -> int:
        """Optimistic-concurrency UPDATE for executor terminal writes.

        HIGH-3 (batch 3.1.8): the executor captures ``lifecycle_version``
        at start and passes it as ``expected_version``.  The UPDATE only
        succeeds if the version hasn't changed (no control operation
        happened in between).  Returns rowcount:
          - 1 = success (version matched, state written)
          - 0 = version mismatch (a pause / remove / resume happened;
            the stale write is discarded)

        HIGH (batch 3.1.9): the UPDATE does NOT bump ``lifecycle_version``
        on success.  Only control operations (pause / resume / remove)
        bump the version — so multiple sequential executions of a
        recurring task reuse the same version and the conditional UPDATE
        matches every time.  Previously the executor bumped the version
        on each successful write, which caused the SECOND execution's
        ``expected_version`` (still the captured-at-start value) to
        mismatch the now-incremented DB version — every subsequent
        execution's terminal state was silently discarded, the task
        appeared stuck at its pre-execution ``next_run``, and a process
        restart could re-fire the task immediately.
        """
        conn = await self._require_conn()
        clauses: list[str] = []
        params: list[Any] = []
        for col, val in [
            ("status", status),
            ("last_run", last_run),
            ("next_run", next_run),
            ("run_count", run_count),
            ("last_result", last_result),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        # HIGH (batch 3.1.9): NO version bump here — only the WHERE
        # clause checks the version.  Control ops bump the version;
        # executor writes only check it.
        # HIGH-3 (batch 3.1.8): WHERE clause is ``id = ? AND
        # lifecycle_version = ?`` — params MUST be in that order
        # (task_id first, then expected_version).  A previous version
        # had these reversed, which made every conditional UPDATE
        # match 0 rows (id column received an int, lifecycle_version
        # received a string) — silently discarding every executor
        # terminal write as a "version mismatch".
        params.extend([task_id, expected_version])
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
            f"WHERE id = ? AND lifecycle_version = ?",
            tuple(params),
        )
        await conn.commit()
        return cursor.rowcount

    async def list_scheduled_tasks(
        self, *, principal_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List scheduled tasks, optionally filtered by ``principal_id``.

        M4 batch 3.1.10: when ``principal_id`` is provided, only tasks
        belonging to that principal are returned.  ``None`` returns all
        (used by the engine's internal ``_load_tasks`` / reconcile).
        """
        conn = await self._require_conn()
        if principal_id is not None:
            cursor = await conn.execute(
                """
                SELECT id, name, prompt, status, schedule_config, deliver_to, meta,
                       created_at, last_run, next_run, run_count, last_result, error,
                       lifecycle_version, principal_id, execution_id, lease_until
                FROM scheduled_tasks
                WHERE principal_id = ?
                ORDER BY created_at
                """,
                (principal_id,),
            )
        else:
            cursor = await conn.execute(
                """
                SELECT id, name, prompt, status, schedule_config, deliver_to, meta,
                       created_at, last_run, next_run, run_count, last_result, error,
                       lifecycle_version, principal_id, execution_id, lease_until
                FROM scheduled_tasks
                ORDER BY created_at
                """
            )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_scheduled_task(
        self, task_id: str, *, principal_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Get a scheduled task by id, optionally verifying ``principal_id``.

        M4 batch 3.1.10: when ``principal_id`` is provided, returns
        ``None`` if the task belongs to a different principal — so the
        engine can return ``not_found`` (rather than revealing the
        task's existence to an unauthorized caller).
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM scheduled_tasks WHERE id = ?", (task_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        result = dict(row)
        if principal_id is not None and result.get("principal_id") != principal_id:
            return None
        return result

    async def claim_scheduled_task(
        self,
        task_id: str,
        *,
        execution_id: str,
        started_at: str,
        lease_until: str,
        expected_version: int,
    ) -> int:
        """Atomically claim a task for execution (durable lease).

        M4 batch 3.1.10: CAS UPDATE that transitions a task from
        PENDING to RUNNING, stamping an ``execution_id`` and
        ``lease_until`` so a crash during execution leaves a durable
        marker that restart recovery can detect and disclose.

        M4 batch 3.1.11 (MEDIUM-1): ``last_run`` is now set to
        ``started_at`` (the actual execution start time), NOT
        ``lease_until`` (the deadline).  Previously ``last_run`` was
        set to ``lease_until``, making the DB appear ~10 minutes
        behind the real start time during execution — corrupting
        audit timelines and crash-recovery forensics.

        Returns rowcount:
          - 1 = claim succeeded (status was PENDING, version matched)
          - 0 = claim failed (task was not PENDING, or a control op
                bumped the version since the executor captured it)

        The UPDATE does NOT bump ``lifecycle_version`` — execution
        claims are not control operations.  This keeps the version
        stable across multiple sequential executions of a recurring
        task.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            UPDATE scheduled_tasks
            SET status = 'running', execution_id = ?, lease_until = ?,
                last_run = ?
            WHERE id = ? AND status = 'pending' AND lifecycle_version = ?
            """,
            (execution_id, lease_until, started_at, task_id, expected_version),
        )
        await conn.commit()
        return cursor.rowcount

    async def clear_scheduled_task_lease(
        self, task_id: str, *, execution_id: str,
    ) -> int:
        """Clear the execution lease on a task after successful terminal write.

        M4 batch 3.1.10: called by the executor after it has written
        the terminal state (COMPLETED / FAILED / PENDING-for-next-run).
        Clears ``execution_id`` and ``lease_until`` only if the stored
        ``execution_id`` matches — so a stale executor that lost a
        lease race cannot clear a newer executor's lease.

        Returns rowcount (1 = cleared, 0 = execution_id mismatch).
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            UPDATE scheduled_tasks
            SET execution_id = NULL, lease_until = NULL
            WHERE id = ? AND execution_id = ?
            """,
            (task_id, execution_id),
        )
        await conn.commit()
        return cursor.rowcount

    async def recover_expired_leases(self, *, now_iso: str) -> int:
        """Mark tasks with expired leases as FAILED (durable at-least-once disclosure).

        M4 batch 3.1.10: called by ``CronEngine.start()`` after loading
        tasks.  Any task with ``status='running'`` and
        ``lease_until < now`` represents a crashed execution — its
        terminal state was never persisted.  Mark it FAILED with an
        error explaining the crash, and bump the lifecycle_version so
        any stale executor that somehow resumes will fail its
        conditional write.

        M4 batch 3.1.12 (HIGH-1): ``recover_all_running_tasks`` is now
        the preferred startup recovery path (single-instance model —
        all RUNNING rows belong to the dead previous process).  This
        method is still used for periodic sweep inside a running
        engine (catches executor hangs where the lease expires but
        the process is still alive).

        Returns the number of tasks recovered.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            UPDATE scheduled_tasks
            SET status = 'failed', error = 'execution lease expired '
                || '(process crash during execution; at-least-once disclosure)',
                execution_id = NULL, lease_until = NULL,
                lifecycle_version = lifecycle_version + 1
            WHERE status = 'running' AND lease_until IS NOT NULL
                  AND lease_until < ?
            """,
            (now_iso,),
        )
        await conn.commit()
        return cursor.rowcount

    async def recover_all_running_tasks(self) -> int:
        """M4 batch 3.1.12 (HIGH-1): mark ALL running tasks as FAILED.

        Single-instance model: when the engine starts, any task with
        ``status='running'`` belongs to a DEAD previous process (the
        process crash is why we're starting).  Without this, a task
        whose lease hasn't expired yet would stay RUNNING forever —
        ``recover_expired_leases`` only matches ``lease_until < now``,
        and the tick loop only fires PENDING tasks, so an unexpired
        RUNNING row is never re-evaluated.

        This method is called by ``CronEngine.start()`` BEFORE
        ``recover_expired_leases``.  It catches:
          - Tasks with unexpired leases (the gap left by 3.1.10).
          - Tasks with expired leases (idempotent with
            ``recover_expired_leases`` — the second call matches 0
            rows because status is no longer 'running').
          - Tasks with NULL leases (the CRITICAL-2 hole from 3.1.11
            where a stale executor cleared the lease but left status
            RUNNING — though 3.1.12's atomic control_finalize closes
            that hole at the source, this is the defense-in-depth).

        Bumps ``lifecycle_version`` so any stale executor that
        somehow resumes will fail its conditional write.

        Returns the number of tasks recovered.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            UPDATE scheduled_tasks
            SET status = 'failed',
                error = 'process restart detected - task was running '
                        || 'at startup; single-instance model treats '
                        || 'this as a crash (at-least-once disclosure)',
                execution_id = NULL, lease_until = NULL,
                lifecycle_version = lifecycle_version + 1
            WHERE status = 'running'
            """
        )
        await conn.commit()
        return cursor.rowcount

    async def query_running_task_ids(self) -> list[str]:
        """M4 batch 3.1.13 (CRITICAL-2): query task IDs with
        ``status='running'`` WITHOUT writing FAILED.

        Called by ``CronEngine.start()`` BEFORE
        ``recover_all_running_tasks`` so the engine can per-task
        reload the recovered tasks (instead of the full
        ``_load_tasks()`` that overwrites other tasks' in-memory
        state — see CRITICAL-2 in the security review).

        Single-instance model: at startup, any task with
        ``status='running'`` belongs to a DEAD previous process.
        We query the IDs first so we know which tasks will be
        recovered, then call ``recover_all_running_tasks`` to
        bulk-UPDATE them, then per-task reload each one.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT id FROM scheduled_tasks WHERE status = 'running'"
        )
        rows = await cursor.fetchall()
        return [str(row[0]) for row in rows]

    async def query_expired_lease_task_ids(self, *, now_iso: str) -> list[str]:
        """M4 batch 3.1.13 (CRITICAL-1): query task IDs with expired
        leases WITHOUT writing FAILED.

        The tick loop uses this to identify which executors need to be
        revoked BEFORE the sweep writes FAILED.  Previously the sweep
        unconditionally wrote FAILED via ``recover_expired_leases`` and
        then called ``_load_tasks()`` — the live executor was never
        cancelled, producing side effects after the DB said FAILED.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT id FROM scheduled_tasks "
            "WHERE status = 'running' AND lease_until IS NOT NULL "
            "AND lease_until < ?",
            (now_iso,),
        )
        rows = await cursor.fetchall()
        return [str(row[0]) for row in rows]

    async def recover_one_expired_lease(
        self, task_id: str, *, now_iso: str,
    ) -> bool:
        """M4 batch 3.1.13 (CRITICAL-1): per-task lease recovery.

        Conditional on ``status='running'`` AND ``lease_until < now``
        AND ``lease_until IS NOT NULL``.  Called by the tick loop's
        periodic sweep AFTER the live executor has been cancelled and
        bounded-awaited.  Returns ``True`` if the row was updated.
        """
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            UPDATE scheduled_tasks
            SET status = 'failed', error = 'execution lease expired '
                || '(periodic sweep; live executor revoked; '
                || 'at-least-once disclosure)',
                execution_id = NULL, lease_until = NULL,
                lifecycle_version = lifecycle_version + 1
            WHERE id = ? AND status = 'running'
                  AND lease_until IS NOT NULL AND lease_until < ?
            """,
            (task_id, now_iso),
        )
        await conn.commit()
        return cursor.rowcount == 1

    async def finalize_scheduled_task(
        self,
        task_id: str,
        *,
        execution_id: str,
        expected_version: int,
        status: str,
        last_run: str | None = None,
        next_run: str | None = None,
        run_count: int | None = None,
        last_result: str | None = None,
        error: str | None = None,
    ) -> int:
        """Atomic terminal write + lease clear (CAS).

        M4 batch 3.1.11 (CRITICAL-2): combines the terminal state
        write AND the lease clear into a single conditional UPDATE so
        they cannot diverge.  Previously the executor wrote the
        terminal state, then SEPARATELY cleared the lease — if the
        terminal write raised (DB error, commit-then-raise), the
        ``except`` branch still cleared the lease, leaving the DB row
        at ``status='running' + execution_id=NULL + lease_until=NULL``
        — permanently stuck (``recover_expired_leases`` only matches
        rows with ``lease_until IS NOT NULL``).

        The UPDATE is conditional on BOTH ``execution_id`` (so a stale
        executor can't finalize a newer executor's task) AND
        ``lifecycle_version`` (so a stale executor can't overwrite a
        control op's desired state).  Returns rowcount:
          - 1 = success (terminal state written + lease cleared)
          - 0 = version mismatch OR execution_id mismatch (a control
                op or a newer executor won; the stale write is
                discarded).  The lease is NOT cleared in this case —
                the caller must leave it intact for restart recovery.
        """
        conn = await self._require_conn()
        clauses: list[str] = [
            "status = ?",
            "execution_id = NULL",
            "lease_until = NULL",
        ]
        params: list[Any] = [status]
        for col, val in [
            ("last_run", last_run),
            ("next_run", next_run),
            ("run_count", run_count),
            ("last_result", last_result),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        # NO version bump — executor terminal writes never bump the
        # version (only control operations do).
        params.extend([task_id, execution_id, expected_version])
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
            f"WHERE id = ? AND execution_id = ? AND lifecycle_version = ?",
            tuple(params),
        )
        await conn.commit()
        return cursor.rowcount

    async def control_update_scheduled_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        target_version: int,
        status: str,
        next_run: str | None = None,
        error: str | None = None,
    ) -> int:
        """Idempotent CAS for control operations (pause / resume / remove).

        M4 batch 3.1.11 (HIGH-2): replaces the unconditional
        ``update_scheduled_task(bump_version=True)`` for control ops.
        Previously a control op used
        ``lifecycle_version = lifecycle_version + 1`` unconditionally,
        so a retry after commit-then-raise bumped the version AGAIN
        — causing version drift between the in-memory epoch (still
        the first bump) and the DB (bumped twice).  Subsequent
        executor writes with the captured ``expected_version`` would
        permanently mismatch.

        This method takes an explicit ``expected_version`` (the
        version the control op observed at start) and a
        ``target_version`` (exactly ``expected_version + 1``).  The
        UPDATE is conditional on ``lifecycle_version = expected_version``
        and sets it to ``target_version`` — so a retry after
        commit-then-raise is idempotent:
          - If the DB is still at ``expected_version``: UPDATE
            succeeds, sets to ``target_version``.
          - If the DB is already at ``target_version`` (prior retry
            committed): UPDATE matches 0 rows (version mismatch) —
            the caller treats this as success by reading back.
          - If the DB is at a HIGHER version (a newer control op
            happened): UPDATE matches 0 rows — the caller must NOT
            overwrite; the newer op wins.

        M4 batch 3.1.12 (CRITICAL-2): this method does NOT clear the
        execution lease (``execution_id`` / ``lease_until``).  Use
        ``control_finalize_scheduled_task`` for control ops that need
        to release the lease atomically with the state transition —
        otherwise a stale executor's ``_clear_lease`` could clear the
        lease while the control op's persist has failed, leaving the
        DB at ``status='running' + execution_id=NULL + lease_until=NULL``
        (permanently stuck, unrecoverable).

        Returns rowcount (1 = applied, 0 = version mismatch).
        """
        conn = await self._require_conn()
        clauses: list[str] = [
            "status = ?",
            "lifecycle_version = ?",
        ]
        params: list[Any] = [status, target_version]
        for col, val in [
            ("next_run", next_run),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        params.append(task_id)
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
            f"WHERE id = ? AND lifecycle_version = ?",
            tuple(params + [expected_version]),
        )
        await conn.commit()
        return cursor.rowcount

    async def control_finalize_scheduled_task(
        self,
        task_id: str,
        *,
        expected_version: int,
        target_version: int,
        status: str,
        next_run: str | None = None,
        error: str | None = None,
    ) -> int:
        """M4 batch 3.1.12 (CRITICAL-2): atomic control state + lease clear.

        Combines the control op's state transition (status +
        lifecycle_version) AND the execution lease release
        (``execution_id = NULL`` / ``lease_until = NULL``) into a
        single CAS UPDATE.  This closes the CRITICAL-2 hole where a
        control op persisted the desired state but left the lease in
        the DB — then a stale executor's ``_clear_lease`` cleared
        the lease independently while the control op's persist had
        actually FAILED, leaving ``status='running' + NULL lease``
        (permanently stuck, unrecoverable by ``recover_expired_leases``
        which matches ``lease_until IS NOT NULL``).

        The UPDATE is conditional on ``lifecycle_version =
        expected_version``.  Idempotent on retry:
          - DB at ``expected_version``: UPDATE succeeds, sets
            ``target_version`` + clears lease.
          - DB at ``target_version`` (prior retry committed): UPDATE
            matches 0 rows — caller reads back to confirm.
          - DB at higher version (newer control op): UPDATE matches
            0 rows — caller must NOT overwrite.

        Returns rowcount (1 = applied, 0 = version mismatch).
        """
        conn = await self._require_conn()
        clauses: list[str] = [
            "status = ?",
            "lifecycle_version = ?",
            "execution_id = NULL",
            "lease_until = NULL",
        ]
        params: list[Any] = [status, target_version]
        for col, val in [
            ("next_run", next_run),
            ("error", error),
        ]:
            if val is not None:
                clauses.append(f"{col} = ?")
                params.append(val)
        params.append(task_id)
        cursor = await conn.execute(
            f"UPDATE scheduled_tasks SET {', '.join(clauses)} "
            f"WHERE id = ? AND lifecycle_version = ?",
            tuple(params + [expected_version]),
        )
        await conn.commit()
        return cursor.rowcount

    # ------------------------------------------------------------------
    # Hermes batch 2: session history FTS5 search
    # ------------------------------------------------------------------

    async def insert_message_fts(
        self,
        session_id: str,
        role: str,
        content: str,
        token_count: int = 0,
        rowid: int | None = None,
    ) -> None:
        """Index a message into messages_fts.

        ``rowid`` should be the messages.id so the FTS row mirrors the base
        row — this lets search results link back to the exact message. When
        omitted, FTS auto-assigns a rowid (still searchable, just not joined).
        """
        conn = await self._require_conn()
        from datetime import datetime as _dt

        created = _dt.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        if rowid is not None:
            await conn.execute(
                "INSERT INTO messages_fts (rowid, session_id, role, content, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (rowid, session_id, role, content, created),
            )
        else:
            await conn.execute(
                "INSERT INTO messages_fts (session_id, role, content, created_at) "
                "VALUES (?, ?, ?, ?)",
                (session_id, role, content, created),
            )
        await conn.commit()

    async def upsert_coding_task(
        self, task: dict[str, Any], *, principal_id: str = "legacy"
    ) -> None:
        """Persist the complete JSON-safe state of one coding task.

        M4 batch 3.1.16A-3: ``principal_id`` is stamped on the row so
        ``list_coding_tasks`` can filter by it.  Callers should pass the
        bound principal; the default ``'legacy'`` is fail-closed and
        only used by pre-A3 callers that haven't been migrated yet.
        """
        conn = await self._require_conn()
        await conn.execute(
            """
            INSERT INTO coding_tasks (id, goal, status, state_json, created_at, updated_at, principal_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET goal=excluded.goal,
                status=excluded.status, state_json=excluded.state_json,
                updated_at=excluded.updated_at,
                principal_id=excluded.principal_id
            """,
            (
                task["id"], task["goal"], task["status"],
                json.dumps(task), task["created_at"], task["updated_at"],
                principal_id,
            ),
        )
        await conn.commit()

    async def list_coding_tasks(
        self, *, principal_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Load persisted coding-task state in creation order.

        M4 batch 3.1.16A-3: when ``principal_id`` is given, only rows
        owned by that principal are returned.  ``principal_id=None``
        (default) is the explicit admin opt-in that returns every row
        regardless of owner — used by migration / admin tooling, never
        by an authenticated principal's TaskManager.
        """
        conn = await self._require_conn()
        if principal_id is None:
            cursor = await conn.execute(
                "SELECT state_json FROM coding_tasks ORDER BY created_at"
            )
        else:
            cursor = await conn.execute(
                "SELECT state_json FROM coding_tasks "
                "WHERE principal_id = ? ORDER BY created_at",
                (principal_id,),
            )
        return [json.loads(str(row["state_json"])) for row in await cursor.fetchall()]

    async def search_sessions(
        self, query: str, limit: int = 10, offset: int = 0
    ) -> list[dict[str, Any]]:
        """FTS5 BM25 search across all session messages.

        Returns rows with id, session_id, role, created_at, rank, and a
        snippet() with the matched term highlighted.
        """
        conn = await self._require_conn()
        # snippet: highlight matches with [ ... ]; bm25() rank (lower = better).
        cursor = await conn.execute(
            """
            SELECT rowid AS id, session_id, role, created_at,
                   rank,
                   snippet(messages_fts, 2, '[', ']]', '...', 12) AS snippet
            FROM messages_fts
            WHERE messages_fts MATCH ?
            ORDER BY rank
            LIMIT ? OFFSET ?
            """,
            (query, limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_session_messages(
        self, session_id: str, limit: int = 50, offset: int = 0
    ) -> list[dict[str, Any]]:
        """Return messages for a session, newest-aware pagination."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE session_id = ?
            ORDER BY created_at, id
            LIMIT ? OFFSET ?
            """,
            (session_id, limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def get_message_window(
        self, session_id: str, message_id: int, window: int = 5
    ) -> list[dict[str, Any]]:
        """Return up to ``window`` messages before and after ``message_id``."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT id, session_id, role, content, token_count, created_at
            FROM messages
            WHERE session_id = ?
            ORDER BY ABS(id - ?), id
            LIMIT ?
            """,
            (session_id, message_id, window * 2 + 1),
        )
        rows = [dict(row) for row in await cursor.fetchall()]
        # Re-sort chronologically after the ABS-based proximity selection.
        rows.sort(key=lambda r: r["id"])
        return rows

    async def count_session_messages(self, session_id: str) -> int:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT COUNT(*) AS n FROM messages WHERE session_id = ?",
            (session_id,),
        )
        row = await cursor.fetchone()
        return int(row["n"]) if row else 0

    async def count_messages_before_after(
        self, session_id: str, message_id: int
    ) -> tuple[int, int]:
        """Return (count_before, count_after) relative to ``message_id``."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT "
            "SUM(CASE WHEN id < ? THEN 1 ELSE 0 END) AS before_n, "
            "SUM(CASE WHEN id > ? THEN 1 ELSE 0 END) AS after_n "
            "FROM messages WHERE session_id = ?",
            (message_id, message_id, session_id),
        )
        row = await cursor.fetchone()
        if not row:
            return (0, 0)
        return (int(row["before_n"] or 0), int(row["after_n"] or 0))

    async def list_sessions(
        self, limit: int = 20, offset: int = 0
    ) -> list[dict[str, Any]]:
        """List sessions newest-first, with a message-count + last-message preview."""
        conn = await self._require_conn()
        cursor = await conn.execute(
            """
            SELECT s.id, s.mode, s.created_at,
                   (SELECT COUNT(*) FROM messages m WHERE m.session_id = s.id) AS message_count,
                   (SELECT content FROM messages m WHERE m.session_id = s.id
                    ORDER BY m.id DESC LIMIT 1) AS preview
            FROM sessions s
            WHERE s.status = 'active'
            ORDER BY s.updated_at DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def register_operation_approval(
        self,
        *,
        approval_id: str,
        binding_digest: str,
        binding_json: str,
        principal_id: str,
        session_id: str,
        task_id: str,
        workspace_id: str,
        operation: str,
        nonce_hash: str,
        expires_at: float,
        created_at: float,
    ) -> None:
        """Persist an immutable destructive-operation approval challenge."""
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT binding_digest FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                existing = await cursor.fetchone()
                if existing is not None:
                    if str(existing["binding_digest"]) != binding_digest:
                        raise PermissionError(
                            "operation approval id is already bound to another operation"
                        )
                    await conn.commit()
                    return
                await conn.execute(
                    """
                    INSERT INTO operation_approvals (
                        approval_id, binding_digest, binding_json, principal_id,
                        session_id, task_id, workspace_id, operation, nonce_hash,
                        expires_at, status, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)
                    """,
                    (
                        approval_id, binding_digest, binding_json, principal_id,
                        session_id, task_id, workspace_id, operation, nonce_hash,
                        expires_at, created_at,
                    ),
                )
                await self._insert_operation_event(
                    conn, approval_id, "registered", binding_digest,
                    principal_id, session_id, {}, created_at,
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def start_agent_turn(
        self,
        *,
        turn_id: str,
        attempt_id: str,
        session_id: str,
        task_id: str | None,
        payload: dict[str, Any],
        now: float,
    ) -> None:
        """Create one durable running turn and its first event atomically."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                await conn.execute(
                    "INSERT INTO agent_turns(turn_id,attempt_id,session_id,task_id,"
                    "status,last_sequence,started_at) VALUES(?,?,?,?, 'running',1,?)",
                    (turn_id, attempt_id, session_id, task_id, now),
                )
                await conn.execute(
                    "INSERT INTO agent_turn_events VALUES(?,1,'turn.started',?,?)",
                    (turn_id, json.dumps(payload, sort_keys=True), now),
                )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def append_agent_turn_event(
        self,
        *,
        turn_id: str,
        expected_sequence: int,
        event_type: str,
        payload: dict[str, Any],
        now: float,
        terminal_status: str | None = None,
        error_code: str | None = None,
    ) -> int:
        """Append in sequence; terminal status and event commit together."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT status,last_sequence FROM agent_turns WHERE turn_id=?",
                    (turn_id,),
                )
                row = await cursor.fetchone()
                if (
                    row is None
                    or row["status"] != "running"
                    or int(row["last_sequence"]) != expected_sequence
                ):
                    raise PermissionError(
                        "turn event is late, replayed, or out of sequence"
                    )
                sequence = expected_sequence + 1
                await conn.execute(
                    "INSERT INTO agent_turn_events VALUES(?,?,?,?,?)",
                    (
                        turn_id, sequence, event_type,
                        json.dumps(payload, sort_keys=True), now,
                    ),
                )
                if terminal_status is None:
                    await conn.execute(
                        "UPDATE agent_turns SET last_sequence=? WHERE turn_id=? "
                        "AND status='running' AND last_sequence=?",
                        (sequence, turn_id, expected_sequence),
                    )
                else:
                    if terminal_status not in {"completed", "interrupted", "failed"}:
                        raise ValueError("invalid terminal turn status")
                    await conn.execute(
                        "UPDATE agent_turns SET status=?,last_sequence=?,error_code=?,"
                        "finished_at=? WHERE turn_id=? AND status='running' "
                        "AND last_sequence=?",
                        (
                            terminal_status, sequence, error_code, now,
                            turn_id, expected_sequence,
                        ),
                    )
                await conn.commit()
                return sequence
            except Exception:
                await conn.rollback()
                raise

    async def recover_inflight_agent_turns(self, *, now: float) -> int:
        """Mark crash-left running turns interrupted without inventing success."""
        conn = await self._require_conn()
        async with self._turn_event_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT turn_id,last_sequence FROM agent_turns "
                    "WHERE status='running' ORDER BY started_at"
                )
                rows = await cursor.fetchall()
                for row in rows:
                    sequence = int(row["last_sequence"]) + 1
                    await conn.execute(
                        "INSERT INTO agent_turn_events VALUES(?,?,?,?,?)",
                        (
                            row["turn_id"], sequence, "turn.interrupted",
                            json.dumps({"reason": "process-restart"}), now,
                        ),
                    )
                    await conn.execute(
                        "UPDATE agent_turns SET status='interrupted',last_sequence=?,"
                        "error_code='PROCESS_RESTART',finished_at=? WHERE turn_id=? "
                        "AND status='running'",
                        (sequence, now, row["turn_id"]),
                    )
                await conn.commit()
                return len(rows)
            except Exception:
                await conn.rollback()
                raise

    async def list_agent_turn_events(
        self, turn_id: str
    ) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM agent_turn_events WHERE turn_id=? ORDER BY sequence",
            (turn_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def approve_operation_approval(
        self,
        approval_id: str,
        *,
        principal_id: str,
        session_id: str,
        now: float,
    ) -> bool:
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                success = bool(
                    row is not None
                    and row["status"] == "pending"
                    and float(row["expires_at"]) > now
                    and row["principal_id"] == principal_id
                    and row["session_id"] == session_id
                )
                if success:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='approved', approved_at=? "
                        "WHERE approval_id=? AND status='pending'",
                        (now, approval_id),
                    )
                if row is not None:
                    await self._insert_operation_event(
                        conn, approval_id,
                        "approved" if success else "approve-rejected",
                        str(row["binding_digest"]), principal_id, session_id,
                        {}, now,
                    )
                await conn.commit()
                return success
            except Exception:
                await conn.rollback()
                raise

    async def consume_operation_approval(
        self,
        approval_id: str,
        *,
        binding_digest: str,
        principal_id: str,
        session_id: str,
        now: float,
    ) -> bool:
        """Consume once; a mismatch burns any pending/approved capability."""
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                active = bool(
                    row is not None
                    and row["status"] in {"pending", "approved"}
                )
                success = bool(
                    active
                    and row["status"] == "approved"
                    and float(row["expires_at"]) > now
                    and row["binding_digest"] == binding_digest
                    and row["principal_id"] == principal_id
                    and row["session_id"] == session_id
                )
                if active:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='consumed', consumed_at=? "
                        "WHERE approval_id=? AND status IN ('pending','approved')",
                        (now, approval_id),
                    )
                if row is not None:
                    await self._insert_operation_event(
                        conn, approval_id,
                        "consumed" if success else "consume-rejected",
                        binding_digest, principal_id, session_id,
                        {"previous_status": str(row["status"])}, now,
                    )
                await conn.commit()
                return success
            except Exception:
                await conn.rollback()
                raise

    async def cancel_operation_approval(
        self, approval_id: str, *, now: float
    ) -> None:
        conn = await self._require_conn()
        async with self._operation_approval_lock:
            await conn.execute("BEGIN IMMEDIATE")
            try:
                cursor = await conn.execute(
                    "SELECT * FROM operation_approvals WHERE approval_id = ?",
                    (approval_id,),
                )
                row = await cursor.fetchone()
                if row is not None and row["status"] in {"pending", "approved"}:
                    await conn.execute(
                        "UPDATE operation_approvals SET status='cancelled', consumed_at=? "
                        "WHERE approval_id=? AND status IN ('pending','approved')",
                        (now, approval_id),
                    )
                    await self._insert_operation_event(
                        conn, approval_id, "cancelled",
                        str(row["binding_digest"]), str(row["principal_id"]),
                        str(row["session_id"]), {}, now,
                    )
                await conn.commit()
            except Exception:
                await conn.rollback()
                raise

    async def list_operation_approval_events(
        self, approval_id: str
    ) -> list[dict[str, Any]]:
        conn = await self._require_conn()
        cursor = await conn.execute(
            "SELECT * FROM operation_approval_events WHERE approval_id=? ORDER BY id",
            (approval_id,),
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def _insert_operation_event(
        self,
        conn,
        approval_id: str,
        event_type: str,
        binding_digest: str,
        principal_id: str,
        session_id: str,
        detail: dict[str, Any],
        created_at: float,
    ) -> None:
        await conn.execute(
            """
            INSERT INTO operation_approval_events (
                approval_id, event_type, binding_digest, principal_id,
                session_id, detail_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval_id, event_type, binding_digest, principal_id,
                session_id, json.dumps(detail, sort_keys=True), created_at,
            ),
        )

    async def _require_conn(self):
        if self._conn is None:
            await self.connect()
        assert self._conn is not None
        return self._conn


def _schedule_to_dict(schedule) -> dict[str, Any]:
    """Serialize a ScheduleConfig (dataclass) to a JSON-safe dict."""
    if schedule is None:
        return {}
    if hasattr(schedule, "__dict__"):
        return {k: v for k, v in vars(schedule).items()}
    if isinstance(schedule, dict):
        return schedule
    return {}
