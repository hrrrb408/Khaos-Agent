"""Async SQLite database wrapper."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from khaos.agent.control.completion_recovery import CompletionGateHistoryRecord

from khaos.agent.control.completion_repository import CompletionDecisionRepository
from khaos.agent.control.goal_repository import GoalSpecRepository
from khaos.agent.control.recovery_gate_repository import RecoveryGateRepository
from khaos.agent.control.recovery_repository import RecoveryDecisionRepository
from khaos.agent.control.state_repository import AgentControlStateRepository
from khaos.agent.core import Message
from khaos.coding.planning.repository import PlanRevisionRepository
from khaos.coding.planning.step_execution_repository import PlanStepExecutionRepository
from khaos.coding.planning.tool_route_repository import PlanToolRouteRepository
from khaos.coding.planning.verification_assessment_repository import (
    VerificationAssessmentRepository,
)
from khaos.db.connection import (
    READER_DRAIN_TIMEOUT,
    DatabaseClosingError,  # noqa: F401 - compatibility export
    DatabaseConnection,
    _AsyncCursor,  # noqa: F401 - compatibility export
    _AsyncSqliteFallback,  # noqa: F401 - compatibility export
    aiosqlite,  # noqa: F401 - tests patch the shared driver module
)
from khaos.evaluation.repository import CapabilityEvaluationRepository
from khaos.subagents.assignment import SubAgentAssignmentRepository

# Compatibility name for released tests and integrations.  The lifecycle
# owner is ``db.connection.READER_DRAIN_TIMEOUT``; this alias must not become
# a second configuration knob and is scheduled for removal after callers
# migrate to the canonical owner.
_READER_DRAIN_TIMEOUT = READER_DRAIN_TIMEOUT
from khaos.db.repositories import (
    AuditRepository,
    ConfigurationRepository,
    PermissionRepository,
    SchedulerRepository,
    SessionRepository,
    ToolOperationRepository,
)
from khaos.db.repositories.audit import (
    _audit_previous_hash,  # noqa: F401 - compatibility export
    _audit_row_hash,  # noqa: F401 - compatibility export
)
from khaos.db.repositories.scheduler import (  # noqa: F401 - compatibility export
    _schedule_to_dict,
)
from khaos.time_utils import utc_now_naive

# The release-pinned migration methods below are hashed byte-for-byte.  Keep
# their released SQL spelling intact; source-integrity tests, rather than
# formatter rewrites, are the authority for these frozen manifests.
# ruff: noqa: ISC004,DTZ005

SCHEMA_PATH = Path(__file__).with_name("schema.sql")
# F-03: split migration files.  ``0001_initial_schema.sql`` contains only
# CREATE TABLE / CREATE VIRTUAL TABLE; ``0001_post_migration.sql`` contains
# CREATE INDEX / CREATE TRIGGER.  The split fixes the index-before-column
# bug: old databases that lack principal_id / project_id columns would
# fail when CREATE INDEX references those columns.  By executing tables →
# _ensure_* (column additions) → indexes, the columns always exist before
# any index or trigger references them.
#
# Batch 6.4 (round-6): these two SQL files are now FROZEN v1 artifacts of
# the immutable migration chain (see ``migrations/_registry.py``).  They
# are no longer hand-edited — any schema change must add a new versioned
# MigrationSpec.  ``schema.sql`` is retained only for tools that read the
# aggregate schema; it is NOT executed and is NOT the checksum source.
_MIGRATIONS_DIR = Path(__file__).with_name("migrations")
_INITIAL_SCHEMA_PATH = _MIGRATIONS_DIR / "0001_initial_schema.sql"
_POST_MIGRATION_PATH = _MIGRATIONS_DIR / "0001_post_migration.sql"
TELEGRAM_REPLAY_WINDOW = 4096
# Batch 6.5 (round-6 §十八): how long ``close()`` waits for in-flight reads
# to drain before closing the reader connection.  Bounded so a stuck read
# cannot block shutdown indefinitely — the generation bump already prevents
# NEW reads, and a read still in flight after this window is a leak (logged,
# then the connection is closed anyway; the stuck coroutine raises on its
# next await).
# Batch 6.4 (round-6): the immutable migration chain lives entirely in
# ``migrations/_registry.py``.  The version/name are derived from the
# chain's last entry so this module and the registry can never disagree.
# Migration history:
#   v1 = initial schema (historical, accepted as-is)
#   v2 = F-02/F-03 memories project_unique + split files (historical)
#   v3 = principal_modes project_pk intermediate (historical)
#   v4 = H-09 principal_modes project_id PK (historical)
#   v5 = Batch 6.1 chat_streams keyed by stream_id (first manifest-checksummed)
#   v6 = Batch 6.4 immutable migration chain + historical ledger backfill
from khaos.db.migrations._registry import (
    CURRENT_NAME as _CHAIN_CURRENT_NAME,
)
from khaos.db.migrations._registry import (
    CURRENT_VERSION as _CHAIN_CURRENT_VERSION,
)
from khaos.db.migrations._registry import (
    MIGRATION_REGISTRY as _MIGRATION_REGISTRY,
)
from khaos.db.migrations._registry import (
    MIGRATIONS,
    REGISTRY_BY_VERSION,
    is_historical,
)
from khaos.db.migrations._registry import (
    verify_source_integrity as _verify_migrator_source_integrity,
)

SCHEMA_MIGRATION_VERSION = _CHAIN_CURRENT_VERSION
SCHEMA_MIGRATION_NAME = _CHAIN_CURRENT_NAME
SCHEMA_MIGRATION_APP_VERSION = "0.1.0"
# Backwards-compatible public import for migration integrity tooling.
MIGRATION_REGISTRY = _MIGRATION_REGISTRY

logger = logging.getLogger(__name__)

# Retained for backwards compatibility with tests/tools that import it, but
# it is no longer used as the checksum source (the manifest in _registry.py
# is).  Kept as a non-empty sentinel so legacy assertions on its shape hold.
SCHEMA_MIGRATION_SALT = "khaos-migration-chain-immutable-2026-07-24"

# Round-4 Batch 1 (C-01): Transaction owner tracking via an immutable
# token that binds the transaction to a specific Database instance,
# connection generation, and asyncio Task.  This closes the ContextVar
# leak where ``create_task()`` inherits the parent's non-None owner and
# incorrectly believes it is inside a nested transaction, skipping
# BEGIN/COMMIT and leaving bare writes on the shared connection.
class TransactionContextLeakError(RuntimeError):
    """A transaction ContextVar leaked across task or database boundaries."""


class OwnerMismatchError(RuntimeError):
    """An upsert collided with a row owned by a different principal/project.

    H-05/H-06 (round-4 review): owner-preserving upserts must reject a
    foreign caller instead of silently mutating the row's non-owner
    columns.  Raised when ``ON CONFLICT DO UPDATE ... WHERE owner =``
    matches zero rows because the existing row's owner differs from the
    caller's.
    """


class TaskLifecycleConflictError(RuntimeError):
    """A coding-task lifecycle CAS did not match the durable row.

    This is deliberately separate from :class:`OwnerMismatchError`.  The
    latter means the owner-scoped row is unavailable to the caller; this
    error means the caller was correctly scoped but its cached lifecycle
    status is stale, or it attempted a forbidden generic lifecycle write.
    """


class ChatStreamTerminalError(RuntimeError):
    """Round-5 Batch 5.2 (C-05): attempt to append to an already-terminal stream.

    The chat stream state machine enforces "Terminal 后禁止 Append" —
    once a stream has received a ``done`` / ``error`` / ``interrupted``
    event, no further events may be appended.  This is the DB-level
    defense-in-depth for the invariant that the application layer
    (``AgentService.chat``) already enforces via the ``terminal_appended``
    flag.

    Round-6 Batch 6.1: the Terminal invariant is now per-``stream_id``,
    not per-``session_id``.  A session can have many streams, each with
    its own Terminal lifecycle.
    """


class ChatStreamOwnerMismatchError(RuntimeError):
    """Batch 7.2 (round-7 §十五): attempt to append to a stream owned by a
    different (session, principal, project).

    ``append_chat_stream_event`` reads back the ``chat_streams`` row after
    the lazy ``INSERT OR IGNORE`` and verifies the caller's owner matches.
    A caller that knows (or guesses) a foreign ``stream_id`` is refused —
    the UUID is hard to guess but that does not replace an Authority check.
    """


class SessionBusyError(RuntimeError):
    """Round-6 Batch 6.1: concurrent chat on the same session is rejected.

    The application layer (``AgentService.chat``) tracks active sessions
    and rejects a second concurrent chat RPC on the same ``session_id``
    with this error.  This makes concurrent behavior explicit (Review §八
    Strategy B: reject) instead of letting two streams race on the same
    session's state.
    """


@dataclass(frozen=True)
class TransactionOwner:
    """Immutable token proving the current task owns the active transaction.

    C-01 (round-4 review): the old ContextVar only stored ``asyncio.Task |
    None`` and checked ``is not None``.  A child ``create_task()`` inherits
    the parent's context, so it saw a non-None owner and skipped
    BEGIN/COMMIT — but it was NOT the real owner.  This token binds the
    transaction to:

    - ``database_id``: ``id(self)`` — prevents cross-Database pollution
      when one task opens transactions on db_a and db_b.
    - ``connection_generation``: bumped on ``close()`` — prevents a
      stale owner from writing to a reopened connection.
    - ``task``: ``asyncio.current_task()`` — only the task that issued
      BEGIN may nest; any other task (even a child that inherited the
      context) must acquire its own transaction.
    """

    database_id: int
    connection_generation: int
    task: asyncio.Task  # type: ignore[type-arg]
    depth: int


_current_transaction_owner: ContextVar[TransactionOwner | None] = ContextVar(
    "khaos_db_transaction_owner", default=None
)


class _MigrationConnection:
    """Delegate a connection while suppressing legacy helper commits.

    The historical migration helpers call ``commit()`` internally. During a
    versioned migration they receive this facade, so every helper participates
    in the outer ``BEGIN IMMEDIATE`` transaction instead of splitting the
    upgrade into crash-visible partial states.
    """

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def __getattr__(self, name: str) -> Any:
        return getattr(self._connection, name)

    async def commit(self) -> None:
        """The versioned migration owner performs the only commit."""


class Database:
    """Small async database facade used by the P0-A runtime."""

    def __init__(self, path: str | Path = "khaos.db"):
        self.path = str(path)
        # Physical connection state is owned by one bounded component.  The
        # underscored properties below are compatibility views for the
        # migration runner and older tests; new code should use
        # ``DatabaseConnection`` through the explicit methods on this facade.
        self._connection = DatabaseConnection(self.path)
        self._session_repository = SessionRepository()
        self._configuration_repository = ConfigurationRepository(self)
        self._permission_repository = PermissionRepository(self)
        self._audit_repository = AuditRepository(self)
        self._scheduler_repository = SchedulerRepository(self)
        self._tool_operation_repository = ToolOperationRepository(self)
        self._goal_spec_repository = GoalSpecRepository(self)
        self._agent_control_state_repository = AgentControlStateRepository(self)
        self._completion_decision_repository = CompletionDecisionRepository(self)
        self._recovery_decision_repository = RecoveryDecisionRepository(self)
        self._recovery_gate_repository = RecoveryGateRepository(self)
        self._plan_revision_repository = PlanRevisionRepository(self)
        self._plan_tool_route_repository = PlanToolRouteRepository(self)
        self._plan_step_execution_repository = PlanStepExecutionRepository(self)
        self._subagent_assignment_repository = SubAgentAssignmentRepository(self)
        self._verification_assessment_repository = VerificationAssessmentRepository(self)
        self._capability_evaluation_repository = CapabilityEvaluationRepository(self)
        # F-01: Per-domain locks remain for logical serialization (e.g. two
        # concurrent permission grants must not race on epoch computation).
        self._operation_approval_lock = asyncio.Lock()
        self._turn_event_lock = asyncio.Lock()
        self._chat_event_lock = asyncio.Lock()
        self._webhook_replay_lock = asyncio.Lock()
        # F-01: Global write transaction lock. Every write transaction must
        # acquire this lock, preventing cross-domain ``commit()`` 串扰 on the
        # shared single connection. Read-only queries do not need this lock.
        self._write_transaction_lock = asyncio.Lock()
        # A coherent evaluation snapshot uses one reader transaction.  The
        # shared reader handle therefore needs a small serialization fence so
        # unrelated read transactions cannot interleave BEGIN/ROLLBACK.
        self._read_transaction_lock = asyncio.Lock()

    # Compatibility views keep the migration runner and existing integrations
    # source-compatible while ensuring the connection component remains the
    # sole owner of physical handles and lifecycle state.
    @property
    def _conn(self) -> Any | None:
        return self._connection.writer

    @property
    def tool_operation_repository(self) -> ToolOperationRepository:
        """Return the sole durable tool-operation SQL owner.

        Runtime components that need operation idempotency receive this
        repository explicitly.  The database facade deliberately exposes no
        same-named forwarding methods, so callers cannot accidentally create
        a second persistence boundary.
        """
        return self._tool_operation_repository

    @property
    def goal_spec_repository(self) -> GoalSpecRepository:
        """Return the sole owner-scoped GoalSpec persistence boundary."""
        return self._goal_spec_repository

    @property
    def agent_control_state_repository(self) -> AgentControlStateRepository:
        """Return the sole SQL owner for cognitive-state CAS transitions."""
        return self._agent_control_state_repository

    @property
    def completion_decision_repository(self) -> CompletionDecisionRepository:
        """Return the sole owner-scoped completion-decision ledger."""
        return self._completion_decision_repository

    @property
    def recovery_decision_repository(self) -> RecoveryDecisionRepository:
        """Return the sole owner-scoped recovery-decision ledger."""
        return self._recovery_decision_repository

    @property
    def recovery_gate_repository(self) -> RecoveryGateRepository:
        """Return the atomic owner for recovery cognitive projections."""
        return self._recovery_gate_repository

    @property
    def plan_revision_repository(self) -> PlanRevisionRepository:
        """Return the sole owner-scoped immutable planning-revision ledger."""
        return self._plan_revision_repository

    @property
    def plan_tool_route_repository(self) -> PlanToolRouteRepository:
        """Return the append-only M7.6 route ledger owner."""
        return self._plan_tool_route_repository

    @property
    def plan_step_execution_repository(self) -> PlanStepExecutionRepository:
        """Return the M7.6 step/fence projection owner."""
        return self._plan_step_execution_repository

    @property
    def subagent_assignment_repository(self) -> SubAgentAssignmentRepository:
        """Return the M7.8 assignment/run persistence owner."""
        return self._subagent_assignment_repository

    @property
    def verification_assessment_repository(self) -> VerificationAssessmentRepository:
        """Return the owner-scoped trusted-verification assessment ledger."""
        return self._verification_assessment_repository

    @property
    def capability_evaluation_repository(self) -> CapabilityEvaluationRepository:
        """Return the observation-only M7.9 evaluation ledger owner."""
        return self._capability_evaluation_repository

    @_conn.setter
    def _conn(self, value: Any | None) -> None:
        self._connection.writer = value

    @property
    def _reader_conn(self) -> Any | None:
        return self._connection.reader

    @_reader_conn.setter
    def _reader_conn(self, value: Any | None) -> None:
        self._connection.reader = value

    @property
    def _connection_generation(self) -> int:
        return self._connection.generation

    @_connection_generation.setter
    def _connection_generation(self, value: int) -> None:
        self._connection.generation = value

    @property
    def _connection_lifecycle_lock(self) -> asyncio.Lock:
        return self._connection.lifecycle_lock

    @property
    def _active_readers(self) -> int:
        return self._connection.active_readers

    @_active_readers.setter
    def _active_readers(self, value: int) -> None:
        self._connection.active_readers = value

    @property
    def _readers_idle(self) -> asyncio.Event:
        return self._connection.readers_idle

    @property
    def _reader_drain_lock(self) -> asyncio.Lock:
        return self._connection.reader_drain_lock

    @property
    def _closing(self) -> bool:
        return self._connection.closing

    @_closing.setter
    def _closing(self, value: bool) -> None:
        self._connection.closing = value

    @property
    def _close_state(self) -> str:
        return self._connection.close_state

    @_close_state.setter
    def _close_state(self, value: str) -> None:
        self._connection.close_state = value

    @property
    def _memory_uri(self) -> str | None:
        return self._connection.memory_uri

    @_memory_uri.setter
    def _memory_uri(self, value: str | None) -> None:
        self._connection.memory_uri = value

    async def connect(self) -> None:
        """Open the shared writer/reader pair through the connection owner."""
        await self._connection.connect()

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[Any]:
        """Acquire the global write lock and run one atomic transaction.

        Round-4 Batch 1 (C-01): the owner token now binds the transaction
        to ``id(self)`` + ``connection_generation`` + ``asyncio.Task``.
        A child ``create_task()`` that inherits the parent's non-None
        ContextVar no longer falsely believes it is nested — the task
        identity check fails and ``TransactionContextLeakError`` is
        raised instead of silently skipping BEGIN/COMMIT.

        C-04: ``transaction()`` always operates on the writer connection
        (``self._conn``).  Read-only methods that call
        ``_require_conn()`` are routed to the reader connection when
        outside a transaction, so they never see uncommitted writer
        state.  Inside a transaction, ``_require_conn()`` routes back
        to the writer so intra-transaction reads see uncommitted
        writes.

        F-01 (Critical): The shared SQLite connection has a single writer.
        Without a global transaction owner, a coroutine in domain A
        (e.g. permission grant) could have its ``BEGIN IMMEDIATE`` …
        ``COMMIT`` transaction prematurely committed by a bare ``commit()``
        in domain B (e.g. audit insert), breaking epoch/rule atomicity.

        This context manager:
        - Acquires ``_write_transaction_lock`` (outermost call only);
        - Issues ``BEGIN IMMEDIATE`` (outermost call only);
        - Sets ``_current_transaction_owner`` so nested ``transaction()``
          calls from the same task reuse the outer transaction;
        - Commits on clean exit, rolls back on any exception;
        - Domain repositories own their logical locks and hold them
          *outside* this manager to prevent same-domain races.

        Nested calls (same task already owns a transaction) yield the raw
        writer connection without re-acquiring the lock or re-issuing
        BEGIN. The outermost call performs the single COMMIT.
        """
        owner = _current_transaction_owner.get()
        if owner is not None:
            # C-01: verify the owner is THIS database and THIS task.
            # A mismatch means the ContextVar leaked across a task or
            # database boundary (e.g. via ``create_task()`` context
            # copy, or one task opening transactions on two Database
            # instances).  Raising is safer than waiting on the writer
            # lock — the parent may be ``await``-ing the child, so
            # waiting could deadlock.
            if (
                owner.database_id != id(self)
                or owner.connection_generation != self._connection_generation
                or owner.task is not asyncio.current_task()
            ):
                raise TransactionContextLeakError(
                    "Transaction ContextVar leaked across boundary: "
                    f"owner(db={owner.database_id}, "
                    f"gen={owner.connection_generation}, "
                    f"task={owner.task!r}) != "
                    f"current(db={id(self)}, "
                    f"gen={self._connection_generation}, "
                    f"task={asyncio.current_task()!r})"
                )
            # Nested call from the same task on the same database:
            # reuse the outer transaction. Do NOT commit.
            conn = self._conn
            assert conn is not None, (
                "writer connection must exist when transaction owner is set"
            )
            yield conn
            return

        # H-06 (round-5 Batch 5.4): acquire the writer connection INSIDE
        # the write lock.  Previously ``_require_writer_conn()`` was called
        # BEFORE the lock, so a concurrent ``close()`` could tear down the
        # connection between acquiring the ref and acquiring the lock —
        # leaving this task with a stale, closed connection but a
        # fresh-generation TransactionOwner token.  Now the connection
        # reference and the generation capture happen atomically under the
        # same lock, and ``close()`` (which also acquires this lock) cannot
        # interleave.
        async with self._write_transaction_lock:
            conn = await self._require_writer_conn_locked()
            new_owner = TransactionOwner(
                database_id=id(self),
                connection_generation=self._connection_generation,
                task=asyncio.current_task(),  # type: ignore[arg-type]
                depth=0,
            )
            token = _current_transaction_owner.set(new_owner)
            # F-01 fail-safe: a previous bare write (not wrapped in
            # ``transaction()``) may have left the connection inside an
            # uncommitted implicit transaction — this happens most often
            # when a coroutine is cancelled mid-write (the cancellation
            # propagates before the bare ``commit()`` runs, but the
            # sqlite3 driver has already issued an implicit BEGIN).
            #
            # When that happens, ``BEGIN IMMEDIATE`` raises
            # ``sqlite3.OperationalError: cannot start a transaction
            # within a transaction``.  The stale transaction was never
            # committed, so rolling it back is always safe and correct:
            # no committed data is lost, and the caller's
            # ``transaction()`` block gets a clean slate.  Without this
            # recovery, a single cancelled bare write would wedge the
            # shared connection for every subsequent transaction.
            try:
                await conn.execute("BEGIN IMMEDIATE")
            except Exception as exc:
                if "cannot start a transaction" not in str(exc).lower():
                    _current_transaction_owner.reset(token)
                    raise
                logger.warning(
                    "transaction(): connection had a stale uncommitted "
                    "transaction (likely from a cancelled bare write); "
                    "rolling back before BEGIN IMMEDIATE: %s",
                    exc,
                )
                try:
                    await conn.rollback()
                except Exception as rollback_exc:
                    # If rollback itself fails the connection is wedged;
                    # let the original BEGIN error surface below.
                    logger.debug("failed to roll back stale transaction", exc_info=rollback_exc)
                await conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                await conn.commit()
            except BaseException:
                await conn.rollback()
                raise
            finally:
                _current_transaction_owner.reset(token)

    async def _commit_if_owner(self) -> None:
        """Commit only if the current task is NOT inside a transaction.

        F-01: When called from within ``transaction()``, this is a no-op
        (the outer transaction owner performs the single COMMIT). When
        called from a bare write method (not wrapped in ``transaction()``),
        it commits normally. This prevents inner methods from prematurely
        committing an outer transaction.

        C-04: commits on the writer connection (``self._conn``), never
        the reader.

        Prefer wrapping write methods in ``transaction()`` directly. This
        helper exists for the migration helpers and edge cases where
        wrapping is not practical.
        """
        if _current_transaction_owner.get() is None:
            conn = await self._require_writer_conn()
            await conn.commit()

    async def close(self) -> None:
        """Close the connection owner after in-flight writes have drained."""
        if _current_transaction_owner.get() is not None:
            raise TransactionContextLeakError(
                "close() called from within an active transaction; "
                "commit or roll back before closing the database"
            )
        # The facade still owns the write lock because transaction ownership
        # is a domain concern.  The connection component owns lifecycle lock
        # ordering, generation bump, and reader drain semantics.
        async with self._write_transaction_lock:
            await self._connection.close()

    @asynccontextmanager
    async def read_connection(self) -> AsyncIterator[Any]:
        """Yield the query-only connection under an explicit read lease.

        Domain repositories use this port instead of reaching into
        ``Database._reader_conn`` or duplicating connection lifecycle logic.
        The lease prevents shutdown from closing the reader while a query is
        still using it, and the connection remains ``PRAGMA query_only``.
        """
        async with self._read_lease():
            yield await self._require_reader_conn()

    @asynccontextmanager
    async def read_transaction(self) -> AsyncIterator[Any]:
        """Yield one coherent, query-only SQLite read transaction.

        This is an observation boundary, not a write transaction.  The
        reader snapshot is isolated from later writer commits and is always
        rolled back on exit, including cancellation.
        """
        async with self._read_transaction_lock, self.read_connection() as conn:
            await conn.execute("BEGIN")
            try:
                yield conn
            finally:
                await conn.rollback()

    @asynccontextmanager
    async def _read_lease(self):
        """Hold a reader-operation lease owned by ``DatabaseConnection``."""
        async with self._connection.read_lease():
            yield

    async def _wait_readers_drained(self) -> None:
        """Wait for in-flight readers through the connection owner."""
        await self._connection.wait_readers_drained()

    async def _require_writer_conn(self):
        """Return the writer connection, opening if necessary.

        C-04: ``transaction()`` and ``run_migrations()`` use this
        directly.  Write methods that are not wrapped in
        ``transaction()`` (legacy bare writes) also use this — they
        should be migrated to ``transaction()`` but until then they
        still need the writer.
        """
        return await self._connection.require_writer()

    async def _require_writer_conn_locked(self):
        """Return the writer connection, opening if necessary.

        H-06 (round-5 Batch 5.4): caller MUST already hold
        ``_write_transaction_lock``.  This variant acquires only the
        connection-lifecycle lock (NOT the write lock) so the open and
        the generation read happen atomically with respect to
        ``close()``.  Using ``connect()`` directly here would
        double-acquire the lifecycle lock is fine (``connect()``
        re-enters it), but the key point is that the returned ``conn``
        reference is captured while the write lock is held, so
        ``close()`` cannot tear it down before BEGIN.
        """
        return await self._connection.require_writer_locked()

    async def _require_reader_conn(self):
        """Return the reader connection, opening if necessary.

        C-04: the reader connection has ``PRAGMA query_only = ON`` so
        any accidental write through it fails at the SQLite level.
        """
        return await self._connection.require_reader()

    async def run_migrations(self) -> None:
        """Apply the schema as one locked, checksummed transaction.

        F-03: the schema is split into two files executed in order:
          1. ``0001_initial_schema.sql``  — CREATE TABLE (no indexes)
          2. ``_run_legacy_schema_upgrades()`` — ALTER TABLE ADD COLUMN
          3. ``0001_post_migration.sql``  — CREATE INDEX / TRIGGER

        This fixes the index-before-column bug: old databases that lack
        ``principal_id`` / ``project_id`` columns would previously fail
        when ``CREATE INDEX`` referenced those columns (schema.sql ran
        indexes before ``_ensure_*`` added the columns).

        Batch 6.4 (round-6): the checksum + verification now come from the
        immutable migration chain in ``migrations/_registry.py``.  Before
        touching the DB we run ``verify_source_integrity()`` — a fail-closed
        self-check that re-hashes the registered SQL files + migrator source
        and aborts if any have drifted from their release-time constant.
        """
        # Batch 6.4 §10.1/§10.2: fail-closed BEFORE any DB access if a
        # registered migration file or migrator method has drifted.
        _verify_migrator_source_integrity()
        conn = await self._require_writer_conn()
        # Batch 6.4: checksum is the immutable manifest hash from the
        # registry, NOT a runtime computation over schema.sql (review §10.1).
        # For the current version it is a release-time literal constant.
        current_spec = REGISTRY_BY_VERSION[SCHEMA_MIGRATION_VERSION]
        checksum = current_spec.sha256
        await conn.execute("PRAGMA journal_mode = WAL")
        await conn.execute("PRAGMA foreign_keys = ON")
        await conn.execute("BEGIN IMMEDIATE")
        try:
            existing_tables = await (
                await conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' "
                    "AND name != 'schema_migrations'"
                )
            ).fetchall()
            ledger_table = await (
                await conn.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' "
                    "AND name='schema_migrations'"
                )
            ).fetchone()
            if existing_tables and ledger_table is None:
                await self._backup_before_migration(conn)
            await conn.execute(
                """
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TEXT NOT NULL,
                    app_version TEXT NOT NULL
                )
                """
            )
            cursor = await conn.execute(
                # Batch 6.4 §10.5: also fetch ``name`` so it can be verified
                # (previously written but never checked).
                "SELECT version, name, checksum FROM schema_migrations "
                "ORDER BY version"
            )
            applied = await cursor.fetchall()
            if applied and int(applied[-1][0]) > SCHEMA_MIGRATION_VERSION:
                raise RuntimeError(
                    "database schema is newer than this Khaos build"
                )
            # Batch 6.4 §10.4/§10.5 + Batch 7.1 §五/§十六: verify EVERY applied
            # row whose version is in the immutable registry.  For each
            # registered row we check BOTH the name and the checksum, unless
            # the version is ``HISTORICAL_ACCEPTED`` (v1–v5: their original
            # checksums were runtime-computed and cannot be reproduced, so
            # they are verified by name only — the documented "accepted
            # as-is" carve-out).
            #
            # Batch 7.1 name handling: the canonical name (spec.name) is
            # always accepted, AND for historical versions we also accept
            # every name in ``accepted_historical_names`` — the real
            # release commits wrote names that differed from the ones Batch
            # 6.4 guessed, so an upgrade would have ``RuntimeError``'d on
            # every live v1–v4 DB.  v6+ has an empty alias set (canonical
            # name only).
            applied_versions = set()
            for row in applied:
                row_version = int(row[0])
                applied_versions.add(row_version)
                if row_version in REGISTRY_BY_VERSION:
                    spec = REGISTRY_BY_VERSION[row_version]
                    expected_checksum = spec.sha256
                    row_name = str(row[1])
                    # §10.5 + §五/§十六: name verified against canonical +
                    # historical alias set.
                    acceptable_names = {spec.name, *spec.accepted_historical_names}
                    if row_name not in acceptable_names:
                        raise RuntimeError(
                            f"database migration name mismatch for "
                            f"version {row_version} (accepted: "
                            f"{sorted(acceptable_names)}, db: "
                            f"{row_name!r}) — migration row may have "
                            f"been tampered or is from an unrecognized "
                            f"release"
                        )
                    # §10.1/§10.2: checksum verified unless historical.
                    if not is_historical(spec):
                        acceptable_checksums = {
                            expected_checksum,
                            *spec.accepted_released_checksums,
                        }
                        if str(row[2]) not in acceptable_checksums:
                            raise RuntimeError(
                                f"database migration checksum mismatch "
                                f"for version {row_version} (registry: "
                                f"{sorted(value[:12] + '…' for value in acceptable_checksums)}, db: "
                                f"{str(row[2])[:12]}…) — migration may "
                                f"have been tampered or drifted"
                            )
            if SCHEMA_MIGRATION_VERSION in applied_versions:
                # Latest version is already applied and verified against the
                # registry.  (Batch 6.4: we still backfill any missing
                # historical rows below for ledger completeness.)  M7.1.2
                # also validates/backfills the GoalSpec projection on every
                # startup so a task inserted through an older compatibility
                # facade cannot become loadable without its canonical goal.
                await self._backfill_historical_ledger_rows(conn, applied_versions)
                await self._backfill_legacy_goal_specs(conn)
                await conn.commit()
                return

            # F-03: execute tables FIRST, then legacy column upgrades,
            # then indexes/triggers.  This ensures all columns exist
            # before any CREATE INDEX references them.
            initial_schema_text = _INITIAL_SCHEMA_PATH.read_text(
                encoding="utf-8"
            )
            post_migration_text = _POST_MIGRATION_PATH.read_text(
                encoding="utf-8"
            )
            # Step 1: CREATE TABLE IF NOT EXISTS (safe for old + fresh DBs)
            await self._execute_schema_statements(conn, initial_schema_text)
            # Step 2: _ensure_* — add missing columns to old DBs
            # (no-op for fresh DBs where columns already exist)
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._run_legacy_schema_upgrades()
            finally:
                self._conn = original_conn
            # Step 3: CREATE INDEX / TRIGGER IF NOT EXISTS (safe now —
            # all columns referenced by indexes exist)
            await self._execute_schema_statements(conn, post_migration_text)
            # Batch 7.2 (round-7 §十四): apply v7 deltas AFTER the v6
            # aggregate so v6's frozen manifest is untouched.  v7 adds
            # the session-global ``event_id`` replay cursor.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v7_upgrades()
            finally:
                self._conn = original_conn
            # Round-14 §4: apply v8 deltas — audit_log tamper protection
            # (prev_hash chain + append-only triggers).  Symmetric to v7:
            # runs after the v6 aggregate so the frozen manifest is untouched.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v8_upgrades()
            finally:
                self._conn = original_conn
            # Round-15 A-2: apply v9 deltas — audit_log INSERT genesis guard.
            # Closes the INSERT-reset bypass of the v8 hash chain.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v9_upgrades()
            finally:
                self._conn = original_conn
            # Phase-1 Authority Scope Closure: bind persistent permission
            # grants to transport/lifetime/session/task/workspace scope.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v10_upgrades()
            finally:
                self._conn = original_conn
            # P1-4: typed resource DSL for relaxing permission grants.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v11_upgrades()
            finally:
                self._conn = original_conn
            # Security closure: create the durable tool-operation journal
            # before any scheduler can dispatch a side effect.  This is a
            # v12 delta so existing v11 databases upgrade without modifying
            # the frozen historical schema manifests.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v12_upgrades()
            finally:
                self._conn = original_conn
            # Memory V2: canonical event ledger and rebuildable derived
            # representation are a new versioned boundary.  The migration
            # is deliberately separate from the frozen V1 memories table.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v13_upgrades()
            finally:
                self._conn = original_conn
            # Memory V2 operational surfaces are a new append-only schema
            # boundary.  v13 remains frozen; v14 adds profile/provider
            # lifecycle state, rebuildable CodeGraph storage, benchmark
            # evidence, and the explicit supersession timestamp.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v14_upgrades()
            finally:
                self._conn = original_conn
            # Memory V2 production closure: explicit projection generations,
            # compliance tombstones, and resumable maintenance cursors.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v15_upgrades()
            finally:
                self._conn = original_conn
            # M7.1.2: create the immutable GoalSpec table and backfill every
            # existing coding task before publishing the v16 ledger row.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v16_upgrades()
            finally:
                self._conn = original_conn
            # M7.1.3: add the independent cognitive-state/version columns.
            # The delta is applied after v16 GoalSpec backfill so every
            # existing coding task receives the conservative UNINITIALIZED/0
            # defaults in the same outer migration transaction.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v17_upgrades()
            finally:
                self._conn = original_conn
            # M7.1.4: add the passive, append-only completion-decision
            # ledger.  No historical decisions are synthesized from legacy
            # TaskStatus, test results, or assistant text.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v18_upgrades()
            finally:
                self._conn = original_conn
            # M7.3: add the passive, append-only deterministic planning
            # revision ledger.  No plan is inferred from legacy task history.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v19_upgrades()
            finally:
                self._conn = original_conn
            # M7.3 closure amendment: add the physical, descriptive
            # publication identity used to atomically bind IMPLEMENTING to
            # one READY plan-revision ledger head.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v20_upgrades()
            finally:
                self._conn = original_conn
            # M7.4: add the immutable, owner/task-scoped trusted-verification
            # assessment ledger.  No historical verification result is
            # synthesized from legacy task/test/model state.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v21_upgrades()
            finally:
                self._conn = original_conn
            # M7.5: add the immutable recovery-decision ledger and the
            # descriptive causal projection for recovery-gate applications.
            # No historical recovery decision is synthesized.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v22_upgrades()
            finally:
                self._conn = original_conn
            # M7.6: connect published-plan routing to durable step state and
            # dispatch fencing before any production tool can use the seam.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v23_upgrades()
            finally:
                self._conn = original_conn
            # M7.7: add provenance/source classification and canonical record
            # digest columns.  Existing nodes remain explicitly UNBOUND and
            # are never relabelled as current without evidence.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v24_upgrades()
            finally:
                self._conn = original_conn
            # M7.8: immutable plan-bound sub-agent assignments and run CAS
            # projections.  Legacy subagent_tasks are intentionally not
            # backfilled: their provenance is unbound and cannot become
            # coding authority.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v25_upgrades()
            finally:
                self._conn = original_conn
            # M7.9: capability evaluation is an append-only observation
            # ledger.  It is intentionally not consumed by any authority.
            original_conn = self._conn
            self._conn = _MigrationConnection(conn)
            try:
                await self._apply_v26_upgrades()
            finally:
                self._conn = original_conn
            # Batch 6.4 §10.4: backfill the historical ledger rows (v1–v5)
            # so the chain is complete from this point on.  Idempotent —
            # uses INSERT OR IGNORE keyed on the version PK.
            await self._backfill_historical_ledger_rows(conn, applied_versions)
            # Record the current version with its immutable manifest checksum.
            await conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (
                    version, name, checksum, applied_at, app_version
                ) VALUES (?, ?, ?, datetime('now'), ?)
                """,
                (
                    SCHEMA_MIGRATION_VERSION,
                    SCHEMA_MIGRATION_NAME,
                    checksum,
                    SCHEMA_MIGRATION_APP_VERSION,
                ),
            )
            await conn.commit()
        except BaseException:
            await conn.rollback()
            raise

    async def _backfill_historical_ledger_rows(
        self, conn: Any, applied_versions: set[int]
    ) -> None:
        """Insert missing historical (v1–v5) ledger rows.

        Batch 6.4 §10.4: the registry now covers v1–v6.  Databases that
        pre-date v6 (or fresh DBs) only have whichever single row the
        legacy runner wrote.  This helper idempotently inserts every
        historical version's row with its canonical name and the
        ``HISTORICAL_ACCEPTED`` sentinel checksum, so the ledger tells
        the complete, verifiable story.  ``applied_versions`` lets us skip rows
        that already exist (e.g. a live v5 DB already has its v5 row).

        Batch 7.1 (round-7 §十九): these rows are SYNTHETIC — they were
        never individually applied by a real release runner; they are
        backfilled for ledger completeness.  We mark them honestly by
        writing ``synthetic-backfill`` in the ``app_version`` column (no
        schema change needed — the column already exists) so a future
        audit can distinguish a real applied row from a synthetic one.
        Real release DBs carry their own ``app_version`` from the release
        that created them.
        """
        for spec in MIGRATIONS:
            if spec.version in applied_versions:
                continue
            if spec.version >= SCHEMA_MIGRATION_VERSION:
                # The current version's row is written by the caller (with
                # the real manifest checksum + applied_at), not here.
                continue
            await conn.execute(
                """
                INSERT OR IGNORE INTO schema_migrations (
                    version, name, checksum, applied_at, app_version
                ) VALUES (?, ?, ?, datetime('now'), ?)
                """,
                (
                    spec.version,
                    spec.name,
                    spec.sha256,  # HISTORICAL_ACCEPTED for v1–v5
                    "synthetic-backfill",  # §十九: mark honestly
                ),
            )

    async def _backup_before_migration(self, conn: Any) -> None:
        """Create one non-overwriting recovery snapshot for a legacy DB."""
        if self.path == ":memory:":
            return
        backup_path = Path(
            f"{self.path}.pre-migration-v{SCHEMA_MIGRATION_VERSION}.bak"
        )
        try:
            descriptor = os.open(
                backup_path,
                os.O_CREAT | os.O_EXCL | os.O_WRONLY,
                0o600,
            )
        except FileExistsError:
            return
        os.close(descriptor)
        source = sqlite3.connect(self.path)
        target = sqlite3.connect(backup_path)
        try:
            source.backup(target)
        except Exception:
            source.close()
            target.close()
            backup_path.unlink(missing_ok=True)
            raise
        else:
            source.close()
            target.close()

    @staticmethod
    async def _execute_schema_statements(conn: Any, script: str) -> None:
        """Execute a SQL script without ``executescript``'s implicit commit."""
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if not sqlite3.complete_statement(statement):
                continue
            sql = statement.strip()
            statement = ""
            if not sql or sql.upper().startswith("PRAGMA JOURNAL_MODE"):
                continue
            if sql.upper().startswith("PRAGMA FOREIGN_KEYS"):
                continue
            await conn.execute(sql)
        if statement.strip():
            raise RuntimeError("schema.sql ended with an incomplete statement")

    async def _run_legacy_schema_upgrades(self) -> None:
        """Run all pre-versioning helpers under the outer migration lock."""
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
        await self._ensure_authorization_contexts()
        await self._ensure_memories_principal_columns()
        await self._ensure_audit_log_principal_columns()
        # M4 batch 3.1.16A-3: principal-scoped ownership for coding_tasks.
        await self._ensure_coding_tasks_principal_columns()
        # M4 batch 3.1.16B-1: security-context snapshot for scheduled_tasks.
        await self._ensure_scheduled_tasks_generation_columns()
        # M4 batch 3.1.16A-4-3: durable principal owner for sessions /
        # messages / agent_turns / session_bookmarks.  Legacy rows get
        # ``principal_id='legacy'`` and are hidden from every
        # authenticated principal (fail-closed).
        await self._ensure_sessions_principal_column()
        await self._ensure_messages_principal_column()
        await self._ensure_agent_turns_principal_column()
        await self._ensure_session_bookmarks_principal_column()
        # M4 batch 3.1.16A-5-1 (CRITICAL): project identity closure.
        # Adds ``project_id`` column to the 8 tables missing it.
        # Legacy rows get ``project_id=''`` ("unbound").  A-5-1b will
        # add drift detection (``ctx.project_id != bound_project_id``
        # → fail-closed) so unbound rows are visible but new writes
        # always stamp the live project_id.
        await self._ensure_sessions_project_id_column()
        await self._ensure_messages_project_id_column()
        await self._ensure_agent_turns_project_id_column()
        await self._ensure_session_bookmarks_project_id_column()
        await self._ensure_memories_project_id_column()
        await self._ensure_audit_log_project_id_column()
        await self._ensure_coding_tasks_project_id_column()
        await self._ensure_scheduler_journal_project_id_column()
        await self._ensure_subagent_tasks_principal_column()
        # C-03 (round-4 review): ensure the sessions.summary column exists
        # during migration.  Previously ``save_session_summary`` called
        # ``_ensure_sessions_metadata_column("summary")`` at runtime inside
        # a transaction, which prematurely committed the outer transaction.
        # Now the column is added during migration only; if it's missing
        # at runtime, the SQL UPDATE fails closed (OperationalError).
        await self._ensure_sessions_metadata_column("summary")
        # F-03 (third-round review): the legacy-quarantine triggers are
        # now created by ``0001_post_migration.sql`` (step 3) with literal
        # strings.  SQLite does not allow ``?`` parameter binding inside
        # ``CREATE TRIGGER`` bodies, so the in-Python helper that used
        # ``error = ?`` is removed — the SQL file is the single source
        # of truth for these triggers.
        #
        # F-02 (third-round review): rebuild memories so project_id is
        # part of the UNIQUE constraint.  Must run AFTER
        # _ensure_memories_project_id_column (which adds the column to
        # legacy DBs) and AFTER _ensure_memories_principal_columns
        # (which establishes the base schema).  Idempotent: no-op on
        # fresh v2 DBs where the UNIQUE already includes project_id.
        #
        # F-03 ordering note: this MUST run BEFORE
        # _ensure_session_identity_invariants because the rebuild DROPs
        # the memories table (and SQLite automatically drops all triggers
        # attached to a dropped table).  If the session-identity triggers
        # were created first, the rebuild would silently destroy them and
        # leave memories without identity-guard enforcement.
        await self._ensure_memories_project_id_unique()
        await self._ensure_session_identity_invariants()
        # H-09 (round-5 Batch 5.3): rebuild principal_modes so project_id
        # is part of the PRIMARY KEY.  Closes cross-project mode leakage
        # on shared DBs (Project A's coding mode would otherwise be
        # loaded by Project B for the same principal).  Idempotent: a
        # no-op on fresh v4 DBs whose PK already includes project_id.
        await self._ensure_principal_modes_project_id_pk()
        # Round-6 Batch 6.1: rebuild chat_streams and chat_stream_events
        # so they are keyed by stream_id (one per chat RPC attempt)
        # instead of session_id.  This fixes the multi-turn conversation
        # breakage where a session was permanently locked to 'done'
        # after the first turn.  Idempotent: no-op on fresh v5 DBs.
        await self._ensure_chat_streams_stream_id_pk()

    async def _ensure_principal_modes_project_id_pk(self) -> None:
        """H-09 (round-5 Batch 5.3): rebuild ``principal_modes`` so
        ``project_id`` is part of the PRIMARY KEY.

        The pre-H-09 PK was ``(principal_id, session_id)`` —
        ``project_id`` did not exist.  When two projects share a state DB
        (via explicit ``--db``), Project B could load Project A's coding
        mode for the same principal, leaking System Prompt / Tool
        Availability / Routing decisions across the project boundary.

        H-09 makes the PK ``(project_id, principal_id, session_id)`` so
        each project gets its own mode rows.  SQLite cannot ALTER a
        PRIMARY KEY, so the table is rebuilt: old data is backed up, the
        table is dropped and recreated with the new schema, and the data
        is re-inserted with ``project_id=''`` (legacy / unbound).  The
        rebuild is idempotent: if the PK already includes ``project_id``
        (fresh DB created with the v4 schema), the method returns
        immediately.
        """
        conn = await self._require_conn()
        # Idempotency check: inspect the table's CREATE SQL.  If the PK
        # already covers project_id, the rebuild is a no-op.
        cursor = await conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='principal_modes'"
        )
        row = await cursor.fetchone()
        if row is None:
            return  # Table doesn't exist yet (shouldn't happen post-schema)
        create_sql = str(row[0])
        if "PRIMARY KEY (project_id, principal_id, session_id)" in create_sql:
            return  # Already migrated (fresh v4 schema)
        # Backup old data.
        await conn.execute(
            "CREATE TABLE _principal_modes_h09_backup AS "
            "SELECT * FROM principal_modes"
        )
        try:
            await conn.execute("DROP TABLE principal_modes")
            await conn.execute(
                """
                CREATE TABLE principal_modes (
                    principal_id TEXT NOT NULL,
                    project_id   TEXT NOT NULL DEFAULT '',
                    session_id   TEXT NOT NULL DEFAULT '',
                    mode         TEXT NOT NULL,
                    updated_at   TEXT NOT NULL DEFAULT (datetime('now')),
                    PRIMARY KEY (project_id, principal_id, session_id)
                )
                """
            )
            # Re-insert legacy rows with project_id='' (unbound).
            await conn.execute(
                """
                INSERT INTO principal_modes
                    (principal_id, project_id, session_id, mode, updated_at)
                SELECT principal_id, '', session_id, mode, updated_at
                FROM _principal_modes_h09_backup
                """
            )
        finally:
            await conn.execute("DROP TABLE _principal_modes_h09_backup")
        await conn.commit()

    async def _ensure_chat_streams_stream_id_pk(self) -> None:
        """Round-6 Batch 6.1: rebuild ``chat_streams`` and
        ``chat_stream_events`` so they are keyed by ``stream_id``
        (one per chat RPC attempt) instead of ``session_id``.

        Pre-6.1 schema used ``session_id`` as the PRIMARY KEY of
        ``chat_streams`` and as the first column of the
        ``chat_stream_events`` PK.  This meant a session could only
        have ONE stream — once it reached ``done``, the Terminal Shield
        rejected any subsequent ``started`` event, breaking multi-turn
        conversations.

        6.1 introduces ``stream_id`` (uuid4 per chat RPC) as the
        primary key.  A session can now have many streams, each with
        its own Terminal lifecycle.

        Migration strategy (SQLite cannot ALTER PK in-place):
          1. Check if ``chat_streams`` already has ``stream_id`` as PK
             (fresh v5 DB) — if so, no-op.
          2. Create ``_chat_streams_v5`` and ``_chat_stream_events_v5``
             with the new schema.
          3. Copy data: legacy rows get ``stream_id = session_id``
             (each legacy session had at most one stream).
          4. Drop old tables, rename new tables.
          5. Recreate indexes.

        Idempotent: safe to run on fresh v5 DBs (detected via PK check).
        """
        conn = await self._require_conn()
        # Idempotency check: inspect chat_streams CREATE SQL.
        cursor = await conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='chat_streams'"
        )
        row = await cursor.fetchone()
        await cursor.close()
        if row is None:
            return  # Table doesn't exist yet (shouldn't happen post-schema)
        create_sql = str(row[0])
        if "stream_id TEXT PRIMARY KEY" in create_sql:
            return  # Already migrated (fresh v5 schema)

        logger.info(
            "Batch 6.1: migrating chat_streams/chat_stream_events "
            "from session_id PK to stream_id PK"
        )

        # Step 1: create new tables with _v5 suffix.
        await conn.execute(
            """
            CREATE TABLE _chat_streams_v5 (
                stream_id           TEXT PRIMARY KEY,
                session_id          TEXT NOT NULL,
                turn_id             TEXT NOT NULL DEFAULT '',
                attempt_id          TEXT NOT NULL DEFAULT '',
                principal_id        TEXT NOT NULL,
                project_id          TEXT NOT NULL DEFAULT '',
                status              TEXT NOT NULL DEFAULT 'running'
                    CHECK(status IN ('running','done','error','interrupted')),
                boot_id             TEXT NOT NULL DEFAULT '',
                runtime_id          TEXT NOT NULL DEFAULT '',
                lease_until         REAL,
                last_sequence       INTEGER NOT NULL DEFAULT 0,
                terminal_event_type TEXT,
                started_at          REAL NOT NULL,
                terminal_at         REAL,
                FOREIGN KEY(session_id, principal_id, project_id)
                    REFERENCES sessions(id, principal_id, project_id)
            )
            """
        )
        await conn.execute(
            """
            CREATE TABLE _chat_stream_events_v5 (
                stream_id    TEXT NOT NULL,
                session_id   TEXT NOT NULL,
                principal_id TEXT NOT NULL,
                project_id   TEXT NOT NULL DEFAULT '',
                sequence     INTEGER NOT NULL,
                event_type   TEXT NOT NULL,
                data_json    TEXT NOT NULL DEFAULT '{}',
                is_terminal  INTEGER NOT NULL DEFAULT 0 CHECK(is_terminal IN (0, 1)),
                created_at   REAL NOT NULL,
                PRIMARY KEY(stream_id, sequence),
                FOREIGN KEY(session_id, principal_id, project_id)
                    REFERENCES sessions(id, principal_id, project_id)
            )
            """
        )

        # Step 2: copy data.  Legacy rows: stream_id = session_id
        # (each legacy session had at most one stream).
        await conn.execute(
            """
            INSERT INTO _chat_streams_v5 (
                stream_id, session_id, turn_id, attempt_id,
                principal_id, project_id, status, boot_id,
                runtime_id, lease_until, last_sequence,
                terminal_event_type, started_at, terminal_at
            )
            SELECT
                session_id, session_id, '', '',
                principal_id, project_id, status, boot_id,
                runtime_id, lease_until, last_sequence,
                terminal_event_type, started_at, terminal_at
            FROM chat_streams
            """
        )
        await conn.execute(
            """
            INSERT INTO _chat_stream_events_v5 (
                stream_id, session_id, principal_id, project_id,
                sequence, event_type, data_json, is_terminal, created_at
            )
            SELECT
                session_id, session_id, principal_id, project_id,
                sequence, event_type, data_json, is_terminal, created_at
            FROM chat_stream_events
            """
        )

        # Step 3: drop old tables, rename new tables.
        await conn.execute("DROP TABLE chat_streams")
        await conn.execute("DROP TABLE chat_stream_events")
        await conn.execute("ALTER TABLE _chat_streams_v5 RENAME TO chat_streams")
        await conn.execute(
            "ALTER TABLE _chat_stream_events_v5 RENAME TO chat_stream_events"
        )

        # Step 4: recreate indexes (from 0001_post_migration.sql).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_stream_events_owner "
            "ON chat_stream_events(principal_id, project_id, session_id, sequence)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_stream_events_stream "
            "ON chat_stream_events(stream_id, sequence)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_streams_session "
            "ON chat_streams(session_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_streams_boot "
            "ON chat_streams(boot_id, status)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_chat_streams_status_lease "
            "ON chat_streams(status, lease_until)"
        )
        await conn.commit()
        logger.info("Batch 6.1: chat_streams migration complete")

    async def _apply_v7_upgrades(self) -> None:
        """Batch 7.2 (round-7 §十四): apply v7 schema deltas.

        Called by ``run_migrations`` AFTER the v6 aggregate (initial schema
        + legacy upgrades + post-migration), so v6's frozen manifest is
        untouched.  v7 adds the session-global ``event_id`` column to
        ``chat_stream_events`` — a true monotonic replay cursor that does
        not collide across streams (the stream-local ``sequence`` did).
        """
        await self._ensure_chat_event_id_column()

    async def _ensure_chat_event_id_column(self) -> None:
        """Batch 7.2 (round-7 §十四): add ``event_id INTEGER PRIMARY KEY
        AUTOINCREMENT`` to ``chat_stream_events``.

        SQLite ``ALTER TABLE ... ADD COLUMN`` cannot add a PRIMARY KEY
        AUTOINCREMENT to an existing table, so on old DBs (pre-v7, where
        the PK was the composite ``(stream_id, sequence)``) we rebuild the
        table.  On fresh v7 DBs the column already exists (the
        ``schema.sql`` reference defines it).  Idempotent: a no-op when
        the column is already present.

        The ``event_id`` is a session-global monotonic cursor: each
        appended event gets the next autoincrement value regardless of
        which stream it belongs to, so session-wide replay (``event_id >
        ?``) never misses events from streams whose stream-local
        ``sequence`` is <= the cursor.
        """
        conn = await self._require_conn()
        cols = await (await conn.execute(
            "PRAGMA table_info(chat_stream_events)"
        )).fetchall()
        col_names = {str(c["name"]) for c in cols}
        if "event_id" in col_names:
            return  # already migrated (fresh v7 DB or already applied)
        # Rebuild with event_id as INTEGER PRIMARY KEY AUTOINCREMENT.
        # Preserve all existing data; event_id becomes the rowid alias.
        logger.info("Batch 7.2: adding event_id to chat_stream_events")
        await conn.execute(
            "CREATE TABLE _chat_stream_events_v7 AS "
            "SELECT * FROM chat_stream_events"
        )
        try:
            await conn.execute("DROP TABLE chat_stream_events")
            await conn.execute(
                """
                CREATE TABLE chat_stream_events (
                    event_id     INTEGER PRIMARY KEY AUTOINCREMENT,
                    stream_id    TEXT NOT NULL,
                    session_id   TEXT NOT NULL,
                    principal_id TEXT NOT NULL,
                    project_id   TEXT NOT NULL DEFAULT '',
                    sequence     INTEGER NOT NULL,
                    event_type   TEXT NOT NULL,
                    data_json    TEXT NOT NULL DEFAULT '{}',
                    is_terminal  INTEGER NOT NULL DEFAULT 0
                        CHECK(is_terminal IN (0, 1)),
                    created_at   REAL NOT NULL,
                    UNIQUE(stream_id, sequence),
                    FOREIGN KEY(session_id, principal_id, project_id)
                        REFERENCES sessions(id, principal_id, project_id)
                )
                """
            )
            await conn.execute(
                "INSERT INTO chat_stream_events "
                "(stream_id, session_id, principal_id, project_id, "
                "sequence, event_type, data_json, is_terminal, created_at) "
                "SELECT stream_id, session_id, principal_id, project_id, "
                "sequence, event_type, data_json, is_terminal, created_at "
                "FROM _chat_stream_events_v7 "
                "ORDER BY created_at, stream_id, sequence"
            )
            await conn.execute("DROP TABLE _chat_stream_events_v7")
            # Rebuild indexes (the old PK indexes were dropped with the table).
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_stream_events_owner "
                "ON chat_stream_events(principal_id, project_id, "
                "session_id, event_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_stream_events_stream "
                "ON chat_stream_events(stream_id, event_id)"
            )
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_chat_stream_events_session "
                "ON chat_stream_events(session_id, principal_id, "
                "project_id, event_id)"
            )
        except BaseException:
            # Restore the backup if the rebuild failed mid-way.
            await conn.execute("DROP TABLE IF EXISTS chat_stream_events")
            await conn.execute(
                "ALTER TABLE _chat_stream_events_v7 RENAME TO "
                "chat_stream_events"
            )
            raise
        await conn.commit()
        logger.info("Batch 7.2: chat_stream_events event_id migration complete")

    async def _apply_v8_upgrades(self) -> None:
        """Round-14 §4: apply v8 schema deltas — audit_log tamper protection.

        Called by ``run_migrations`` AFTER the v6 aggregate + v7 deltas, so
        the v6/v7 frozen manifests are untouched.  v8 adds the ``prev_hash``
        column to ``audit_log`` (hash-chain) and the append-only
        BEFORE DELETE / BEFORE UPDATE triggers, plus backfills ``prev_hash``
        for pre-existing rows so the chain is continuous from genesis.
        """
        await self._ensure_audit_log_tamper_protection()

    async def _ensure_audit_log_tamper_protection(self) -> None:
        """Round-14 §4: add ``prev_hash`` + append-only triggers to audit_log.

        Idempotent.  On a fresh v8 DB the column and triggers already exist
        (``schema.sql`` / ``0001_post_migration.sql`` define them).  On an
        upgraded DB we add the column (default '' so existing rows are
        chain-break markers) and create the triggers.

        The hash chain itself is maintained in ``insert_audit_log``: each
        new row hashes (prev_hash || canonical fields).  Pre-v8 rows keep
        ``prev_hash=''`` and remain readable; the chain is trusted from the
        first post-v8 row forward (genesis sentinel hashes the empty prev).
        """
        conn = await self._require_conn()
        cols = await (await conn.execute(
            "PRAGMA table_info(audit_log)"
        )).fetchall()
        col_names = {str(c["name"]) for c in cols}
        if "prev_hash" not in col_names:
            logger.info("Round-14 §4: adding prev_hash to audit_log")
            await conn.execute(
                "ALTER TABLE audit_log ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''"
            )
        # Append-only triggers (idempotent — CREATE TRIGGER IF NOT EXISTS).
        await conn.execute(
            "CREATE TRIGGER IF NOT EXISTS trg_audit_log_append_only_delete "
            "BEFORE DELETE ON audit_log BEGIN "
            "SELECT RAISE(ABORT, 'audit_log is append-only: rows cannot be deleted'); "
            "END"
        )
        await conn.execute(
            "CREATE TRIGGER IF NOT EXISTS trg_audit_log_append_only_update "
            "BEFORE UPDATE ON audit_log BEGIN "
            "SELECT RAISE(ABORT, 'audit_log is append-only: rows cannot be updated'); "
            "END"
        )
        await conn.commit()

    async def _apply_v9_upgrades(self) -> None:
        """Round-15 A-2: apply v9 schema deltas — audit_log INSERT guard.

        Closes the INSERT-reset bypass of the Round-14 §4 hash chain: a
        ``BEFORE INSERT`` trigger now refuses a row whose ``prev_hash`` is
        empty unless the table is empty (the genesis row).  Combined with
        the DELETE/UPDATE triggers from v8, this means an attacker with a
        write connection cannot INSERT a forged "genesis reset" row to
        hide prior tampering — the only accepted reset is the genuinely
        first row.
        """
        await self._ensure_audit_log_insert_guard()

    async def _apply_v10_upgrades(self) -> None:
        """Phase-1 Authority Scope Closure for persistent permissions."""
        await self._ensure_permissions_scope_columns()

    async def _apply_v11_upgrades(self) -> None:
        """P1-4: add typed resource fields to persistent permissions."""
        await self._ensure_permission_resource_columns()

    async def _apply_v12_upgrades(self) -> None:
        """Security closure: add the durable tool-operation journal."""
        await self._ensure_tool_operations_table()

    async def _apply_v13_upgrades(self) -> None:
        """Create the Memory V2 canonical ledger and derived projections."""
        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0013_memory_v2.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v14_upgrades(self) -> None:
        """Add Memory V2 operational storage without editing the v13 schema."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0014_memory_v2_operational_surfaces.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )
        await self._ensure_memory_nodes_superseded_at()

    async def _apply_v15_upgrades(self) -> None:
        """Add atomic projection, privacy, and resumable maintenance state."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0015_memory_v2_closure.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v16_upgrades(self) -> None:
        """Create and backfill the M7.1.2 immutable GoalSpec contract."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0016_goal_specs.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )
        await self._backfill_legacy_goal_specs(conn)

    async def _apply_v17_upgrades(self) -> None:
        """Add the M7.1.3 independent cognitive-state CAS columns."""

        conn = await self._require_conn()
        await self._ensure_coding_tasks_cognitive_state_columns(conn)

    async def _apply_v18_upgrades(self) -> None:
        """Add the M7.1.4 immutable completion-decision ledger."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0018_completion_decisions.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v19_upgrades(self) -> None:
        """Add the M7.3 immutable deterministic planning ledger."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0019_plan_revisions.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v20_upgrades(self) -> None:
        """Add the M7.3 atomic plan-publication projection."""

        conn = await self._require_conn()
        await self._ensure_coding_tasks_published_plan_revision_column(conn)
        migration_path = _MIGRATIONS_DIR / "0020_plan_publication_fence.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v21_upgrades(self) -> None:
        """Add the M7.4 immutable trusted-verification assessment ledger."""

        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0021_trusted_verification_assessments.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v22_upgrades(self) -> None:
        """Add the M7.5 immutable recovery ledger and causal projection."""

        conn = await self._require_conn()
        await self._ensure_coding_tasks_last_applied_recovery_decision_column(conn)
        migration_path = _MIGRATIONS_DIR / "0022_recovery_control_plane.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v23_upgrades(self) -> None:
        """Add the M7.6 route, step-state, and dispatch-fence ledgers."""
        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0023_plan_tool_routing.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _apply_v24_upgrades(self) -> None:
        """Add additive provenance metadata for bounded M7.7 retrieval."""
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(memory_nodes)")
        columns = {str(row["name"]) for row in await cursor.fetchall()}
        additions = (
            (
                "source_kind",
                "ALTER TABLE memory_nodes ADD COLUMN source_kind "
                "TEXT NOT NULL DEFAULT 'UNBOUND'",
            ),
            (
                "provenance_json",
                "ALTER TABLE memory_nodes ADD COLUMN provenance_json "
                "TEXT NOT NULL DEFAULT '{}'",
            ),
            (
                "record_digest",
                "ALTER TABLE memory_nodes ADD COLUMN record_digest "
                "TEXT NOT NULL DEFAULT ''",
            ),
        )
        for name, statement in additions:
            if name not in columns:
                await conn.execute(statement)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memory_nodes_retrieval_scope "
            "ON memory_nodes(project_id, principal_id, namespace, session_id, "
            "source_kind, status, updated_at, memory_id)"
        )

    async def _apply_v25_upgrades(self) -> None:
        """Add M7.8 assignment/run ledgers and route actor identity."""
        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0025_plan_bound_subagents.sql"
        text = migration_path.read_text(encoding="utf-8")
        # Execute the CREATE statements through the normal statement parser;
        # trigger bodies contain semicolons and must not be split manually.
        create_text = "\n".join(
            line for line in text.splitlines()
            if not line.lstrip().upper().startswith("ALTER TABLE AGENT_PLAN_TOOL_ROUTES")
        )
        await self._execute_schema_statements(conn, create_text)
        cursor = await conn.execute("PRAGMA table_info(agent_plan_tool_routes)")
        columns = {str(row["name"]) for row in await cursor.fetchall()}
        additions = (
            ("task_owner_principal_id", "TEXT NOT NULL DEFAULT ''"),
            ("execution_principal_id", "TEXT NOT NULL DEFAULT ''"),
            ("subagent_assignment_id", "TEXT"),
            ("subagent_assignment_digest", "TEXT"),
        )
        for name, declaration in additions:
            if name not in columns:
                await conn.execute(
                    f"ALTER TABLE agent_plan_tool_routes ADD COLUMN {name} {declaration}"
                )

    async def _apply_v26_upgrades(self) -> None:
        """Add the immutable M7.9 capability-evaluation observation ledger."""
        conn = await self._require_conn()
        migration_path = _MIGRATIONS_DIR / "0026_capability_evaluations.sql"
        await self._execute_schema_statements(
            conn,
            migration_path.read_text(encoding="utf-8"),
        )

    async def _ensure_coding_tasks_last_applied_recovery_decision_column(
        self, conn: Any
    ) -> None:
        """Add the descriptive recovery-gate causal projection once.

        The column records which durable RecoveryDecision caused the last
        recovery control transition.  It is not a capability, approval, or
        lifecycle authority, and legacy rows remain NULL.
        """
        cursor = await conn.execute("PRAGMA table_info(coding_tasks)")
        columns = {str(row["name"]) for row in await cursor.fetchall()}
        if "last_applied_recovery_decision_id" in columns:
            return
        await conn.execute(
            "ALTER TABLE coding_tasks ADD COLUMN last_applied_recovery_decision_id TEXT"
        )

    async def _ensure_coding_tasks_published_plan_revision_column(
        self, conn: Any
    ) -> None:
        """Idempotently add the v20 published-plan identity column.

        SQLite has no portable ``ADD COLUMN IF NOT EXISTS``.  The helper is
        deliberately limited to this one additive column and performs no
        inference from task status, plan history, or model output.  A legacy
        task therefore starts with ``NULL``: it has no published plan until a
        planning publication transaction records one.
        """
        cursor = await conn.execute("PRAGMA table_info(coding_tasks)")
        columns = {str(row["name"]) for row in await cursor.fetchall()}
        if "published_plan_revision_id" in columns:
            return
        await conn.execute(
            "ALTER TABLE coding_tasks ADD COLUMN published_plan_revision_id TEXT"
        )

    async def _ensure_coding_tasks_cognitive_state_columns(
        self, conn: Any
    ) -> None:
        """Idempotently add the v17 control-state columns.

        The normal path executes the checked-in v17 SQL artifact verbatim.
        The per-column fallback handles a process that was interrupted after
        one additive ALTER in a non-versioned/hand-repaired database.  Only
        the two exact v17 columns are accepted; no task history is used to
        infer a cognitive phase.
        """
        cursor = await conn.execute("PRAGMA table_info(coding_tasks)")
        columns = {str(row["name"]) for row in await cursor.fetchall()}
        required = {"cognitive_state", "control_state_version"}
        missing = required - columns
        if not missing:
            return

        migration_path = _MIGRATIONS_DIR / "0017_agent_cognitive_state.sql"
        migration_sql = migration_path.read_text(encoding="utf-8")
        if missing == required:
            await self._execute_schema_statements(conn, migration_sql)
            return

        # SQLite has no portable ``ADD COLUMN IF NOT EXISTS``.  When a
        # partial additive operation is observed, execute only the missing
        # statement while retaining the same schema contract as the artifact.
        if "cognitive_state" in missing:
            await conn.execute(
                "ALTER TABLE coding_tasks ADD COLUMN cognitive_state TEXT "
                "NOT NULL DEFAULT 'uninitialized' CHECK (cognitive_state IN "
                "('uninitialized', 'understanding', 'exploring', 'planning', "
                "'implementing', 'verifying', 'diagnosing', 'recovering', "
                "'replanning', 'reviewing', 'completion_check'))"
            )
        if "control_state_version" in missing:
            await conn.execute(
                "ALTER TABLE coding_tasks ADD COLUMN control_state_version "
                "INTEGER NOT NULL DEFAULT 0 CHECK (control_state_version >= 0)"
            )

    async def _backfill_legacy_goal_specs(self, conn: Any) -> None:
        """Backfill and validate one conservative GoalSpec per task.

        This method runs inside the outer migration transaction.  It uses
        direct SQL intentionally: invoking a repository transaction here
        would create a second transaction owner during migration.  Existing
        canonical rows are validated, never replaced; missing projection
        references are added to ``coding_tasks.state_json`` only.
        """
        from khaos.agent.control.goal import GoalSpec

        task_cursor = await conn.execute(
            """
            SELECT id, goal, state_json, principal_id, project_id
            FROM coding_tasks
            ORDER BY id
            """
        )
        task_rows = await task_cursor.fetchall()
        for task_row in task_rows:
            task_id = task_row["id"]
            raw_goal = task_row["goal"]
            principal_id = task_row["principal_id"]
            project_id = task_row["project_id"]
            if (
                type(task_id) is not str
                or not task_id
                or type(raw_goal) is not str
                or not raw_goal
                or type(principal_id) is not str
                or not principal_id
                or type(project_id) is not str
            ):
                raise RuntimeError(
                    f"cannot backfill GoalSpec for malformed coding task {task_id!r}"
                )
            try:
                state = json.loads(str(task_row["state_json"]))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise RuntimeError(
                    f"coding task {task_id!r} has malformed state_json; "
                    "GoalSpec backfill refused"
                ) from exc
            if type(state) is not dict:
                raise RuntimeError(
                    f"coding task {task_id!r} state_json is not an object; "
                    "GoalSpec backfill refused"
                )
            state_goal = state.get("goal")
            if state_goal is not None and (
                type(state_goal) is not str or state_goal != raw_goal
            ):
                raise RuntimeError(
                    f"coding task {task_id!r} goal projection disagrees with row"
                )

            spec_cursor = await conn.execute(
                """
                SELECT goal_spec_id, task_id, principal_id, project_id,
                       schema_version, semantic_digest, canonical_json
                FROM agent_goal_specs
                WHERE task_id = ?
                """,
                (task_id,),
            )
            spec_row = await spec_cursor.fetchone()
            if spec_row is None:
                # The task id is part of the identity only for persistence;
                # it is deliberately excluded from semantic_digest.
                spec = GoalSpec.from_user_goal(
                    raw_goal,
                    goal_spec_id=f"legacy-{task_id}",
                )
                try:
                    await conn.execute(
                        """
                        INSERT INTO agent_goal_specs (
                            goal_spec_id, task_id, principal_id, project_id,
                            schema_version, semantic_digest, canonical_json, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            spec.goal_spec_id,
                            task_id,
                            principal_id,
                            project_id,
                            spec.schema_version,
                            spec.semantic_digest,
                            spec.canonical_json(),
                            utc_now_naive().isoformat(),
                        ),
                    )
                except sqlite3.IntegrityError as exc:
                    raise RuntimeError(
                        f"GoalSpec backfill conflict for coding task {task_id!r}"
                    ) from exc
            else:
                if (
                    type(spec_row["goal_spec_id"]) is not str
                    or not spec_row["goal_spec_id"]
                    or type(spec_row["task_id"]) is not str
                    or not spec_row["task_id"]
                    or type(spec_row["principal_id"]) is not str
                    or not spec_row["principal_id"]
                    or type(spec_row["project_id"]) is not str
                    or type(spec_row["semantic_digest"]) is not str
                    or not spec_row["semantic_digest"]
                    or type(spec_row["canonical_json"]) is not str
                    or type(spec_row["schema_version"]) is not int
                ):
                    raise RuntimeError(
                        f"GoalSpec row for coding task {task_id!r} has invalid owner, identity, or payload fields"
                    )
                if (
                    spec_row["task_id"] != task_id
                    or spec_row["principal_id"] != principal_id
                    or spec_row["project_id"] != project_id
                ):
                    raise RuntimeError(
                        f"GoalSpec owner/task mismatch for coding task {task_id!r}"
                    )
                try:
                    spec = GoalSpec.from_canonical_json(
                        spec_row["canonical_json"],
                        expected_digest=spec_row["semantic_digest"],
                    )
                except (TypeError, ValueError) as exc:
                    raise RuntimeError(
                        f"GoalSpec row for coding task {task_id!r} failed integrity validation"
                    ) from exc
                if (
                    spec.schema_version != spec_row["schema_version"]
                    or spec.raw_goal != raw_goal
                    or spec.goal_spec_id != spec_row["goal_spec_id"]
                ):
                    raise RuntimeError(
                        f"GoalSpec row for coding task {task_id!r} disagrees with task"
                    )

            expected_id = spec.goal_spec_id
            expected_digest = spec.semantic_digest
            for field_name, expected_value in (
                ("goal_spec_id", expected_id),
                ("goal_spec_digest", expected_digest),
            ):
                projected_value = state.get(field_name)
                if projected_value is not None and projected_value != expected_value:
                    raise RuntimeError(
                        f"coding task {task_id!r} has conflicting {field_name} projection"
                    )
            if (
                state.get("goal_spec_id") != expected_id
                or state.get("goal_spec_digest") != expected_digest
            ):
                state["goal_spec_id"] = expected_id
                state["goal_spec_digest"] = expected_digest
                await conn.execute(
                    "UPDATE coding_tasks SET state_json = ? WHERE id = ?",
                    (
                        json.dumps(
                            state,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        task_id,
                    ),
                )

        orphan_cursor = await conn.execute(
            """
            SELECT specs.goal_spec_id
            FROM agent_goal_specs AS specs
            LEFT JOIN coding_tasks AS tasks ON tasks.id = specs.task_id
            WHERE tasks.id IS NULL
            """
        )
        orphan = await orphan_cursor.fetchone()
        if orphan is not None:
            raise RuntimeError(
                f"orphan GoalSpec {str(orphan['goal_spec_id'])!r} detected"
            )

    async def _ensure_memory_nodes_superseded_at(self) -> None:
        """Add the temporal supersession marker to existing v13 databases."""

        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(memory_nodes)")
        columns = {str(row[1]) for row in await cursor.fetchall()}
        if "superseded_at" not in columns:
            await conn.execute(
                "ALTER TABLE memory_nodes ADD COLUMN superseded_at TEXT"
            )
        await conn.execute(
            "UPDATE memory_nodes SET superseded_at = updated_at "
            "WHERE status = 'SUPERSEDED' AND superseded_at IS NULL"
        )

    async def _ensure_tool_operations_table(self) -> None:
        """Create the crash/replay-safe tool operation journal."""
        conn = await self._require_conn()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS tool_operations (
                operation_id       TEXT PRIMARY KEY,
                tool_name          TEXT NOT NULL,
                arguments_digest   TEXT NOT NULL,
                status             TEXT NOT NULL
                    CHECK (status IN ('running', 'completed', 'unknown')),
                effect_id          TEXT NOT NULL,
                effect_status      TEXT NOT NULL,
                reconciliation_hint TEXT NOT NULL DEFAULT '',
                result_json        TEXT NOT NULL DEFAULT '',
                owner_token        TEXT NOT NULL,
                principal_id       TEXT NOT NULL DEFAULT '',
                project_id         TEXT NOT NULL DEFAULT '',
                session_id         TEXT NOT NULL DEFAULT '',
                task_id            TEXT NOT NULL DEFAULT '',
                workspace_id       TEXT NOT NULL DEFAULT '',
                created_at         TEXT NOT NULL,
                updated_at         TEXT NOT NULL
            )
            """
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_operations_status "
            "ON tool_operations(status, updated_at)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_operations_owner "
            "ON tool_operations(principal_id, project_id, session_id)"
        )
        await conn.commit()

    async def _ensure_audit_log_insert_guard(self) -> None:
        """Round-15 A-2: add the BEFORE INSERT genesis guard to audit_log.

        Idempotent (``CREATE TRIGGER IF NOT EXISTS``).  The trigger rejects
        an INSERT whose ``NEW.prev_hash`` is empty when the table already
        has at least one row.  The very first row (empty table) is allowed
        to carry an empty ``prev_hash`` because it IS the genesis.  This
        keeps ``verify_audit_chain``'s genesis-reset handling sound: the
        only legitimate empty ``prev_hash`` is on row id=1.
        """
        conn = await self._require_conn()
        await conn.execute(
            "CREATE TRIGGER IF NOT EXISTS trg_audit_log_genesis_guard "
            "BEFORE INSERT ON audit_log "
            "WHEN NEW.prev_hash = '' AND EXISTS (SELECT 1 FROM audit_log) "
            "BEGIN "
            "SELECT RAISE(ABORT, 'audit_log prev_hash may be empty only on the genesis row'); "
            "END"
        )
        await conn.commit()

    async def _ensure_session_identity_invariants(self) -> None:
        """Make SQLite enforce duplicated session identity on every write."""
        conn = await self._require_conn()
        await conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_identity "
            "ON sessions(id, principal_id, project_id)"
        )
        children = (
            ("messages", "session_id", None),
            ("agent_turns", "session_id", None),
            ("session_bookmarks", "session_id", None),
            ("subagent_tasks", "parent_session_id", None),
            ("audit_log", "session_id", "NEW.session_id IS NOT NULL"),
            ("memories", "session_id", "NEW.namespace = 'session'"),
        )
        for table, session_column, condition in children:
            guard = f"({condition}) AND " if condition else ""
            for operation in ("INSERT", "UPDATE"):
                trigger = f"trg_{table}_session_identity_{operation.lower()}"
                await conn.execute(
                    f"""
                    CREATE TRIGGER IF NOT EXISTS {trigger}
                    BEFORE {operation} ON {table}
                    WHEN {guard}NOT EXISTS (
                        SELECT 1 FROM sessions AS s
                        WHERE s.id = NEW.{session_column}
                          AND s.principal_id = NEW.principal_id
                          AND s.project_id = NEW.project_id
                    )
                    BEGIN
                        SELECT RAISE(ABORT, 'session identity mismatch');
                    END
                    """
                )
        await conn.commit()

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

    async def _ensure_scheduled_tasks_generation_columns(self) -> None:
        """M4 batch 3.1.16B-1 (CRITICAL): add ``policy_digest`` and
        ``project_id`` columns to ``scheduled_tasks`` for security-
        context snapshotting.

        Every task now captures the ``EffectiveSecurityPolicy.digest``
        and ``project_id`` (``sha256(realpath(project_root))[:32]``)
        at creation time.  B-2 will compare these against the live
        values at ``start()`` and ``_execute_task`` claim time to
        detect policy/project drift — a task created under policy A
        must NOT silently execute under policy B if the user tightened
        security between creation and firing.

        Legacy rows (pre-B-1) have empty ``policy_digest``.  Unlike
        the ``principal_id='legacy'`` quarantine in batch 3.1.12,
        B-1 does NOT quarantine legacy rows at migration time —
        because new tasks created without a ``policy_digest`` (e.g.
        by test engines) also have empty ``policy_digest``, so a
        migration-time quarantine would catch them too.  Instead,
        B-2 adds drift-detection enforcement in ``start()`` and
        ``_execute_task`` that quarantines tasks with empty or
        mismatched ``policy_digest`` at load / claim time, when the
        engine's bound ``policy_digest`` is known.  This cleanly
        separates schema (B-1) from enforcement (B-2).
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(scheduled_tasks)")
        columns = {row[1] for row in await cursor.fetchall()}
        added = False
        if "policy_digest" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks "
                "ADD COLUMN policy_digest TEXT NOT NULL DEFAULT ''"
            )
            added = True
        if "project_id" not in columns:
            await conn.execute(
                "ALTER TABLE scheduled_tasks "
                "ADD COLUMN project_id TEXT NOT NULL DEFAULT ''"
            )
            added = True
        if added:
            await conn.commit()
        # Policy-scoped lookup index (idempotent).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_scheduled_tasks_policy "
            "ON scheduled_tasks(policy_digest, status)"
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
            "DROP INDEX IF EXISTS idx_permissions_principal"
        )
        await conn.execute(
            "CREATE INDEX idx_permissions_principal "
            "ON permissions(principal_id, project_id, policy_digest, "
            "generation, mode, permission_level)"
        )
        await conn.commit()

    async def _ensure_permissions_scope_columns(self) -> None:
        """Add transport/lifetime scope columns for permission grants.

        Phase-1 Authority Scope Closure: existing permission rows are
        deliberately migrated to the restrictive interactive-project scope.
        They must be explicitly re-granted if an administrator intends them
        to apply to unattended transports; a schema upgrade must not widen an
        existing approval authority.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(permissions)")
        columns = {row[1] for row in await cursor.fetchall()}
        additions = (
            (
                "transport_class",
                "ALTER TABLE permissions ADD COLUMN transport_class "
                "TEXT NOT NULL DEFAULT 'interactive'",
            ),
            (
                "grant_lifetime",
                "ALTER TABLE permissions ADD COLUMN grant_lifetime "
                "TEXT NOT NULL DEFAULT 'project_interactive'",
            ),
            (
                "session_id",
                "ALTER TABLE permissions ADD COLUMN session_id "
                "TEXT NOT NULL DEFAULT ''",
            ),
            (
                "task_id",
                "ALTER TABLE permissions ADD COLUMN task_id "
                "TEXT NOT NULL DEFAULT ''",
            ),
            (
                "workspace_id",
                "ALTER TABLE permissions ADD COLUMN workspace_id "
                "TEXT NOT NULL DEFAULT ''",
            ),
            (
                "expires_at",
                "ALTER TABLE permissions ADD COLUMN expires_at REAL",
            ),
            (
                "created_by",
                "ALTER TABLE permissions ADD COLUMN created_by "
                "TEXT NOT NULL DEFAULT 'migration:legacy'",
            ),
        )
        for name, statement in additions:
            if name not in columns:
                await conn.execute(statement)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_permissions_scope "
            "ON permissions(principal_id, project_id, policy_digest, "
            "generation, transport_class, grant_lifetime, session_id, task_id)"
        )
        await conn.commit()

    async def _ensure_permission_resource_columns(self) -> None:
        """Add typed resource fields without widening legacy authority.

        Existing rows remain empty and are interpreted by the permission
        engine: non-relaxing legacy globs remain enforcement rules, while
        relaxing rows are converted only when their syntax is unambiguous.
        Ambiguous legacy relaxing rows are quarantined on load.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(permissions)")
        columns = {row[1] for row in await cursor.fetchall()}
        additions = (
            (
                "resource_type",
                "ALTER TABLE permissions ADD COLUMN resource_type "
                "TEXT NOT NULL DEFAULT ''",
            ),
            (
                "resource_spec",
                "ALTER TABLE permissions ADD COLUMN resource_spec "
                "TEXT NOT NULL DEFAULT ''",
            ),
        )
        for name, statement in additions:
            if name not in columns:
                await conn.execute(statement)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_permissions_resource "
            "ON permissions(principal_id, project_id, policy_digest, "
            "generation, resource_type, permission_level)"
        )
        await conn.commit()

    async def _ensure_authorization_contexts(self) -> None:
        """Create the authoritative per-principal/project revocation epoch."""
        conn = await self._require_conn()
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS authorization_contexts (
                principal_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                policy_digest TEXT NOT NULL,
                epoch INTEGER NOT NULL DEFAULT 1 CHECK (epoch >= 1),
                updated_at TEXT NOT NULL DEFAULT (datetime('now')),
                PRIMARY KEY (principal_id, project_id)
            )
            """
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

    async def _ensure_sessions_principal_column(self) -> None:
        """M4 batch 3.1.16A-4-3 (CRITICAL): add ``principal_id`` column
        to ``sessions`` for durable principal ownership.

        Legacy rows (pre-A-4-3) get ``principal_id='legacy'`` and are
        hidden from every authenticated principal by ``list_sessions``
        / ``search_sessions`` (fail-closed).  Unlike ``coding_tasks``
        we do NOT quarantine legacy rows to a special status — sessions
        have no execution semantics, so hiding them in principal-scoped
        queries is sufficient.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(sessions)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE sessions "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            await conn.commit()
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_sessions_principal "
            "ON sessions(principal_id, status, updated_at)"
        )
        await conn.commit()

    async def _ensure_messages_principal_column(self) -> None:
        """M4 batch 3.1.16A-4-3 (CRITICAL): add ``principal_id`` column
        to ``messages``.

        Legacy rows get ``principal_id='legacy'``.  A principal scoped
        query (``list_messages(principal_id=...)``) does not see them.
        ``search_sessions`` filters via the sessions JOIN so legacy
        sessions' messages are excluded too.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(messages)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE messages "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            await conn.commit()
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_principal "
            "ON messages(principal_id, session_id, created_at)"
        )
        await conn.commit()

    async def _ensure_agent_turns_principal_column(self) -> None:
        """M4 batch 3.1.16A-4-3 (CRITICAL): add ``principal_id`` column
        to ``agent_turns``.

        Legacy rows get ``principal_id='legacy'``.  ``recover_inflight_
        agent_turns`` is a process-wide startup sweep and ignores the
        column (it must mark every stale ``running`` turn as
        ``interrupted`` regardless of owner).  Per-principal visibility
        is enforced by ``list_agent_turn_events`` callers.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(agent_turns)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE agent_turns "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            await conn.commit()

    async def _ensure_session_bookmarks_principal_column(self) -> None:
        """M4 batch 3.1.16A-4-3 (CRITICAL): add ``principal_id`` column
        to ``session_bookmarks``.

        Legacy rows get ``principal_id='legacy'`` and are invisible to
        authenticated principals via ``list_bookmarks`` / ``load_bookmark``.
        """
        conn = await self._require_conn()
        cursor = await conn.execute("PRAGMA table_info(session_bookmarks)")
        columns = {row[1] for row in await cursor.fetchall()}
        if "principal_id" not in columns:
            await conn.execute(
                "ALTER TABLE session_bookmarks "
                "ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'legacy'"
            )
            await conn.commit()
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_session_bookmarks_principal "
            "ON session_bookmarks(principal_id, session_id)"
        )
        await conn.commit()

    # ------------------------------------------------------------------
    # M4 batch 3.1.16A-5-1 (CRITICAL): project identity closure.
    #
    # The following helpers add a ``project_id`` column to the 8 tables
    # that were missing it (sessions / messages / agent_turns /
    # session_bookmarks / memories / audit_log / coding_tasks /
    # scheduler_operation_journal).  ``scheduled_tasks`` and
    # ``permissions`` already had ``project_id`` (B-1 and A-2
    # respectively).
    #
    # Legacy rows (pre-A-5-1) get ``project_id=''`` — "unbound".  A-5-1b
    # will introduce drift detection (``ctx.project_id !=
    # bound_project_id`` → fail-closed) so unbound rows are visible but
    # new writes always stamp the live project_id.  A-5-2 may later
    # provide a ``reclaim`` tool to backfill ``project_id`` on legacy
    # rows owned by the current project.
    #
    # The helpers are idempotent: re-running ``run_migrations`` on an
    # already-migrated DB is a no-op.
    # ------------------------------------------------------------------

    async def _ensure_table_project_id_column(
        self,
        table: str,
        index_name: str,
        index_columns: str,
    ) -> None:
        """Generic helper: add ``project_id`` column + index to a table.

        Args:
            table: Table name (e.g. ``"sessions"``).
            index_name: Index name (e.g. ``"idx_sessions_project"``).
            index_columns: Comma-separated columns for the index
                (e.g. ``"project_id, principal_id, status"``).
        """
        conn = await self._require_conn()
        cursor = await conn.execute(f"PRAGMA table_info({table})")
        columns = {row[1] for row in await cursor.fetchall()}
        if "project_id" not in columns:
            await conn.execute(
                f"ALTER TABLE {table} "
                "ADD COLUMN project_id TEXT NOT NULL DEFAULT ''"
            )
            await conn.commit()
        await conn.execute(
            f"CREATE INDEX IF NOT EXISTS {index_name} "
            f"ON {table}({index_columns})"
        )
        await conn.commit()

    async def _ensure_sessions_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``sessions``."""
        await self._ensure_table_project_id_column(
            "sessions",
            "idx_sessions_project",
            "project_id, principal_id, status",
        )

    async def _ensure_messages_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``messages``."""
        await self._ensure_table_project_id_column(
            "messages",
            "idx_messages_project",
            "project_id, principal_id, session_id",
        )

    async def _ensure_agent_turns_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``agent_turns``."""
        await self._ensure_table_project_id_column(
            "agent_turns",
            "idx_agent_turns_project",
            "project_id, principal_id, session_id",
        )

    async def _ensure_session_bookmarks_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``session_bookmarks``."""
        await self._ensure_table_project_id_column(
            "session_bookmarks",
            "idx_session_bookmarks_project",
            "project_id, principal_id, session_id",
        )

    async def _ensure_memories_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``memories``.

        Note: ``project_id`` is NOT added to the UNIQUE constraint
        (``namespace, principal_id, session_id, scope, key``).  Adding
        it would require a table rebuild (drop + recreate + migrate)
        and is unnecessary because ``principal_id`` already partitions
        the namespace — two projects sharing a state DB (which A-1
        forbids) would still collide on the same principal's memory
        keys.  The column is for forensics / future sweep queries,
        not for uniqueness enforcement.
        """
        await self._ensure_table_project_id_column(
            "memories",
            "idx_memories_project",
            "project_id, namespace, principal_id, scope",
        )

    async def _ensure_memories_project_id_unique(self) -> None:
        """F-02 (third-round review): rebuild ``memories`` so ``project_id``
        is part of the UNIQUE constraint.

        The pre-F-02 UNIQUE was ``(namespace, principal_id, session_id,
        scope, key)`` — ``project_id`` was a plain column.  When two
        projects share a state DB (via explicit ``--db``), project B's
        upsert of the same key could update project A's row while
        leaving ``project_id=A`` stamped.  F-02 makes the UNIQUE key
        ``(project_id, namespace, principal_id, session_id, scope, key)``
        so each project gets its own row.

        SQLite cannot ALTER a UNIQUE constraint, so the table is rebuilt:
        old data is backed up, the table is dropped and recreated with
        the new schema, FTS5 + triggers are rebuilt, and the data is
        re-inserted.  Legacy rows with ``project_id=''`` are preserved
        as-is — they share the empty project partition.  Run the A-5-2
        ``khaos migrate project-identity`` backfill before this migration
        on multi-project shared DBs to avoid collapsing unbound rows.

        The rebuild is idempotent: if the UNIQUE constraint already
        includes ``project_id`` (fresh DB created with the v2 schema),
        the method returns immediately.
        """
        conn = await self._require_conn()
        # Idempotency check: inspect the UNIQUE index that SQLite
        # automatically creates for the UNIQUE constraint.  If it
        # already covers project_id, the rebuild is a no-op.
        cursor = await conn.execute(
            "SELECT sql FROM sqlite_master "
            "WHERE type='table' AND name='memories'"
        )
        row = await cursor.fetchone()
        if row is None:
            return  # Table doesn't exist yet (shouldn't happen post-schema)
        create_sql = str(row[0])
        if "UNIQUE(project_id, namespace, principal_id, session_id, scope, key)" in create_sql:
            return  # Already migrated (fresh v2 schema)
        # Backup old data.
        await conn.execute("CREATE TABLE _memories_f02_backup AS SELECT * FROM memories")
        # Drop old table, FTS, and triggers (triggers drop automatically).
        await conn.execute("DROP TABLE IF EXISTS memories")
        await conn.execute("DROP TABLE IF EXISTS memory_fts")
        # Create new table with project_id in the UNIQUE constraint.
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
                project_id   TEXT NOT NULL DEFAULT '',
                UNIQUE(project_id, namespace, principal_id, session_id, scope, key)
            )
            """
        )
        # Migrate old data.  If there are duplicate rows that would
        # violate the new UNIQUE (same project_id + namespace + principal
        # + session + scope + key), keep the one with the highest id
        # (most recent write wins — matches the old ON CONFLICT behavior).
        await conn.execute(
            """
            INSERT INTO memories (
                id, scope, key, value, ttl, confidence, access_freq,
                created_at, updated_at, principal_id, namespace, session_id,
                project_id
            )
            SELECT id, scope, key, value, ttl, confidence, access_freq,
                   created_at, updated_at, principal_id, namespace, session_id,
                   project_id
            FROM _memories_f02_backup
            WHERE id IN (
                SELECT MAX(id) FROM _memories_f02_backup
                GROUP BY project_id, namespace, principal_id, session_id, scope, key
            )
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
        # Recreate the project-scoped index (dropped with the table).
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_memories_project "
            "ON memories(project_id, namespace, principal_id, scope)"
        )
        # Cleanup backup.
        await conn.execute("DROP TABLE _memories_f02_backup")

    async def _ensure_audit_log_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``audit_log``."""
        await self._ensure_table_project_id_column(
            "audit_log",
            "idx_audit_log_project",
            "project_id, principal_id, created_at",
        )

    async def _ensure_coding_tasks_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``coding_tasks``."""
        await self._ensure_table_project_id_column(
            "coding_tasks",
            "idx_coding_tasks_project",
            "project_id, principal_id, status",
        )

    async def _ensure_scheduler_journal_project_id_column(self) -> None:
        """A-5-1: add ``project_id`` to ``scheduler_operation_journal``.

        This column was omitted from B-5 (oversight) — the journal
        table already had ``principal_id`` and ``policy_digest`` but
        not ``project_id``.  A-5-1 closes the gap so cross-project
        forensics can disambiguate entries.
        """
        await self._ensure_table_project_id_column(
            "scheduler_operation_journal",
            "idx_scheduler_journal_project",
            "project_id, task_id, seq",
        )

    async def create_session(
        self,
        session_id: str,
        mode: str = "office",
        *,
        principal_id: str = "legacy",
        project_id: str = "",
    ) -> None:
        """Create a session if missing and keep its mode current.

        M4 batch 3.1.16A-4-3: ``principal_id`` is stamped on the row
        so ``list_sessions`` / ``search_sessions`` can filter by it.
        Callers should pass the bound principal; the default
        ``'legacy'`` is fail-closed and only used by pre-A-4-3 callers
        that haven't been migrated yet.

        M4 batch 3.1.16A-5-1b: ``project_id`` is stamped on the row
        for project identity closure.  Default ``''`` is fail-closed
        (unbound) for pre-A-5-1b callers; production callers pass
        ``ctx.project_id`` (RPC) or ``compute_project_id(root)`` (CLI).

        H-05 (round-4 review): ``ON CONFLICT DO UPDATE`` does NOT touch
        ``principal_id`` or ``project_id`` AND carries an Owner-Match
        predicate (``WHERE sessions.principal_id = excluded.principal_id
        AND sessions.project_id = excluded.project_id``).  A foreign
        caller colliding with an existing id no longer silently mutates
        ``mode``/``updated_at`` — the WHERE clause matches zero rows,
        ``rowcount == 0``, and we raise ``OwnerMismatchError`` so the
        caller can fail loudly instead of touching another owner's row.
        """
        async with self.transaction() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO sessions (id, mode, principal_id, project_id)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    mode = excluded.mode,
                    updated_at = datetime('now')
                WHERE sessions.principal_id = excluded.principal_id
                  AND sessions.project_id = excluded.project_id
                """,
                (session_id, mode, principal_id, project_id),
            )
            if cursor.rowcount == 0:
                # Conflict on id but owner did not match — foreign owner
                # tried to (re)create a session it does not own.
                raise OwnerMismatchError(
                    f"session {session_id!r} already exists with a "
                    f"different (principal_id, project_id) owner"
                )

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
        async with self._webhook_replay_lock:
            if platform == "telegram":
                return await self._consume_telegram_update(
                    channel_id, event_id
                )
            now = time.time()
            async with self.transaction() as conn:
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
                return cursor.rowcount == 1

    async def _consume_telegram_update(
        self, channel_id: str, event_id: str
    ) -> bool:
        try:
            update_id = int(event_id)
        except (TypeError, ValueError):
            return False
        if update_id < 0:
            return False
        now = time.time()
        async with self.transaction() as conn:
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
            return True

    async def insert_message(
        self,
        session_id: str,
        message: Message,
        *,
        principal_id: str = "legacy",
        project_id: str = "",
    ) -> int:
        """Persist a chat message and return its row id.

        M4 batch 3.1.16A-4-3: ``principal_id`` is stamped on the row
        so ``list_messages`` / ``get_session_messages`` / ``search_
        sessions`` can filter without a JOIN.  Callers should pass the
        bound principal (typically ``AgentLoop.principal_id``).

        M4 batch 3.1.16A-5-1b: ``project_id`` is stamped on the row
        for project identity closure (see ``create_session``).
        Production callers pass ``AgentLoop.project_id`` (plumbed from
        ``RuntimeConfig.project_id``).
        """
        async with self.transaction() as conn:
            return await self._session_repository.insert_message(
                conn,
                session_id,
                message,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def list_messages(
        self,
        session_id: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[Message]:
        """Load persisted messages for a session in chronological order.

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, only
        rows owned by that principal are returned.  ``principal_id=
        None`` (default) is the explicit admin opt-in that returns
        every row regardless of owner — used by migration / admin
        tooling, never by an authenticated principal's AgentLoop.

        H-02 (round-4 review): ``project_id`` is an independent owner
        dimension.  When provided, rows are further scoped to that
        project — closing the cross-project read path on shared DBs.
        Production callers pass both ``principal_id`` and ``project_id``;
        ``None`` on either remains the explicit admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.list_messages(
                conn,
                session_id,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def set_config(self, key: str, value: Any) -> None:
        """Persist a JSON configuration value."""
        await self._configuration_repository.set_config(key, value)

    async def get_config(self, key: str, default: Any = None) -> Any:
        """Read a JSON configuration value."""
        return await self._configuration_repository.get_config(key, default)

    async def get_principal_mode(
        self,
        principal_id: str,
        session_id: str = "",
        default: str = "office",
        *,
        project_id: str = "",
    ) -> str:
        """M4 batch 3.1.16A-2: read principal-scoped mode.

        Lookup order:
        1. (project_id, principal_id, session_id) — session-specific override
        2. (project_id, principal_id, '')         — principal default
        3. ``default`` (typically 'office')

        H-09 (round-5 Batch 5.3): ``project_id`` is now part of the
        lookup key — closes cross-project mode leakage on shared DBs.
        ``project_id=''`` (the default) preserves legacy/test behaviour.
        """
        return await self._configuration_repository.get_principal_mode(
            principal_id,
            session_id,
            default,
            project_id=project_id,
        )

    async def set_principal_mode(
        self,
        principal_id: str,
        mode: str,
        session_id: str = "",
        *,
        project_id: str = "",
    ) -> None:
        """M4 batch 3.1.16A-2: persist principal-scoped mode.

        When ``session_id`` is empty, sets the principal's default
        mode.  When non-empty, sets a session-specific override.

        H-09 (round-5 Batch 5.3): ``project_id`` is now part of the
        PK — each project gets its own mode rows.  ``project_id=''``
        (the default) preserves legacy/test behaviour.
        """
        await self._configuration_repository.set_principal_mode(
            principal_id,
            mode,
            session_id,
            project_id=project_id,
        )

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
        transport_class: str = "interactive",
        grant_lifetime: str = "project_interactive",
        session_id: str = "",
        task_id: str = "",
        workspace_id: str = "",
        expires_at: float | None = None,
        created_by: str = "",
        resource_type: str = "",
        resource_spec: dict[str, Any] | str | None = None,
    ) -> int:
        """Persist a permission rule and return its row id.

        M4 batch 3.1.16A-2: ``principal_id``, ``project_id``,
        ``policy_digest`` and ``generation`` scope the rule to a
        specific principal/project/policy. Phase-1 scope fields further
        bind the grant to a transport class and optional session/task/
        workspace lifetime. Legacy callers that omit them get the safe
        interactive-project default and are never matched by authenticated
        principals when ``principal_id='legacy'``.
        """
        return await self._permission_repository.insert_permission_rule(
            pattern,
            permission_level,
            approval,
            mode,
            principal_id=principal_id,
            project_id=project_id,
            policy_digest=policy_digest,
            generation=generation,
            transport_class=transport_class,
            grant_lifetime=grant_lifetime,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
            expires_at=expires_at,
            created_by=created_by,
            resource_type=resource_type,
            resource_spec=resource_spec,
        )

    async def list_permission_rules(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
        policy_digest: str | None = None,
        generation: int | None = None,
    ) -> list[dict[str, Any]]:
        """Load permission rules newest first.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, only
        rules belonging to that principal are returned (legacy rows
        with ``principal_id='legacy'`` are excluded).  When
        ``principal_id`` is ``None`` (default), all rules are returned
        — this preserves the legacy admin/inspection behaviour.
        """
        return await self._permission_repository.list_permission_rules(
            principal_id=principal_id,
            project_id=project_id,
            policy_digest=policy_digest,
            generation=generation,
        )

    async def delete_permission_rule(
        self,
        rule_id: int,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
        policy_digest: str | None = None,
    ) -> int:
        """Delete a permission rule.

        M4 batch 3.1.16A-2: when ``principal_id`` is provided, the
        rule is only deleted if it belongs to that principal — this
        prevents a principal from revoking another principal's rules.
        Returns the number of rows deleted (0 if the rule doesn't
        exist or belongs to a different principal).
        """
        return await self._permission_repository.delete_permission_rule(
            rule_id,
            principal_id=principal_id,
            project_id=project_id,
            policy_digest=policy_digest,
        )

    async def bind_authorization_context(
        self, principal_id: str, project_id: str, policy_digest: str
    ) -> int:
        """Bind the current policy, bumping epoch when the digest changes."""
        return await self._permission_repository.bind_authorization_context(
            principal_id,
            project_id,
            policy_digest,
        )

    async def get_authorization_context(
        self, principal_id: str, project_id: str
    ) -> dict[str, Any] | None:
        return await self._permission_repository.get_authorization_context(
            principal_id,
            project_id,
        )

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
        project_id: str = "",
    ) -> int:
        """Persist an audit log entry and return its row id.

        M4 batch 3.1.16A-2: ``principal_id`` and optional context
        fields (``runtime_id``, ``task_id``, ``operation_id``,
        ``policy_digest``, ``authority_generation``,
        ``source_transport``) are stamped on every entry for
        attribution.  Legacy callers that omit them get
        ``principal_id='legacy'``.

        M4 batch 3.1.16A-5-1b: ``project_id`` is stamped on every
        entry for project identity closure (cross-project forensics).
        Default ``''`` for pre-A-5-1b callers; production callers pass
        ``AuditLogger._project_id`` (plumbed from
        ``RuntimeConfig.project_id`` or ``agent._bound_project_id``).

        Round-14 §4: each row extends the tamper-evident hash chain.  We
        read the most recent row's ``prev_hash`` (genesis sentinel '' when
        the table is empty or all pre-v8 rows), then store
        ``prev_hash = sha256(prev_prev_hash || canonical_fields)``.  A
        deleted/reordered/edited row breaks the chain and is detectable by
        :meth:`verify_audit_chain`.  This runs inside the same transaction
        as the INSERT, so concurrency cannot interleave the read and write.
        """
        return await self._audit_repository.insert_audit_log(
            action,
            target,
            result,
            detail,
            session_id,
            principal_id=principal_id,
            runtime_id=runtime_id,
            task_id=task_id,
            operation_id=operation_id,
            policy_digest=policy_digest,
            authority_generation=authority_generation,
            source_transport=source_transport,
            project_id=project_id,
        )

    async def list_audit_logs(
        self,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return audit logs in insertion order.

        H-02/H-03/H-04 (round-4 review): ``principal_id`` and
        ``project_id`` are independent owner dimensions.  When either is
        provided, entries are scoped to that owner — closing the
        cross-project / cross-principal read path on shared DBs.
        Production callers pass both; ``None`` on either (default)
        remains the admin opt-in.
        """
        return await self._audit_repository.list_audit_logs(
            principal_id=principal_id,
            project_id=project_id,
        )

    async def get_audit_chain_head(
        self, row_id: int | None = None,
    ) -> dict[str, Any] | None:
        """Return a recomputed audit-chain link for one row or the head.

        The local audit anchor uses this narrow read to compare its persisted
        chain head with SQLite without trusting a stored hash value.  The
        full :meth:`verify_audit_chain` replay remains the authoritative
        consistency check before an anchor is advanced.
        """
        return await self._audit_repository.get_audit_chain_head(row_id)

    async def verify_audit_chain_since(self, row_id: int) -> list[dict[str, Any]]:
        """Verify the chain from an anchored row through the current head.

        Startup performs a complete replay.  Once the anchor is trusted,
        writes only need to replay the suffix since the last anchored row;
        this keeps per-event verification bounded while still checking every
        newly appended link before the independent head advances.
        """
        return await self._audit_repository.verify_audit_chain_since(row_id)

    async def verify_audit_chain(self) -> list[dict[str, Any]]:
        """Round-14 §4 / Round-15 A-2: verify the audit_log hash chain.

        Returns a list of broken-link records (empty when the chain is
        intact).  Only the **first** row may carry an empty ``prev_hash``
        (the genesis row).  Round-15 A-2: a non-first row with an empty
        ``prev_hash`` is now a *break* (an INSERT-reset forgery attempt),
        not a trusted reset — the BEFORE INSERT trigger added in v9 makes
        such an insert fail at the DB layer; this verifier is the
        defense-in-depth that catches it if the trigger is ever absent.
        """
        return await self._audit_repository.verify_audit_chain()

    async def query_audit_logs(
        self,
        action: str | None = None,
        result: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
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

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, entries are
        further scoped to that project — closing the cross-project read
        path on shared DBs.  Production callers pass both; ``None`` on
        either remains the admin opt-in.
        """
        return await self._audit_repository.query_audit_logs(
            action,
            result,
            since,
            until,
            limit,
            principal_id=principal_id,
            project_id=project_id,
        )

    async def insert_subagent_task(
        self,
        task_id: str,
        parent_session_id: str,
        goal: str,
        context: str,
        tools: str,
        status: str = "pending",
        principal_id: str = "",
        project_id: str = "",
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
        async with self.transaction() as conn:
            # C-03 (round-4 review): _ensure_subagent_tasks_principal_column
            # is now only called during migration. If the column is missing
            # at runtime, the INSERT will fail with OperationalError (fail
            # closed) — the DB needs migration, not runtime ALTER.
            await conn.execute(
                """
                INSERT INTO subagent_tasks (
                    id, parent_session_id, goal, context, tools, status,
                    principal_id, project_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id, parent_session_id, goal, context, tools, status,
                    principal_id, project_id,
                ),
            )

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
        async with self.transaction() as conn:
            finished_expr = "datetime('now')" if finished else "finished_at"
            cursor = await conn.execute(
                f"""
                UPDATE subagent_tasks
                SET status = ?, result = ?, error = ?, finished_at = {finished_expr}
                WHERE id = ?
                """,
                (status, result, error, task_id),
            )
            return cursor.rowcount or 0

    async def list_subagent_tasks(
        self,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List subagent tasks.

        B1: when ``principal_id`` is set, only rows owned by that
        principal are returned.  ``None`` preserves the legacy
        "return everything" behaviour.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both; ``None`` on either
        remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            # C-03: _ensure_subagent_tasks_principal_column removed from
            # runtime — column is added during migration, missing = fail closed.
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
                SELECT id, parent_session_id, goal, context, tools, status, result, error, principal_id, project_id
                FROM subagent_tasks
                {where}
                ORDER BY created_at, id
                """,
                tuple(params),
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
        changed = False
        if "principal_id" not in existing:
            await conn.execute(
                "ALTER TABLE subagent_tasks ADD COLUMN principal_id TEXT NOT NULL DEFAULT ''"
            )
            changed = True
        if "project_id" not in existing:
            await conn.execute(
                "ALTER TABLE subagent_tasks "
                "ADD COLUMN project_id TEXT NOT NULL DEFAULT ''"
            )
            changed = True
        if changed:
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
        *,
        principal_id: str = "legacy",
        project_id: str = "",
    ) -> None:
        """保存一个会话书签。

        同一 (session_id, name) 已存在时整体覆盖更新（upsert）。

        M4 batch 3.1.16A-4-3: ``principal_id`` is stamped on the row so
        ``list_bookmarks`` / ``load_bookmark`` can filter by it.  The
        ``ON CONFLICT DO UPDATE`` does NOT touch ``principal_id`` —
        once a bookmark is bound to a principal, a later ``save_bookmark``
        call from a different principal cannot re-stamp ownership (the
        row keeps its original owner).  Cross-principal upsert is an
        owner-preserving update.

        M4 batch 3.1.16A-5-1b: ``project_id`` is stamped on the row for
        project identity closure (same owner-preserving policy —
        ``ON CONFLICT`` does NOT touch ``project_id``).

        H-06 (round-4 review): the upsert now carries an Owner-Match
        predicate (``WHERE bookmarks.principal_id = excluded.principal_id
        AND bookmarks.project_id = excluded.project_id``).  A foreign
        caller colliding with an existing (session_id, name) no longer
        silently overwrites ``description``/``mode``/``project_root``/
        ``summary`` — the WHERE matches zero rows, ``rowcount == 0``,
        and we raise ``OwnerMismatchError``.  Owner-preserving is now
        also owner-authorized.
        """
        async with self.transaction() as conn:
            cursor = await conn.execute(
                """
                INSERT INTO session_bookmarks
                    (session_id, name, description, mode, project_root, summary,
                     principal_id, project_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id, name) DO UPDATE SET
                    description  = excluded.description,
                    mode         = excluded.mode,
                    project_root = excluded.project_root,
                    summary      = excluded.summary
                WHERE session_bookmarks.principal_id = excluded.principal_id
                  AND session_bookmarks.project_id  = excluded.project_id
                """,
                (session_id, name, description, mode, project_root, summary,
                 principal_id, project_id),
            )
            if cursor.rowcount == 0:
                raise OwnerMismatchError(
                    f"bookmark {name!r} on session {session_id!r} already "
                    f"exists with a different (principal_id, project_id) owner"
                )

    async def load_bookmark(
        self,
        session_id: str,
        name: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any] | None:
        """加载指定书签。不存在时返回 None。

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, only a
        bookmark owned by that principal is returned — a foreign-
        principal bookmark is treated as ``None`` (existence hidden,
        matching the ``TaskService.get`` pattern).

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, the bookmark is
        further scoped to that project — closing the cross-project read
        path on shared DBs.  Production callers pass both; ``None`` on
        either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            clauses: list[str] = ["session_id = ?", "name = ?"]
            params: list[Any] = [session_id, name]
            if principal_id is not None:
                clauses.append("principal_id = ?")
                params.append(principal_id)
            if project_id is not None:
                clauses.append("project_id = ?")
                params.append(project_id)
            cursor = await conn.execute(
                f"""
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at, principal_id, project_id
                FROM session_bookmarks
                WHERE {' AND '.join(clauses)}
                """,
                tuple(params),
            )
            row = await cursor.fetchone()
            return dict(row) if row is not None else None

    async def list_bookmarks(
        self,
        session_id: str | None = None,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """列出书签，可按 session 过滤。按创建时间倒序返回。

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, only
        bookmarks owned by that principal are returned.  ``principal_id
        =None`` (default) is the admin opt-in.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, bookmarks are
        further scoped to that project — closing the cross-project read
        path on shared DBs.  Production callers pass both; ``None`` on
        either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            clauses: list[str] = []
            params: list[Any] = []
            if session_id is not None:
                clauses.append("session_id = ?")
                params.append(session_id)
            if principal_id is not None:
                clauses.append("principal_id = ?")
                params.append(principal_id)
            if project_id is not None:
                clauses.append("project_id = ?")
                params.append(project_id)
            where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            cursor = await conn.execute(
                f"""
                SELECT id, session_id, name, description, mode, project_root,
                       summary, created_at, principal_id, project_id
                FROM session_bookmarks
                {where}
                ORDER BY created_at DESC, id DESC
                """,
                tuple(params),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def delete_bookmark(
        self,
        session_id: str,
        name: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> None:
        """删除指定书签。不存在的书签静默忽略。

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, the
        DELETE is scoped to that principal — preventing cross-principal
        deletion.  ``principal_id=None`` (default) preserves the legacy
        unscoped behavior for admin callers.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, the DELETE is
        further scoped to that project — preventing cross-project
        deletion.  Production callers pass both; ``None`` on either
        remains the admin opt-in.
        """
        async with self.transaction() as conn:
            clauses: list[str] = ["session_id = ?", "name = ?"]
            params: list[Any] = [session_id, name]
            if principal_id is not None:
                clauses.append("principal_id = ?")
                params.append(principal_id)
            if project_id is not None:
                clauses.append("project_id = ?")
                params.append(project_id)
            await conn.execute(
                f"DELETE FROM session_bookmarks "
                f"WHERE {' AND '.join(clauses)}",
                tuple(params),
            )

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

        C-03 (round-4 review): the ``summary`` column is now added during
        migration (``_run_legacy_schema_upgrades``), not at runtime.  If
        the column is missing, the UPDATE fails with OperationalError
        (fail closed) — the DB needs migration, not runtime ALTER.

        同时合并写入 metadata JSON 的 summary 字段，保持向后兼容。
        """
        async with self.transaction() as conn:
            await conn.execute(
                "UPDATE sessions SET summary = ?, updated_at = datetime('now') WHERE id = ?",
                (summary, session_id),
            )
            # 同步到 metadata JSON，便于旧读取路径访问
            await self._merge_session_metadata(session_id, {"summary": summary})

    async def get_session_summary(self, session_id: str) -> str | None:
        """读取会话摘要。优先读 summary 列，回退到 metadata JSON。"""
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
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
        async with self.transaction():
            await self._merge_session_metadata(session_id, {"changed_files": list(files)})

    async def get_session_changes(self, session_id: str) -> list[str]:
        """读取会话修改的文件列表。"""
        meta = await self._read_session_metadata(session_id)
        raw = meta.get("changed_files")
        if not isinstance(raw, list):
            return []
        return [str(item) for item in raw]

    async def _read_session_metadata(self, session_id: str) -> dict[str, Any]:
        """读取 sessions.metadata 的 JSON 字典，缺失/损坏时返回空字典。"""
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
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
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
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
        project_id: str = "",
        policy_digest: str = "",
    ) -> str:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.insert_scheduled_task(
            name, prompt, status, schedule, deliver_to, meta,
            principal_id=principal_id, next_run=next_run,
            project_id=project_id, policy_digest=policy_digest,
        )

    async def update_scheduled_task_status(
        self, task_id: str, status: str, bump_version: bool = False
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.update_scheduled_task_status(
            task_id, status, bump_version
        )

    async def update_scheduled_task(
        self, task_id: str, status: str | None = None,
        last_run: str | None = None, next_run: str | None = None,
        run_count: int | None = None, last_result: str | None = None,
        error: str | None = None, bump_version: bool = False,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.update_scheduled_task(
            task_id, status, last_run, next_run, run_count,
            last_result, error, bump_version
        )

    async def update_scheduled_task_conditional(
        self, task_id: str, expected_version: int, status: str | None = None,
        last_run: str | None = None, next_run: str | None = None,
        run_count: int | None = None, last_result: str | None = None,
        error: str | None = None,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.update_scheduled_task_conditional(
            task_id, expected_version, status, last_run, next_run,
            run_count, last_result, error
        )

    async def list_scheduled_tasks(
        self, *, principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.list_scheduled_tasks(
            principal_id=principal_id, project_id=project_id
        )

    async def get_scheduled_task(
        self, task_id: str, *, principal_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.get_scheduled_task(
            task_id, principal_id=principal_id, project_id=project_id
        )

    async def claim_scheduled_task(
        self, task_id: str, *, execution_id: str, started_at: str,
        lease_until: str, expected_version: int,
        expected_principal_id: str | None = None,
        expected_project_id: str | None = None,
        expected_policy_digest: str | None = None,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.claim_scheduled_task(
            task_id, execution_id=execution_id, started_at=started_at,
            lease_until=lease_until, expected_version=expected_version,
            expected_principal_id=expected_principal_id,
            expected_project_id=expected_project_id,
            expected_policy_digest=expected_policy_digest,
        )

    async def clear_scheduled_task_lease(
        self, task_id: str, *, execution_id: str
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.clear_scheduled_task_lease(
            task_id, execution_id=execution_id
        )

    async def recover_expired_leases(self, *, now_iso: str) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.recover_expired_leases(
            now_iso=now_iso
        )

    async def recover_all_running_tasks(self) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.recover_all_running_tasks()

    async def query_running_task_ids(self) -> list[str]:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.query_running_task_ids()

    async def query_expired_lease_task_ids(
        self, *, now_iso: str
    ) -> list[str]:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.query_expired_lease_task_ids(
            now_iso=now_iso
        )

    async def recover_one_expired_lease(
        self, task_id: str, *, now_iso: str
    ) -> bool:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.recover_one_expired_lease(
            task_id, now_iso=now_iso
        )

    async def finalize_scheduled_task(
        self, task_id: str, *, execution_id: str, expected_version: int,
        status: str, last_run: str | None = None,
        next_run: str | None = None, run_count: int | None = None,
        last_result: str | None = None, error: str | None = None,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.finalize_scheduled_task(
            task_id, execution_id=execution_id, expected_version=expected_version,
            status=status, last_run=last_run, next_run=next_run,
            run_count=run_count, last_result=last_result, error=error,
        )

    async def control_update_scheduled_task(
        self, task_id: str, *, expected_version: int, target_version: int,
        status: str, next_run: str | None = None, error: str | None = None,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.control_update_scheduled_task(
            task_id, expected_version=expected_version,
            target_version=target_version, status=status,
            next_run=next_run, error=error,
        )

    async def control_finalize_scheduled_task(
        self, task_id: str, *, expected_version: int, target_version: int,
        status: str, next_run: str | None = None, error: str | None = None,
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.control_finalize_scheduled_task(
            task_id, expected_version=expected_version,
            target_version=target_version, status=status,
            next_run=next_run, error=error,
        )

    async def insert_scheduler_journal_entry(
        self, *, operation_id: str, task_id: str, operation_type: str,
        desired_status: str, expected_version: int, target_version: int,
        principal_id: str = "", policy_digest: str = "",
        project_id: str = "",
    ) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.insert_scheduler_journal_entry(
            operation_id=operation_id, task_id=task_id,
            operation_type=operation_type, desired_status=desired_status,
            expected_version=expected_version, target_version=target_version,
            principal_id=principal_id, policy_digest=policy_digest,
            project_id=project_id,
        )

    async def mark_scheduler_journal_applied(self, operation_id: str) -> int:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.mark_scheduler_journal_applied(
            operation_id
        )

    async def list_pending_scheduler_journal_entries(
        self,
    ) -> list[dict[str, Any]]:
        """Compatibility facade for the scheduler repository."""
        return await self._scheduler_repository.list_pending_scheduler_journal_entries()
    # Durable tool-operation persistence is intentionally not exposed as
    # Database methods.  ToolOperationRepository is the only SQL owner; the
    # read-only property near the connection views is the explicit injection
    # boundary for runtime consumers.
    async def checkpoint_wal(self) -> dict[str, int]:
        """Run a bounded passive WAL checkpoint under the writer lock."""
        async with self._write_transaction_lock:
            conn = await self._require_writer_conn_locked()
            cursor = await conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            row = await cursor.fetchone()
            if row is None:
                return {"busy": 0, "log_pages": 0, "checkpointed_pages": 0}
            return {
                "busy": int(row[0]),
                "log_pages": int(row[1]),
                "checkpointed_pages": int(row[2]),
            }

    async def health_check(self) -> dict[str, Any]:
        """Return a bounded, side-effect-free database readiness check.

        The check uses the writer transaction path rather than only testing
        that a connection object exists.  ``BEGIN IMMEDIATE`` plus a rollback
        proves that the configured database is reachable and currently
        writable, while ``quick_check(1)`` catches an integrity failure before
        the gateway advertises readiness.  No application row is changed.
        """
        try:
            async with self.transaction() as conn:
                cursor = await conn.execute("PRAGMA quick_check(1)")
                row = await cursor.fetchone()
                quick_check = str(row[0]) if row is not None else ""
                await conn.execute("SELECT 1")
            ok = quick_check.lower() == "ok"
            return {
                "ok": ok,
                "connected": True,
                "writable": True,
                "quick_check": quick_check or "missing",
            }
        except (OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as exc:
            logger.warning("database health check failed: %s", exc.__class__.__name__)
            return {
                "ok": False,
                "connected": self._conn is not None,
                "writable": False,
                "quick_check": "error",
                "error": exc.__class__.__name__,
            }

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

        M4 batch 3.1.16A-4-3: ``messages_fts`` itself has no ``principal_id``
        column (it is a standalone FTS5 table, not external-content).
        Principal scoping for search is enforced by ``search_sessions``
        via a JOIN to ``sessions`` / ``messages`` on the principal_id
        column.  This method therefore needs no ``principal_id``
        parameter — the caller (``AgentLoop._persist_message``) already
        stamped principal_id on the base ``messages`` row, and the FTS
        row mirrors that rowid.
        """
        async with self.transaction() as conn:
            created = utc_now_naive().strftime("%Y-%m-%d %H:%M:%S")
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

    async def insert_coding_task(
        self, task: dict[str, Any], *, principal_id: str = "legacy",
        project_id: str = "",
    ) -> None:
        """INSERT a new coding task row (plain INSERT, no upsert).

        Round-4 review Batch 4 (§八): coding tasks now use a full 128-bit
        UUID (``uuid.uuid4().hex``) so collision is virtually impossible.
        If one ever happens, ``sqlite3.IntegrityError`` is raised instead
        of silently overwriting an old row — mirroring the
        ``insert_subagent_task`` policy.

        ``principal_id`` is stamped on the row so ``list_coding_tasks``
        can filter by it.  The default ``'legacy'`` is fail-closed and
        quarantines the task (status→failed) so only an admin can
        re-claim it.
        """
        persisted_task = dict(task)
        if principal_id == "legacy" and task.get("status") != "failed":
            persisted_task["status"] = "failed"
            persisted_task["error"] = (
                "quarantined: legacy write - task has no authenticated "
                "owner; an admin must re-claim it with a real principal "
                "before it can run"
            )
        async with self.transaction() as conn:
            await conn.execute(
                """
                INSERT INTO coding_tasks (id, goal, status, state_json, created_at, updated_at, principal_id, project_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    persisted_task["id"], persisted_task["goal"],
                    persisted_task["status"], json.dumps(persisted_task),
                    persisted_task["created_at"], persisted_task["updated_at"],
                    principal_id, project_id,
                ),
            )

    async def update_coding_task(
        self, task: dict[str, Any], *, principal_id: str,
        project_id: str, expected_status: str,
    ) -> None:
        """Update a coding task with owner and lifecycle CAS predicates.

        Existing task persistence is a lifecycle compare-and-swap.  The
        caller must state the durable status it read *before* applying its
        in-memory mutation; the SQL update then requires that status to
        remain current.  This prevents a stale TaskManager cache from
        overwriting a Gate-committed terminal status.

        Owner mismatch and lifecycle conflict are intentionally distinct:
        an owner-scoped row that cannot be selected raises
        ``OwnerMismatchError``; a selected row whose status no longer
        matches ``expected_status`` raises ``TaskLifecycleConflictError``.
        The owner-scoped probe does not disclose whether an unowned id
        exists.

        Unlike ``insert_coding_task``, this method does NOT re-stamp
        ``principal_id`` or ``project_id`` — ownership is immutable
        after creation.  Only ``goal``, ``status``, ``state_json``,
        and ``updated_at`` are updated.

        The generic path is never a successful completion authority:
        active-to-``completed`` and terminal-to-different-status writes are
        rejected even when the supplied expected status happens to match.
        CompletionGateRepository owns the dedicated successful projection
        SQL.
        """
        persisted_task = dict(task)
        task_id = persisted_task["id"]
        new_status = persisted_task["status"]
        if type(expected_status) is not str or not expected_status:
            raise ValueError("expected_status must be a non-empty status string")
        if type(new_status) is not str or not new_status:
            raise ValueError("task status must be a non-empty status string")

        async with self.transaction() as conn:
            owner_cursor = await conn.execute(
                """
                SELECT status FROM coding_tasks
                WHERE id = ? AND principal_id = ? AND project_id = ?
                """,
                (task_id, principal_id, project_id),
            )
            owner_row = await owner_cursor.fetchone()
            if owner_row is None:
                raise OwnerMismatchError(
                    f"coding task {task_id!r} does not exist "
                    "or is owned by a different (principal_id, project_id)"
                )

            current_status = owner_row["status"]
            if current_status != expected_status:
                raise TaskLifecycleConflictError(
                    f"coding task {task_id!r} lifecycle is stale: "
                    f"expected {expected_status!r}, current {current_status!r}"
                )

            # Terminal states are monotonic in the generic persistence
            # domain.  Same-status metadata projections are allowed, but no
            # stale or direct caller can move a terminal row elsewhere.
            if (
                current_status in {"completed", "failed", "cancelled"}
                and new_status != current_status
            ):
                raise TaskLifecycleConflictError(
                    f"coding task {task_id!r} terminal status "
                    f"{current_status!r} cannot change to {new_status!r}"
                )
            if new_status == "completed" and current_status != "completed":
                raise TaskLifecycleConflictError(
                    "generic coding-task persistence cannot transition an "
                    "active task to completed; CompletionGate owns that write"
                )

            cursor = await conn.execute(
                """
                UPDATE coding_tasks SET
                    goal = ?,
                    status = ?,
                    state_json = ?,
                    updated_at = ?
                WHERE id = ? AND principal_id = ? AND project_id = ?
                  AND status = ?
                """,
                (
                    persisted_task["goal"],
                    persisted_task["status"],
                    json.dumps(persisted_task),
                    persisted_task["updated_at"],
                    persisted_task["id"],
                    principal_id,
                    project_id,
                    expected_status,
                ),
            )
            if cursor.rowcount != 1:
                raise TaskLifecycleConflictError(
                    f"coding task {task_id!r} lifecycle changed during update"
                )

    async def list_coding_tasks(
        self, *, principal_id: str | None = None, project_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Load persisted coding-task state in creation order.

        M4 batch 3.1.16A-3: when ``principal_id`` is given, only rows
        owned by that principal are returned.  ``principal_id=None``
        (default) is the explicit admin opt-in that returns every row
        regardless of owner — used by migration / admin tooling, never
        by an authenticated principal's TaskManager.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both; ``None`` on either
        remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
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
                f"SELECT id, goal, status, state_json, created_at, updated_at, "
                f"principal_id, project_id, cognitive_state, "
                f"control_state_version FROM coding_tasks {where} "
                "ORDER BY created_at",
                tuple(params),
            )
            rows = await cursor.fetchall()
            result: list[dict[str, Any]] = []
            for row in rows:
                state = json.loads(str(row["state_json"]))
                if type(state) is not dict:
                    raise ValueError(
                        f"coding task {row['id']!r} state_json is not an object"
                    )
                for field_name, physical_value in (
                    ("id", row["id"]),
                    ("goal", row["goal"]),
                    ("status", row["status"]),
                    ("created_at", row["created_at"]),
                    ("updated_at", row["updated_at"]),
                ):
                    if field_name in state and state[field_name] != physical_value:
                        raise ValueError(
                            f"coding task {row['id']!r} {field_name} projection disagrees"
                        )
                    state[field_name] = physical_value
                # Owner columns are authoritative even if an old state JSON
                # payload contains a stale or forged projection.
                state["principal_id"] = row["principal_id"]
                # M7.1.3: cognitive state/version are a separate SQL CAS
                # domain.  The state_json values are only a compatibility
                # projection and are overwritten by the canonical columns.
                state["cognitive_state"] = row["cognitive_state"]
                state["control_state_version"] = row["control_state_version"]
                result.append(state)
            return result

    async def search_sessions(
        self,
        query: str,
        limit: int = 10,
        offset: int = 0,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """FTS5 BM25 search across all session messages.

        Returns rows with id, session_id, role, created_at, rank, and a
        snippet() with the matched term highlighted.

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, results
        are scoped to messages owned by that principal via a JOIN to
        the base ``messages`` table on rowid.  Legacy rows
        (``principal_id='legacy'``) are excluded.  ``principal_id=None``
        (default) is the admin opt-in.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When either ``principal_id`` or
        ``project_id`` is provided, the query JOINs the base
        ``messages`` table and applies the supplied owner filters —
        closing the cross-project read path on shared DBs.  Production
        callers pass both; ``None`` on either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.search_sessions(
                conn,
                query,
                limit,
                offset,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def get_session_messages(
        self,
        session_id: str,
        limit: int = 50,
        offset: int = 0,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return messages for a session, newest-aware pagination.

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, only
        rows owned by that principal are returned.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both; ``None`` on either
        remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.get_session_messages(
                conn,
                session_id,
                limit,
                offset,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def get_message_window(
        self,
        session_id: str,
        message_id: int,
        window: int = 5,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Return up to ``window`` messages before and after ``message_id``.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both ``principal_id`` and
        ``project_id``; ``None`` on either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.get_message_window(
                conn,
                session_id,
                message_id,
                window,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def count_session_messages(
        self,
        session_id: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> int:
        """Count messages for a session, optionally scoped by owner.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both ``principal_id`` and
        ``project_id``; ``None`` on either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.count_session_messages(
                conn,
                session_id,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def count_messages_before_after(
        self,
        session_id: str,
        message_id: int,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> tuple[int, int]:
        """Return (count_before, count_after) relative to ``message_id``.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, rows are further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both ``principal_id`` and
        ``project_id``; ``None`` on either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.count_messages_before_after(
                conn,
                session_id,
                message_id,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def list_sessions(
        self,
        limit: int = 20,
        offset: int = 0,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """List sessions newest-first, with a message-count + last-message preview.

        M4 batch 3.1.16A-4-3: when ``principal_id`` is given, only
        sessions owned by that principal are returned.  Legacy rows
        (``principal_id='legacy'``) are excluded.  ``principal_id=None``
        (default) is the admin opt-in.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, sessions are
        further scoped to that project — closing the cross-project read
        path on shared DBs.  Production callers pass both; ``None`` on
        either remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.list_sessions(
                conn,
                limit,
                offset,
                principal_id=principal_id,
                project_id=project_id,
            )

    async def get_session(
        self,
        session_id: str,
        *,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return one session row, or ``None`` if missing.

        C-2-3: when ``principal_id`` is given, only a row owned by
        that principal is returned (cross-principal access yields
        ``None``, hidden as "not found" by the caller).  This is the
        single-row counterpart to :meth:`list_sessions`.

        H-02/H-03/H-04 (round-4 review): ``project_id`` is an
        independent owner dimension.  When provided, the row is further
        scoped to that project — closing the cross-project read path on
        shared DBs.  Production callers pass both; ``None`` on either
        remains the admin opt-in.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            return await self._session_repository.get_session(
                conn,
                session_id,
                principal_id=principal_id,
                project_id=project_id,
            )

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
        async with self._operation_approval_lock, self.transaction() as conn:
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

    async def start_agent_turn(
        self,
        *,
        turn_id: str,
        attempt_id: str,
        session_id: str,
        task_id: str | None,
        payload: dict[str, Any],
        now: float,
        principal_id: str = "legacy",
        project_id: str = "",
    ) -> None:
        """Create one durable running turn and its first event atomically.

        M4 batch 3.1.16A-4-3: ``principal_id`` is stamped as a top-level
        column on ``agent_turns`` so per-principal turn queries can
        filter without an extra JOIN to ``sessions``.  ``payload`` still
        carries ``principal_id`` in its JSON for backward compatibility
        with older consumers that read the event stream.

        M4 batch 3.1.16A-5-1b: ``project_id`` is stamped on the row for
        project identity closure.  ``recover_inflight_agent_turns`` is a
        process-wide sweep and ignores this column (same as
        ``principal_id``); per-project visibility is enforced by
        ``list_agent_turn_events`` callers.
        """
        async with self._turn_event_lock, self.transaction() as conn:
            await conn.execute(
                "INSERT INTO agent_turns(turn_id,attempt_id,session_id,task_id,"
                "status,last_sequence,started_at,principal_id,project_id) "
                "VALUES(?,?,?,?, 'running',1,?,?,?)",
                (turn_id, attempt_id, session_id, task_id, now, principal_id, project_id),
            )
            await conn.execute(
                "INSERT INTO agent_turn_events VALUES(?,1,'turn.started',?,?)",
                (turn_id, json.dumps(payload, sort_keys=True), now),
            )

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
        async with self._turn_event_lock, self.transaction() as conn:
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
            return sequence

    async def append_chat_stream_event(
        self,
        *,
        stream_id: str,
        session_id: str,
        principal_id: str,
        project_id: str,
        event_type: str,
        data: dict[str, Any],
        now: float,
        boot_id: str = "",
        runtime_id: str = "",
        lease_until: float | None = None,
        turn_id: str = "",
        attempt_id: str = "",
    ) -> int:
        """Append one Gateway-facing event and return its stream sequence.

        Round-5 Batch 5.2 (C-05) + Round-6 Batch 6.1: enforces the chat
        stream state machine keyed by ``stream_id``:
          - ``chat_streams`` main table row is created lazily on first
            append (status='running'), keyed by ``stream_id``.
          - Before appending, checks ``chat_streams.status`` — if the
            stream is already terminal, raises ``ChatStreamTerminalError``
            (defense-in-depth for "Terminal 后禁止 Append").
          - On terminal events (done/error/interrupted), performs a CAS
            ``UPDATE chat_streams SET status=? WHERE stream_id=? AND
            status='running'`` so exactly one terminal transition is
            possible.
          - On non-terminal events, renews ``lease_until`` and updates
            ``last_sequence``.
          - A session can have many streams (one per chat RPC); the
            Terminal invariant is per-stream, not per-session.
        """
        async with self._chat_event_lock, self.transaction() as conn:
            is_terminal = event_type in {"done", "error", "interrupted"}

            # C-05/6.1: lazily create the chat_streams main-table row,
            # keyed by stream_id.  INSERT OR IGNORE is safe: if a row
            # already exists (from a previous append or a crashed
            # process), it's a no-op.
            await conn.execute(
                "INSERT OR IGNORE INTO chat_streams ("
                "stream_id,session_id,turn_id,attempt_id,"
                "principal_id,project_id,status,boot_id,"
                "runtime_id,lease_until,last_sequence,terminal_event_type,"
                "started_at,terminal_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,NULL,0,NULL,?,NULL)",
                (
                    stream_id, session_id, turn_id, attempt_id,
                    principal_id, project_id,
                    "running", boot_id, runtime_id, now,
                ),
            )

            # Batch 7.2 (round-7 §十五): OWNER VERIFICATION.  Read back
            # the stream row and confirm the caller's
            # (session_id, principal_id, project_id) match the row's
            # owner.  Without this, a caller that knows (or guesses) a
            # foreign stream_id could insert events under its own
            # owner partition while mutating the victim's state-machine
            # row (INSERT OR IGNORE is a silent no-op on an existing
            # foreign row, then the SELECT below read the VICTIM's row).
            cursor = await conn.execute(
                "SELECT status, session_id, principal_id, project_id "
                "FROM chat_streams WHERE stream_id = ?",
                (stream_id,),
            )
            row = await cursor.fetchone()
            current_status = str(row["status"]) if row else "running"
            if row is not None and (
                str(row["session_id"]) != session_id
                or str(row["principal_id"]) != principal_id
                or str(row["project_id"]) != project_id
            ):
                raise ChatStreamOwnerMismatchError(
                    f"chat stream {stream_id} is owned by a "
                    f"different (session/principal/project); "
                    f"append refused"
                )
            # C-05/6.1: terminal shield — reject append if already
            # terminal.  Keyed by stream_id, NOT session_id.
            if current_status != "running":
                raise ChatStreamTerminalError(
                    f"chat stream {stream_id} is already terminal "
                    f"(status={current_status}); cannot append "
                    f"'{event_type}'"
                )

            cursor = await conn.execute(
                "SELECT COALESCE(MAX(sequence), 0) FROM chat_stream_events "
                "WHERE stream_id = ?",
                (stream_id,),
            )
            row = await cursor.fetchone()
            sequence = int(row[0]) + 1
            await conn.execute(
                "INSERT INTO chat_stream_events ("
                "stream_id,session_id,principal_id,project_id,sequence,"
                "event_type,data_json,is_terminal,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (
                    stream_id,
                    session_id,
                    principal_id,
                    project_id,
                    sequence,
                    event_type,
                    json.dumps(data, ensure_ascii=False, sort_keys=True),
                    int(is_terminal),
                    now,
                ),
            )

            # Update chat_streams state machine (keyed by stream_id).
            # Batch 7.2 (round-7 §十五): every UPDATE carries the full
            # owner predicate so a foreign caller cannot drive another
            # principal's stream to terminal or renew its lease.
            if is_terminal:
                # CAS: running → terminal (exactly one terminal).
                await conn.execute(
                    "UPDATE chat_streams SET status=?, "
                    "terminal_event_type=?, terminal_at=?, "
                    "last_sequence=? "
                    "WHERE stream_id=? AND session_id=? AND "
                    "principal_id=? AND project_id=? AND status='running'",
                    (event_type, event_type, now, sequence,
                     stream_id, session_id, principal_id, project_id),
                )
            else:
                # Renew lease + update last_sequence for running streams.
                if lease_until is not None:
                    await conn.execute(
                        "UPDATE chat_streams SET last_sequence=?, "
                        "lease_until=? WHERE stream_id=? AND session_id=? "
                        "AND principal_id=? AND project_id=?",
                        (sequence, lease_until, stream_id,
                         session_id, principal_id, project_id),
                    )
                else:
                    await conn.execute(
                        "UPDATE chat_streams SET last_sequence=? "
                        "WHERE stream_id=? AND session_id=? "
                        "AND principal_id=? AND project_id=?",
                        (sequence, stream_id,
                         session_id, principal_id, project_id),
                    )
            return sequence

    async def list_chat_stream_events(
        self,
        *,
        stream_id: str = "",
        session_id: str = "",
        principal_id: str,
        project_id: str,
        after_sequence: int = 0,
        after_event_id: int | None = None,
        limit: int = 256,
    ) -> list[dict[str, Any]]:
        """Read durable chat events after an exclusive cursor.

        Batch 7.2 (round-7 §十四): the cursor is now the session-global
        ``event_id`` (passed via ``after_sequence`` for wire-compat), NOT
        the stream-local ``sequence``.  This fixes the cross-stream
        missed-events bug: a cursor of ``event_id=3`` no longer filters
        out other streams whose stream-local ``sequence`` is <= 3.

        If ``stream_id`` is provided, returns events for that stream
        only.  If only ``session_id`` is provided, returns events across
        ALL streams for that session.  Both paths order by ``event_id``
        (the session-global monotonic cursor) so pagination is stable
        with no gaps and no duplicates on reconnect.

        Each returned event dict now includes ``event_id`` (the cursor)
        and ``stream_id`` (so the client can attribute events to
        streams) alongside the existing ``sequence``/``event``/``data``/
        ``terminal``/``created_at`` fields.
        """
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            if after_event_id is not None and after_sequence:
                raise ValueError(
                    "ambiguous replay cursor: use after_event_id only"
                )
            after = max(
                0,
                int(after_event_id if after_event_id is not None else after_sequence),
            )
            lim = max(1, min(limit, 1024))
            if stream_id:
                cursor = await conn.execute(
                    "SELECT event_id,stream_id,sequence,event_type,data_json,"
                    "is_terminal,created_at "
                    "FROM chat_stream_events WHERE stream_id=? AND principal_id=? "
                    "AND project_id=? AND event_id>? ORDER BY event_id LIMIT ?",
                    (stream_id, principal_id, project_id, after, lim),
                )
            else:
                cursor = await conn.execute(
                    "SELECT event_id,stream_id,sequence,event_type,data_json,"
                    "is_terminal,created_at "
                    "FROM chat_stream_events WHERE session_id=? AND principal_id=? "
                    "AND project_id=? AND event_id>? ORDER BY event_id LIMIT ?",
                    (session_id, principal_id, project_id, after, lim),
                )
            return [
                {
                    "event_id": int(row["event_id"]),
                    "stream_id": str(row["stream_id"]),
                    "sequence": int(row["sequence"]),
                    "event": str(row["event_type"]),
                    "data": json.loads(str(row["data_json"])),
                    "terminal": bool(row["is_terminal"]),
                    "created_at": float(row["created_at"]),
                }
                for row in await cursor.fetchall()
            ]

    async def delete_chat_stream_events_for_session(
        self,
        *,
        session_id: str,
        principal_id: str,
        project_id: str,
    ) -> int:
        """F-07: cascade-delete all chat_stream_events for one session.

        The ``chat_stream_events`` FK to ``sessions`` does not carry
        ``ON DELETE CASCADE`` (the schema predates the durable ledger),
        so session deletion must explicitly remove the events to keep
        long-lived services from accumulating unbounded ledger rows.
        Returns the number of deleted rows.

        C-02 (round-4 review): now goes through ``transaction()`` so the
        global ``_write_transaction_lock`` is acquired and the
        ``TransactionOwner`` token is set.  Previously this method
        hand-wrote ``BEGIN IMMEDIATE`` / ``commit()`` / ``rollback()``
        and only held ``_chat_event_lock``, which bypassed the
        Transaction Authority and could interleave with a concurrent
        permission grant or audit insert on the same shared connection.

        Round-5 Batch 5.2 (C-05): also cascade-deletes the matching
        ``chat_streams`` state-machine row so that deleting a session
        does not leave an orphaned state row that would later be
        recovered by ``recover_inflight_chat_streams``.

        Round-6 Batch 6.1: deletes ALL streams for the session (a
        session can now have many streams).
        """
        async with self._chat_event_lock, self.transaction() as conn:
            cursor = await conn.execute(
                "DELETE FROM chat_stream_events "
                "WHERE session_id=? AND principal_id=? AND project_id=?",
                (session_id, principal_id, project_id),
            )
            deleted = cursor.rowcount or 0
            await cursor.close()
            # C-05/6.1: cascade-delete ALL state-machine rows for
            # this session (there may be many streams).
            await conn.execute(
                "DELETE FROM chat_streams "
                "WHERE session_id=? AND principal_id=? AND project_id=?",
                (session_id, principal_id, project_id),
            )
            return deleted

    async def prune_terminal_chat_streams(
        self,
        *,
        older_than_seconds: float,
        now: float,
        limit: int = 1000,
    ) -> int:
        """F-07: drop chat_stream_events whose stream is terminal and
        older than ``older_than_seconds``.

        A stream is considered "terminal and aged-out" when its
        highest-sequence event is terminal AND that event's
        ``created_at`` is older than ``now - older_than_seconds``.  All
        events for such streams (including the terminal one) are
        deleted to bound long-term ledger growth.  ``limit`` caps the
        number of streams pruned per call so the GC stays
        latency-bounded.

        C-02 (round-4 review): now goes through ``transaction()`` (see
        ``delete_chat_stream_events_for_session`` for rationale).

        Round-5 Batch 5.2 (C-05): also cascade-deletes the matching
        ``chat_streams`` state-machine rows for the pruned streams so
        that the state table does not accumulate orphaned terminal rows.

        Round-6 Batch 6.1: prune is now per-stream (stream_id), not
        per-session.
        """
        async with self._chat_event_lock, self.transaction() as conn:
            # C-05/6.1: first compute the stream_ids that will be
            # pruned so we can cascade-delete their chat_streams rows.
            cursor = await conn.execute(
                """
                    SELECT latest.stream_id AS stream_id
                    FROM (
                        SELECT stream_id, MAX(sequence) AS sequence
                        FROM chat_stream_events GROUP BY stream_id
                    ) latest
                    JOIN chat_stream_events e
                        ON e.stream_id = latest.stream_id
                        AND e.sequence = latest.sequence
                    WHERE e.is_terminal = 1
                        AND e.created_at < ?
                    LIMIT ?
                    """,
                (now - older_than_seconds, max(1, min(limit, 10_000))),
            )
            rows = await cursor.fetchall()
            await cursor.close()
            if not rows:
                return 0
            stream_ids = [str(r["stream_id"]) for r in rows]
            placeholders = ",".join("?" * len(stream_ids))
            cursor = await conn.execute(
                f"DELETE FROM chat_stream_events "
                f"WHERE stream_id IN ({placeholders})",
                stream_ids,
            )
            deleted = cursor.rowcount or 0
            await cursor.close()
            # C-05/6.1: cascade-delete the state-machine rows.
            await conn.execute(
                f"DELETE FROM chat_streams "
                f"WHERE stream_id IN ({placeholders})",
                stream_ids,
            )
            return deleted

    async def recover_inflight_chat_streams(
        self, *, now: float, boot_id: str | None = None,
    ) -> int:
        """Close crash-left chat ledgers with a durable error terminal.

        Round-5 Batch 5.2 (C-05): recovery now respects boot_id and lease.
          - ``boot_id=None`` (legacy/test mode): recover ALL non-terminal
            streams.  Backward compatible with existing callers.
          - ``boot_id=<current>`` (production mode): only recover streams
            whose ``chat_streams.boot_id`` differs from the current boot
            (i.e. crash-left by a PREVIOUS process), OR whose lease has
            expired (owning process is likely dead).  The current
            process's own active streams are NEVER recovered.

        This function should ONLY be called at process startup (before
        any new chats are started).  Periodic maintenance must NOT call
        it — that was the C-05 bug where hourly maintenance terminated
        active chats waiting on long tool calls.

        Round-6 Batch 6.1: recovery is now per-stream (stream_id), not
        per-session.  Each non-terminal stream gets its own error
        terminal event.
        """
        async with self._chat_event_lock, self.transaction() as conn:
            if boot_id is None:
                # Legacy mode: recover all non-terminal streams.
                cursor = await conn.execute(
                    """
                        SELECT e.stream_id,e.session_id,e.principal_id,
                               e.project_id,e.sequence
                        FROM chat_stream_events e
                        JOIN (
                            SELECT stream_id,MAX(sequence) AS sequence
                            FROM chat_stream_events GROUP BY stream_id
                        ) latest ON latest.stream_id=e.stream_id
                            AND latest.sequence=e.sequence
                        WHERE e.is_terminal=0
                        """
                )
            else:
                # C-05: only recover OTHER-boot or expired-lease streams.
                cursor = await conn.execute(
                    """
                        SELECT e.stream_id,e.session_id,e.principal_id,
                               e.project_id,e.sequence
                        FROM chat_stream_events e
                        JOIN (
                            SELECT stream_id,MAX(sequence) AS sequence
                            FROM chat_stream_events GROUP BY stream_id
                        ) latest ON latest.stream_id=e.stream_id
                            AND latest.sequence=e.sequence
                        LEFT JOIN chat_streams cs
                            ON cs.stream_id=e.stream_id
                        WHERE e.is_terminal=0
                          AND (
                            cs.boot_id IS NULL
                            OR cs.boot_id=''
                            OR cs.boot_id != ?
                            OR (cs.boot_id=? AND cs.lease_until IS NOT NULL
                                AND cs.lease_until < ?)
                          )
                        """,
                    (boot_id, boot_id, now),
                )
            rows = await cursor.fetchall()
            for row in rows:
                await conn.execute(
                    "INSERT INTO chat_stream_events ("
                    "stream_id,session_id,principal_id,project_id,sequence,"
                    "event_type,data_json,is_terminal,created_at) "
                    "VALUES(?,?,?,?,?,?,?,1,?)",
                    (
                        row["stream_id"],
                        row["session_id"],
                        row["principal_id"],
                        row["project_id"],
                        int(row["sequence"]) + 1,
                        "error",
                        json.dumps({
                            "code": "PROCESS_RESTART",
                            "message": "chat interrupted by process restart",
                            "recoverable": True,
                        }, sort_keys=True),
                        now,
                    ),
                )
                # C-05/6.1: CAS the chat_streams row to terminal too.
                await conn.execute(
                    "UPDATE chat_streams SET status='error', "
                    "terminal_event_type='error', terminal_at=?, "
                    "last_sequence=? "
                    "WHERE stream_id=? AND status='running'",
                    (
                        now,
                        int(row["sequence"]) + 1,
                        row["stream_id"],
                    ),
                )
            return len(rows)

    async def recover_inflight_agent_turns(self, *, now: float) -> int:
        """Mark crash-left running turns interrupted without inventing success."""
        async with self._turn_event_lock, self.transaction() as conn:
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
            return len(rows)

    async def list_agent_turn_events(
        self, turn_id: str
    ) -> list[dict[str, Any]]:
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
            conn = await self._require_conn()
            cursor = await conn.execute(
                "SELECT * FROM agent_turn_events WHERE turn_id=? ORDER BY sequence",
                (turn_id,),
            )
            return [dict(row) for row in await cursor.fetchall()]

    async def list_completion_gate_history(
        self,
        task_id: str,
        *,
        principal_id: str,
        project_id: str,
    ) -> tuple[CompletionGateHistoryRecord, ...]:
        """Read owner-scoped ``completion.gated`` events for one task.

        M7.1.8 reuses the existing durable turn-event ledger rather than
        introducing a second gate-history table.  The task/owner predicates
        are applied to ``agent_turns`` before a bounded newest tail is handed
        to the recovery decoder; oversized bodies are replaced by an empty
        transport value plus their byte count.  The decoder, not this
        generic DB facade, owns the event payload schema.
        """
        if type(task_id) is not str or not task_id:
            raise ValueError("task_id must be a non-empty string")
        if type(principal_id) is not str or not principal_id:
            raise ValueError("principal_id must be a non-empty string")
        if type(project_id) is not str:
            raise ValueError("project_id must be a string")
        from khaos.agent.control.completion_recovery import (
            MAX_COMPLETION_GATE_HISTORY_RECORDS,
            MAX_COMPLETION_GATE_PAYLOAD_BYTES,
            CompletionGateHistoryRecord,
        )

        async with self._read_lease():
            conn = await self._require_conn()
            cursor = await conn.execute(
                """
                SELECT t.turn_id, t.attempt_id, t.task_id, t.started_at,
                       e.sequence, e.event_type,
                       CASE
                           WHEN length(CAST(e.payload_json AS BLOB)) <= ?
                           THEN e.payload_json
                           ELSE ''
                       END AS payload_json,
                       COALESCE(length(CAST(e.payload_json AS BLOB)), -1)
                           AS payload_bytes,
                       e.created_at
                FROM agent_turns AS t
                JOIN agent_turn_events AS e ON e.turn_id = t.turn_id
                WHERE t.task_id = ?
                  AND t.principal_id = ?
                  AND t.project_id = ?
                  AND e.event_type = 'completion.gated'
                ORDER BY e.created_at DESC, t.started_at DESC,
                         t.turn_id DESC, e.sequence DESC
                LIMIT ?
                """,
                (
                    MAX_COMPLETION_GATE_PAYLOAD_BYTES,
                    task_id,
                    principal_id,
                    project_id,
                    MAX_COMPLETION_GATE_HISTORY_RECORDS,
                ),
            )
            rows = await cursor.fetchall()
        # The query reads the newest bounded tail so a current gate result is
        # retained while memory use remains fixed.  Restore chronological
        # order for callers that inspect the history deterministically.
        rows.reverse()
        return tuple(
            CompletionGateHistoryRecord(
                turn_id=row["turn_id"],
                attempt_id=row["attempt_id"],
                task_id=row["task_id"],
                event_sequence=row["sequence"],
                event_type=row["event_type"],
                payload_json=row["payload_json"],
                payload_bytes=row["payload_bytes"],
                created_at=row["created_at"],
                turn_started_at=row["started_at"],
            )
            for row in rows
        )

    async def prune_terminal_agent_turns(
        self, *, older_than_seconds: float, now: float, limit: int = 256
    ) -> dict[str, int]:
        """Bound completed turn journals while retaining live turns."""
        cutoff = now - max(0.0, older_than_seconds)
        async with self._turn_event_lock, self.transaction() as conn:
            cursor = await conn.execute(
                "SELECT turn_id FROM agent_turns "
                "WHERE status != 'running' AND finished_at IS NOT NULL "
                "AND finished_at < ? ORDER BY finished_at LIMIT ?",
                (cutoff, max(1, min(limit, 10_000))),
            )
            turn_ids = [str(row["turn_id"]) for row in await cursor.fetchall()]
            if not turn_ids:
                return {"agent_turn_events": 0, "agent_turns": 0}
            placeholders = ",".join("?" for _ in turn_ids)
            events = await conn.execute(
                f"DELETE FROM agent_turn_events WHERE turn_id IN ({placeholders})",
                tuple(turn_ids),
            )
            turns = await conn.execute(
                f"DELETE FROM agent_turns WHERE turn_id IN ({placeholders})",
                tuple(turn_ids),
            )
            return {
                "agent_turn_events": int(events.rowcount or 0),
                "agent_turns": int(turns.rowcount or 0),
            }

    async def approve_operation_approval(
        self,
        approval_id: str,
        *,
        principal_id: str,
        session_id: str,
        now: float,
    ) -> bool:
        async with self._operation_approval_lock, self.transaction() as conn:
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
            return success

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
        async with self._operation_approval_lock, self.transaction() as conn:
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
            return success

    async def cancel_operation_approval(
        self, approval_id: str, *, now: float
    ) -> None:
        async with self._operation_approval_lock, self.transaction() as conn:
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

    async def list_operation_approval_events(
        self, approval_id: str
    ) -> list[dict[str, Any]]:
        async with self._read_lease():  # Batch 6.5 §十八 reader operation lease
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

    async def prune_approval_ledger(
        self, *, retention_seconds: int
    ) -> dict[str, int]:
        """Batch 6.5 (round-6 §25.3): DB-level retention for the durable
        approval ledger.

        ``ApprovalBroker.sweep_expired`` clears the in-memory dicts only;
        the underlying ``operation_approvals`` / ``operation_approval_events``
        rows accumulated without bound.  This method deletes rows that are
        either terminal (``consumed`` / ``cancelled``) OR past their
        ``expires_at`` by more than ``retention_seconds`` — a grace window
        so recently-resolved approvals remain auditable.  The matching
        ``operation_approval_events`` rows are pruned via cascading
        deletion on the approval id.

        Returns ``{"operation_approvals": N, "operation_approval_events": N}``
        with the per-table deleted counts.

        This is a WRITE and runs under ``transaction()`` so the prune is
        atomic.  The Maintenance loop calls it hourly.
        """
        retention_seconds = max(retention_seconds, 0)
        cutoff = time.time() - retention_seconds
        deleted_op = 0
        deleted_ev = 0
        async with self.transaction() as conn:
            # Collect the approval_ids we are about to remove so we can
            # prune their events in the same transaction (the events table
            # has no FK cascade — it is append-only audit).
            cursor = await conn.execute(
                """
                SELECT approval_id FROM operation_approvals
                WHERE status IN ('consumed', 'cancelled')
                   OR (expires_at IS NOT NULL AND expires_at < ?)
                """,
                (cutoff,),
            )
            stale_ids = [str(row["approval_id"]) for row in await cursor.fetchall()]
            if stale_ids:
                # Prune events for the stale approvals first.
                placeholders = ",".join("?" for _ in stale_ids)
                ev_cur = await conn.execute(
                    f"DELETE FROM operation_approval_events "
                    f"WHERE approval_id IN ({placeholders})",
                    stale_ids,
                )
                deleted_ev = ev_cur.rowcount or 0
                op_cur = await conn.execute(
                    f"DELETE FROM operation_approvals "
                    f"WHERE approval_id IN ({placeholders})",
                    stale_ids,
                )
                deleted_op = op_cur.rowcount or 0
        logger.debug(
            "prune_approval_ledger: removed %d operation_approvals + %d "
            "events (retention_seconds=%d, cutoff=%d)",
            deleted_op, deleted_ev, retention_seconds, int(cutoff),
        )
        return {
            "operation_approvals": deleted_op,
            "operation_approval_events": deleted_ev,
        }

    async def _require_conn(self):
        """Return the appropriate connection for the current context.

        C-04 (round-4 review): routes to the writer connection when the
        current task owns an active transaction (so intra-transaction
        reads see uncommitted writes), and to the reader connection
        otherwise (so reads never see another task's uncommitted writer
        state on the shared SQLite connection).

        C-01: the owner check uses the full TransactionOwner token
        (database_id + connection_generation + task), not just
        ``is not None``.  A leaked ContextVar from a different task or
        database is treated as "no owner" and routed to the reader —
        the leaked task's writes would fail closed on the reader's
        ``query_only`` PRAGMA.

        Migration context: when ``self._conn`` is a
        ``_MigrationConnection`` (i.e. ``run_migrations()`` is in
        progress), always return it — the migration helpers need the
        writer connection (wrapped by ``_MigrationConnection`` to
        suppress intermediate commits), not the reader.
        """
        # During migration, self._conn is _MigrationConnection — use it
        # directly so _ensure_* helpers ALTER TABLE on the writer, not
        # the query_only reader.
        if isinstance(self._conn, _MigrationConnection):
            return self._conn
        owner = _current_transaction_owner.get()
        if (
            owner is not None
            and owner.database_id == id(self)
            and owner.connection_generation == self._connection_generation
            and owner.task is asyncio.current_task()
        ):
            # Inside a transaction owned by this task: use writer so
            # reads see uncommitted writes within the same transaction.
            return self._conn  # type: ignore[return-value]
        return await self._require_reader_conn()
