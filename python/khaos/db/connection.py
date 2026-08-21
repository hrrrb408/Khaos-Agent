"""Connection lifecycle boundary for the shared SQLite database.

``Database`` owns domain repositories and transaction orchestration.  This
module owns only the physical writer/reader pair and its lifecycle fences:

* both connections are atomically published after configuration;
* the reader is query-only and every read holds a bounded close lease;
* close is fail-closed and quarantines a connection that cannot be torn down;
* the ``:memory:`` path uses one shared-cache URI for writer and reader.

The migration runner may temporarily replace ``writer`` with its
``_MigrationConnection`` facade.  The property is intentionally public to
the containing package so that the frozen migration source remains unchanged
while ownership of the physical connections is explicit.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

try:
    import aiosqlite
except ModuleNotFoundError:  # pragma: no cover - bare environments only
    aiosqlite = None

logger = logging.getLogger(__name__)

READER_DRAIN_TIMEOUT = 10.0


class DatabaseClosingError(RuntimeError):
    """A connection operation was attempted across the close fence."""


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
    """Small sqlite3-backed async facade used when aiosqlite is unavailable."""

    def __init__(self, path: str, *, uri: bool = False):
        self._conn = sqlite3.connect(path, uri=uri)
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


class DatabaseConnection:
    """Own the physical SQLite connections and lifecycle state.

    The class deliberately does not know about repositories, migrations, or
    transaction ownership.  ``Database`` serializes writes around this
    object; callers that need a connection receive one through the explicit
    writer/reader methods below.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        self.writer: Any | None = None
        self.reader: Any | None = None
        self.generation = 0
        self.lifecycle_lock = asyncio.Lock()
        self.active_readers = 0
        self.readers_idle = asyncio.Event()
        self.readers_idle.set()
        self.reader_drain_lock = asyncio.Lock()
        self.closing = False
        self.close_state = "OPEN"
        self.memory_uri: str | None = None

    async def connect(self) -> None:
        """Open and configure writer/reader connections atomically."""
        async with self.lifecycle_lock:
            if self.close_state == "QUARANTINED":
                raise DatabaseClosingError(
                    "database close failed and is quarantined; retry close "
                    "before reconnecting"
                )
            if self.writer is not None:
                return

            writer: Any = None
            reader: Any = None
            try:
                if aiosqlite is None:
                    if self.path == ":memory:":
                        self.memory_uri = self.memory_uri or (
                            f"file:khaos-{uuid.uuid4().hex}?mode=memory&cache=shared"
                        )
                        writer = _AsyncSqliteFallback(self.memory_uri, uri=True)
                        reader = _AsyncSqliteFallback(self.memory_uri, uri=True)
                    else:
                        writer = _AsyncSqliteFallback(self.path)
                        reader = _AsyncSqliteFallback(self.path)
                elif self.path == ":memory:":
                    self.memory_uri = self.memory_uri or (
                        f"file:khaos-{uuid.uuid4().hex}?mode=memory&cache=shared"
                    )
                    writer = await aiosqlite.connect(self.memory_uri, uri=True)
                    writer.row_factory = aiosqlite.Row
                    reader = await aiosqlite.connect(self.memory_uri, uri=True)
                    reader.row_factory = aiosqlite.Row
                else:
                    writer = await aiosqlite.connect(self.path)
                    writer.row_factory = aiosqlite.Row
                    reader = await aiosqlite.connect(self.path)
                    reader.row_factory = aiosqlite.Row

                await writer.execute("PRAGMA foreign_keys = ON")
                await writer.execute("PRAGMA journal_mode = WAL")
                await writer.execute("PRAGMA busy_timeout = 5000")
                await reader.execute("PRAGMA foreign_keys = ON")
                await reader.execute("PRAGMA query_only = ON")
                await reader.execute("PRAGMA busy_timeout = 5000")

                # Publish only after both handles are fully configured.  A
                # reader-open failure therefore cannot leave a half-open DB.
                self.writer = writer
                self.reader = reader
                writer = None
                reader = None
            finally:
                await self._close_partial(reader, "reader")
                await self._close_partial(writer, "writer")

    async def _close_partial(self, connection: Any, label: str) -> None:
        if connection is None:
            return
        try:
            await connection.close()
        except Exception as exc:  # pragma: no cover - cleanup best effort
            logger.debug("failed to close partial %s connection", label, exc_info=exc)

    async def close(self) -> None:
        """Close both handles after rejecting new reader operations."""
        async with self.lifecycle_lock:
            self.closing = True
            self.close_state = "CLOSING"
            self.generation += 1
            try:
                if self.writer is not None:
                    await self.writer.close()
                    self.writer = None
                await self.wait_readers_drained()
                if self.reader is not None:
                    await self.reader.close()
                    self.reader = None
            except BaseException:
                self.close_state = "QUARANTINED"
                raise
            else:
                self.close_state = "CLOSED"
                self.closing = False

    @asynccontextmanager
    async def read_lease(self) -> AsyncIterator[None]:
        """Admit one reader operation until it exits or close completes."""
        if self.closing:
            raise DatabaseClosingError(
                "database is closing; new read operations are rejected"
            )
        self.active_readers += 1
        self.readers_idle.clear()
        try:
            yield
        finally:
            self.active_readers -= 1
            if self.active_readers <= 0:
                self.active_readers = 0
                self.readers_idle.set()

    async def wait_readers_drained(self) -> None:
        """Wait for active readers, with a bounded close deadline."""
        if self.active_readers == 0:
            return
        logger.debug(
            "close: waiting for %d in-flight reader(s) to drain",
            self.active_readers,
        )
        try:
            await asyncio.wait_for(
                self.readers_idle.wait(), timeout=READER_DRAIN_TIMEOUT
            )
        except TimeoutError:
            logger.warning(
                "close: %d reader(s) still in flight after %.1fs drain timeout; "
                "closing reader connection anyway",
                self.active_readers,
                READER_DRAIN_TIMEOUT,
            )

    async def require_writer(self) -> Any:
        """Return the writer, opening the pair when needed."""
        if self.writer is None:
            await self.connect()
        assert self.writer is not None
        return self.writer

    async def require_writer_locked(self) -> Any:
        """Return the writer while the caller holds the write lock."""
        return await self.require_writer()

    async def require_reader(self) -> Any:
        """Return the query-only reader, opening the pair when needed."""
        if self.reader is None:
            await self.connect()
        assert self.reader is not None
        return self.reader


__all__ = [
    "READER_DRAIN_TIMEOUT",
    "DatabaseClosingError",
    "DatabaseConnection",
]
