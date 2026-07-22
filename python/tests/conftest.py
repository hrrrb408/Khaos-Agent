"""Shared test fixtures."""
from __future__ import annotations

import os
import asyncio
import sqlite3

import pytest

# Force mock mode for all tests — prevent accidentally hitting real APIs
os.environ.setdefault("KHAOS_NO_CONFIG", "1")
# M4 batch 3.1.16A-1: tests legitimately need to create databases in
# ``tmp_path`` without each test constructing a state-root path.  This
# bypasses the state-root enforcement in ``state_root.py`` so that
# ``Database(tmp_path / "khaos.db")`` and ``serve_json_lines(socket,
# str(tmp_path / "khaos.db"), ...)`` continue to work unchanged.
# Production code never sets this variable.
os.environ.setdefault("KHAOS_ALLOW_PROJECT_DB", "1")


@pytest.fixture(autouse=True)
def _close_test_event_loops(monkeypatch):
    """Close private event loops created by synchronous test adapters."""
    event_loops: list[asyncio.AbstractEventLoop] = []
    original_new_event_loop = asyncio.new_event_loop

    def tracked_new_event_loop():
        loop = original_new_event_loop()
        event_loops.append(loop)
        return loop

    monkeypatch.setattr(asyncio, "new_event_loop", tracked_new_event_loop)
    yield
    for loop in reversed(event_loops):
        if not loop.is_closed():
            loop.run_until_complete(loop.shutdown_asyncgens())
            loop.close()


@pytest.fixture(autouse=True)
async def _close_test_databases(monkeypatch, _close_test_event_loops):
    """Close async and raw SQLite connections before the test loop ends."""
    import aiosqlite

    from khaos.db import Database

    instances: list[Database] = []
    async_connections: list[aiosqlite.Connection] = []
    raw_connections: list[sqlite3.Connection] = []
    original_init = Database.__init__
    original_async_init = aiosqlite.Connection.__init__
    original_connect = sqlite3.connect

    def tracked_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        instances.append(self)

    def tracked_connect(*args, **kwargs):
        # Worker-thread tests intentionally pass connections across thread
        # boundaries.  Keep that explicit test behavior cleanup-safe too.
        kwargs.setdefault("check_same_thread", False)
        connection = original_connect(*args, **kwargs)
        raw_connections.append(connection)
        return connection

    def tracked_async_init(self, *args, **kwargs):
        original_async_init(self, *args, **kwargs)
        async_connections.append(self)

    monkeypatch.setattr(Database, "__init__", tracked_init)
    # Patch the constructor rather than only ``aiosqlite.connect``: callers
    # may retain a previously imported alias to the factory, which otherwise
    # escapes per-test cleanup and is only reported by Python 3.13 much later.
    monkeypatch.setattr(aiosqlite.Connection, "__init__", tracked_async_init)
    monkeypatch.setattr(sqlite3, "connect", tracked_connect)
    yield
    for database in reversed(instances):
        await database.close()
    for connection in reversed(async_connections):
        if connection._connection is not None:
            await connection.close()
    for connection in reversed(raw_connections):
        connection.close()
