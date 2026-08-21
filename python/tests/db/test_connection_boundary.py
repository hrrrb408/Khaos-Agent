"""Contract tests for the physical SQLite connection boundary."""

import asyncio

import pytest
from khaos.db import Database
from khaos.db.connection import DatabaseClosingError, DatabaseConnection


async def test_database_facade_exposes_one_connection_owner(tmp_path):
    db = Database(tmp_path / "owner.db")
    assert isinstance(db._connection, DatabaseConnection)
    assert db._conn is None

    await db.connect()
    try:
        assert db._conn is db._connection.writer
        assert db._reader_conn is db._connection.reader
        assert db._connection_generation == db._connection.generation
    finally:
        await db.close()


async def test_connection_owner_rejects_new_reads_across_close_fence(tmp_path):
    connection = DatabaseConnection(tmp_path / "fence.db")
    await connection.connect()
    try:
        connection.closing = True
        with pytest.raises(DatabaseClosingError):
            async with connection.read_lease():
                pass
    finally:
        connection.closing = False
        await connection.close()


async def test_connection_owner_drains_reader_leases_before_close(tmp_path):
    connection = DatabaseConnection(tmp_path / "drain.db")
    await connection.connect()
    entered = asyncio.Event()
    release = asyncio.Event()

    async def reader_task():
        async with connection.read_lease():
            entered.set()
            await release.wait()

    task = asyncio.create_task(reader_task())
    await entered.wait()
    close_task = asyncio.create_task(connection.close())
    await asyncio.sleep(0)
    assert not close_task.done()
    release.set()
    await task
    await close_task
    assert connection.close_state == "CLOSED"
    assert connection.writer is None
    assert connection.reader is None
