"""Negative tests for the memory SQL repository boundary."""

from khaos.db import Database
from khaos.db.repositories.memories import MemorySqlRepository
from khaos.memory import SqliteMemoryRepository


def test_database_does_not_publish_memory_sql_facade_methods():
    """Memory SQL must have one repository owner, not a second facade."""
    removed = {
        "upsert_memory",
        "get_memory",
        "delete_memory",
        "delete_memory_by_id",
        "list_memories",
        "search_memories",
        "touch_memory",
    }
    assert removed.isdisjoint(vars(Database))
    assert hasattr(Database, "read_connection")


def test_memory_sql_adapter_is_the_repository_owner():
    """The public adapter must inherit the SQL repository implementation."""
    assert issubclass(SqliteMemoryRepository, MemorySqlRepository)
