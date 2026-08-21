"""Domain models for the durable memory subsystem.

This module deliberately contains no persistence or orchestration code.  Keeping
the value objects here makes the storage adapter and the injection pipeline
depend on a small, stable contract instead of on SQLite row details.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any


class MemoryScope(Enum):
    """Visibility scope used by the three-layer memory model."""

    GLOBAL = "global"
    OFFICE = "office"
    CODING = "coding"


class MemoryConfidence(Enum):
    """Confidence assigned to a memory assertion."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Memory:
    """One durable memory entry.

    ``id`` and timestamps are populated by persistence.  Callers creating a
    new value should leave ``id`` and timestamps unset.
    """

    id: int | None
    scope: MemoryScope
    key: str
    value: str
    ttl: int = 604800
    confidence: MemoryConfidence = MemoryConfidence.MEDIUM
    access_freq: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None


def memory_from_row(row: Mapping[str, Any]) -> Memory:
    """Convert one repository row into the public domain model."""

    return Memory(
        id=int(row["id"]),
        scope=MemoryScope(str(row["scope"])),
        key=str(row["key"]),
        value=str(row["value"]),
        ttl=int(row["ttl"]),
        confidence=MemoryConfidence(int(row["confidence"])),
        access_freq=int(row["access_freq"]),
        created_at=parse_datetime(row.get("created_at")),
        updated_at=parse_datetime(row.get("updated_at")),
    )


def parse_datetime(value: Any) -> datetime | None:
    """Parse an optional SQLite ISO timestamp without leaking row semantics."""

    if not value:
        return None
    return datetime.fromisoformat(str(value))


__all__ = [
    "Memory",
    "MemoryConfidence",
    "MemoryScope",
    "memory_from_row",
    "parse_datetime",
]
