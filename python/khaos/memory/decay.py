"""Pure TTL-expiration policy for durable memories."""

from __future__ import annotations

from datetime import datetime

from khaos.memory.models import Memory


def expired_memory_ids(
    memories: list[Memory],
    *,
    now: datetime,
) -> list[int]:
    """Return IDs whose last update is older than their TTL.

    Rows without an ID or timestamp are not eligible for automatic deletion;
    this is the safe treatment for legacy and partially migrated rows.
    """

    expired: list[int] = []
    for memory in memories:
        if memory.id is None or memory.updated_at is None:
            continue
        if (now - memory.updated_at).total_seconds() > memory.ttl:
            expired.append(memory.id)
    return expired


__all__ = ["expired_memory_ids"]
