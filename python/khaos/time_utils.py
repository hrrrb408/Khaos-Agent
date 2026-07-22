"""Time helpers with explicit UTC semantics."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now_naive() -> datetime:
    """Return current UTC as a naive datetime for legacy DB compatibility."""
    return datetime.now(UTC).replace(tzinfo=None)
