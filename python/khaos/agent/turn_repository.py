"""Durable turn persistence port and the SQLite composition adapter.

``TurnCoordinator`` owns the in-memory turn state machine.  This module owns
the persistence boundary it is allowed to call.  The database facade remains
the lifecycle/transaction owner, but callers no longer pass a database object
into the coordinator or reach arbitrary database methods from the agent
state machine.
"""

from __future__ import annotations

from typing import Any, Protocol


class TurnRepository(Protocol):
    """Persistence operations required by one durable agent turn."""

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
        """Create a running turn and its initial event atomically."""

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
        """Append one event using the turn's compare-and-set sequence."""

    async def recover_inflight_agent_turns(self, *, now: float) -> int:
        """Mark turns left running by a previous process as interrupted."""


class DatabaseTurnRepository:
    """Narrow turn port backed by the shared :class:`khaos.db.Database`.

    This adapter is intentionally the only place in the agent layer that
    knows the database method names for turn persistence.  Replacing the
    storage implementation therefore changes one composition adapter rather
    than the coordinator and its state-machine tests.
    """

    __slots__ = ("__weakref__", "_db")

    def __init__(self, db: Any) -> None:
        self._db = db

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
        await self._db.start_agent_turn(
            turn_id=turn_id,
            attempt_id=attempt_id,
            session_id=session_id,
            task_id=task_id,
            payload=payload,
            now=now,
            principal_id=principal_id,
            project_id=project_id,
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
        return await self._db.append_agent_turn_event(
            turn_id=turn_id,
            expected_sequence=expected_sequence,
            event_type=event_type,
            payload=payload,
            now=now,
            terminal_status=terminal_status,
            error_code=error_code,
        )

    async def recover_inflight_agent_turns(self, *, now: float) -> int:
        return await self._db.recover_inflight_agent_turns(now=now)


__all__ = ["DatabaseTurnRepository", "TurnRepository"]
