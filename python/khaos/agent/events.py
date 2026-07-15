"""Durable single-writer turn event coordination."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass
from typing import Any


_RECOVERED_DATABASES: set[int] = set()


@dataclass(frozen=True)
class TurnEvent:
    turn_id: str
    attempt_id: str
    sequence: int
    event_type: str
    payload: dict[str, Any]


class TurnCoordinator:
    """Append one ordered event stream and exactly one durable terminal."""

    def __init__(
        self, db: Any, *, turn_id: str, attempt_id: str, sequence: int = 1
    ) -> None:
        self._db = db
        self.turn_id = turn_id
        self.attempt_id = attempt_id
        self.sequence = sequence
        self._terminal = False
        self._active_tool_calls: set[str] = set()

    @classmethod
    async def start(
        cls,
        db: Any,
        *,
        session_id: str,
        task_id: str | None,
        principal_id: str,
    ) -> "TurnCoordinator":
        await _recover_once(db)
        turn_id = uuid.uuid4().hex
        attempt_id = uuid.uuid4().hex
        await db.start_agent_turn(
            turn_id=turn_id,
            attempt_id=attempt_id,
            session_id=session_id,
            task_id=task_id,
            payload={
                "principal_id": principal_id,
                "session_id": session_id,
                "task_id": task_id,
                "attempt_id": attempt_id,
            },
            now=time.time(),
        )
        return cls(db, turn_id=turn_id, attempt_id=attempt_id)

    async def emit(
        self, event_type: str, payload: dict[str, Any] | None = None
    ) -> TurnEvent:
        if self._terminal:
            raise PermissionError("late event after terminal turn state")
        value = dict(payload or {})
        call_id = str(value.get("tool_call_id") or value.get("id") or "")
        if event_type == "tool.call":
            if not call_id or call_id in self._active_tool_calls:
                raise PermissionError("duplicate or missing tool call id")
            self._active_tool_calls.add(call_id)
        elif event_type == "tool.result":
            if call_id not in self._active_tool_calls:
                raise PermissionError("tool result has no unmatched tool call")
            self._active_tool_calls.remove(call_id)
        elif event_type == "approval.wait" and call_id not in self._active_tool_calls:
            raise PermissionError("approval wait has no tool call")
        self.sequence = await self._db.append_agent_turn_event(
            turn_id=self.turn_id,
            expected_sequence=self.sequence,
            event_type=event_type,
            payload=value,
            now=time.time(),
        )
        return TurnEvent(
            self.turn_id, self.attempt_id, self.sequence, event_type, value
        )

    async def terminal(
        self,
        status: str,
        *,
        reason: str,
        error_code: str | None = None,
    ) -> TurnEvent:
        if self._terminal:
            raise PermissionError("turn already has a terminal event")
        event_type = f"turn.{status}"
        payload = {
            "reason": reason,
            "unmatched_tool_calls": sorted(self._active_tool_calls),
        }
        self.sequence = await self._db.append_agent_turn_event(
            turn_id=self.turn_id,
            expected_sequence=self.sequence,
            event_type=event_type,
            payload=payload,
            now=time.time(),
            terminal_status=status,
            error_code=error_code,
        )
        self._terminal = True
        return TurnEvent(
            self.turn_id, self.attempt_id, self.sequence, event_type, payload
        )

    @property
    def is_terminal(self) -> bool:
        return self._terminal


async def _recover_once(db: Any) -> None:
    key = id(db)
    if key in _RECOVERED_DATABASES:
        return
    _RECOVERED_DATABASES.add(key)
    try:
        await db.recover_inflight_agent_turns(now=time.time())
    except Exception:
        _RECOVERED_DATABASES.discard(key)
        raise
