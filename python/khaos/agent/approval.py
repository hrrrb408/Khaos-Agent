"""Shared approval broker for tool permissions and task APIs."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


@dataclass(frozen=True)
class ApprovalDecision:
    approved: bool
    remember: bool = False


class ApprovalBroker:
    """One await/resolve channel keyed by tool call id."""

    def __init__(self) -> None:
        self._pending: dict[str, asyncio.Future[ApprovalDecision]] = {}
        self._decisions: dict[str, ApprovalDecision] = {}
        self._bindings: dict[str, str] = {}
        self._lock = asyncio.Lock()

    async def bind(self, tool_call_id: str, approval_key: str) -> None:
        """Bind a pending approval to an immutable ChangeSet operation."""
        async with self._lock:
            self._bindings[tool_call_id] = approval_key

    async def wait(self, tool_call_id: str, timeout: float | None = None) -> dict:
        async with self._lock:
            future = self._pending.get(tool_call_id)
            if future is None:
                decision = self._decisions.pop(tool_call_id, None)
                if decision is not None:
                    return {"approved": decision.approved, "remember": decision.remember}
                future = asyncio.get_running_loop().create_future()
                self._pending[tool_call_id] = future
        try:
            decision = await asyncio.wait_for(asyncio.shield(future), timeout) if timeout else await future
            return {"approved": decision.approved, "remember": decision.remember}
        except asyncio.TimeoutError:
            return {"approved": False, "remember": False}
        finally:
            async with self._lock:
                self._pending.pop(tool_call_id, None)

    async def resolve(
        self,
        tool_call_id: str,
        approved: bool,
        remember: bool = False,
        approval_key: str | None = None,
    ) -> bool:
        async with self._lock:
            expected_key = self._bindings.get(tool_call_id)
            if expected_key is not None and expected_key != approval_key:
                return False
            future = self._pending.get(tool_call_id)
            if future is None:
                self._decisions[tool_call_id] = ApprovalDecision(approved, remember)
                return True
            if future.done():
                return False
            future.set_result(ApprovalDecision(approved, remember))
            self._bindings.pop(tool_call_id, None)
            return True
