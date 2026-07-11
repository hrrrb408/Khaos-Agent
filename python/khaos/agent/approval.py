"""Shared approval broker for tool permissions and task APIs."""

from __future__ import annotations

import asyncio
import time
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
        self._bindings: dict[str, tuple[str, float | None]] = {}
        self._operation_approvals: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    async def bind(self, tool_call_id: str, approval_key: str, expiry: float | None = None) -> None:
        """Bind a pending approval to an immutable ChangeSet operation."""
        async with self._lock:
            self._bindings[tool_call_id] = (approval_key, expiry)

    async def wait(self, tool_call_id: str, timeout: float | None = None) -> dict:
        async with self._lock:
            future = self._pending.get(tool_call_id)
            if future is None:
                decision = self._decisions.pop(tool_call_id, None)
                if decision is not None:
                    self._bindings.pop(tool_call_id, None)
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
            binding = self._bindings.get(tool_call_id)
            if binding is not None and (binding[0] != approval_key or binding[1] is not None and time.time() >= binding[1]):
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

    async def register_operation(
        self, approval_id: str, binding: dict, expiry: float
    ) -> None:
        """Register immutable destructive-operation state before prompting."""
        async with self._lock:
            self._operation_approvals[approval_id] = {
                "binding": dict(binding),
                "expiry": expiry,
                "approved": False,
                "used": False,
            }

    async def approve_operation(self, approval_id: str, requester: str) -> bool:
        """Mark a registered operation approved by its bound requester."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if (
                record is None
                or record["used"]
                or time.time() >= record["expiry"]
                or record["binding"].get("requester") != requester
            ):
                return False
            record["approved"] = True
            return True

    async def consume_operation(self, approval_id: str, binding: dict) -> bool:
        """Atomically consume an approved operation; every attempt is one-shot."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is None or record["used"]:
                return False
            record["used"] = True
            return bool(
                record["approved"]
                and time.time() < record["expiry"]
                and record["binding"] == binding
            )

    async def cancel_operation(self, approval_id: str) -> None:
        """Make a denied or cancelled destructive approval non-replayable."""
        async with self._lock:
            record = self._operation_approvals.get(approval_id)
            if record is not None:
                record["used"] = True
