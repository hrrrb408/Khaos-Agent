"""Runtime coordination for durable tool-operation idempotency.

The operation store owns the in-process claim/event map and consumes the
durable operation-row protocol from ``db.repositories.tool_operations``.  It
does not admit calls, evaluate permissions, or invoke handlers.  The durable
repository is injected explicitly so a missing owner fails closed instead of
silently falling back to process-local idempotency.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, replace
from typing import Any

from khaos.db.repositories.tool_operations import ToolOperationRepository
from khaos.exceptions import PermissionDeniedError
from khaos.security.protocol_boundary import canonical_digest
from khaos.tools.result_codec import ToolResultCodec
from khaos.tools.result_store import ToolResultStore
from khaos.tools.scheduler_models import (
    DELIVERY_AUDIT_DEGRADED,
    DELIVERY_DEGRADED,
    EFFECT_UNKNOWN,
    ToolResult,
)

logger = logging.getLogger(__name__)


@dataclass
class OperationClaim:
    """In-process view of a durable tool-operation claim."""

    operation_id: str
    owner_token: str
    effect_id: str
    arguments_digest: str = ""
    result: ToolResult | None = None
    wait_event: asyncio.Event | None = None


class ToolOperationStore:
    """Own operation identity, claim, wait, and terminal result protocols."""

    def __init__(
        self,
        *,
        repository: ToolOperationRepository | None,
        result_store: ToolResultStore,
    ) -> None:
        self._repository = repository
        self._result_store = result_store
        self._events: dict[str, asyncio.Event] = {}
        self._claims: dict[str, OperationClaim] = {}
        self._lock = asyncio.Lock()

    def _require_repository(self) -> ToolOperationRepository:
        """Return the durable owner or fail closed before an effect edge."""
        if self._repository is None:
            raise RuntimeError(
                "durable tool-operation repository is required for idempotency"
            )
        return self._repository

    def scope(
        self,
        idempotency_key: str,
        *,
        tool_name: str,
        session_id: str | None,
        tool_context: Mapping[str, Any],
    ) -> str:
        """Return a principal/session/workspace-bound operation identity."""
        key = str(idempotency_key or "").strip()
        if not key:
            return ""
        return canonical_digest(
            {
                "idempotency_key": key,
                "tool_name": tool_name,
                "principal_id": str(tool_context.get("principal_id") or ""),
                "project_id": str(tool_context.get("project_id") or ""),
                "session_id": str(session_id or tool_context.get("session_id") or ""),
                "task_id": str(tool_context.get("task_id") or ""),
                "workspace_id": str(tool_context.get("workspace_id") or ""),
            }
        )

    async def get_result(
        self,
        call: Mapping[str, Any],
        *,
        session_id: str | None,
        tool_context: Mapping[str, Any],
    ) -> ToolResult | None:
        operation_id = self.scope(
            str(call.get("_idempotency_key") or ""),
            tool_name=str(call.get("name") or ""),
            session_id=session_id,
            tool_context=tool_context,
        )
        if not operation_id:
            return None
        return await self._result_store.get(
            operation_id, canonical_digest(call.get("arguments", {}))
        )

    async def put_result(
        self,
        call: Mapping[str, Any],
        *,
        session_id: str | None,
        tool_context: Mapping[str, Any],
        result: ToolResult,
    ) -> None:
        operation_id = self.scope(
            str(call.get("_idempotency_key") or ""),
            tool_name=str(call.get("name") or ""),
            session_id=session_id,
            tool_context=tool_context,
        )
        if not operation_id:
            return
        await self._result_store.put(
            operation_id,
            canonical_digest(call.get("arguments", {})),
            result,
        )

    async def claim(
        self,
        call: Mapping[str, Any],
        *,
        tool: Any,
        session_id: str | None,
        tool_context: Mapping[str, Any],
    ) -> OperationClaim | None:
        """Claim a durable operation before a handler crosses its effect edge."""
        async with self._lock:
            return await self._claim_locked(
                call,
                tool=tool,
                session_id=session_id,
                tool_context=tool_context,
            )

    async def _claim_locked(
        self,
        call: Mapping[str, Any],
        *,
        tool: Any,
        session_id: str | None,
        tool_context: Mapping[str, Any],
    ) -> OperationClaim | None:
        operation_id = self.scope(
            str(call.get("_idempotency_key") or ""),
            tool_name=str(tool.name),
            session_id=session_id,
            tool_context=tool_context,
        )
        if not operation_id:
            return None
        arguments_digest = canonical_digest(call.get("arguments", {}))
        cached_result = await self._result_store.get(operation_id, arguments_digest)
        if cached_result is not None:
            return OperationClaim(
                operation_id=operation_id,
                owner_token="",
                effect_id=cached_result.effect_id,
                arguments_digest=arguments_digest,
                result=cached_result,
            )

        active_event = self._events.get(operation_id)
        if active_event is not None:
            active_claim = self._claims.get(operation_id)
            if (
                active_claim is not None
                and active_claim.arguments_digest != arguments_digest
            ):
                raise PermissionDeniedError(
                    "idempotency key was reused with different tool arguments"
                )
            return OperationClaim(
                operation_id=operation_id,
                owner_token="",
                effect_id=(active_claim.effect_id if active_claim else ""),
                arguments_digest=arguments_digest,
                wait_event=active_event,
            )

        owner_token = uuid.uuid4().hex
        effect_id = uuid.uuid4().hex
        row = await self._require_repository().claim_tool_operation(
            operation_id=operation_id,
            tool_name=tool.name,
            arguments_digest=arguments_digest,
            effect_id=effect_id,
            owner_token=owner_token,
            principal_id=str(tool_context.get("principal_id") or ""),
            project_id=str(tool_context.get("project_id") or ""),
            session_id=str(session_id or tool_context.get("session_id") or ""),
            task_id=str(tool_context.get("task_id") or ""),
            workspace_id=str(tool_context.get("workspace_id") or ""),
        )
        if row.get("state") == "conflict":
            raise PermissionDeniedError(
                str(
                    row.get("conflict_reason")
                    or "idempotency operation identity conflict"
                )
            )
        if row.get("state") == "claimed":
            event = asyncio.Event()
            self._events[operation_id] = event
            claim = OperationClaim(
                operation_id=operation_id,
                owner_token=owner_token,
                effect_id=str(row["effect_id"]),
                arguments_digest=arguments_digest,
            )
            self._claims[operation_id] = claim
            return claim
        if row.get("status") != "running":
            return OperationClaim(
                operation_id=operation_id,
                owner_token="",
                effect_id=str(row.get("effect_id") or ""),
                arguments_digest=arguments_digest,
                result=ToolResultCodec.deserialize_operation_result(
                    row, call=call, tool=tool
                ),
            )

        orphan = ToolResultCodec.deserialize_operation_result(row, call=call, tool=tool)
        orphan = replace(
            orphan,
            effect_status=EFFECT_UNKNOWN,
            success=False,
            error="durable operation was running without a live owner",
            retry_safe=False,
            warning="previous execution ownership was lost; reconcile before retry",
            reconciliation_hint=(
                str(row.get("reconciliation_hint") or "")
                or "inspect the external side effect using effect_id"
            ),
        )
        await self._require_repository().mark_tool_operation_unknown(
            operation_id=operation_id,
            reconciliation_hint=orphan.reconciliation_hint,
            result_json=ToolResultCodec.serialize_operation_result(orphan),
        )
        return OperationClaim(
            operation_id=operation_id,
            owner_token="",
            effect_id=str(row.get("effect_id") or ""),
            arguments_digest=arguments_digest,
            result=orphan,
        )

    async def wait(
        self,
        claim: OperationClaim,
        *,
        call: Mapping[str, Any],
        tool: Any,
        session_id: str | None,
        tool_context: Mapping[str, Any],
        timeout: float,
    ) -> ToolResult:
        """Wait for a local owner, then disclose missing durable evidence."""
        if claim.wait_event is not None:
            try:
                await asyncio.wait_for(
                    claim.wait_event.wait(), timeout=max(1.0, timeout)
                )
            except TimeoutError:
                return ToolResult(
                    tool_call_id=str(call["id"]),
                    name=tool.name,
                    success=False,
                    error="idempotent operation did not finish before the wait deadline",
                    arguments=dict(call.get("arguments", {})),
                    effect_status=EFFECT_UNKNOWN,
                    delivery_status=DELIVERY_DEGRADED,
                    warning="reconcile effect_id before retry",
                    effect_id=claim.effect_id,
                    reconciliation_hint="the original handler may still be running",
                    retry_safe=False,
                )
        result = await self._result_store.get(
            claim.operation_id, canonical_digest(call.get("arguments", {}))
        )
        if result is not None:
            return result
        row = await self._require_repository().claim_tool_operation(
            operation_id=claim.operation_id,
            tool_name=tool.name,
            arguments_digest=canonical_digest(call.get("arguments", {})),
            effect_id=uuid.uuid4().hex,
            owner_token=uuid.uuid4().hex,
            principal_id=str(tool_context.get("principal_id") or ""),
            project_id=str(tool_context.get("project_id") or ""),
            session_id=str(session_id or tool_context.get("session_id") or ""),
            task_id=str(tool_context.get("task_id") or ""),
            workspace_id=str(tool_context.get("workspace_id") or ""),
        )
        if row.get("status") != "running":
            return ToolResultCodec.deserialize_operation_result(row, call=call, tool=tool)
        return ToolResult(
            tool_call_id=str(call["id"]),
            name=tool.name,
            success=False,
            error="idempotent operation completed without a durable result",
            arguments=dict(call.get("arguments", {})),
            effect_status=EFFECT_UNKNOWN,
            delivery_status=DELIVERY_DEGRADED,
            warning="reconcile effect_id before retry",
            effect_id=claim.effect_id,
            reconciliation_hint="durable result missing",
            retry_safe=False,
        )

    async def finish(
        self,
        claim: OperationClaim | None,
        result: ToolResult,
        *,
        terminal_status: str,
    ) -> ToolResult:
        """Persist terminal evidence and wake local duplicate callers."""
        if claim is None:
            return result
        journal_error = ""
        if claim.owner_token:
            try:
                updated = await self._require_repository().complete_tool_operation(
                    operation_id=claim.operation_id,
                    owner_token=claim.owner_token,
                    status=terminal_status,
                    effect_status=result.effect_status,
                    reconciliation_hint=result.reconciliation_hint,
                    result_json=ToolResultCodec.serialize_operation_result(result),
                )
                if not updated:
                    journal_error = (
                        "durable tool operation lost ownership before finalize"
                    )
            except Exception as exc:
                journal_error = f"durable operation finalization failed: {exc}"
                logger.exception(
                    "durable tool operation finalization failed: operation_id=%s",
                    claim.operation_id,
                )
        try:
            cached_result = result
            if journal_error:
                hint = result.reconciliation_hint or (
                    "durable operation finalization failed; reconcile effect_id "
                    "before retry"
                )
                warning = result.warning
                warning = f"{warning}; " if warning else ""
                warning += journal_error
                cached_result = replace(
                    result,
                    delivery_status=(
                        result.delivery_status
                        if result.delivery_status == DELIVERY_AUDIT_DEGRADED
                        else DELIVERY_DEGRADED
                    ),
                    warning=warning,
                    reconciliation_hint=hint,
                    retry_safe=False,
                )
            await self._result_store.put(
                claim.operation_id,
                canonical_digest(cached_result.arguments or {}),
                cached_result,
            )
            event = self._events.pop(claim.operation_id, None)
            self._claims.pop(claim.operation_id, None)
            if event is not None:
                event.set()
            return cached_result
        except Exception as exc:
            logger.exception(
                "in-process operation finalization failed: operation_id=%s",
                claim.operation_id,
            )
            warning = result.warning
            warning = f"{warning}; " if warning else ""
            warning += f"in-process operation finalization failed: {exc}"
            return replace(
                result,
                delivery_status=(
                    result.delivery_status
                    if result.delivery_status == DELIVERY_AUDIT_DEGRADED
                    else DELIVERY_DEGRADED
                ),
                warning=warning,
                reconciliation_hint=(
                    result.reconciliation_hint
                    or "operation finalization failed; reconcile effect_id before retry"
                ),
                retry_safe=False,
            )

    async def update_effect_id(self, claim: OperationClaim, effect_id: str) -> None:
        """Persist a handler-provided external effect identity before finalize."""
        if not claim.owner_token or not effect_id:
            return
        updated = await self._require_repository().update_tool_operation_effect_id(
            operation_id=claim.operation_id,
            owner_token=claim.owner_token,
            effect_id=effect_id,
        )
        if not updated:
            raise RuntimeError("durable tool operation lost ownership")


__all__ = ["OperationClaim", "ToolOperationStore"]
