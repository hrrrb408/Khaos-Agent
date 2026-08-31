"""Canonical runtime-domain event bridge for Memory V2.

The bridge is intentionally small: domain owners (AgentLoop, TaskManager,
approval, workspace, and verification) publish structured facts here, while
the Broker/ledger remain the only canonical persistence boundary.  It also
keeps unbounded tool output out of the append-only ledger.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from khaos.memory.core.contracts import (
    MemoryEvent,
    MemoryEventType,
    RuntimeMemoryContext,
    Sensitivity,
    SourceType,
    TrustHint,
    canonical_json,
)

logger = logging.getLogger(__name__)


class MemoryEventBridge:
    """Publish bounded, fully scoped runtime events through a Broker."""

    def __init__(self, broker: Any, *, max_payload_bytes: int = 32 * 1024) -> None:
        if broker is None or not callable(getattr(broker, "record_event", None)):
            raise ValueError("MemoryEventBridge requires the canonical MemoryBroker")
        if max_payload_bytes <= 0:
            raise ValueError("max_payload_bytes must be positive")
        self._broker = broker
        self.max_payload_bytes = max_payload_bytes

    async def record(
        self,
        event_type: MemoryEventType | str,
        runtime: RuntimeMemoryContext,
        payload: Mapping[str, Any],
        *,
        source_type: SourceType | str = SourceType.SYSTEM,
        trust_hint: TrustHint | str = TrustHint.AGENT_INFERRED,
        source_ref: str | None = None,
        sensitivity: Sensitivity | str = Sensitivity.INTERNAL,
        occurred_at: datetime | None = None,
    ) -> MemoryEvent:
        """Create and append one host-bound event."""

        bounded = _bound_payload(payload, self.max_payload_bytes)
        event = MemoryEvent.create(
            event_type,
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            session_id=runtime.session_id,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
            repo_id=runtime.repo_id,
            branch=runtime.branch,
            commit_sha=runtime.commit_sha,
            source_type=source_type,
            source_ref=source_ref,
            occurred_at=occurred_at,
            trust_hint=trust_hint,
            sensitivity=sensitivity,
            payload=bounded,
        )
        await self._broker.record_event(event)
        return event

    async def user_message(self, runtime: RuntimeMemoryContext, *, content: str, **metadata: Any) -> MemoryEvent:
        """Record a user message and preserve only bounded content."""

        return await self.record(
            MemoryEventType.USER_MESSAGE,
            runtime,
            {"role": "user", "content": content, **metadata},
            source_type=SourceType.USER,
            trust_hint=TrustHint.USER_STATED,
        )

    async def assistant_message(self, runtime: RuntimeMemoryContext, *, content: str, **metadata: Any) -> MemoryEvent:
        """Record an assistant observation, never an instruction authority."""

        return await self.record(
            MemoryEventType.ASSISTANT_MESSAGE,
            runtime,
            {"role": "assistant", "content": content, **metadata},
            source_type=SourceType.SYSTEM,
        )

    async def tool_call(self, runtime: RuntimeMemoryContext, **payload: Any) -> MemoryEvent:
        """Record a tool invocation with bounded arguments metadata."""

        return await self.record(
            MemoryEventType.TOOL_CALL,
            runtime,
            payload,
            source_type=SourceType.TOOL,
            trust_hint=TrustHint.TOOL_OBSERVED,
        )

    async def tool_result(self, runtime: RuntimeMemoryContext, **payload: Any) -> MemoryEvent:
        """Record tool outcome metadata used by failure/decision extraction."""

        return await self.record(
            MemoryEventType.TOOL_RESULT,
            runtime,
            payload,
            source_type=SourceType.TOOL,
            trust_hint=TrustHint.TOOL_OBSERVED,
        )

    async def task(self, runtime: RuntimeMemoryContext, *, transition: str, **payload: Any) -> MemoryEvent:
        """Record a task creation/transition event."""

        event_type = (
            MemoryEventType.TASK_CREATED
            if transition == "created"
            else MemoryEventType.TASK_TRANSITION
        )
        return await self.record(event_type, runtime, {"transition": transition, **payload})

    async def approval(self, runtime: RuntimeMemoryContext, *, decided: bool, **payload: Any) -> MemoryEvent:
        """Record an approval request or decision without making policy."""

        return await self.record(
            MemoryEventType.APPROVAL_DECIDED if decided else MemoryEventType.APPROVAL_REQUESTED,
            runtime,
            payload,
            source_type=SourceType.SYSTEM,
        )

    async def verification(self, runtime: RuntimeMemoryContext, *, result: bool, **payload: Any) -> MemoryEvent:
        """Record verification lifecycle evidence; receipt minting stays separate."""

        return await self.record(
            MemoryEventType.VERIFICATION_RESULT,
            runtime,
            {"result": result, **payload},
            source_type=SourceType.VERIFICATION,
            trust_hint=TrustHint.VERIFICATION_CONFIRMED if result else TrustHint.AGENT_INFERRED,
        )

    async def record_and_admit(
        self,
        event_type: MemoryEventType | str,
        runtime: RuntimeMemoryContext,
        payload: Mapping[str, Any],
        *,
        profile: Any = None,
        source_type: SourceType | str = SourceType.SYSTEM,
        trust_hint: TrustHint | str = TrustHint.AGENT_INFERRED,
        source_ref: str | None = None,
        sensitivity: Sensitivity | str = Sensitivity.INTERNAL,
        occurred_at: datetime | None = None,
    ) -> MemoryEvent:
        """Publish an event and admit its bounded derived candidates."""

        event = await self.record(
            event_type,
            runtime,
            payload,
            source_type=source_type,
            trust_hint=trust_hint,
            source_ref=source_ref,
            sensitivity=sensitivity,
            occurred_at=occurred_at,
        )
        max_candidates = int(getattr(profile, "max_mutations_per_event", 16))
        if max_candidates <= 0:
            return event
        from khaos.memory.extraction import extract_candidates_from_event

        for candidate in extract_candidates_from_event(event, profile=profile)[:max_candidates]:
            try:
                await self._broker.propose_memory(candidate, runtime)
            except (TypeError, ValueError, RuntimeError):
                logger.warning(
                    "memory candidate admission failed for event %s",
                    event.event_id,
                    exc_info=True,
                )
        return event


def _bound_payload(payload: Mapping[str, Any], max_bytes: int) -> dict[str, Any]:
    """Bound nested values and fail closed if the event is still oversized."""

    if not isinstance(payload, Mapping):
        raise TypeError("event payload must be a mapping")
    bounded = {
        str(key): _bound_value(value, key=str(key)) for key, value in payload.items()
    }
    encoded = canonical_json(bounded).encode("utf-8")
    if len(encoded) <= max_bytes:
        return bounded
    summary = {
        "truncated": True,
        "payload_sha256": hashlib.sha256(encoded).hexdigest(),
        "payload_bytes": len(encoded),
        "keys": sorted(bounded)[:256],
    }
    if len(canonical_json(summary).encode("utf-8")) > max_bytes:
        raise ValueError("runtime event payload exceeds the bounded ledger limit")
    return summary


_SECRET_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "access_token",
        "authorization",
        "bearer_token",
        "cookie",
        "credential",
        "credentials",
        "dispatch_token",
        "password",
        "private_key",
        "secret",
        "secret_value",
        "sandbox_token",
        "approval_receipt",
        "approval_token",
        "capability_handle",
        "credential_handle",
        "verification_proof",
    }
)
_SECRET_TEXT_PATTERNS = (
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    re.compile(r"(?i)\b(?:api[_ -]?key|access[_ -]?token|secret|password)\s*[:=]\s*[^\s,;]+"),
)


def _bound_value(value: Any, *, key: str = "") -> Any:
    """Bound values and remove known authority/secret material."""

    if key.casefold() in _SECRET_FIELD_NAMES:
        return "[REDACTED_SECRET]"
    if isinstance(value, str):
        sanitized = value
        for pattern in _SECRET_TEXT_PATTERNS:
            sanitized = pattern.sub("[REDACTED_SECRET]", sanitized)
        if len(sanitized.encode("utf-8")) <= 4096:
            return sanitized
        encoded = sanitized.encode("utf-8")
        return {
            "truncated": True,
            "sha256": hashlib.sha256(encoded).hexdigest(),
            "bytes": len(encoded),
            "preview": encoded[:1024].decode("utf-8", errors="replace"),
        }
    if isinstance(value, Mapping):
        return {
            str(key): _bound_value(item, key=str(key))
            for key, item in list(value.items())[:256]
        }
    if isinstance(value, (list, tuple)):
        return [_bound_value(item) for item in list(value)[:256]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


__all__ = ["MemoryEventBridge"]
