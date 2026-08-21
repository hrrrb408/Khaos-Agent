"""Deterministic, side-effect-free admission for tool calls.

Admission is the first scheduler boundary after a model or integration hands
over a call.  It normalizes the untrusted call shape, captures immutable raw
phase evidence, resolves the declared tool, and validates the arguments.  It
does not inspect permissions, prepare an authority, invoke a handler, or
write audit state; those responsibilities stay in :class:`ToolScheduler`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from khaos.security.orchestration_components import ToolPhaseCoordinator
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
)
from khaos.tools.registry import ToolDefinition, ToolRegistry


@dataclass(frozen=True, slots=True)
class AdmittedToolCall:
    """A normalized call with a declared tool and validated arguments."""

    call: dict[str, Any]
    tool: ToolDefinition


@dataclass(frozen=True, slots=True)
class RejectedToolCall:
    """A safe projection for an expected admission failure."""

    call: dict[str, Any]
    error: str


ToolAdmissionResult = AdmittedToolCall | RejectedToolCall


class ToolAdmission:
    """Own the side-effect-free validation boundary for one tool call."""

    def __init__(self, registry: ToolRegistry):
        self._registry = registry

    def admit(self, call: dict[str, Any]) -> ToolAdmissionResult:
        """Normalize and validate one call without executing it.

        Unknown tool names intentionally propagate the registry's
        ``ToolNotFoundError``.  That is a caller/configuration error, whereas
        malformed phase evidence and invalid arguments are ordinary rejected
        calls that the scheduler can report as a ``ToolResult``.
        """
        normalized = self.normalize_call(call)
        try:
            raw_phase = ToolPhaseSnapshot.raw(normalized)
        except OrchestrationPhaseError as exc:
            return RejectedToolCall(
                normalized,
                f"Tool phase admission rejected: {exc}",
            )
        normalized["_phase_snapshot"] = raw_phase
        normalized["_phase_digest"] = raw_phase.digest()

        tool = self._registry.get(normalized["name"])
        if not self._registry.validate_call(tool.name, normalized["arguments"]):
            return RejectedToolCall(normalized, "Invalid tool arguments")

        ToolPhaseCoordinator.advance(normalized, ToolPhase.VALIDATED)
        return AdmittedToolCall(normalized, tool)

    @staticmethod
    def normalize_call(call: dict[str, Any]) -> dict[str, Any]:
        """Copy the model-visible shape and discard untrusted fields."""
        normalized = {
            "id": str(call.get("id") or call.get("tool_call_id") or call.get("name")),
            "name": str(call["name"]),
            "arguments": dict(call.get("arguments") or {}),
        }
        # Only the server-side binding path may carry an operation key.
        # A top-level value supplied by a model, gateway caller, or plugin is
        # untrusted input and must not become durable idempotency authority.
        if call.get("_server_operation_key") is True:
            idempotency_key = call.get("_idempotency_key")
            if idempotency_key:
                normalized["_idempotency_key"] = str(idempotency_key)
                normalized["_server_operation_key"] = True
        return normalized


__all__ = [
    "AdmittedToolCall",
    "RejectedToolCall",
    "ToolAdmission",
    "ToolAdmissionResult",
]
