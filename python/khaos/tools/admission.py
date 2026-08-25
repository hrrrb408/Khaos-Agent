"""Deterministic, side-effect-free admission for tool calls.

Admission is the first scheduler boundary after a model or integration hands
over a call.  It normalizes the untrusted call shape, captures immutable raw
phase evidence, resolves the declared tool, and validates the arguments.  It
does not inspect permissions, prepare an authority, invoke a handler, or
write audit state; those responsibilities stay in :class:`ToolScheduler`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

from khaos.security.orchestration_components import ToolPhaseCoordinator
from khaos.security.orchestration_phases import (
    OrchestrationPhaseError,
    ToolPhase,
    ToolPhaseSnapshot,
)
from khaos.tools.registry import ToolDefinition, ToolRegistry


@dataclass(frozen=True, slots=True)
class AdmittedToolCall:
    """A normalized call with an immutable argument snapshot.

    The scheduler may attach its own phase/resource metadata to a detached
    state map, but it cannot replace the argument snapshot consumed by the
    authorization and execution owners.  ``scheduler_state`` is the only
    mutable compatibility projection; the admitted object is the authority
    source for the call payload.
    """

    call: Mapping[str, Any]
    tool: ToolDefinition
    phase_snapshot: ToolPhaseSnapshot

    @property
    def arguments_digest(self) -> str:
        """Return the digest captured before any scheduler side effect."""
        return self.phase_snapshot.arguments_digest

    def materialize_arguments(self) -> dict[str, Any]:
        """Return a detached handler argument map from the frozen snapshot."""
        arguments = self.call.get("arguments", {})
        return _thaw(arguments)

    def assert_unchanged(self, state: Mapping[str, Any] | None = None) -> None:
        """Reject identity or argument drift in a mutable scheduler state."""
        self.phase_snapshot.assert_call(self.call if state is None else state)

    def scheduler_state(self) -> dict[str, Any]:
        """Create the scheduler's detached metadata/state projection."""
        state = _thaw(self.call)
        state["_admitted_call"] = self
        return state


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
        arguments = cast(dict[str, Any], normalized["arguments"])
        if not self._registry.validate_call(tool.name, arguments):
            return RejectedToolCall(normalized, "Invalid tool arguments")

        ToolPhaseCoordinator.advance(normalized, ToolPhase.VALIDATED)
        immutable = _freeze(normalized)
        phase_snapshot = immutable.get("_phase_snapshot")
        if not isinstance(phase_snapshot, ToolPhaseSnapshot):
            raise OrchestrationPhaseError(
                "validated tool call is missing immutable phase evidence"
            )
        return AdmittedToolCall(immutable, tool, phase_snapshot)

    @staticmethod
    def normalize_call(call: dict[str, Any]) -> dict[str, Any]:
        """Copy the model-visible shape and discard untrusted fields."""
        normalized: dict[str, Any] = {
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


def _freeze(value: Any) -> Any:
    """Recursively freeze JSON-shaped model data at the admission boundary."""
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, Any], value)
        frozen: dict[str, Any] = {
            str(key): _freeze(item) for key, item in mapping.items()
        }
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        items = cast(tuple[Any, ...] | list[Any], value)
        return tuple(_freeze(item) for item in items)
    return value


def _thaw(value: Any) -> Any:
    """Detach an immutable snapshot for legacy scheduler/handler adapters."""
    if isinstance(value, Mapping):
        mapping = cast(Mapping[object, Any], value)
        return {str(key): _thaw(item) for key, item in mapping.items()}
    if isinstance(value, tuple):
        items = cast(tuple[Any, ...], value)
        return [_thaw(item) for item in items]
    return value


__all__ = [
    "AdmittedToolCall",
    "RejectedToolCall",
    "ToolAdmission",
    "ToolAdmissionResult",
]
