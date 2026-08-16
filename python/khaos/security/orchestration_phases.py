"""Immutable orchestration phase evidence for the agent and tool TCBs.

The phase objects in this module are deliberately small.  They do not own
execution, approval, or persistence state; they carry the immutable evidence
that a caller may use to prove which orchestration boundary a value crossed.
Mutable adapters can still exist at the edges, but a phase transition always
returns a new object and rejects skipped or reversed transitions.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Any


class OrchestrationPhaseError(ValueError):
    """Raised when an orchestration phase is malformed or skips a boundary."""


class TurnPhase(str, Enum):
    """Durable boundaries for one AgentLoop turn."""

    ADMITTED = "admitted"
    CONTEXT_ASSEMBLED = "context_assembled"
    MODEL_EXECUTING = "model_executing"
    TOOL_EXECUTING = "tool_executing"
    VERIFYING = "verifying"
    FINALIZING = "finalizing"
    FINALIZED = "finalized"


_TURN_TRANSITIONS: Mapping[TurnPhase, frozenset[TurnPhase]] = MappingProxyType(
    {
        TurnPhase.ADMITTED: frozenset(
            {TurnPhase.CONTEXT_ASSEMBLED, TurnPhase.FINALIZING}
        ),
        TurnPhase.CONTEXT_ASSEMBLED: frozenset(
            {TurnPhase.MODEL_EXECUTING, TurnPhase.FINALIZING}
        ),
        TurnPhase.MODEL_EXECUTING: frozenset(
            {TurnPhase.TOOL_EXECUTING, TurnPhase.FINALIZING}
        ),
        TurnPhase.TOOL_EXECUTING: frozenset(
            {
                TurnPhase.MODEL_EXECUTING,
                TurnPhase.VERIFYING,
                TurnPhase.FINALIZING,
            }
        ),
        TurnPhase.VERIFYING: frozenset(
            {TurnPhase.MODEL_EXECUTING, TurnPhase.FINALIZING}
        ),
        TurnPhase.FINALIZING: frozenset({TurnPhase.FINALIZED}),
        TurnPhase.FINALIZED: frozenset(),
    }
)


class ToolPhase(str, Enum):
    """Security boundaries for one ToolScheduler call."""

    RAW = "raw"
    VALIDATED = "validated"
    RESOURCE_RESOLVED = "resource_resolved"
    PERMISSION_DECIDED = "permission_decided"
    APPROVAL_BOUND = "approval_bound"
    AUTHORIZED_EFFECT = "authorized_effect"
    DISPATCHING = "dispatching"
    TERMINAL = "terminal"


_TOOL_TRANSITIONS: Mapping[ToolPhase, frozenset[ToolPhase]] = MappingProxyType(
    {
        ToolPhase.RAW: frozenset({ToolPhase.VALIDATED}),
        ToolPhase.VALIDATED: frozenset({ToolPhase.RESOURCE_RESOLVED}),
        ToolPhase.RESOURCE_RESOLVED: frozenset(
            {ToolPhase.PERMISSION_DECIDED}
        ),
        ToolPhase.PERMISSION_DECIDED: frozenset({ToolPhase.APPROVAL_BOUND}),
        ToolPhase.APPROVAL_BOUND: frozenset({ToolPhase.AUTHORIZED_EFFECT}),
        ToolPhase.AUTHORIZED_EFFECT: frozenset({ToolPhase.DISPATCHING}),
        ToolPhase.DISPATCHING: frozenset({ToolPhase.TERMINAL}),
        ToolPhase.TERMINAL: frozenset(),
    }
)


def _digest(value: Any) -> str:
    """Return a strict, deterministic digest for phase evidence."""
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise OrchestrationPhaseError(
            f"phase evidence is not canonical JSON: {type(exc).__name__}"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _immutable_metadata(
    metadata: Mapping[str, str] | None,
) -> Mapping[str, str]:
    """Copy and freeze small phase metadata at the trust boundary."""
    values = dict(metadata or {})
    if any(type(key) is not str or type(value) is not str for key, value in values.items()):
        raise OrchestrationPhaseError("phase metadata must be string-to-string")
    return MappingProxyType(values)


@dataclass(frozen=True, slots=True)
class TurnPhaseSnapshot:
    """Immutable evidence for the current AgentLoop orchestration phase."""

    phase: TurnPhase
    session_id: str
    turn_id: str
    attempt_id: str
    task_id: str = ""
    context_digest: str = ""
    tool_batch_digest: str = ""
    verification_digest: str = ""
    terminal_status: str = ""
    metadata: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if not all(
            type(value) is str
            for value in (
                self.session_id,
                self.turn_id,
                self.attempt_id,
                self.task_id,
                self.context_digest,
                self.tool_batch_digest,
                self.verification_digest,
                self.terminal_status,
            )
        ):
            raise OrchestrationPhaseError("turn phase identity fields must be strings")
        if not isinstance(self.phase, TurnPhase):
            raise OrchestrationPhaseError("invalid turn phase")
        object.__setattr__(self, "metadata", _immutable_metadata(self.metadata))

    @classmethod
    def admitted(
        cls,
        *,
        session_id: str,
        turn_id: str,
        attempt_id: str,
        task_id: str = "",
    ) -> TurnPhaseSnapshot:
        """Create the first immutable phase for an admitted turn."""
        return cls(
            phase=TurnPhase.ADMITTED,
            session_id=session_id,
            turn_id=turn_id,
            attempt_id=attempt_id,
            task_id=task_id,
        )

    def transition(
        self,
        next_phase: TurnPhase,
        *,
        context_digest: str | None = None,
        tool_batch_digest: str | None = None,
        verification_digest: str | None = None,
        terminal_status: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> TurnPhaseSnapshot:
        """Advance exactly one allowed boundary and return a new snapshot."""
        if not isinstance(next_phase, TurnPhase):
            raise OrchestrationPhaseError("invalid turn phase")
        if next_phase not in _TURN_TRANSITIONS[self.phase]:
            raise OrchestrationPhaseError(
                f"invalid turn transition: {self.phase.value} -> {next_phase.value}"
            )
        return TurnPhaseSnapshot(
            phase=next_phase,
            session_id=self.session_id,
            turn_id=self.turn_id,
            attempt_id=self.attempt_id,
            task_id=self.task_id,
            context_digest=(
                self.context_digest
                if context_digest is None
                else context_digest
            ),
            tool_batch_digest=(
                self.tool_batch_digest
                if tool_batch_digest is None
                else tool_batch_digest
            ),
            verification_digest=(
                self.verification_digest
                if verification_digest is None
                else verification_digest
            ),
            terminal_status=(
                self.terminal_status
                if terminal_status is None
                else terminal_status
            ),
            metadata=(self.metadata if metadata is None else metadata),
        )

    def digest(self) -> str:
        """Return the immutable evidence digest for this phase."""
        return _digest(
            {
                "phase": self.phase.value,
                "session_id": self.session_id,
                "turn_id": self.turn_id,
                "attempt_id": self.attempt_id,
                "task_id": self.task_id,
                "context_digest": self.context_digest,
                "tool_batch_digest": self.tool_batch_digest,
                "verification_digest": self.verification_digest,
                "terminal_status": self.terminal_status,
                "metadata": dict(self.metadata),
            }
        )


@dataclass(frozen=True, slots=True)
class ToolPhaseSnapshot:
    """Immutable evidence for one tool's authorization/dispatch path."""

    phase: ToolPhase
    tool_call_id: str
    tool_name: str
    arguments_digest: str = ""
    resource_digest: str = ""
    permission_digest: str = ""
    approval_digest: str = ""
    authority_digest: str = ""
    effect_digest: str = ""
    result_digest: str = ""
    metadata: Mapping[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        if not all(
            type(value) is str
            for value in (
                self.tool_call_id,
                self.tool_name,
                self.arguments_digest,
                self.resource_digest,
                self.permission_digest,
                self.approval_digest,
                self.authority_digest,
                self.effect_digest,
                self.result_digest,
            )
        ):
            raise OrchestrationPhaseError("tool phase fields must be strings")
        if not isinstance(self.phase, ToolPhase):
            raise OrchestrationPhaseError("invalid tool phase")
        if not self.tool_call_id or not self.tool_name:
            raise OrchestrationPhaseError("tool phase identity is required")
        object.__setattr__(self, "metadata", _immutable_metadata(self.metadata))

    @classmethod
    def raw(cls, call: Mapping[str, Any]) -> ToolPhaseSnapshot:
        """Capture the raw call without retaining its mutable argument map."""
        tool_call_id = call.get("id")
        tool_name = call.get("name")
        if type(tool_call_id) is not str or not tool_call_id:
            raise OrchestrationPhaseError("tool call id is required")
        if type(tool_name) is not str or not tool_name:
            raise OrchestrationPhaseError("tool name is required")
        arguments = call.get("arguments", {})
        return cls(
            phase=ToolPhase.RAW,
            tool_call_id=tool_call_id,
            tool_name=tool_name,
            arguments_digest=_digest(arguments),
        )

    def transition(
        self,
        next_phase: ToolPhase,
        *,
        resource_digest: str | None = None,
        permission_digest: str | None = None,
        approval_digest: str | None = None,
        authority_digest: str | None = None,
        effect_digest: str | None = None,
        result_digest: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> ToolPhaseSnapshot:
        """Advance exactly one allowed tool boundary."""
        if not isinstance(next_phase, ToolPhase):
            raise OrchestrationPhaseError("invalid tool phase")
        if next_phase not in _TOOL_TRANSITIONS[self.phase]:
            raise OrchestrationPhaseError(
                f"invalid tool transition: {self.phase.value} -> {next_phase.value}"
            )
        return ToolPhaseSnapshot(
            phase=next_phase,
            tool_call_id=self.tool_call_id,
            tool_name=self.tool_name,
            arguments_digest=self.arguments_digest,
            resource_digest=(
                self.resource_digest
                if resource_digest is None
                else resource_digest
            ),
            permission_digest=(
                self.permission_digest
                if permission_digest is None
                else permission_digest
            ),
            approval_digest=(
                self.approval_digest
                if approval_digest is None
                else approval_digest
            ),
            authority_digest=(
                self.authority_digest
                if authority_digest is None
                else authority_digest
            ),
            effect_digest=(
                self.effect_digest if effect_digest is None else effect_digest
            ),
            result_digest=(
                self.result_digest if result_digest is None else result_digest
            ),
            metadata=(self.metadata if metadata is None else metadata),
        )

    def assert_call(self, call: Mapping[str, Any]) -> None:
        """Reject a mutable call map that drifted from the raw snapshot."""
        if call.get("id") != self.tool_call_id or call.get("name") != self.tool_name:
            raise OrchestrationPhaseError("tool call identity changed after admission")
        if _digest(call.get("arguments", {})) != self.arguments_digest:
            raise OrchestrationPhaseError(
                "tool arguments changed after phase admission"
            )

    def digest(self) -> str:
        """Return the immutable evidence digest for this phase."""
        return _digest(
            {
                "phase": self.phase.value,
                "tool_call_id": self.tool_call_id,
                "tool_name": self.tool_name,
                "arguments_digest": self.arguments_digest,
                "resource_digest": self.resource_digest,
                "permission_digest": self.permission_digest,
                "approval_digest": self.approval_digest,
                "authority_digest": self.authority_digest,
                "effect_digest": self.effect_digest,
                "result_digest": self.result_digest,
                "metadata": dict(self.metadata),
            }
        )


def digest_phase_payload(value: Any) -> str:
    """Expose strict phase payload hashing to orchestration adapters."""
    return _digest(value)


__all__ = [
    "OrchestrationPhaseError",
    "ToolPhase",
    "ToolPhaseSnapshot",
    "TurnPhase",
    "TurnPhaseSnapshot",
    "digest_phase_payload",
]
