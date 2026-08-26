"""Pure durable Agent Cognitive State contracts.

The cognitive state describes the engineering phase an agent is in.  It is
deliberately separate from ``TurnPhase`` (per-turn orchestration) and
``TaskStatus`` (task lifecycle).  This module contains no database or agent
loop dependency so the transition graph remains a single, testable authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from types import MappingProxyType
from typing import Final


class AgentCognitiveState(str, Enum):
    """Durable engineering phase of an agent task.

    Terminal task lifecycle states such as ``blocked``, ``completed``,
    ``failed``, and ``cancelled`` intentionally do not belong here.  They are
    owned by ``TaskStatus`` and can legally coexist with a non-terminal
    cognitive phase while the task is waiting for an external condition.
    """

    UNINITIALIZED = "uninitialized"
    UNDERSTANDING = "understanding"
    EXPLORING = "exploring"
    PLANNING = "planning"
    IMPLEMENTING = "implementing"
    VERIFYING = "verifying"
    DIAGNOSING = "diagnosing"
    RECOVERING = "recovering"
    REPLANNING = "replanning"
    REVIEWING = "reviewing"
    COMPLETION_CHECK = "completion_check"

    @classmethod
    def parse(cls, value: str) -> AgentCognitiveState:
        """Parse one persisted state, rejecting non-string/unknown values."""
        if type(value) is not str:
            raise ValueError("cognitive state must be a string")
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(f"unknown cognitive state: {value!r}") from exc


class CognitiveTransitionValidation(str, Enum):
    """Pure validation outcome for one requested cognitive transition."""

    ALLOWED = "allowed"
    UNCHANGED = "unchanged"
    ILLEGAL = "illegal_transition"


# This is the sole transition authority.  Both the mapping and every target
# collection are immutable, so callers cannot widen the graph at runtime.
LEGAL_COGNITIVE_TRANSITIONS: Final[
    Mapping[AgentCognitiveState, frozenset[AgentCognitiveState]]
] = MappingProxyType(
    {
        AgentCognitiveState.UNINITIALIZED: frozenset(
            {AgentCognitiveState.UNDERSTANDING}
        ),
        AgentCognitiveState.UNDERSTANDING: frozenset(
            {
                AgentCognitiveState.EXPLORING,
                AgentCognitiveState.PLANNING,
                AgentCognitiveState.IMPLEMENTING,
            }
        ),
        AgentCognitiveState.EXPLORING: frozenset(
            {
                AgentCognitiveState.PLANNING,
                AgentCognitiveState.IMPLEMENTING,
                AgentCognitiveState.DIAGNOSING,
            }
        ),
        AgentCognitiveState.PLANNING: frozenset(
            {
                AgentCognitiveState.EXPLORING,
                AgentCognitiveState.IMPLEMENTING,
                AgentCognitiveState.REPLANNING,
            }
        ),
        AgentCognitiveState.IMPLEMENTING: frozenset(
            {
                AgentCognitiveState.EXPLORING,
                AgentCognitiveState.VERIFYING,
                AgentCognitiveState.DIAGNOSING,
            }
        ),
        AgentCognitiveState.VERIFYING: frozenset(
            {
                AgentCognitiveState.REVIEWING,
                AgentCognitiveState.DIAGNOSING,
                AgentCognitiveState.RECOVERING,
            }
        ),
        AgentCognitiveState.DIAGNOSING: frozenset(
            {
                AgentCognitiveState.EXPLORING,
                AgentCognitiveState.RECOVERING,
                AgentCognitiveState.REPLANNING,
            }
        ),
        AgentCognitiveState.RECOVERING: frozenset(
            {
                AgentCognitiveState.IMPLEMENTING,
                AgentCognitiveState.VERIFYING,
                AgentCognitiveState.REPLANNING,
            }
        ),
        AgentCognitiveState.REPLANNING: frozenset(
            {
                AgentCognitiveState.EXPLORING,
                AgentCognitiveState.PLANNING,
            }
        ),
        AgentCognitiveState.REVIEWING: frozenset(
            {
                AgentCognitiveState.COMPLETION_CHECK,
                AgentCognitiveState.DIAGNOSING,
                AgentCognitiveState.REPLANNING,
            }
        ),
        AgentCognitiveState.COMPLETION_CHECK: frozenset(
            {
                AgentCognitiveState.REPLANNING,
                AgentCognitiveState.REVIEWING,
            }
        ),
    }
)


class AgentCognitiveStateMachine:
    """Pure validator for the closed cognitive transition graph."""

    @staticmethod
    def _require_state(value: AgentCognitiveState) -> None:
        if type(value) is not AgentCognitiveState:
            raise TypeError("cognitive states must be AgentCognitiveState values")

    @classmethod
    def validate_transition(
        cls,
        current: AgentCognitiveState,
        target: AgentCognitiveState,
    ) -> CognitiveTransitionValidation:
        """Return whether ``current`` may move to ``target``.

        A self-transition is an explicit no-op.  It is valid for callers that
        want an idempotent initialization or resume operation, but it is not a
        versioned transition.
        """
        cls._require_state(current)
        cls._require_state(target)
        if current is target:
            return CognitiveTransitionValidation.UNCHANGED
        if target in LEGAL_COGNITIVE_TRANSITIONS[current]:
            return CognitiveTransitionValidation.ALLOWED
        return CognitiveTransitionValidation.ILLEGAL

    @classmethod
    def can_transition(
        cls,
        current: AgentCognitiveState,
        target: AgentCognitiveState,
    ) -> bool:
        """Return ``True`` for a legal transition or an explicit no-op."""
        return cls.validate_transition(current, target) is not CognitiveTransitionValidation.ILLEGAL


__all__ = [
    "LEGAL_COGNITIVE_TRANSITIONS",
    "AgentCognitiveState",
    "AgentCognitiveStateMachine",
    "CognitiveTransitionValidation",
]
