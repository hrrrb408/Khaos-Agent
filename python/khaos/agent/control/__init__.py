"""Typed contracts for the agent task control plane.

M7.1.2 exposes only the immutable GoalSpec declaration and its durable
repository.  Mutable assessment, completion, planning, and recovery
contracts belong to later batches and are deliberately not imported here.
"""

from khaos.agent.control.goal import (
    ACCEPTANCE_CRITERION_SCHEMA_KEYS,
    GOAL_REQUIREMENT_SCHEMA_KEYS,
    GOAL_SPEC_SCHEMA_VERSION,
    AcceptanceCriterion,
    GoalRequirement,
    GoalSource,
    GoalSpec,
    GoalSpecValidationError,
    normalize_goal,
)
from khaos.agent.control.goal_repository import (
    GoalSpecConflictError,
    GoalSpecIntegrityError,
    GoalSpecRepository,
)
from khaos.agent.control.state import (
    LEGAL_COGNITIVE_TRANSITIONS,
    AgentCognitiveState,
    AgentCognitiveStateMachine,
    CognitiveTransitionValidation,
)
from khaos.agent.control.state_repository import (
    AgentControlStateRepository,
    CognitiveStateIntegrityError,
    CognitiveStateSnapshot,
    CognitiveTransitionResult,
    CognitiveTransitionStatus,
)

__all__ = [
    "ACCEPTANCE_CRITERION_SCHEMA_KEYS",
    "GOAL_REQUIREMENT_SCHEMA_KEYS",
    "GOAL_SPEC_SCHEMA_VERSION",
    "LEGAL_COGNITIVE_TRANSITIONS",
    "AcceptanceCriterion",
    "AgentCognitiveState",
    "AgentCognitiveStateMachine",
    "AgentControlStateRepository",
    "CognitiveStateIntegrityError",
    "CognitiveStateSnapshot",
    "CognitiveTransitionResult",
    "CognitiveTransitionStatus",
    "CognitiveTransitionValidation",
    "GoalRequirement",
    "GoalSource",
    "GoalSpec",
    "GoalSpecConflictError",
    "GoalSpecIntegrityError",
    "GoalSpecRepository",
    "GoalSpecValidationError",
    "normalize_goal",
]
