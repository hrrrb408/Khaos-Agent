"""Typed contracts for the agent task control plane.

M7.1.4 adds the immutable CompletionDecision record and its passive,
append-only durable ledger.  Evaluation, completion gating, planning, and
recovery remain later control-plane responsibilities.
"""

from khaos.agent.control.completion import (
    COMPLETION_DECISION_SCHEMA_VERSION,
    AssessmentStatus,
    CompletionDecision,
    CompletionDecisionValidationError,
    CompletionEvidenceKind,
    CompletionEvidenceRef,
    CompletionIssue,
    CompletionIssueCode,
    CompletionOutcome,
    CriterionAssessment,
    EvidenceRef,
    RequirementAssessment,
)
from khaos.agent.control.completion_repository import (
    CompletionDecisionBindingError,
    CompletionDecisionConflictError,
    CompletionDecisionIntegrityError,
    CompletionDecisionRepository,
    CompletionDecisionRepositoryError,
    StoredCompletionDecision,
)
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
    "COMPLETION_DECISION_SCHEMA_VERSION",
    "GOAL_REQUIREMENT_SCHEMA_KEYS",
    "GOAL_SPEC_SCHEMA_VERSION",
    "LEGAL_COGNITIVE_TRANSITIONS",
    "AcceptanceCriterion",
    "AgentCognitiveState",
    "AgentCognitiveStateMachine",
    "AgentControlStateRepository",
    "AssessmentStatus",
    "CognitiveStateIntegrityError",
    "CognitiveStateSnapshot",
    "CognitiveTransitionResult",
    "CognitiveTransitionStatus",
    "CognitiveTransitionValidation",
    "CompletionDecision",
    "CompletionDecisionBindingError",
    "CompletionDecisionConflictError",
    "CompletionDecisionIntegrityError",
    "CompletionDecisionRepository",
    "CompletionDecisionRepositoryError",
    "CompletionDecisionValidationError",
    "CompletionEvidenceKind",
    "CompletionEvidenceRef",
    "CompletionIssue",
    "CompletionIssueCode",
    "CompletionOutcome",
    "CriterionAssessment",
    "EvidenceRef",
    "GoalRequirement",
    "GoalSource",
    "GoalSpec",
    "GoalSpecConflictError",
    "GoalSpecIntegrityError",
    "GoalSpecRepository",
    "GoalSpecValidationError",
    "RequirementAssessment",
    "StoredCompletionDecision",
    "normalize_goal",
]
