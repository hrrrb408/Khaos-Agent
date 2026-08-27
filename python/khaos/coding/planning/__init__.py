"""Read-only implementation planning contracts and deterministic service."""
from khaos.coding.planning.contracts import *
from khaos.coding.planning.execution_models import (
    ExecutionRunStatus,
    PlanExecutionRun,
    PlannedEditBundle,
    PlannedEditOperation,
    PlannedFileEdit,
    WorkspaceMutationResult,
)
from khaos.coding.planning.repository import (
    PlanningTaskSnapshot,
    PlanPublicationResult,
    PlanPublicationStatus,
    PlanRevisionBindingError,
    PlanRevisionConflictError,
    PlanRevisionIntegrityError,
    PlanRevisionRepository,
    PlanRevisionStaleError,
    StoredPlanRevision,
)
from khaos.coding.planning.revision import (
    PLANNER_ALGORITHM_VERSION,
    PLANNING_SCHEMA_VERSION,
    PlanDisposition,
    PlanningAffectedFile,
    PlanningAffectedSymbol,
    PlanningContractError,
    PlanningDependencyImpact,
    PlanningDiagnostic,
    PlanningEvidenceKind,
    PlanningEvidenceRef,
    PlanningInput,
    PlanningRisk,
    PlanningRiskLevel,
    PlanningStep,
    PlanningVerificationIntent,
    PlanRevision,
    plan_revision_from_canonical_json,
)
from khaos.coding.planning.service import DeterministicPlanningService
from khaos.coding.planning.verification_execution_models import (
    TrustedVerificationCommand,
    VerificationExecutionRun,
    VerificationPhaseContext,
    VerificationResult,
    VerificationRunStatus,
    VerificationStepRun,
    VerificationStepStatus,
)


def __getattr__(name: str) -> object:
    """Lazily expose orchestration types without importing workspace code.

    ``khaos.security.resource_scope`` imports planning security identities.
    Eagerly importing the coordinator while that package is initialized would
    recurse through ``coding.workspace`` back into ``resource_scope``.  The
    coordinator remains available through the historical package-level API,
    but is loaded only when a caller explicitly requests an orchestration
    symbol.
    """
    if name in {
        "PlanningControlCoordinator",
        "PlanningControlResult",
        "PlanningControlStatus",
    }:
        from khaos.coding.planning.coordinator import (
            PlanningControlCoordinator,
            PlanningControlResult,
            PlanningControlStatus,
        )

        globals().update(
            {
                "PlanningControlCoordinator": PlanningControlCoordinator,
                "PlanningControlResult": PlanningControlResult,
                "PlanningControlStatus": PlanningControlStatus,
            }
        )
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "PLANNER_ALGORITHM_VERSION",
    "PLANNING_SCHEMA_VERSION",
    "DeterministicPlanningService",
    "ExecutionRunStatus",
    "PlanDisposition",
    "PlanExecutionRun",
    "PlanPublicationResult",
    "PlanPublicationStatus",
    "PlanRevision",
    "PlanRevisionBindingError",
    "PlanRevisionConflictError",
    "PlanRevisionIntegrityError",
    "PlanRevisionRepository",
    "PlanRevisionStaleError",
    "PlannedEditBundle",
    "PlannedEditOperation",
    "PlannedFileEdit",
    "PlanningAffectedFile",
    "PlanningAffectedSymbol",
    "PlanningContractError",
    "PlanningControlCoordinator",
    "PlanningControlResult",
    "PlanningControlStatus",
    "PlanningDependencyImpact",
    "PlanningDiagnostic",
    "PlanningEvidenceKind",
    "PlanningEvidenceRef",
    "PlanningInput",
    "PlanningRisk",
    "PlanningRiskLevel",
    "PlanningStep",
    "PlanningTaskSnapshot",
    "PlanningVerificationIntent",
    "StoredPlanRevision",
    "TrustedVerificationCommand",
    "VerificationExecutionRun",
    "VerificationPhaseContext",
    "VerificationResult",
    "VerificationRunStatus",
    "VerificationStepRun",
    "VerificationStepStatus",
    "WorkspaceMutationResult",
    "plan_revision_from_canonical_json",
]
