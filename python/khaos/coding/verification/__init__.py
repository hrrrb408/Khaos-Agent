"""Project-aware verification pipeline."""

from khaos.coding.verification.contracts import (
    DiagnosticCategory,
    DiagnosticSeverity,
    VerificationCheck,
    VerificationCheckKind,
    VerificationCheckStatus,
    VerificationContractError,
    VerificationCost,
    VerificationDiagnostic,
    VerificationReason,
    VerificationRisk,
    VerificationRunStatus,
    VerificationStage,
    VerificationStatus,
)
from khaos.coding.verification.contracts import (
    VerificationPlan as AutonomousVerificationPlan,
)
from khaos.coding.verification.detector import ProjectDetector
from khaos.coding.verification.diagnostics import (
    DiagnosticParser,
    RepairContext,
    parse_diagnostics,
)
from khaos.coding.verification.evidence import (
    StoredVerificationRun,
    VerificationEvidence,
    VerificationEvidenceLedger,
    VerificationEvidenceSet,
    VerificationEvidenceStore,
    VerificationObservationStore,
    VerificationRun,
    VerificationRunResult,
)
from khaos.coding.verification.executor import VerificationExecutor
from khaos.coding.verification.impact import (
    ChangedRange,
    EditImpact,
    VerificationImpact,
    VerificationImpactAnalyzer,
    edit_transaction_result_from_tool_output,
)
from khaos.coding.verification.models import VerificationPlan, VerificationStepResult
from khaos.coding.verification.pipeline import (
    VerificationMemoryOutcome,
    VerificationPipeline,
)
from khaos.coding.verification.planner import (
    AutonomousPlannerLimits,
    AutonomousVerificationPlanner,
    VerificationPlanner,
)
from khaos.coding.verification.profile import (
    ProfileDetector,
    ProjectProfile,
    ProjectVerificationProfile,
    VerificationCommandSpec,
    VerificationProfile,
    VerificationProfileDetector,
)
from khaos.coding.verification.service import (
    AutonomousVerificationCoordinator,
    AutonomousVerificationFactProvider,
)

__all__ = [
    "AutonomousPlannerLimits",
    "AutonomousVerificationCoordinator",
    "AutonomousVerificationFactProvider",
    "AutonomousVerificationPlan",
    "AutonomousVerificationPlanner",
    "ChangedRange",
    "DiagnosticCategory",
    "DiagnosticParser",
    "DiagnosticSeverity",
    "EditImpact",
    "ProfileDetector",
    "ProjectDetector",
    "ProjectProfile",
    "ProjectVerificationProfile",
    "RepairContext",
    "StoredVerificationRun",
    "VerificationCheck",
    "VerificationCheckKind",
    "VerificationCheckStatus",
    "VerificationCommandSpec",
    "VerificationContractError",
    "VerificationCost",
    "VerificationDiagnostic",
    "VerificationEvidence",
    "VerificationEvidenceLedger",
    "VerificationEvidenceSet",
    "VerificationEvidenceStore",
    "VerificationExecutor",
    "VerificationImpact",
    "VerificationImpactAnalyzer",
    "VerificationMemoryOutcome",
    "VerificationObservationStore",
    "VerificationPipeline",
    "VerificationPlan",
    "VerificationPlanner",
    "VerificationProfile",
    "VerificationProfileDetector",
    "VerificationReason",
    "VerificationRisk",
    "VerificationRun",
    "VerificationRunResult",
    "VerificationRunStatus",
    "VerificationStage",
    "VerificationStatus",
    "VerificationStepResult",
    "edit_transaction_result_from_tool_output",
    "parse_diagnostics",
]
