"""Subagent spawning & orchestration (Phase 8).

The public exports are loaded lazily because the database imports the
assignment repository during package initialization.  Eagerly importing the
service here would complete a cycle through ``runtime`` and ``tools`` before
the tool registry has finished initializing.
"""

from importlib import import_module
from typing import Any

_EXPORT_MODULES = {
    "SubTaskPlan": "khaos.subagents.planner",
    "TaskPlanner": "khaos.subagents.planner",
    "SubAgentRunner": "khaos.subagents.runner",
    "SubAgentService": "khaos.subagents.service",
    "SubAgentConfig": "khaos.subagents.spawner",
    "SubAgentSpawner": "khaos.subagents.spawner",
    "SubAgentTask": "khaos.subagents.spawner",
    "AssignmentDisposition": "khaos.subagents.assignment",
    "AssignmentRequestResult": "khaos.subagents.assignment",
    "AssignmentRunState": "khaos.subagents.assignment",
    "DelegatedExecutionContext": "khaos.subagents.assignment",
    "SubAgentAssignment": "khaos.subagents.assignment",
    "SubAgentAssignmentRepository": "khaos.subagents.assignment",
    "SubAgentControlCoordinator": "khaos.subagents.assignment",
    "SubAgentPolicy": "khaos.subagents.assignment",
    "SubAgentReport": "khaos.subagents.assignment",
    "AssignmentContext": "khaos.subagents.contracts",
    "ChildWorkspaceBinding": "khaos.subagents.contracts",
    "ChildWorkspaceState": "khaos.subagents.contracts",
    "ContextTransferItem": "khaos.subagents.contracts",
    "ContextTransferPackage": "khaos.subagents.contracts",
    "MergeCandidate": "khaos.subagents.contracts",
    "MergeCandidateBinding": "khaos.subagents.contracts",
    "MergeConflictKind": "khaos.subagents.contracts",
    "MergePlan": "khaos.subagents.contracts",
    "MergeResult": "khaos.subagents.contracts",
    "MergeResultStatus": "khaos.subagents.contracts",
    "PublicationAttestation": "khaos.subagents.contracts",
    "ParallelMetrics": "khaos.subagents.contracts",
    "ParallelSubagentContractError": "khaos.subagents.contracts",
    "MergeCoordinator": "khaos.subagents.merge",
    "BoundedParallelScheduler": "khaos.subagents.scheduler",
    "ChildUsage": "khaos.subagents.scheduler",
    "SubagentBudgetExceeded": "khaos.subagents.scheduler",
    "SubagentSchedulerError": "khaos.subagents.scheduler",
    "SubagentCoordinator": "khaos.subagents.coordinator",
    "ChildWorkspaceService": "khaos.subagents.workspace",
    "ParallelSubagentRepository": "khaos.subagents.repository",
    "ParallelSubagentRecovery": "khaos.subagents.recovery",
    "SubagentAccessMode": "khaos.subagents.contracts",
    "SubagentAssignment": "khaos.subagents.contracts",
    "SubagentParallelismPolicy": "khaos.subagents.contracts",
    "SubagentResult": "khaos.subagents.contracts",
    "SubagentResultStatus": "khaos.subagents.contracts",
    "SubagentRole": "khaos.subagents.contracts",
    "VerifiedIntegrationArtifact": "khaos.subagents.contracts",
}


def __getattr__(name: str) -> Any:
    """Resolve a public subagent export without importing the whole stack."""
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name), name)
    globals()[name] = value
    return value

__all__ = [
    "AssignmentContext",
    "AssignmentDisposition",
    "AssignmentRequestResult",
    "AssignmentRunState",
    "BoundedParallelScheduler",
    "ChildUsage",
    "ChildWorkspaceBinding",
    "ChildWorkspaceService",
    "ChildWorkspaceState",
    "ContextTransferItem",
    "ContextTransferPackage",
    "DelegatedExecutionContext",
    "MergeCandidate",
    "MergeCandidateBinding",
    "MergeConflictKind",
    "MergeCoordinator",
    "MergePlan",
    "MergeResult",
    "MergeResultStatus",
    "ParallelMetrics",
    "ParallelSubagentContractError",
    "ParallelSubagentRecovery",
    "ParallelSubagentRepository",
    "PublicationAttestation",
    "SubAgentAssignment",
    "SubAgentAssignmentRepository",
    "SubAgentConfig",
    "SubAgentControlCoordinator",
    "SubAgentPolicy",
    "SubAgentReport",
    "SubAgentRunner",
    "SubAgentService",
    "SubAgentSpawner",
    "SubAgentTask",
    "SubTaskPlan",
    "SubagentAccessMode",
    "SubagentAssignment",
    "SubagentBudgetExceeded",
    "SubagentCoordinator",
    "SubagentParallelismPolicy",
    "SubagentResult",
    "SubagentResultStatus",
    "SubagentRole",
    "SubagentSchedulerError",
    "TaskPlanner",
    "VerifiedIntegrationArtifact",
]
