"""Subagent spawning & orchestration (Phase 8)."""

from khaos.subagents.planner import SubTaskPlan, TaskPlanner
from khaos.subagents.runner import SubAgentRunner
from khaos.subagents.service import SubAgentService
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner, SubAgentTask
from khaos.subagents.assignment import (
    AssignmentDisposition,
    AssignmentRequestResult,
    AssignmentRunState,
    DelegatedExecutionContext,
    SubAgentAssignment,
    SubAgentAssignmentRepository,
    SubAgentControlCoordinator,
    SubAgentPolicy,
    SubAgentReport,
)

__all__ = [
    "SubAgentConfig",
    "SubAgentRunner",
    "SubAgentService",
    "SubAgentSpawner",
    "SubAgentTask",
    "SubTaskPlan",
    "TaskPlanner",
    "AssignmentDisposition",
    "AssignmentRequestResult",
    "AssignmentRunState",
    "DelegatedExecutionContext",
    "SubAgentAssignment",
    "SubAgentAssignmentRepository",
    "SubAgentControlCoordinator",
    "SubAgentPolicy",
    "SubAgentReport",
]
