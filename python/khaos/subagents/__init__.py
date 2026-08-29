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
    "AssignmentDisposition",
    "AssignmentRequestResult",
    "AssignmentRunState",
    "DelegatedExecutionContext",
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
    "TaskPlanner",
]
