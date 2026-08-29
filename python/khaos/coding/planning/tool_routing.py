"""Typed, fail-closed routing contracts for published-plan tool admission.

The router is a narrowing control plane.  These value objects deliberately
carry identity and digest material needed by Permission/Approval and dispatch
without turning a plan into a capability grant.
"""

from __future__ import annotations

import json
import shlex
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any

from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.revision import PlanningStep
from khaos.permissions.resource import AuthorizationResource, AuthorizationResourceKind
from khaos.security.protocol_boundary import canonical_digest


class PlanRouteDisposition(str, Enum):
    """Closed route outcomes; ALLOW is not an authorization grant."""

    ALLOW = "allow"
    SUPPORTING_READ = "supporting_read"
    BLOCKED = "blocked"
    STALE = "stale"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class PlanExecutionEpochBinding:
    """Server-owned execution epoch for one published plan/recovery cause."""

    principal_id: str
    project_id: str
    task_id: str
    goal_spec_id: str
    goal_spec_digest: str
    workspace_id: str
    repository_id: str
    base_revision: str | None
    workspace_generation: int
    plan_revision_id: str
    plan_revision_digest: str
    recovery_decision_id: str | None = None

    def __post_init__(self) -> None:
        required = (
            self.principal_id, self.project_id, self.task_id,
            self.goal_spec_id, self.goal_spec_digest, self.workspace_id,
            self.repository_id, self.plan_revision_id,
            self.plan_revision_digest,
        )
        if any(type(value) is not str or not value for value in required):
            raise ValueError("plan execution epoch identity is incomplete")
        if type(self.workspace_generation) is not int or self.workspace_generation <= 0:
            raise ValueError("plan execution epoch workspace generation is invalid")
        if self.base_revision is not None and (
            type(self.base_revision) is not str or not self.base_revision
        ):
            raise ValueError("plan execution epoch base revision is invalid")

    def digest(self) -> str:
        return canonical_digest({
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "goal_spec_id": self.goal_spec_id,
            "goal_spec_digest": self.goal_spec_digest,
            "workspace_id": self.workspace_id,
            "repository_id": self.repository_id,
            "base_revision": self.base_revision,
            "workspace_generation": self.workspace_generation,
            "plan_revision_id": self.plan_revision_id,
            "plan_revision_digest": self.plan_revision_digest,
            "recovery_decision_id": self.recovery_decision_id,
        })


@dataclass(frozen=True, slots=True)
class PlanToolRouteInput:
    """Server-built input to route one admitted call."""

    tool: Any
    arguments: Mapping[str, Any]
    resource: AuthorizationResource
    principal_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    cognitive_state: AgentCognitiveState
    task_status: str
    recovery_decision_id: str | None = None


@dataclass(frozen=True, slots=True)
class PlanToolRouteBinding:
    """Exact server-owned binding carried through approval and dispatch."""

    route_id: str
    route_digest: str
    principal_id: str
    project_id: str
    task_id: str
    workspace_id: str
    workspace_generation: int
    plan_revision_id: str | None
    plan_revision_digest: str | None
    plan_step_id: str | None
    plan_step_digest: str | None
    execution_epoch_digest: str | None
    tool_name: str
    tool_security_digest: str
    arguments_digest: str
    authorization_resource_digest: str
    disposition: PlanRouteDisposition
    reason_code: str
    # M7.8 additive actor/owner binding.  Empty values from v23 routes are
    # normalized to the ordinary parent identity for compatibility.
    task_owner_principal_id: str = ""
    execution_principal_id: str = ""
    subagent_assignment_id: str | None = None
    subagent_assignment_digest: str | None = None

    def __post_init__(self) -> None:
        if not self.task_owner_principal_id:
            object.__setattr__(self, "task_owner_principal_id", self.principal_id)
        if not self.execution_principal_id:
            object.__setattr__(self, "execution_principal_id", self.principal_id)

    def payload(self) -> dict[str, Any]:
        return {
            "route_id": self.route_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "workspace_id": self.workspace_id,
            "workspace_generation": self.workspace_generation,
            "plan_revision_id": self.plan_revision_id,
            "plan_revision_digest": self.plan_revision_digest,
            "plan_step_id": self.plan_step_id,
            "plan_step_digest": self.plan_step_digest,
            "execution_epoch_digest": self.execution_epoch_digest,
            "tool_name": self.tool_name,
            "tool_security_digest": self.tool_security_digest,
            "arguments_digest": self.arguments_digest,
            "authorization_resource_digest": self.authorization_resource_digest,
            "disposition": self.disposition.value,
            "reason_code": self.reason_code,
            "task_owner_principal_id": self.task_owner_principal_id,
            "execution_principal_id": self.execution_principal_id,
            "subagent_assignment_id": self.subagent_assignment_id,
            "subagent_assignment_digest": self.subagent_assignment_digest,
        }

    def recompute_digest(self) -> str:
        return canonical_digest(self.payload())


@dataclass(frozen=True, slots=True)
class PlanToolRouteDecision:
    """Route result.  It never represents Permission or Approval."""

    disposition: PlanRouteDisposition
    reason_code: str
    reason: str
    binding: PlanToolRouteBinding
    requires_approval: bool = False


def step_digest(step: PlanningStep) -> str:
    """Digest exactly the immutable M7.3 step payload."""
    return canonical_digest(step.to_payload())


def arguments_digest(arguments: Mapping[str, Any]) -> str:
    return canonical_digest(dict(arguments))


def relative_resource_targets(resource: AuthorizationResource) -> tuple[str, ...]:
    """Extract normalized workspace-relative paths from a canonical resource."""
    try:
        payload = json.loads(resource.canonical_target)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("authorization resource target is malformed") from exc
    root = resource.workspace_root
    if not root:
        raise ValueError("authorization resource has no workspace root")

    def relative(value: Any) -> str:
        if type(value) is not str or not value:
            raise ValueError("authorization resource path is malformed")
        import os

        rel = os.path.relpath(value, root)
        if rel == ".." or rel.startswith("../"):
            raise ValueError("authorization resource escapes workspace")
        return str(PurePosixPath(rel.replace(os.sep, "/")))

    if resource.kind is AuthorizationResourceKind.WORKSPACE_PATH:
        return (relative(payload.get("path")),)
    if resource.kind is AuthorizationResourceKind.WORKSPACE_COPY_MOVE:
        return (relative(payload.get("source")), relative(payload.get("destination")))
    return ()


def command_argv(arguments: Mapping[str, Any], tool_name: str) -> tuple[str, ...] | None:
    """Return an exact argv candidate; never performs prefix matching."""
    if tool_name == "terminal_argv":
        argv = arguments.get("argv")
        if isinstance(argv, list) and all(isinstance(item, str) and item for item in argv):
            return tuple(argv)
        return None
    if tool_name == "test_run":
        command = arguments.get("command")
        if isinstance(command, str) and command.strip():
            try:
                return tuple(shlex.split(command))
            except ValueError:
                return None
    return None


def stable_route_id() -> str:
    import uuid

    return f"route-{uuid.uuid4().hex}"


__all__ = [
    "PlanExecutionEpochBinding",
    "PlanRouteDisposition",
    "PlanToolRouteBinding",
    "PlanToolRouteDecision",
    "PlanToolRouteInput",
    "arguments_digest",
    "command_argv",
    "relative_resource_targets",
    "stable_route_id",
    "step_digest",
]
