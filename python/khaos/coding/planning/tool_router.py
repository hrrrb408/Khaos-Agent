"""Published-plan tool router.

This module only narrows the call before ordinary Permission/Approval.  It
does not grant capabilities, invoke handlers, consume approvals, or change
task lifecycle state.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from khaos.agent.control.state import AgentCognitiveState
from khaos.coding.planning.repository import (
    PlanRevisionRepository,
    PlanRevisionRepositoryError,
    StoredPlanRevision,
)
from khaos.coding.planning.revision import PlanningStep, PlanOperation
from khaos.coding.planning.tool_routing import (
    PlanExecutionEpochBinding,
    PlanRouteDisposition,
    PlanToolRouteBinding,
    PlanToolRouteDecision,
    arguments_digest,
    command_argv,
    relative_resource_targets,
    stable_route_id,
    step_digest,
)
from khaos.permissions.resource import AuthorizationResourceKind

_TERMINAL_TASK_STATUSES = frozenset({"completed", "failed", "cancelled"})
_MUTATING_ROLES = frozenset({
    "file_mutation", "file_create", "file_rename", "file_delete",
    "verification_command",
})
_READ_ROLES = frozenset({"supporting_read"})
_READ_RESOURCE_KINDS = frozenset({
    AuthorizationResourceKind.WORKSPACE_PATH,
    AuthorizationResourceKind.WORKSPACE_COPY_MOVE,
    AuthorizationResourceKind.WORKSPACE,
})
_ROLE_RESOURCE_KINDS = {
    "file_mutation": frozenset({AuthorizationResourceKind.WORKSPACE_PATH}),
    "file_create": frozenset({AuthorizationResourceKind.WORKSPACE_COPY_MOVE}),
    "file_rename": frozenset({AuthorizationResourceKind.WORKSPACE_COPY_MOVE}),
    "file_delete": frozenset({AuthorizationResourceKind.WORKSPACE_PATH}),
    "verification_command": frozenset({AuthorizationResourceKind.PROCESS_ARGV}),
}


class PlanToolRouterError(RuntimeError):
    """Base error for fail-closed route construction."""


class PlanToolRouter:
    """Resolve one admitted tool call against the physical published plan."""

    def __init__(self, plan_repository: PlanRevisionRepository, route_repository: Any) -> None:
        self._plan_repository = plan_repository
        self._route_repository = route_repository

    async def route(
        self,
        *,
        tool: Any,
        arguments: Mapping[str, Any],
        resource: Any,
        mode: str,
        tool_context: Mapping[str, Any],
    ) -> PlanToolRouteDecision:
        """Return and durably record a server-selected route."""
        if mode != "coding":
            return self._decision(
                tool=tool, arguments=arguments, resource=resource,
                context=tool_context, disposition=PlanRouteDisposition.ALLOW,
                reason_code="non_coding_mode", reason="plan routing is coding-only",
            )
        if tool.plan_tool_role is None:
            return await self._record(
                self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="tool_role_undeclared",
                    reason="tool has no reviewed plan compatibility declaration",
                )
            )
        try:
            principal_id = _required_context(tool_context, "principal_id")
            project_id = _required_context(tool_context, "project_id")
            task_id = _required_context(tool_context, "task_id")
            workspace_id = _required_context(tool_context, "workspace_id")
            if resource is None:
                raise PlanToolRouterError("canonical AuthorizationResource is required")
            if any(
                getattr(resource, name, None) != expected
                for name, expected in (
                    ("principal_id", principal_id),
                    ("project_id", project_id),
                    ("task_id", task_id),
                    ("workspace_id", workspace_id),
                )
            ):
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.INVALID,
                    reason_code="resource_identity_mismatch",
                    reason="authorization resource is outside the current task scope",
                ))
            snapshot = await self._plan_repository.get_current_task_snapshot(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if snapshot is None:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.UNAVAILABLE,
                    reason_code="task_unavailable", reason="task snapshot is unavailable",
                ))
            if snapshot.principal_id != principal_id or snapshot.project_id != project_id:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.INVALID,
                    reason_code="owner_mismatch", reason="task owner binding is invalid",
                ))
            if snapshot.workspace_id != workspace_id:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.STALE,
                    reason_code="workspace_mismatch", reason="task workspace binding is stale",
                ))
            if snapshot.task_status in _TERMINAL_TASK_STATUSES:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="task_terminal", reason="terminal tasks cannot execute plan tools",
                ))
            if resource.workspace_generation != int(snapshot_generation(tool_context, resource)):
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.STALE,
                    reason_code="workspace_generation_drift", reason="workspace generation changed",
                ))

            role_value = _role_value(tool.plan_tool_role)
            if role_value in _READ_ROLES:
                if resource.kind not in _READ_RESOURCE_KINDS:
                    return await self._record(self._decision(
                        tool=tool, arguments=arguments, resource=resource,
                        context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                        reason_code="read_resource_kind_disallowed",
                        reason="supporting reads are restricted to workspace resources",
                    ))
                if snapshot.cognitive_state in {
                    AgentCognitiveState.REPLANNING,
                    AgentCognitiveState.PLANNING,
                }:
                    disposition = PlanRouteDisposition.BLOCKED
                    code = "cognitive_state_disallows_read"
                    reason = "current cognitive phase does not admit supporting reads"
                else:
                    disposition = PlanRouteDisposition.SUPPORTING_READ
                    code = "supporting_read"
                    reason = "read-only workspace context route"
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=disposition,
                    reason_code=code, reason=reason,
                ))

            if role_value in _MUTATING_ROLES and snapshot.cognitive_state not in {
                AgentCognitiveState.IMPLEMENTING,
                AgentCognitiveState.RECOVERING,
            }:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="cognitive_state_disallows_effect",
                    reason="current cognitive phase does not admit plan effects",
                ))

            published = await self._plan_repository.get_published_for_task(
                task_id, principal_id=principal_id, project_id=project_id
            )
            if published is None:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="no_published_plan",
                    reason="mutating/process tool requires an exact published plan",
                ))
            if published.revision.task_id != task_id:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.INVALID,
                    reason_code="plan_task_mismatch", reason="published plan task binding is invalid",
                    published=published,
                ))
            if (
                published.revision.workspace_id != workspace_id
                or published.revision.workspace_id != resource.workspace_id
                or snapshot.workspace_id != published.revision.workspace_id
                or snapshot.repository_id != published.revision.repository_id
                or snapshot.base_revision != published.revision.base_revision
            ):
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.STALE,
                    reason_code="plan_scope_drift",
                    reason="published plan physical scope no longer matches the task",
                    published=published,
                ))
            epoch = PlanExecutionEpochBinding(
                principal_id=principal_id,
                project_id=project_id,
                task_id=task_id,
                goal_spec_id=published.revision.goal_spec_id,
                goal_spec_digest=published.revision.goal_spec_digest,
                workspace_id=published.revision.workspace_id,
                repository_id=published.revision.repository_id,
                base_revision=published.revision.base_revision,
                workspace_generation=resource.workspace_generation,
                plan_revision_id=published.plan_revision_id,
                plan_revision_digest=published.revision.plan_semantic_digest,
                recovery_decision_id=snapshot.last_applied_recovery_decision_id,
            )
            candidates = self._matching_steps(
                published.revision.steps, tool, arguments, resource
            )
            if len(candidates) > 1:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.AMBIGUOUS,
                    reason_code="multiple_matching_steps", reason="more than one executable step matches",
                    published=published, epoch=epoch,
                ))
            if not candidates:
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="no_matching_step", reason="call is outside the published plan vocabulary/scope",
                    published=published, epoch=epoch,
                ))
            step = candidates[0]
            state = await self._route_repository.get_step_state(
                principal_id=principal_id,
                project_id=project_id,
                task_id=task_id,
                execution_epoch_digest=epoch.digest(),
                plan_step_id=step.step_id,
            )
            if state is not None and state.state != "PENDING":
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code={
                        "ACTIVE": "step_dispatch_active",
                        "UNCERTAIN": "step_effect_uncertain",
                        "EXECUTED": "step_already_executed",
                    }.get(state.state, "step_state_invalid"),
                    reason="plan step is not in the executable PENDING state",
                    published=published, epoch=epoch, step=step,
                ))
            if not await self._dependencies_executed(
                published.revision.steps, step, epoch.digest(), principal_id, project_id, task_id
            ):
                return await self._record(self._decision(
                    tool=tool, arguments=arguments, resource=resource,
                    context=tool_context, disposition=PlanRouteDisposition.BLOCKED,
                    reason_code="dependency_not_satisfied", reason="step dependency is not durably EXECUTED",
                    published=published, epoch=epoch, step=step,
                ))
            decision = self._decision(
                tool=tool, arguments=arguments, resource=resource,
                context=tool_context, disposition=PlanRouteDisposition.ALLOW,
                reason_code="matched_executable_step", reason="exact published-plan step matched",
                published=published, epoch=epoch, step=step,
                requires_approval=bool(step.requires_approval or step.risk.requires_approval),
            )
            return await self._record(decision)
        except (PlanRevisionRepositoryError, PlanToolRouterError, ValueError, KeyError) as exc:
            return await self._record(self._decision(
                tool=tool, arguments=arguments, resource=resource,
                context=tool_context, disposition=PlanRouteDisposition.INVALID,
                reason_code="route_integrity_error", reason=str(exc),
            ))

    async def begin_dispatch(self, decision: PlanToolRouteDecision) -> Any:
        """Atomically revalidate and register an active durable fence."""
        if decision.disposition is not PlanRouteDisposition.ALLOW:
            raise PlanToolRouterError("only an ALLOW route can begin dispatch")
        return await self._route_repository.begin_dispatch(decision.binding)

    async def finish_dispatch(
        self, fence: Any, *, effect_status: str, effect_id: str,
        affected_targets: tuple[str, ...] = (),
    ) -> None:
        await self._route_repository.finish_dispatch(
            fence, effect_status=effect_status, effect_id=effect_id,
            affected_targets=affected_targets,
        )

    async def _record(self, decision: PlanToolRouteDecision) -> PlanToolRouteDecision:
        await self._route_repository.append_route(decision.binding)
        return decision

    def _decision(
        self, *, tool: Any, arguments: Mapping[str, Any], resource: Any,
        context: Mapping[str, Any], disposition: PlanRouteDisposition,
        reason_code: str, reason: str, published: StoredPlanRevision | None = None,
        epoch: PlanExecutionEpochBinding | None = None, step: PlanningStep | None = None,
        requires_approval: bool = False,
    ) -> PlanToolRouteDecision:
        route_id = stable_route_id()
        binding = PlanToolRouteBinding(
            route_id=route_id,
            route_digest="",
            principal_id=str(context.get("principal_id") or ""),
            project_id=str(context.get("project_id") or ""),
            task_id=str(context.get("task_id") or ""),
            workspace_id=str(context.get("workspace_id") or ""),
            workspace_generation=int(getattr(resource, "workspace_generation", 0) or 0),
            plan_revision_id=published.plan_revision_id if published else None,
            plan_revision_digest=(published.revision.plan_semantic_digest if published else None),
            plan_step_id=step.step_id if step else None,
            plan_step_digest=step_digest(step) if step else None,
            execution_epoch_digest=epoch.digest() if epoch else None,
            tool_name=tool.name,
            tool_security_digest=tool.security_digest,
            arguments_digest=arguments_digest(arguments),
            authorization_resource_digest=(resource.digest() if resource is not None else ""),
            disposition=disposition,
            reason_code=reason_code,
        )
        object.__setattr__(binding, "route_digest", binding.recompute_digest())
        return PlanToolRouteDecision(disposition, reason_code, reason, binding, requires_approval)

    async def _dependencies_executed(
        self, steps: tuple[PlanningStep, ...], step: PlanningStep, epoch_digest: str,
        principal_id: str, project_id: str, task_id: str,
    ) -> bool:
        for dependency in step.dependencies:
            state = await self._route_repository.get_step_state(
                principal_id=principal_id, project_id=project_id, task_id=task_id,
                execution_epoch_digest=epoch_digest, plan_step_id=dependency,
            )
            if state is None or state.state != "EXECUTED":
                return False
        return True

    @staticmethod
    def _matching_steps(
        steps: tuple[PlanningStep, ...], tool: Any,
        arguments: Mapping[str, Any], resource: Any,
    ) -> list[PlanningStep]:
        role = tool.plan_tool_role
        role_value = _role_value(role)
        if resource.kind not in _ROLE_RESOURCE_KINDS.get(role_value, frozenset()):
            return []
        try:
            targets = relative_resource_targets(resource)
        except (ValueError, TypeError, OSError):
            return []
        matches: list[PlanningStep] = []
        for step in steps:
            if not _role_matches_operation(role, step.operation):
                continue
            if role_value in {
                "file_mutation", "file_create", "file_delete",
            } and tuple(sorted(targets)) != tuple(sorted(step.target_files)):
                continue
            if role_value == "file_rename" and tuple(sorted(targets)) != tuple(sorted(step.target_files)):
                continue
            if role_value == "verification_command":
                argv = command_argv(arguments, tool.name)
                planned = {
                    intent.command
                    for intent in step.verification_requirements
                    if intent.command is not None
                }
                if argv is None or argv not in planned:
                    continue
            matches.append(step)
        return matches


def _required_context(context: Mapping[str, Any], key: str) -> str:
    value = context.get(key)
    if type(value) is not str or not value:
        raise PlanToolRouterError(f"missing routing context: {key}")
    return value


def snapshot_generation(context: Mapping[str, Any], resource: Any) -> int:
    value = context.get("workspace_generation", getattr(resource, "workspace_generation", 0))
    if type(value) is not int or value <= 0:
        raise PlanToolRouterError("workspace generation is missing")
    return value


def _role_matches_operation(role: Any, operation: PlanOperation) -> bool:
    return {
        "file_mutation": {PlanOperation.MODIFY, PlanOperation.DOCUMENT, PlanOperation.CONFIGURE},
        "file_create": {PlanOperation.CREATE},
        "file_delete": {PlanOperation.DELETE},
        "file_rename": {PlanOperation.RENAME},
        "verification_command": {PlanOperation.TEST},
    }.get(_role_value(role), set()).__contains__(operation)


def _role_value(role: Any) -> str:
    return str(getattr(role, "value", role) or "")


__all__ = ["PlanToolRouter", "PlanToolRouterError"]
