"""Pure approval-binding projections for the tool authorization boundary.

This module does not call a permission engine or consume a receipt. It only
turns server-owned tool/context state into the immutable binding and request
objects that are shown to an approval adapter and rechecked at dispatch.
Keeping those projections here prevents the scheduler from growing a second,
slightly different digest schema for the same approval.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from khaos.agent.approval import ApprovalBinding
from khaos.coding.execution.identity import trusted_system_executable
from khaos.permissions import (
    ApprovalMode,
    GrantLifetime,
    PermissionDecision,
    PermissionRule,
    TransportClass,
    is_interactive_transport,
)
from khaos.permissions.resource import AuthorizationResource
from khaos.permissions.rules import typed_rule_from_authorization_resource
from khaos.security.protocol_boundary import canonical_digest
from khaos.tools.scheduler_models import PermissionRequest


def tool_has_capability(tool: object, capability_name: str) -> bool:
    """Check the declarative capability contract for one registered tool."""
    for capability in getattr(tool, "capabilities", ()):
        name = getattr(capability, "name", "")
        value = getattr(name, "value", name)
        if str(value) == capability_name:
            return True
    return False


@dataclass(frozen=True)
class RememberRuleProjection:
    """Result of projecting a user's remember request into a rule."""

    rule: PermissionRule | None = None
    warning: str = ""


class ToolAuthorization:
    """Own permission decision hardening and remember-rule projection.

    The coordinator deliberately stops before approval-broker registration and
    receipt consumption.  Those effects remain explicit in the scheduler so
    the event stream can expose a permission request before waiting for the
    user callback.
    """

    def __init__(self, permission_engine: Any) -> None:
        self._permission_engine = permission_engine

    async def decide(
        self,
        *,
        tool: Any,
        arguments: dict[str, Any],
        mode: str,
        resource: AuthorizationResource | None,
        source_transport: str,
        session_id: str,
        task_id: str,
        workspace_id: str,
        environment: Mapping[str, str] | None,
        executable_argv: tuple[str, ...],
    ) -> PermissionDecision:
        """Evaluate policy and force untrusted read-only commands to confirm."""
        decision = await self._permission_engine.check(
            tool_name=tool.name,
            params=arguments,
            permission_level=tool.permission_level,
            mode=mode,
            resource=resource,
            source_transport=source_transport,
            session_id=session_id,
            task_id=task_id,
            workspace_id=workspace_id,
        )
        if (
            decision.approved == ApprovalMode.AUTO_APPROVE
            and tool_has_capability(tool, "process.execute")
        ):
            executable_environment = dict(environment or {})
            if "PATH" not in executable_environment:
                executable_environment["PATH"] = ""
            trusted = (
                tool.name != "terminal_shell"
                and bool(executable_argv)
                and trusted_system_executable(
                    executable_argv, executable_environment
                )
            )
            if not trusted:
                return PermissionDecision(
                    approved=ApprovalMode.ASK_EVERY,
                    reason=(
                        "read-only command executable is not a trusted "
                        "system executable"
                    ),
                    target=decision.target,
                    matched_rule=decision.matched_rule,
                    requires_user_confirm=True,
                )
        return decision

    @staticmethod
    def project_remember_rule(
        *,
        confirmation: Mapping[str, Any],
        source_transport: str,
        resource: AuthorizationResource | None,
        decision_target: str,
        tool: Any,
        mode: str,
        session_id: str,
        tool_context: Mapping[str, Any],
    ) -> RememberRuleProjection:
        """Convert a confirmed remember request into a scoped permission rule."""
        if not confirmation.get("remember"):
            return RememberRuleProjection()
        if not is_interactive_transport(source_transport):
            return RememberRuleProjection(
                warning=(
                    "remember request ignored for unattended or unknown "
                    "transport"
                )
            )
        try:
            if resource is not None:
                resource_type, resource_spec = typed_rule_from_authorization_resource(
                    resource, tool.permission_level
                )
                remember_pattern = decision_target
            else:
                resource_type, resource_spec = "", None
                remember_pattern = confirmation.get("pattern", decision_target)
            return RememberRuleProjection(
                rule=PermissionRule(
                    id=None,
                    pattern=remember_pattern,
                    permission_level=tool.permission_level,
                    approval=ApprovalMode.AUTO_APPROVE,
                    mode=mode,
                    transport_class=TransportClass.INTERACTIVE.value,
                    grant_lifetime=GrantLifetime.PROJECT_INTERACTIVE.value,
                    session_id=session_id,
                    task_id=str(tool_context.get("task_id") or ""),
                    workspace_id=str(tool_context.get("workspace_id") or ""),
                    created_by=f"approval:{source_transport}",
                    resource_type=resource_type,
                    resource_spec=resource_spec,
                )
            )
        except (TypeError, ValueError) as exc:
            return RememberRuleProjection(
                warning=f"remember-rule rejected: typed resource invalid ({exc})"
            )


def build_approval_binding(
    *,
    tool: Any,
    arguments: dict[str, Any],
    tool_context: Mapping[str, Any],
    principal_id: str,
    session_id: str,
    tool_call_id: str,
    turn_id: str,
    approval_target: str,
    resource: AuthorizationResource | None,
    expires_at: float,
    authorization_epoch: int,
    policy_digest: str,
    step_authority_digest: str,
) -> ApprovalBinding:
    """Build the one immutable digest contract consumed by approval broker."""
    project_id = str(tool_context.get("project_id") or "")
    workspace_id = str(
        tool_context.get("workspace_id") or f"session:{session_id}"
    )
    profile_digest = canonical_digest(
        {
            "permission_level": tool.permission_level,
            "target": approval_target,
            "network_policy": tool_context["network_policy"],
            "effective_policy_digest": tool_context.get("effective_policy_digest", ""),
        }
    )
    return ApprovalBinding(
        principal_id=principal_id,
        session_id=session_id,
        task_id=str(tool_context.get("task_id") or f"session:{session_id}"),
        turn_id=turn_id,
        tool_call_id=tool_call_id,
        tool_name=str(tool.name),
        arguments_digest=canonical_digest(arguments),
        workspace_id=workspace_id,
        profile_digest=profile_digest,
        expires_at=expires_at,
        project_id=project_id,
        workspace_generation=(resource.workspace_generation if resource else 0),
        authorization_resource_digest=(resource.digest() if resource else ""),
        authorization_epoch=authorization_epoch,
        policy_digest=policy_digest,
        tool_schema_digest=tool.schema_digest,
        tool_security_digest=tool.security_digest,
        step_authority_digest=step_authority_digest,
    )


def build_permission_request(
    *,
    call: Mapping[str, Any],
    tool: Any,
    binding: ApprovalBinding,
    approval_id: str,
    binding_digest: str,
    reason: str,
    target: str,
    step_execution_digest: str,
) -> PermissionRequest:
    """Project a registered binding into the adapter-facing request object."""
    return PermissionRequest(
        tool_call_id=str(call["id"]),
        approval_id=approval_id,
        name=str(tool.name),
        arguments=dict(call["arguments"]),
        level=str(tool.permission_level),
        target=target,
        reason=reason,
        binding_digest=binding_digest,
        expires_at=binding.expires_at,
        principal_id=binding.principal_id,
        session_id=binding.session_id,
        task_id=binding.task_id,
        workspace_id=binding.workspace_id,
        arguments_digest=binding.arguments_digest,
        profile_digest=binding.profile_digest,
        project_id=binding.project_id,
        workspace_generation=binding.workspace_generation,
        authorization_resource_digest=binding.authorization_resource_digest,
        authorization_epoch=binding.authorization_epoch,
        policy_digest=binding.policy_digest,
        tool_schema_digest=binding.tool_schema_digest,
        tool_security_digest=binding.tool_security_digest,
        step_execution_digest=step_execution_digest,
    )


__all__ = [
    "RememberRuleProjection",
    "ToolAuthorization",
    "build_approval_binding",
    "build_permission_request",
    "tool_has_capability",
]
