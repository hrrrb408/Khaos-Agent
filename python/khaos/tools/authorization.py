"""Pure approval-binding projections for the tool authorization boundary.

This module does not call a permission engine or consume a receipt. It only
turns server-owned tool/context state into the immutable binding and request
objects that are shown to an approval adapter and rechecked at dispatch.
Keeping those projections here prevents the scheduler from growing a second,
slightly different digest schema for the same approval.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from khaos.agent.approval import ApprovalBinding
from khaos.permissions.resource import AuthorizationResource
from khaos.security.protocol_boundary import canonical_digest
from khaos.tools.scheduler_models import PermissionRequest


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


__all__ = ["build_approval_binding", "build_permission_request"]
