"""Contract tests for approval binding/request projections."""

import asyncio
import inspect
import json
from types import SimpleNamespace

from khaos.permissions import ApprovalMode, PermissionDecision
from khaos.permissions.resource import AuthorizationResource, AuthorizationResourceKind
from khaos.tools.authorization import (
    ToolAuthorization,
    build_approval_binding,
    build_permission_request,
)
from khaos.tools.scheduler import ToolScheduler


def _resource() -> AuthorizationResource:
    return AuthorizationResource(
        kind=AuthorizationResourceKind.WORKSPACE_PATH,
        principal_id="principal",
        project_id="project",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=3,
        canonical_target=json.dumps(
            {"path": "/workspace/file.txt", "tool": "write_file"},
            sort_keys=True,
            separators=(",", ":"),
        ),
        root_device=1,
        root_inode=2,
    )


def _tool() -> SimpleNamespace:
    return SimpleNamespace(
        name="write_file",
        permission_level="write",
        schema_digest="s" * 64,
        security_digest="t" * 64,
    )


def _process_tool() -> SimpleNamespace:
    return SimpleNamespace(
        name="terminal_argv",
        permission_level="execute",
        capabilities=(SimpleNamespace(name="process.execute"),),
        schema_digest="s" * 64,
        security_digest="t" * 64,
    )


class _PermissionEngine:
    def __init__(self, decision: PermissionDecision) -> None:
        self.decision = decision

    async def check(self, **_kwargs):
        return self.decision


def test_binding_projection_binds_arguments_profile_policy_and_resource() -> None:
    tool = _tool()
    arguments = {"path": "file.txt", "content": "安全"}
    context = {
        "task_id": "task",
        "project_id": "project",
        "workspace_id": "workspace",
        "network_policy": "none",
        "effective_policy_digest": "p" * 64,
    }

    binding = build_approval_binding(
        tool=tool,
        arguments=arguments,
        tool_context=context,
        principal_id="principal",
        session_id="session",
        tool_call_id="call",
        turn_id="turn",
        approval_target="workspace:file.txt",
        resource=_resource(),
        expires_at=100.0,
        authorization_epoch=7,
        policy_digest="q" * 64,
        step_authority_digest="a" * 64,
    )

    assert binding.tool_call_id == "call"
    assert binding.arguments_digest
    assert binding.profile_digest
    assert binding.authorization_resource_digest == _resource().digest()
    assert binding.authorization_epoch == 7


def test_request_projection_reuses_registered_binding_identity() -> None:
    tool = _tool()
    binding = build_approval_binding(
        tool=tool,
        arguments={"path": "file.txt"},
        tool_context={
            "network_policy": "none",
            "effective_policy_digest": "p" * 64,
        },
        principal_id="principal",
        session_id="session",
        tool_call_id="call",
        turn_id="turn",
        approval_target="workspace:file.txt",
        resource=None,
        expires_at=100.0,
        authorization_epoch=1,
        policy_digest="q" * 64,
        step_authority_digest="a" * 64,
    )

    request = build_permission_request(
        call={"id": "call", "arguments": {"path": "file.txt"}},
        tool=tool,
        binding=binding,
        approval_id="approval",
        binding_digest="b" * 64,
        reason="needs approval",
        target="workspace:file.txt",
        step_execution_digest="e" * 64,
    )

    assert request.approval_id == "approval"
    assert request.binding_digest == "b" * 64
    assert request.arguments_digest == binding.arguments_digest
    assert request.profile_digest == binding.profile_digest
    assert request.step_execution_digest == "e" * 64


def test_tool_authorization_forces_untrusted_process_auto_approval_to_confirm() -> None:
    authorization = ToolAuthorization(
        _PermissionEngine(
            PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="remembered",
                target="process:/tmp/fake",
            )
        )
    )

    decision = asyncio.run(
        authorization.decide(
            tool=_process_tool(),
            arguments={"argv": ["/definitely-not-trusted/khaos"]},
            mode="coding",
            resource=None,
            source_transport="cli",
            session_id="session",
            task_id="task",
            workspace_id="workspace",
            environment={"PATH": "/usr/bin"},
            executable_argv=("/definitely-not-trusted/khaos",),
        )
    )

    assert decision.approved == ApprovalMode.ASK_EVERY
    assert decision.requires_user_confirm is True


def test_tool_authorization_projects_interactive_remember_rule() -> None:
    projection = ToolAuthorization.project_remember_rule(
        confirmation={"remember": True},
        source_transport="cli",
        resource=_resource(),
        decision_target="workspace:file.txt",
        tool=_tool(),
        mode="coding",
        session_id="session",
        tool_context={"task_id": "task", "workspace_id": "workspace"},
    )

    assert projection.warning == ""
    assert projection.rule is not None
    assert projection.rule.resource_type
    assert projection.rule.grant_lifetime == "project_interactive"


def test_tool_authorization_rejects_remember_for_unattended_transport() -> None:
    projection = ToolAuthorization.project_remember_rule(
        confirmation={"remember": True},
        source_transport="webhook",
        resource=None,
        decision_target="workspace:file.txt",
        tool=_tool(),
        mode="coding",
        session_id="session",
        tool_context={},
    )

    assert projection.rule is None
    assert "ignored for unattended" in projection.warning


def test_scheduler_delegates_permission_decision_to_authorization_owner() -> None:
    source = inspect.getsource(ToolScheduler)
    assert "self.permission_engine.check" not in source
    assert "self._tool_authorization.decide" in source
