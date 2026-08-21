"""Contract tests for approval binding/request projections."""

from types import SimpleNamespace

from khaos.permissions.resource import AuthorizationResource, AuthorizationResourceKind
from khaos.tools.authorization import build_approval_binding, build_permission_request


def _resource() -> AuthorizationResource:
    return AuthorizationResource(
        kind=AuthorizationResourceKind.WORKSPACE_PATH,
        principal_id="principal",
        project_id="project",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=3,
        canonical_target="workspace:file.txt",
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
