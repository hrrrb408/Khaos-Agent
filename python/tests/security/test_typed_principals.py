from __future__ import annotations

import pytest

from khaos.runtime.context import RequestContext
from khaos.security.principals import (
    AutomationPrincipal,
    BrowserPrincipal,
    ChannelPrincipal,
    DelegationAuthority,
    DelegationScope,
    GatewayPrincipal,
    HumanPrincipal,
    PrincipalDelegationError,
    PrincipalKind,
    SubagentPrincipal,
)


POLICY = "a" * 64


def _root() -> DelegationScope:
    return DelegationScope.root(
        HumanPrincipal("human:alice"),
        project_id="project-a",
        session_id="session-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls", "argv:/usr/bin/cat"},
        policy_digest=POLICY,
        issued_at=100.0,
        expires_at=200.0,
        nonce="root-nonce",
    )


@pytest.mark.parametrize(
    ("transport", "kind"),
    [
        ("cli", PrincipalKind.HUMAN),
        ("rpc", PrincipalKind.GATEWAY),
        ("webhook", PrincipalKind.CHANNEL),
        ("cron", PrincipalKind.AUTOMATION),
        ("subagent", PrincipalKind.SUBAGENT),
        ("browser", PrincipalKind.BROWSER),
    ],
)
def test_request_context_assigns_typed_transport_principal(transport, kind) -> None:
    context = RequestContext(
        principal_id="principal-a",
        source_transport=transport,
    )

    assert context.principal.kind is kind
    assert context.principal.identity == f"{kind.value}:principal-a"


def test_all_concrete_principal_types_are_distinct() -> None:
    principals = {
        type(principal)
        for principal in (
            HumanPrincipal("human-a"),
            GatewayPrincipal("gateway-a"),
            ChannelPrincipal("channel-a"),
            AutomationPrincipal("cron-a"),
            SubagentPrincipal("subagent-a"),
            BrowserPrincipal("browser-a"),
        )
    }

    assert len(principals) == 6


def test_delegation_is_narrow_only_and_one_shot() -> None:
    authority = DelegationAuthority()
    root = _root()
    authority.register_root(root)
    child = authority.delegate(
        root,
        GatewayPrincipal("gateway:alice"),
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls"},
        expires_at=150.0,
        now=101.0,
        nonce="gateway-nonce",
    )

    authority.consume(
        child,
        principal=GatewayPrincipal("gateway:alice"),
        project_id="project-a",
        session_id="session-a",
        runtime_id="runtime-a",
        task_id="task-a",
        workspace_id="workspace-a",
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls"},
        policy_digest=POLICY,
        now=102.0,
    )
    with pytest.raises(PrincipalDelegationError, match="consumed"):
        authority.consume(
            child,
            principal=GatewayPrincipal("gateway:alice"),
            project_id="project-a",
            session_id="session-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            operation_family="process.execute.read",
            resource_scope={"argv:/usr/bin/ls"},
            policy_digest=POLICY,
            now=102.0,
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"operation_family": "process.execute.write"},
        {"resource_scope": {"argv:/usr/bin/rm"}},
    ],
)
def test_cross_scope_or_widening_delegation_is_rejected(changes) -> None:
    authority = DelegationAuthority()
    root = _root()
    authority.register_root(root)
    kwargs = {
        "operation_family": "process.execute.read",
        "resource_scope": {"argv:/usr/bin/ls"},
        "expires_at": 150.0,
        "now": 101.0,
        "nonce": "rejected-nonce",
    }
    kwargs.update(changes)

    with pytest.raises(PrincipalDelegationError):
        authority.delegate(root, SubagentPrincipal("subagent:one"), **kwargs)


def test_cross_context_replay_is_rejected_at_consumption() -> None:
    authority = DelegationAuthority()
    root = _root()
    authority.register_root(root)
    child = authority.delegate(
        root,
        SubagentPrincipal("subagent:one"),
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls"},
        expires_at=150.0,
        now=101.0,
        nonce="context-replay",
    )

    with pytest.raises(PrincipalDelegationError, match="exact"):
        authority.consume(
            child,
            principal=SubagentPrincipal("subagent:one"),
            project_id="project-b",
            session_id="session-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            operation_family="process.execute.read",
            resource_scope={"argv:/usr/bin/ls"},
            policy_digest=POLICY,
            now=102.0,
        )


def test_channel_cannot_reuse_gateway_delegation() -> None:
    authority = DelegationAuthority()
    root = _root()
    authority.register_root(root)
    child = authority.delegate(
        root,
        GatewayPrincipal("gateway:alice"),
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls"},
        expires_at=150.0,
        now=101.0,
        nonce="cross-principal",
    )

    with pytest.raises(PrincipalDelegationError, match="exact"):
        authority.consume(
            child,
            principal=ChannelPrincipal("channel:alice"),
            project_id="project-a",
            session_id="session-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            operation_family="process.execute.read",
            resource_scope={"argv:/usr/bin/ls"},
            policy_digest=POLICY,
            now=102.0,
        )


def test_expired_parent_and_expired_child_fail_closed() -> None:
    authority = DelegationAuthority()
    root = _root()
    authority.register_root(root)
    with pytest.raises(PrincipalDelegationError, match="expired"):
        authority.delegate(
            root,
            AutomationPrincipal("cron:one"),
            operation_family="process.execute.read",
            resource_scope={"argv:/usr/bin/ls"},
            expires_at=150.0,
            now=200.0,
        )

    child = authority.delegate(
        root,
        BrowserPrincipal("browser:one"),
        operation_family="process.execute.read",
        resource_scope={"argv:/usr/bin/ls"},
        expires_at=150.0,
        now=101.0,
    )
    with pytest.raises(PrincipalDelegationError, match="expired"):
        authority.consume(
            child,
            principal=BrowserPrincipal("browser:one"),
            project_id="project-a",
            session_id="session-a",
            runtime_id="runtime-a",
            task_id="task-a",
            workspace_id="workspace-a",
            operation_family="process.execute.read",
            resource_scope={"argv:/usr/bin/ls"},
            policy_digest=POLICY,
            now=150.0,
        )


def test_principal_kind_cannot_be_forged_for_a_transport() -> None:
    with pytest.raises(ValueError, match="does not match"):
        RequestContext(
            principal_id="channel:sender",
            source_transport="webhook",
            principal_kind=PrincipalKind.HUMAN.value,
        )
