"""Authority-owned typed delegation tests (M6.9 BATCH 4).

Delegation state used to be caller-side: ``SubAgentService`` copied the
parent's ``delegation_digest`` onto the child, and ``DelegationAuthority``
was unused in production.  Now the authority daemon owns the registry:
roots are registered by ingress principals, children are narrow-only
with unique nonces, consumption is one-shot, revocation cascades, and a
child can never present the parent's delegation.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from khaos.runtime.context import RequestContext
from khaos.security.authorityd import (
    AuthorityControlPlaneError,
    AuthorityDaemon,
    _dispatch,
)
from khaos.security.authorityd_protocol import (
    AUTHORITYD_PROTOCOL,
    Ed25519KeyStore,
)
from khaos.security.delegation_issuer import (
    AuthorityDelegationIssuer,
    ProductionSubAgentDelegationIssuer,
)
from khaos.security.principals import (
    PRINCIPAL_DELEGATION_FAMILY,
    DelegationAuthority,
    DelegationScope,
    GatewayPrincipal,
    PrincipalDelegationError,
    SubagentPrincipal,
)
from khaos.subagents.service import SubAgentService
from khaos.subagents.spawner import SubAgentConfig, SubAgentSpawner


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


def _daemon(tmp_path: Path) -> AuthorityDaemon:
    return AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(
            tmp_path / "authorityd-key.pem", create=True
        ),
        audit_writer=_MemoryWorm(),
        issuer_id="test-authorityd",
        policy=lambda _intent: None,
    )


def _root(
    *,
    principal=None,
    project: str = "proj",
    session: str = "sess",
    runtime: str = "rt",
    task: str = "task",
    workspace: str = "ws",
    family: str = "subagent",
    resources: frozenset[str] = frozenset({"tool.a", "tool.b"}),
    policy: str = "a" * 64,
    expires_at: float | None = None,
) -> DelegationScope:
    return DelegationScope.root(
        principal or GatewayPrincipal("gateway:api-key"),
        project_id=project,
        session_id=session,
        runtime_id=runtime,
        task_id=task,
        workspace_id=workspace,
        operation_family=family,
        resource_scope=resources,
        policy_digest=policy,
        expires_at=expires_at if expires_at is not None else time.time() + 3600,
    )


def _child(daemon: AuthorityDaemon, root: DelegationScope, *, subject_id: str, **overrides) -> DelegationScope:
    return daemon.delegation_child(
        root,
        subject_id,
        "subagent",
        operation_family=overrides.get("family", "subagent"),
        resource_scope=overrides.get("resources", ["tool.a"]),
        expires_at=overrides.get(
            "expires_at", time.time() + overrides.get("ttl", 600)
        ),
    )


def _consume_kwargs(scope: DelegationScope, **overrides) -> dict[str, str]:
    kwargs = {
        "principal_id": scope.subject.principal_id,
        "principal_kind": scope.subject.kind.value,
        "project_id": scope.project_id,
        "session_id": scope.session_id,
        "runtime_id": scope.runtime_id,
        "task_id": scope.task_id,
        "workspace_id": scope.workspace_id,
        "operation_family": scope.operation_family,
        "resource_scope": list(scope.resource_scope),
        "policy_digest": scope.policy_digest,
    }
    kwargs.update(overrides)
    return kwargs


def test_root_registration_is_ingress_only_and_idempotent(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    first = daemon.delegation_root(root)
    second = daemon.delegation_root(root)
    assert first == second == root.digest
    # A subagent can never establish a root scope.
    with pytest.raises(AuthorityControlPlaneError, match="ingress principal"):
        daemon.delegation_root(
            DelegationScope.root(
                SubagentPrincipal("subagent:x"),
                project_id="proj",
                session_id="sess",
                runtime_id="rt",
                task_id="task",
                workspace_id="ws",
                operation_family="subagent",
                resource_scope=["tool.a"],
                policy_digest="a" * 64,
                expires_at=time.time() + 600,
            )
        )


def test_child_delegations_are_unique_and_narrow(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child_a = _child(daemon, root, subject_id="subagent:a")
    child_b = _child(daemon, root, subject_id="subagent:b")
    assert child_a.digest != child_b.digest
    assert child_a.digest != root.digest
    assert child_a.nonce != child_b.nonce
    assert child_a.resource_scope.issubset(root.resource_scope)


def test_replayed_child_payload_cannot_become_a_root(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child = _child(daemon, root, subject_id="subagent:a")
    daemon.delegation_consume(child, **_consume_kwargs(child))
    # Replaying the consumed child payload as a fresh root is rejected:
    # a subagent principal can never establish an ingress root scope.
    with pytest.raises(AuthorityControlPlaneError, match="ingress principal"):
        daemon.delegation_root(child)


def test_consume_is_one_shot(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child = _child(daemon, root, subject_id="subagent:a")
    daemon.delegation_consume(child, **_consume_kwargs(child))
    with pytest.raises(AuthorityControlPlaneError, match="already consumed"):
        daemon.delegation_consume(child, **_consume_kwargs(child))


def test_principal_delegation_consumes_at_effect_claim_with_unbound_workspace() -> None:
    authority = DelegationAuthority()
    root = DelegationScope.root(
        GatewayPrincipal("gateway:api-key"),
        project_id="proj",
        session_id="sess",
        runtime_id="rt",
        task_id="unbound",
        workspace_id="unbound",
        operation_family=PRINCIPAL_DELEGATION_FAMILY,
        resource_scope=["tool.a"],
        policy_digest="a" * 64,
        expires_at=time.time() + 600,
    )
    authority.register_root(root)
    child = authority.delegate(
        root,
        SubagentPrincipal("subagent:a"),
        operation_family=PRINCIPAL_DELEGATION_FAMILY,
        resource_scope=["tool.a"],
        expires_at=time.time() + 300,
        task_id="child-task",
        workspace_id="unbound",
    )
    authority.consume_for_effect(
        child.digest,
        principal=child.subject,
        parent_principal_id=child.parent_principal.identity,
        project_id="proj",
        session_id="sess",
        runtime_id="rt",
        task_id="child-task",
        workspace_id="real-workspace",
        policy_digest="a" * 64,
        delegation_resource="tool.a",
    )
    assert authority.live_scope(child.digest) is None
    with pytest.raises(PrincipalDelegationError, match="unknown|consumed"):
        authority.consume_for_effect(
            child.digest,
            principal=child.subject,
            parent_principal_id=child.parent_principal.identity,
            project_id="proj",
            session_id="sess",
            runtime_id="rt",
            task_id="child-task",
            workspace_id="real-workspace",
            policy_digest="a" * 64,
            delegation_resource="tool.a",
        )


def test_cross_context_consumption_fails_closed(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child = _child(daemon, root, subject_id="subagent:a")
    for mutate in (
        {"principal_id": "subagent:other"},
        {"principal_kind": "browser"},
        {"project_id": "other-proj"},
        {"session_id": "other-sess"},
        {"runtime_id": "other-rt"},
        {"task_id": "other-task"},
        {"workspace_id": "other-ws"},
        {"operation_family": "exec"},
        {"policy_digest": "q" * 64},
    ):
        with pytest.raises(AuthorityControlPlaneError):
            daemon.delegation_consume(child, **_consume_kwargs(child, **mutate))
    with pytest.raises(AuthorityControlPlaneError):
        daemon.delegation_consume(
            child, **_consume_kwargs(child, resource_scope=["tool.a", "tool.b"])
        )


def test_child_can_never_outlive_expired_parent(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root(expires_at=time.time() + 60)
    daemon.delegation_root(root)
    # A child whose expiry exceeds the parent's is a widening and is
    # rejected at issuance: descendants can never outlive the parent.
    with pytest.raises(AuthorityControlPlaneError, match="widen"):
        _child(daemon, root, subject_id="subagent:a", ttl=3600)
    # Once the parent window passes, consuming any child fails closed.
    child = _child(daemon, root, subject_id="subagent:a", ttl=30)
    import khaos.security.principals as principals_module

    original = principals_module.time.time
    principals_module.time.time = lambda: original() + 120
    try:
        with pytest.raises(AuthorityControlPlaneError, match="expired"):
            daemon.delegation_consume(child, **_consume_kwargs(child))
    finally:
        principals_module.time.time = original


def test_revoked_parent_cascades_to_unclaimed_children(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child = _child(daemon, root, subject_id="subagent:a")
    daemon.delegation_revoke(root)
    # The cascade removed the unclaimed child from the live registry, so
    # consuming it fails closed instead of honoring the stale scope.
    with pytest.raises(AuthorityControlPlaneError, match="unknown or already consumed"):
        daemon.delegation_consume(child, **_consume_kwargs(child))


def test_sibling_delegation_cannot_be_consumed_by_another_subagent(
    tmp_path: Path,
) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    daemon.delegation_root(root)
    child_a = _child(daemon, root, subject_id="subagent:a")
    child_b = _child(daemon, root, subject_id="subagent:b")
    # Cross-subagent reuse: B presents A's delegation.
    with pytest.raises(AuthorityControlPlaneError):
        daemon.delegation_consume(
            child_a, **_consume_kwargs(child_a, principal_id="subagent:b")
        )
    # The failed attempt must not have consumed either scope.
    daemon.delegation_consume(child_a, **_consume_kwargs(child_a))
    daemon.delegation_consume(child_b, **_consume_kwargs(child_b))


def test_widening_delegation_is_rejected(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root(resources=frozenset({"tool.a"}))
    daemon.delegation_root(root)
    with pytest.raises(AuthorityControlPlaneError, match="widen"):
        daemon.delegation_child(
            root,
            "subagent:a",
            "subagent",
            operation_family="subagent",
            resource_scope=["tool.a", "tool.b"],
            expires_at=time.time() + 60,
        )
    with pytest.raises(AuthorityControlPlaneError, match="widen"):
        daemon.delegation_child(
            root,
            "subagent:a",
            "subagent",
            operation_family="exec",
            resource_scope=["tool.a"],
            expires_at=time.time() + 60,
        )


def test_scope_payload_roundtrip_is_canonical(tmp_path: Path) -> None:
    root = _root(resources=frozenset({"tool.a", "tool.b"}))
    payload = root.canonical()
    assert DelegationScope.from_payload(payload).digest == root.digest
    # A non-canonical encoding (unsorted resource scope) is rejected even
    # though its content is semantically identical: the wire form is part
    # of the signed digest.
    unsorted_payload = dict(payload)
    unsorted_payload["resource_scope"] = ["tool.b", "tool.a"]
    with pytest.raises(PrincipalDelegationError, match="not canonical"):
        DelegationScope.from_payload(unsorted_payload)
    incomplete = {k: v for k, v in payload.items() if k != "nonce"}
    with pytest.raises(PrincipalDelegationError, match="incomplete"):
        DelegationScope.from_payload(incomplete)


def test_dispatch_delegation_operations(tmp_path: Path) -> None:
    daemon = _daemon(tmp_path)
    root = _root()
    registered = _dispatch(
        daemon,
        {"protocol": AUTHORITYD_PROTOCOL, "operation": "delegation_root", "scope": root.canonical()},
    )
    assert registered["ok"] is True
    issued = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "delegation_child",
            "parent": root.canonical(),
            "child_principal_id": "subagent:a",
            "child_principal_kind": "subagent",
            "operation_family": "subagent",
            "resource_scope": ["tool.a"],
            "expires_at": time.time() + 600,
        },
    )
    assert issued["ok"] is True
    child = DelegationScope.from_payload(issued["delegation"])
    consumed = _dispatch(
        daemon,
        {
            "protocol": AUTHORITYD_PROTOCOL,
            "operation": "delegation_consume",
            "delegation": child.canonical(),
            **_consume_kwargs(child),
        },
    )
    assert consumed["ok"] is True
    with pytest.raises(AuthorityControlPlaneError):
        _dispatch(
            daemon,
            {
                "protocol": AUTHORITYD_PROTOCOL,
                "operation": "delegation_consume",
                "delegation": child.canonical(),
                **_consume_kwargs(child),
            },
        )


class _FakeIssuer:
    """Records issuance requests and returns unique digests."""

    def __init__(self) -> None:
        self.issued: list[str] = []
        self.requests: list[dict[str, str]] = []
        self.fail = False

    def issue_subagent_delegation(
        self,
        ctx: RequestContext,
        *,
        task_id: str,
        tools: list[str],
        timeout_seconds: int,
        session_id: str = "",
        runtime_id: str = "",
        workspace_id: str = "",
    ) -> str:
        if self.fail:
            raise PermissionError("authority unavailable")
        self.requests.append(
            {
                "task_id": task_id,
                "session_id": session_id,
                "runtime_id": runtime_id,
                "workspace_id": workspace_id,
            }
        )
        digest = f"{len(self.issued):064d}"[-64:]
        self.issued.append(digest)
        return digest


class _FakeDB:
    async def create_session(self, *args, **kwargs) -> None:
        return None

    async def insert_subagent_task(self, *args, **kwargs) -> None:
        return None


def _service(issuer: _FakeIssuer | None) -> SubAgentService:
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=3, max_spawn_depth=1, allow_nesting=False),
        _FakeDB(),
    )
    return SubAgentService(spawner, runner=None, delegation_issuer=issuer)


def _ctx() -> RequestContext:
    return RequestContext.for_rpc(
        "gateway:api-key", project_id="proj", policy_digest="a" * 64
    )


async def test_spawn_does_not_reuse_parent_delegation_digest() -> None:
    service = _service(None)
    result = await service.handle_spawn(
        _ctx(), {"goal": "g", "tools": ["tool.a"], "timeout": 10}
    )
    assert result["ok"] is True
    # The spawned task must NOT carry the parent context's digest.
    task = service.spawner._tasks[result["task_id"]]
    assert task.delegation_digest != _ctx().delegation_digest
    assert task.delegation_digest == ""


async def test_spawn_with_issuer_receives_unique_child_digests() -> None:
    issuer = _FakeIssuer()
    service = _service(issuer)
    ctx = _ctx()
    first = await service.handle_spawn(
        ctx, {"goal": "g", "tools": ["tool.a"], "timeout": 10}
    )
    second = await service.handle_spawn(
        ctx, {"goal": "g2", "tools": ["tool.a"], "timeout": 10}
    )
    assert first["ok"] is True and second["ok"] is True
    assert len(issuer.issued) == 2
    assert issuer.issued[0] != issuer.issued[1]
    task_a = service.spawner._tasks[first["task_id"]]
    task_b = service.spawner._tasks[second["task_id"]]
    assert task_a.delegation_digest != task_b.delegation_digest
    assert task_a.delegation_digest != ctx.delegation_digest
    assert task_a.session_id == issuer.requests[0]["session_id"]
    assert task_a.runtime_id == issuer.requests[0]["runtime_id"]
    assert task_a.parent_principal_id == ctx.parent_principal_id
    assert task_a.session_id.endswith(f"/{task_a.id}")


class _AuthorityClientDouble:
    """In-process owner double for the issuer's vertical binding test."""

    def __init__(self) -> None:
        self.authority = DelegationAuthority()

    def delegation_register_root(self, scope: DelegationScope) -> str:
        return self.authority.register_root(scope)

    def delegation_issue_child(
        self,
        parent: DelegationScope,
        child_principal_id: str,
        child_principal_kind: str,
        *,
        operation_family: str,
        resource_scope: list[str],
        expires_at: float,
        session_id: str | None = None,
        runtime_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> DelegationScope:
        return self.authority.delegate(
            parent,
            SubagentPrincipal(child_principal_id),
            operation_family=operation_family,
            resource_scope=resource_scope,
            expires_at=expires_at,
            session_id=session_id,
            runtime_id=runtime_id,
            task_id=task_id,
            workspace_id=workspace_id,
        )

    def close(self) -> None:
        self.closed = True


def test_issuer_binds_delegation_to_the_real_child_execution_context() -> None:
    client = _AuthorityClientDouble()
    issuer = AuthorityDelegationIssuer(client)
    ctx = _ctx()
    task_id = "task_child"
    session_id = "subagent:gateway:api-key/task_child"
    runtime_id = "runtime_child"
    digest = issuer.issue_subagent_delegation(
        ctx,
        task_id=task_id,
        tools=["tool.a"],
        timeout_seconds=60,
        session_id=session_id,
        runtime_id=runtime_id,
    )
    child = client.authority.live_scope(digest)
    assert child is not None
    assert child.task_id == task_id
    assert child.session_id == session_id
    assert child.runtime_id == runtime_id
    assert child.parent_principal.identity == ctx.parent_principal_id


def test_production_subagent_issuer_uses_a_bound_short_lived_broker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Production delegation issuance never creates an unbound client."""
    from khaos.security.authority_broker import AuthorityBroker

    client = _AuthorityClientDouble()
    calls: dict[str, object] = {}

    def fake_for_production(cls, **kwargs):
        _ = cls
        calls.update(kwargs)
        return client

    monkeypatch.setattr(
        AuthorityBroker,
        "for_production",
        classmethod(fake_for_production),
    )
    issuer = ProductionSubAgentDelegationIssuer(
        policy_digest="a" * 64,
        catalog_digest="b" * 64,
        project_id="proj",
    )
    digest = issuer.issue_subagent_delegation(
        _ctx(),
        task_id="task_child",
        tools=["tool.a"],
        timeout_seconds=60,
        session_id="subagent:gateway:api-key/task_child",
        runtime_id="runtime_child",
    )

    assert digest
    assert calls == {
        "policy_digest": "a" * 64,
        "catalog_digest": "b" * 64,
        "runtime_id": "delegation:runtime_child",
        "principal_id": "gateway:api-key",
        "project_id": "proj",
        "principal_kind": "gateway",
    }
    assert getattr(client, "closed", False) is True


def test_principal_delegation_rejects_the_wrong_parent_identity() -> None:
    authority = DelegationAuthority()
    root = DelegationScope.root(
        GatewayPrincipal("gateway:api-key"),
        project_id="proj",
        session_id="unbound",
        runtime_id="unbound",
        task_id="unbound",
        workspace_id="unbound",
        operation_family=PRINCIPAL_DELEGATION_FAMILY,
        resource_scope=["tool.a"],
        policy_digest="a" * 64,
        expires_at=time.time() + 600,
    )
    authority.register_root(root)
    child = authority.delegate(
        root,
        SubagentPrincipal("subagent:a"),
        operation_family=PRINCIPAL_DELEGATION_FAMILY,
        resource_scope=["tool.a"],
        expires_at=time.time() + 300,
        session_id="child-session",
        runtime_id="child-runtime",
        task_id="child-task",
    )
    with pytest.raises(PrincipalDelegationError, match="parent"):
        authority.consume_for_effect(
            child.digest,
            principal=child.subject,
            parent_principal_id="gateway:wrong",
            project_id="proj",
            session_id="child-session",
            runtime_id="child-runtime",
            task_id="child-task",
            workspace_id="workspace",
            policy_digest="a" * 64,
            delegation_resource="tool.a",
        )


async def test_spawn_fails_closed_when_issuance_fails() -> None:
    issuer = _FakeIssuer()
    issuer.fail = True
    service = _service(issuer)
    result = await service.handle_spawn(
        _ctx(), {"goal": "g", "tools": ["tool.a"], "timeout": 10}
    )
    assert result["ok"] is False
    assert "delegation issuance failed" in result["error"]
