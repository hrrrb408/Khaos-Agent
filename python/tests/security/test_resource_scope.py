"""Typed resource partial-order and authority integration tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from khaos.coding.planning.security_identities import (
    AuthorizationId,
    CanonicalWorkspaceId,
    EffectId,
    ExecutionContextId,
    ExecutionRunId,
    GrantId,
    LeaseId,
    PrincipalId,
    ProjectId,
    ReceiptNonce,
    RuntimeId,
    SessionId,
    TaskId,
    WorkspaceGeneration,
)
from khaos.security.authorityd import AuthorityDaemon, AuthorityPolicyKernel
from khaos.security.authorityd_protocol import (
    AuthorityControlPlaneError,
    AuthorizationIntent,
    Ed25519KeyStore,
)
from khaos.security.resource_scope import (
    CredentialScope,
    ExecutionScope,
    FilesystemScope,
    GitRefScope,
    NetworkScope,
    ResourceScopeError,
    TypedResourcePartialOrder,
)


class _MemoryWorm:
    def __init__(self) -> None:
        self.records: list[dict[str, object]] = []

    def append(self, record: dict[str, object]) -> None:
        self.records.append(record)


def test_security_identity_aliases_keep_distinct_static_names() -> None:
    assert str(PrincipalId("principal")) == "principal"
    assert str(ProjectId("project")) == "project"
    assert str(RuntimeId("runtime")) == "runtime"
    assert str(TaskId("task")) == "task"
    assert str(CanonicalWorkspaceId("workspace")) == "workspace"
    assert int(WorkspaceGeneration(2)) == 2
    assert str(SessionId("session")) == "session"
    assert str(AuthorizationId("authorization")) == "authorization"
    assert str(GrantId("grant")) == "grant"
    assert str(ReceiptNonce("nonce")) == "nonce"
    assert str(ExecutionRunId("run")) == "run"
    assert str(ExecutionContextId("context")) == "context"
    assert str(LeaseId("lease")) == "lease"
    assert str(EffectId("effect")) == "effect"


def test_filesystem_scope_is_workspace_bound_and_path_narrowing() -> None:
    parent = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        root="/repo",
        operations=frozenset({"read", "write"}),
    )
    child = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        root="/repo/src",
        operations=frozenset({"read"}),
    )
    sibling = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        root="/repo-tests",
        operations=frozenset({"read"}),
    )
    other_workspace = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-b"),
        root="/repo/src",
        operations=frozenset({"read"}),
    )

    assert parent.contains(child)
    assert not parent.contains(sibling)
    assert not parent.contains(other_workspace)


def test_network_scope_requires_explicit_origin_and_path_subset() -> None:
    parent = NetworkScope(
        schemes=frozenset({"https"}),
        hosts=frozenset({"api.example.com", "cdn.example.com"}),
        ports=frozenset({443}),
        path_prefixes=frozenset({"/v1"}),
        operations=frozenset({"connect", "read"}),
    )
    child = NetworkScope(
        schemes=frozenset({"https"}),
        hosts=frozenset({"api.example.com"}),
        ports=frozenset({443}),
        path_prefixes=frozenset({"/v1/repos"}),
        operations=frozenset({"read"}),
    )
    escape = NetworkScope(
        schemes=frozenset({"https"}),
        hosts=frozenset({"api.example.com"}),
        ports=frozenset({443}),
        path_prefixes=frozenset({"/v10"}),
        operations=frozenset({"read"}),
    )

    assert parent.contains(child)
    assert not parent.contains(escape)
    with pytest.raises(ResourceScopeError):
        NetworkScope(
            schemes=frozenset({"https"}),
            hosts=frozenset({"*.example.com"}),
            ports=frozenset({443}),
            path_prefixes=frozenset({"/"}),
            operations=frozenset({"read"}),
        )


def test_git_execution_and_credential_scopes_are_same_kind_only() -> None:
    git_parent = GitRefScope(
        repository="khaos",
        refs=frozenset({"refs/heads/main", "refs/heads/release"}),
        operations=frozenset({"read", "hash"}),
    )
    git_child = GitRefScope(
        repository="khaos",
        refs=frozenset({"refs/heads/main"}),
        operations=frozenset({"hash"}),
    )
    execution_parent = ExecutionScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        executable="/usr/bin/git",
        argv_prefix=("status",),
        cwd="/repo",
        operations=frozenset({"spawn", "observe"}),
    )
    execution_child = ExecutionScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        executable="/usr/bin/git",
        argv_prefix=("status", "--short"),
        cwd="/repo",
        operations=frozenset({"observe"}),
    )
    credential = CredentialScope(
        provider="keychain",
        names=frozenset({"github-token"}),
        operations=frozenset({"read"}),
    )

    assert git_parent.contains(git_child)
    assert execution_parent.contains(execution_child)
    assert not git_parent.contains(execution_child)
    assert credential.contains(credential)


def test_partial_order_catalog_is_immutable_and_fails_closed() -> None:
    parent = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        root="/repo",
        operations=frozenset({"read", "write"}),
    )
    child = FilesystemScope(
        workspace_id=CanonicalWorkspaceId("workspace-a"),
        root="/repo/src",
        operations=frozenset({"read"}),
    )
    order = TypedResourcePartialOrder(
        {parent.digest(): parent, child.digest(): child}
    )

    assert order.contains(parent.digest(), child.digest())
    assert not order.contains(parent.digest(), "0" * 64)
    order.require_transition(
        parent_digest=parent.digest(),
        requested_scope=child.digest(),
        source_operation="workspace.write",
        target_operation="workspace.read",
    )
    with pytest.raises(ResourceScopeError, match="action"):
        order.require_transition(
            parent_digest=parent.digest(),
            requested_scope=child.digest(),
            source_operation="workspace.write",
            target_operation="workspace.write",
        )
    with pytest.raises(ResourceScopeError, match="not a typed subset"):
        order.require_subset(child.digest(), parent.digest())
    with pytest.raises(ResourceScopeError, match="operation families"):
        order.require_transition(
            parent_digest=parent.digest(),
            requested_scope=child.digest(),
            source_operation="workspace.write",
            target_operation="network.read",
        )
    with pytest.raises(ResourceScopeError):
        TypedResourcePartialOrder({"0" * 64: parent})


def test_catalog_manifest_binds_policy_and_round_trips() -> None:
    scope = GitRefScope(
        repository="/repo",
        refs=frozenset({"HEAD"}),
        operations=frozenset({"status", "hash"}),
    )
    order = TypedResourcePartialOrder(
        {scope.digest(): scope},
        policy_digest="policy-digest",
    )
    restored = TypedResourcePartialOrder.from_manifest(
        order.manifest(),
        expected_policy_digest="policy-digest",
    )
    assert restored.catalog_digest == order.catalog_digest
    assert restored.policy_digest == "policy-digest"
    assert restored.require_scope(scope) == scope.digest()
    restored.require_operation(scope.digest(), "git.hash")
    with pytest.raises(ResourceScopeError, match="action"):
        restored.require_operation(scope.digest(), "git.apply")
    with pytest.raises(ResourceScopeError, match="not bound"):
        TypedResourcePartialOrder.from_manifest(
            order.manifest(), expected_policy_digest="other-policy"
        )


def test_authority_kernel_enforces_typed_narrowing_when_configured(
    tmp_path: Path,
) -> None:
    parent_scope = GitRefScope(
        repository="khaos",
        refs=frozenset({"refs/heads/main", "refs/heads/release"}),
        operations=frozenset({"read", "hash", "workspace"}),
    )
    child_scope = GitRefScope(
        repository="khaos",
        refs=frozenset({"refs/heads/main"}),
        operations=frozenset({"hash"}),
    )
    sibling_scope = GitRefScope(
        repository="khaos",
        refs=frozenset({"refs/heads/secret"}),
        operations=frozenset({"hash"}),
    )
    order = TypedResourcePartialOrder(
        {
            parent_scope.digest(): parent_scope,
            child_scope.digest(): child_scope,
            sibling_scope.digest(): sibling_scope,
        }
    )
    kernel = AuthorityPolicyKernel(resource_order=order)
    worm = _MemoryWorm()
    daemon = AuthorityDaemon(
        socket_path=tmp_path / "authorityd.sock",
        signing_key=Ed25519KeyStore.load_or_create(tmp_path / "key.pem", create=True),
        audit_writer=worm,
        issuer_id="test-authorityd",
        policy=kernel,
    )
    parent = daemon.prepare(
        AuthorizationIntent(
            principal_id="agent",
            project_id="project",
            runtime_id="runtime",
            task_id="task",
            workspace_id="workspace",
            operation="git.workspace",
            resource_digest=parent_scope.digest(),
            policy_digest="policy",
            nonce="typed-parent",
            authorization_epoch=1,
        )
    )
    with pytest.raises(AuthorityControlPlaneError, match="typed resource"):
        daemon.prepare(
            AuthorizationIntent(
                principal_id="agent",
                project_id="project",
                runtime_id="runtime",
                task_id="task",
                workspace_id="workspace",
                operation="git.workspace",
                resource_digest="0" * 64,
                policy_digest="policy",
                nonce="unknown-resource",
                authorization_epoch=1,
            )
        )

    child = daemon.narrow(
        parent,
        operation="git.hash",
        resource_digest=child_scope.digest(),
    )
    assert child.operation == "git.hash"
    assert child.resource_digest == child_scope.digest()

    with pytest.raises(AuthorityControlPlaneError, match="typed resource"):
        daemon.narrow(
            child,
            operation="git.hash",
            resource_digest=sibling_scope.digest(),
        )
