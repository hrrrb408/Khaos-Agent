"""Credential owner/lease boundary tests."""

from __future__ import annotations

import time

import pytest
from khaos.security.credential_broker import (
    CredentialBroker,
    CredentialBrokerError,
)
from khaos.security.resource_scope import CredentialScope


def test_credential_lease_keeps_secret_out_of_identity_and_is_single_target() -> None:
    secret = "github-secret-value"
    scope = CredentialScope(
        provider="github",
        names=frozenset({"github-token"}),
        operations=frozenset({"github_read_issue"}),
    )
    broker = CredentialBroker(policy_digest="policy", principal_id="principal")
    broker.register(scope, lambda: {"GH_TOKEN": secret})
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )

    assert secret not in repr(lease)
    assert secret not in repr(lease.summary())
    assert broker.materialize(
        lease,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    ) == {"GH_TOKEN": secret}
    with pytest.raises(CredentialBrokerError, match="binding"):
        broker.materialize(
            lease,
            binding={"host": "github.com", "repository": "other/repo"},
            operation="github_read_issue",
        )
    broker.revoke(lease)
    with pytest.raises(CredentialBrokerError, match="unknown or revoked"):
        broker.materialize(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
    assert broker.terminal_postcondition()
    broker.close()
    assert broker.terminal_closed


def test_credential_lease_scope_is_bound_to_the_named_provider() -> None:
    github_scope = CredentialScope(
        provider="github",
        names=frozenset({"github-token"}),
        operations=frozenset({"github_read_issue"}),
    )
    broker = CredentialBroker()
    broker.register(github_scope, lambda: {"GH_TOKEN": "secret"})
    lease = broker.issue(
        github_scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )

    assert lease.scope.provider == "github"
    assert "github-token" in lease.scope.names
    broker.close()


def test_credential_lease_expiry_is_fail_closed() -> None:
    scope = CredentialScope(
        provider="git",
        names=frozenset({"https-askpass"}),
        operations=frozenset({"git_push"}),
    )
    broker = CredentialBroker(max_ttl_seconds=1.0)
    broker.register(scope, lambda: {"GIT_ASKPASS": "/private/helper"})
    lease = broker.issue(
        scope,
        binding="remote:https://github.com/owner/repo.git",
        operation="git_push",
        ttl_seconds=0.01,
    )
    time.sleep(0.02)
    with pytest.raises(CredentialBrokerError, match="expired"):
        broker.materialize(
            lease,
            binding="remote:https://github.com/owner/repo.git",
            operation="git_push",
        )
    assert broker.terminal_postcondition()


def test_raw_context_adoption_is_explicitly_disabled_by_default() -> None:
    broker = CredentialBroker()
    with pytest.raises(CredentialBrokerError, match="disabled"):
        broker.adopt_context(
            {
                "scope": "github-token",
                "environment": {"GH_TOKEN": "secret"},
            },
            provider="github",
            name="github-token",
            operation="github_read_issue",
            binding="github:owner/repo",
        )


def test_runtime_binding_cannot_be_retargeted() -> None:
    broker = CredentialBroker()
    broker.bind_runtime(policy_digest="policy-1", principal_id="principal-1")
    with pytest.raises(CredentialBrokerError, match="policy digest"):
        broker.bind_runtime(policy_digest="policy-2", principal_id="principal-1")
    with pytest.raises(CredentialBrokerError, match="principal"):
        broker.bind_runtime(policy_digest="policy-1", principal_id="principal-2")


def test_trusted_context_adapter_creates_opaque_expiring_lease() -> None:
    broker = CredentialBroker(allow_context_adoption=True)
    lease = broker.adopt_context(
        {
            "scope": "github-token",
            "environment": {"GH_TOKEN": "secret"},
        },
        provider="github",
        name="github-token",
        operation="github_read_issue",
        binding="github:owner/repo",
    )
    assert lease.scope.provider == "github"
    assert broker.materialize(
        lease,
        binding="github:owner/repo",
        operation="github_read_issue",
    ) == {"GH_TOKEN": "secret"}
    broker.revoke(lease)
    assert broker.terminal_postcondition()


def test_registered_provider_can_issue_without_passing_raw_context() -> None:
    broker = CredentialBroker()
    scope = CredentialScope(
        provider="github",
        names=frozenset({"github-token"}),
        operations=frozenset({"github_read_issue"}),
    )
    broker.register(scope, lambda: {"GH_TOKEN": "secret"})
    lease = broker.issue_named(
        provider="github",
        name="github-token",
        operation="github_read_issue",
        binding={"host": "github.com", "repository": "owner/repo"},
    )
    assert broker.materialize(
        lease,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    ) == {"GH_TOKEN": "secret"}
    broker.revoke(lease)
