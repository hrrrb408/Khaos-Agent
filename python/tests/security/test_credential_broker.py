"""Credential owner/lease boundary tests."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest
from khaos.security.credential_broker import (
    CredentialBroker,
    CredentialBrokerError,
    CredentialEnvironmentSchema,
)
from khaos.security.resource_scope import CredentialScope


async def _await_terminal(broker: CredentialBroker, budget: float = 5.0) -> bool:
    """Poll until every owned lease/transaction settles."""
    deadline = time.monotonic() + budget
    while time.monotonic() < deadline:
        if broker.terminal_postcondition():
            return True
        await asyncio.sleep(0.01)
    return broker.terminal_postcondition()


def _github_scope(*operations: str) -> CredentialScope:
    return CredentialScope(
        provider="github",
        names=frozenset({"github-token"}),
        operations=frozenset(operations),
    )


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
    with pytest.raises(CredentialBrokerError, match="binding"):
        broker.materialize(
            lease,
            binding={"host": "github.com", "repository": "other/repo"},
            operation="github_read_issue",
        )
    assert broker.materialize(
        lease,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    ) == {"GH_TOKEN": secret}
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


def test_lease_operation_is_exact_even_when_scope_contains_multiple_operations() -> None:
    scope = _github_scope("github_read_issue", "github_comment_issue")
    broker = CredentialBroker()
    broker.register(scope, lambda: {"GH_TOKEN": "secret"})
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )

    assert lease.authorized_operation == "github_read_issue"
    assert lease.summary()["authorized_operation"] == "github_read_issue"
    with pytest.raises(CredentialBrokerError, match="different operation"):
        broker.materialize(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_comment_issue",
        )
    assert broker.materialize(
        lease,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    ) == {"GH_TOKEN": "secret"}


def test_revoke_during_provider_loader_discards_secret_without_sleep() -> None:
    entered = threading.Event()
    release = threading.Event()
    result: dict[str, object] = {}
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(2.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )

    def run() -> None:
        try:
            broker.materialize(
                lease,
                binding={"host": "github.com", "repository": "owner/repo"},
                operation="github_read_issue",
            )
        except BaseException as exc:  # noqa: BLE001 - capture worker outcome
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(2.0)
    assert any(item.startswith("credential-materialization:") for item in broker.owned_resources())
    broker.revoke(lease)
    assert not broker.terminal_closed
    release.set()
    worker.join(2.0)
    assert not worker.is_alive()
    assert isinstance(result.get("error"), CredentialBrokerError)
    assert "revoked" in str(result["error"])
    assert broker.terminal_postcondition()
    broker.close()
    assert broker.terminal_closed


def test_close_during_provider_loader_is_quarantined_until_transaction_settles() -> None:
    entered = threading.Event()
    release = threading.Event()
    result: dict[str, object] = {}
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(2.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding="github:owner/repo",
        operation="github_read_issue",
    )

    def run() -> None:
        try:
            broker.materialize(
                lease,
                binding="github:owner/repo",
                operation="github_read_issue",
            )
        except BaseException as exc:  # noqa: BLE001 - capture worker outcome
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(2.0)
    broker.close()
    assert broker.generation_admission_closed
    assert broker.is_quarantined
    assert not broker.terminal_closed
    release.set()
    worker.join(2.0)
    assert not worker.is_alive()
    assert isinstance(result.get("error"), CredentialBrokerError)
    assert "closed" in str(result["error"]) or "revoked" in str(result["error"])
    assert broker.terminal_closed
    assert not broker.is_quarantined


def test_expiry_during_provider_loader_is_checked_after_loader_returns(monkeypatch) -> None:
    import khaos.security.credential_broker as module

    clock = [100.0]
    monkeypatch.setattr(module.time, "time", lambda: clock[0])
    entered = threading.Event()
    release = threading.Event()
    result: dict[str, object] = {}
    broker = CredentialBroker(max_ttl_seconds=10.0)
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(2.0)
        return {"GH_TOKEN": "expired"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding="github:owner/repo",
        operation="github_read_issue",
        ttl_seconds=1.0,
    )

    def run() -> None:
        try:
            broker.materialize(
                lease,
                binding="github:owner/repo",
                operation="github_read_issue",
            )
        except BaseException as exc:  # noqa: BLE001 - capture worker outcome
            result["error"] = exc

    worker = threading.Thread(target=run)
    worker.start()
    assert entered.wait(2.0)
    clock[0] = 102.0
    release.set()
    worker.join(2.0)
    assert not worker.is_alive()
    assert isinstance(result.get("error"), CredentialBrokerError)
    assert "expired" in str(result["error"])
    assert broker.terminal_postcondition()


def test_concurrent_materialize_has_one_claim_without_sleep() -> None:
    entered = threading.Event()
    release = threading.Event()
    outcomes: list[object] = []
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(2.0)
        return {"GH_TOKEN": "one-shot"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding="github:owner/repo",
        operation="github_read_issue",
    )

    def run() -> None:
        try:
            outcomes.append(
                broker.materialize(
                    lease,
                    binding="github:owner/repo",
                    operation="github_read_issue",
                )
            )
        except BaseException as exc:  # noqa: BLE001 - capture worker outcome
            outcomes.append(exc)

    first = threading.Thread(target=run)
    first.start()
    assert entered.wait(2.0)
    second = threading.Thread(target=run)
    second.start()
    second.join(2.0)
    assert not second.is_alive()
    release.set()
    first.join(2.0)
    assert not first.is_alive()
    assert sum(isinstance(item, dict) for item in outcomes) == 1
    assert sum(isinstance(item, CredentialBrokerError) for item in outcomes) == 1
    assert "already been claimed" in str(next(item for item in outcomes if isinstance(item, CredentialBrokerError)))


def test_provider_environment_schema_rejects_host_mutation_keys() -> None:
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")
    broker.register(scope, lambda: {"PATH": "/tmp/attacker", "GH_TOKEN": "secret"})
    lease = broker.issue(
        scope,
        binding="github:owner/repo",
        operation="github_read_issue",
    )
    with pytest.raises(CredentialBrokerError, match="outside its schema"):
        broker.materialize(
            lease,
            binding="github:owner/repo",
            operation="github_read_issue",
        )
    assert broker.terminal_postcondition()


def test_unknown_provider_requires_explicit_environment_schema() -> None:
    broker = CredentialBroker()
    scope = CredentialScope(
        provider="vault",
        names=frozenset({"token"}),
        operations=frozenset({"read"}),
    )
    with pytest.raises(CredentialBrokerError, match="schema is required"):
        broker.register(scope, lambda: {"VAULT_TOKEN": "secret"})
    broker.register(
        scope,
        lambda: {"VAULT_TOKEN": "secret"},
        allowed_environment_keys={"VAULT_TOKEN"},
        max_entries=1,
    )
    lease = broker.issue(scope, binding="vault:token", operation="read")
    assert broker.materialize(lease, binding="vault:token", operation="read") == {
        "VAULT_TOKEN": "secret"
    }


def test_environment_schema_rejects_string_key_iterables_and_invalid_limits() -> None:
    broker = CredentialBroker()
    scope = CredentialScope(
        provider="custom",
        names=frozenset({"token"}),
        operations=frozenset({"read"}),
    )
    with pytest.raises(CredentialBrokerError, match="iterable of names"):
        broker.register(
            scope,
            lambda: {"CUSTOM_TOKEN": "secret"},
            allowed_environment_keys="CUSTOM_TOKEN",
        )
    with pytest.raises(CredentialBrokerError, match="limits must be integers"):
        CredentialEnvironmentSchema(frozenset({"CUSTOM_TOKEN"}), "1")


def test_provider_rejects_unencodable_unicode_environment_value() -> None:
    broker = CredentialBroker()
    scope = CredentialScope(
        provider="custom",
        names=frozenset({"token"}),
        operations=frozenset({"read"}),
    )
    broker.register(
        scope,
        lambda: {"CUSTOM_TOKEN": "bad\ud800"},
        allowed_environment_keys={"CUSTOM_TOKEN"},
    )
    lease = broker.issue(scope, binding="target", operation="read")
    with pytest.raises(CredentialBrokerError, match="invalid environment text"):
        broker.materialize(lease, binding="target", operation="read")


async def test_materialize_async_keeps_event_loop_responsive_while_provider_blocks() -> None:
    entered = threading.Event()
    release = threading.Event()
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(5.0)
        return {"GH_TOKEN": "secret"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )
    heartbeats = 0

    async def heartbeat() -> None:
        nonlocal heartbeats
        while True:
            heartbeats += 1
            await asyncio.sleep(0)

    ticker = asyncio.ensure_future(heartbeat())
    material = asyncio.ensure_future(
        broker.materialize_async(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
    )
    try:
        assert await asyncio.to_thread(entered.wait, 2.0)
        for _ in range(100):
            if heartbeats >= 10:
                break
            await asyncio.sleep(0.01)
        assert heartbeats >= 10
        release.set()
        environment = await material
        assert environment == {"GH_TOKEN": "secret"}
    finally:
        release.set()
        ticker.cancel()
    assert broker.terminal_postcondition()


async def test_cancel_materialize_async_while_provider_blocked_returns_no_secret() -> None:
    entered = threading.Event()
    release = threading.Event()
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(5.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )
    material = asyncio.ensure_future(
        broker.materialize_async(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
    )
    assert await asyncio.to_thread(entered.wait, 2.0)
    material.cancel()
    with pytest.raises(asyncio.CancelledError):
        await material
    # The caller vanished, but the transaction stays owned until the
    # provider worker settles; the secret is discarded, never returned.
    assert any(
        item.startswith("credential-materialization:")
        for item in broker.owned_resources()
    )
    assert not broker.terminal_postcondition()
    release.set()
    assert await _await_terminal(broker)


async def test_revoke_while_async_provider_blocked_returns_no_secret() -> None:
    entered = threading.Event()
    release = threading.Event()
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(5.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )
    material = asyncio.ensure_future(
        broker.materialize_async(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
    )
    assert await asyncio.to_thread(entered.wait, 2.0)
    broker.revoke(lease)
    release.set()
    with pytest.raises(CredentialBrokerError, match="revoked"):
        await material
    assert broker.terminal_postcondition()


async def test_close_while_async_provider_blocked_never_claims_false_closed() -> None:
    entered = threading.Event()
    release = threading.Event()
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(5.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )
    material = asyncio.ensure_future(
        broker.materialize_async(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
    )
    assert await asyncio.to_thread(entered.wait, 2.0)
    broker.close()
    assert broker.generation_admission_closed
    assert broker.is_quarantined
    assert not broker.terminal_closed
    release.set()
    with pytest.raises(CredentialBrokerError):
        await material
    assert broker.terminal_closed
    assert not broker.is_quarantined


async def test_materialize_async_timeout_fails_closed_and_settles_without_zombie() -> None:
    entered = threading.Event()
    release = threading.Event()
    broker = CredentialBroker()
    scope = _github_scope("github_read_issue")

    def loader() -> dict[str, str]:
        entered.set()
        assert release.wait(5.0)
        return {"GH_TOKEN": "must-not-return"}

    broker.register(scope, loader)
    lease = broker.issue(
        scope,
        binding={"host": "github.com", "repository": "owner/repo"},
        operation="github_read_issue",
    )
    material = asyncio.ensure_future(
        broker.materialize_async(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
            timeout=0.05,
        )
    )
    assert await asyncio.to_thread(entered.wait, 2.0)
    with pytest.raises(CredentialBrokerError, match="timed out"):
        await material
    # Timed out but still owned: never an anonymous zombie transaction.
    assert any(
        item.startswith("credential-materialization:")
        for item in broker.owned_resources()
    )
    assert not broker.terminal_postcondition()
    release.set()
    assert await _await_terminal(broker)
    with pytest.raises(CredentialBrokerError, match="unknown or revoked"):
        broker.materialize(
            lease,
            binding={"host": "github.com", "repository": "owner/repo"},
            operation="github_read_issue",
        )
