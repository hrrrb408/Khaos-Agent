"""M5.5 Batch B — contained credential providers are physically killable.

A provider classified as blocking/untrusted executes as validated data in
a dedicated child process.  These tests prove the closure conditions:

* a hung provider is reclaimed by TERM → grace → KILL → wait within a
  bounded wall clock, without exiting the trusted process;
* broker ``close()`` actively terminates hung hosts instead of waiting
  out their materialization deadline;
* ``terminal_closed`` / ``owned_resources`` never lie about a live host;
* worker material still passes the parent-side environment schema;
* caller cancellation discards the result and settles bounded.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time

import pytest

from khaos.security.credential_broker import (
    CredentialBroker,
    CredentialBrokerError,
)
from khaos.security.credential_provider_host import (
    CredentialProviderHost,
    CredentialProviderHostError,
)
from khaos.security.credential_provider_worker import (
    ProviderSpecError,
    validate_provider_spec,
)
from khaos.security.resource_scope import CredentialScope

pytestmark = pytest.mark.posix_host


def _scope(name: str = "ssh-agent") -> CredentialScope:
    return CredentialScope(
        provider="git",
        names=frozenset({name}),
        operations=frozenset({"git_push"}),
    )


async def _await_terminal(broker: CredentialBroker, timeout: float = 10.0) -> bool:
    """Poll until every owned transaction and host has provably settled."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if broker.terminal_postcondition() and broker.owned_resources() == ():
            return True
        await asyncio.sleep(0.05)
    return False


# ─── Spec validation ──────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "spec",
    [
        {"type": "unknown"},
        {"type": "constant"},
        {"type": "constant", "environment": {}},
        {"type": "constant", "environment": {"NOT A KEY": "v"}},
        {"type": "env", "variables": {}},
        {"type": "env", "variables": {"OUT": "bad name"}},
        {"type": "command", "argv": []},
        {"type": "command", "argv": ["sh", "-c", "x"], "timeout_seconds": 0},
        {"type": "sleep", "seconds": -1},
        {"no-type": True},
    ],
)
def test_invalid_specs_are_rejected_at_registration(spec):
    with pytest.raises(ProviderSpecError):
        validate_provider_spec(spec)
    broker = CredentialBroker()
    with pytest.raises(CredentialBrokerError, match="spec is invalid"):
        broker.register_hosted(_scope(), spec)


def test_non_json_spec_is_rejected():
    with pytest.raises(ProviderSpecError):
        validate_provider_spec({"type": "constant", "environment": {"A": object()}})


# ─── Host: happy paths ────────────────────────────────────────────────────


async def test_host_materializes_constant_spec():
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/tmp/agent.sock"}},
        deadline=15.0,
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/agent.sock"}
    assert not host.alive


async def test_host_materializes_env_spec_with_passthrough(monkeypatch):
    monkeypatch.setenv("KHAOS_TEST_AGENT_SOCK", "/tmp/passthrough.sock")
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "env", "variables": {"SSH_AUTH_SOCK": "KHAOS_TEST_AGENT_SOCK"}},
        deadline=15.0,
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/passthrough.sock"}


async def test_host_env_spec_missing_variable_fails_closed():
    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="missing"):
        await host.materialize(
            {"type": "env", "variables": {"SSH_AUTH_SOCK": "KHAOS_ABSENT_VAR"}},
            deadline=15.0,
        )
    assert not host.alive


async def test_host_materializes_command_spec():
    helper = (
        "import json; print(json.dumps({'GIT_ASKPASS': '/bin/true'}))"
    )
    host = CredentialProviderHost()
    environment = await host.materialize(
        {"type": "command", "argv": [sys.executable, "-c", helper]},
        deadline=20.0,
    )
    assert environment == {"GIT_ASKPASS": "/bin/true"}


async def test_host_command_failure_fails_closed():
    host = CredentialProviderHost()
    with pytest.raises(CredentialProviderHostError, match="status"):
        await host.materialize(
            {"type": "command", "argv": [sys.executable, "-c", "import sys; sys.exit(3)"]},
            deadline=20.0,
        )
    assert not host.alive


# ─── Host: killability ────────────────────────────────────────────────────


async def test_hung_provider_deadline_terminates_child_bounded():
    host = CredentialProviderHost(termination_grace=0.5, kill_grace=2.0)
    started = time.monotonic()
    with pytest.raises(CredentialProviderHostError, match="deadline"):
        await host.materialize({"type": "sleep", "seconds": 3600}, deadline=0.5)
    elapsed = time.monotonic() - started

    assert not host.alive
    # TERM (or KILL) plus wait must stay far below the provider's hang time.
    assert elapsed < 10.0


async def test_host_signals_do_not_kill_wrong_process_after_settlement():
    host = CredentialProviderHost()
    await host.materialize(
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/x"}}, deadline=15.0
    )
    # Repeated late termination requests against a reaped host are no-ops.
    host.request_termination()
    host.request_termination()
    assert not host.alive


# ─── Broker integration ───────────────────────────────────────────────────


async def test_broker_materializes_hosted_provider_and_settles():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/tmp/agent.sock"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    environment = await broker.materialize_async(
        lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    assert environment == {"SSH_AUTH_SOCK": "/tmp/agent.sock"}
    assert broker.owned_resources() == ()
    broker.close()
    assert broker.terminal_closed


async def test_broker_hung_hosted_provider_is_killed_and_close_is_terminal():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=0.5,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    started = time.monotonic()
    with pytest.raises(CredentialBrokerError, match="deadline"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    assert time.monotonic() - started < 10.0

    broker.close()
    assert await _await_terminal(broker)
    assert broker.owned_resources() == ()


async def test_broker_close_terminates_hung_host_without_waiting_deadline():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=120.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    materialization = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    # Let the hosted child start, then close: SIGTERM must reclaim it long
    # before the 120 s materialization deadline would have elapsed.
    await asyncio.sleep(0.3)
    assert any(
        resource.startswith("credential-provider-host:")
        for resource in broker.owned_resources()
    )
    started = time.monotonic()
    broker.close()
    done, _pending = await asyncio.wait(
        [materialization], timeout=15.0, return_when=asyncio.FIRST_EXCEPTION
    )
    assert done, "hosted materialization did not settle after close"
    assert time.monotonic() - started < 15.0
    assert await _await_terminal(broker)


async def test_broker_hung_host_cancellation_discards_result_bounded():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 3600},
        deadline_seconds=0.5,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    task = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    await asyncio.sleep(0.1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # Cancellation never destroys ownership: the transaction stays owned
    # until the (killed) provider settles, then the broker reaches a true
    # terminal state without process exit.
    assert await _await_terminal(broker)
    with pytest.raises(CredentialBrokerError):
        # The one-shot lease was consumed by the canceled transaction.
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )


async def test_broker_enforces_schema_on_hosted_material():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        # ssh-agent schema allows only SSH_AUTH_SOCK.
        {"type": "constant", "environment": {"GIT_ASKPASS": "/evil/helper"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="outside its schema"):
        await broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    assert broker.owned_resources() == ()


async def test_hosted_provider_requires_async_materialization():
    broker = CredentialBroker()
    broker.register_hosted(
        _scope(),
        {"type": "constant", "environment": {"SSH_AUTH_SOCK": "/x"}},
        deadline_seconds=15.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="materialize_async"):
        broker.materialize(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )


async def test_hosted_provider_admission_is_bounded():
    broker = CredentialBroker(max_provider_workers=1, max_pending_providers=0)
    broker.register_hosted(
        _scope(),
        {"type": "sleep", "seconds": 2},
        allowed_environment_keys={"PROVIDER_SLEPT"},
        deadline_seconds=10.0,
    )
    lease = broker.issue(
        _scope(), binding={"remote_url": "git@host:repo"}, operation="git_push"
    )
    first = asyncio.ensure_future(
        broker.materialize_async(
            lease, binding={"remote_url": "git@host:repo"}, operation="git_push"
        )
    )
    await asyncio.sleep(0.3)
    second_lease = broker.issue(
        _scope(), binding={"remote_url": "git@other:repo"}, operation="git_push"
    )
    with pytest.raises(CredentialBrokerError, match="admission is full"):
        await broker.materialize_async(
            second_lease,
            binding={"remote_url": "git@other:repo"},
            operation="git_push",
        )
    await asyncio.wait_for(first, timeout=20.0)
