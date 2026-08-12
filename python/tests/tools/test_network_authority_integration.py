from __future__ import annotations

from types import SimpleNamespace

import pytest
from khaos.coding.execution.models import NetworkPolicy
from khaos.tools.registry import ToolCapability
from khaos.tools.scheduler import ToolScheduler, _authority_profile


class _FakeLease:
    identity_digest = "lease-identity"


class _FakeBroker:
    def __init__(self) -> None:
        self.closed = False

    async def close(self) -> None:
        self.closed = True


class _FakeNetworkBrokerFactory:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.broker = _FakeBroker()
        self.lease = _FakeLease()

    async def start(self, **kwargs: object):
        self.calls.append(kwargs)
        return self.broker, self.lease


class _FakePermissionEngine:
    async def authorization_snapshot(self) -> int:
        return 17


@pytest.mark.asyncio
async def test_scheduler_binds_managed_network_lease_before_step_authority(
    tmp_path,
):
    scheduler = object.__new__(ToolScheduler)
    scheduler.network_broker_factory = _FakeNetworkBrokerFactory()
    scheduler.permission_engine = _FakePermissionEngine()
    scheduler.runtime_id = "runtime"
    scheduler._network_brokers = set()

    tool = SimpleNamespace(
        name="terminal_argv",
        execution_kind="host-sandbox",
        capabilities=(
            ToolCapability(
                "process.execute",
                frozenset({"coding"}),
                frozenset({"task-workspace"}),
            ),
        ),
    )
    call: dict[str, object] = {"id": "call-1", "arguments": {"argv": ["printf", "ok"]}}
    context = {
        "network_guard": SimpleNamespace(
            network_enabled=True,
            allowed_domains=frozenset({"example.com"}),
            blocked_domains=frozenset({"blocked.example"}),
        ),
        "principal_id": "principal",
        "project_id": "project",
        "runtime_id": "runtime",
        "task_id": "task",
        "workspace_id": "workspace",
        "workspace_generation": 3,
        "effective_policy_digest": "policy",
    }

    await scheduler._prepare_network_authority_inputs(
        tool=tool,
        call=call,
        tool_context=context,
    )

    factory = scheduler.network_broker_factory
    assert len(factory.calls) == 1
    assert factory.calls[0]["authorization_epoch"] == 17
    assert factory.calls[0]["workspace_generation"] == 3
    assert factory.calls[0]["allowed_domains"] == frozenset({"example.com"})
    assert call["_network_lease"] is factory.lease
    assert factory.broker in scheduler._network_brokers

    profile = _authority_profile(
        tool=tool,
        arguments=call["arguments"],
        tool_context={
            "workspace_root": tmp_path,
            "network_policy": NetworkPolicy.UNRESTRICTED_WITH_APPROVAL.value,
        },
        environment_keys=("PATH",),
        network_lease=call["_network_lease"],
    )
    assert profile is not None
    assert profile.network is NetworkPolicy.BROKERED
    assert profile.network_broker is factory.lease

    await scheduler._close_network_broker(call)
    assert factory.broker.closed is True
    assert factory.broker not in scheduler._network_brokers
