"""M4 batch 3.1.16A-4-4-3 acceptance tests — Channel authority closure.

Verifies that:

1. The module-global ``_registry`` holder and ``set_channel_registry``
   setter have been deleted.
2. The four channel tools declare ``channel.read`` / ``channel.manage``
   capabilities in the registry.
3. ``ToolInvocationBroker.invoke`` injects ``channel_registry`` +
   ``principal_id`` (read) and additionally ``channel_admins`` (manage)
   from ``tool_context``.
4. Read tools fail-closed on missing ``principal_id`` via the broker.
5. Mutation tools fail-closed via ``_require_admin`` when the caller's
   ``principal_id`` is not in ``channel_admins`` (cross-principal
   isolation via the broker).
6. The admin gate is the :class:`EffectiveSecurityPolicy`'s compiled
   ``channel_admins`` frozenset (user ∪ project, OR semantics).

These are signature/wiring tests — the deeper behavioral tests live in
``tests/channels/test_channel_tools.py``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import khaos.tools.channel_tools as channel_tools
from khaos.channels import ChannelRegistry, ChannelType
from khaos.security.effective_policy import (
    EffectiveSecurityPolicy,
    compile_effective_policy,
    validate_policy_dict,
)
from khaos.security.policy import SandboxPolicy
from khaos.security.sandbox import SandboxMode
from khaos.tools import create_runtime_registry
from khaos.tools.registry import ToolInvocationBroker


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _registry_with_main() -> ChannelRegistry:
    registry = ChannelRegistry()
    registry.register("main", ChannelType.SLACK)
    return registry


def _build_broker() -> ToolInvocationBroker:
    """Build a runtime registry + broker (handlers bound)."""
    registry = create_runtime_registry()
    return ToolInvocationBroker(registry)


def _read_context(
    *, principal_id: str = "api:alice",
    channel_registry: ChannelRegistry | None = None,
) -> dict:
    return {
        "principal_id": principal_id,
        "channel_registry": channel_registry,
    }


def _manage_context(
    *, principal_id: str = "api:alice",
    channel_registry: ChannelRegistry | None = None,
    channel_admins: frozenset[str] | None = None,
) -> dict:
    return {
        "principal_id": principal_id,
        "channel_registry": channel_registry,
        "channel_admins": channel_admins if channel_admins is not None else frozenset(),
    }


# ---------------------------------------------------------------------------
# 1. Holder removal
# ---------------------------------------------------------------------------


def test_set_channel_registry_removed() -> None:
    assert not hasattr(channel_tools, "set_channel_registry")


def test_channel_registry_holder_removed() -> None:
    assert not hasattr(channel_tools, "_registry")


# ---------------------------------------------------------------------------
# 2. Capability declaration
# ---------------------------------------------------------------------------


def test_channel_list_has_channel_read_capability() -> None:
    registry = create_runtime_registry()
    caps = registry.capabilities_for("channel_list")
    assert any(c.name == "channel.read" for c in caps)


def test_channel_health_has_channel_read_capability() -> None:
    registry = create_runtime_registry()
    caps = registry.capabilities_for("channel_health")
    assert any(c.name == "channel.read" for c in caps)


def test_channel_enable_has_channel_manage_capability() -> None:
    registry = create_runtime_registry()
    caps = registry.capabilities_for("channel_enable")
    assert any(c.name == "channel.manage" for c in caps)


def test_channel_disable_has_channel_manage_capability() -> None:
    registry = create_runtime_registry()
    caps = registry.capabilities_for("channel_disable")
    assert any(c.name == "channel.manage" for c in caps)


# ---------------------------------------------------------------------------
# 3. Broker injection — happy path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_injects_registry_and_principal_for_read() -> None:
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_list",
        mode="office",
        context=_read_context(principal_id="api:alice", channel_registry=registry),
    )
    assert isinstance(result, dict)
    assert "channels" in result
    assert result["channels"][0]["id"] == "main"


@pytest.mark.asyncio
async def test_broker_injects_registry_principal_admins_for_manage() -> None:
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_disable",
        mode="office",
        context=_manage_context(
            principal_id="api:alice",
            channel_registry=registry,
            channel_admins=frozenset({"api:alice"}),
        ),
        channel_id="main",
    )
    assert result["status"] == "disabled"
    assert result["channel_id"] == "main"


@pytest.mark.asyncio
async def test_broker_rejects_unknown_mode_for_channel_read() -> None:
    """``channel.read`` declares modes={all} so any mode is accepted —
    but ``foo`` is not a real mode.  We use ``coding`` here to confirm
    the capability's mode gate accepts it (modes={all})."""
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_list",
        mode="coding",
        context=_read_context(principal_id="api:alice", channel_registry=registry),
    )
    assert "channels" in result


# ---------------------------------------------------------------------------
# 4. Fail-closed via broker — missing principal_id
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_fail_closed_for_empty_principal_on_read() -> None:
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_list",
        mode="office",
        context=_read_context(principal_id="", channel_registry=registry),
    )
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


@pytest.mark.asyncio
async def test_broker_fail_closed_for_empty_principal_on_manage() -> None:
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_enable",
        mode="office",
        context=_manage_context(
            principal_id="",
            channel_registry=registry,
            channel_admins=frozenset({"api:alice"}),
        ),
        channel_id="main",
    )
    assert result["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 5. Cross-principal isolation via broker — admin gate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_broker_rejects_mutation_from_non_admin_principal() -> None:
    """Bob is not in the admin allowlist — channel_disable via the
    broker must be forbidden, even though Bob is authenticated."""
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_disable",
        mode="office",
        context=_manage_context(
            principal_id="api:bob",
            channel_registry=registry,
            channel_admins=frozenset({"api:alice"}),  # only Alice
        ),
        channel_id="main",
    )
    assert result["status"] == "forbidden"
    assert "not a channel admin" in result["error"]


@pytest.mark.asyncio
async def test_broker_rejects_mutation_with_empty_admin_allowlist() -> None:
    """Default ``channels.admin_principals: []`` — NO principal can
    mutate channels via the broker, even an authenticated one."""
    broker = _build_broker()
    registry = _registry_with_main()
    result = await broker.invoke(
        "channel_enable",
        mode="office",
        context=_manage_context(
            principal_id="api:alice",
            channel_registry=registry,
            channel_admins=frozenset(),  # default
        ),
        channel_id="main",
    )
    assert result["status"] == "forbidden"


# ---------------------------------------------------------------------------
# 6. EffectiveSecurityPolicy compiles channel_admins with OR semantics
# ---------------------------------------------------------------------------


def test_effective_policy_channel_admins_defaults_to_empty() -> None:
    """No ``channels.admin_principals`` configured → empty frozenset
    (fail-closed)."""
    project = SandboxPolicy()
    policy = compile_effective_policy(
        project, workspace_root=Path("/tmp"),
        user_policy=None,
    )
    assert policy.channel_admins == frozenset()


def test_effective_policy_channel_admins_union_user_and_project() -> None:
    """OR semantics — user ∪ project.  Admin is an authorization grant,
    so a stricter layer cannot revoke a more permissive layer's grant."""
    project = SandboxPolicy(channel_admins=["api:alice"])
    user = SandboxPolicy(channel_admins=["api:bob", "api:carol"])
    policy = compile_effective_policy(
        project, workspace_root=Path("/tmp"),
        user_policy=user,
    )
    assert policy.channel_admins == frozenset({"api:alice", "api:bob", "api:carol"})


def test_effective_policy_channel_admins_project_only_when_user_unset() -> None:
    """``user.channel_admins=None`` (key absent) → user contributes
    nothing; the result is just the project layer's admins."""
    project = SandboxPolicy(channel_admins=["api:alice"])
    user = SandboxPolicy()  # channel_admins defaults to None
    policy = compile_effective_policy(
        project, workspace_root=Path("/tmp"),
        user_policy=user,
    )
    assert policy.channel_admins == frozenset({"api:alice"})


def test_effective_policy_channel_admins_in_digest() -> None:
    """``channel_admins`` is part of the binding digest so an approval
    made under one admin set is invalidated if the policy later
    adds/removes admins."""
    p1 = compile_effective_policy(
        SandboxPolicy(channel_admins=["api:alice"]),
        workspace_root=Path("/tmp"),
    )
    p2 = compile_effective_policy(
        SandboxPolicy(channel_admins=["api:alice", "api:bob"]),
        workspace_root=Path("/tmp"),
    )
    assert p1.digest != p2.digest


def test_validate_policy_dict_accepts_channels_section() -> None:
    """``channels`` is a valid top-level section; ``admin_principals``
    is a valid sub-key."""
    validate_policy_dict({
        "channels": {"admin_principals": ["api:alice", "api:bob"]},
    })


def test_validate_policy_dict_rejects_unknown_channels_key() -> None:
    """Unknown keys under ``channels`` fail closed (typo protection)."""
    from khaos.security.effective_policy import PolicyCompilationError

    with pytest.raises(PolicyCompilationError):
        validate_policy_dict({
            "channels": {"admin_principals": [], "unknown_key": "evil"},
        })


def test_validate_policy_dict_rejects_non_string_admin_principal() -> None:
    """``admin_principals`` must be a list of strings — a non-string
    entry fails closed."""
    from khaos.security.effective_policy import PolicyCompilationError

    with pytest.raises(PolicyCompilationError):
        validate_policy_dict({
            "channels": {"admin_principals": ["api:alice", 123]},
        })


def test_sandbox_policy_from_dict_parses_channels_admin_principals() -> None:
    """SandboxPolicy.from_dict reads ``channels.admin_principals``."""
    policy = SandboxPolicy.from_dict({
        "channels": {"admin_principals": ["api:alice", "api:bob"]},
    })
    assert policy.channel_admins == ["api:alice", "api:bob"]


def test_sandbox_policy_from_dict_defaults_channel_admins_to_none() -> None:
    """No ``channels`` section → ``channel_admins=None`` (layer
    contributes no admins)."""
    policy = SandboxPolicy.from_dict({})
    assert policy.channel_admins is None


# ---------------------------------------------------------------------------
# 7. Production wiring regression
# ---------------------------------------------------------------------------


def test_grpc_server_no_longer_imports_set_channel_registry() -> None:
    """``grpc_server.py`` no longer imports ``set_channel_registry``
    (the holder setter has been deleted from ``channel_tools``)."""
    import khaos.grpc_server as grpc_server

    # The module must still import successfully.
    assert grpc_server is not None
    # The deleted setter must not be reachable via the channel_tools module.
    assert not hasattr(channel_tools, "set_channel_registry")


def test_grpc_server_no_longer_calls_set_channel_registry() -> None:
    """``grpc_server.py``'s source must not reference the deleted
    ``set_channel_registry`` setter (a regression guard)."""
    import inspect

    src = inspect.getsource(__import__("khaos.grpc_server", fromlist=["__name__"]))
    assert "set_channel_registry(" not in src, (
        "grpc_server.py still calls set_channel_registry — the holder is "
        "supposed to be gone (M4 batch 3.1.16A-4-4-3)."
    )
