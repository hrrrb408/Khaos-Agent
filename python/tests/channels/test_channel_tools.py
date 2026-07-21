"""Tests for ``khaos.tools.channel_tools``.

M4 batch 3.1.16A-4-4-3: the module-global ``_registry`` holder and the
``set_channel_registry`` setter have been removed.  Every handler now
receives ``principal_id`` and ``channel_registry`` as keyword arguments
(injected by the broker in production via the ``channel.read`` /
``channel.manage`` capabilities).  Mutation handlers additionally
receive ``channel_admins`` (the admin principal allowlist compiled into
the EffectiveSecurityPolicy) and fail-closed via ``_require_admin``.

These tests pass them directly to mimic the broker injection.
"""

from __future__ import annotations

import asyncio

import pytest

import khaos.tools.channel_tools as channel_tools
from khaos.channels import ChannelRegistry, ChannelType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _registry_with_main() -> ChannelRegistry:
    registry = ChannelRegistry()
    registry.register("main", ChannelType.SLACK)
    return registry


# ---------------------------------------------------------------------------
# Happy path — kwargs injected (mirrors broker injection in production)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_list_returns_registered_channels() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_list(
        principal_id="api:alice", channel_registry=registry,
    )
    assert isinstance(result["channels"], list)
    assert len(result["channels"]) >= 1
    assert result["channels"][0]["id"] == "main"
    assert result["channels"][0]["type"] == "slack"


@pytest.mark.asyncio
async def test_channel_health_returns_report() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_health(
        principal_id="api:alice", channel_registry=registry,
    )
    assert "report" in result


@pytest.mark.asyncio
async def test_channel_enable_succeeds_for_admin() -> None:
    registry = _registry_with_main()
    # First disable so enable has an effect.
    registry.disable("main")
    result = await channel_tools.channel_enable(
        "main",
        principal_id="api:alice",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "enabled"
    assert result["channel_id"] == "main"


@pytest.mark.asyncio
async def test_channel_disable_succeeds_for_admin() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_disable(
        "main",
        principal_id="api:alice",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "disabled"
    assert result["channel_id"] == "main"


# ---------------------------------------------------------------------------
# Admin gate — fail-closed for non-admin principals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_enable_rejects_non_admin() -> None:
    """Bob is not in the admin allowlist — must be forbidden."""
    registry = _registry_with_main()
    result = await channel_tools.channel_enable(
        "main",
        principal_id="api:bob",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "forbidden"
    assert "not a channel admin" in result["error"]
    assert result["channel_id"] == "main"


@pytest.mark.asyncio
async def test_channel_disable_rejects_non_admin() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_disable(
        "main",
        principal_id="api:bob",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "forbidden"
    assert "not a channel admin" in result["error"]


@pytest.mark.asyncio
async def test_channel_enable_rejects_empty_admin_list() -> None:
    """Default ``channels.admin_principals: []`` means NO principal can
    mutate channels via the tool path — fail-closed until an admin is
    explicitly declared."""
    registry = _registry_with_main()
    result = await channel_tools.channel_enable(
        "main",
        principal_id="api:alice",
        channel_registry=registry,
        channel_admins=frozenset(),  # default
    )
    assert result["status"] == "forbidden"


@pytest.mark.asyncio
async def test_channel_disable_rejects_none_admin_list() -> None:
    """A misconfigured tool context (``channel_admins=None``) must not
    fall open — same fail-closed semantics as an empty list."""
    registry = _registry_with_main()
    result = await channel_tools.channel_disable(
        "main",
        principal_id="api:alice",
        channel_registry=registry,
        channel_admins=None,
    )
    assert result["status"] == "forbidden"


# ---------------------------------------------------------------------------
# Fail-closed — missing principal_id / missing registry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_channel_list_rejects_empty_principal_id() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_list(
        principal_id="", channel_registry=registry,
    )
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


@pytest.mark.asyncio
async def test_channel_health_rejects_empty_principal_id() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_health(
        principal_id="", channel_registry=registry,
    )
    assert result["status"] == "unavailable"


@pytest.mark.asyncio
async def test_channel_enable_rejects_empty_principal_id() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_enable(
        "main",
        principal_id="",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "unavailable"
    assert "principal_id is required" in result["error"]


@pytest.mark.asyncio
async def test_channel_disable_rejects_empty_principal_id() -> None:
    registry = _registry_with_main()
    result = await channel_tools.channel_disable(
        "main",
        principal_id="",
        channel_registry=registry,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "unavailable"


@pytest.mark.asyncio
async def test_channel_list_reports_unavailable_when_registry_missing() -> None:
    result = await channel_tools.channel_list(
        principal_id="api:alice", channel_registry=None,
    )
    assert result["status"] == "unavailable"
    assert "channel registry not configured" in result["error"]


@pytest.mark.asyncio
async def test_channel_enable_reports_unavailable_when_registry_missing() -> None:
    """Even an admin cannot mutate a channel when the tool context is
    misconfigured (no registry injected) — fail-closed gracefully."""
    result = await channel_tools.channel_enable(
        "main",
        principal_id="api:alice",
        channel_registry=None,
        channel_admins=frozenset({"api:alice"}),
    )
    assert result["status"] == "unavailable"
    assert "channel registry not configured" in result["error"]


# ---------------------------------------------------------------------------
# Module-global holder removal
# ---------------------------------------------------------------------------


def test_set_channel_registry_removed():
    """The setter function has been deleted — callers can no longer
    install a module-global ChannelRegistry (the source of the cross-
    principal mutation risk)."""
    assert not hasattr(channel_tools, "set_channel_registry")


def test_channel_registry_holder_removed():
    assert not hasattr(channel_tools, "_registry")


# ---------------------------------------------------------------------------
# CHANNEL_TOOLS spec list retained for backward compat
# ---------------------------------------------------------------------------


def test_channel_tools_spec_list_has_four_tools():
    """``CHANNEL_TOOLS`` is kept as a declarative spec list so legacy
    callers (e.g. agents that introspect available tools) keep working."""
    assert len(channel_tools.CHANNEL_TOOLS) == 4
    names = {spec["name"] for spec in channel_tools.CHANNEL_TOOLS}
    assert names == {
        "channel_list", "channel_health",
        "channel_enable", "channel_disable",
    }
