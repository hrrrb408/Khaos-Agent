"""Structural tests for the channel registry owner and reader snapshots."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from types import MappingProxyType

import pytest
from khaos.channels import (
    ChannelConfig,
    ChannelRegistry,
    ChannelStatus,
    ChannelType,
    RegisteredChannelSnapshot,
)


def test_registry_reads_are_immutable_snapshots() -> None:
    registry = ChannelRegistry()
    config = ChannelConfig(
        ChannelType.SLACK,
        extra={"region": "cn"},
    )
    initial = registry.register("slack", ChannelType.SLACK, config)

    assert isinstance(initial, RegisteredChannelSnapshot)
    assert isinstance(initial.config.extra, MappingProxyType)
    with pytest.raises(FrozenInstanceError):
        initial.config = initial.config  # type: ignore[misc]
    with pytest.raises(TypeError):
        initial.config.extra["region"] = "us"  # type: ignore[index]

    config.extra["region"] = "us"
    registry.record_failure("slack", "temporary")
    current = registry.get("slack")
    assert current is not None
    assert current.config.extra["region"] == "cn"
    assert initial.health.status == ChannelStatus.ENABLED
    assert current.health.status == ChannelStatus.DEGRADED


def test_registry_configuration_replacement_is_validated() -> None:
    registry = ChannelRegistry()
    registry.register("slack", ChannelType.SLACK)

    with pytest.raises(ValueError, match="channel config type"):
        registry.replace_config(
            "slack",
            ChannelConfig(ChannelType.TELEGRAM),
        )
    assert registry.replace_config("missing", ChannelConfig(ChannelType.SLACK)) is None
