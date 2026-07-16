import pytest

from khaos.channels import ChannelConfig, ChannelRegistry, ChannelStatus, ChannelType


def test_registry_lifecycle_and_health():
    registry = ChannelRegistry(max_consecutive_failures=2)
    channel = registry.register("tg", ChannelType.TELEGRAM)
    assert registry.get("tg") is channel
    assert registry.get_by_type(ChannelType.TELEGRAM) == [channel]
    registry.record_failure("tg", "one")
    assert channel.health.status == ChannelStatus.DEGRADED
    registry.record_failure("tg", "two")
    assert channel.health.status == ChannelStatus.ERROR
    registry.record_success("tg", received=True)
    assert channel.health.total_received == 1
    assert channel.health.consecutive_failures == 0
    assert registry.disable("tg") and not channel.is_enabled
    assert registry.list_all(enabled_only=True) == []
    assert registry.enable("tg")
    assert registry.get_health_report()[0]["healthy"]
    assert registry.unregister("tg")
    assert not registry.unregister("missing")


def test_generic_webhook_requires_high_entropy_secret_to_register_or_enable():
    registry = ChannelRegistry()
    with pytest.raises(ValueError, match="at least 32"):
        registry.register("generic", ChannelType.WEBHOOK_IN)
    channel = registry.register(
        "generic",
        ChannelType.WEBHOOK_IN,
        ChannelConfig(
            ChannelType.WEBHOOK_IN,
            enabled=False,
            secret="0123456789abcdef0123456789abcdef",
        ),
    )
    channel.config.secret = ""
    with pytest.raises(ValueError, match="at least 32"):
        registry.enable("generic")
