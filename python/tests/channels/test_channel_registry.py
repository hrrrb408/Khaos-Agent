import pytest
from khaos.channels import ChannelConfig, ChannelRegistry, ChannelStatus, ChannelType


def test_registry_lifecycle_and_health():
    registry = ChannelRegistry(max_consecutive_failures=2)
    channel = registry.register("tg", ChannelType.TELEGRAM)
    assert registry.get("tg") == channel
    assert registry.get_by_type(ChannelType.TELEGRAM) == [channel]
    registry.record_failure("tg", "one")
    assert registry.get("tg").health.status == ChannelStatus.DEGRADED
    registry.record_failure("tg", "two")
    assert registry.get("tg").health.status == ChannelStatus.ERROR
    registry.record_success("tg", received=True)
    current = registry.get("tg")
    assert current.health.total_received == 1
    assert current.health.consecutive_failures == 0
    assert registry.disable("tg") and not registry.get("tg").is_enabled
    assert registry.list_all(enabled_only=True) == []
    assert registry.enable("tg")
    assert registry.get_health_report()[0]["healthy"]
    assert registry.unregister("tg")
    assert not registry.unregister("missing")


def test_generic_webhook_requires_high_entropy_secret_to_register_or_enable():
    registry = ChannelRegistry()
    with pytest.raises(ValueError, match="at least 32"):
        registry.register("generic", ChannelType.WEBHOOK_IN)
    registry.register(
        "generic",
        ChannelType.WEBHOOK_IN,
        ChannelConfig(
            ChannelType.WEBHOOK_IN,
            enabled=False,
            secret="0123456789abcdef0123456789abcdef",
        ),
    )
    registry.replace_config(
        "generic",
        ChannelConfig(
            ChannelType.WEBHOOK_IN,
            enabled=False,
            secret="0123456789abcdef0123456789abcdef",
        ),
    )
    with pytest.raises(ValueError, match="at least 32"):
        registry.replace_config(
            "generic",
            ChannelConfig(ChannelType.WEBHOOK_IN, enabled=True, secret=""),
        )


def test_enabled_platform_secret_cannot_bind_multiple_channels():
    registry = ChannelRegistry()
    registry.register(
        "slack-primary",
        ChannelType.SLACK,
        ChannelConfig(ChannelType.SLACK, secret="shared-signing-secret"),
    )
    with pytest.raises(ValueError, match="only one channel"):
        registry.register(
            "slack-secondary",
            ChannelType.SLACK,
            ChannelConfig(ChannelType.SLACK, secret="shared-signing-secret"),
        )

    disabled = registry.register(
        "slack-disabled",
        ChannelType.SLACK,
        ChannelConfig(
            ChannelType.SLACK,
            enabled=False,
            secret="shared-signing-secret",
        ),
    )
    assert disabled.is_enabled is False
    with pytest.raises(ValueError, match="only one channel"):
        registry.enable("slack-disabled")

    registry.register(
        "telegram-primary",
        ChannelType.TELEGRAM,
        ChannelConfig(ChannelType.TELEGRAM, secret="shared-signing-secret"),
    )
