from khaos.channels import ChannelRegistry, ChannelStatus, ChannelType


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
