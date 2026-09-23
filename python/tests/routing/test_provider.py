from khaos.routing.provider import (
    ProviderConfig,
    ProviderManager,
    provider_capabilities,
)


def test_provider_wire_capability_profile_is_provider_scoped():
    assert provider_capabilities("siliconflow").supports_multiple_system_messages is False
    assert provider_capabilities("nvidia").supports_multiple_system_messages is True

    assert ProviderConfig("siliconflow", "https://example.test/v1").supports_multiple_system_messages is False
    assert ProviderConfig("nvidia", "https://example.test/v1").supports_multiple_system_messages is True

    manager = ProviderManager()
    manager.register_provider(ProviderConfig("siliconflow", "https://example.test/v1"))
    assert manager.get_provider("siliconflow").supports_multiple_system_messages is False
