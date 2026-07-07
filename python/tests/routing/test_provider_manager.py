import os

import pytest

from khaos.routing import ModelSpec, ProviderConfig, ProviderManager


def test_provider_expands_env_api_key(monkeypatch):
    monkeypatch.setenv("KHAOS_TEST_KEY", "secret")
    manager = ProviderManager()

    manager.register_provider(
        ProviderConfig(name="openai", base_url="https://api.example", api_key="${KHAOS_TEST_KEY}")
    )

    assert manager.get_provider("openai").api_key == "secret"


def test_register_model_requires_provider():
    manager = ProviderManager()

    with pytest.raises(KeyError):
        manager.register_model("m1", ModelSpec("missing", "model", 1000))


def test_register_and_get_model():
    manager = ProviderManager()
    manager.register_provider(ProviderConfig("local", "http://localhost"))
    manager.register_model("local-fast", ModelSpec("local", "fast", 4096))

    assert manager.get_model("local-fast").model == "fast"


def test_from_config_builds_providers_and_models(monkeypatch):
    monkeypatch.setenv("LOCAL_KEY", "abc")
    manager = ProviderManager.from_config(
        {
            "providers": {
                "local": {"base_url": "http://localhost", "api_key": "${LOCAL_KEY}", "rpm_limit": 60}
            },
            "models": {
                "chat": {
                    "provider": "local",
                    "model": "chat-1",
                    "max_context_tokens": 8192,
                    "supports_tools": True,
                }
            },
        }
    )

    assert manager.get_provider("local").api_key == "abc"
    assert manager.get_model("chat").max_context_tokens == 8192


def test_missing_provider_and_model_raise():
    manager = ProviderManager()

    with pytest.raises(KeyError):
        manager.get_provider("missing")
    with pytest.raises(KeyError):
        manager.get_model("missing")

