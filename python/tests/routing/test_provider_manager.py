import pytest
from khaos.config import ConfigError
from khaos.routing import ModelSpec, ProviderConfig, ProviderManager
from khaos.security.credentials import CredentialRef


def test_provider_expands_endpoint_without_accepting_secret_material(monkeypatch):
    monkeypatch.setenv("KHAOS_TEST_ENDPOINT", "https://api.example/v1")
    manager = ProviderManager()

    manager.register_provider(
        ProviderConfig(
            name="openai",
            base_url="${KHAOS_TEST_ENDPOINT}",
            credential_ref=CredentialRef.for_provider("openai", "test"),
        )
    )

    assert manager.get_provider("openai").base_url == "https://api.example/v1"
    assert manager.get_provider("openai").credential_ref == CredentialRef.for_provider("openai", "test")


def test_provider_missing_env_endpoint_raises(monkeypatch):
    monkeypatch.delenv("KHAOS_MISSING_ENDPOINT", raising=False)
    manager = ProviderManager()

    with pytest.raises(ConfigError, match="KHAOS_MISSING_ENDPOINT"):
        manager.register_provider(
            ProviderConfig(
                name="openai",
                base_url="${KHAOS_MISSING_ENDPOINT}",
                credential_ref=CredentialRef.for_provider("openai", "test"),
            )
        )


def test_register_model_requires_provider():
    manager = ProviderManager()

    with pytest.raises(KeyError):
        manager.register_model("m1", ModelSpec("missing", "model", 1000))


def test_register_and_get_model():
    manager = ProviderManager()
    manager.register_provider(ProviderConfig("local", "http://localhost"))
    manager.register_model("local-fast", ModelSpec("local", "fast", 4096))

    assert manager.get_model("local-fast").model == "fast"


def test_from_config_builds_secretless_providers_and_models():
    manager = ProviderManager.from_config(
        {
            "providers": {
                "local": {
                    "base_url": "http://localhost",
                    "credential_ref": "khaos/providers/local/test",
                    "rpm_limit": 60,
                }
            },
            "models": {
                "chat": {
                    "provider": "local",
                    "model": "chat-1",
                    "max_context_tokens": 8192,
                    "max_output_tokens": 2048,
                    "supports_tools": True,
                }
            },
        }
    )

    assert manager.get_provider("local").credential_ref == CredentialRef.for_provider("local", "test")
    assert manager.get_model("chat").max_context_tokens == 8192
    assert manager.get_model("chat").max_output_tokens == 2048


def test_from_config_gives_zhipu_coding_reasoning_models_a_bounded_default_output_budget():
    manager = ProviderManager.from_config(
        {
            "providers": {
                "zhipu-coding": {
                    "base_url": "https://example.test/v1",
                    "credential_ref": "khaos/providers/zhipu-coding/test",
                }
            },
            "models": {
                "glm-5.3-flash": {
                    "provider": "zhipu-coding",
                    "model": "glm-5.3-flash",
                    "max_context_tokens": 128000,
                }
            },
        }
    )

    assert manager.get_model("glm-5.3-flash").max_output_tokens == 32768
    assert manager.get_provider("zhipu-coding").timeout == 300


def test_missing_provider_and_model_raise():
    manager = ProviderManager()

    with pytest.raises(KeyError):
        manager.get_provider("missing")
    with pytest.raises(KeyError):
        manager.get_model("missing")
