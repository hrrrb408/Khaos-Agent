import pytest

from khaos.config import ConfigError, expand_config_placeholders, expand_env_placeholders


def test_expand_env_placeholders_supports_nested_paths(monkeypatch):
    monkeypatch.setenv("KHAOS_HOME", "/tmp/khaos")

    assert expand_env_placeholders("${KHAOS_HOME}/config.yaml") == "/tmp/khaos/config.yaml"


def test_expand_env_placeholders_leaves_plain_strings_unchanged():
    assert expand_env_placeholders("literal-api-key") == "literal-api-key"


def test_expand_env_placeholders_raises_clear_error_for_missing_env(monkeypatch):
    monkeypatch.delenv("MISSING_KHAOS_KEY", raising=False)

    with pytest.raises(ConfigError, match="MISSING_KHAOS_KEY"):
        expand_env_placeholders("${MISSING_KHAOS_KEY}", source="models.providers.nvidia.api_key")


def test_expand_config_placeholders_recurses(monkeypatch):
    monkeypatch.setenv("KHAOS_HOME", "/tmp/khaos")

    config = expand_config_placeholders({"path": "${KHAOS_HOME}/config.yaml"})

    assert config["path"] == "/tmp/khaos/config.yaml"
