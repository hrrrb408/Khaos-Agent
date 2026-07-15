import os

import pytest

import yaml

from khaos.config import (
    ConfigError,
    check_needs_setup,
    expand_config_placeholders,
    expand_env_placeholders,
    set_user_config_value,
)


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


def test_check_needs_setup_true(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    assert check_needs_setup() is True


def test_check_needs_setup_false(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    user_config = tmp_path / ".khaos" / "config.yaml"
    user_config.parent.mkdir()
    user_config.write_text(
        """
models:
  providers:
    nvidia:
      api_key: "valid-test-key-123"
""",
        encoding="utf-8",
    )

    assert check_needs_setup() is False


def test_set_user_config_value(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = set_user_config_value("models.default_model", "test-model")

    data = yaml.safe_load(target.read_text(encoding="utf-8"))

    assert data["models"]["default_model"] == "test-model"
    assert target.stat().st_mode & 0o777 == 0o600


def test_config_writer_rejects_symlink_and_hardlink_targets(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    config_dir = tmp_path / ".khaos"
    config_dir.mkdir()
    outside = tmp_path / "outside.yaml"
    outside.write_text("safe: true\n", encoding="utf-8")
    target = config_dir / "config.yaml"
    target.symlink_to(outside)
    with pytest.raises(ConfigError, match="single-link"):
        set_user_config_value("models.default_model", "blocked")
    assert outside.read_text(encoding="utf-8") == "safe: true\n"

    target.unlink()
    os.link(outside, target)
    with pytest.raises(ConfigError, match="single-link"):
        set_user_config_value("models.default_model", "blocked")
    assert outside.read_text(encoding="utf-8") == "safe: true\n"
