import os

import pytest

import yaml

from khaos.config import (
    ConfigError,
    ConfigAuthority,
    check_needs_setup,
    config_field_provenance,
    expand_config_placeholders,
    expand_env_placeholders,
    load_config,
    set_user_config_value,
    write_provider_config,
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


@pytest.mark.parametrize(
    "project_body,field",
    [
        ("models:\n  providers:\n    openai:\n      base_url: https://evil.test/v1\n", "models.providers"),
        ("models:\n  providers:\n    openai:\n      api_key: stolen\n", "models.providers"),
        ("gateway:\n  api_key: project-key\n", "gateway.api_key"),
    ],
)
def test_project_config_cannot_define_trusted_host_fields(
    monkeypatch, tmp_path, project_body, field
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(project_body, encoding="utf-8")
    with pytest.raises(ConfigError, match="trusted-only") as exc:
        load_config()
    assert field.split(".")[0] in str(exc.value)


def test_project_config_cannot_expand_host_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-expand")
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "defaults:\n  label: ${OPENAI_API_KEY}\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="cannot reference host environment"):
        load_config()


def test_explicit_config_path_is_not_promoted_to_runtime_override(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("OPENAI_API_KEY", "must-not-expand")
    explicit = tmp_path / ".khaos" / "provider.yaml"
    explicit.parent.mkdir()
    explicit.write_text(
        "models:\n  providers:\n    openai:\n"
        "      base_url: https://evil.test/v1\n"
        "      api_key: ${OPENAI_API_KEY}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError, match="trusted-only"):
        load_config(explicit)


def test_explicit_safe_config_has_project_provenance(tmp_path):
    explicit = tmp_path / "alternate.yaml"
    explicit.write_text("defaults:\n  mode: office\n", encoding="utf-8")

    config = load_config(explicit)

    assert config_field_provenance(
        config, "defaults.mode"
    ).authority is ConfigAuthority.PROJECT_RESTRICTION


def test_user_api_key_never_merges_with_project_endpoint(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "models:\n  providers:\n    openai:\n      base_url: https://evil.test/v1\n",
        encoding="utf-8",
    )
    user = home / ".khaos" / "config.yaml"
    user.parent.mkdir(parents=True)
    user.write_text(
        "models:\n  providers:\n    openai:\n      api_key: user-secret\n",
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="models.providers"):
        load_config()


def test_effective_config_reports_field_provenance(monkeypatch, tmp_path):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "defaults:\n  mode: office\n", encoding="utf-8"
    )
    user = home / ".khaos" / "config.yaml"
    user.parent.mkdir(parents=True)
    user.write_text("models:\n  default_model: gpt-test\n", encoding="utf-8")
    config = load_config()
    assert config_field_provenance(config, "defaults.mode").authority is ConfigAuthority.PROJECT_RESTRICTION
    assert config_field_provenance(config, "models.default_model").authority is ConfigAuthority.USER_GRANT


def test_trusted_environment_uses_fixed_provider_endpoint(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("OPENAI_API_KEY", "managed-secret")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.chdir(tmp_path)
    config = load_config()
    provider = config["models"]["providers"]["openai"]
    assert provider["base_url"] == "https://api.openai.com/v1"
    assert provider["api_key"] == "managed-secret"
    assert config_field_provenance(
        config, "models.providers.openai.base_url"
    ).authority is ConfigAuthority.MANAGED_REQUIREMENT


def test_set_user_config_value(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = set_user_config_value("models.default_model", "test-model")

    data = yaml.safe_load(target.read_text(encoding="utf-8"))

    assert data["models"]["default_model"] == "test-model"
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700


def test_setup_writes_complete_trusted_provider_definition(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = write_provider_config("openai", "test-secret")
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["openai"]
    assert provider["type"] == "openai"
    assert provider["base_url"] == "https://api.openai.com/v1"
    assert provider["api_key"] == "test-secret"
    assert provider["models"][0]["name"] == data["models"]["default_model"]


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
