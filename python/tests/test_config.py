import os

import pytest
import yaml
from khaos.config import (
    ConfigAuthority,
    ConfigError,
    check_needs_setup,
    config_field_provenance,
    expand_config_placeholders,
    expand_env_placeholders,
    load_config,
    parse_model_selection,
    set_user_config_value,
    write_provider_config,
)
from khaos.routing.provider import DiscoveredModel
from khaos.security.credential_broker import CredentialBroker
from khaos.security.credentials import (
    CredentialRef,
    InMemoryCredentialStore,
    SecretValue,
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
    ref = CredentialRef.for_provider("nvidia")
    broker = CredentialBroker()
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    broker.put_provider_credential(
        ref, SecretValue("valid-test-key-123"), provider="nvidia"
    )
    try:
        config = {"models": {"providers": {"nvidia": {"credential_ref": ref.value}}}}
        assert check_needs_setup(config, credential_broker=broker) is False
    finally:
        broker.close()


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


def test_explicit_user_config_path_preserves_layered_user_authority(
    monkeypatch, tmp_path
):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.yaml").write_text(
        "defaults:\n  mode: coding\n", encoding="utf-8"
    )
    user_path = home / ".khaos" / "config.yaml"
    user_path.parent.mkdir(parents=True)
    user_path.write_text(
        "models:\n  providers:\n    zhipu-coding:\n"
        "      type: openai_compatible\n"
        "      base_url: https://open.bigmodel.cn/api/coding/paas/v4\n"
        "      credential_ref: khaos/providers/zhipu-coding/default\n"
        "      models:\n        - name: glm-5.3-flash\n"
        "  default_model: glm-5.3-flash\n",
        encoding="utf-8",
    )

    config = load_config(user_path)

    assert config["defaults"]["mode"] == "coding"
    assert config["models"]["default_model"] == "glm-5.3-flash"
    assert config_field_provenance(
        config, "models.providers.zhipu-coding.type"
    ).authority is ConfigAuthority.USER_GRANT


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


@pytest.mark.parametrize(
    "env_name",
    [
        "NVIDIA_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "ZAI_API_KEY",
        "ZAI_CODING_API_KEY",
        "SILICONFLOW_API_KEY",
    ],
)
def test_legacy_provider_environment_credentials_are_rejected(
    monkeypatch, tmp_path, env_name
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    for name in (
        "NVIDIA_API_KEY",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "ZAI_API_KEY",
        "ZAI_CODING_API_KEY",
        "SILICONFLOW_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv(env_name, "managed-secret-must-not-enter-config")
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ConfigError, match=env_name):
        load_config()


@pytest.mark.posix_host
def test_set_user_config_value(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = set_user_config_value("models.default_model", "test-model")

    data = yaml.safe_load(target.read_text(encoding="utf-8"))

    assert data["models"]["default_model"] == "test-model"
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.parent.stat().st_mode & 0o777 == 0o700


@pytest.mark.posix_host
def test_setup_writes_complete_trusted_provider_definition(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = write_provider_config("openai", CredentialRef.for_provider("openai"))
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["openai"]
    assert provider["type"] == "openai"
    assert provider["base_url"] == "https://api.openai.com/v1"
    assert provider["credential_ref"] == "khaos/providers/openai/default"
    assert "api_key" not in provider
    assert provider["models"][0]["name"] == data["models"]["default_model"]


@pytest.mark.posix_host
def test_setup_writes_zhipu_provider_definition(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    target = write_provider_config("zhipu", CredentialRef.for_provider("zhipu"))
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["zhipu"]

    assert provider["type"] == "openai_compatible"
    assert provider["base_url"] == "https://open.bigmodel.cn/api/paas/v4"
    assert provider["credential_ref"] == "khaos/providers/zhipu/default"
    assert "api_key" not in provider
    assert provider["models"][0]["name"] == "glm-5.3-flash"
    assert data["models"]["default_model"] == "glm-5.3-flash"


@pytest.mark.posix_host
def test_setup_writes_zhipu_coding_provider_definition(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    target = write_provider_config(
        "zhipu-coding", CredentialRef.for_provider("zhipu-coding")
    )
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["zhipu-coding"]

    assert provider["type"] == "openai_compatible"
    assert provider["base_url"] == "https://open.bigmodel.cn/api/coding/paas/v4"
    assert provider["credential_ref"] == "khaos/providers/zhipu-coding/default"
    assert "api_key" not in provider
    assert provider["models"][0]["name"] == "glm-5.3-flash"
    assert provider["models"][0]["max_output_tokens"] == 32768
    assert data["models"]["default_model"] == "glm-5.3-flash"


@pytest.mark.posix_host
def test_setup_writes_siliconflow_provider_definition(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))

    target = write_provider_config(
        "siliconflow", CredentialRef.for_provider("siliconflow")
    )
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["siliconflow"]

    assert provider["type"] == "openai_compatible"
    assert provider["base_url"] == "https://api.siliconflow.cn/v1"
    assert provider["credential_ref"] == "khaos/providers/siliconflow/default"
    assert "api_key" not in provider
    assert provider["models"][0]["name"] == "deepseek-ai/DeepSeek-V4-Flash"
    assert data["models"]["default_model"] == "deepseek-ai/DeepSeek-V4-Flash"


@pytest.mark.posix_host
def test_setup_writes_selected_discovered_models(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    target = write_provider_config(
        "nvidia",
        CredentialRef.for_provider("nvidia"),
        models=[
            DiscoveredModel("nvidia", "model-a", max_context_tokens=65536),
            DiscoveredModel("nvidia", "model-b", supports_tools=True),
        ],
        default_model="model-b",
    )

    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    provider = data["models"]["providers"]["nvidia"]

    assert provider["models"] == [
        {"name": "model-a", "max_context_tokens": 65536},
        {"name": "model-b", "supports_tools": True},
    ]
    assert data["models"]["default_model"] == "model-b"


def test_parse_model_selection_supports_single_multiple_and_all():
    assert parse_model_selection("", 3) == [0]
    assert parse_model_selection("1,3", 3) == [0, 2]
    assert parse_model_selection("all", 3) == [0, 1, 2]
    assert parse_model_selection("1,1", 3) is None
    assert parse_model_selection("4", 3) is None
    assert parse_model_selection("one", 3) is None


@pytest.mark.posix_host
def test_setup_wizard_discovers_and_prompts_for_models(monkeypatch, tmp_path):
    from khaos.config import run_setup_wizard

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(
        "khaos.config.build_platform_credential_store", InMemoryCredentialStore
    )
    discovered = [
        DiscoveredModel("nvidia", "model-a"),
        DiscoveredModel("nvidia", "model-b", supports_tools=True),
    ]
    monkeypatch.setattr("khaos.config._discover_models_for_setup", lambda *_args: discovered)
    answers = iter(["1", "1,2", "2"])
    monkeypatch.setattr("builtins.input", lambda _prompt: next(answers))
    monkeypatch.setattr("khaos.config.getpass.getpass", lambda _prompt: "test-nvidia-secret")

    target = run_setup_wizard(tmp_path / ".khaos" / "config.yaml")

    assert target == tmp_path / ".khaos" / "config.yaml"
    data = yaml.safe_load(target.read_text(encoding="utf-8"))
    assert data["models"]["default_model"] == "model-b"
    assert [item["name"] for item in data["models"]["providers"]["nvidia"]["models"]] == [
        "model-a",
        "model-b",
    ]


@pytest.mark.posix_host
def test_setup_wizard_does_not_save_key_when_discovery_fails(
    monkeypatch, tmp_path, capsys
):
    from khaos.config import run_setup_wizard

    monkeypatch.setenv("HOME", str(tmp_path))

    async def failing_discovery(*_args):
        raise RuntimeError("provider response echoed setup-secret")

    monkeypatch.setattr("khaos.config.discover_provider_models", failing_discovery)
    monkeypatch.setattr(
        "khaos.config.build_platform_credential_store", InMemoryCredentialStore
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    monkeypatch.setattr(
        "khaos.config.getpass.getpass", lambda _prompt: "setup-secret-value"
    )

    target = run_setup_wizard(tmp_path / ".khaos" / "config.yaml")

    assert target is None
    assert not (tmp_path / ".khaos" / "config.yaml").exists()
    output = capsys.readouterr()
    assert "setup-secret-value" not in output.out
    assert "setup-secret-value" not in output.err


def test_setup_prompt_accepts_builtin_provider_aliases(monkeypatch):
    from khaos.config import _prompt_provider

    monkeypatch.setattr("builtins.input", lambda _prompt: "4")

    assert _prompt_provider() == "zhipu"

    monkeypatch.setattr("builtins.input", lambda _prompt: "5")
    assert _prompt_provider() == "zhipu-coding"

    monkeypatch.setattr("builtins.input", lambda _prompt: "6")
    assert _prompt_provider() == "siliconflow"

    monkeypatch.setattr("builtins.input", lambda _prompt: "硅基流动")
    assert _prompt_provider() == "siliconflow"


@pytest.mark.posix_host
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
