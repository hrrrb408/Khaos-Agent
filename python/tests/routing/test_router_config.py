from khaos.routing.router import create_default_router
from khaos.rpc.composition import load_router_from_config
from khaos.security.credential_broker import CredentialBroker
from khaos.security.credentials import (
    CredentialRef,
    InMemoryCredentialStore,
    SecretValue,
)


def test_create_default_router_expands_only_active_provider(monkeypatch, tmp_path):
    monkeypatch.delenv("KHAOS_NO_CONFIG", raising=False)
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    config = tmp_path / "config.yaml"
    config.write_text(
        """
models:
  default_model: "qwen/qwen3.5-122b-a10b"
""",
        encoding="utf-8",
    )

    ref = CredentialRef.for_provider("nvidia", name="test")
    broker = CredentialBroker()
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    broker.put_provider_credential(ref, SecretValue("test-key-123"), provider="nvidia")
    user_config = home / ".khaos" / "config.yaml"
    user_config.parent.mkdir(parents=True)
    user_config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: https://integrate.api.nvidia.com/v1
      credential_ref: khaos/providers/nvidia/test
      models:
        - name: qwen/qwen3.5-122b-a10b
          max_context_tokens: 128000
""",
        encoding="utf-8",
    )

    try:
        router = create_default_router(str(config), credential_broker=broker)
    finally:
        broker.close()

    provider = router.provider_manager.get_provider("nvidia")
    assert provider.credential_ref == ref
    assert not hasattr(provider, "api_key")
    assert "openai" not in router.provider_manager.providers


def test_explicit_user_config_path_keeps_layered_trust_boundary(monkeypatch, tmp_path):
    """An explicit user path must not be reclassified as project input."""

    monkeypatch.delenv("KHAOS_NO_CONFIG", raising=False)
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.yaml").write_text("models: {}\n", encoding="utf-8")

    ref = CredentialRef.for_provider("nvidia", name="explicit-user")
    broker = CredentialBroker()
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    broker.put_provider_credential(
        ref,
        SecretValue("test-key-explicit-user"),
        provider="nvidia",
    )
    user_config = home / ".khaos" / "config.yaml"
    user_config.parent.mkdir(parents=True)
    user_config.write_text(
        """
models:
  default_model: qwen/test
  providers:
    nvidia:
      type: openai_compatible
      base_url: https://integrate.api.nvidia.com/v1
      credential_ref: khaos/providers/nvidia/explicit-user
      models:
        - name: qwen/test
          max_context_tokens: 128000
""",
        encoding="utf-8",
    )

    try:
        router = load_router_from_config(
            user_config,
            project_root=project,
            credential_broker=broker,
        )
        assert router.provider_manager.get_provider("nvidia").credential_ref == ref
    finally:
        broker.close()


def test_missing_project_template_still_loads_trusted_user_provider(
    monkeypatch, tmp_path
):
    """Local projects need not carry a Khaos config.yaml template."""

    monkeypatch.delenv("KHAOS_NO_CONFIG", raising=False)
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    project = tmp_path / "project"
    project.mkdir()

    ref = CredentialRef.for_provider("nvidia", name="missing-project")
    broker = CredentialBroker()
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    broker.put_provider_credential(
        ref,
        SecretValue("test-key-missing-project"),
        provider="nvidia",
    )
    user_config = home / ".khaos" / "config.yaml"
    user_config.parent.mkdir(parents=True)
    user_config.write_text(
        """
models:
  default_model: qwen/test
  providers:
    nvidia:
      type: openai_compatible
      base_url: https://integrate.api.nvidia.com/v1
      credential_ref: khaos/providers/nvidia/missing-project
      models:
        - name: qwen/test
          max_context_tokens: 128000
""",
        encoding="utf-8",
    )

    try:
        router = load_router_from_config(
            project / "config.yaml",
            project_root=project,
            credential_broker=broker,
        )
        assert router.provider_manager.get_provider("nvidia").credential_ref == ref
    finally:
        broker.close()
