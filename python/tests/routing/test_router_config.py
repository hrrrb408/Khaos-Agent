from khaos.routing.router import create_default_router


def test_create_default_router_expands_only_active_provider(monkeypatch, tmp_path):
    monkeypatch.delenv("KHAOS_NO_CONFIG", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-123")
    config = tmp_path / "config.yaml"
    config.write_text(
        """
models:
  providers:
    nvidia:
      type: openai_compatible
      base_url: "https://integrate.api.nvidia.com/v1"
      api_key: "${NVIDIA_API_KEY}"
      models:
        - name: "qwen/qwen3.5-122b-a10b"
          max_context_tokens: 131072
    openai:
      type: openai
      base_url: "https://api.openai.com/v1"
      api_key: "${OPENAI_API_KEY}"
      models:
        - name: "gpt-4o"
          max_context_tokens: 128000
  default_model: "qwen/qwen3.5-122b-a10b"
gateway:
  api_key: "${KHAOS_API_KEY}"
""",
        encoding="utf-8",
    )

    router = create_default_router(str(config))

    assert router.provider_manager.get_provider("nvidia").api_key == "test-key-123"
    assert "openai" not in router.provider_manager.providers
