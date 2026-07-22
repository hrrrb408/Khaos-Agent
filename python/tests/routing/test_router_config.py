from khaos.routing.router import create_default_router


def test_create_default_router_expands_only_active_provider(monkeypatch, tmp_path):
    monkeypatch.delenv("KHAOS_NO_CONFIG", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key-123")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    config = tmp_path / "config.yaml"
    config.write_text(
        """
models:
  default_model: "qwen/qwen3.5-122b-a10b"
""",
        encoding="utf-8",
    )

    router = create_default_router(str(config))

    assert router.provider_manager.get_provider("nvidia").api_key == "test-key-123"
    assert "openai" not in router.provider_manager.providers
