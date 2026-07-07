"""Provider and model registry for Phase 2 routing."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProviderConfig:
    """Model provider configuration."""

    name: str
    base_url: str
    api_key: str = ""
    type: str = "openai_compatible"
    rpm_limit: int = 0
    tpm_limit: int = 0
    timeout: int = 120


@dataclass(frozen=True)
class ModelSpec:
    """One model exposed by a provider."""

    provider: str
    model: str
    max_context_tokens: int
    supports_streaming: bool = True
    supports_tools: bool = True
    supports_vision: bool = False
    available: bool = True


class ProviderManager:
    """Provider and model registry with env-var expansion."""

    def __init__(self):
        self._providers: dict[str, ProviderConfig] = {}
        self._models: dict[str, ModelSpec] = {}

    def register_provider(self, config: ProviderConfig) -> None:
        """Register provider config."""
        self._providers[config.name] = ProviderConfig(
            name=config.name,
            base_url=self._expand_env(config.base_url),
            api_key=self._expand_env(config.api_key),
            type=config.type,
            rpm_limit=config.rpm_limit,
            tpm_limit=config.tpm_limit,
            timeout=config.timeout,
        )

    def register_model(self, name: str, spec: ModelSpec) -> None:
        """Register a model spec by logical model name."""
        if spec.provider not in self._providers:
            raise KeyError(f"provider not registered: {spec.provider}")
        self._models[name] = spec

    def get_model(self, name: str) -> ModelSpec:
        """Return a registered model."""
        try:
            return self._models[name]
        except KeyError as exc:
            raise KeyError(f"model not registered: {name}") from exc

    def get_provider(self, name: str) -> ProviderConfig:
        """Return a registered provider."""
        try:
            return self._providers[name]
        except KeyError as exc:
            raise KeyError(f"provider not registered: {name}") from exc

    def is_model_available(self, name: str) -> bool:
        """Return whether a model can currently serve requests."""
        return self.get_model(name).available

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "ProviderManager":
        """Build manager from config.yaml-style dict."""
        manager = cls()
        providers_config = config.get("providers", {})
        models_config = config.get("models", {})
        if isinstance(models_config, dict) and "providers" in models_config:
            providers_config = {
                name: data
                for name, data in models_config.get("providers", {}).items()
            }
        for name, provider_data in providers_config.items():
            manager.register_provider(
                ProviderConfig(
                    name=name,
                    type=str(provider_data.get("type", "openai_compatible")),
                    base_url=str(provider_data.get("base_url", "")),
                    api_key=str(provider_data.get("api_key", "")),
                    rpm_limit=int(provider_data.get("rpm_limit", 0)),
                    tpm_limit=int(provider_data.get("tpm_limit", 0)),
                    timeout=int(provider_data.get("timeout", 120)),
                )
            )
        if isinstance(models_config, dict) and "providers" in models_config:
            flattened_models: dict[str, dict[str, Any]] = {}
            for provider_name, provider_data in models_config.get("providers", {}).items():
                for model_data in provider_data.get("models", []):
                    model_name = str(model_data["name"])
                    flattened_models[model_name] = {
                        **model_data,
                        "provider": provider_name,
                        "model": model_name,
                    }
            models_config = flattened_models
        for name, model_data in models_config.items():
            if name in {"providers", "default_model", "router"}:
                continue
            manager.register_model(
                name,
                ModelSpec(
                    provider=str(model_data["provider"]),
                    model=str(model_data["model"]),
                    max_context_tokens=int(model_data.get("max_context_tokens", 128000)),
                    supports_streaming=bool(model_data.get("supports_streaming", True)),
                    supports_tools=bool(model_data.get("supports_tools", True)),
                    supports_vision=bool(model_data.get("supports_vision", False)),
                    available=bool(model_data.get("available", True)),
                ),
            )
        return manager

    @staticmethod
    def _expand_env(value: str) -> str:
        pattern = re.compile(r"\$\{([^}]+)\}")
        return pattern.sub(lambda match: os.environ.get(match.group(1), ""), value)
