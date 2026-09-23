"""Provider and model registry for Phase 2 routing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from khaos.config import expand_env_placeholders
from khaos.security.credential_broker import CredentialBroker
from khaos.security.credentials import (
    CredentialRef,
    build_platform_credential_store,
)

DEFAULT_MAX_OUTPUT_TOKENS = 4096
DEFAULT_PROVIDER_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class ProviderCapabilities:
    """Wire-level capabilities that affect provider request serialization."""

    supports_multiple_system_messages: bool = True


def provider_capabilities(provider_name: str) -> ProviderCapabilities:
    """Return the conservative wire profile for a provider adapter.

    SiliconFlow's OpenAI-compatible endpoint currently accepts only one
    ``system`` message per request.  Keep this compatibility fact at the
    provider boundary so AgentLoop message history and authority semantics
    remain unchanged.
    """
    if provider_name.casefold() == "siliconflow":
        return ProviderCapabilities(supports_multiple_system_messages=False)
    return ProviderCapabilities()


@dataclass(frozen=True)
class ProviderConfig:
    """Model provider configuration."""

    name: str
    base_url: str
    credential_ref: CredentialRef | None = None
    type: str = "openai_compatible"
    rpm_limit: int = 0
    tpm_limit: int = 0
    timeout: int = 120
    supports_multiple_system_messages: bool | None = None

    def __post_init__(self) -> None:
        """Resolve provider-specific wire capabilities once at construction."""
        if self.credential_ref is not None:
            if not isinstance(self.credential_ref, CredentialRef):
                raise ValueError("provider credential_ref must be a CredentialRef")
            if self.credential_ref.provider != self.name.casefold():
                raise ValueError("provider credential_ref belongs to another provider")
        if self.supports_multiple_system_messages is None:
            object.__setattr__(
                self,
                "supports_multiple_system_messages",
                provider_capabilities(self.name).supports_multiple_system_messages,
            )


@dataclass(frozen=True)
class ModelSpec:
    """One model exposed by a provider."""

    provider: str
    model: str
    max_context_tokens: int
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    supports_streaming: bool = True
    supports_tools: bool = True
    supports_vision: bool = False
    available: bool = True


_PROVIDER_DEFAULT_MAX_OUTPUT_TOKENS = {
    # GLM Coding Plan reasoning responses can exhaust a small generic
    # completion ceiling before emitting the next tool call.  Keep this as a
    # provider default only; an explicit model config value still wins.
    "zhipu-coding": 32_768,
}

_PROVIDER_DEFAULT_TIMEOUT_SECONDS = {
    # Reasoning-heavy Coding Plan responses can have a long gap between SSE
    # chunks while the model is deciding its next tool call.  Keep the
    # transport ceiling bounded and let an explicit provider timeout win.
    "zhipu-coding": 300,
}


def provider_default_max_output_tokens(provider_name: str) -> int:
    """Return the safe output ceiling used when a model omits one."""
    return _PROVIDER_DEFAULT_MAX_OUTPUT_TOKENS.get(
        provider_name.casefold(),
        DEFAULT_MAX_OUTPUT_TOKENS,
    )


def provider_default_timeout_seconds(provider_name: str) -> int:
    """Return the bounded transport timeout used when one is omitted."""
    return _PROVIDER_DEFAULT_TIMEOUT_SECONDS.get(
        provider_name.casefold(),
        DEFAULT_PROVIDER_TIMEOUT_SECONDS,
    )


@dataclass(frozen=True)
class DiscoveredModel:
    """Safe model metadata returned by a provider model-catalog request.

    Provider catalog responses are untrusted metadata. Only the validated
    model identifier and optional capability hints are carried forward to
    setup/configuration; credential material and raw provider payloads never
    enter this value.
    """

    provider: str
    model: str
    max_context_tokens: int | None = None
    supports_tools: bool | None = None
    owned_by: str | None = None


class ProviderManager:
    """Provider and model registry with env-var expansion."""

    def __init__(self, credential_broker: CredentialBroker | None = None):
        self._providers = {}
        self._models = {}
        self.credential_broker = credential_broker

    @property
    def providers(self) -> dict[str, ProviderConfig]:
        """Registered provider configs keyed by provider name."""
        return self._providers

    @property
    def models(self) -> dict[str, ModelSpec]:
        """Registered model specs keyed by logical model name."""
        return self._models

    def register_provider(self, config: ProviderConfig) -> None:
        """Register provider config."""
        self._providers[config.name] = ProviderConfig(
            name=config.name,
            base_url=self._expand_env(config.base_url),
            credential_ref=config.credential_ref,
            type=config.type,
            rpm_limit=config.rpm_limit,
            tpm_limit=config.tpm_limit,
            timeout=config.timeout,
            supports_multiple_system_messages=config.supports_multiple_system_messages,
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

    def provider_clients(self):
        """Build and cache a BaseProvider per registered provider.

        Returns a dict of provider name -> provider instance. Lazily imports
        the providers package so the type registry is populated on first use.
        """
        from khaos.routing.providers import build_provider

        cached = getattr(self, "_provider_clients", None)
        if cached is not None:
            return cached
        self._provider_clients = {
            name: build_provider(
                config, credential_broker=self.credential_broker
            )
            for name, config in self._providers.items()
        }
        return self._provider_clients

    def provider_for_model(self, model_name: str):
        """Return the BaseProvider that serves ``model_name``."""
        spec = self.get_model(model_name)
        return self.provider_clients()[spec.provider]

    @classmethod
    def from_config(
        cls,
        config: dict[str, Any],
        *,
        credential_broker: CredentialBroker | None = None,
    ) -> ProviderManager:
        """Build manager from config.yaml-style dict."""
        providers_config = config.get("providers", {})
        models_config = config.get("models", {})
        if isinstance(models_config, dict) and "providers" in models_config:
            providers_config = {
                name: data
                for name, data in models_config.get("providers", {}).items()
            }
        if not isinstance(providers_config, dict):
            raise TypeError("provider configuration must be a mapping")
        provider_configs: list[ProviderConfig] = []
        for name, provider_data in providers_config.items():
            if not isinstance(provider_data, dict):
                raise TypeError("provider configuration must be a mapping")
            if any(
                isinstance(key, str)
                and key.casefold()
                in {
                    "api_key",
                    "apikey",
                    "api_key_env",
                    "access_token",
                    "access_token_env",
                    "secret",
                    "secret_env",
                    "password",
                    "password_env",
                    "token",
                    "token_env",
                    "authorization",
                    "authorization_env",
                }
                for key in provider_data
            ):
                raise ValueError(
                    "plaintext provider credentials are unsupported; use credential_ref"
                )
            raw_ref = provider_data.get("credential_ref")
            ref = (
                CredentialRef.from_config(str(name), raw_ref)
                if raw_ref is not None
                else None
            )
            provider_configs.append(
                ProviderConfig(
                    name=str(name),
                    type=str(provider_data.get("type", "openai_compatible")),
                    base_url=str(provider_data.get("base_url", "")),
                    credential_ref=ref,
                    rpm_limit=int(provider_data.get("rpm_limit", 0)),
                    tpm_limit=int(provider_data.get("tpm_limit", 0)),
                    timeout=int(
                        provider_data.get(
                            "timeout",
                            provider_default_timeout_seconds(str(name)),
                        )
                    ),
                )
            )
        if credential_broker is None and any(
            provider.credential_ref is not None for provider in provider_configs
        ):
            credential_broker = CredentialBroker()
            store = build_platform_credential_store()
            for provider in provider_configs:
                if provider.credential_ref is not None:
                    credential_broker.register_credential_store(
                        provider.credential_ref,
                        store,
                        provider=provider.name,
                    )
        manager = cls(credential_broker=credential_broker)
        for provider in provider_configs:
            if (
                provider.base_url
                and not provider.base_url.startswith("mock://")
                and provider.credential_ref is None
            ):
                raise ValueError(
                    "non-mock provider requires credential_ref"
                )
            manager.register_provider(provider)
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
            provider_name = str(model_data["provider"])
            manager.register_model(
                name,
                ModelSpec(
                    provider=provider_name,
                    model=str(model_data["model"]),
                    max_context_tokens=int(model_data.get("max_context_tokens", 128000)),
                    max_output_tokens=int(
                        model_data.get(
                            "max_output_tokens",
                            provider_default_max_output_tokens(provider_name),
                        )
                    ),
                    supports_streaming=bool(model_data.get("supports_streaming", True)),
                    supports_tools=bool(model_data.get("supports_tools", True)),
                    supports_vision=bool(model_data.get("supports_vision", False)),
                    available=bool(model_data.get("available", True)),
                ),
            )
        return manager

    @staticmethod
    def _expand_env(value: str) -> str:
        return expand_env_placeholders(value, source="provider config")
