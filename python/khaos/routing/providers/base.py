"""Abstract base for model providers and the factory that builds them."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import Any

import httpx

from khaos.agent.core import Message
from khaos.exceptions import KhaosError
from khaos.routing.provider import ModelSpec, ProviderConfig


class ProviderError(KhaosError):
    """Raised when a provider cannot serve a request (auth, network, format)."""

    pass


class BaseProvider(ABC):
    """Common interface every model provider implements.

    Providers are stateless beyond their config: a router can hold many of
    them and dispatch by model name. The two methods every provider must
    implement are :meth:`stream_chat` (the streaming chat path) and
    :meth:`supports` (capability gating). Tool-format conversion is the
    provider's responsibility — Khaos passes its neutral tool list and the
    provider rewrites it.
    """

    #: The ``type`` string this provider answers to in ``config.yaml``.
    type_name: str = ""

    def __init__(self, config: ProviderConfig, http_client: httpx.AsyncClient | None = None):
        self.config = config
        self.http_client = http_client

    @abstractmethod
    async def stream_chat(
        self,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> AsyncIterator[Message]:
        """Stream chat completions for ``model`` as Khaos Message chunks."""
        raise NotImplementedError
        yield Message(role="assistant", content="")  # pragma: no cover - type hint

    def supports(self, model: ModelSpec) -> bool:
        """True when this provider can serve ``model`` (default: yes)."""
        return True

    @staticmethod
    def _client_or_new(http_client: httpx.AsyncClient | None, timeout: int):
        """Return ``(client, should_close)`` for a streaming call."""
        if http_client is not None:
            return http_client, False
        return httpx.AsyncClient(timeout=timeout), True


# Registry of provider type -> class. Populated by each provider module on
# import; build_provider consults this. OpenAI-compatible is the default.
_PROVIDER_REGISTRY: dict[str, type[BaseProvider]] = {}


def register_provider_type(type_name: str, cls: type[BaseProvider]) -> None:
    """Register a provider class for ``type_name``."""
    _PROVIDER_REGISTRY[type_name] = cls


def known_provider_types() -> list[str]:
    """Return the registered provider type names."""
    return sorted(_PROVIDER_REGISTRY)


def build_provider(
    config: ProviderConfig,
    http_client: httpx.AsyncClient | None = None,
) -> BaseProvider:
    """Construct the provider for ``config.type``.

    Falls back to OpenAI-compatible for unknown types so a missing ``type``
    field in older configs keeps working.
    """
    type_name = config.type or "openai_compatible"
    cls = _PROVIDER_REGISTRY.get(type_name) or _PROVIDER_REGISTRY.get("openai_compatible")
    if cls is None:  # pragma: no cover - openai_compatible always registers first
        raise ProviderError(f"no provider registered for type {type_name!r}")
    return cls(config, http_client=http_client)


__all__ = [
    "BaseProvider",
    "ProviderError",
    "build_provider",
    "register_provider_type",
    "known_provider_types",
]
