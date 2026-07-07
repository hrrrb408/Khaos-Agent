"""Pluggable model provider abstractions.

Each provider implements :class:`BaseProvider`, turning Khaos's neutral
``Message`` list + tool definitions into a provider-specific HTTP request and
parsing its SSE stream back into ``Message`` chunks. The router picks a
provider by the ``type`` field in ``config.yaml`` and delegates streaming to
it, so adding a new vendor means one new module plus a registry entry.
"""

from khaos.routing.providers.base import (
    BaseProvider,
    ProviderError,
    build_provider,
    known_provider_types,
    register_provider_type,
)
from khaos.routing.providers.anthropic import AnthropicProvider
from khaos.routing.providers.openai_compatible import OpenAICompatibleProvider

__all__ = [
    "BaseProvider",
    "ProviderError",
    "OpenAICompatibleProvider",
    "AnthropicProvider",
    "build_provider",
    "known_provider_types",
    "register_provider_type",
]
