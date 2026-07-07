"""OpenAI-compatible provider (NVIDIA NIM, OpenRouter, vLLM, Ollama, …).

This is a thin adapter over the existing :class:`ModelClient` so all current
behavior and tests carry over unchanged. The provider type is registered as
both ``openai_compatible`` and ``openai`` (native OpenAI is wire-compatible).
"""

from __future__ import annotations

from collections.abc import AsyncIterator

from khaos.agent.core import Message
from khaos.routing.model_client import ModelClient
from khaos.routing.provider import ModelSpec, ProviderConfig
from khaos.routing.providers.base import BaseProvider, register_provider_type


class OpenAICompatibleProvider(BaseProvider):
    """Streams via the OpenAI /chat/completions SSE protocol."""

    type_name = "openai_compatible"

    def __init__(self, config: ProviderConfig, http_client=None):
        super().__init__(config, http_client=http_client)
        # Reuse the battle-tested ModelClient so streaming/retry behavior is
        # identical to pre-Phase-4 code paths.
        self._client = ModelClient(http_client=http_client)

    async def stream_chat(
        self,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> AsyncIterator[Message]:
        async for chunk in self._client.stream_chat(self.config, model, messages, tools):
            yield chunk


# Register under both the canonical type name and the native OpenAI alias so
# config.yaml entries with ``type: openai`` map here without a separate class.
register_provider_type("openai_compatible", OpenAICompatibleProvider)
register_provider_type("openai", OpenAICompatibleProvider)


__all__ = ["OpenAICompatibleProvider"]
