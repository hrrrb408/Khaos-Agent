"""Function-level model router skeleton for P0-A."""

from __future__ import annotations

import asyncio
import os
import json
import shlex
import uuid
from dataclasses import dataclass, field
from typing import AsyncIterator

from khaos.agent.core import Message
from khaos.config import (
    config_for_models,
    expand_config_placeholders,
    expand_env_placeholders,
    load_config,
)
from khaos.exceptions import ModelUnavailableError
from khaos.routing.model_client import ModelClient
from khaos.routing.provider import ModelSpec, ProviderConfig, ProviderManager


@dataclass(frozen=True)
class RoutingRule:
    """Mapping from function key to primary and fallback model names."""

    function: str
    primary_model: str
    fallback_models: list[str] = field(default_factory=list)
    prefer_coding_model: bool = False


class ModelRouter:
    """Function router with provider-aware fallback and mock streaming."""

    def __init__(
        self,
        provider_manager: ProviderManager | None = None,
        mock_response: str = "Khaos mock response.",
        model_client: ModelClient | None = None,
    ):
        self.provider_manager = provider_manager or _default_provider_manager()
        self.mock_response = mock_response
        self.model_client = model_client or ModelClient()
        self._rules: dict[str, RoutingRule] = {}

    def set_rule(self, function: str, rule: RoutingRule) -> None:
        """Register or replace a routing rule."""
        self._rules[function] = rule

    async def resolve(self, function: str) -> str:
        """Resolve a function key to a model name, preserving P0 test API."""
        return (await self.resolve_model(function)).model

    async def resolve_model(self, function: str) -> ModelSpec:
        """Resolve a function key to the first available model spec."""
        rule = self._rules.get(function)
        if rule is None:
            raise ModelUnavailableError(f"no routing rule for function: {function}")
        for model_name in [rule.primary_model, *rule.fallback_models]:
            try:
                if self.provider_manager.is_model_available(model_name):
                    return self.provider_manager.get_model(model_name)
            except KeyError:
                continue
        raise ModelUnavailableError(f"no available model for function: {function}")

    async def call(
        self,
        function: str,
        messages: list[Message],
        **kwargs,
    ) -> AsyncIterator[Message]:
        """Stream mock model text chunks for the resolved function."""
        model = await self.resolve_model(function)
        provider = self.provider_manager.get_provider(model.provider)
        if not provider.base_url.startswith("mock://"):
            async for chunk in self.model_client.stream_chat(provider, model, messages, kwargs.get("tools")):
                yield chunk
            return
        tool_call = self._extract_tool_call(messages)
        if tool_call is not None:
            yield Message(role="assistant", content="", tool_calls=[tool_call], stop_reason="tool_use")
            return
        response = kwargs.get("mock_response", self.mock_response)
        if messages and messages[-1].role == "tool":
            response = "Tool completed."
        for chunk in self._chunk_response(response):
            await asyncio.sleep(0)
            yield Message(role="assistant", content=chunk)
        yield Message(role="assistant", content="", stop_reason="end_turn")

    async def call_with_fallback(
        self,
        function: str,
        messages: list[Message],
        **kwargs,
    ) -> AsyncIterator[Message]:
        """Call primary model and fall back if it fails before streaming."""
        rule = self._rules.get(function)
        if rule is None:
            raise ModelUnavailableError(f"no routing rule for function: {function}")
        errors: list[str] = []
        for model_name in [rule.primary_model, *rule.fallback_models]:
            try:
                if not self.provider_manager.is_model_available(model_name):
                    continue
                model = self.provider_manager.get_model(model_name)
                provider = self.provider_manager.get_provider(model.provider)
                if provider.base_url.startswith("mock://"):
                    stream = self._call_resolved(messages, kwargs)
                else:
                    stream = self.model_client.stream_chat(provider, model, messages, kwargs.get("tools"))
                async for chunk in stream:
                    yield chunk
                return
            except Exception as exc:
                errors.append(f"{model_name}: {exc}")
        raise ModelUnavailableError("; ".join(errors) or f"no available model for function: {function}")

    async def call_model(
        self,
        model_name: str,
        messages: list[Message],
        **kwargs,
    ) -> AsyncIterator[Message]:
        """Stream a response from a specific model by name.

        This is the per-model entry point used by the MoA runner; it bypasses
        function routing and dispatches to the provider that owns the model.
        OpenAI-compatible providers reuse the shared ModelClient; any other
        registered provider type (e.g. Anthropic) is served by its own
        BaseProvider implementation via ``provider_clients()``.
        """
        if not self.provider_manager.is_model_available(model_name):
            raise ModelUnavailableError(f"model not available: {model_name}")
        model = self.provider_manager.get_model(model_name)
        provider = self.provider_manager.get_provider(model.provider)
        if provider.base_url.startswith("mock://"):
            async for chunk in self._call_resolved(messages, kwargs):
                yield chunk
            return
        # Route non-OpenAI providers through their dedicated BaseProvider.
        if provider.type not in {"", "openai_compatible", "openai"}:
            client = self.provider_manager.provider_clients()[provider.name]
            async for chunk in client.stream_chat(
                model, messages, kwargs.get("tools")
            ):
                yield chunk
            return
        async for chunk in self.model_client.stream_chat(
            provider, model, messages, kwargs.get("tools")
        ):
            yield chunk

    async def call_moa(
        self,
        messages: list[Message],
        moa_config,
        pipeline_name: str | None = None,
        **kwargs,
    ) -> AsyncIterator[Message]:
        """Run a Mixture-of-Agents pipeline.

        ``moa_config`` is a :class:`~khaos.routing.moa.MoAConfig`. When it is
        disabled or has no pipelines, this raises ModelUnavailableError so the
        caller can decide whether to fall back to a normal ``call``.
        """
        from khaos.routing.moa import MoARunner

        pipeline = moa_config.pipeline(pipeline_name) if moa_config else None
        if pipeline is None:
            raise ModelUnavailableError(
                "MoA disabled or pipeline not found: "
                f"{pipeline_name or '<default>'}"
            )
        runner = MoARunner(self._moa_caller(kwargs))
        async for chunk in runner.run(pipeline, messages):
            yield chunk

    def _moa_caller(self, kwargs: dict):
        """Build a (model_name, messages) -> stream callable bound to this router."""

        async def caller(model_name: str, msgs: list[Message]):  # type: ignore[no-untyped-def]
            async for chunk in self.call_model(model_name, msgs, **kwargs):
                yield chunk

        return caller

    async def _call_resolved(self, messages: list[Message], kwargs: dict) -> AsyncIterator[Message]:
        tool_call = self._extract_tool_call(messages)
        if tool_call is not None:
            yield Message(role="assistant", content="", tool_calls=[tool_call], stop_reason="tool_use")
            return
        response = kwargs.get("mock_response", self.mock_response)
        if messages and messages[-1].role == "tool":
            response = "Tool completed."
        for chunk in self._chunk_response(response):
            await asyncio.sleep(0)
            yield Message(role="assistant", content=chunk)
        yield Message(role="assistant", content="", stop_reason="end_turn")

    @staticmethod
    def _chunk_response(response: str) -> list[str]:
        words = response.split(" ")
        if len(words) <= 1:
            return [response]
        return [f"{word} " for word in words[:-1]] + [words[-1]]

    @staticmethod
    def _extract_tool_call(messages: list[Message]) -> dict | None:
        if not messages:
            return None
        last = messages[-1]
        if last.role != "user":
            return None
        text = last.content.strip()
        if text.startswith("/tool "):
            payload = text.removeprefix("/tool ").strip()
            if payload.startswith("{"):
                data = json.loads(payload)
                return {
                    "id": str(data.get("id") or uuid.uuid4()),
                    "name": data["name"],
                    "arguments": dict(data.get("arguments") or {}),
                }
            parts = shlex.split(payload)
            if not parts:
                return None
            return _tool_call_from_parts(parts)
        return None


def _tool_call_from_parts(parts: list[str]) -> dict | None:
    name = parts[0]
    if name == "read_file" and len(parts) >= 2:
        return {"id": str(uuid.uuid4()), "name": name, "arguments": {"path": parts[1]}}
    if name == "write_file" and len(parts) >= 3:
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "arguments": {"path": parts[1], "content": " ".join(parts[2:])},
        }
    if name == "terminal" and len(parts) >= 2:
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "arguments": {"command": " ".join(parts[1:])},
        }
    if name == "search_files" and len(parts) >= 2:
        return {
            "id": str(uuid.uuid4()),
            "name": name,
            "arguments": {"root": parts[1], "query": parts[2] if len(parts) > 2 else ""},
        }
    return None

def create_default_router(config_path: str | None = None, *, honor_no_config: bool = True) -> ModelRouter:
    """Create router from config.yaml, falling back to mock if no config.

    Tests can set KHAOS_NO_CONFIG=1 to force mock mode.
    """
    # Tests can force mock via env var
    if honor_no_config and os.environ.get("KHAOS_NO_CONFIG"):
        return _mock_fallback()

    if config_path:
        expanded_path = expand_env_placeholders(os.path.expanduser(config_path), source="router config path")
        config = load_config(expanded_path, strict_env=False) if os.path.isfile(expanded_path) else {}
    else:
        config = load_config(strict_env=False)

    models_config = config.get("models", {})

    # Try to build real providers from config
    if models_config.get("providers"):
        from khaos.routing.provider import ProviderManager

        default_model = models_config.get("default_model", "")
        active_config = config_for_models(config, {str(default_model)} if default_model else set())
        active_config = expand_config_placeholders(active_config, strict=True)
        pm = ProviderManager.from_config(active_config)

        router = ModelRouter(provider_manager=pm)
        if default_model:
            router.set_rule("agent_loop", RoutingRule(function="agent_loop", primary_model=default_model))
            router.set_rule("coding", RoutingRule(function="coding", primary_model=default_model, prefer_coding_model=True))
            router.set_rule("compression", RoutingRule(function="compression", primary_model=default_model))
        return router

    # Fallback: mock provider for tests
    return _mock_fallback()


def _mock_fallback() -> ModelRouter:
    from khaos.routing.provider import ProviderManager, ProviderConfig

    router = ModelRouter(provider_manager=_default_provider_manager())
    router.set_rule("agent_loop", RoutingRule(function="agent_loop", primary_model="mock-provider/mock-office"))
    router.set_rule("coding", RoutingRule(function="coding", primary_model="mock-provider/mock-coding", prefer_coding_model=True))
    router.set_rule("compression", RoutingRule(function="compression", primary_model="mock-provider/mock-compression"))
    return router


def _default_provider_manager() -> ProviderManager:
    manager = ProviderManager()
    manager.register_provider(ProviderConfig(name="mock-provider", base_url="mock://local"))
    for name in [
        "mock-provider/mock-office",
        "mock-provider/mock-coding",
        "mock-provider/mock-compression",
        "mock-provider/mock-summary",
    ]:
        manager.register_model(
            name,
            ModelSpec(provider="mock-provider", model=name, max_context_tokens=128000),
        )
    return manager
