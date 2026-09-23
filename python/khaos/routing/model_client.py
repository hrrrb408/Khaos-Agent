"""Async OpenAI-compatible model client."""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from khaos.agent.core import Message
from khaos.agent.error_handler import ModelRateLimitError
from khaos.exceptions import ProviderError
from khaos.routing.provider import DiscoveredModel, ModelSpec, ProviderConfig
from khaos.security.credential_broker import CredentialBroker, CredentialBrokerError
from khaos.security.credentials import CredentialAccessMode

_MODEL_DISCOVERY_MAX_RESPONSE_BYTES = 1_048_576
_MODEL_DISCOVERY_MAX_MODELS = 1_024
_MODEL_ID_MAX_LENGTH = 256
_MAX_USAGE_TOKENS = 1_000_000_000
_MAX_RETRY_DELAY_SECONDS = 30.0
_MAX_OBSERVATION_TEXT_BYTES = 256
_SAFE_RATE_LIMIT_HEADERS = frozenset(
    {
        "retry-after",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
)
_REQUEST_ID_HEADERS = (
    "x-request-id",
    "x-siliconflow-request-id",
    "request-id",
)
_BEARER_PATTERN = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+")
_API_KEY_PATTERN = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b")


@dataclass(frozen=True, slots=True)
class ProviderRequestObservation:
    """Bounded, credential-free metadata for one provider HTTP attempt."""

    provider: str
    model: str
    attempt: int
    max_attempts: int
    status_code: int | None
    started_at: str
    latency_ms: int | None
    first_byte_latency_ms: int | None
    retryable: bool
    retry_after_seconds: float | None = None
    retry_delay_ms: int | None = None
    request_id: str | None = None
    rate_limit_headers: tuple[tuple[str, str], ...] = ()
    provider_error_type: str | None = None
    provider_error_code: str | None = None
    provider_message: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    total_tokens: int | None = None
    response_model: str | None = None

    def __post_init__(self) -> None:
        for name in ("provider", "model", "started_at"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"provider observation {name} is invalid")
        for name in ("attempt", "max_attempts"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"provider observation {name} is invalid")
        if self.attempt > self.max_attempts:
            raise ValueError("provider observation attempt exceeds max_attempts")
        if self.status_code is not None and (
            type(self.status_code) is not int or not 100 <= self.status_code <= 599
        ):
            raise ValueError("provider observation status_code is invalid")
        for name in ("latency_ms", "first_byte_latency_ms", "retry_delay_ms"):
            value = getattr(self, name)
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"provider observation {name} is invalid")
        if type(self.retryable) is not bool:
            raise ValueError("provider observation retryable is invalid")
        if self.retry_after_seconds is not None and (
            type(self.retry_after_seconds) not in {int, float}
            or not math.isfinite(float(self.retry_after_seconds))
            or not 0 <= float(self.retry_after_seconds) <= _MAX_RETRY_DELAY_SECONDS
        ):
            raise ValueError("provider observation retry_after_seconds is invalid")
        if not isinstance(self.rate_limit_headers, tuple):
            raise TypeError("provider observation rate_limit_headers is invalid")
        for name, value in self.rate_limit_headers:
            if not isinstance(name, str) or not isinstance(value, str):
                raise TypeError("provider observation rate_limit_headers is invalid")
            if name not in _SAFE_RATE_LIMIT_HEADERS:
                raise ValueError("provider observation contains an unsafe header")
            if len(value.encode("utf-8")) > _MAX_OBSERVATION_TEXT_BYTES:
                raise ValueError("provider observation header value is too large")
        for name in (
            "request_id",
            "provider_error_type",
            "provider_error_code",
            "provider_message",
        ):
            value = getattr(self, name)
            if value is not None and len(value.encode("utf-8")) > _MAX_OBSERVATION_TEXT_BYTES:
                raise ValueError(f"provider observation {name} is too large")
        for name in ("input_tokens", "output_tokens", "total_tokens"):
            value = getattr(self, name)
            if value is not None and (
                type(value) is not int
                or value < 0
                or value > _MAX_USAGE_TOKENS
            ):
                raise ValueError(f"provider observation {name} is invalid")
        if self.response_model is not None:
            if not isinstance(self.response_model, str) or not self.response_model.strip():
                raise ValueError("provider observation response_model is invalid")
            if len(self.response_model) > _MODEL_ID_MAX_LENGTH or any(
                ord(char) < 0x20 or ord(char) == 0x7F
                for char in self.response_model
            ):
                raise ValueError("provider observation response_model is invalid")

    def to_payload(self) -> dict[str, object]:
        """Return only the bounded fields safe for a diagnostic report."""

        return {
            "provider": self.provider,
            "model": self.model,
            "attempt": self.attempt,
            "max_attempts": self.max_attempts,
            "status_code": self.status_code,
            "started_at": self.started_at,
            "latency_ms": self.latency_ms,
            "first_byte_latency_ms": self.first_byte_latency_ms,
            "retryable": self.retryable,
            "retry_after_seconds": self.retry_after_seconds,
            "retry_delay_ms": self.retry_delay_ms,
            "request_id": self.request_id,
            "rate_limit_headers": dict(self.rate_limit_headers),
            "provider_error_type": self.provider_error_type,
            "provider_error_code": self.provider_error_code,
            "provider_message": self.provider_message,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "response_model": self.response_model,
        }


class ModelClient:
    """OpenAI-compatible chat completions client with SSE streaming."""

    def __init__(
        self,
        http_client: httpx.AsyncClient | None = None,
        max_retries: int = 3,
        base_delay: float = 0.1,
        request_observer: Callable[[ProviderRequestObservation], None] | None = None,
        max_retry_delay: float = _MAX_RETRY_DELAY_SECONDS,
        credential_broker: CredentialBroker | None = None,
    ):
        if type(max_retries) is not int or max_retries <= 0:
            raise ValueError("max_retries must be positive")
        if (
            type(base_delay) not in {int, float}
            or not math.isfinite(float(base_delay))
            or base_delay < 0
        ):
            raise ValueError("base_delay must be finite and non-negative")
        if (
            type(max_retry_delay) not in {int, float}
            or not math.isfinite(float(max_retry_delay))
            or not 0 < max_retry_delay <= _MAX_RETRY_DELAY_SECONDS
        ):
            raise ValueError("max_retry_delay is outside the bounded range")
        self.http_client = http_client
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.request_observer = request_observer
        self.max_retry_delay = float(max_retry_delay)
        self.credential_broker = credential_broker

    async def stream_chat(
        self,
        provider: ProviderConfig,
        model: ModelSpec,
        messages: list[Message],
        tools: list[dict] | None = None,
    ) -> AsyncIterator[Message]:
        """Stream chat completions as Khaos Message chunks."""
        payload: dict[str, Any] = {
            "model": model.model,
            "messages": _serialize_messages(provider, messages),
            "stream": True,
            "max_tokens": model.max_output_tokens,
        }
        if tools and model.supports_tools:
            payload["tools"] = tools

        headers = self._provider_headers(
            provider,
            model=model,
            operation="provider.request",
            accept="text/event-stream",
        )

        url = provider.base_url.rstrip("/") + "/chat/completions"
        client = self.http_client or httpx.AsyncClient(timeout=provider.timeout)
        should_close = self.http_client is None
        try:
            async for message in self._stream_with_retries(
                client,
                url,
                headers,
                payload,
                provider_name=provider.name,
            ):
                yield message
        finally:
            if should_close:
                await client.aclose()

    async def list_models(
        self,
        provider: ProviderConfig,
        *,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> list[DiscoveredModel]:
        """Discover models through the provider's OpenAI-compatible catalog.

        The response is deliberately bounded and reduced to validated
        metadata before it reaches setup/UI code.  Error messages contain no
        response body, because a provider must never be able to echo a
        credential into durable or user-visible diagnostics.
        """
        try:
            access_mode = CredentialAccessMode(access_mode)
        except ValueError as exc:
            raise ProviderError("provider credential access mode is invalid") from exc
        headers = self._provider_headers(
            provider,
            model=None,
            operation="provider.discovery",
            accept="application/json",
            access_mode=access_mode,
        )

        url = provider.base_url.rstrip("/") + "/models"
        client = self.http_client or httpx.AsyncClient(timeout=provider.timeout)
        should_close = self.http_client is None
        try:
            try:
                async with client.stream("GET", url, headers=headers) as response:
                    if response.status_code == 429:
                        raise ModelRateLimitError("model provider rate limited")
                    if response.is_error:
                        raise ProviderError(
                            f"model discovery returned HTTP {response.status_code}"
                        )
                    content_length = response.headers.get("content-length")
                    if content_length is not None:
                        try:
                            if int(content_length) > _MODEL_DISCOVERY_MAX_RESPONSE_BYTES:
                                raise ProviderError("model discovery response too large")
                        except ValueError:
                            pass
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(body) + len(chunk) > _MODEL_DISCOVERY_MAX_RESPONSE_BYTES:
                            raise ProviderError("model discovery response too large")
                        body.extend(chunk)
            except httpx.HTTPError as exc:
                raise ProviderError("model discovery request failed") from exc

            try:
                payload = json.loads(bytes(body))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ProviderError("model discovery returned invalid JSON") from exc
            return _parse_model_catalog(provider.name, payload)
        finally:
            if should_close:
                await client.aclose()

    async def _stream_with_retries(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
        payload: dict[str, Any],
        *,
        provider_name: str,
    ) -> AsyncIterator[Message]:
        last_rate_limit: ModelRateLimitError | None = None
        for attempt in range(1, self.max_retries + 1):
            started_monotonic = time.monotonic()
            started_at = datetime.now(UTC).isoformat()
            status_code: int | None = None
            first_byte_monotonic: float | None = None
            retry_after_seconds: float | None = None
            retry_delay_seconds: float | None = None
            request_id: str | None = None
            rate_limit_headers: tuple[tuple[str, str], ...] = ()
            provider_error_type: str | None = None
            provider_error_code: str | None = None
            provider_message: str | None = None
            input_tokens: int | None = None
            output_tokens: int | None = None
            total_tokens: int | None = None
            response_model: str | None = None
            rate_limited = False
            try:
                async with client.stream("POST", url, headers=headers, json=payload) as response:
                    status_code = response.status_code
                    rate_limit_headers = _safe_rate_limit_headers(response.headers, headers.get("Authorization", ""))
                    request_id = _safe_request_id(response.headers, headers.get("Authorization", ""))
                    if response.status_code == 429:
                        rate_limited = True
                        provider_error_type = "rate_limit"
                        provider_message = "model provider rate limited"
                        retry_after_seconds = _parse_retry_after(
                            response.headers.get("Retry-After"),
                            max_delay=self.max_retry_delay,
                        )
                        if attempt < self.max_retries:
                            retry_delay_seconds = (
                                retry_after_seconds
                                if retry_after_seconds is not None
                                else min(
                                    self.max_retry_delay,
                                    self.base_delay * (2 ** (attempt - 1)),
                                )
                            )
                        last_rate_limit = ModelRateLimitError(provider_message)
                    elif response.is_error:
                        provider_error_type = "http_error"
                        provider_message = f"model provider returned HTTP {response.status_code}"
                        raise ProviderError(provider_message)
                    else:
                        parser = _OpenAIStreamParser()
                        async for line in response.aiter_lines():
                            if first_byte_monotonic is None:
                                first_byte_monotonic = time.monotonic()
                            if not line.startswith("data:"):
                                continue
                            data = line.removeprefix("data:").strip()
                            if data == "[DONE]":
                                final = parser.final_tool_message()
                                if final is not None:
                                    yield final
                                yield Message(
                                    role="assistant",
                                    content="",
                                    stop_reason=(
                                        "tool_use"
                                        if final is not None
                                        else parser.stop_reason or "end_turn"
                                    ),
                                )
                                return
                            try:
                                parsed = json.loads(data)
                            except json.JSONDecodeError as exc:
                                raise ProviderError(
                                    "model provider returned invalid stream JSON"
                                ) from exc
                            chunk = parser.parse_payload(parsed)
                            if parser.usage is not None:
                                (
                                    input_tokens,
                                    output_tokens,
                                    total_tokens,
                                ) = parser.usage
                            if parser.response_model is not None:
                                response_model = parser.response_model
                            if chunk is not None:
                                yield chunk
                        final = parser.final_tool_message()
                        if final is not None:
                            yield final
                        yield Message(
                            role="assistant",
                            content="",
                            stop_reason=(
                                "tool_use"
                                if final is not None
                                else parser.stop_reason or "end_turn"
                            ),
                        )
                        return
            except httpx.HTTPError as exc:
                provider_error_type = "transport_error"
                provider_message = "model provider request failed"
                raise ProviderError(provider_message) from exc
            finally:
                self._observe(
                    ProviderRequestObservation(
                        provider=provider_name,
                        model=str(payload.get("model", "unknown")),
                        attempt=attempt,
                        max_attempts=self.max_retries,
                        status_code=status_code,
                        started_at=started_at,
                        latency_ms=int((time.monotonic() - started_monotonic) * 1000),
                        first_byte_latency_ms=(
                            int((first_byte_monotonic - started_monotonic) * 1000)
                            if first_byte_monotonic is not None
                            else None
                        ),
                        retryable=rate_limited,
                        retry_after_seconds=retry_after_seconds,
                        retry_delay_ms=(
                            int(retry_delay_seconds * 1000)
                            if retry_delay_seconds is not None
                            else None
                        ),
                        request_id=request_id,
                        rate_limit_headers=rate_limit_headers,
                        provider_error_type=provider_error_type,
                        provider_error_code=provider_error_code,
                        provider_message=provider_message,
                        input_tokens=input_tokens,
                        output_tokens=output_tokens,
                        total_tokens=total_tokens,
                        response_model=response_model,
                    )
                )
            if rate_limited:
                if attempt < self.max_retries:
                    await asyncio.sleep(retry_delay_seconds or 0)
                    continue
                assert last_rate_limit is not None
                raise last_rate_limit
        assert last_rate_limit is not None
        raise last_rate_limit

    def _observe(self, observation: ProviderRequestObservation) -> None:
        """Deliver safe in-memory metadata without affecting request behavior."""

        if self.request_observer is None:
            return
        try:
            self.request_observer(observation)
        except Exception:  # noqa: BLE001 - diagnostics must never affect provider execution
            # Diagnostics are strictly best effort and must never change the
            # provider or AgentLoop outcome.
            return

    def _provider_headers(
        self,
        provider: ProviderConfig,
        *,
        model: ModelSpec | None,
        operation: str,
        accept: str,
        access_mode: CredentialAccessMode = CredentialAccessMode.RUNTIME,
    ) -> dict[str, str]:
        """Build headers without carrying a provider secret in config."""
        try:
            access_mode = CredentialAccessMode(access_mode)
        except ValueError as exc:
            raise ProviderError("provider credential access mode is invalid") from exc
        headers = {"Accept": accept}
        ref = provider.credential_ref
        if ref is None:
            return headers
        if self.credential_broker is None:
            raise ProviderError("provider credential broker unavailable")
        binding = {
            "provider": provider.name,
            "model": model.model if model is not None else "<catalog>",
            "endpoint": provider.base_url,
            "operation": operation,
        }
        try:
            if access_mode is CredentialAccessMode.PROVISIONING:
                handle = self.credential_broker.issue_provisioning_provider_handle(
                    ref,
                    provider=provider.name,
                    binding=binding,
                    operation=operation,
                )
                self.credential_broker.authorize_provisioning_provider_headers(
                    headers,
                    handle,
                    provider=provider.name,
                    binding=binding,
                    operation=operation,
                )
            else:
                handle = self.credential_broker.issue_provider_handle(
                    ref,
                    provider=provider.name,
                    binding=binding,
                    operation=operation,
                )
                self.credential_broker.authorize_provider_headers(
                    headers,
                    handle,
                    provider=provider.name,
                    binding=binding,
                    operation=operation,
                )
        except CredentialBrokerError as exc:
            code = getattr(exc, "code", None)
            if code == "CREDENTIAL_SESSION_LOCKED":
                message = "provider credential session is locked"
            elif code == "CREDENTIAL_MISSING":
                message = "provider credential is missing"
            else:
                message = "provider credential unavailable"
            raise ProviderError(message, code=code) from exc
        return headers


def _safe_text(value: str, authorization_header: str) -> str:
    """Normalize and redact untrusted provider metadata before observation."""

    normalized = "".join(
        character if ord(character) >= 0x20 and ord(character) != 0x7F else " "
        for character in str(value)
    )
    normalized = " ".join(normalized.split())
    if authorization_header:
        normalized = normalized.replace(authorization_header, "[REDACTED]")
        token = authorization_header.removeprefix("Bearer ").strip()
        if token:
            normalized = normalized.replace(token, "[REDACTED]")
    normalized = _BEARER_PATTERN.sub(r"\1[REDACTED]", normalized)
    normalized = _API_KEY_PATTERN.sub("[REDACTED]", normalized)
    encoded = normalized.encode("utf-8", errors="replace")[:_MAX_OBSERVATION_TEXT_BYTES]
    return encoded.decode("utf-8", errors="ignore")


def _safe_rate_limit_headers(
    headers: httpx.Headers,
    authorization_header: str,
) -> tuple[tuple[str, str], ...]:
    """Keep only a small allowlist of redacted rate-limit headers."""

    values: list[tuple[str, str]] = []
    for name, value in headers.items():
        normalized_name = name.casefold()
        if normalized_name not in _SAFE_RATE_LIMIT_HEADERS:
            continue
        safe_value = _safe_text(value, authorization_header)
        if safe_value:
            values.append((normalized_name, safe_value))
    return tuple(sorted(values))


def _safe_request_id(headers: httpx.Headers, authorization_header: str) -> str | None:
    """Read one bounded request identifier without retaining other headers."""

    for name in _REQUEST_ID_HEADERS:
        value = headers.get(name)
        if value:
            safe_value = _safe_text(value, authorization_header)
            if safe_value:
                return safe_value
    return None


def _parse_retry_after(value: str | None, *, max_delay: float) -> float | None:
    """Parse a bounded delta-seconds or HTTP-date Retry-After value."""

    if not isinstance(value, str) or len(value.encode("utf-8")) > _MAX_OBSERVATION_TEXT_BYTES:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        delay = float(candidate)
    except ValueError:
        try:
            date = parsedate_to_datetime(candidate)
            if date.tzinfo is None:
                date = date.replace(tzinfo=UTC)
            delay = date.timestamp() - time.time()
        except (TypeError, ValueError, OverflowError):
            return None
    if not math.isfinite(delay) or delay < 0:
        return None
    return min(delay, max_delay)


class _OpenAIStreamParser:
    def __init__(self):
        self.tool_calls: dict[int, dict[str, Any]] = {}
        self.stop_reason: str | None = None
        self.usage: tuple[int | None, int | None, int | None] | None = None
        self.response_model: str | None = None

    def parse_payload(self, payload: dict[str, Any]) -> Message | None:
        model_id = _validated_model_id(payload.get("model"))
        if model_id is not None:
            self.response_model = model_id
        usage = _parse_stream_usage(payload.get("usage"))
        if usage is not None:
            self.usage = usage
        choice = (payload.get("choices") or [{}])[0]
        delta = choice.get("delta") or {}
        finish_reason = choice.get("finish_reason")
        if finish_reason:
            self.stop_reason = _map_finish_reason(str(finish_reason))
        if delta.get("tool_calls"):
            self._accumulate_tool_calls(delta["tool_calls"])
        if delta.get("function_call"):
            self._accumulate_legacy_function_call(delta["function_call"])
        # Some OpenAI-compatible providers put a text delta and a tool-call
        # delta in the same SSE choice.  Accumulate the structured call before
        # returning the text so the later terminal_tool_message() still has a
        # complete call to dispatch.
        content = delta.get("content")
        if content:
            return Message(role="assistant", content=str(content))
        return None

    def final_tool_message(self) -> Message | None:
        if not self.tool_calls:
            return None
        calls = []
        for index in sorted(self.tool_calls):
            call = self.tool_calls[index]
            function = call.get("function", {})
            raw_arguments = function.get("arguments", "") or "{}"
            try:
                arguments = json.loads(raw_arguments)
            except json.JSONDecodeError:
                arguments = {"_raw": raw_arguments}
            calls.append(
                {
                    "id": call.get("id") or f"call_{index}",
                    "name": function.get("name", ""),
                    "arguments": arguments,
                }
            )
        return Message(role="assistant", content="", tool_calls=calls, stop_reason="tool_use")

    def _accumulate_tool_calls(self, chunks: list[dict[str, Any]]) -> None:
        for chunk in chunks:
            index = int(chunk.get("index", 0))
            target = self.tool_calls.setdefault(index, {"function": {"name": "", "arguments": ""}})
            if chunk.get("id"):
                target["id"] = chunk["id"]
            function = chunk.get("function") or {}
            if function.get("name"):
                target["function"]["name"] += function["name"]
            if function.get("arguments"):
                target["function"]["arguments"] += function["arguments"]

    def _accumulate_legacy_function_call(self, chunk: dict[str, str]) -> None:
        target = self.tool_calls.setdefault(0, {"id": "function_call", "function": {"name": "", "arguments": ""}})
        if chunk.get("name"):
            target["function"]["name"] += chunk["name"]
        if chunk.get("arguments"):
            target["function"]["arguments"] += chunk["arguments"]


def _parse_stream_usage(
    value: Any,
) -> tuple[int | None, int | None, int | None] | None:
    """Parse only bounded numeric usage fields from an untrusted SSE chunk."""

    if not isinstance(value, dict):
        return None
    result: tuple[int | None, int | None, int | None] = (
        _parse_usage_value(value.get("prompt_tokens")),
        _parse_usage_value(value.get("completion_tokens")),
        _parse_usage_value(value.get("total_tokens")),
    )
    return result if any(item is not None for item in result) else None


def _parse_usage_value(value: object) -> int | None:
    """Return one bounded provider usage value, rejecting malformed values."""

    return (
        value
        if type(value) is int and 0 <= value <= _MAX_USAGE_TOKENS
        else None
    )


def _message_to_openai(message: Message) -> dict[str, Any]:
    if message.role == "tool":
        return {
            "role": "tool",
            "tool_call_id": message.tool_call_id or "",
            "content": message.content,
        }
    item: dict[str, Any] = {"role": message.role, "content": message.content}
    if message.tool_calls:
        item["tool_calls"] = [
            {
                "id": call.get("id"),
                "type": "function",
                "function": {
                    "name": call.get("name"),
                    "arguments": json.dumps(call.get("arguments", {}), ensure_ascii=False),
                },
            }
            for call in message.tool_calls
        ]
    return item


def _serialize_messages(
    provider: ProviderConfig,
    messages: list[Message],
) -> list[dict[str, Any]]:
    """Serialize Khaos messages using the provider's wire compatibility profile."""
    if provider.supports_multiple_system_messages:
        return [_message_to_openai(message) for message in messages]

    system_messages = [message for message in messages if message.role == "system"]
    if len(system_messages) <= 1:
        return [_message_to_openai(message) for message in messages]
    if any(message.tool_calls for message in system_messages):
        raise ProviderError(
            "provider does not support merging system messages with tool calls"
        )

    first_system_index = next(
        index for index, message in enumerate(messages) if message.role == "system"
    )
    merged_system = {
        "role": "system",
        "content": "\n\n".join(message.content for message in system_messages),
    }
    serialized: list[dict[str, Any]] = []
    inserted = False
    for index, message in enumerate(messages):
        if message.role == "system":
            if not inserted and index == first_system_index:
                serialized.append(merged_system)
                inserted = True
            continue
        serialized.append(_message_to_openai(message))
    return serialized


def _parse_model_catalog(provider_name: str, payload: Any) -> list[DiscoveredModel]:
    """Validate an OpenAI-compatible model catalog without retaining raw data."""
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ProviderError("model discovery returned an invalid catalog")

    models: list[DiscoveredModel] = []
    seen: set[str] = set()
    for item in payload["data"][:_MODEL_DISCOVERY_MAX_MODELS]:
        if isinstance(item, str):
            model_id = _validated_model_id(item)
            metadata: dict[str, Any] = {}
        elif isinstance(item, dict):
            model_id = _validated_model_id(item.get("id"))
            metadata = item
        else:
            continue
        if model_id is None or model_id in seen:
            continue
        seen.add(model_id)
        models.append(
            DiscoveredModel(
                provider=provider_name,
                model=model_id,
                max_context_tokens=_optional_positive_int(
                    metadata,
                    "max_context_tokens",
                    "context_length",
                    "max_context_length",
                ),
                supports_tools=(
                    metadata.get("supports_tools")
                    if isinstance(metadata.get("supports_tools"), bool)
                    else None
                ),
                owned_by=_optional_metadata_string(metadata.get("owned_by")),
            )
        )

    if len(payload["data"]) > _MODEL_DISCOVERY_MAX_MODELS:
        raise ProviderError("model discovery returned too many models")
    if not models:
        raise ProviderError("model discovery returned no valid models")
    return sorted(models, key=lambda model: model.model.casefold())


def _validated_model_id(value: Any) -> str | None:
    """Return a bounded printable model identifier or ``None``."""
    if not isinstance(value, str):
        return None
    model_id = value.strip()
    if not model_id or len(model_id) > _MODEL_ID_MAX_LENGTH:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in model_id):
        return None
    return model_id


def _optional_positive_int(metadata: dict[str, Any], *keys: str) -> int | None:
    """Read a bounded positive integer hint from provider metadata."""
    for key in keys:
        value = metadata.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 1_000_000_000:
            return value
    return None


def _optional_metadata_string(value: Any) -> str | None:
    """Keep only short printable owner metadata for in-memory display."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if not value or len(value) > 128:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    return value


def _map_finish_reason(finish_reason: str) -> str:
    if finish_reason in {"tool_calls", "function_call"}:
        return "tool_use"
    if finish_reason == "length":
        return "max_tokens"
    return "end_turn"
