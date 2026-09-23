import asyncio
import json

import httpx
import pytest
from khaos.agent import Message
from khaos.agent.error_handler import ModelRateLimitError
from khaos.routing.model_client import (
    ModelClient,
    ProviderRequestObservation,
    _OpenAIStreamParser,
)
from khaos.routing.provider import ModelSpec, ProviderConfig
from khaos.routing.providers.base import ProviderError
from khaos.security.credential_broker import CredentialBroker
from khaos.security.credentials import (
    CredentialRef,
    InMemoryCredentialStore,
    SecretValue,
)


def _sse(payloads: list[dict]) -> bytes:
    lines = [f"data: {json.dumps(payload)}\n\n" for payload in payloads]
    lines.append("data: [DONE]\n\n")
    return "".join(lines).encode("utf-8")


def _authenticated_provider(
    name: str, base_url: str, secret: str = "secret"
) -> tuple[CredentialBroker, ProviderConfig]:
    broker = CredentialBroker()
    ref = CredentialRef.for_provider(name, name="test")
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider=name)
    broker.put_provider_credential(ref, SecretValue(secret), provider=name)
    return broker, ProviderConfig(name, base_url, credential_ref=ref)


async def test_model_client_streams_text_chunks():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        body = json.loads(request.content)
        assert body["model"] == "qwen/qwen3-8b"
        assert body["max_tokens"] == 2048
        return httpx.Response(
            200,
            content=_sse(
                [
                    {"choices": [{"delta": {"content": "hello "}}]},
                    {"choices": [{"delta": {"content": "world"}, "finish_reason": "stop"}]},
                ]
            ),
        )

    broker, provider = _authenticated_provider(
        "nvidia", "https://integrate.api.nvidia.com/v1"
    )
    try:
        client = ModelClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            credential_broker=broker,
        )
        chunks = [
            chunk
            async for chunk in client.stream_chat(
                provider,
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768, max_output_tokens=2048),
                [Message("user", "hi")],
            )
        ]
    finally:
        broker.close()

    assert "".join(chunk.content for chunk in chunks if chunk.content) == "hello world"
    assert chunks[-1].stop_reason == "end_turn"


async def test_model_client_observes_stream_usage_without_response_body():
    observations: list[ProviderRequestObservation] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {
                        "model": "glm-5.3-flash",
                        "choices": [{"delta": {"content": "ACK"}}],
                    },
                    {
                        "model": "glm-5.3-flash",
                        "choices": [{"delta": {}, "finish_reason": "stop"}],
                        "usage": {
                            "prompt_tokens": 11,
                            "completion_tokens": 7,
                            "total_tokens": 18,
                            "prompt_tokens_details": {"cached_tokens": 3},
                        },
                    },
                ]
            ),
        )

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        request_observer=observations.append,
    )
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("zhipu-coding", "https://example.test/v1"),
            ModelSpec("zhipu-coding", "glm-5.3-flash", 128000),
            [Message("user", "ack")],
        )
    ]

    assert "".join(chunk.content for chunk in chunks if chunk.content) == "ACK"
    assert len(observations) == 1
    observation = observations[0]
    assert observation.input_tokens == 11
    assert observation.output_tokens == 7
    assert observation.total_tokens == 18
    assert observation.response_model == "glm-5.3-flash"
    assert observation.to_payload()["response_model"] == "glm-5.3-flash"
    assert "prompt_tokens_details" not in json.dumps(observation.to_payload())


async def test_model_client_rejects_unbounded_stream_usage_fields():
    observations: list[ProviderRequestObservation] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {
                        "choices": [{"delta": {"content": "ok"}}],
                        "usage": {
                            "prompt_tokens": 1_000_000_001,
                            "completion_tokens": "7",
                            "total_tokens": True,
                        },
                    }
                ]
            ),
        )

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        request_observer=observations.append,
    )
    [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen", 32768),
            [Message("user", "ack")],
        )
    ]

    assert len(observations) == 1
    assert observations[0].input_tokens is None
    assert observations[0].output_tokens is None
    assert observations[0].total_tokens is None


async def test_model_client_parses_tool_calls():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_1",
                                            "function": {"name": "read_file", "arguments": "{\"path\""},
                                        }
                                    ]
                                }
                            }
                        ]
                    },
                    {
                        "choices": [
                            {
                                "delta": {"tool_calls": [{"index": 0, "function": {"arguments": ":\"a.txt\"}"}}]},
                                "finish_reason": "tool_calls",
                            }
                        ]
                    },
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "read")],
        )
    ]

    tool_message = next(chunk for chunk in chunks if chunk.tool_calls)
    assert tool_message.stop_reason == "tool_use"
    assert tool_message.tool_calls == [{"id": "call_1", "name": "read_file", "arguments": {"path": "a.txt"}}]


def test_openai_stream_parser_keeps_tool_call_when_delta_also_has_content():
    parser = _OpenAIStreamParser()

    content = parser.parse_payload(
        {
            "choices": [
                {
                    "delta": {
                        "content": "I will inspect the file.",
                        "tool_calls": [
                            {
                                "index": 0,
                                "id": "call_1",
                                "function": {
                                    "name": "read_file",
                                    "arguments": '{"path":"a.txt"}',
                                },
                            }
                        ],
                    }
                }
            ]
        }
    )

    assert content is not None
    assert content.content == "I will inspect the file."
    assert parser.final_tool_message().tool_calls == [
        {"id": "call_1", "name": "read_file", "arguments": {"path": "a.txt"}}
    ]


async def test_openai_stream_tool_calls_override_misleading_stop_finish_reason():
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            content=_sse(
                [
                    {
                        "choices": [
                            {
                                "delta": {
                                    "tool_calls": [
                                        {
                                            "index": 0,
                                            "id": "call_stop",
                                            "function": {
                                                "name": "read_file",
                                                "arguments": '{"path":"a.txt"}',
                                            },
                                        }
                                    ]
                                },
                                "finish_reason": "stop",
                            }
                        ]
                    }
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "read")],
        )
    ]

    assert any(chunk.tool_calls for chunk in chunks)
    assert chunks[-1].stop_reason == "tool_use"


async def test_siliconflow_merges_multiple_system_messages_at_wire_boundary():
    request_body: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        request_body.update(json.loads(request.content))
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("siliconflow", "https://example.test/v1"),
            ModelSpec("siliconflow", "Qwen/Qwen3.5-27B", 128000),
            [
                Message("system", "first policy"),
                Message("user", "task"),
                Message("system", "second policy"),
                Message("user", "follow-up"),
            ],
        )
    ]

    assert [message["role"] for message in request_body["messages"]] == [
        "system",
        "user",
        "user",
    ]
    assert request_body["messages"][0]["content"] == "first policy\n\nsecond policy"
    assert [message["content"] for message in request_body["messages"][1:]] == [
        "task",
        "follow-up",
    ]
    assert chunks[-1].stop_reason == "end_turn"


async def test_other_providers_preserve_multiple_system_messages():
    request_body: dict = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        request_body.update(json.loads(request.content))
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [
                Message("system", "first policy"),
                Message("user", "task"),
                Message("system", "second policy"),
                Message("user", "follow-up"),
            ],
        )
    ]

    assert [message["role"] for message in request_body["messages"]] == [
        "system",
        "user",
        "system",
        "user",
    ]
    assert [message["content"] for message in request_body["messages"]] == [
        "first policy",
        "task",
        "second policy",
        "follow-up",
    ]


async def test_siliconflow_rejects_system_tool_calls_instead_of_dropping_them():
    requests = 0

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(200, content=_sse([]))

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    with pytest.raises(ProviderError, match="merging system messages"):
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("siliconflow", "https://example.test/v1"),
                ModelSpec("siliconflow", "Qwen/Qwen3.5-27B", 128000),
                [
                    Message(
                        "system",
                        "policy",
                        tool_calls=[{"id": "call_1", "name": "unexpected", "arguments": {}}],
                    ),
                    Message("system", "another policy"),
                    Message("user", "task"),
                ],
            )
        ]

    assert requests == 0


async def test_model_client_maps_length_finish_reason_to_max_tokens():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=_sse(
                [
                    {"choices": [{"delta": {"content": "truncated"}, "finish_reason": "length"}]},
                ]
            ),
        )

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "hi")],
        )
    ]

    assert chunks[0].content == "truncated"
    assert chunks[-1].stop_reason == "max_tokens"


async def test_model_client_retries_429_then_succeeds():
    calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, content=b"rate limited")
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), base_delay=0)
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "hi")],
        )
    ]

    assert calls == 2
    assert chunks[0].content == "ok"


async def test_model_client_raises_after_429_budget():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"rate limited")

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)), max_retries=2, base_delay=0)

    with pytest.raises(ModelRateLimitError):
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("nvidia", "https://example.test/v1"),
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                [Message("user", "hi")],
            )
        ]


async def test_model_client_observes_bounded_rate_limit_metadata_without_secrets():
    calls = 0
    observations: list[ProviderRequestObservation] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        assert request.headers["authorization"] == "Bearer secret"
        if calls == 1:
            return httpx.Response(
                429,
                headers={
                    "Retry-After": "0",
                    "X-RateLimit-Limit": "10",
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": "123",
                    "X-Request-ID": "Bearer secret",
                    "X-Not-Allowed": "should not be observed",
                },
                content=b"Bearer secret sk-provider-response-secret-value",
            )
        return httpx.Response(
            200,
            headers={"X-Request-ID": "request-2"},
            content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]),
        )

    broker, provider = _authenticated_provider("siliconflow", "https://example.test/v1")
    try:
        client = ModelClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            base_delay=0,
            request_observer=observations.append,
            credential_broker=broker,
        )
        chunks = [
            chunk
            async for chunk in client.stream_chat(
                provider,
                ModelSpec("siliconflow", "Qwen/Qwen3.5-27B", 128000),
                [Message("user", "hi")],
            )
        ]
    finally:
        broker.close()

    assert calls == 2
    assert "".join(chunk.content for chunk in chunks if chunk.content) == "ok"
    assert len(observations) == 2
    first, second = observations
    assert first.provider == "siliconflow"
    assert first.model == "Qwen/Qwen3.5-27B"
    assert first.attempt == 1
    assert first.max_attempts == 3
    assert first.status_code == 429
    assert first.retryable is True
    assert first.retry_after_seconds == 0
    assert first.retry_delay_ms == 0
    assert first.request_id == "[REDACTED]"
    assert dict(first.rate_limit_headers) == {
        "retry-after": "0",
        "x-ratelimit-limit": "10",
        "x-ratelimit-remaining": "0",
        "x-ratelimit-reset": "123",
    }
    assert first.provider_error_type == "rate_limit"
    assert first.provider_message == "model provider rate limited"
    assert "secret" not in json.dumps(first.to_payload())
    assert second.status_code == 200
    assert second.retryable is False
    assert second.request_id == "request-2"
    assert second.first_byte_latency_ms is not None


async def test_model_client_observes_each_bounded_retry_attempt():
    observations: list[ProviderRequestObservation] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, content=b"unbounded body is never retained")

    broker, provider = _authenticated_provider("nvidia", "https://example.test/v1")
    try:
        client = ModelClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            max_retries=3,
            base_delay=0,
            request_observer=observations.append,
            credential_broker=broker,
        )

        with pytest.raises(ModelRateLimitError):
            [
                chunk
                async for chunk in client.stream_chat(
                    provider,
                    ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                    [Message("user", "hi")],
                )
            ]
    finally:
        broker.close()

    assert [(item.attempt, item.max_attempts) for item in observations] == [
        (1, 3),
        (2, 3),
        (3, 3),
    ]
    assert [item.retry_delay_ms for item in observations] == [0, 0, None]
    assert all(item.status_code == 429 for item in observations)
    assert all(item.provider_message == "model provider rate limited" for item in observations)


async def test_model_client_honors_bounded_retry_after_without_waiting_unboundedly():
    calls = 0
    observations: list[ProviderRequestObservation] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "999999"})
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        base_delay=0,
        max_retry_delay=0.01,
        request_observer=observations.append,
    )
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("siliconflow", "https://example.test/v1"),
            ModelSpec("siliconflow", "Qwen/Qwen3.5-27B", 128000),
            [Message("user", "hi")],
        )
    ]

    assert calls == 2
    assert "".join(chunk.content for chunk in chunks if chunk.content) == "ok"
    assert observations[0].retry_after_seconds == 0.01
    assert observations[0].retry_delay_ms == 10


async def test_model_client_cancellation_interrupts_rate_limit_backoff():
    response_started = asyncio.Event()
    observations: list[ProviderRequestObservation] = []

    async def handler(_request: httpx.Request) -> httpx.Response:
        response_started.set()
        return httpx.Response(429, content=b"rate limited")

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        base_delay=1,
        request_observer=observations.append,
    )

    async def consume() -> None:
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("nvidia", "https://example.test/v1"),
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                [Message("user", "hi")],
            )
        ]

    task = asyncio.create_task(consume())
    await asyncio.wait_for(response_started.wait(), timeout=1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert len(observations) == 1
    assert observations[0].status_code == 429


async def test_model_client_observer_failure_does_not_change_provider_result():
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_sse([{"choices": [{"delta": {"content": "ok"}}]}]))

    def broken_observer(_observation: ProviderRequestObservation) -> None:
        raise RuntimeError("diagnostic sink failed")

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        request_observer=broken_observer,
    )
    chunks = [
        chunk
        async for chunk in client.stream_chat(
            ProviderConfig("nvidia", "https://example.test/v1"),
            ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
            [Message("user", "hi")],
        )
    ]

    assert "".join(chunk.content for chunk in chunks if chunk.content) == "ok"


async def test_model_client_http_errors_redact_response_body():
    leaked_value = "provider-response-secret-value"

    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        return httpx.Response(401, json={"error": {"message": leaked_value}})

    client = ModelClient(httpx.AsyncClient(transport=httpx.MockTransport(handler)))

    with pytest.raises(ProviderError, match="HTTP 401") as exc_info:
        [
            chunk
            async for chunk in client.stream_chat(
                ProviderConfig("nvidia", "https://example.test/v1"),
                ModelSpec("nvidia", "qwen/qwen3-8b", 32768),
                [Message("user", "hi")],
            )
        ]

    assert leaked_value not in str(exc_info.value)
    assert "error" not in str(exc_info.value)


async def test_model_client_discovers_and_normalizes_models():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v1/models"
        assert request.headers["authorization"] == "Bearer secret"
        return httpx.Response(
            200,
            json={
                "data": [
                    {"id": "zeta", "owned_by": "nvidia", "context_length": 65536},
                    {"id": "alpha", "supports_tools": True},
                    {"id": "zeta"},
                    {"id": "bad\nmodel"},
                    "beta",
                ]
            },
        )

    broker, provider = _authenticated_provider("nvidia", "https://example.test/v1")
    try:
        client = ModelClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            credential_broker=broker,
        )
        models = await client.list_models(provider)
    finally:
        broker.close()

    assert [model.model for model in models] == ["alpha", "beta", "zeta"]
    assert models[0].supports_tools is True
    assert models[2].max_context_tokens == 65536
    assert models[2].owned_by == "nvidia"


async def test_model_client_model_discovery_errors_do_not_echo_response_body():
    leaked_value = "provider-response-secret-value"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": leaked_value}})

    broker, provider = _authenticated_provider("nvidia", "https://example.test/v1")
    try:
        client = ModelClient(
            httpx.AsyncClient(transport=httpx.MockTransport(handler)),
            credential_broker=broker,
        )

        with pytest.raises(ProviderError, match="HTTP 401") as exc_info:
            await client.list_models(provider)
    finally:
        broker.close()

    assert leaked_value not in str(exc_info.value)
