import pytest

from khaos.agent import CompressionLevel, ContextCompressor, Message
from khaos.routing.router import create_default_router


def _messages(count: int, words: int = 20) -> list[Message]:
    return [Message(role="system", content="system")] + [
        Message(role="user" if index % 2 == 0 else "assistant", content="x " * words)
        for index in range(count)
    ]


async def test_micro_compact_truncates_long_message():
    compressor = ContextCompressor(create_default_router(), micro_max_chars=20)
    message = Message(role="user", content="a" * 50)

    compacted = await compressor._micro_compact(message)

    assert "[截断:" in compacted.content
    assert len(compacted.content) < len(message.content) + 50


async def test_system_and_recent_messages_are_preserved():
    messages = _messages(8, words=10)
    compressor = ContextCompressor(create_default_router())

    result = await compressor.compress(messages, threshold=20)

    assert result.messages[0].role == "system"
    assert [message.content for message in result.messages[-4:]] == [
        message.content for message in messages[-4:]
    ]


async def test_context_collapse_creates_required_summary_format():
    compressor = ContextCompressor(create_default_router())

    collapsed = await compressor._context_collapse(
        [Message(role="user", content="decide alpha"), Message(role="assistant", content="ok")]
    )

    assert len(collapsed) == 1
    assert collapsed[0].content.startswith("[摘要开始]")
    assert "原始 2 条消息压缩为 1 条" in collapsed[0].content
    assert collapsed[0].content.endswith("[摘要结束]")


async def test_tool_call_and_result_pair_are_preserved():
    call = Message(role="assistant", content="", tool_calls=[{"id": "call_1", "name": "read_file"}])
    result = Message(role="tool", content="result", tool_call_id="call_1")
    compressor = ContextCompressor(create_default_router())

    collapsed = await compressor._context_collapse(
        [Message(role="user", content="old"), call, result, Message(role="assistant", content="done")]
    )

    assert call.tool_calls == collapsed[0].tool_calls
    assert collapsed[1].tool_call_id == "call_1"


async def test_auto_compact_uses_router_summary():
    messages = _messages(8, words=40)
    router = create_default_router()
    router.mock_response = "compressed decision"
    compressor = ContextCompressor(router)

    result = await compressor.compress(messages, threshold=20)

    assert result.level is CompressionLevel.AUTO_COMPACT
    assert "[摘要开始]" in result.messages[1].content
    assert "compressed decision" in result.messages[1].content


async def test_l2_failure_falls_back_to_context_collapse():
    class FailingRouter:
        async def call(self, function, messages):
            raise RuntimeError("model down")
            yield

    compressor = ContextCompressor(FailingRouter())

    result = await compressor.compress(_messages(8, words=40), threshold=20)

    assert result.level is CompressionLevel.CONTEXT_COLLAPSE
    assert compressor._consecutive_l2_failures == 1


async def test_circuit_opens_after_three_l2_failures():
    class FailingRouter:
        async def call(self, function, messages):
            raise RuntimeError("model down")
            yield

    compressor = ContextCompressor(FailingRouter())
    for _ in range(3):
        await compressor.compress(_messages(8, words=40), threshold=20)

    assert compressor.is_circuit_open


async def test_open_circuit_skips_l2():
    class CountingRouter:
        def __init__(self):
            self.calls = 0

        async def call(self, function, messages):
            self.calls += 1
            yield Message(role="assistant", content="summary")

    router = CountingRouter()
    compressor = ContextCompressor(router)
    compressor._consecutive_l2_failures = 3

    result = await compressor.compress(_messages(8, words=40), threshold=20)

    assert result.level is CompressionLevel.CONTEXT_COLLAPSE
    assert router.calls == 0


async def test_compressed_tokens_decrease():
    messages = _messages(12, words=80)
    compressor = ContextCompressor(create_default_router())

    result = await compressor.compress(messages, threshold=50)

    assert result.compressed_tokens < result.original_tokens


async def test_no_middle_messages_returns_micro_result():
    messages = _messages(3, words=5)
    compressor = ContextCompressor(create_default_router())

    result = await compressor.compress(messages, threshold=1)

    assert result.level is CompressionLevel.MICRO_COMPACT
    assert result.messages == messages


async def test_context_collapse_fallback_to_micro(monkeypatch):
    compressor = ContextCompressor(create_default_router())

    async def fail(messages):
        raise RuntimeError("collapse failed")

    monkeypatch.setattr(compressor, "_context_collapse", fail)
    compressor._consecutive_l2_failures = 3

    result = await compressor.compress(_messages(8, words=40), threshold=20)

    assert result.level is CompressionLevel.MICRO_COMPACT


def test_extract_key_decisions_limits_empty_input():
    from khaos.agent.compressor import extract_key_decisions

    assert extract_key_decisions([Message(role="user", content="")]) == "无明确关键决策"

