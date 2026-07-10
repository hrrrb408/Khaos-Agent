"""Tests for the multi-channel message dispatcher."""

from __future__ import annotations

from pathlib import Path

from khaos.channels import (
    ChannelType,
    DeliveryResult,
    LogFileChannel,
    Message,
    MessageDispatcher,
    MemoryChannel,
    WebSocketChannel,
)


# ---------------------------------------------------------------------------
# Message dataclass
# ---------------------------------------------------------------------------


def test_message_dataclass() -> None:
    msg = Message(content="hello", channel=ChannelType.LOG_FILE, target="job1")
    assert msg.content == "hello"
    assert msg.channel == ChannelType.LOG_FILE
    assert msg.target == "job1"
    assert msg.metadata == {}
    assert msg.media_paths == []
    # Defaults.
    default = Message(content="x")
    assert default.channel == ChannelType.WEBSOCKET


# ---------------------------------------------------------------------------
# WebSocket channel
# ---------------------------------------------------------------------------


class _FakeWS:
    def __init__(self):
        self.sent: list[tuple[str, str]] = []

    async def send(self, content: str, target: str = "") -> None:
        self.sent.append((content, target))


async def test_dispatch_to_websocket() -> None:
    ws = _FakeWS()
    dispatcher = MessageDispatcher()
    dispatcher.register(WebSocketChannel(gateway_ws=ws))

    results = await dispatcher.dispatch(
        Message(content="hi", channel=ChannelType.WEBSOCKET, target="sess1")
    )

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].channel == "websocket"
    assert ws.sent == [("hi", "sess1")]


async def test_websocket_no_connection() -> None:
    """WebSocketChannel with no gateway_ws reports a failure."""
    dispatcher = MessageDispatcher()
    dispatcher.register(WebSocketChannel())

    results = await dispatcher.dispatch(Message(content="x", channel=ChannelType.WEBSOCKET))

    assert results[0].success is False
    assert "no websocket connection" in results[0].error


# ---------------------------------------------------------------------------
# LogFile channel
# ---------------------------------------------------------------------------


async def test_dispatch_to_log_file(tmp_path: Path) -> None:
    dispatcher = MessageDispatcher()
    dispatcher.register(LogFileChannel(log_dir=str(tmp_path / "logs")))

    results = await dispatcher.dispatch(
        Message(content="cron done", channel=ChannelType.LOG_FILE, target="job42")
    )

    assert results[0].success is True
    assert results[0].channel == "log_file"
    log_file = tmp_path / "logs" / "job42.log"
    assert log_file.is_file()
    assert "cron done" in log_file.read_text()


def test_log_file_channel_creates_dir(tmp_path: Path) -> None:
    """The log dir is auto-created on channel init."""
    target = tmp_path / "deep" / "nested" / "logs"
    channel = LogFileChannel(log_dir=str(target))
    assert target.is_dir()


# ---------------------------------------------------------------------------
# Memory channel
# ---------------------------------------------------------------------------


class _FakeStore:
    def __init__(self):
        self.records: list = []

    async def set(self, memory):
        self.records.append(memory)
        memory.id = len(self.records)


async def test_dispatch_to_memory() -> None:
    store = _FakeStore()
    dispatcher = MessageDispatcher()
    dispatcher.register(MemoryChannel(memory_store=store))

    results = await dispatcher.dispatch(
        Message(content="result payload", channel=ChannelType.MEMORY, target="job1")
    )

    assert results[0].success is True
    assert results[0].channel == "memory"
    assert len(store.records) == 1
    assert store.records[0].value == "result payload"


async def test_memory_channel_no_store() -> None:
    dispatcher = MessageDispatcher()
    dispatcher.register(MemoryChannel())

    results = await dispatcher.dispatch(Message(content="x", channel=ChannelType.MEMORY))

    assert results[0].success is False
    assert "no memory store" in results[0].error


# ---------------------------------------------------------------------------
# Dispatcher routing
# ---------------------------------------------------------------------------


async def test_dispatch_unregistered_channel() -> None:
    """Dispatching to a channel nobody registered returns an error result."""
    dispatcher = MessageDispatcher()

    results = await dispatcher.dispatch(Message(content="x", channel=ChannelType.HTTP_CALLBACK))

    assert len(results) == 1
    assert results[0].success is False
    assert "not registered" in results[0].error


async def test_dispatch_multi(tmp_path: Path) -> None:
    """dispatch_multi fans a message out to several channels at once."""
    ws = _FakeWS()
    dispatcher = MessageDispatcher()
    dispatcher.register(WebSocketChannel(gateway_ws=ws))
    dispatcher.register(LogFileChannel(log_dir=str(tmp_path / "logs")))

    results = await dispatcher.dispatch_multi(
        Message(content="multi-msg", target="t1"),
        [ChannelType.WEBSOCKET, ChannelType.LOG_FILE],
    )

    assert len(results) == 2
    assert {r.channel for r in results} == {"websocket", "log_file"}
    assert all(r.success for r in results)
    assert ws.sent == [("multi-msg", "t1")]


def test_has_channel() -> None:
    dispatcher = MessageDispatcher()
    dispatcher.register(LogFileChannel(log_dir=str(Path(__file__).parent / "_tmplogs")))
    assert dispatcher.has_channel(ChannelType.LOG_FILE) is True
    assert dispatcher.has_channel(ChannelType.WEBSOCKET) is False
