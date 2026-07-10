"""Unified message dispatcher across multiple channels."""

from __future__ import annotations

import logging

from khaos.channels.models import ChannelType, DeliveryResult, Message

logger = logging.getLogger(__name__)


class Channel:
    """消息通道基类。"""

    channel_type: ChannelType = ChannelType.WEBSOCKET

    async def send(self, message: Message) -> DeliveryResult:
        raise NotImplementedError


class WebSocketChannel(Channel):
    """通过 Go 网关的 WebSocket 推送。"""

    channel_type = ChannelType.WEBSOCKET

    def __init__(self, gateway_ws=None):
        self._ws = gateway_ws

    async def send(self, message: Message) -> DeliveryResult:
        if self._ws:
            try:
                await self._ws.send(message.content, target=message.target)
                return DeliveryResult(
                    success=True,
                    channel="websocket",
                    target=message.target,
                )
            except Exception as exc:
                return DeliveryResult(
                    success=False,
                    channel="websocket",
                    target=message.target,
                    error=str(exc),
                )
        return DeliveryResult(
            success=False,
            channel="websocket",
            target=message.target,
            error="no websocket connection",
        )


class LogFileChannel(Channel):
    """写入日志文件。"""

    channel_type = ChannelType.LOG_FILE

    def __init__(self, log_dir: str = "~/.khaos/logs"):
        from pathlib import Path

        self._log_dir = Path(log_dir).expanduser()
        self._log_dir.mkdir(parents=True, exist_ok=True)

    async def send(self, message: Message) -> DeliveryResult:
        from datetime import datetime

        path = self._log_dir / f"{message.target or 'default'}.log"
        try:
            with open(path, "a", encoding="utf-8") as f:
                ts = datetime.utcnow().isoformat()
                f.write(f"[{ts}] {message.content}\n")
            return DeliveryResult(
                success=True,
                channel="log_file",
                target=str(path),
            )
        except Exception as exc:
            return DeliveryResult(
                success=False,
                channel="log_file",
                target=str(path),
                error=str(exc),
            )


class MemoryChannel(Channel):
    """写入记忆存储（用于定时任务结果回写）。"""

    channel_type = ChannelType.MEMORY

    def __init__(self, memory_store=None):
        self._store = memory_store

    async def send(self, message: Message) -> DeliveryResult:
        if not self._store:
            return DeliveryResult(
                success=False,
                channel="memory",
                target="",
                error="no memory store",
            )
        try:
            from khaos.memory import Memory, MemoryScope

            await self._store.set(
                Memory(
                    id=None,
                    scope=MemoryScope.GLOBAL,
                    key=f"cron_result:{message.target}",
                    value=message.content[:500],
                )
            )
            return DeliveryResult(
                success=True,
                channel="memory",
                target=message.target,
            )
        except Exception as exc:
            return DeliveryResult(
                success=False,
                channel="memory",
                target=message.target,
                error=str(exc),
            )


class MessageDispatcher:
    """统一消息分发器。"""

    def __init__(self):
        self._channels: dict[ChannelType, Channel] = {}

    def register(self, channel: Channel) -> None:
        self._channels[channel.channel_type] = channel

    async def dispatch(self, message: Message) -> list[DeliveryResult]:
        """发送消息到目标通道。"""
        channel = self._channels.get(message.channel)
        if not channel:
            logger.warning("no channel registered for %s", message.channel)
            return [
                DeliveryResult(
                    success=False,
                    channel=message.channel.value,
                    target=message.target,
                    error="channel not registered",
                )
            ]
        result = await channel.send(message)
        return [result]

    async def dispatch_multi(
        self, message: Message, channels: list[ChannelType]
    ) -> list[DeliveryResult]:
        """发送到多个通道（如同时推送 WebSocket + 日志）。"""
        results: list[DeliveryResult] = []
        for ch_type in channels:
            message_copy = Message(
                content=message.content,
                channel=ch_type,
                target=message.target,
                metadata=message.metadata,
                media_paths=message.media_paths,
            )
            results.extend(await self.dispatch(message_copy))
        return results

    def has_channel(self, channel_type: ChannelType) -> bool:
        return channel_type in self._channels
