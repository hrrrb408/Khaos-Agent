"""Unified message dispatcher across multiple channels."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import stat
from pathlib import Path

from khaos.channels.models import ChannelType, DeliveryResult, Message
from khaos.time_utils import utc_now_naive

logger = logging.getLogger(__name__)
_LOG_TARGET = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


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
            except Exception as exc:  # noqa: BLE001 - channel backends report delivery failure
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
        self._log_dir = Path(log_dir).expanduser()
        self._log_dir.mkdir(parents=True, exist_ok=True)

    async def send(self, message: Message) -> DeliveryResult:
        try:
            logical_name = _validate_log_target(message.target)
        except ValueError as exc:
            return DeliveryResult(
                success=False,
                channel="log_file",
                target=message.target,
                error=str(exc),
            )
        path = self._log_dir / f"{logical_name}.log"
        try:
            await asyncio.to_thread(
                _append_log_line, self._log_dir, f"{logical_name}.log", message.content
            )
            return DeliveryResult(
                success=True,
                channel="log_file",
                target=str(path),
            )
        except Exception as exc:  # noqa: BLE001 - file delivery must return a result
            return DeliveryResult(
                success=False,
                channel="log_file",
                target=str(path),
                error=str(exc),
            )


def _validate_log_target(target: str) -> str:
    """Validate a logical file name before it reaches the filesystem."""
    logical_name = target or "default"
    if (
        type(logical_name) is not str
        or not _LOG_TARGET.fullmatch(logical_name)
        or logical_name in {".", ".."}
        or ".." in logical_name
    ):
        raise ValueError("log target must be a simple logical name")
    return logical_name


def _append_log_line(log_dir: Path, file_name: str, content: str) -> None:
    """Append through a directory fd so the logical name cannot escape it."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | no_follow
    directory_fd = os.open(str(log_dir), directory_flags)
    file_fd = -1
    try:
        if not no_follow or os.open not in getattr(os, "supports_dir_fd", set()):
            # A path-only fallback cannot close the symlink-swap race between
            # validation and open. Refuse delivery on platforms without the
            # dirfd/no-follow primitive instead of becoming a filesystem
            # deputy for the caller.
            raise OSError("log target requires dirfd no-follow support")
        file_fd = os.open(file_name, flags | no_follow, 0o600, dir_fd=directory_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError("log target is not a single regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(file_fd, 0o600)
        with os.fdopen(file_fd, "a", encoding="utf-8", closefd=True) as file:
            file_fd = -1
            ts = utc_now_naive().isoformat()
            file.write(f"[{ts}] {content}\n")
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        os.close(directory_fd)


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
        except Exception as exc:  # noqa: BLE001 - memory adapters report delivery failure
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
                reply_to_id=message.reply_to_id,
                parse_mode=message.parse_mode,
            )
            results.extend(await self.dispatch(message_copy))
        return results

    def has_channel(self, channel_type: ChannelType) -> bool:
        return channel_type in self._channels
