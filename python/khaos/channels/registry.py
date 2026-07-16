"""Channel registry with status management and health checks."""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from khaos.channels.dispatcher import Channel
from khaos.channels.models import ChannelType
from khaos.channels.webhook import is_valid_generic_webhook_secret

logger = logging.getLogger(__name__)


class ChannelStatus(Enum):
    DISABLED = "disabled"
    ENABLED = "enabled"
    DEGRADED = "degraded"
    ERROR = "error"
    INITIALIZING = "initializing"


@dataclass
class ChannelConfig:
    channel_type: ChannelType
    enabled: bool = True
    secret: str = ""
    webhook_path: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class ChannelHealth:
    status: ChannelStatus = ChannelStatus.INITIALIZING
    last_ping: float = 0.0
    last_error: str = ""
    total_sent: int = 0
    total_received: int = 0
    total_failed: int = 0
    consecutive_failures: int = 0


@dataclass
class RegisteredChannel:
    id: str
    channel_type: ChannelType
    config: ChannelConfig
    health: ChannelHealth = field(default_factory=ChannelHealth)
    channel: Channel | None = None
    created_at: float = field(default_factory=time.time)

    @property
    def is_healthy(self) -> bool:
        return self.config.enabled and self.health.status != ChannelStatus.ERROR

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled


class ChannelRegistry:
    def __init__(self, health_check_interval: float = 60.0, max_consecutive_failures: int = 5) -> None:
        self._channels: dict[str, RegisteredChannel] = {}
        self._health_check_interval = health_check_interval
        self._max_consecutive_failures = max_consecutive_failures
        self._running = False
        self._health_task: asyncio.Task[None] | None = None

    def register(self, channel_id: str, channel_type: ChannelType, config: ChannelConfig | dict[str, Any] | None = None, channel: Channel | None = None) -> RegisteredChannel:
        if isinstance(config, dict):
            config = ChannelConfig(channel_type=channel_type, **config)
        elif config is None:
            config = ChannelConfig(channel_type=channel_type)
        elif config.channel_type != channel_type:
            raise ValueError("channel config type does not match registered type")
        self._validate_config(config)
        registered = RegisteredChannel(channel_id, channel_type, config, channel=channel)
        self._channels[channel_id] = registered
        return registered

    def unregister(self, channel_id: str) -> bool:
        channel = self._channels.pop(channel_id, None)
        if channel is None:
            return False
        channel.health.status = ChannelStatus.DISABLED
        return True

    def get(self, channel_id: str) -> RegisteredChannel | None:
        return self._channels.get(channel_id)

    def get_by_type(self, channel_type: ChannelType) -> list[RegisteredChannel]:
        return [item for item in self._channels.values() if item.channel_type == channel_type]

    def list_all(self, enabled_only: bool = False) -> list[RegisteredChannel]:
        return [item for item in self._channels.values() if not enabled_only or item.is_enabled]

    def enable(self, channel_id: str) -> bool:
        channel = self.get(channel_id)
        if channel is None:
            return False
        self._validate_config(channel.config)
        channel.config.enabled = True
        channel.health.status = ChannelStatus.ENABLED
        channel.health.consecutive_failures = 0
        return True

    @staticmethod
    def _validate_config(config: ChannelConfig) -> None:
        if (
            config.channel_type == ChannelType.WEBHOOK_IN
            and not is_valid_generic_webhook_secret(config.secret)
        ):
            raise ValueError(
                "generic webhook requires a high-entropy secret of at least 32 characters"
            )

    def disable(self, channel_id: str) -> bool:
        channel = self.get(channel_id)
        if channel is None:
            return False
        channel.config.enabled = False
        channel.health.status = ChannelStatus.DISABLED
        return True

    def record_success(self, channel_id: str, *, received: bool = False) -> None:
        channel = self.get(channel_id)
        if channel is None:
            return
        channel.health.total_received += int(received)
        channel.health.total_sent += int(not received)
        channel.health.consecutive_failures = 0
        channel.health.last_error = ""
        channel.health.last_ping = time.time()
        channel.health.status = ChannelStatus.ENABLED

    def record_failure(self, channel_id: str, error: str = "") -> None:
        channel = self.get(channel_id)
        if channel is None:
            return
        health = channel.health
        health.consecutive_failures += 1
        health.total_failed += 1
        health.last_error = error
        health.last_ping = time.time()
        health.status = ChannelStatus.ERROR if health.consecutive_failures >= self._max_consecutive_failures else ChannelStatus.DEGRADED

    def get_health_report(self) -> list[dict[str, Any]]:
        return [{"id": item.id, "type": item.channel_type.value, "enabled": item.is_enabled, "healthy": item.is_healthy, "status": item.health.status.value, "last_ping": item.health.last_ping, "last_error": item.health.last_error, "total_sent": item.health.total_sent, "total_received": item.health.total_received, "total_failed": item.health.total_failed} for item in self._channels.values()]

    async def start_health_checks(self) -> None:
        if self._running:
            return
        self._running = True
        self._health_task = asyncio.create_task(self._health_loop())

    async def stop_health_checks(self) -> None:
        self._running = False
        if self._health_task is not None:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass
            self._health_task = None

    async def _health_loop(self) -> None:
        while self._running:
            now = time.time()
            for channel in self._channels.values():
                if channel.is_enabled and channel.health.last_ping and now - channel.health.last_ping > 120 and channel.health.status == ChannelStatus.ENABLED:
                    channel.health.status = ChannelStatus.DEGRADED
            await asyncio.sleep(self._health_check_interval)
