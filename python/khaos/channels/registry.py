"""Owned channel configuration and immutable reader snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
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
    """Mutable record owned exclusively by :class:`ChannelRegistry`."""

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


@dataclass(frozen=True, slots=True)
class ChannelConfigSnapshot:
    """Immutable configuration view exposed to readers."""

    channel_type: ChannelType
    enabled: bool
    secret: str
    webhook_path: str
    extra: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ChannelHealthSnapshot:
    """Immutable health view exposed to readers."""

    status: ChannelStatus
    last_ping: float
    last_error: str
    total_sent: int
    total_received: int
    total_failed: int
    consecutive_failures: int


@dataclass(frozen=True, slots=True)
class RegisteredChannelSnapshot:
    """Stable point-in-time view of a registered channel."""

    id: str
    channel_type: ChannelType
    config: ChannelConfigSnapshot
    health: ChannelHealthSnapshot
    channel: Channel | None
    created_at: float

    @property
    def is_healthy(self) -> bool:
        return self.config.enabled and self.health.status != ChannelStatus.ERROR

    @property
    def is_enabled(self) -> bool:
        return self.config.enabled


class ChannelRegistry:
    """Single writer for channel configuration and health state.

    All mutating methods use one re-entrant lock. Read methods return
    immutable snapshots, preventing handlers and UI code from changing the
    registry by mutating a returned object.
    """

    def __init__(
        self,
        health_check_interval: float = 60.0,
        max_consecutive_failures: int = 5,
    ) -> None:
        self._channels: dict[str, RegisteredChannel] = {}
        self._health_check_interval = health_check_interval
        self._max_consecutive_failures = max_consecutive_failures
        self._lock = threading.RLock()
        self._running = False
        self._health_task: asyncio.Task[None] | None = None

    def register(
        self,
        channel_id: str,
        channel_type: ChannelType,
        config: ChannelConfig | dict[str, Any] | None = None,
        channel: Channel | None = None,
    ) -> RegisteredChannelSnapshot:
        """Register one channel and return its initial immutable snapshot."""
        if isinstance(config, dict):
            config = ChannelConfig(channel_type=channel_type, **config)
        elif config is None:
            config = ChannelConfig(channel_type=channel_type)
        elif config.channel_type != channel_type:
            raise ValueError("channel config type does not match registered type")

        owned_config = self._copy_config(config)
        with self._lock:
            self._validate_config(owned_config)
            self._validate_unique_enabled_secret(channel_id, owned_config)
            registered = RegisteredChannel(
                channel_id,
                channel_type,
                owned_config,
                channel=channel,
            )
            registered.health.status = (
                ChannelStatus.ENABLED
                if owned_config.enabled
                else ChannelStatus.DISABLED
            )
            self._channels[channel_id] = registered
            return self._snapshot(registered)

    def unregister(self, channel_id: str) -> bool:
        with self._lock:
            channel = self._channels.pop(channel_id, None)
            if channel is None:
                return False
            channel.health.status = ChannelStatus.DISABLED
            return True

    def get(self, channel_id: str) -> RegisteredChannelSnapshot | None:
        with self._lock:
            channel = self._channels.get(channel_id)
            return self._snapshot(channel) if channel is not None else None

    def get_by_type(self, channel_type: ChannelType) -> list[RegisteredChannelSnapshot]:
        with self._lock:
            return [
                self._snapshot(item)
                for item in self._channels.values()
                if item.channel_type == channel_type
            ]

    def list_all(
        self, enabled_only: bool = False
    ) -> list[RegisteredChannelSnapshot]:
        with self._lock:
            return [
                self._snapshot(item)
                for item in self._channels.values()
                if not enabled_only or item.is_enabled
            ]

    def replace_config(
        self, channel_id: str, config: ChannelConfig
    ) -> RegisteredChannelSnapshot | None:
        """Replace configuration through the registry's validation boundary."""
        owned_config = self._copy_config(config)
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                return None
            if owned_config.channel_type != channel.channel_type:
                raise ValueError("channel config type does not match registered type")
            self._validate_config(owned_config)
            self._validate_unique_enabled_secret(
                channel_id,
                owned_config,
                enabling=owned_config.enabled,
            )
            channel.config = owned_config
            channel.health.status = (
                ChannelStatus.ENABLED
                if owned_config.enabled
                else ChannelStatus.DISABLED
            )
            channel.health.consecutive_failures = 0
            return self._snapshot(channel)

    def enable(self, channel_id: str) -> bool:
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                return False
            self._validate_config(channel.config)
            self._validate_unique_enabled_secret(
                channel_id,
                channel.config,
                enabling=True,
            )
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

    def _validate_unique_enabled_secret(
        self,
        channel_id: str,
        config: ChannelConfig,
        *,
        enabling: bool = False,
    ) -> None:
        if (not config.enabled and not enabling) or not config.secret:
            return
        fingerprint = _integration_fingerprint(config)
        for existing_id, existing in self._channels.items():
            if existing_id == channel_id or not existing.is_enabled:
                continue
            if _integration_fingerprint(existing.config) == fingerprint:
                raise ValueError(
                    "an enabled platform integration secret may bind only one channel"
                )

    def disable(self, channel_id: str) -> bool:
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                return False
            channel.config.enabled = False
            channel.health.status = ChannelStatus.DISABLED
            return True

    def record_success(self, channel_id: str, *, received: bool = False) -> None:
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                return
            channel.health.total_received += int(received)
            channel.health.total_sent += int(not received)
            channel.health.consecutive_failures = 0
            channel.health.last_error = ""
            channel.health.last_ping = time.time()
            channel.health.status = (
                ChannelStatus.ENABLED
                if channel.config.enabled
                else ChannelStatus.DISABLED
            )

    def record_failure(self, channel_id: str, error: str = "") -> None:
        with self._lock:
            channel = self._channels.get(channel_id)
            if channel is None:
                return
            health = channel.health
            health.consecutive_failures += 1
            health.total_failed += 1
            health.last_error = error
            health.last_ping = time.time()
            health.status = (
                ChannelStatus.ERROR
                if health.consecutive_failures >= self._max_consecutive_failures
                else ChannelStatus.DEGRADED
            )

    def get_health_report(self) -> list[dict[str, Any]]:
        return [
            {
                "id": item.id,
                "type": item.channel_type.value,
                "enabled": item.is_enabled,
                "healthy": item.is_healthy,
                "status": item.health.status.value,
                "last_ping": item.health.last_ping,
                "last_error": item.health.last_error,
                "total_sent": item.health.total_sent,
                "total_received": item.health.total_received,
                "total_failed": item.health.total_failed,
            }
            for item in self.list_all()
        ]

    async def start_health_checks(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            self._health_task = asyncio.create_task(self._health_loop())

    async def stop_health_checks(self) -> None:
        with self._lock:
            self._running = False
            task = self._health_task
            self._health_task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _health_loop(self) -> None:
        while True:
            with self._lock:
                if not self._running:
                    return
                now = time.time()
                for channel in self._channels.values():
                    if (
                        channel.is_enabled
                        and channel.health.last_ping
                        and now - channel.health.last_ping > 120
                        and channel.health.status == ChannelStatus.ENABLED
                    ):
                        channel.health.status = ChannelStatus.DEGRADED
            await asyncio.sleep(self._health_check_interval)

    @staticmethod
    def _copy_config(config: ChannelConfig) -> ChannelConfig:
        return ChannelConfig(
            channel_type=config.channel_type,
            enabled=config.enabled,
            secret=config.secret,
            webhook_path=config.webhook_path,
            extra=dict(config.extra),
        )

    @staticmethod
    def _snapshot(channel: RegisteredChannel) -> RegisteredChannelSnapshot:
        return RegisteredChannelSnapshot(
            id=channel.id,
            channel_type=channel.channel_type,
            config=ChannelConfigSnapshot(
                channel_type=channel.config.channel_type,
                enabled=channel.config.enabled,
                secret=channel.config.secret,
                webhook_path=channel.config.webhook_path,
                extra=MappingProxyType(dict(channel.config.extra)),
            ),
            health=ChannelHealthSnapshot(
                status=channel.health.status,
                last_ping=channel.health.last_ping,
                last_error=channel.health.last_error,
                total_sent=channel.health.total_sent,
                total_received=channel.health.total_received,
                total_failed=channel.health.total_failed,
                consecutive_failures=channel.health.consecutive_failures,
            ),
            channel=channel.channel,
            created_at=channel.created_at,
        )


def _integration_fingerprint(config: ChannelConfig) -> str:
    encoded = f"{config.channel_type.value}\0{config.secret}".encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ChannelConfig",
    "ChannelConfigSnapshot",
    "ChannelHealth",
    "ChannelHealthSnapshot",
    "ChannelRegistry",
    "ChannelStatus",
    "RegisteredChannel",
    "RegisteredChannelSnapshot",
]
