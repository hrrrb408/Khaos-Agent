"""Multi-channel message delivery models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ChannelType(Enum):
    """消息通道类型。"""

    WEBSOCKET = "websocket"
    HTTP_CALLBACK = "http_callback"
    LOG_FILE = "log_file"
    MEMORY = "memory"          # 写入记忆存储
    # 后续扩展：
    # TELEGRAM = "telegram"
    # DISCORD = "discord"
    # WECHAT = "wechat"


@dataclass
class Message:
    """要发送的消息。"""

    content: str
    channel: ChannelType = ChannelType.WEBSOCKET
    target: str = ""           # 通道目标（session_id / URL / file path）
    metadata: dict = field(default_factory=dict)
    media_paths: list[str] = field(default_factory=list)  # 附件路径


@dataclass
class DeliveryResult:
    """投递结果。"""

    success: bool
    channel: str
    target: str
    error: Optional[str] = None
    timestamp: float = 0.0
