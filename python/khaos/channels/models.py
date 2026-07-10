"""Multi-channel message delivery models."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class ChannelType(Enum):
    """Message channel type."""

    WEBSOCKET = "websocket"
    HTTP_CALLBACK = "http_callback"
    LOG_FILE = "log_file"
    MEMORY = "memory"
    TELEGRAM = "telegram"
    DISCORD = "discord"
    SLACK = "slack"
    WECHAT = "wechat"
    WEBHOOK_IN = "webhook_in"


class MessageDirection(Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class ContentType(Enum):
    TEXT = "text"
    IMAGE = "image"
    FILE = "file"
    AUDIO = "audio"
    VIDEO = "video"
    STICKER = "sticker"
    REPLY = "reply"
    MIXED = "mixed"


@dataclass
class MediaAttachment:
    url: str = ""
    file_path: str = ""
    mime_type: str = ""
    file_name: str = ""
    file_size: int = 0
    thumbnail_url: str = ""
    width: int = 0
    height: int = 0
    duration: float = 0.0
    caption: str = ""


@dataclass
class ReplyReference:
    message_id: str = ""
    author: str = ""
    text_preview: str = ""


@dataclass
class Sender:
    id: str = ""
    name: str = ""
    is_bot: bool = False
    platform_id: str = ""
    role: str = "user"


@dataclass
class PlatformMessage:
    id: str = ""
    direction: MessageDirection = MessageDirection.INBOUND
    channel: ChannelType = ChannelType.WEBSOCKET
    content_type: ContentType = ContentType.TEXT
    text: str = ""
    attachments: list[MediaAttachment] = field(default_factory=list)
    reply_to: Optional[ReplyReference] = None
    sender: Sender = field(default_factory=Sender)
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def plain_text(self) -> str:
        if self.text:
            result = self.text
        elif self.attachments:
            captions = [item.caption for item in self.attachments if item.caption]
            result = " ".join(captions) if captions else " ".join(
                item.file_name for item in self.attachments if item.file_name
            )
        else:
            result = ""
        if self.reply_to:
            result = (
                f"[reply to {self.reply_to.author}: "
                f"{self.reply_to.text_preview}]\n{result}"
            )
        return result

    def has_media(self) -> bool:
        return bool(self.attachments)

    def to_agent_input(self) -> str:
        parts = [self.plain_text()]
        if self.attachments:
            names = ", ".join(
                item.file_name or item.mime_type for item in self.attachments
            )
            parts.append(f"[{len(self.attachments)} attachment(s): {names}]")
        return "\n".join(parts)


@dataclass
class Message:
    content: str
    channel: ChannelType = ChannelType.WEBSOCKET
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    media_paths: list[str] = field(default_factory=list)
    reply_to_id: str = ""
    parse_mode: str = ""


@dataclass
class DeliveryResult:
    success: bool
    channel: str
    target: str
    error: Optional[str] = None
    timestamp: float = 0.0
    platform_message_id: str = ""
