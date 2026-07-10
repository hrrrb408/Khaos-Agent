"""Platform-specific bot adapter base classes."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from khaos.channels.dispatcher import Channel
from khaos.channels.models import ChannelType, DeliveryResult, Message

logger = logging.getLogger(__name__)


class BotAdapter(Channel, ABC):
    def __init__(self, token: str = "", base_url: str = "") -> None:
        self._token = token
        self._base_url = base_url

    @abstractmethod
    async def send_typing(self, target: str) -> bool:
        raise NotImplementedError

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": message.target, "text": message.content}
        if message.reply_to_id:
            payload["reply_to_message_id"] = message.reply_to_id
        return payload

    async def send(self, message: Message) -> DeliveryResult:
        await self.format_outbound(message)
        logger.info("%s send to %s", self.channel_type.value, message.target)
        return DeliveryResult(True, self.channel_type.value, message.target)


class TelegramAdapter(BotAdapter):
    channel_type = ChannelType.TELEGRAM

    def __init__(self, token: str = "") -> None:
        super().__init__(token, f"https://api.telegram.org/bot{token}")

    async def send_typing(self, target: str) -> bool:
        return True

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload = await super().format_outbound(message)
        payload["parse_mode"] = message.parse_mode or "Markdown"
        if message.media_paths:
            payload["photo"] = message.media_paths[0]
        return payload


class DiscordAdapter(BotAdapter):
    channel_type = ChannelType.DISCORD

    async def send_typing(self, target: str) -> bool:
        return True

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"content": message.content}
        if message.reply_to_id:
            payload["message_reference"] = {"message_id": message.reply_to_id}
        return payload


class SlackAdapter(BotAdapter):
    channel_type = ChannelType.SLACK

    async def send_typing(self, target: str) -> bool:
        return True

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": message.target, "text": message.content}
        if message.parse_mode == "markdown":
            payload["mrkdwn"] = True
        return payload


class WeChatAdapter(BotAdapter):
    channel_type = ChannelType.WECHAT

    async def send_typing(self, target: str) -> bool:
        return True

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        return {"touser": message.target, "msgtype": "text", "text": {"content": message.content}}
