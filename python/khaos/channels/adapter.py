"""Platform-specific bot adapter base classes."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from khaos.channels.dispatcher import Channel
from khaos.channels.models import ChannelType, DeliveryResult, Message

logger = logging.getLogger(__name__)


class BotAdapter(Channel, ABC):
    def __init__(self, token: str = "", base_url: str = "", http_client: httpx.AsyncClient | None = None) -> None:
        self._token = token
        self._base_url = base_url
        self._http_client = http_client

    @abstractmethod
    async def send_typing(self, target: str) -> bool:
        raise NotImplementedError

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"chat_id": message.target, "text": message.content}
        if message.reply_to_id:
            payload["reply_to_message_id"] = message.reply_to_id
        return payload

    async def send(self, message: Message) -> DeliveryResult:
        try:
            response = await self._post(self._send_url(message), await self.format_outbound(message))
            response.raise_for_status()
            data = response.json() if response.content else {}
            if data.get("ok") is False:
                raise RuntimeError(str(data.get("description", "platform rejected message")))
            message_id = str(data.get("message_id", data.get("ts", data.get("id", data.get("result", {}).get("message_id", "")))))
            return DeliveryResult(True, self.channel_type.value, message.target, platform_message_id=message_id)
        except (httpx.HTTPError, ValueError, RuntimeError) as exc:
            logger.warning("%s send failed: %s", self.channel_type.value, exc)
            return DeliveryResult(False, self.channel_type.value, message.target, error=str(exc))

    def _send_url(self, message: Message) -> str:
        return self._base_url

    async def _post(self, url: str, payload: dict[str, Any]) -> httpx.Response:
        headers = self._headers()
        if self._http_client is not None:
            return await self._http_client.post(url, json=payload, headers=headers)
        async with httpx.AsyncClient(timeout=30) as client:
            return await client.post(url, json=payload, headers=headers)

    def _headers(self) -> dict[str, str]:
        return {}


class TelegramAdapter(BotAdapter):
    channel_type = ChannelType.TELEGRAM

    def __init__(self, token: str = "", http_client: httpx.AsyncClient | None = None) -> None:
        super().__init__(token, f"https://api.telegram.org/bot{token}", http_client)

    async def send_typing(self, target: str) -> bool:
        response = await self._post(f"{self._base_url}/sendChatAction", {"chat_id": target, "action": "typing"})
        return response.is_success

    def _send_url(self, message: Message) -> str:
        return f"{self._base_url}/{'sendPhoto' if message.media_paths else 'sendMessage'}"

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload = await super().format_outbound(message)
        payload["parse_mode"] = message.parse_mode or "Markdown"
        if message.media_paths:
            payload["photo"] = message.media_paths[0]
        return payload


class DiscordAdapter(BotAdapter):
    channel_type = ChannelType.DISCORD

    def __init__(self, token: str = "", base_url: str = "https://discord.com/api/v10", http_client: httpx.AsyncClient | None = None) -> None:
        super().__init__(token, base_url, http_client)

    async def send_typing(self, target: str) -> bool:
        response = await self._post(f"{self._base_url}/channels/{target}/typing", {})
        return response.is_success

    def _send_url(self, message: Message) -> str:
        return message.target if message.target.startswith("https://") else f"{self._base_url}/channels/{message.target}/messages"

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bot {self._token}"} if self._token else {}

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"content": message.content}
        if message.reply_to_id:
            payload["message_reference"] = {"message_id": message.reply_to_id}
        return payload


class SlackAdapter(BotAdapter):
    channel_type = ChannelType.SLACK

    def __init__(self, token: str = "", http_client: httpx.AsyncClient | None = None) -> None:
        super().__init__(token, "https://slack.com/api/chat.postMessage", http_client)

    async def send_typing(self, target: str) -> bool:
        # Slack Web API has no typing endpoint for bots.
        return True

    def _headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        payload: dict[str, Any] = {"channel": message.target, "text": message.content}
        if message.parse_mode == "markdown":
            payload["mrkdwn"] = True
        return payload


class WeChatAdapter(BotAdapter):
    channel_type = ChannelType.WECHAT

    def __init__(self, token: str = "", base_url: str = "https://api.weixin.qq.com/cgi-bin/message/custom/send", http_client: httpx.AsyncClient | None = None) -> None:
        super().__init__(token, base_url, http_client)

    async def send_typing(self, target: str) -> bool:
        return True

    def _send_url(self, message: Message) -> str:
        separator = "&" if "?" in self._base_url else "?"
        return f"{self._base_url}{separator}access_token={self._token}"

    async def format_outbound(self, message: Message) -> dict[str, Any]:
        return {"touser": message.target, "msgtype": "text", "text": {"content": message.content}}
