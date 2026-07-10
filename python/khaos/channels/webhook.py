"""Inbound webhook parsing and signature verification."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import logging
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from khaos.channels.models import (
    ChannelType,
    ContentType,
    MediaAttachment,
    PlatformMessage,
    ReplyReference,
    Sender,
)

logger = logging.getLogger(__name__)


class WebhookHandler:
    def __init__(
        self,
        platform: ChannelType,
        secret: str = "",
        on_message: Callable[[PlatformMessage], Awaitable[None]] | None = None,
    ) -> None:
        self.platform = platform
        self.secret = secret
        self._on_message = on_message

    async def handle(self, headers: Mapping[str, str], body: bytes) -> dict[str, str]:
        normalized = {key.lower(): value for key, value in headers.items()}
        if self.secret and not self._verify_signature(normalized, body):
            return {"status": "signature_error"}
        try:
            raw: Any
            if self.platform == ChannelType.WECHAT and body.lstrip().startswith(b"<"):
                raw = body.decode("utf-8")
            else:
                raw = json.loads(body)
            msg = self._parser()(raw)
            msg.channel = self.platform
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            TypeError,
            ValueError,
            ET.ParseError,
        ) as exc:
            logger.warning("webhook parse failed for %s: %s", self.platform.value, exc)
            return {"status": "parse_error", "error": str(exc)}
        if self._on_message is not None:
            callback_result = self._on_message(msg)
            if inspect.isawaitable(callback_result):
                await callback_result
        return {"status": "ok", "message_id": msg.id}

    def _parser(self) -> Callable[[Any], PlatformMessage]:
        return {
            ChannelType.TELEGRAM: _parse_telegram,
            ChannelType.DISCORD: _parse_discord,
            ChannelType.SLACK: _parse_slack,
            ChannelType.WECHAT: _parse_wechat,
        }.get(self.platform, _parse_generic_webhook)

    def _verify_signature(self, headers: Mapping[str, str], body: bytes) -> bool:
        if self.platform == ChannelType.TELEGRAM:
            return hmac.compare_digest(
                headers.get("x-telegram-bot-api-secret-token", ""), self.secret
            )
        if self.platform == ChannelType.DISCORD:
            timestamp = headers.get("x-signature-timestamp", "")
            signature = headers.get("x-signature-ed25519", "")
            if not timestamp or not signature:
                return False
            try:
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.secret))
                public_key.verify(bytes.fromhex(signature), timestamp.encode() + body)
            except (ValueError, InvalidSignature):
                return False
            return True
        if self.platform == ChannelType.SLACK:
            timestamp = headers.get("x-slack-request-timestamp", "")
            signature = headers.get("x-slack-signature", "")
            base = b"v0:" + timestamp.encode() + b":" + body
            expected = "v0=" + hmac.new(
                self.secret.encode(), base, hashlib.sha256
            ).hexdigest()
            return bool(timestamp and signature) and hmac.compare_digest(signature, expected)
        if self.platform == ChannelType.WECHAT:
            return hmac.compare_digest(headers.get("x-wechat-token", ""), self.secret)
        return True


def _parse_telegram(raw: dict[str, Any]) -> PlatformMessage:
    data = raw.get("message", raw)
    author, chat = data.get("from", {}), data.get("chat", {})
    msg = PlatformMessage(
        id=str(data.get("message_id", "")), text=data.get("text", data.get("caption", "")),
        sender=Sender(id=str(author.get("id", "")), name=author.get("first_name", author.get("username", "")), is_bot=author.get("is_bot", False), platform_id=str(author.get("id", ""))),
        target=str(chat.get("id", "")), raw_payload=raw,
    )
    reply = data.get("reply_to_message")
    if reply:
        reply_author = reply.get("from", {})
        msg.reply_to = ReplyReference(str(reply.get("message_id", "")), reply_author.get("first_name", reply_author.get("username", "")), (reply.get("text", "") or "")[:100])
    if data.get("photo"):
        photo = data["photo"][-1]
        msg.content_type = ContentType.IMAGE
        msg.attachments.append(MediaAttachment(url=photo.get("file_id", ""), file_name="photo.jpg", mime_type="image/jpeg", width=photo.get("width", 0), height=photo.get("height", 0), caption=data.get("caption", "")))
    if data.get("document"):
        doc = data["document"]
        msg.content_type = ContentType.MIXED if msg.attachments else ContentType.FILE
        msg.attachments.append(MediaAttachment(url=doc.get("file_id", ""), file_name=doc.get("file_name", "document"), mime_type=doc.get("mime_type", ""), file_size=doc.get("file_size", 0), caption=data.get("caption", "")))
    return msg


def _parse_discord(raw: dict[str, Any]) -> PlatformMessage:
    data = raw.get("data", raw)
    author = data.get("author", data.get("member", {}).get("user", {}))
    permissions = data.get("member", {}).get("permissions", 0)
    try:
        is_admin = bool(int(permissions) & 8)
    except (TypeError, ValueError):
        is_admin = False
    msg = PlatformMessage(id=str(data.get("id", raw.get("id", ""))), channel=ChannelType.DISCORD, text=data.get("content", ""), sender=Sender(id=str(author.get("id", "")), name=author.get("username", ""), is_bot=author.get("bot", False), platform_id=str(author.get("id", "")), role="admin" if is_admin else "user"), target=str(data.get("channel_id", "")), raw_payload=raw)
    ref = data.get("referenced_message") or data.get("message_reference")
    if ref:
        msg.reply_to = ReplyReference(str(ref.get("message_id", ref.get("id", ""))), ref.get("author", {}).get("username", ""), (ref.get("content", "") or "")[:100])
    for item in data.get("attachments", []):
        msg.attachments.append(MediaAttachment(url=item.get("url", ""), file_name=item.get("filename", ""), mime_type=item.get("content_type", ""), file_size=item.get("size", 0), width=item.get("width", 0) or 0, height=item.get("height", 0) or 0))
    if msg.attachments:
        msg.content_type = ContentType.MIXED if msg.text else ContentType.FILE
    return msg


def _parse_slack(raw: dict[str, Any]) -> PlatformMessage:
    event = raw.get("event", raw)
    msg = PlatformMessage(id=str(event.get("client_msg_id", event.get("message_ts", event.get("ts", "")))), channel=ChannelType.SLACK, text=event.get("text", ""), sender=Sender(id=str(event.get("user", "")), name=str(event.get("user", "")), platform_id=str(event.get("user", ""))), target=str(event.get("channel", "")), raw_payload=raw)
    for item in event.get("files", []):
        msg.attachments.append(MediaAttachment(url=item.get("url_private", item.get("permalink", "")), file_name=item.get("name", ""), mime_type=item.get("mimetype", ""), file_size=item.get("size", 0)))
    if msg.attachments:
        msg.content_type = ContentType.MIXED if msg.text else ContentType.FILE
    return msg


def _parse_wechat(raw: dict[str, Any] | str) -> PlatformMessage:
    if isinstance(raw, str):
        root = ET.fromstring(raw)
        data = {
            element.tag.rsplit("}", 1)[-1]: element.text or ""
            for element in root.iter()
            if element is not root
        }
    else:
        data = raw
    msg_type = str(data.get("MsgType", "text")).lower()
    text = str(data.get("Content", data.get("content", data.get("text", ""))))
    message = PlatformMessage(id=str(data.get("MsgId", data.get("MsgID", ""))), channel=ChannelType.WECHAT, text=text, sender=Sender(id=str(data.get("FromUserName", "")), platform_id=str(data.get("FromUserName", ""))), target=str(data.get("ToUserName", "")), raw_payload=data, metadata={"msg_type": msg_type})
    if msg_type in {"image", "voice", "video"}:
        content_type = {"image": ContentType.IMAGE, "voice": ContentType.AUDIO, "video": ContentType.VIDEO}[msg_type]
        message.content_type = content_type
        message.attachments.append(MediaAttachment(url=str(data.get("PicUrl", data.get("MediaId", ""))), mime_type=str(data.get("Format", "")), thumbnail_url=str(data.get("ThumbMediaId", ""))))
    elif msg_type == "location":
        message.text = str(data.get("Label", ""))
        message.metadata.update({"latitude": data.get("Location_X"), "longitude": data.get("Location_Y"), "scale": data.get("Scale")})
    elif msg_type == "link":
        message.text = str(data.get("Title", ""))
        message.attachments.append(MediaAttachment(url=str(data.get("Url", "")), caption=str(data.get("Description", ""))))
        message.content_type = ContentType.MIXED
    elif msg_type == "event":
        message.text = str(data.get("Event", ""))
        message.metadata.update({"event": data.get("Event"), "event_key": data.get("EventKey")})
    return message


def _parse_generic_webhook(raw: dict[str, Any]) -> PlatformMessage:
    if not isinstance(raw, dict):
        raise TypeError("webhook payload must be an object")
    return PlatformMessage(id=str(raw.get("id", raw.get("message_id", ""))), channel=ChannelType.WEBHOOK_IN, text=str(raw.get("text", raw.get("message", raw.get("content", "")))), sender=Sender(id=str(raw.get("user_id", raw.get("from_id", raw.get("sender_id", "")))), name=str(raw.get("user_name", raw.get("from_name", ""))), platform_id=str(raw.get("user_id", ""))), target=str(raw.get("channel_id", raw.get("chat_id", raw.get("target", "")))), raw_payload=raw)
