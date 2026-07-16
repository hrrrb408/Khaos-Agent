"""Inbound webhook parsing and signature verification."""

from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import logging
import math
import time
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

WEBHOOK_SIGNATURE_WINDOW_SECONDS = 300
GENERIC_WEBHOOK_SECRET_MIN_LENGTH = 32


def is_valid_generic_webhook_secret(secret: str) -> bool:
    """Reject missing, short, and trivially low-entropy generic secrets."""
    return (
        len(secret) >= GENERIC_WEBHOOK_SECRET_MIN_LENGTH
        and len(set(secret)) >= 8
    )


class WebhookReplayGuard:
    """Bound replay state for timestamped, signature-authenticated webhooks."""

    def __init__(
        self,
        *,
        window_seconds: int = WEBHOOK_SIGNATURE_WINDOW_SECONDS,
        max_entries: int = 10_000,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._seen: dict[str, float] = {}

    def consume(self, key: str, *, issued_at: float, now: float) -> bool:
        cutoff = now - self.window_seconds
        self._seen = {
            item: timestamp
            for item, timestamp in self._seen.items()
            if timestamp >= cutoff
        }
        if key in self._seen:
            return False
        if len(self._seen) >= self.max_entries:
            oldest = min(self._seen, key=self._seen.__getitem__)
            del self._seen[oldest]
        self._seen[key] = issued_at
        return True


class WebhookHandler:
    def __init__(
        self,
        platform: ChannelType,
        secret: str = "",
        on_message: Callable[[PlatformMessage], Awaitable[None]] | None = None,
        *,
        replay_guard: WebhookReplayGuard | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.platform = platform
        self.secret = secret
        self._on_message = on_message
        self._replay_guard = replay_guard or WebhookReplayGuard()
        self._now = now

    async def handle(self, headers: Mapping[str, str], body: bytes) -> dict[str, str]:
        normalized = {key.lower(): value for key, value in headers.items()}
        if not self.secret:
            return {"status": "configuration_error", "error": "webhook secret required"}
        if not self._verify_signature(normalized, body):
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
            issued_at = self._fresh_timestamp(timestamp)
            if issued_at is None:
                return False
            base = b"v0:" + timestamp.encode() + b":" + body
            expected = "v0=" + hmac.new(
                self.secret.encode(), base, hashlib.sha256
            ).hexdigest()
            return (
                bool(signature)
                and hmac.compare_digest(signature.encode(), expected.encode())
                and self._replay_guard.consume(
                    f"slack:{signature}", issued_at=issued_at, now=self._now()
                )
            )
        if self.platform == ChannelType.WECHAT:
            return hmac.compare_digest(headers.get("x-wechat-token", ""), self.secret)
        if self.platform == ChannelType.WEBHOOK_IN:
            if not is_valid_generic_webhook_secret(self.secret):
                return False
            timestamp = headers.get("x-khaos-timestamp", "")
            message_id = headers.get("x-khaos-message-id", "")
            body_digest = headers.get("x-khaos-content-sha256", "")
            signature = headers.get("x-khaos-signature", "")
            issued_at = self._fresh_timestamp(timestamp)
            actual_digest = hashlib.sha256(body).hexdigest()
            if (
                issued_at is None
                or len(message_id) < 16
                or not hmac.compare_digest(body_digest.encode(), actual_digest.encode())
            ):
                return False
            signed = f"v1\n{timestamp}\n{message_id}\n{body_digest}".encode("utf-8")
            expected = "v1=" + hmac.new(
                self.secret.encode("utf-8"), signed, hashlib.sha256
            ).hexdigest()
            return (
                hmac.compare_digest(signature.encode(), expected.encode())
                and self._replay_guard.consume(
                    f"generic:{message_id}", issued_at=issued_at, now=self._now()
                )
            )
        return False

    def _fresh_timestamp(self, value: str) -> float | None:
        try:
            issued_at = float(value)
        except (TypeError, ValueError):
            return None
        if (
            not math.isfinite(issued_at)
            or abs(self._now() - issued_at) > WEBHOOK_SIGNATURE_WINDOW_SECONDS
        ):
            return None
        return issued_at


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
