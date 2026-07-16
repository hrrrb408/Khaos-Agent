"""Inbound webhook parsing and signature verification."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import inspect
import json
import logging
import math
import time
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
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


@dataclass
class _RateBucket:
    tokens: float
    last_fill: float
    last_seen: float


class WebhookRateLimiter:
    """Bound verified webhook dispatch independently per integration."""

    def __init__(
        self,
        *,
        rate_per_minute: int = 60,
        burst: int = 10,
        max_integrations: int = 4096,
        idle_seconds: float = 600.0,
    ) -> None:
        if min(rate_per_minute, burst, max_integrations) <= 0 or idle_seconds <= 0:
            raise ValueError("webhook rate limit values must be positive")
        self._rate = rate_per_minute / 60.0
        self._burst = float(burst)
        self._max_integrations = max_integrations
        self._idle_seconds = idle_seconds
        self._buckets: dict[str, _RateBucket] = {}
        self._lock = asyncio.Lock()

    async def allow(self, channel_id: str, platform: str, now: float) -> bool:
        key = f"{platform}:{channel_id}"
        async with self._lock:
            self._buckets = {
                item: bucket
                for item, bucket in self._buckets.items()
                if now - bucket.last_seen <= self._idle_seconds
            }
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_integrations:
                    oldest = min(
                        self._buckets,
                        key=lambda item: self._buckets[item].last_seen,
                    )
                    del self._buckets[oldest]
                bucket = _RateBucket(self._burst, now, now)
                self._buckets[key] = bucket
            elapsed = max(0.0, now - bucket.last_fill)
            bucket.tokens = min(self._burst, bucket.tokens + elapsed * self._rate)
            bucket.last_fill = now
            bucket.last_seen = now
            if bucket.tokens < 1.0:
                return False
            bucket.tokens -= 1.0
            return True

    async def refund(self, channel_id: str, platform: str) -> None:
        """Return a reservation when a signed request is rejected as replay."""
        key = f"{platform}:{channel_id}"
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is not None:
                bucket.tokens = min(self._burst, bucket.tokens + 1.0)


def is_valid_generic_webhook_secret(secret: str) -> bool:
    """Reject missing, short, and trivially low-entropy generic secrets."""
    return (
        len(secret) >= GENERIC_WEBHOOK_SECRET_MIN_LENGTH
        and len(set(secret)) >= 8
    )


class WebhookReplayGuard:
    """Durable-capable replay state for authenticated webhook events."""

    def __init__(
        self,
        *,
        window_seconds: int = WEBHOOK_SIGNATURE_WINDOW_SECONDS,
        max_entries: int = 10_000,
        consumer: Callable[
            [str, str, str, float, float | None], Awaitable[bool]
        ] | None = None,
    ) -> None:
        self.window_seconds = window_seconds
        self.max_entries = max_entries
        self._consumer = consumer
        self._seen: dict[str, float] = {}

    async def consume(
        self,
        channel_id: str,
        platform: str,
        event_id: str,
        *,
        issued_at: float,
        expires_at: float | None,
        now: float,
    ) -> bool:
        if self._consumer is not None:
            return await self._consumer(
                channel_id, platform, event_id, issued_at, expires_at
            )
        cutoff = now - self.window_seconds
        self._seen = {
            item: timestamp
            for item, timestamp in self._seen.items()
            if timestamp >= cutoff
        }
        key = f"{channel_id}:{platform}:{event_id}"
        if key in self._seen:
            return False
        if len(self._seen) >= self.max_entries:
            oldest = min(self._seen, key=self._seen.__getitem__)
            del self._seen[oldest]
        self._seen[key] = issued_at
        return True


@dataclass(frozen=True)
class _WebhookVerification:
    issued_at: float
    expires_at: float | None
    replay_hint: str = ""


class WebhookHandler:
    def __init__(
        self,
        platform: ChannelType,
        secret: str = "",
        on_message: Callable[[PlatformMessage], Awaitable[None]] | None = None,
        *,
        channel_id: str = "default",
        replay_guard: WebhookReplayGuard | None = None,
        verified_limiter: WebhookRateLimiter | None = None,
        now: Callable[[], float] = time.time,
    ) -> None:
        self.platform = platform
        self.secret = secret
        self.channel_id = channel_id
        self._on_message = on_message
        self._replay_guard = replay_guard or WebhookReplayGuard()
        self._verified_limiter = verified_limiter
        self._now = now

    async def handle(
        self,
        headers: Mapping[str, str],
        body: bytes,
        query: Mapping[str, str] | None = None,
    ) -> dict[str, str]:
        normalized = {key.lower(): value for key, value in headers.items()}
        normalized_query = {
            key.lower(): value for key, value in (query or {}).items()
        }
        if not self.secret:
            return {"status": "configuration_error", "error": "webhook secret required"}
        verification = self._verify_signature(normalized, normalized_query, body)
        if verification is None:
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
        replay_id = self._replay_id(raw, msg, verification.replay_hint)
        if not replay_id:
            return {"status": "replay_error"}
        reserved = False
        if self._verified_limiter is not None:
            reserved = await self._verified_limiter.allow(
                self.channel_id, self.platform.value, self._now()
            )
            if not reserved:
                return {"status": "rate_limited"}
        if not await self._replay_guard.consume(
            self.channel_id,
            self.platform.value,
            replay_id,
            issued_at=verification.issued_at,
            expires_at=verification.expires_at,
            now=self._now(),
        ):
            if reserved and self._verified_limiter is not None:
                await self._verified_limiter.refund(
                    self.channel_id, self.platform.value
                )
            return {"status": "replay_error"}
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

    def _verify_signature(
        self,
        headers: Mapping[str, str],
        query: Mapping[str, str],
        body: bytes,
    ) -> _WebhookVerification | None:
        now = self._now()
        if self.platform == ChannelType.TELEGRAM:
            if not hmac.compare_digest(
                headers.get("x-telegram-bot-api-secret-token", ""), self.secret
            ):
                return None
            return _WebhookVerification(now, None)
        if self.platform == ChannelType.DISCORD:
            timestamp = headers.get("x-signature-timestamp", "")
            signature = headers.get("x-signature-ed25519", "")
            issued_at = self._fresh_timestamp(timestamp)
            if issued_at is None or not signature:
                return None
            try:
                public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.secret))
                public_key.verify(bytes.fromhex(signature), timestamp.encode() + body)
            except (ValueError, InvalidSignature):
                return None
            return _WebhookVerification(
                issued_at, issued_at + WEBHOOK_SIGNATURE_WINDOW_SECONDS
            )
        if self.platform == ChannelType.SLACK:
            timestamp = headers.get("x-slack-request-timestamp", "")
            signature = headers.get("x-slack-signature", "")
            issued_at = self._fresh_timestamp(timestamp)
            if issued_at is None:
                return None
            base = b"v0:" + timestamp.encode() + b":" + body
            expected = "v0=" + hmac.new(
                self.secret.encode(), base, hashlib.sha256
            ).hexdigest()
            if not signature or not hmac.compare_digest(
                signature.encode(), expected.encode()
            ):
                return None
            return _WebhookVerification(
                issued_at,
                issued_at + WEBHOOK_SIGNATURE_WINDOW_SECONDS,
                signature,
            )
        if self.platform == ChannelType.WECHAT:
            timestamp = query.get("timestamp", headers.get("x-wechat-timestamp", ""))
            nonce = query.get("nonce", headers.get("x-wechat-nonce", ""))
            signature = query.get(
                "signature", headers.get("x-wechat-signature", "")
            )
            issued_at = self._fresh_timestamp(timestamp)
            if issued_at is None or not nonce or not signature:
                return None
            expected = hashlib.sha1(
                "".join(sorted((self.secret, timestamp, nonce))).encode("utf-8")
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                return None
            return _WebhookVerification(
                issued_at,
                issued_at + WEBHOOK_SIGNATURE_WINDOW_SECONDS,
                f"{timestamp}:{nonce}",
            )
        if self.platform == ChannelType.WEBHOOK_IN:
            if not is_valid_generic_webhook_secret(self.secret):
                return None
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
                return None
            signed = (
                f"v2\n{self.platform.value}\n{self.channel_id}\n{timestamp}\n"
                f"{message_id}\n{body_digest}"
            ).encode("utf-8")
            expected = "v2=" + hmac.new(
                self.secret.encode("utf-8"), signed, hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature.encode(), expected.encode()):
                return None
            return _WebhookVerification(
                issued_at,
                issued_at + WEBHOOK_SIGNATURE_WINDOW_SECONDS,
                message_id,
            )
        return None

    def _replay_id(
        self, raw: Any, message: PlatformMessage, replay_hint: str
    ) -> str:
        if self.platform == ChannelType.TELEGRAM:
            return str(raw.get("update_id", "")) if isinstance(raw, dict) else ""
        if self.platform == ChannelType.DISCORD:
            return str(raw.get("id", message.id)) if isinstance(raw, dict) else message.id
        if self.platform == ChannelType.SLACK and isinstance(raw, dict):
            return str(raw.get("event_id", replay_hint or message.id))
        return replay_hint or message.id

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
