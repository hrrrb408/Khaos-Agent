import hashlib
import hmac
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from khaos.channels import ChannelType, ContentType, WebhookHandler


@pytest.mark.asyncio
async def test_parse_telegram_photo_and_reply():
    body = json.dumps({"message": {"message_id": 2, "caption": "pic", "from": {"id": 3, "first_name": "A"}, "chat": {"id": 4}, "photo": [{"file_id": "x", "width": 10}], "reply_to_message": {"message_id": 1, "text": "old", "from": {"first_name": "B"}}}}).encode()
    messages = []
    result = await WebhookHandler(ChannelType.TELEGRAM, "telegram-secret", messages.append).handle({"x-telegram-bot-api-secret-token": "telegram-secret"}, body)
    assert result == {"status": "ok", "message_id": "2"}
    assert messages[0].content_type == ContentType.IMAGE
    assert messages[0].reply_to.author == "B"


@pytest.mark.asyncio
async def test_slack_signature_and_file():
    body = json.dumps({"event": {"client_msg_id": "m", "text": "hi", "user": "u", "channel": "c", "files": [{"name": "x.txt"}]}}).encode()
    timestamp, secret = str(int(time.time())), "s" * 32
    signature = "v0=" + hmac.new(secret.encode(), f"v0:{timestamp}:".encode() + body, hashlib.sha256).hexdigest()
    messages = []
    result = await WebhookHandler(ChannelType.SLACK, secret, messages.append).handle({"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": signature}, body)
    assert result["status"] == "ok"
    assert messages[0].attachments[0].file_name == "x.txt"

@pytest.mark.asyncio
async def test_slack_rejects_stale_and_replayed_requests():
    now = 1_700_000_000
    secret = "s" * 32
    body = b'{"event":{"client_msg_id":"m"}}'
    handler = WebhookHandler(ChannelType.SLACK, secret, now=lambda: now)

    def headers(timestamp: int) -> dict[str, str]:
        value = str(timestamp)
        signature = "v0=" + hmac.new(
            secret.encode(), f"v0:{value}:".encode() + body, hashlib.sha256
        ).hexdigest()
        return {"x-slack-request-timestamp": value, "x-slack-signature": signature}

    assert (await handler.handle(headers(now - 301), body))["status"] == "signature_error"
    assert (await handler.handle(headers(now), body))["status"] == "ok"
    assert (await handler.handle(headers(now), body))["status"] == "signature_error"


@pytest.mark.asyncio
async def test_discord_ed25519_signature():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    timestamp = "123"
    body = b'{"id":"interaction-1","data":{"content":"hello"}}'
    signature = private_key.sign(timestamp.encode() + body).hex()
    handler = WebhookHandler(ChannelType.DISCORD, public_key.hex())

    accepted = await handler.handle(
        {"x-signature-timestamp": timestamp, "x-signature-ed25519": signature},
        body,
    )
    rejected = await handler.handle(
        {"x-signature-timestamp": timestamp, "x-signature-ed25519": "00" * 64},
        body,
    )

    assert accepted["status"] == "ok"
    assert rejected["status"] == "signature_error"


@pytest.mark.asyncio
async def test_wechat_xml_and_bad_signature():
    body = b"<xml><MsgId>8</MsgId><Content><![CDATA[hello]]></Content><FromUserName>u</FromUserName></xml>"
    messages = []
    handler = WebhookHandler(ChannelType.WECHAT, "token", messages.append)
    assert (await handler.handle({"x-wechat-token": "bad"}, body))["status"] == "signature_error"
    assert (await handler.handle({"x-wechat-token": "token"}, body))["message_id"] == "8"
    assert messages[0].text == "hello"


@pytest.mark.asyncio
async def test_wechat_image_and_location_types():
    messages = []
    image = b"<xml><MsgType>image</MsgType><MsgId>9</MsgId><PicUrl>https://img</PicUrl></xml>"
    location = b"<xml><MsgType>location</MsgType><Label>Shanghai</Label><Location_X>31.2</Location_X><Location_Y>121.5</Location_Y></xml>"
    handler = WebhookHandler(ChannelType.WECHAT, "token", messages.append)
    await handler.handle({"x-wechat-token": "token"}, image)
    await handler.handle({"x-wechat-token": "token"}, location)
    assert messages[0].content_type == ContentType.IMAGE
    assert messages[0].attachments[0].url == "https://img"
    assert messages[1].text == "Shanghai"
    assert messages[1].metadata["latitude"] == "31.2"


@pytest.mark.asyncio
async def test_generic_and_parse_error():
    now = 1_700_000_000
    secret = "0123456789abcdef0123456789abcdef"
    messages = []
    handler = WebhookHandler(
        ChannelType.WEBHOOK_IN, secret, messages.append, now=lambda: now
    )

    def headers(body: bytes, message_id: str) -> dict[str, str]:
        timestamp = str(now)
        digest = hashlib.sha256(body).hexdigest()
        signed = f"v1\n{timestamp}\n{message_id}\n{digest}".encode()
        signature = "v1=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return {
            "x-khaos-timestamp": timestamp,
            "x-khaos-message-id": message_id,
            "x-khaos-content-sha256": digest,
            "x-khaos-signature": signature,
        }

    body = b'{"id":"1","text":"hi"}'
    request_headers = headers(body, "message-id-00001")
    assert (await handler.handle(request_headers, body))["status"] == "ok"
    assert (await handler.handle(request_headers, body))["status"] == "signature_error"
    assert (await handler.handle(headers(b"no", "message-id-00002"), b"no"))["status"] == "parse_error"


@pytest.mark.asyncio
async def test_generic_rejects_missing_secret_stale_digest_and_signature():
    now = 1_700_000_000
    secret = "0123456789abcdef0123456789abcdef"
    body = b'{"id":"1","text":"run"}'
    assert (
        await WebhookHandler(ChannelType.WEBHOOK_IN, now=lambda: now).handle({}, body)
    )["status"] == "configuration_error"
    weak = WebhookHandler(ChannelType.WEBHOOK_IN, "short", now=lambda: now)
    assert (await weak.handle({}, body))["status"] == "signature_error"
    digest = hashlib.sha256(body).hexdigest()

    def signed_headers(timestamp: str, body_digest: str = digest) -> dict[str, str]:
        message_id = "message-id-00001"
        signed = f"v1\n{timestamp}\n{message_id}\n{body_digest}".encode()
        return {
            "x-khaos-timestamp": timestamp,
            "x-khaos-message-id": message_id,
            "x-khaos-content-sha256": body_digest,
            "x-khaos-signature": "v1=" + hmac.new(
                secret.encode(), signed, hashlib.sha256
            ).hexdigest(),
        }

    handler = WebhookHandler(ChannelType.WEBHOOK_IN, secret, now=lambda: now)
    assert (await handler.handle(signed_headers(str(now - 301)), body))["status"] == "signature_error"
    assert (await handler.handle(signed_headers(str(now), "0" * 64), body))["status"] == "signature_error"
    bad_signature = signed_headers(str(now))
    bad_signature["x-khaos-signature"] = "v1=" + "0" * 64
    assert (await handler.handle(bad_signature, body))["status"] == "signature_error"
    assert (await handler.handle(signed_headers("nan"), body))["status"] == "signature_error"
