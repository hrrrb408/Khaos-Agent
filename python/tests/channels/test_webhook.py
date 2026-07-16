import hashlib
import hmac
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from khaos.channels import (
    ChannelType,
    ContentType,
    WebhookHandler,
    WebhookReplayGuard,
)
from khaos.db import Database


@pytest.mark.asyncio
async def test_parse_telegram_photo_and_reply():
    body = json.dumps({"update_id": 100, "message": {"message_id": 2, "caption": "pic", "from": {"id": 3, "first_name": "A"}, "chat": {"id": 4}, "photo": [{"file_id": "x", "width": 10}], "reply_to_message": {"message_id": 1, "text": "old", "from": {"first_name": "B"}}}}).encode()
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
    assert (await handler.handle(headers(now), body))["status"] == "replay_error"


@pytest.mark.asyncio
async def test_discord_ed25519_signature():
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    now = 1_700_000_000
    timestamp = str(now)
    body = b'{"id":"interaction-1","data":{"content":"hello"}}'
    signature = private_key.sign(timestamp.encode() + body).hex()
    handler = WebhookHandler(
        ChannelType.DISCORD, public_key.hex(), now=lambda: now
    )

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

    replayed = await handler.handle(
        {"x-signature-timestamp": timestamp, "x-signature-ed25519": signature},
        body,
    )
    assert replayed["status"] == "replay_error"


@pytest.mark.asyncio
async def test_wechat_xml_and_bad_signature():
    now = 1_700_000_000
    timestamp, nonce, secret = str(now), "nonce-1", "token"
    body = b"<xml><MsgId>8</MsgId><Content><![CDATA[hello]]></Content><FromUserName>u</FromUserName></xml>"
    messages = []
    handler = WebhookHandler(
        ChannelType.WECHAT, secret, messages.append, now=lambda: now
    )
    query = {
        "timestamp": timestamp,
        "nonce": nonce,
        "signature": hashlib.sha1(
            "".join(sorted((secret, timestamp, nonce))).encode()
        ).hexdigest(),
    }
    assert (await handler.handle({}, body, {**query, "signature": "bad"}))["status"] == "signature_error"
    assert (await handler.handle({}, body, query))["message_id"] == "8"
    assert (await handler.handle({}, body, query))["status"] == "replay_error"
    assert messages[0].text == "hello"


@pytest.mark.asyncio
async def test_wechat_image_and_location_types():
    now = 1_700_000_000
    secret = "token"
    messages = []
    image = b"<xml><MsgType>image</MsgType><MsgId>9</MsgId><PicUrl>https://img</PicUrl></xml>"
    location = b"<xml><MsgType>location</MsgType><MsgId>10</MsgId><Label>Shanghai</Label><Location_X>31.2</Location_X><Location_Y>121.5</Location_Y></xml>"
    handler = WebhookHandler(
        ChannelType.WECHAT, secret, messages.append, now=lambda: now
    )

    def query(nonce: str) -> dict[str, str]:
        timestamp = str(now)
        return {
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hashlib.sha1(
                "".join(sorted((secret, timestamp, nonce))).encode()
            ).hexdigest(),
        }

    await handler.handle({}, image, query("image"))
    await handler.handle({}, location, query("location"))
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
        signed = f"v2\nwebhook_in\ndefault\n{timestamp}\n{message_id}\n{digest}".encode()
        signature = "v2=" + hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
        return {
            "x-khaos-timestamp": timestamp,
            "x-khaos-message-id": message_id,
            "x-khaos-content-sha256": digest,
            "x-khaos-signature": signature,
        }

    body = b'{"id":"1","text":"hi"}'
    request_headers = headers(body, "message-id-00001")
    assert (await handler.handle(request_headers, body))["status"] == "ok"
    assert (await handler.handle(request_headers, body))["status"] == "replay_error"
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
        signed = f"v2\nwebhook_in\ndefault\n{timestamp}\n{message_id}\n{body_digest}".encode()
        return {
            "x-khaos-timestamp": timestamp,
            "x-khaos-message-id": message_id,
            "x-khaos-content-sha256": body_digest,
            "x-khaos-signature": "v2=" + hmac.new(
                secret.encode(), signed, hashlib.sha256
            ).hexdigest(),
        }

    handler = WebhookHandler(ChannelType.WEBHOOK_IN, secret, now=lambda: now)
    assert (await handler.handle(signed_headers(str(now - 301)), body))["status"] == "signature_error"
    assert (await handler.handle(signed_headers(str(now), "0" * 64), body))["status"] == "signature_error"
    bad_signature = signed_headers(str(now))
    bad_signature["x-khaos-signature"] = "v2=" + "0" * 64
    assert (await handler.handle(bad_signature, body))["status"] == "signature_error"
    assert (await handler.handle(signed_headers("nan"), body))["status"] == "signature_error"


@pytest.mark.asyncio
async def test_generic_signature_is_bound_to_khaos_channel_id():
    now = 1_700_000_000
    secret = "0123456789abcdef0123456789abcdef"
    body = b'{"id":"1","text":"run"}'
    timestamp = str(now)
    message_id = "message-id-00001"
    digest = hashlib.sha256(body).hexdigest()
    signed = (
        f"v2\nwebhook_in\nchannel-a\n{timestamp}\n{message_id}\n{digest}"
    ).encode()
    headers = {
        "x-khaos-timestamp": timestamp,
        "x-khaos-message-id": message_id,
        "x-khaos-content-sha256": digest,
        "x-khaos-signature": "v2=" + hmac.new(
            secret.encode(), signed, hashlib.sha256
        ).hexdigest(),
    }

    accepted = WebhookHandler(
        ChannelType.WEBHOOK_IN,
        secret,
        channel_id="channel-a",
        now=lambda: now,
    )
    wrong_channel = WebhookHandler(
        ChannelType.WEBHOOK_IN,
        secret,
        channel_id="channel-b",
        now=lambda: now,
    )
    assert (await accepted.handle(headers, body))["status"] == "ok"
    assert (await wrong_channel.handle(headers, body))["status"] == "signature_error"


@pytest.mark.asyncio
async def test_telegram_update_id_replay_survives_runtime_restart(tmp_path):
    path = tmp_path / "khaos.db"
    body = json.dumps({
        "update_id": 4242,
        "message": {
            "message_id": 7,
            "text": "run",
            "from": {"id": 1},
            "chat": {"id": 2},
        },
    }).encode()
    headers = {"x-telegram-bot-api-secret-token": "telegram-secret"}

    first_db = Database(path)
    await first_db.connect()
    await first_db.run_migrations()
    first = WebhookHandler(
        ChannelType.TELEGRAM,
        "telegram-secret",
        channel_id="telegram-primary",
        replay_guard=WebhookReplayGuard(
            consumer=first_db.consume_webhook_event
        ),
    )
    assert (await first.handle(headers, body))["status"] == "ok"
    await first_db.close()

    restarted_db = Database(path)
    await restarted_db.connect()
    await restarted_db.run_migrations()
    restarted = WebhookHandler(
        ChannelType.TELEGRAM,
        "telegram-secret",
        channel_id="telegram-primary",
        replay_guard=WebhookReplayGuard(
            consumer=restarted_db.consume_webhook_event
        ),
    )
    assert (await restarted.handle(headers, body))["status"] == "replay_error"
    await restarted_db.close()
