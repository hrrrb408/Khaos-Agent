import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from khaos.channels import ChannelType, ContentType, WebhookHandler


@pytest.mark.asyncio
async def test_parse_telegram_photo_and_reply():
    body = json.dumps({"message": {"message_id": 2, "caption": "pic", "from": {"id": 3, "first_name": "A"}, "chat": {"id": 4}, "photo": [{"file_id": "x", "width": 10}], "reply_to_message": {"message_id": 1, "text": "old", "from": {"first_name": "B"}}}}).encode()
    messages = []
    result = await WebhookHandler(ChannelType.TELEGRAM, on_message=messages.append).handle({}, body)
    assert result == {"status": "ok", "message_id": "2"}
    assert messages[0].content_type == ContentType.IMAGE
    assert messages[0].reply_to.author == "B"


@pytest.mark.asyncio
async def test_slack_signature_and_file():
    body = json.dumps({"event": {"client_msg_id": "m", "text": "hi", "user": "u", "channel": "c", "files": [{"name": "x.txt"}]}}).encode()
    timestamp, secret = "1", "secret"
    signature = "v0=" + hmac.new(secret.encode(), b"v0:1:" + body, hashlib.sha256).hexdigest()
    messages = []
    result = await WebhookHandler(ChannelType.SLACK, secret, messages.append).handle({"X-Slack-Request-Timestamp": timestamp, "X-Slack-Signature": signature}, body)
    assert result["status"] == "ok"
    assert messages[0].attachments[0].file_name == "x.txt"


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
async def test_generic_and_parse_error():
    messages = []
    handler = WebhookHandler(ChannelType.WEBHOOK_IN, on_message=messages.append)
    assert (await handler.handle({}, b'{"id":"1","text":"hi"}'))["status"] == "ok"
    assert (await handler.handle({}, b"no"))["status"] == "parse_error"
