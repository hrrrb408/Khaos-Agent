import pytest
import httpx

from khaos.channels import DiscordAdapter, Message, SlackAdapter, TelegramAdapter, WeChatAdapter


@pytest.mark.asyncio
async def test_adapter_formats_and_send():
    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("sendChatAction"):
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(200, json={"ok": True, "result": {"message_id": 9}})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    message = Message("hello", target="42", reply_to_id="1", parse_mode="markdown", media_paths=["p.png"])
    assert (await TelegramAdapter().format_outbound(message))["photo"] == "p.png"
    assert (await DiscordAdapter().format_outbound(message))["message_reference"]["message_id"] == "1"
    assert (await SlackAdapter().format_outbound(message))["mrkdwn"] is True
    assert (await WeChatAdapter().format_outbound(message))["touser"] == "42"
    result = await TelegramAdapter(http_client=client).send(message)
    assert result.success and result.platform_message_id == "9"
    assert await TelegramAdapter(http_client=client).send_typing("42")
    await client.aclose()


@pytest.mark.asyncio
async def test_discord_bot_token_never_follows_arbitrary_https_target():
    requests: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "1"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    adapter = DiscordAdapter(token="bot-secret", http_client=client)
    result = await adapter.send(Message("hello", target="https://attacker.invalid/hook"))
    assert result.success is False
    assert requests == []
    await client.aclose()


@pytest.mark.asyncio
async def test_discord_configured_webhook_has_no_bot_authorization_header():
    requests: list[httpx.Request] = []
    webhook = "https://discord.com/api/webhooks/123/token"

    async def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"id": "1"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(respond))
    adapter = DiscordAdapter(
        token="bot-secret", webhook_url=webhook, http_client=client
    )
    result = await adapter.send(Message("hello", target="webhook"))
    assert result.success is True
    assert requests[0].url == httpx.URL(webhook)
    assert "authorization" not in requests[0].headers
    await client.aclose()
