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
