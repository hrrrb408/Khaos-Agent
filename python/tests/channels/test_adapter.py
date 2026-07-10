import pytest

from khaos.channels import DiscordAdapter, Message, SlackAdapter, TelegramAdapter, WeChatAdapter


@pytest.mark.asyncio
async def test_adapter_formats_and_send():
    message = Message("hello", target="42", reply_to_id="1", parse_mode="markdown", media_paths=["p.png"])
    assert (await TelegramAdapter().format_outbound(message))["photo"] == "p.png"
    assert (await DiscordAdapter().format_outbound(message))["message_reference"]["message_id"] == "1"
    assert (await SlackAdapter().format_outbound(message))["mrkdwn"] is True
    assert (await WeChatAdapter().format_outbound(message))["touser"] == "42"
    assert (await TelegramAdapter().send(message)).success
    assert await TelegramAdapter().send_typing("42")
