from khaos.channels import MediaAttachment, PlatformMessage, ReplyReference, Sender


def test_platform_message_plain_text():
    assert PlatformMessage(text="hello").plain_text() == "hello"


def test_platform_message_plain_text_with_reply():
    message = PlatformMessage(text="answer", reply_to=ReplyReference("1", "Ada", "question"))
    assert "Ada: question" in message.plain_text()


def test_platform_message_plain_text_with_attachments():
    message = PlatformMessage(attachments=[MediaAttachment(file_name="a.pdf")])
    assert message.plain_text() == "a.pdf"
    assert message.has_media()
    assert "1 attachment(s): a.pdf" in message.to_agent_input()


def test_defaults():
    assert Sender().role == "user"
    assert MediaAttachment().file_size == 0
