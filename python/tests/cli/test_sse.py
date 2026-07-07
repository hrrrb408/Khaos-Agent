import json

from khaos.agent import Message
from khaos.cli.sse import encode_sse, event_name_for


def test_encode_message_sse_frame():
    frame = encode_sse(Message(role="assistant", content="hello", token_count=1))

    assert frame.startswith("event: message\n")
    payload = json.loads(frame.split("data: ", 1)[1])
    assert payload["content"] == "hello"


def test_done_event_name():
    message = Message(role="system", content="done", token_count=3)

    assert event_name_for(message) == "done"
    assert "total_tokens" in encode_sse(message)


def test_permission_request_event_uses_metadata():
    frame = encode_sse(
        Message(
            role="system",
            content="permission_request",
            event="permission_request",
            metadata={"id": "1", "name": "terminal"},
        )
    )

    assert frame.startswith("event: permission_request\n")
    assert '"name": "terminal"' in frame


def test_tool_result_event_uses_metadata():
    frame = encode_sse(
        Message(
            role="tool",
            content="{}",
            event="tool_result",
            metadata={"id": "1", "success": True},
        )
    )

    assert frame.startswith("event: tool_result\n")
    assert '"success": true' in frame
