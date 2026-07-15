from khaos.tui.view_model import build_approval_view, tool_diff_preview


def test_approval_view_exposes_binding_scope_and_expiry():
    view = build_approval_view(
        {
            "name": "terminal",
            "arguments": {"command": "make test"},
            "level": "execute",
            "principal_id": "user:1",
            "task_id": "task:1",
            "workspace_id": "workspace:1",
            "binding_digest": "b" * 64,
            "arguments_digest": "a" * 64,
            "profile_digest": "p" * 64,
            "expires_at": 130.0,
        },
        now=100.0,
    )

    assert view.target == "make test"
    assert view.expires_in_seconds == 30
    assert view.binding_digest == "b" * 16
    assert view.arguments_digest == "a" * 16
    assert view.profile_digest == "p" * 16
    assert not view.expired


def test_approval_view_marks_stale_request_expired():
    view = build_approval_view({"expires_at": 99.0}, now=100.0)

    assert view.expired
    assert view.expires_in_seconds == 0


def test_diff_preview_only_accepts_tool_supplied_artifact():
    assert tool_diff_preview({"output": "updated file"}) is None
    assert tool_diff_preview({"output": {"path": "a.py"}}) is None
    assert tool_diff_preview(
        {"output": {"path": "a.py", "diff": "--- a.py\n+++ a.py"}}
    ) == ("a.py", "--- a.py\n+++ a.py")
