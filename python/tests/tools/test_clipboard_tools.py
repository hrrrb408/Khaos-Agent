import subprocess

from khaos.tools import clipboard_tools
from khaos.tools.clipboard_tools import clipboard_read, clipboard_write


class _RunResult:
    def __init__(self, stdout: str = ""):
        self.stdout = stdout


async def test_clipboard_read_macos_pbpaste(monkeypatch):
    calls = []

    def fake_run(command, capture_output, check, text, input=None):
        calls.append(command)
        assert command == ["pbpaste"]
        assert capture_output is True
        assert check is True
        assert text is True
        assert input is None
        return _RunResult("clipboard text")

    monkeypatch.setattr(clipboard_tools.sys, "platform", "darwin")
    monkeypatch.setattr(clipboard_tools.subprocess, "run", fake_run)

    result = await clipboard_read()

    assert calls == [["pbpaste"]]
    assert result == {"ok": True, "content": "clipboard text", "length": 14}


async def test_clipboard_read_linux_xclip(monkeypatch):
    calls = []

    def fake_run(command, capture_output, check, text, input=None):
        calls.append(command)
        if command[0] == "xclip":
            return _RunResult("linux text")
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(clipboard_tools.sys, "platform", "linux")
    monkeypatch.setattr(clipboard_tools.subprocess, "run", fake_run)

    result = await clipboard_read()

    assert calls == [["xclip", "-selection", "clipboard", "-o"]]
    assert result == {"ok": True, "content": "linux text", "length": 10}


async def test_clipboard_not_accessible(monkeypatch):
    def fake_run(command, capture_output, check, text, input=None):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr(clipboard_tools.sys, "platform", "linux")
    monkeypatch.setattr(clipboard_tools.subprocess, "run", fake_run)

    result = await clipboard_read()

    assert result == {"ok": False, "error": "Clipboard not accessible"}


async def test_clipboard_write(monkeypatch):
    calls = []

    def fake_run(command, capture_output, check, text, input=None):
        calls.append((command, input))
        if command[0] == "xclip":
            raise subprocess.CalledProcessError(1, command)
        return _RunResult()

    monkeypatch.setattr(clipboard_tools.sys, "platform", "linux")
    monkeypatch.setattr(clipboard_tools.subprocess, "run", fake_run)

    result = await clipboard_write("write me")

    assert calls == [
        (["xclip", "-selection", "clipboard", "-i"], "write me"),
        (["xsel", "--clipboard", "--input"], "write me"),
    ]
    assert result == {"ok": True, "length": 8}
