"""Batch 10.3 (round-10 §六): TCB tool absolute-path resolution regressions.

``ip``/``nft`` were previously invoked via bare PATH lookup
(``subprocess.run(["ip", ...])``).  Under Root or CAP_NET_ADMIN a
malicious PATH entry equals arbitrary high-privilege code execution
before the sandbox is established.  These tests verify the tools are
now resolved to validated absolute paths.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from khaos.security.browser_sandbox import (
    BrowserSandboxError,
    _resolve_tcb_tool,
    _tcb_tool_cache,
)


def _make_binary(path: Path, *, mode: int = 0o755) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"#!/bin/sh\nexit 0\n")
    os.chmod(path, mode)
    return path


def test_resolve_tcb_tool_returns_absolute_path(monkeypatch, tmp_path) -> None:
    """_resolve_tcb_tool returns the absolute resolved path."""
    binary = _make_binary(tmp_path / "ip")
    # Clear the module-level cache so the test is isolated.
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which",
        lambda name: str(binary) if name == "ip" else None,
    )
    resolved = _resolve_tcb_tool("ip", validate=False)
    assert resolved == str(binary)
    assert Path(resolved).is_absolute()


def test_resolve_tcb_tool_caches_result(monkeypatch, tmp_path) -> None:
    """Resolution is cached for the process lifetime."""
    cache: dict[str, str] = {}
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", cache
    )
    binary = _make_binary(tmp_path / "nft")
    call_count = {"n": 0}

    def counting_which(name: str) -> str | None:
        call_count["n"] += 1
        return str(binary) if name == "nft" else None

    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which", counting_which
    )
    first = _resolve_tcb_tool("nft", validate=False)
    second = _resolve_tcb_tool("nft", validate=False)
    assert first == second == str(binary)
    assert call_count["n"] == 1, "shutil.which must be called only once"


def test_production_rejects_group_writable_ip(monkeypatch, tmp_path) -> None:
    """Production (validate=True) rejects a group-writable ip binary."""
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    binary = _make_binary(tmp_path / "ip", mode=0o774)  # group-writable
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which",
        lambda name: str(binary) if name == "ip" else None,
    )
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        _resolve_tcb_tool("ip", validate=True)


def test_production_rejects_symlink_ip(monkeypatch, tmp_path) -> None:
    """Production rejects a symlink ip binary (O_NOFOLLOW)."""
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    target = _make_binary(tmp_path / "real-ip")
    link = tmp_path / "ip"
    link.symlink_to(target)
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which",
        lambda name: str(link) if name == "ip" else None,
    )
    with pytest.raises(BrowserSandboxError, match="secure open failed"):
        _resolve_tcb_tool("ip", validate=True)


def test_production_rejects_missing_tool(monkeypatch) -> None:
    """Production raises when the tool is not on PATH."""
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which", lambda name: None
    )
    with pytest.raises(BrowserSandboxError, match="not found on PATH"):
        _resolve_tcb_tool("nft", validate=True)


def test_dev_mode_returns_bare_name_when_missing(monkeypatch) -> None:
    """Dev mode (validate=False) returns the bare name if not found."""
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which", lambda name: None
    )
    assert _resolve_tcb_tool("ip", validate=False) == "ip"


def test_run_command_resolves_bare_ip_nft(monkeypatch, tmp_path) -> None:
    """_run_command transparently resolves argv[0] ip/nft to absolute."""
    from khaos.security import browser_sandbox as bs

    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    binary = _make_binary(tmp_path / "ip")
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        class _R:
            returncode = 0
            stderr = ""
            stdout = ""
        return _R()

    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which",
        lambda name: str(binary) if name == "ip" else None,
    )
    monkeypatch.setattr(bs.subprocess, "run", fake_run)
    bs._run_command(["ip", "netns", "list"], "test")
    assert captured[0][0] == str(binary), (
        "_run_command must resolve bare 'ip' to the absolute path"
    )
    assert captured[0][1:] == ["netns", "list"]
