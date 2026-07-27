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


def test_production_rejects_symlink_to_group_writable_ip(monkeypatch, tmp_path) -> None:
    """Production rejects a symlink whose target is group-writable."""
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._tcb_tool_cache", {}
    )
    target = _make_binary(tmp_path / "real-ip", mode=0o774)  # group-writable
    link = tmp_path / "ip"
    link.symlink_to(target)
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.shutil.which",
        lambda name: str(link) if name == "ip" else None,
    )
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
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


# ---------------------------------------------------------------------------
# Batch 11.1 (round-11 §四): TCB cache validation-bypass regressions.
# ---------------------------------------------------------------------------

def test_dev_probe_then_production_request_re_validates(monkeypatch, tmp_path) -> None:
    """Cache poisoning regression: a validate=False probe must NOT let a
    later validate=True call skip validation.

    Production startup calls _has_net_admin (validate=False in the old
    code) BEFORE _assert_resource_names_available (validate=True).  The
    old cache stored only the path string, so the validate=True call hit
    the cache and skipped _validate_tcb_binary entirely.  A malicious
    group-writable ip would be executed with CAP_NET_ADMIN.
    """
    from khaos.security import browser_sandbox as bs
    from khaos.security.browser_sandbox import TrustedTool

    # A group-writable binary that MUST be rejected by validate=True.
    binary = _make_binary(tmp_path / "ip", mode=0o774)
    monkeypatch.setattr(bs, "_tcb_tool_cache", {})
    monkeypatch.setattr(
        bs.shutil, "which",
        lambda name: str(binary) if name == "ip" else None,
    )
    validate_calls = {"count": 0}
    original_validate = bs._validate_tcb_binary

    def counting_validate(path, *, label):
        validate_calls["count"] += 1
        return original_validate(path, label=label)

    monkeypatch.setattr(bs, "_validate_tcb_binary", counting_validate)

    # Step 1: dev probe (validate=False) — caches unvalidated path.
    result1 = _resolve_tcb_tool("ip", validate=False)
    assert result1 == str(binary)
    assert validate_calls["count"] == 0, "validate=False must not validate"
    cached = bs._tcb_tool_cache.get("ip")
    assert cached is not None and cached.validated is False

    # Step 2: production request (validate=True) — MUST re-validate.
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        _resolve_tcb_tool("ip", validate=True)
    assert validate_calls["count"] == 1, (
        "validate=True after validate=False MUST re-validate the cached "
        "unvalidated entry (cache poisoning regression)"
    )


def test_validated_cache_entry_not_re_validated(monkeypatch, tmp_path) -> None:
    """A validated cache entry is trusted on subsequent validate=True calls
    (no redundant re-validation)."""
    from khaos.security import browser_sandbox as bs

    binary = _make_binary(tmp_path / "nft", mode=0o755)
    monkeypatch.setattr(bs, "_tcb_tool_cache", {})
    monkeypatch.setattr(
        bs.shutil, "which",
        lambda name: str(binary) if name == "nft" else None,
    )
    validate_calls = {"count": 0}
    original_validate = bs._validate_tcb_binary

    def counting_validate(path, *, label):
        validate_calls["count"] += 1
        return original_validate(path, label=label)

    monkeypatch.setattr(bs, "_validate_tcb_binary", counting_validate)

    _resolve_tcb_tool("nft", validate=True)
    assert validate_calls["count"] == 1
    # Second validate=True call should hit cache (already validated).
    _resolve_tcb_tool("nft", validate=True)
    assert validate_calls["count"] == 1, (
        "already-validated cache entry must not be re-validated"
    )


def test_production_capability_probe_uses_validated_tool(monkeypatch, tmp_path) -> None:
    """_has_net_admin(validate=True) must use a validated ip binary.

    This reproduces the production startup order: _check_prerequisites
    passes require_os_sandbox → _has_net_admin(validate=True)."""
    from khaos.security import browser_sandbox as bs

    binary = _make_binary(tmp_path / "ip", mode=0o774)  # group-writable
    monkeypatch.setattr(bs, "_tcb_tool_cache", {})
    monkeypatch.setattr(
        bs.shutil, "which",
        lambda name: str(binary) if name == "ip" else None,
    )
    # Force the Linux platform gate so the probe reaches _resolve_tcb_tool.
    monkeypatch.setattr(bs.sys, "platform", "linux")
    # Production probe with validate=True must reject the bad binary.
    with pytest.raises(BrowserSandboxError, match="group/other writable"):
        bs._has_net_admin(validate=True)
