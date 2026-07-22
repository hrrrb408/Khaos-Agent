"""Tests for the network access control guard."""

from __future__ import annotations

from khaos.security.network_guard import NetworkGuard


def test_network_disabled_blocks_curl() -> None:
    """Default (network off) blocks curl."""
    guard = NetworkGuard()
    result = guard.check_tool("terminal", {"command": "curl https://example.com"})

    assert result.allowed is False
    assert "example.com" in result.reason


def test_network_disabled_blocks_wget() -> None:
    """Default (network off) blocks wget."""
    guard = NetworkGuard()
    result = guard.check_tool("terminal", {"command": "wget http://example.com/file"})

    assert result.allowed is False
    assert result.domain == "example.com"


def test_git_local_commands_allowed() -> None:
    """git add/commit/diff/log are local and allowed even with network off."""
    guard = NetworkGuard()
    for command in ["git add .", "git commit -m x", "git diff", "git log"]:
        result = guard.check_tool("terminal", {"command": command})
        assert result.allowed is True, f"blocked local git: {command}"


def test_git_network_commands_blocked() -> None:
    """git push/pull/fetch/clone are network operations and blocked."""
    guard = NetworkGuard()
    for sub in ["push", "pull", "fetch", "clone"]:
        result = guard.check_tool("terminal", {"command": f"git {sub}"})
        assert result.allowed is False, f"allowed network git: git {sub}"
        assert "git" in result.reason


def test_non_network_command_allowed() -> None:
    """ls/cat/pytest do not touch the network."""
    guard = NetworkGuard()
    for command in ["ls -la", "cat file.txt", "pytest -q", "echo hello"]:
        result = guard.check_tool("terminal", {"command": command})
        assert result.allowed is True, f"blocked non-network: {command}"


def test_url_blocked() -> None:
    """browser_navigate is blocked by default (no allowlist)."""
    guard = NetworkGuard()
    result = guard.check_tool(
        "browser_navigate", {"url": "https://evil.example.com"}
    )

    assert result.allowed is False
    assert result.domain == "evil.example.com"


def test_domain_allowlist() -> None:
    """H1: an allowlisted domain is allowed when network is enabled.

    The previous semantics (allowlist bypasses ``network_enabled=False``)
    was a fail-open: an allowlist like ``[pypi.org]`` silently granted
    unrestricted network access because the first line of ``check_tool``
    was ``if self.network_enabled: return allowed``.  ``network_enabled``
    is now a TOTAL SWITCH — when off, all network access is blocked;
    when on, the allowlist narrows what's permitted.
    """
    guard = NetworkGuard(network_enabled=True, allowed_domains=["pypi.org"])
    result = guard.check_tool("terminal", {"command": "curl https://pypi.org/simple"})

    assert result.allowed is True
    assert result.domain == "pypi.org"


def test_domain_wildcard() -> None:
    """H1: subdomain matching — allowlisting github.com allows api.github.com
    when network is enabled."""
    guard = NetworkGuard(network_enabled=True, allowed_domains=["github.com"])
    result = guard.check_tool("terminal", {"command": "curl https://api.github.com"})

    assert result.allowed is True
    assert result.domain == "api.github.com"


def test_network_enabled_allows_all() -> None:
    """network_enabled=True bypasses all checks."""
    guard = NetworkGuard(network_enabled=True)
    result = guard.check_tool("terminal", {"command": "curl https://anything.com"})

    assert result.allowed is True


def test_blocked_domain_overrides_allowlist() -> None:
    """A blocked domain wins even if it matches the allowlist pattern."""
    guard = NetworkGuard(
        allowed_domains=["example.com"], blocked_domains=["bad.example.com"]
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://bad.example.com"}
    )

    assert result.allowed is False


def test_empty_url_allowed() -> None:
    """An empty url argument is treated as non-network."""
    guard = NetworkGuard()
    result = guard.check_tool("browser_navigate", {"url": ""})

    assert result.allowed is True


def test_websocket_url_uses_the_same_domain_allowlist() -> None:
    """WebSocket schemes are parsed before applying the domain policy."""
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["socket.example.com"],
    )

    allowed = guard.check_tool(
        "browser_navigate", {"url": "wss://socket.example.com/events"}
    )
    denied = guard.check_tool(
        "browser_navigate", {"url": "ws://other.example.com/events"}
    )

    assert allowed.allowed is True
    assert denied.allowed is False
