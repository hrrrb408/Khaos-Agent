"""Tests for environment-variable protection.

Verifies that:
- ``env``/``printenv`` commands are blocked by CommandGuard.
- Python code reading ``os.environ``/``getenv`` is flagged as risky.
- ``_build_safe_env()`` strips credential-bearing variables.
- The secret scanner detects leaked env-var credentials.
"""

from __future__ import annotations

import os

import pytest

from khaos.security.command_guard import CommandGuard
from khaos.security.secret_scanner import SecretScanner
from khaos.tools.terminal_tools import SAFE_ENV_PREFIXES, _build_safe_env


# ---------------------------------------------------------------------------
# CommandGuard: env / printenv blocked
# ---------------------------------------------------------------------------


def test_env_command_blocked() -> None:
    """The bare ``env`` command is blocked (it dumps all environment vars)."""
    result = CommandGuard().check("env")

    assert result.safe is False
    assert result.risk_level == "blocked"


def test_printenv_command_blocked() -> None:
    """``printenv`` is blocked for the same reason."""
    result = CommandGuard().check("printenv")

    assert result.safe is False
    assert result.risk_level == "blocked"


def test_env_in_pipeline_blocked() -> None:
    """``env`` reached via a pipe is still blocked (injection detection)."""
    result = CommandGuard().check("ls | env")

    assert result.safe is False


# ---------------------------------------------------------------------------
# CommandGuard: python getenv / os.environ flagged as risky
# ---------------------------------------------------------------------------


def test_python_getenv_detected() -> None:
    """Python code reading os.environ is flagged as risky (needs approval)."""
    result = CommandGuard().check('python -c "import os; print(os.environ)"')

    assert result.risk_level == "risky"
    assert result.safe is True  # risky ≠ blocked; it requires confirmation


def test_python_getenv_call_detected() -> None:
    """``getenv`` calls are also flagged."""
    result = CommandGuard().check('python -c "import os; os.getenv(\'KEY\')"')

    assert result.risk_level == "risky"


# ---------------------------------------------------------------------------
# _build_safe_env: credential stripping
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_credential_env(monkeypatch):
    """Populate the environment with safe + credential-bearing vars."""
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/test")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-secret-key-1234567890")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-secret-9876543210")
    monkeypatch.setenv("MY_DB_PASSWORD", "supersecret")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_abcdef1234567890")


def test_safe_env_excludes_api_keys(fake_credential_env) -> None:
    """_build_safe_env() strips OPENAI_API_KEY and similar credentials."""
    env = _build_safe_env()

    assert "OPENAI_API_KEY" not in env
    assert "ANTHROPIC_API_KEY" not in env
    assert "MY_DB_PASSWORD" not in env
    assert "GITHUB_TOKEN" not in env


def test_safe_env_includes_path(fake_credential_env) -> None:
    """_build_safe_env() keeps safe vars like PATH and HOME."""
    env = _build_safe_env()

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == "/home/test"


def test_safe_env_includes_exact_allowlist(monkeypatch) -> None:
    """Non-prefixed allowlisted vars (CI, GITHUB_ACTIONS) are forwarded."""
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")

    env = _build_safe_env()

    assert env["CI"] == "true"
    assert env["GITHUB_ACTIONS"] == "true"


def test_safe_env_prefixes_documented() -> None:
    """The safe-prefix list covers the documented essentials."""
    for expected in ("PATH", "HOME", "USER", "LANG", "TERM", "SHELL"):
        assert expected in SAFE_ENV_PREFIXES


# ---------------------------------------------------------------------------
# SecretScanner: env-var credential leak detection
# ---------------------------------------------------------------------------


def test_env_var_secret_detected() -> None:
    """An OPENAI_API_KEY=... assignment in output is flagged."""
    scanner = SecretScanner()
    result = scanner.scan_text("OPENAI_API_KEY=sk-proj-abcdefghijklmno0123456789")

    assert result.has_secrets is True
    categories = {match.category for match in result.secrets}
    assert "API Key in env var" in categories


def test_env_var_secret_anthropic_detected() -> None:
    scanner = SecretScanner()
    result = scanner.scan_text("ANTHROPIC_API_KEY=sk-ant-supersecret1234567890")

    assert result.has_secrets is True
