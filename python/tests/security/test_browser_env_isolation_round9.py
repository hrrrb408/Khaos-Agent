"""Batch 9.1 (round-9 §九): Chromium environment isolation regressions.

Verifies that ``BrowserNetworkSandbox.launcher_environment()`` returns the
COMPLETE Chromium environment (no ``os.environ`` inheritance) and that only
an explicit allowlist of benign runtime variables is forwarded.  Provider
API keys, cloud credentials, proxy secrets and any other parent-process env
must NOT appear in the dict that becomes Chromium's environment.
"""

from __future__ import annotations

import os

import pytest

from khaos.security.browser_sandbox import BrowserNetworkSandbox, _BROWSER_ENV_ALLOWLIST


def _active_sandbox(monkeypatch) -> BrowserNetworkSandbox:
    """Return a sandbox instance whose launcher_environment() is callable."""
    sandbox = BrowserNetworkSandbox.__new__(BrowserNetworkSandbox)
    sandbox._active = True
    sandbox._netns_name = "khaos-br-test"
    sandbox._cgroup_path = None
    sandbox._require_os_sandbox = False  # dev mode: skip TCB validation
    sandbox._production_authority = False
    # The launcher binary is not built in unit-test environments; stub it.
    monkeypatch.setattr(
        BrowserNetworkSandbox, "_locate_browser_launcher",
        staticmethod(lambda: "/usr/local/bin/khaos-sandbox-launcher"),
    )
    return sandbox


# Variables that must NEVER reach Chromium, regardless of deployment.
_SENSITIVE_VARS = [
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "DATABASE_URL",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "GH_TOKEN",
    "KHAOS_SENTINEL_SECRET",
]


def test_launcher_environment_excludes_parent_secrets(monkeypatch) -> None:
    """Parent-process secrets must not leak into the Chromium environment."""
    # Populate os.environ with sensitive vars + allowlist vars.
    for name in _SENSITIVE_VARS:
        monkeypatch.setenv(name, f"secret-{name}")
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("LANG", "en_US.UTF-8")

    sandbox = _active_sandbox(monkeypatch)
    env = sandbox.launcher_environment("/opt/chromium")

    for secret in _SENSITIVE_VARS:
        assert secret not in env, (
            f"sensitive env var {secret} leaked into Chromium environment"
        )


def test_launcher_environment_forwards_allowlist_only(monkeypatch) -> None:
    """Only the explicit allowlist vars (when set) are forwarded."""
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin")
    monkeypatch.setenv("LANG", "C.UTF-8")
    monkeypatch.setenv("PLAYWRIGHT_BROWSERS_PATH", "/opt/khaos-playwright")
    # An unset allowlist var must be absent (not empty string).
    monkeypatch.delenv("LC_ALL", raising=False)
    monkeypatch.delenv("TZ", raising=False)

    sandbox = _active_sandbox(monkeypatch)
    env = sandbox.launcher_environment("/opt/chromium")

    assert env["PATH"] == "/usr/local/bin:/usr/bin"
    assert env["LANG"] == "C.UTF-8"
    assert env["PLAYWRIGHT_BROWSERS_PATH"] == "/opt/khaos-playwright"
    assert "LC_ALL" not in env
    assert "TZ" not in env


def test_launcher_environment_includes_authority_metadata(monkeypatch) -> None:
    """The four KHAOS_BROWSER_* authority vars + host home are present."""
    monkeypatch.setenv("PATH", "/usr/bin")
    sandbox = _active_sandbox(monkeypatch)
    env = sandbox.launcher_environment("/opt/chromium")

    assert env["KHAOS_BROWSER_LAUNCH"] == "1"
    assert env["KHAOS_BROWSER_REAL_EXECUTABLE"] == "/opt/chromium"
    assert env["KHAOS_BROWSER_NETNS"] == "khaos-br-test"
    # Batch 9.2: resolved host home is forwarded for masking.
    assert env["KHAOS_BROWSER_HOST_HOME"]


def test_launcher_environment_forwards_cgroup_procs(monkeypatch) -> None:
    """When a cgroup path is set, KHAOS_BROWSER_CGROUP_PROCS is included."""
    from pathlib import Path

    monkeypatch.setenv("PATH", "/usr/bin")
    sandbox = _active_sandbox(monkeypatch)
    sandbox._cgroup_path = Path("/sys/fs/cgroup/khaos-browser/leaf")
    env = sandbox.launcher_environment("/opt/chromium")

    assert env["KHAOS_BROWSER_CGROUP_PROCS"] == str(
        Path("/sys/fs/cgroup/khaos-browser/leaf") / "cgroup.procs"
    )


def test_allowlist_constant_does_not_include_secrets() -> None:
    """Guard against accidentally adding sensitive prefixes to the allowlist."""
    for name in _BROWSER_ENV_ALLOWLIST:
        upper = name.upper()
        for forbidden in ("KEY", "SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PROXY"):
            assert forbidden not in upper, (
                f"allowlist var {name} contains sensitive substring {forbidden}"
            )
