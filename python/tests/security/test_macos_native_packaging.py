"""Contracts for the concrete macOS launchd authority deployment."""

from __future__ import annotations

import importlib.util
import os
import plistlib
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[3]
PLIST = ROOT / "packaging" / "macos" / "com.khaos.authorityd.backend.plist"
WORKFLOW = ROOT / ".github" / "workflows" / "native-authority-production-e2e.yml"
RENDERER = ROOT / "scripts" / "render_macos_authority_backend_plist.py"


def _renderer_module():
    spec = importlib.util.spec_from_file_location("macos_backend_plist", RENDERER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _configure_renderer_environment(
    monkeypatch: pytest.MonkeyPatch, ca_file: Path
) -> None:
    monkeypatch.setenv("KHAOS_TEAM_ID", "TEAMID123")
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", "a" * 64)
    monkeypatch.setenv("KHAOS_AUTHORITYD_UID", "505")
    monkeypatch.setenv("KHAOS_AGENT_UID", "501")
    monkeypatch.setenv("KHAOS_AGENT_CODE_SIGNATURE", "com.khaos.agent")
    monkeypatch.setenv(
        "KHAOS_AUDIT_WORM_ENDPOINT", "https://127.0.0.1:8443/append"
    )
    monkeypatch.setenv("KHAOS_AUDIT_WORM_CA_FILE", str(ca_file))


def test_backend_template_keeps_launchd_logging_and_authority_identity_shape() -> None:
    with PLIST.open("rb") as handle:
        document = plistlib.load(handle)

    assert document["Label"] == "com.khaos.authorityd.backend"
    assert document["UserName"] == "khaos-authority"
    assert document["GroupName"] == "khaos-authority"
    assert document["EnvironmentVariables"]["KHAOS_AUTHORITYD_BACKEND_SOCKET"] == (
        "/var/run/khaos-authorityd/backend.sock"
    )
    assert document["StandardOutPath"] == "/var/log/khaos-authorityd-backend.log"
    assert document["StandardErrorPath"] == "/var/log/khaos-authorityd-backend.err.log"


def test_renderer_publishes_a_complete_concrete_backend_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_file = tmp_path / "worm-ca.pem"
    ca_file.write_text("test CA\n", encoding="utf-8")
    _configure_renderer_environment(monkeypatch, ca_file)
    output = tmp_path / "rendered" / "com.khaos.authorityd.backend.plist"

    _renderer_module().render_backend_plist(PLIST, output)

    with output.open("rb") as handle:
        document = plistlib.load(handle)
    environment = document["EnvironmentVariables"]
    assert environment["KHAOS_EFFECTIVE_POLICY_DIGEST"] == "a" * 64
    assert environment["KHAOS_AUDIT_WORM_ENDPOINT"] == (
        "https://127.0.0.1:8443/append"
    )
    assert environment["KHAOS_AUDIT_WORM_CA_FILE"] == str(ca_file)
    assert environment["KHAOS_AUTHORITYD_UID"] == "505"
    assert environment["KHAOS_AUTHORITY_PROFILE"] == "native-production"
    assert environment["KHAOS_AUTHORITYD_LAUNCHD_SERVICE"] == "com.khaos.authorityd"
    assert environment["KHAOS_AUTHORITYD_KEYCHAIN_GROUP"] == (
        "TEAMID123.com.khaos.authority"
    )
    assert environment["KHAOS_AUTHORITYD_AGENT_CODE_REQUIREMENT"] == (
        'identifier "com.khaos.agent" and anchor apple generic '
        "and certificate leaf[subject.OU] = TEAMID123"
    )
    # The private-mode contract is consumed by launchd on POSIX. Windows
    # exposes chmod bits as compatibility metadata and cannot represent the
    # POSIX 0600 mode that the macOS deployment requires.
    if os.name == "posix":
        assert output.stat().st_mode & 0o777 == 0o600


def test_renderer_rejects_a_missing_or_non_file_worm_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ca_file = tmp_path / "missing-ca.pem"
    _configure_renderer_environment(monkeypatch, ca_file)

    with pytest.raises(SystemExit, match="KHAOS_AUDIT_WORM_CA_FILE"):
        _renderer_module().render_backend_plist(
            PLIST, tmp_path / "rendered.plist"
        )


def test_macos_workflow_renders_and_owns_the_native_receiver_lifecycle() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "render_macos_authority_backend_plist.py" in source
    assert "--template packaging/macos/com.khaos.authorityd.backend.plist" in source
    assert "--output /tmp/com.khaos.authorityd.backend.plist" in source
    assert "sudo cp /tmp/com.khaos.authorityd.backend.plist" in source
    assert "sudo cp packaging/macos/com.khaos.authorityd.backend.plist" not in source
    assert "nohup \"$VENV_PY\"" in source
    assert "/tmp/khaos-worm-receiver.pid" in source
    assert "kill -0 \"$WORM_PID\"" in source
    assert "--cacert /tmp/khaos-worm-ca.pem" in source
    assert "KHAOS_AUDIT_WORM_CA_FILE=/tmp/khaos-worm-ca.pem" in source
    assert "https://127.0.0.1:8443/append" in source
