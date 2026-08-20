"""Contracts for the native Windows authority backend service host."""

from __future__ import annotations

from pathlib import Path

import pytest
from khaos.security.authorityd_main import _authority_transport_value

ROOT = Path(__file__).resolve().parents[3]
HOST = ROOT / "rust" / "khaos-core" / "src" / "bin" / "khaos-authorityd-backend-windows.rs"
ENTRY = ROOT / "packaging" / "windows" / "authorityd-backend-entry.py"
WORKFLOW = ROOT / ".github" / "workflows" / "native-authority-production-e2e.yml"


def test_backend_host_is_a_real_scm_service_with_owned_child_lifecycle() -> None:
    source = HOST.read_text(encoding="utf-8")

    assert "StartServiceCtrlDispatcherW" in source
    assert 'const SERVICE_NAME: &str = "KhaosAuthorityDBackend"' in source
    assert "RegisterServiceCtrlHandlerExW" in source
    assert "SERVICE_CONTROL_STOP" in source
    assert "CreateJobObjectW" in source
    assert "JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE" in source
    assert "AssignProcessToJobObject" in source
    assert "TerminateJobObject" in source
    assert "QueryInformationJobObject" in source
    assert "ActiveProcesses == 0" in source
    assert "WaitForSingleObject(process, CHILD_STOP_TIMEOUT_MS)" in source
    assert 'args(["-I", "-S"])' in source
    assert ".env_clear()" in source
    assert "Command::new(&config.python)" in source
    assert "cmd.exe" not in source.lower()
    assert "powershell" not in source.lower()


def test_backend_entry_uses_only_the_staged_site_tree() -> None:
    source = ENTRY.read_text(encoding="utf-8")

    assert "backend-site" in source
    assert "sys.path.insert(0, str(site_root))" in source
    assert 'runpy.run_module("khaos.security.authorityd_main", run_name="__main__")' in source
    assert "PYTHONPATH" not in source


def test_windows_workflow_uses_the_native_backend_host() -> None:
    source = WORKFLOW.read_text(encoding="utf-8")

    assert "--bin khaos-authorityd-backend-windows" in source
    assert "authorityd-backend-entry.py" in source
    assert "authorityd-backend.env" in source
    assert "khaos-authorityd-backend-windows.exe" in source
    assert "khaos-authorityd-backend.cmd" not in source
    assert "sc.exe\" create KhaosAuthorityDBackend" in source
    assert "Resolve-Path" in source
    assert "Scripts\\python.exe" in source
    assert "Lib\\site-packages" in source
    assert "Test-Path -LiteralPath $venvSite -PathType Container" in source
    assert "$venvPython = (uv run --project . which python)" not in source
    assert "KHAOS_AUTHORITYD_SOCKET=unused" not in source
    assert "KHAOS_AUTHORITYD_BACKEND_PIPE=\\\\.\\pipe\\KhaosAuthorityDBackend" in source
    assert "KHAOS_AUDIT_WORM_CA_FILE=$env:KHAOS_AUDIT_WORM_CA_FILE" in source
    assert "-SkipCertificateCheck" in source
    assert "start_worm_audit_receiver.ps1" in source
    assert "stop_worm_audit_receiver.ps1" in source
    assert "Start-Job" not in source
    assert "worm-receiver.pid" in source
    assert "Get-Process -Id $receiverPid" in source
    assert (
        "--catalog-output 'C:\\ProgramData\\Khaos\\native-resource-catalog.json'"
        in source
    )
    assert "$entry = uv run python scripts/run_native_authority_e2e.py --emit-catalog" not in source


def test_windows_backend_uses_the_named_pipe_as_its_control_plane_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "KHAOS_AUTHORITYD_BACKEND_PIPE", r"\\.\pipe\KhaosAuthorityDBackend"
    )
    monkeypatch.setenv("KHAOS_AUTHORITYD_SOCKET", "unused")

    assert _authority_transport_value(platform_name="nt") == (
        r"\\.\pipe\KhaosAuthorityDBackend"
    )


def test_windows_backend_rejects_missing_named_pipe_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("KHAOS_AUTHORITYD_BACKEND_PIPE", raising=False)

    with pytest.raises(SystemExit, match="KHAOS_AUTHORITYD_BACKEND_PIPE"):
        _authority_transport_value(platform_name="nt")


def test_worm_receiver_lifecycle_is_owned_by_a_real_process() -> None:
    start = (ROOT / "scripts" / "start_worm_audit_receiver.ps1").read_text(
        encoding="utf-8"
    )
    stop = (ROOT / "scripts" / "stop_worm_audit_receiver.ps1").read_text(
        encoding="utf-8"
    )

    assert "Start-Process" in start
    assert "-PassThru" in start
    assert "RedirectStandardOutput" in start
    assert "RedirectStandardError" in start
    assert "WriteAllText" in start
    assert "Get-CimInstance Win32_Process" in stop
    assert "run_worm_audit_receiver\\.py" in stop
    assert "Stop-Process -Id $receiverPid -Force" in stop
    assert "WaitForExit(10000)" in stop
