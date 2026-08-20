"""Source-level contract tests for Windows Service SID provisioning."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SERVICE_SID_HELPER = ROOT / "packaging" / "windows" / "service-sid.ps1"
INSTALLER = ROOT / "packaging" / "windows" / "install-khaos-authorityd.ps1"
WORKFLOW = ROOT / ".github" / "workflows" / "native-authority-production-e2e.yml"


def test_service_sid_resolution_is_scm_owned_and_fail_closed() -> None:
    source = SERVICE_SID_HELPER.read_text(encoding="utf-8")

    assert "showsid" in source
    assert "S-1-5-80" in source
    assert "SecurityIdentifier" in source
    assert "NTAccount" not in source


def test_installer_and_workflow_share_service_sid_resolution() -> None:
    installer = INSTALLER.read_text(encoding="utf-8")
    workflow = WORKFLOW.read_text(encoding="utf-8")

    assert "service-sid.ps1" in installer
    assert "Get-KhaosServiceSid" in installer
    assert "service-sid.ps1" in workflow
    assert "Get-KhaosServiceSid" in workflow
    assert "NTAccount('NT SERVICE\\KhaosAuthorityD')" not in workflow
