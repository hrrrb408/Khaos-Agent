"""Static policy checks for security-critical GitHub Actions workflows."""

from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[3]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED_ACTION = re.compile(
    r"^\s*(?:-\s+)?uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@([0-9a-f]{40})(?:\s+#.*)?$"
)


def _workflow_files() -> list[Path]:
    return sorted((*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")))


def test_every_external_action_is_pinned_to_full_commit_sha():
    violations: list[str] = []
    for workflow in _workflow_files():
        for line_number, line in enumerate(
            workflow.read_text(encoding="utf-8").splitlines(), start=1
        ):
            if "uses:" in line and not PINNED_ACTION.match(line):
                violations.append(f"{workflow.name}:{line_number}:{line.strip()}")
    assert not violations, "unpinned Actions:\n" + "\n".join(violations)


def test_security_workflows_have_read_only_token_and_no_soft_failures():
    for workflow in _workflow_files():
        text = workflow.read_text(encoding="utf-8")
        parsed = yaml.safe_load(text)
        assert parsed["permissions"] == {"contents": "read"}, workflow.name
        assert "continue-on-error" not in text, workflow.name
        assert "persist-credentials: false" in text, workflow.name


def test_platform_matrix_and_real_sandbox_jobs_are_mandatory():
    matrix = (WORKFLOWS / "security-contract-matrix.yml").read_text(encoding="utf-8")
    platform = (WORKFLOWS / "platform-sandbox-security.yml").read_text(encoding="utf-8")
    docker = (WORKFLOWS / "docker-security.yml").read_text(encoding="utf-8")

    for runner in ("ubuntu-24.04", "windows-2025", "macos-14"):
        assert runner in matrix
    assert "KHAOS_REQUIRE_PLATFORM_SANDBOX" in platform
    assert "windows-fail-closed-security" in platform
    assert "-m windows_fail_closed" in platform
    assert "KHAOS_RUN_PRODUCTION_SANDBOX" in docker
    assert "-m docker_sandbox_real" in docker

    for required_contract in (
        "test_webhook.py",
        "test_capability_broker.py",
        "test_channel_registry.py",
        "test_m4_batch3_1_6_2_authority.py",
        "test_m4_batch3_0_workspace_mutation.py",
        "test_process_supervisor.py",
        "test_workspace_storage.py",
        "test_workspace_storage_authority.py",
        "test_workspace_manager.py",
        "test_execution_binding.py",
        "test_managed_process_lifecycle.py",
        "test_middleware.py",
    ):
        assert required_contract in matrix
