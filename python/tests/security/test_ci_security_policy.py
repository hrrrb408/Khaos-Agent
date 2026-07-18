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
        "test_office_workspace_fs_security.py",
        "test_office_mutation_fence.py",
        "test_office_aggregate_storage.py",
        "test_office_mutation_authority.py",
        "test_file_search_redos.py",
        "test_effective_policy.py",
        "test_commands_require_approval.py",
        # M2: runtime lifecycle / factory / RPC peer-identity contracts
        # must stay in the matrix so they cannot be silently removed.
        "test_aclose.py",
        "test_factory_effective_policy.py",
        "test_grpc_server.py",
        # M2: the M4 security regression suite (B1 / H1 / H2 / H3 / B2 /
        # H4 / H5 / H6 closures) must stay in the matrix so a future
        # refactor cannot silently regress the closed boundaries.
        "test_m4_security_regression.py",
    ):
        assert required_contract in matrix


def test_browser_e2e_workflow_is_mandatory():
    """M4: ``browser-e2e.yml`` must exist and actually run the real
    Playwright security E2E suite.

    The existing ``test_platform_matrix_and_real_sandbox_jobs_are_mandatory``
    asserts that the security-contract-matrix, platform-sandbox and
    docker-security workflows exist and are mandatory — but it does NOT
    check ``browser-e2e.yml``.  Someone could delete the browser E2E
    workflow and the CI policy test would still pass.

    This test closes that gap by asserting:

    * ``.github/workflows/browser-e2e.yml`` exists;
    * it declares the ``KHAOS_RUN_BROWSER_E2E=1`` env-var gate (proving
      it actually runs the real E2E tests, not a mock);
    * it installs the ``browser`` extra (proving Playwright is shipped
      rather than the install being skipped);
    * it runs the real E2E test file with the ``browser_real`` marker
      filter (so a future refactor cannot silently swap it for the mock
      test file).
    """
    workflow = WORKFLOWS / "browser-e2e.yml"
    assert workflow.exists(), (
        "browser-e2e.yml workflow is missing — the real Playwright "
        "security E2E suite is no longer enforced in CI"
    )
    text = workflow.read_text(encoding="utf-8")
    # Env-var gate: proves the workflow actually runs the real E2E tests
    # (the e2e test file skips when this is unset).
    assert "KHAOS_RUN_BROWSER_E2E" in text, (
        "browser-e2e.yml is missing the KHAOS_RUN_BROWSER_E2E env-var "
        "gate — the E2E tests would skip"
    )
    assert '"1"' in text or "=1" in text, (
        "KHAOS_RUN_BROWSER_E2E is not set to 1 in browser-e2e.yml"
    )
    # Installs the ``browser`` extra — proves Playwright is shipped
    # rather than the install being skipped.
    assert "browser]" in text, (
        "browser-e2e.yml does not install the browser extra — "
        "Playwright would not be available"
    )
    # The workflow runs the real E2E test file with the real marker.
    assert "test_browser_tools_e2e.py" in text, (
        "browser-e2e.yml does not run test_browser_tools_e2e.py"
    )
    assert "-m browser_real" in text, (
        "browser-e2e.yml does not filter on the browser_real marker — "
        "the real E2E tests would not run"
    )
