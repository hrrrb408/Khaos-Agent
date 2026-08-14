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
            if (
                "uses:" in line
                and "uses: ./" not in line
                and not PINNED_ACTION.match(line)
            ):
                violations.append(f"{workflow.name}:{line_number}:{line.strip()}")
    assert not violations, "unpinned Actions:\n" + "\n".join(violations)


def test_security_workflows_have_read_only_token_and_no_soft_failures():
    for workflow in _workflow_files():
        text = workflow.read_text(encoding="utf-8")
        parsed = yaml.safe_load(text)
        if workflow.name == "release-provenance.yml":
            # Publishing a GitHub Release and its signed attestation bundles
            # is the one deliberate write-capable workflow.  Keep the scope
            # exact so a future edit cannot silently grant broader access.
            assert parsed["permissions"] == {
                "contents": "write",
                "id-token": "write",
                "attestations": "write",
            }, workflow.name
        else:
            assert parsed["permissions"] == {"contents": "read"}, workflow.name
        assert "continue-on-error" not in text, workflow.name
        assert "persist-credentials: false" in text, workflow.name


def test_release_provenance_binds_exact_required_gates_and_forbids_replacement():
    """Release evidence must name exact successful gate runs, immutably."""
    workflow = (WORKFLOWS / "release-provenance.yml").read_text(encoding="utf-8")
    generator = (ROOT / "scripts" / "generate_release_evidence.py").read_text(
        encoding="utf-8"
    )
    verifier = (ROOT / "scripts" / "verify_release_gate_runs.py").read_text(
        encoding="utf-8"
    )
    assert "verify_release_gate_runs.py" in workflow
    assert "--commit \"$release_commit\"" in workflow
    assert "git fetch --no-tags origin main" in workflow
    assert 'git merge-base --is-ancestor "$release_commit" FETCH_HEAD' in workflow
    assert "--gate-evidence" in workflow
    assert "release-gate-evidence.json" in workflow
    assert "--clobber" not in workflow
    assert "security-closure-gate.yml" in verifier
    assert "product-integrity-gate.yml" in verifier
    assert 'run.get("conclusion") == "success"' in verifier
    assert 'run.get("event") == "push"' in verifier
    assert 'run.get("head_branch") == "main"' in verifier
    assert "main ancestry" in verifier
    assert 'evidence.get("main_ancestry")' in generator
    assert 'record.get("event") != "push"' in generator
    assert 'record.get("head_branch") != "main"' in generator
    assert 'run.get("run_attempt") or 0' in verifier
    assert 'security-evidence-{commit}' in verifier
    assert 'artifact.get("expired") is not False' in verifier
    assert 'record.get("run_attempt") != 1' in generator
    assert "required_gates" in generator
    assert "run_id" in generator
    assert "evidence_digest" in generator


def test_platform_matrix_and_real_sandbox_jobs_are_mandatory():
    matrix = (WORKFLOWS / "security-contract-matrix.yml").read_text(encoding="utf-8")
    platform = (WORKFLOWS / "platform-sandbox-security.yml").read_text(encoding="utf-8")
    docker = (WORKFLOWS / "docker-security.yml").read_text(encoding="utf-8")

    for runner in ("ubuntu-24.04", "windows-2025", "macos-14"):
        assert runner in matrix
    assert "KHAOS_REQUIRE_PLATFORM_SANDBOX" not in platform
    assert 'KHAOS_DEV_MODE: "0"' in platform
    assert "windows-fail-closed-security" in platform
    assert "-m windows_fail_closed" in platform
    assert "KHAOS_RUN_PRODUCTION_SANDBOX" in docker
    assert "docker_sandbox_real" in docker
    assert "production_sandbox_real" in docker
    assert 'docker_sandbox_real or production_sandbox_real' in docker

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
        "test_audit_logger.py",
        "test_browser_tools.py",
        "test_factory_effective_policy.py",
        "test_grpc_server.py",
        # M2: the M4 security regression suite (B1 / H1 / H2 / H3 / B2 /
        # H4 / H5 / H6 closures) must stay in the matrix so a future
        # refactor cannot silently regress the closed boundaries.
        "test_m4_security_regression.py",
        # M3 (round-3): the round-2 lifecycle regression tests must stay
        # in the matrix — without them in this required list, a future
        # workflow edit could drop the files and the CI policy test would
        # still pass, silently losing the BrowserManager / spawner /
        # runner shutdown coverage.
        "test_browser_close_concurrency.py",
        "test_spawner_shutdown.py",
        "test_runner_shutdown.py",
        # M4 (round-6): the Cron engine shutdown / cancelled-task
        # persistence contracts and the SubAgent service real-status
        # contract must stay in the matrix.  Without them in this
        # required list, a future workflow edit could drop the files
        # and the CI policy test would still pass, silently losing the
        # round-6 cron bounded-drain / cancelled-state / service
        # status coverage.
        "test_cron_engine.py",
        "test_service.py",
    ):
        assert required_contract in matrix


def test_product_infra_marker_exclusions_have_dedicated_owners():
    """Every marker excluded from the product suite must have an owner job.

    The product matrix intentionally cannot provide Docker, Chromium, or
    privileged kernel infrastructure.  This check prevents a future workflow
    edit from turning that intentional deselection into an unowned coverage
    hole, especially for ``production_sandbox_real`` which is distinct from
    the lower-level Docker contract marker.
    """
    product = (WORKFLOWS / "product-integrity-gate.yml").read_text(
        encoding="utf-8"
    )
    docker = (WORKFLOWS / "docker-security.yml").read_text(encoding="utf-8")
    browser = (WORKFLOWS / "browser-e2e.yml").read_text(encoding="utf-8")
    platform = (WORKFLOWS / "platform-sandbox-security.yml").read_text(
        encoding="utf-8"
    )
    excluded = (
        "browser_real",
        "docker_sandbox_real",
        "production_sandbox_real",
        "kernel_real",
        "platform_sandbox_real",
    )
    for marker in excluded:
        assert marker in product
    assert "browser_real" in browser
    assert 'docker_sandbox_real or production_sandbox_real' in docker
    assert "real_bwrap" in platform
    assert "real_macos" in platform


def test_windows_product_suite_declares_posix_host_applicability_boundary():
    """Windows must record POSIX-host exclusions explicitly, not hide them."""
    product = (WORKFLOWS / "product-integrity-gate.yml").read_text(
        encoding="utf-8"
    )
    assert 'and not posix_host' in product
    assert "explicitly marked ``posix_host`` tests" in product


def test_windows_product_suite_runs_complete_collection_in_isolated_shards():
    """Windows sharding must isolate resources without shrinking coverage."""
    product = (WORKFLOWS / "product-integrity-gate.yml").read_text(
        encoding="utf-8"
    )
    runner = (ROOT / "scripts" / "run_windows_product_suite.py").read_text(
        encoding="utf-8"
    )
    assert "scripts/run_windows_product_suite.py --shards 4" in product
    assert "every test selected by its marker" in runner
    assert "assigned to exactly one child process" in runner
    assert "Shards run serially" in runner
    assert "Do not overlap child processes" in runner
    assert "DEDICATED_FIRST_SHARD_PREFIXES" in runner
    assert "global Winsock provider state" in runner
    assert "--collect" in runner
    assert "Collect in a process that exits before any test shard is launched" in runner
    assert "python/tests/coding/test_runtime_approval_e2e.py::" in runner
    assert "python/tests/tools/test_terminal_tools.py::" in runner


def test_macos_product_suite_runs_complete_collection_in_isolated_shards():
    """macOS must isolate the full applicable suite without dropping POSIX tests."""
    product = (WORKFLOWS / "product-integrity-gate.yml").read_text(
        encoding="utf-8"
    )
    assert "Run FULL Python product suite in isolated macOS shards" in product
    assert "if: matrix.os == 'macos-14'" in product
    assert (
        "uv run python scripts/run_windows_product_suite.py --shards 4"
        in product
    )
    assert (
        'not browser_real and not docker_sandbox_real and '
        'not production_sandbox_real and not kernel_real and '
        'not platform_sandbox_real"'
        in product
    )


def test_production_docker_image_reference_matches_preload():
    """Production Docker tests and CI must use the same pinned reference."""
    workflow = (WORKFLOWS / "docker-security.yml").read_text(encoding="utf-8")
    trusted = (ROOT / "python/tests/coding/test_m4_batch3_1_trusted_verification.py").read_text(
        encoding="utf-8"
    )
    image_match = re.search(r'^IMAGE = "(sha256:[0-9a-f]{64})"$', trusted, re.MULTILINE)
    assert image_match, "trusted verification test image digest is missing or malformed"
    image_digest = image_match.group(1)
    assert f"python@{image_digest}" in workflow
    assert "requested_image_reference=IMAGE_REFERENCE" in trusted


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
    assert "browser]" in text or "--extra browser" in text, (
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


def test_execution_authority_modules_are_type_checked():
    """Round-20 authority modules must stay in the hard Pyright job."""
    workflow = (WORKFLOWS / "type-check.yml").read_text(encoding="utf-8")
    for module in (
        "python/khaos/coding/execution/capability.py",
        "python/khaos/coding/execution/authority.py",
        "python/khaos/coding/execution/docker.py",
        "python/khaos/coding/execution/identity.py",
        "python/khaos/coding/execution/platform.py",
        "python/khaos/coding/execution/service.py",
    ):
        assert module in workflow


def test_browser_kernel_isolation_job_runs_round6_primitives():
    """Batch 9.7a (round-9 §十七): the ``browser-kernel-isolation`` job
    must run the round-6 kernel primitive suite, NOT the round-8
    fullstack test.

    Previously the job ran test_browser_fullstack_kernel_round8.py with
    -m "kernel_real and browser_real" but only set
    KHAOS_RUN_KERNEL_BROWSER_E2E=1 (not KHAOS_RUN_BROWSER_E2E=1), so the
    round8 _require_fullstack() gate called pytest.skip() — the required
    job was green but empty.  Now it must run the round-6 primitives
    (which only need the kernel gate) so the required context is real.
    """
    platform = (WORKFLOWS / "platform-sandbox-security.yml").read_text("utf-8")
    assert "test_browser_kernel_isolation_round6.py" in platform, (
        "browser-kernel-isolation job must run the round-6 kernel "
        "primitive suite (not the round-8 fullstack test, which skips "
        "without KHAOS_RUN_BROWSER_E2E=1)"
    )


def test_fullstack_helper_binds_to_live_non_root_step_ancestor():
    """The helper authority must outlive sudo and parent the pytest clients."""
    platform = (WORKFLOWS / "platform-sandbox-security.yml").read_text("utf-8")
    assert 'KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID="$$"' in platform
    assert 'KHAOS_BROWSER_KERNEL_HELPER_CLIENT_PID="$BASHPID"' not in platform


def test_single_security_closure_gate_requires_all_evidence_families():
    gate = (WORKFLOWS / "security-closure-gate.yml").read_text("utf-8")
    for dependency in (
        "Python Security Suite",
        "Go Race",
        "Rust Test",
        "Rust Clippy",
        "Linux Bwrap Real Kernel",
        "macOS Seatbelt Real Kernel",
        "Browser Non-root",
        "Browser Kernel Attack E2E",
        "Docker Security",
        "Supply Chain",
        "Schema Fuzz",
        "Authorization Drift E2E",
        "Process Lifecycle E2E",
        "Event-loop Starvation Tests",
    ):
        assert dependency in gate
    assert "name: Security Closure Gate" in gate
    assert "if: always()" in gate
    # Round-11 review Critical-3: the aggregate must require exact success —
    # cancelled/skipped must block (they are NOT proven), same as failure.
    assert 'test "$result" = "success"' in gate
    assert "actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131" in gate
    assert "if-no-files-found: error" in gate
    assert "security-evidence.json" in gate


def test_bootstrap_toolchain_is_hash_verified():
    """Batch 9.7b (round-9 §二十一): the CI toolchain (uv, pip-audit) must
    be installed with hash verification, not a bare ``pip install``.

    A compromised PyPI mirror that swapped the same-version wheel would
    otherwise control every subsequent frozen install.  Every workflow
    that installs uv/pip-audit must use --require-hashes against the
    pinned bootstrap-requirements.txt.
    """
    bootstrap = ROOT / "python" / "bootstrap-requirements.txt"
    assert bootstrap.exists(), (
        "python/bootstrap-requirements.txt is missing — the CI toolchain "
        "has no hash-pinned trust root"
    )
    text = bootstrap.read_text("utf-8")
    assert "uv==0.11.9" in text and "--hash=sha256:" in text, (
        "bootstrap-requirements.txt must pin uv with sha256 hashes"
    )
    # uv is a single Rust binary with NO Python deps, so hashing the uv
    # wheels alone is a complete trust root (no transitive tree to pin).
    # uv is the bootstrap trust root — it MUST always be hash-verified.
    # No workflow may install uv without --require-hashes against the
    # pinned bootstrap-requirements.txt.
    for workflow in _workflow_files():
        wt = workflow.read_text("utf-8")
        assert "pip install uv==" not in wt, (
            f"{workflow.name} installs uv without --require-hashes: "
            f"use 'pip install --require-hashes -r "
            f"python/bootstrap-requirements.txt' instead"
        )
    # Batch 10.7 (round-10 §十一): pip-audit is the Security Evidence
    # Trust Root — it decides whether the required 'pip-audit (Python)'
    # check is green or red.  It MUST be hash-locked (with its full
    # transitive dependency tree) via audit-requirements.txt.  No workflow
    # may install pip-audit bare (without --require-hashes).
    audit_lock = ROOT / "python" / "audit-requirements.txt"
    assert audit_lock.exists(), (
        "python/audit-requirements.txt is missing — pip-audit has no "
        "hash-pinned trust root"
    )
    audit_lock_text = audit_lock.read_text("utf-8")
    assert "pip-audit==2.10.0" in audit_lock_text and "--hash=sha256:" in audit_lock_text, (
        "audit-requirements.txt must pin pip-audit with sha256 hashes "
        "(including transitive deps)"
    )
    for workflow in _workflow_files():
        wt = workflow.read_text("utf-8")
        assert "pip install pip-audit==" not in wt, (
            f"{workflow.name} installs pip-audit without --require-hashes: "
            f"use 'pip install --require-hashes -r "
            f"python/audit-requirements.txt' instead"
        )
