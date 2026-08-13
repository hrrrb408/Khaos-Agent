"""Production browser authority closure and fail-closed regressions."""

from __future__ import annotations

from unittest.mock import Mock

import pytest

pytestmark = pytest.mark.posix_host

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    BrowserSandboxError,
    IsolationLevel,
    validate_production_python_privileges,
)
from khaos.security.kernel_helper_client import KernelIsolationEvidence


def _evidence(
    *, process_isolated: bool = False, teardown: bool = False
) -> KernelIsolationEvidence:
    return KernelIsolationEvidence(
        helper_authenticated=True,
        network_namespace=not teardown,
        nft_default_deny=not teardown,
        cgroup_attached=not teardown,
        process_isolated=process_isolated and not teardown,
        resource_registry_verified=True,
        quarantined=False,
        proxy_host="" if teardown else "10.200.4.1",
    )


class FakeAuthority:
    available = True

    def __init__(self) -> None:
        self.operations: list[tuple[str, int | None]] = []

    def setup(self) -> KernelIsolationEvidence:
        self.operations.append(("setup", None))
        return _evidence()

    def allow_proxy(self, port: int) -> KernelIsolationEvidence:
        self.operations.append(("allow_proxy", port))
        return _evidence()

    def revoke_proxy(self, port: int) -> KernelIsolationEvidence:
        self.operations.append(("revoke_proxy", port))
        return _evidence()

    def teardown(self) -> KernelIsolationEvidence:
        self.operations.append(("teardown", None))
        return _evidence(teardown=True)


@pytest.fixture
def production(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    monkeypatch.setattr("khaos.security.browser_sandbox.sys.platform", "linux")
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.validate_production_python_privileges",
        lambda: None,
    )


def test_production_routes_setup_policy_and_teardown_only_to_helper(
    production: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = FakeAuthority()
    direct_subprocess = Mock(side_effect=AssertionError("Python invoked kernel CLI"))
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.subprocess.run", direct_subprocess
    )
    sandbox = BrowserNetworkSandbox(
        require_os_sandbox=True,
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        runtime_id="runtime-a",
        sandbox_token="ab" * 32,
        kernel_authority=authority,  # type: ignore[arg-type]
    )

    sandbox.setup()
    sandbox.install_egress_pin(8123)
    sandbox.remove_egress_port(8123)
    cleanup = sandbox.teardown()

    assert authority.operations == [
        ("setup", None),
        ("allow_proxy", 8123),
        ("revoke_proxy", 8123),
        ("teardown", None),
    ]
    assert cleanup.fully_closed
    direct_subprocess.assert_not_called()


def test_production_status_is_evidence_backed(production: None) -> None:
    sandbox = BrowserNetworkSandbox(
        require_os_sandbox=True,
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        runtime_id="runtime-a",
        sandbox_token="ab" * 32,
        kernel_authority=FakeAuthority(),  # type: ignore[arg-type]
    )
    sandbox.setup()
    status = sandbox.enforcement_status
    assert status.isolation_level is IsolationLevel.FULL_KERNEL_ISOLATION
    assert status.helper_authenticated
    assert status.nft_default_deny
    assert status.resource_registry_verified
    assert not status.process_isolation


def test_helper_unavailable_never_reaches_cli(
    production: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    authority = FakeAuthority()
    authority.available = False
    direct_subprocess = Mock(side_effect=AssertionError("CLI fallback reached"))
    monkeypatch.setattr(
        "khaos.security.browser_sandbox.subprocess.run", direct_subprocess
    )
    sandbox = BrowserNetworkSandbox(
        require_os_sandbox=True,
        project_id="project-a",
        runtime_id="runtime-a",
        sandbox_token="ab" * 32,
        kernel_authority=authority,  # type: ignore[arg-type]
    )
    with pytest.raises(BrowserSandboxError, match="helper unavailable"):
        sandbox.setup()
    direct_subprocess.assert_not_called()


def test_launcher_environment_contains_no_kernel_resource_identity(
    production: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    sandbox = BrowserNetworkSandbox(
        require_os_sandbox=True,
        principal_id="principal-a",
        project_id="project-a",
        task_id="task-a",
        runtime_id="runtime-a",
        sandbox_token="ab" * 32,
        kernel_authority=FakeAuthority(),  # type: ignore[arg-type]
    )
    sandbox.setup()
    monkeypatch.setattr(
        sandbox, "_locate_and_validate_browser_launcher", lambda: "/trusted/launcher"
    )
    monkeypatch.setattr(
        "khaos.security.browser_sandbox._validate_tcb_binary", lambda *args, **kwargs: None
    )
    monkeypatch.setattr("khaos.security.browser_sandbox.shutil.which", lambda name: "/usr/bin/bwrap")
    environment = sandbox.launcher_environment("/trusted/chromium")

    assert environment["KHAOS_BROWSER_AUTHORITY"] == "1"
    assert environment["KHAOS_BROWSER_PRINCIPAL_ID"] == "principal-a"
    assert environment["KHAOS_BROWSER_PROJECT_ID"] == "project-a"
    assert environment["KHAOS_BROWSER_RUNTIME_ID"] == "runtime-a"
    assert environment["KHAOS_BROWSER_TASK_ID"] == "task-a"
    assert environment["KHAOS_BROWSER_SANDBOX_TOKEN"] == "ab" * 32
    assert "KHAOS_BROWSER_NETNS" not in environment
    assert "KHAOS_BROWSER_CGROUP_PROCS" not in environment
    assert not any("VETH" in key or "NFT" in key for key in environment)


def test_production_python_root_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("khaos.security.browser_sandbox.sys.platform", "linux")
    monkeypatch.setattr("khaos.security.browser_sandbox.os.geteuid", lambda: 0)
    with pytest.raises(BrowserSandboxError, match="must be non-root"):
        validate_production_python_privileges()
