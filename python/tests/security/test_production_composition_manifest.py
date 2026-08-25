"""Production runtime composition manifest tests (M6.9 BATCH 10).

The static import graph alone cannot prove the running system is
composed of production components: a dev adapter or the forbidden host
backend could be injected at runtime.  These tests exercise
``verify_runtime_composition`` against real, fake, and forbidden runtime
graphs to prove the verifier fails closed.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest


def _runtime():
    from khaos.runtime import ProductionRuntimeConfig, build_production_runtime

    async def _build():
        from khaos.db.database import Database

        with tempfile.TemporaryDirectory(prefix="khaos-comp-test-") as tmp:
            db = Database(Path(tmp) / "comp.db")
            await db.connect()
            await db.run_migrations()
            runtime = None
            try:
                runtime = await build_production_runtime(
                    ProductionRuntimeConfig(
                        db=db,
                        principal_id="composition-test",
                        source_transport="cli",
                        foreground_session=False,
                        project_id="composition-test",
                    )
                )
                # Detach heavy transitive objects from the tempdir-bound db
                # by returning a shallow composition view the verifier can
                # walk without touching db files after close.
                from khaos.security.production_composition_manifest import (
                    verify_runtime_composition,
                )

                return verify_runtime_composition(runtime).to_payload()
            finally:
                if runtime is not None:
                    from khaos.runtime import close_runtime_or_register

                    await close_runtime_or_register(runtime)
                await db.close()

    return asyncio.run(_build())


@pytest.fixture(autouse=True)
def _production_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.delenv("KHAOS_DEV_MODE", raising=False)
    # Provision the typed resource catalog the production runtime
    # requires: the catalog must byte-match the one compiled into the
    # effective policy of this checkout.
    from khaos.security.effective_policy import load_effective_policy

    policy = load_effective_policy(Path(__file__).resolve().parents[3])
    assert policy.resource_order is not None
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        json.dumps(policy.resource_order.manifest(), sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("KHAOS_TYPED_RESOURCE_CATALOG_PATH", str(catalog_path))
    monkeypatch.setenv("KHAOS_EFFECTIVE_POLICY_DIGEST", policy.digest)


@pytest.mark.posix_host
def test_real_production_runtime_composes_and_verifies() -> None:
    # Building a production runtime fail-closes without a deployed
    # authority (native identity handles).  The real-runtime composition
    # proof therefore runs where a production authority is actually
    # deployed: the compose security E2E job (Linux) and the native CI
    # environments.  Everywhere else it is skipped, never faked.
    import socket as socket_module

    authority_socket = os.environ.get("KHAOS_AUTHORITYD_SOCKET", "")
    if not authority_socket:
        pytest.skip("no deployed authorityd: production runtime cannot be built")
    try:
        probe = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_STREAM)
        probe.settimeout(1.0)
        probe.connect(authority_socket)
        probe.close()
    except OSError:
        pytest.skip("authorityd socket unreachable: production runtime cannot be built")
    payload = _runtime()
    assert payload["valid"] is True, payload["errors"]
    assert payload["forbidden_detected"] == []
    components: dict[str, str] = payload["components"]
    # Every security-relevant owner is the exact production type.
    assert components["tool_scheduler"] == "khaos.tools.scheduler.ToolScheduler"
    assert components["security_middleware"] == "khaos.security.middleware.SecurityMiddleware"
    assert components["sandbox_backend"] == "khaos.security.sandbox.Sandbox"
    assert components["network_guard"] == "khaos.security.network_guard.NetworkGuard"
    assert (
        components["credential_broker"]
        == "khaos.security.credential_broker.CredentialBroker"
    )
    assert (
        components["network_broker"]
        == "khaos.security.network_broker.NetworkBrokerFactory"
    )
    assert (
        components["workspace_authority"]
        == "khaos.coding.workspace.manager.WorkspaceManager"
    )
    assert (
        components["office_mutation_authority"]
        == "khaos.coding.workspace.office_authority.OfficeMutationAuthority"
    )
    # The manifest carries a digest over its content.
    assert len(payload["manifest_digest"]) == 64


def test_missing_components_fail_closed() -> None:
    from khaos.security.production_composition_manifest import (
        verify_runtime_composition,
    )

    class _Empty:
        pass

    manifest = verify_runtime_composition(_Empty())
    assert manifest.valid is False
    assert any("tool_scheduler" in error for error in manifest.errors)
    assert any("sandbox" in error for error in manifest.errors)
    assert any("audit_logger" in error for error in manifest.errors)
    assert any("credential_broker" in error for error in manifest.errors)


def test_forbidden_mock_component_is_detected() -> None:
    from khaos.security.production_composition_manifest import (
        verify_runtime_composition,
    )

    class _Runtime:
        tool_scheduler = MagicMock()

    manifest = verify_runtime_composition(_Runtime())
    assert manifest.valid is False
    assert any("mock" in detected.lower() for detected in manifest.forbidden_detected)


def test_forbidden_host_backend_name_is_detected_by_name() -> None:
    """The verifier must not need to import the forbidden module."""
    from khaos.security.production_composition_manifest import (
        FORBIDDEN_TYPE_NAMES,
        _walk_object_graph,
    )

    assert "khaos.coding.execution.host.HostExecutionBackend" in FORBIDDEN_TYPE_NAMES
    # The verifier module itself must not import the forbidden module.
    # This must be checked in a fresh subprocess: in a shared pytest
    # session other tests legitimately import the host backend, so the
    # parent process's sys.modules says nothing about the verifier.
    import subprocess
    import sys

    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys, khaos.security.production_composition_manifest; "
            "assert 'khaos.coding.execution.host' not in sys.modules, "
            "'verifier imported the forbidden module'",
        ],
        check=False,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "PYTHONPATH": os.pathsep.join(
                filter(
                    None,
                    (
                        str(Path(__file__).resolve().parents[3] / "python"),
                        os.environ.get("PYTHONPATH", ""),
                    ),
                )
            ),
        },
    )
    assert probe.returncode == 0, probe.stderr

    class _FakeHostBackend:
        pass

    _FakeHostBackend.__module__ = "khaos.coding.execution.host"
    _FakeHostBackend.__qualname__ = "HostExecutionBackend"

    class _Runtime:
        backend = _FakeHostBackend()

    graph = _walk_object_graph(_Runtime())
    names = {f"{t.__module__}.{t.__qualname__}" for t in graph}
    assert "khaos.coding.execution.host.HostExecutionBackend" in names
    from khaos.security.production_composition_manifest import (
        verify_runtime_composition,
    )

    manifest = verify_runtime_composition(_Runtime())
    assert manifest.valid is False
    assert "khaos.coding.execution.host.HostExecutionBackend" in manifest.forbidden_detected


@pytest.mark.parametrize(
    ("module", "qualname"),
    [
        ("khaos.security.mock_authority", "MockAuthority"),
        ("khaos.coding.execution.host", "HostBackend"),
        ("khaos.coding.execution.testing_sandbox", "TestingSandbox"),
        ("khaos.runtime.testing", "TestingRuntimeComposition"),
    ],
)
def test_forbidden_testing_compositions_are_detected_without_importing_them(
    module: str, qualname: str
) -> None:
    from khaos.security.production_composition_manifest import (
        FORBIDDEN_TYPE_NAMES,
        verify_runtime_composition,
    )

    expected = f"{module}.{qualname}"
    assert expected in FORBIDDEN_TYPE_NAMES

    class _FakeComponent:
        pass

    _FakeComponent.__module__ = module
    _FakeComponent.__qualname__ = qualname

    class _Runtime:
        component = _FakeComponent()

    manifest = verify_runtime_composition(_Runtime())
    assert manifest.valid is False
    assert expected in manifest.forbidden_detected


def test_graph_walk_is_bounded() -> None:
    from khaos.security.production_composition_manifest import _walk_object_graph

    class _Deep:
        def __init__(self, depth: int = 0) -> None:
            self.child = _Deep(depth + 1) if depth < 8 else None

    # The walk terminates on deep cyclic graphs.
    types = _walk_object_graph(_Deep(), max_depth=4)
    assert types
