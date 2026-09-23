"""Synthetic credential isolation and secretless configuration contracts."""

from __future__ import annotations

import json
import os
import pickle
import secrets
import subprocess
import sys

import httpx
import pytest
from khaos.coding.execution.environment import build_task_environment
from khaos.config import (
    ConfigError,
    load_config,
    provider_diagnostics,
    set_provider_credential,
)
from khaos.memory.core.contracts import MemoryCapabilities
from khaos.memory.providers import MemoryHttpProvider, ProviderManifest
from khaos.memory.providers.lifecycle import ProviderLifecycleError
from khaos.memory.providers.manager import build_native_registry
from khaos.routing.provider import ProviderConfig
from khaos.security.credential_broker import CredentialBroker, CredentialBrokerError
from khaos.security.credentials import (
    CredentialAccessMode,
    CredentialNotFound,
    CredentialRef,
    CredentialStoreDiagnostic,
    CredentialStoreUnavailable,
    InMemoryCredentialStore,
    LinuxSecretServiceCredentialStore,
    MacOSKeychainCredentialStore,
    SecretValue,
    UnavailableCredentialStore,
    build_platform_credential_store,
)

SYNTHETIC_CANARY = "synthetic-provider-canary-value-9f31"


def test_linux_secret_service_backend_is_native_and_session_bound(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    store = LinuxSecretServiceCredentialStore()

    assert store.backend_name == "linux-secret-service"
    assert store.requires_session_unlock is True
    assert store.backend_audit() == {
        "backend": "linux-secret-service",
        "api": "libsecret-secret-service",
        "collection": "default",
        "attributes": ("khaos-provider", "khaos-reference"),
        "runtime_authentication_ui": "FAIL_CLOSED",
        "provisioning_authentication_ui": "ALLOW",
        "session_unlock": True,
        "secret_material_in_argv": False,
        "secret_material_in_environment": False,
    }


def test_linux_platform_factory_does_not_fallback_to_plaintext(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")

    store = build_platform_credential_store()

    assert isinstance(store, LinuxSecretServiceCredentialStore)
    assert not hasattr(store, "api_key")


def _registered_broker(provider: str = "nvidia"):
    broker = CredentialBroker()
    ref = CredentialRef.for_provider(provider, name="test")
    store = InMemoryCredentialStore()
    broker.register_credential_store(ref, store, provider=provider)
    broker.put_provider_credential(ref, SecretValue(SYNTHETIC_CANARY), provider=provider)
    return broker, ref, store


def test_secret_value_is_defensive_in_common_serialization_paths():
    secret = SecretValue(SYNTHETIC_CANARY)

    assert SYNTHETIC_CANARY not in str(secret)
    assert SYNTHETIC_CANARY not in repr(secret)
    assert SYNTHETIC_CANARY not in format(secret)
    with pytest.raises(TypeError):
        json.dumps({"secret": secret})
    with pytest.raises(TypeError):
        pickle.dumps(secret)


def test_secret_value_matches_without_exposing_plaintext():
    secret = SecretValue(SYNTHETIC_CANARY)
    same = SecretValue(SYNTHETIC_CANARY)
    different = SecretValue(f"{SYNTHETIC_CANARY}-different")

    assert secret.matches(same) is True
    assert secret.matches(different) is False
    assert secret.matches(SYNTHETIC_CANARY) is False


def test_native_store_diagnostic_is_bounded_and_secretless():
    diagnostic = CredentialStoreDiagnostic(
        backend="macos-keychain",
        operation="PUT",
        native_status=-25308,
        category="INTERACTION_REQUIRED",
        interaction_allowed=False,
    )
    error = CredentialStoreUnavailable(
        "macOS Keychain write failed", diagnostic=diagnostic
    )

    metadata = error.safe_metadata()
    serialized = json.dumps(metadata, sort_keys=True)
    assert metadata["error_type"] == "CredentialStoreUnavailable"
    assert metadata["diagnostic"] == {
        "backend": "macos-keychain",
        "operation": "PUT",
        "native_status": -25308,
        "category": "INTERACTION_REQUIRED",
        "interaction_allowed": False,
    }
    assert SYNTHETIC_CANARY not in serialized
    assert "Security.framework" not in serialized


def test_broker_exposes_native_failure_category_without_secret_material():
    broker = CredentialBroker()
    ref = CredentialRef.for_provider("test", name="diagnostic")
    diagnostic = CredentialStoreDiagnostic(
        backend="macos-keychain",
        operation="EXISTS",
        native_status=-25308,
        category="INTERACTION_REQUIRED",
        interaction_allowed=False,
    )
    broker.register_credential_store(
        ref,
        UnavailableCredentialStore("synthetic backend unavailable", diagnostic=diagnostic),
        provider="test",
    )
    try:
        status = broker.provider_credential_status(ref, provider="test")
    finally:
        broker.close()

    assert status["status"] == "INTERACTION_REQUIRED"
    assert status["diagnostic"] == diagnostic.to_payload()


def test_broker_is_only_transport_boundary_and_redacts_exact_canary():
    broker, ref, _store = _registered_broker()
    try:
        binding = {"provider": "nvidia", "model": "synthetic-model"}
        handle = broker.issue_provider_handle(
            ref,
            provider="nvidia",
            binding=binding,
            operation="provider.request",
        )
        headers: dict[str, str] = {}
        broker.authorize_provider_headers(
            headers,
            handle,
            provider="nvidia",
            binding=binding,
            operation="provider.request",
        )

        assert headers["Authorization"] == f"Bearer {SYNTHETIC_CANARY}"
        assert SYNTHETIC_CANARY not in repr(ProviderConfig("nvidia", "mock://local", ref))
        assert broker.secret_redactor.redact_text(headers["Authorization"]) == (
            "Bearer [REDACTED_SECRET]"
        )
    finally:
        broker.close()


def test_cross_provider_reference_is_denied():
    broker, ref, _store = _registered_broker("nvidia")
    try:
        with pytest.raises(CredentialBrokerError, match="provider mismatch"):
            broker.provider_credential_status(ref, provider="openai")
        with pytest.raises(CredentialBrokerError, match="provider mismatch"):
            broker.issue_provider_handle(
                ref,
                provider="openai",
                binding="synthetic",
            )
    finally:
        broker.close()


def test_unavailable_store_fails_closed_without_plaintext_fallback():
    broker = CredentialBroker()
    ref = CredentialRef.for_provider("openai", name="unavailable")
    broker.register_credential_store(
        ref,
        UnavailableCredentialStore("synthetic unavailable backend"),
        provider="openai",
    )
    try:
        status = broker.provider_credential_status(ref, provider="openai")
        assert status["status"] == "UNAVAILABLE"
        assert status["credential_present"] is None
        with pytest.raises(CredentialBrokerError, match="unavailable"):
            broker.issue_provider_handle(
                ref,
                provider="openai",
                binding="synthetic",
            )
    finally:
        broker.close()


@pytest.mark.posix_host
def test_secretless_writer_stores_only_opaque_ref(tmp_path):
    target = tmp_path / ".khaos" / "config.yaml"
    store = InMemoryCredentialStore()

    written = set_provider_credential(
        "zhipu-coding",
        SYNTHETIC_CANARY,
        target,
        store=store,
    )

    assert written == target
    text = target.read_text(encoding="utf-8")
    assert SYNTHETIC_CANARY not in text
    assert "api_key" not in text
    assert "credential_ref: khaos/providers/zhipu-coding/default" in text
    assert store.exists(CredentialRef.for_provider("zhipu-coding"))


def test_plaintext_provider_config_is_rejected_without_reading_secret_into_error(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    project = tmp_path / "config.yaml"
    project.write_text(
        "models:\n  providers:\n    openai:\n      api_key: synthetic-legacy-secret\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigError) as exc:
        load_config(project)
    assert "synthetic-legacy-secret" not in str(exc.value)
    assert "credential_ref" in str(exc.value)


def test_provider_doctor_returns_metadata_only(tmp_path):
    target = tmp_path / "config.yaml"
    target.write_text(
        "models:\n  providers:\n    zhipu:\n"
        "      api_key: synthetic-doctor-secret\n"
        "      base_url: https://example.test/v1\n"
        "      models:\n        - name: glm-synthetic\n",
        encoding="utf-8",
    )

    report = provider_diagnostics(target)
    serialized = json.dumps(report, ensure_ascii=False, sort_keys=True)
    assert "synthetic-doctor-secret" not in serialized
    assert report["providers"][0]["credential_status"] == "LEGACY_PLAINTEXT_BLOCKED"
    assert report["providers"][0]["endpoint_profile"] == "https://example.test/v1"


def test_memory_provider_rejects_environment_credential_selector():
    with pytest.raises(ProviderLifecycleError, match="plaintext credentials"):
        build_native_registry(
            None,
            config={
                "memory": {
                    "providers": {
                        "remote-memory": {
                            "network": {
                                "required": True,
                                "endpoint": "https://memory.example.test",
                            },
                            "api_key_env": "SYNTHETIC_MEMORY_PROVIDER_KEY",
                        }
                    }
                }
            },
        )


def test_task_environment_is_allowlisted_and_not_inherited_by_child_processes(
    tmp_path,
):
    synthetic_home = tmp_path / "task-home"
    synthetic_tmp = synthetic_home / "tmp"
    synthetic_tmp.mkdir(parents=True)
    task_environment = build_task_environment(
        home=str(synthetic_home),
        tmpdir=str(synthetic_tmp),
        base_environment={
            "PATH": "/usr/bin:/bin",
            "HOME": "/Users/host-user",
            "OPENAI_API_KEY": SYNTHETIC_CANARY,
            "ZHIPU_API_KEY": SYNTHETIC_CANARY,
            "SILICONFLOW_API_KEY": SYNTHETIC_CANARY,
            "AUTHORIZATION": f"Bearer {SYNTHETIC_CANARY}",
            "LANG": "C.UTF-8",
        },
    )

    assert task_environment["HOME"] == str(synthetic_home)
    assert task_environment["TMPDIR"] == str(synthetic_tmp)
    assert task_environment["PYTHONDONTWRITEBYTECODE"] == "1"
    assert all(
        not key.casefold().endswith(("_api_key", "_token", "_secret"))
        for key in task_environment
    )
    assert "AUTHORIZATION" not in task_environment

    probe = (
        "import os, subprocess, sys; "
        "child = subprocess.run([sys.executable, '-c', "
        "'import os; print(os.getenv(\\\"OPENAI_API_KEY\\\")); "
        "print(os.getenv(\\\"AUTHORIZATION\\\")); "
        "print(os.getenv(\\\"HOME\\\"))'], capture_output=True, text=True); "
        "print(child.stdout, end='')"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe],
        env=task_environment,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert SYNTHETIC_CANARY not in result.stdout
    assert "None" in result.stdout
    assert str(synthetic_home) in result.stdout


def test_task_environment_suppresses_python_bytecode_cache(tmp_path):
    synthetic_home = tmp_path / "task-home"
    synthetic_tmp = synthetic_home / "tmp"
    synthetic_tmp.mkdir(parents=True)
    (tmp_path / "imported_module.py").write_text("VALUE = 7\n", encoding="utf-8")
    runner = tmp_path / "runner.py"
    runner.write_text(
        "import imported_module\nprint(imported_module.VALUE)\n",
        encoding="utf-8",
    )
    task_environment = build_task_environment(
        home=str(synthetic_home),
        tmpdir=str(synthetic_tmp),
        base_environment={"PATH": "/usr/bin:/bin"},
    )

    result = subprocess.run(
        [sys.executable, str(runner)],
        cwd=tmp_path,
        env=task_environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "7"
    assert not (tmp_path / "__pycache__").exists()


@pytest.mark.asyncio
async def test_memory_http_provider_resolves_credentials_only_at_transport_boundary():
    broker, ref, _store = _registered_broker("remote-memory")
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    provider = MemoryHttpProvider(
        ProviderManifest(
            provider_id="remote-memory",
            network_required=True,
            endpoint="https://memory.example.test",
            capabilities=MemoryCapabilities(),
        ),
        credential_ref=ref,
        credential_broker=broker,
    )
    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://memory.example.test",
    )
    authorization = ""
    redacted = ""
    try:
        health = await provider.health()
        authorization = requests[0].headers["Authorization"]
        redacted = broker.secret_redactor.redact_text(authorization)
    finally:
        await provider.stop()
        broker.close()

    assert health.healthy is True
    assert authorization == f"Bearer {SYNTHETIC_CANARY}"
    assert SYNTHETIC_CANARY not in repr(provider)
    assert redacted == "Bearer [REDACTED_SECRET]"
    assert broker.secret_redactor.contains_registered_secret(SYNTHETIC_CANARY) is False


@pytest.mark.posix_host
def test_macos_keychain_round_trip_is_native_and_cleanup_is_idempotent():
    if sys.platform != "darwin":
        pytest.skip("macOS Keychain contract")
    if os.environ.get("KHAOS_RUN_KEYCHAIN_TEST") != "1":
        pytest.skip("interactive host Keychain test is opt-in")
    try:
        store = MacOSKeychainCredentialStore(
            service_name="com.khaos.tests.credential-isolation"
        )
    except CredentialStoreUnavailable as exc:
        pytest.skip(f"macOS Keychain unavailable: {type(exc).__name__}")
    ref = CredentialRef.for_provider(
        "test", name=f"keychain-roundtrip-{secrets.token_hex(8)}"
    )
    secret = SecretValue(SYNTHETIC_CANARY)
    replacement = SecretValue(f"{SYNTHETIC_CANARY}-replacement")
    primary_error: CredentialStoreUnavailable | None = None
    cleanup_error: CredentialStoreUnavailable | None = None
    try:
        store.put(ref, secret, access_mode=CredentialAccessMode.PROVISIONING)
        assert store.exists(ref, access_mode=CredentialAccessMode.RUNTIME)
        for _access_check in range(3):
            loaded = store.get(ref, access_mode=CredentialAccessMode.RUNTIME)
            assert loaded.matches(secret)
        store.put(ref, replacement, access_mode=CredentialAccessMode.PROVISIONING)
        replaced = store.get(ref, access_mode=CredentialAccessMode.RUNTIME)
        assert replaced.matches(replacement)
        store.delete(ref, access_mode=CredentialAccessMode.PROVISIONING)
        assert store.exists(ref, access_mode=CredentialAccessMode.RUNTIME) is False
        with pytest.raises(CredentialNotFound):
            store.get(ref, access_mode=CredentialAccessMode.RUNTIME)
    except CredentialStoreUnavailable as exc:
        primary_error = exc
    finally:
        try:
            store.delete(ref, access_mode=CredentialAccessMode.PROVISIONING)
            store.delete(ref, access_mode=CredentialAccessMode.PROVISIONING)
        except CredentialStoreUnavailable as exc:
            cleanup_error = exc
    if primary_error is not None:
        pytest.fail(
            f"native Keychain operation failed: {primary_error.safe_metadata()}"
        )
    if cleanup_error is not None:
        pytest.fail(f"native Keychain cleanup failed: {cleanup_error.safe_metadata()}")
