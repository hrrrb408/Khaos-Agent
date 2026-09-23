"""Deterministic boundaries between operator provisioning and Agent runtime."""

from __future__ import annotations

import json

import httpx
import pytest
from khaos.cli.main import handle_credentials_command
from khaos.config import ConfigError, set_provider_credential
from khaos.routing.model_client import ModelClient
from khaos.routing.provider import ProviderConfig
from khaos.security.credential_broker import CredentialBroker, CredentialBrokerError
from khaos.security.credentials import (
    CredentialAccessMode,
    CredentialProvisioningCancelled,
    CredentialRef,
    CredentialStoreDiagnostic,
    CredentialStoreUnavailable,
    InMemoryCredentialStore,
    MacOSKeychainCredentialStore,
    SecretValue,
    _native_store_failure,
    credential_store_backend_audit,
)


class _RecordingStore(InMemoryCredentialStore):
    """Test store that records the authority mode for every operation."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, CredentialAccessMode]] = []

    def put(self, ref, secret, *, access_mode=CredentialAccessMode.RUNTIME):
        self.calls.append(("put", access_mode))
        super().put(ref, secret, access_mode=access_mode)

    def get(self, ref, *, access_mode=CredentialAccessMode.RUNTIME):
        self.calls.append(("get", access_mode))
        return super().get(ref, access_mode=access_mode)

    def exists(self, ref, *, access_mode=CredentialAccessMode.RUNTIME):
        self.calls.append(("exists", access_mode))
        return super().exists(ref, access_mode=access_mode)

    def delete(self, ref, *, access_mode=CredentialAccessMode.RUNTIME):
        self.calls.append(("delete", access_mode))
        super().delete(ref, access_mode=access_mode)


class _Setter:
    def __init__(self) -> None:
        self.values: list[bool] = []
        self.argtypes = None
        self.restype = None

    def __call__(self, value: bool) -> int:
        self.values.append(bool(value))
        return 0


class _InteractionLibrary:
    def __init__(self) -> None:
        self.SecKeychainSetUserInteractionAllowed = _Setter()


def test_native_interaction_scope_is_explicit_and_restores_runtime_deny():
    library = _InteractionLibrary()

    with MacOSKeychainCredentialStore._interaction_scope(
        library, CredentialAccessMode.PROVISIONING
    ):
        assert library.SecKeychainSetUserInteractionAllowed.values == [True]
    assert library.SecKeychainSetUserInteractionAllowed.values == [True, False]

    with MacOSKeychainCredentialStore._interaction_scope(
        library, CredentialAccessMode.RUNTIME
    ):
        assert library.SecKeychainSetUserInteractionAllowed.values == [True, False, False]


def test_native_interaction_policy_missing_fails_closed():
    with (
        pytest.raises(CredentialStoreUnavailable) as exc_info,
        MacOSKeychainCredentialStore._interaction_scope(
            object(), CredentialAccessMode.RUNTIME
        ),
    ):
        raise AssertionError("scope must not yield without a policy setter")

    assert exc_info.value.diagnostic is not None
    assert exc_info.value.diagnostic.category == "INTERACTION_POLICY_UNAVAILABLE"


def test_broker_uses_provisioning_only_for_operator_operations():
    broker = CredentialBroker()
    ref = CredentialRef.for_provider("nvidia", name="mode-test")
    store = _RecordingStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    try:
        broker.provision_provider_credential(
            ref, SecretValue("synthetic-mode-secret"), provider="nvidia"
        )
        handle = broker.issue_provider_handle(
            ref, provider="nvidia", binding={"provider": "nvidia"}
        )
        headers: dict[str, str] = {}
        broker.authorize_provider_headers(
            headers,
            handle,
            provider="nvidia",
            binding={"provider": "nvidia"},
        )
        broker.delete_provisioned_provider_credential(ref, provider="nvidia")
    finally:
        broker.close()

    assert store.calls == [
        ("put", CredentialAccessMode.PROVISIONING),
        ("exists", CredentialAccessMode.RUNTIME),
        ("get", CredentialAccessMode.RUNTIME),
        ("delete", CredentialAccessMode.PROVISIONING),
    ]


@pytest.mark.asyncio
async def test_model_discovery_can_use_provisioning_but_runtime_defaults_to_deny_ui():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer synthetic-discovery-secret"
        return httpx.Response(200, json={"data": [{"id": "model-a"}]})

    broker = CredentialBroker()
    ref = CredentialRef.for_provider("nvidia", name="discovery-mode")
    store = _RecordingStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    broker.provision_provider_credential(
        ref, SecretValue("synthetic-discovery-secret"), provider="nvidia"
    )
    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        credential_broker=broker,
    )
    try:
        models = await client.list_models(
            ProviderConfig(
                "nvidia",
                "https://example.test/v1",
                credential_ref=ref,
            ),
            access_mode=CredentialAccessMode.PROVISIONING,
        )
    finally:
        await client.http_client.aclose()
        broker.close()

    assert [model.model for model in models] == ["model-a"]
    assert store.calls[-2:] == [
        ("exists", CredentialAccessMode.PROVISIONING),
        ("get", CredentialAccessMode.PROVISIONING),
    ]


def test_runtime_interaction_required_is_typed_and_never_deletes():
    broker = CredentialBroker()
    ref = CredentialRef.for_provider("nvidia", name="runtime-interaction")

    class RuntimeBlockedStore(_RecordingStore):
        def exists(self, ref, *, access_mode=CredentialAccessMode.RUNTIME):
            self.calls.append(("exists", access_mode))
            if access_mode is CredentialAccessMode.RUNTIME:
                raise CredentialStoreUnavailable(
                    "runtime access blocked",
                    diagnostic=CredentialStoreDiagnostic(
                        backend="macos-keychain",
                        operation="EXISTS",
                        native_status=-25308,
                        category="INTERACTION_REQUIRED",
                        interaction_allowed=False,
                    ),
                )
            return True

    store = RuntimeBlockedStore()
    broker.register_credential_store(ref, store, provider="nvidia")
    try:
        status = broker.provider_credential_status(ref, provider="nvidia")
        with pytest.raises(CredentialBrokerError) as exc_info:
            broker.issue_provider_handle(
                ref, provider="nvidia", binding={"provider": "nvidia"}
            )
    finally:
        broker.close()

    assert status["status"] == "INTERACTION_REQUIRED"
    assert exc_info.value.diagnostic is not None
    assert exc_info.value.diagnostic.native_status == -25308
    assert all(operation != "delete" for operation, _mode in store.calls)


def test_provisioning_cancellation_is_typed():
    error = _native_store_failure(
        "operator cancelled provisioning",
        "PUT",
        -128,
        access_mode=CredentialAccessMode.PROVISIONING,
    )
    assert isinstance(error, CredentialProvisioningCancelled)
    assert error.safe_metadata()["diagnostic"]["category"] == "USER_CANCELED"


def test_provider_replace_rollback_preserves_existing_secret(monkeypatch, tmp_path):
    store = InMemoryCredentialStore()
    ref = CredentialRef.for_provider("nvidia")
    old = SecretValue("synthetic-old-secret")
    store.put(ref, old, access_mode=CredentialAccessMode.PROVISIONING)

    def fail_write(*_args, **_kwargs):
        raise ConfigError("synthetic config publication failure")

    monkeypatch.setattr("khaos.config.write_provider_config", fail_write)
    with pytest.raises(ConfigError, match="secure provider credential write failed"):
        set_provider_credential(
            "nvidia",
            "synthetic-new-secret",
            tmp_path / "config.yaml",
            store=store,
        )

    restored = store.get(ref, access_mode=CredentialAccessMode.PROVISIONING)
    assert restored.matches(old)


def test_provider_replace_rollback_removes_new_secret(monkeypatch, tmp_path):
    store = InMemoryCredentialStore()
    ref = CredentialRef.for_provider("nvidia")

    def fail_write(*_args, **_kwargs):
        raise OSError("synthetic config publication failure")

    monkeypatch.setattr("khaos.config.write_provider_config", fail_write)
    with pytest.raises(ConfigError, match="secure provider credential write failed"):
        set_provider_credential(
            "nvidia",
            "synthetic-new-secret",
            tmp_path / "config.yaml",
            store=store,
        )

    assert store.exists(ref, access_mode=CredentialAccessMode.PROVISIONING) is False


def test_backend_audit_keeps_dpk_as_optional_future_hardening():
    audit = credential_store_backend_audit(
        object()  # type: ignore[arg-type]
    )
    assert audit["data_protection_decision"] == "NOT_APPLICABLE"
    assert MacOSKeychainCredentialStore.backend_audit() == {
        "backend": "macos-keychain",
        "api": "legacy-SecKeychain",
        "data_protection_keychain": False,
        "accessibility": "UNSPECIFIED_LEGACY",
        "access_control": "NONE",
        "user_presence": False,
        "synchronizable": False,
        "access_group": None,
        "interaction_policy_api": "SecKeychainSetUserInteractionAllowed",
        "runtime_authentication_ui": "FAIL",
        "provisioning_authentication_ui": "ALLOW",
        "data_protection_decision": "OPTIONAL_FUTURE_HARDENING",
    }


def test_cli_never_accepts_a_secret_as_an_argument(capsys):
    assert handle_credentials_command(["set", "nvidia", "secret-in-argv"]) == 2
    assert "secret-in-argv" not in capsys.readouterr().err


def test_cli_set_uses_hidden_input_and_status_never_prompts(monkeypatch, capsys):
    captured: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "khaos.cli.main.set_provider_credential",
        lambda provider, secret: captured.append((provider, secret)),
    )
    monkeypatch.setattr(
        "khaos.cli.main.getpass.getpass", lambda _prompt: "synthetic-cli-secret"
    )
    assert handle_credentials_command(["set", "nvidia"]) == 0
    assert captured == [("nvidia", "synthetic-cli-secret")]
    output = capsys.readouterr()
    assert "synthetic-cli-secret" not in output.out
    assert "synthetic-cli-secret" not in output.err

    monkeypatch.setattr(
        "khaos.cli.main.provider_diagnostics",
        lambda: {"config_status": "MISSING", "providers": []},
    )
    monkeypatch.setattr(
        "khaos.cli.main.getpass.getpass",
        lambda _prompt: pytest.fail("status must never prompt"),
    )
    assert handle_credentials_command(["status", "nvidia"]) == 0
    assert json.loads(capsys.readouterr().out)["providers"] == []


def test_builtin_tools_do_not_expose_credential_provisioning():
    from khaos.tools import create_builtin_registry

    names = create_builtin_registry().exec_tool_names()
    assert not any(
        "credential" in name.casefold() and action in name.casefold()
        for name in names
        for action in ("set", "replace", "delete", "provision")
    )
