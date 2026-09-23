"""Synthetic local-first credential session lifecycle contracts."""

from __future__ import annotations

import json

import httpx
import pytest
from khaos.agent import Message
from khaos.exceptions import ProviderError
from khaos.routing.model_client import ModelClient
from khaos.routing.provider import ModelSpec, ProviderConfig
from khaos.security.credential_broker import (
    CredentialBroker,
    CredentialSessionLocked,
    CredentialSessionMissing,
)
from khaos.security.credentials import (
    CredentialAccessMode,
    CredentialRef,
    InMemoryCredentialStore,
    SecretValue,
)

SYNTHETIC_SESSION_SECRET = "synthetic-session-secret-4e8c"


class _CountingSessionStore(InMemoryCredentialStore):
    """Synthetic persistent store that exposes only operation counts."""

    def __init__(self) -> None:
        super().__init__()
        self.calls: list[tuple[str, object]] = []

    def put(
        self,
        ref,
        secret,
        *,
        access_mode=CredentialAccessMode.RUNTIME,
    ):
        self.calls.append(("put", access_mode))
        super().put(ref, secret, access_mode=access_mode)

    def get(
        self,
        ref,
        *,
        access_mode=CredentialAccessMode.RUNTIME,
    ):
        self.calls.append(("get", access_mode))
        return super().get(ref, access_mode=access_mode)

    def exists(
        self,
        ref,
        *,
        access_mode=CredentialAccessMode.RUNTIME,
    ):
        self.calls.append(("exists", access_mode))
        return super().exists(ref, access_mode=access_mode)

    def delete(
        self,
        ref,
        *,
        access_mode=CredentialAccessMode.RUNTIME,
    ):
        self.calls.append(("delete", access_mode))
        super().delete(ref, access_mode=access_mode)


def _sse(text: str = "ok") -> bytes:
    payload = {"choices": [{"delta": {"content": text}}]}
    return f"data: {json.dumps(payload)}\n\ndata: [DONE]\n\n".encode()


def _session_fixture():
    broker = CredentialBroker()
    ref = CredentialRef.for_provider("zhipu-coding", name="session")
    store = _CountingSessionStore()
    broker.register_credential_store(
        ref,
        store,
        provider="zhipu-coding",
        session_required=True,
    )
    broker.provision_provider_credential(
        ref,
        SecretValue(SYNTHETIC_SESSION_SECRET),
        provider="zhipu-coding",
    )
    store.calls.clear()
    provider = ProviderConfig(
        "zhipu-coding",
        "https://example.test/v1",
        credential_ref=ref,
    )
    model = ModelSpec("zhipu-coding", "glm-synthetic", 128000)
    return broker, ref, store, provider, model


@pytest.mark.asyncio
async def test_session_unlock_loads_once_and_runtime_never_reads_store():
    broker, ref, store, provider, model = _session_fixture()
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert request.headers["authorization"] == (
            f"Bearer {SYNTHETIC_SESSION_SECRET}"
        )
        return httpx.Response(200, content=_sse())

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        credential_broker=broker,
    )
    try:
        assert broker.credential_session.status(ref, provider=provider.name)["session"] == (
            "LOCKED"
        )
        with pytest.raises(ProviderError) as locked:
            [
                chunk
                async for chunk in client.stream_chat(
                    provider, model, [Message("user", "before unlock")]
                )
            ]
        assert isinstance(locked.value.__cause__, CredentialSessionLocked)
        assert locked.value.code == "CREDENTIAL_SESSION_LOCKED"
        assert [operation for operation, _mode in store.calls] == []

        lease = broker.credential_session.unlock(ref, provider=provider.name)
        assert lease.summary()["credential_ref"] == ref.value
        assert [operation for operation, _mode in store.calls] == ["get"]
        store.calls.clear()

        for _ in range(3):
            chunks = [
                chunk
                async for chunk in client.stream_chat(
                    provider, model, [Message("user", "runtime")]
                )
            ]
            assert chunks[-1].stop_reason == "end_turn"
        assert len(requests) == 3
        assert store.calls == []
        status = broker.provider_credential_status(ref, provider=provider.name)
        assert status["session"] == "UNLOCKED"
        assert store.calls == []

        broker.credential_session.lock(ref, provider=provider.name)
        with pytest.raises(ProviderError) as locked_again:
            [
                chunk
                async for chunk in client.stream_chat(
                    provider, model, [Message("user", "after lock")]
                )
            ]
        assert isinstance(locked_again.value.__cause__, CredentialSessionLocked)
        assert store.calls == []
    finally:
        await client.http_client.aclose()
        broker.close()


@pytest.mark.asyncio
async def test_post_delete_runtime_reports_missing_without_store_probe():
    broker, ref, store, provider, model = _session_fixture()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=_sse())

    client = ModelClient(
        httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        credential_broker=broker,
    )
    try:
        broker.credential_session.unlock(ref, provider=provider.name)
        store.calls.clear()
        broker.delete_provisioned_provider_credential(ref, provider=provider.name)

        with pytest.raises(ProviderError) as missing:
            [
                chunk
                async for chunk in client.stream_chat(
                    provider, model, [Message("user", "after delete")]
                )
            ]
        assert missing.value.code == "CREDENTIAL_MISSING"
        assert isinstance(missing.value.__cause__, CredentialSessionMissing)
        assert store.calls == [("delete", CredentialAccessMode.PROVISIONING)]
    finally:
        await client.http_client.aclose()
        broker.close()


def test_session_restart_is_locked_and_replace_delete_invalidate_leases():
    broker, ref, store, provider, _model = _session_fixture()
    try:
        broker.credential_session.unlock(ref, provider=provider.name)
        store.calls.clear()
        broker.provision_provider_credential(
            ref,
            SecretValue("synthetic-replacement-secret-7b2a"),
            provider=provider.name,
        )
        assert broker.credential_session.status(ref, provider=provider.name)["session"] == (
            "LOCKED"
        )
        with pytest.raises(CredentialSessionLocked):
            broker.issue_provider_handle(
                ref,
                provider=provider.name,
                binding={"provider": provider.name},
            )

        broker.credential_session.unlock(ref, provider=provider.name)
        broker.delete_provisioned_provider_credential(ref, provider=provider.name)
        assert broker.credential_session.status(ref, provider=provider.name)["session"] == (
            "LOCKED"
        )
        with pytest.raises(CredentialSessionMissing):
            broker.credential_session.unlock(ref, provider=provider.name)
    finally:
        broker.close()

    restarted = CredentialBroker()
    try:
        restarted.register_credential_store(
            ref,
            store,
            provider=provider.name,
            session_required=True,
        )
        with pytest.raises(CredentialSessionLocked):
            restarted.issue_provider_handle(
                ref,
                provider=provider.name,
                binding={"provider": provider.name},
            )
    finally:
        restarted.close()


def test_session_secret_never_enters_safe_metadata():
    broker, ref, _store, provider, _model = _session_fixture()
    try:
        lease = broker.credential_session.unlock(ref, provider=provider.name)
        serialized = json.dumps(
            {
                "lease": lease.summary(),
                "status": broker.credential_session.status(ref, provider=provider.name),
            },
            sort_keys=True,
        )
        assert SYNTHETIC_SESSION_SECRET not in serialized
    finally:
        broker.close()


@pytest.mark.asyncio
async def test_tui_credentials_command_is_explicit_and_secretless():
    from khaos.tui.commands import TuiContext, handle_command

    broker, _ref, _store, provider, _model = _session_fixture()

    class _ProviderManager:
        def __init__(self) -> None:
            self.providers = {provider.name: provider}

        def get_provider(self, name):
            if name != provider.name:
                raise KeyError(name)
            return provider

    class _Router:
        provider_manager = _ProviderManager()

    ctx = TuiContext(router=_Router(), credential_broker=broker)
    try:
        unlocked = await handle_command(
            "/credentials unlock zhipu-coding", ctx
        )
        assert unlocked.message == "zhipu-coding: UNLOCKED"
        status = await handle_command("/credentials status zhipu-coding", ctx)
        assert status.message == "zhipu-coding: UNLOCKED (AVAILABLE)"
        locked = await handle_command("/credentials lock zhipu-coding", ctx)
        assert locked.message == "zhipu-coding: LOCKED"
    finally:
        broker.close()
