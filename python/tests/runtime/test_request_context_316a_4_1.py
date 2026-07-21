"""M4 batch 3.1.16A-4-1 acceptance tests.

Verifies that:

1. :class:`RequestContext` is immutable (frozen) and rejects empty
   principal_id for ``for_rpc`` / ``for_webhook`` / ``for_cron``.
2. The JSON-line dispatcher builds a ``RequestContext`` from the
   authenticated RPC principal and passes it as the first parameter
   to EVERY service method — closing the gap where Python services
   were fixed to ``local-uid`` regardless of the transport principal.
3. ``AgentService.switch_mode`` uses ``ctx.principal_id`` instead of
   the hardcoded ``local-uid``.
4. ``_build_runtime`` populates ``session_id`` on the ``RuntimeConfig``
   (previously always ``""``, which broke ModeManager's
   ``(principal, session)`` binding).
5. ``_handle_optional_subagent`` stamps ``ctx.principal_id`` onto the
   payload so the existing B1/M2 principal checks inside
   ``SubAgentService`` see the authenticated value.

These are signature/wiring tests — A-4-2 will add the deeper
behavioural tests (DB queries actually filter by ``ctx.principal_id``).
"""

from __future__ import annotations

import inspect
import os

import pytest

from khaos.grpc_server import (
    AgentService,
    AuditService,
    MemoryService,
    TaskService,
    _handle_optional_subagent,
)
from khaos.runtime import RequestContext


def _test_ctx(*, principal_id: str = "", session_id: str = "") -> RequestContext:
    if not principal_id:
        ctx = RequestContext.for_cli()
        if session_id:
            ctx = ctx.with_session(session_id)
        return ctx
    return RequestContext(
        principal_id=principal_id,
        session_id=session_id,
        source_transport="test",
    )


# ---------------------------------------------------------------------------
# RequestContext immutability and factory validation
# ---------------------------------------------------------------------------


def test_request_context_is_frozen():
    """``RequestContext`` must be immutable so a handler cannot rewrite
    the transport principal mid-request."""
    ctx = _test_ctx()
    with pytest.raises(Exception):  # noqa: B017 — FrozenInstanceError subclass
        ctx.principal_id = "attacker"  # type: ignore[misc]


def test_request_context_for_rpc_rejects_empty_principal():
    with pytest.raises(ValueError, match="principal_id is required"):
        RequestContext.for_rpc("")


def test_request_context_for_webhook_rejects_empty_principal():
    with pytest.raises(ValueError, match="principal_id is required"):
        RequestContext.for_webhook("")


def test_request_context_for_cron_rejects_empty_principal():
    with pytest.raises(ValueError, match="principal_id is required"):
        RequestContext.for_cron("")


def test_request_context_for_cli_uses_local_uid():
    ctx = RequestContext.for_cli()
    # On Unix, principal is ``local-uid:<uid>``.  On Windows (no
    # ``os.getuid``), falls back to ``local-uid:windows``.
    try:
        expected = f"local-uid:{os.getuid()}"
    except AttributeError:
        expected = "local-uid:windows"
    assert ctx.principal_id == expected
    assert ctx.source_transport == "cli"


def test_request_context_with_session_preserves_principal():
    """``with_session`` must not drop the principal — it is the
    authority carrier."""
    ctx = RequestContext.for_rpc("api:user-1").with_session("session-42")
    assert ctx.principal_id == "api:user-1"
    assert ctx.session_id == "session-42"
    assert ctx.source_transport == "rpc"


def test_request_context_with_runtime_id_preserves_principal_and_session():
    ctx = (
        RequestContext.for_rpc("api:user-1")
        .with_session("session-42")
        .with_runtime_id("runtime-7")
    )
    assert ctx.principal_id == "api:user-1"
    assert ctx.session_id == "session-42"
    assert ctx.runtime_id == "runtime-7"


# ---------------------------------------------------------------------------
# Every service method takes ``ctx: RequestContext`` as the first
# non-self parameter.  This is the structural guarantee that the
# dispatcher can pass ``ctx`` to every method without TypeError.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fn, name",
    [
        (AgentService.chat, "AgentService.chat"),
        (AgentService.switch_mode, "AgentService.switch_mode"),
        (AgentService.confirm_permission, "AgentService.confirm_permission"),
        (AgentService.handle_webhook, "AgentService.handle_webhook"),
        (AgentService.list_channels, "AgentService.list_channels"),
        (AgentService.set_channel_enabled, "AgentService.set_channel_enabled"),
        (MemoryService.get_memory, "MemoryService.get_memory"),
        (MemoryService.set_memory, "MemoryService.set_memory"),
        (MemoryService.delete_memory, "MemoryService.delete_memory"),
        (MemoryService.search_memory, "MemoryService.search_memory"),
        (AuditService.query, "AuditService.query"),
        (TaskService.list, "TaskService.list"),
        (TaskService.get, "TaskService.get"),
        (TaskService.create, "TaskService.create"),
        (TaskService.cancel, "TaskService.cancel"),
        (TaskService.approve, "TaskService.approve"),
        (TaskService.reject, "TaskService.reject"),
        (TaskService.artifacts, "TaskService.artifacts"),
        (TaskService.events, "TaskService.events"),
    ],
)
def test_service_method_first_param_is_ctx(fn, name):
    """Every principal-aware service method MUST accept ``ctx`` as its
    first non-self parameter.  A-4-2 will then read ``ctx.principal_id``
    inside the method body to scope DB queries."""
    sig = inspect.signature(fn)
    params = list(sig.parameters.values())
    # Skip ``self`` for bound methods.
    if params and params[0].name == "self":
        params = params[1:]
    assert params, f"{name} has no parameters"
    first = params[0]
    assert first.name == "ctx", (
        f"{name} first non-self parameter is {first.name!r}, expected 'ctx'"
    )
    assert first.annotation is RequestContext or first.annotation == "RequestContext", (
        f"{name} ctx annotation is {first.annotation!r}, expected RequestContext"
    )


# ---------------------------------------------------------------------------
# _handle_optional_subagent passes ctx directly to the handler
# (A-4-2: no longer stamps payload)
# ---------------------------------------------------------------------------


async def test_handle_optional_subagent_passes_ctx_to_handler():
    """``_handle_optional_subagent`` MUST pass ``ctx`` directly to the
    SubAgent handler so it reads ``ctx.principal_id`` (not the payload).
    """
    captured_ctxs: list[RequestContext] = []
    captured_payloads: list[dict] = []

    class _StubService:
        async def handle_spawn(self, ctx, payload):
            captured_ctxs.append(ctx)
            captured_payloads.append(payload)
            return {"ok": True, "task_id": "t1"}

    ctx = RequestContext.for_rpc("api:web-user-42")
    result = await _handle_optional_subagent(_StubService(), "spawn", ctx, {"goal": "x"})
    assert result["ok"] is True
    assert captured_ctxs == [ctx]
    # Payload is NOT modified — no principal_id stamped on it.
    assert captured_payloads == [{"goal": "x"}]


async def test_handle_optional_subagent_rejects_when_service_is_none():
    ctx = RequestContext.for_rpc("api:user-1")
    result = await _handle_optional_subagent(None, "spawn", ctx, {})
    assert result == {"ok": False, "error": "subagents not enabled"}


async def test_handle_optional_subagent_ignores_payload_principal():
    """A compromised Gateway that sends ``principal_id: 'admin'`` in
    the payload MUST NOT win — the handler reads ``ctx.principal_id``
    directly (A-4-2: no longer stamped on payload)."""
    captured_ctxs: list[RequestContext] = []

    class _StubService:
        async def handle_spawn(self, ctx, payload):
            captured_ctxs.append(ctx)
            return {"ok": True}

    ctx = RequestContext.for_rpc("api:low-privilege-user")
    await _handle_optional_subagent(
        _StubService(), "spawn", ctx, {"principal_id": "admin"},
    )
    # The handler received ctx with the correct principal.
    assert captured_ctxs[0].principal_id == "api:low-privilege-user"


# ---------------------------------------------------------------------------
# AgentService.switch_mode uses ctx.principal_id (not local-uid)
# ---------------------------------------------------------------------------


async def test_switch_mode_uses_transport_principal(tmp_path, monkeypatch):
    """``switch_mode`` MUST bind the new mode to ``ctx.principal_id``,
    not the hardcoded ``local-uid``.  Previously an API principal A
    calling SwitchMode would modify the local-uid's mode, then A's
    Chat runtime would load A's principal — producing inconsistent
    authority and UI state."""
    from khaos.db import Database
    from khaos.modes import ModeManager

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    captured_principal: list[str] = []

    original_init = ModeManager.__init__

    def spy_init(self, *args, **kwargs):
        captured_principal.append(kwargs.get("principal_id", ""))
        return original_init(self, *args, **kwargs)

    monkeypatch.setattr(ModeManager, "__init__", spy_init)

    await service.switch_mode(
        RequestContext.for_rpc("api:remote-user-7"),
        "session-99",
        "coding",
    )

    assert captured_principal, "ModeManager was not constructed"
    assert "api:remote-user-7" in captured_principal, (
        f"switch_mode used principal {captured_principal!r}, "
        f"expected 'api:remote-user-7'"
    )
    await db.close()


# ---------------------------------------------------------------------------
# _build_runtime populates session_id on RuntimeConfig
# ---------------------------------------------------------------------------


async def test_build_runtime_propagates_session_id(tmp_path, monkeypatch):
    """``_build_runtime`` MUST pass ``session_id`` into the
    ``RuntimeConfig``.  Previously it always passed ``""``, which
    broke ModeManager's ``(principal, session)`` binding — the
    session_id lived on ``ctx`` but was never read."""
    from khaos.db import Database
    import khaos.runtime as runtime_module
    from khaos.runtime import RuntimeConfig

    (tmp_path / "prompts").mkdir()
    (tmp_path / "prompts" / "office.md").write_text("office", encoding="utf-8")
    (tmp_path / "prompts" / "coding.md").write_text("coding", encoding="utf-8")
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    service = AgentService(db, project_root=tmp_path)

    captured_configs: list[RuntimeConfig] = []

    class _StubRuntime:
        """Bare stub — the test only inspects the RuntimeConfig."""
        async def aclose(self):
            pass

    async def spy_build(config: RuntimeConfig):
        captured_configs.append(config)
        return _StubRuntime()

    # ``_build_runtime`` does ``from khaos.runtime import build_runtime``
    # INSIDE the function body, so we must patch the source module —
    # patching ``khaos.grpc_server.build_runtime`` would not be visible
    # to the lazy import.
    monkeypatch.setattr(runtime_module, "build_runtime", spy_build)

    await service._build_runtime(
        RequestContext.for_rpc("api:user-1").with_session("session-42"),
        "session-42",
        "office",
    )

    assert captured_configs, "build_runtime was not called"
    cfg = captured_configs[0]
    assert cfg.session_id == "session-42", (
        f"_build_runtime passed session_id={cfg.session_id!r}, "
        f"expected 'session-42'"
    )
    assert cfg.principal_id == "api:user-1", (
        f"_build_runtime passed principal_id={cfg.principal_id!r}, "
        f"expected 'api:user-1'"
    )
    await db.close()
