"""M4 security closure regression tests (B1 / H1 / H2 / H3).

These tests pin the security contracts that were reopened in the post-PR-#28
review.  Each test corresponds to one of the explicit gaps called out in the
M4 review and exists so a future refactor cannot silently regress the
closed boundary.

Covered regressions:

* B1 — SubAgent must inherit the same EffectivePolicy / Sandbox /
  NetworkGuard / AuditLogger as the main AgentLoop (no parallel
  unsupervised scheduler).  ``browser_file_upload`` must reject host
  files outside the workspace root.
* H1 — ``network_enabled=True`` must NOT bypass ``allowed_domains`` /
  ``blocked_domains``; the blocklist always wins, an allowlist enforces
  deny-by-default, and an empty allowlist means "unrestricted but still
  subject to the blocklist".
* H2 — ``commands.allow`` layered enforcement uses three-state semantics
  (``None`` = unset, empty = deny all, non-empty = whitelist) so a
  project whitelist is not silently erased by the default user layer.
* H3 — ``RuntimeResult.aclose`` uses a shared ``_close_task`` so
  concurrent callers wait on the same cleanup, a cancelled caller does
  not abort the cleanup, and a component failure leaves ``_closed=False``
  so the caller can retry.
* H1 — per-principal ``BrowserContext`` isolation: different principals
  get independent contexts; closing one principal's context does not
  close another's.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from khaos.db import Database
from khaos.runtime import RequestContext, RuntimeConfig, build_runtime
from khaos.runtime.factory import RuntimeResult
from khaos.security.command_guard import CommandGuard
from khaos.security.effective_policy import (
    compile_effective_policy,
)
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_guard import NetworkGuard
from khaos.security.policy import SandboxPolicy
from khaos.security.sandbox import SandboxMode
from khaos.tools.browser_tools import BrowserManager
from khaos.tools.registry import create_runtime_registry


pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="runtime factory wires POSIX-only workspace authority",
)


# ───────────────────────────────── helpers ──────────────────────────────────


async def _build_runtime(tmp_path: Path, policy_yaml: str, **overrides):
    """Build a runtime with a project policy file; return (result, db)."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    await db.create_session("s1")
    (tmp_path / "khaos_policy.yaml").write_text(policy_yaml, encoding="utf-8")
    cfg = RuntimeConfig(project_root=tmp_path, db=db, **overrides)
    result = await build_runtime(cfg)
    return result, db


# ───────────────────────── B1: SubAgent security inheritance ────────────────


async def test_subagent_runtime_inherits_effective_policy_middleware(tmp_path):
    """B1: a subagent runtime (tool_allowlist set) must carry the same
    EffectivePolicy / Sandbox / NetworkGuard / AuditLogger as the main
    runtime — not a bare ``ToolScheduler`` with no security middleware.

    The previous path constructed ``ToolScheduler(create_runtime_registry(),
    permission_engine)`` with no middleware at all, giving the subagent an
    unsupervised execution path that bypassed every security boundary the
    main AgentLoop was bound by.
    """
    policy = (
        "sandbox:\n"
        "  mode: workspace-write\n"
        "  network: false\n"
        "commands:\n"
        "  require_approval:\n"
        "    - rm\n"
    )
    # tool_allowlist exercises the SubAgent code path in build_runtime.
    result, db = await _build_runtime(
        tmp_path,
        policy,
        tool_allowlist=["read_file", "list_directory"],
        audit_logger=MagicMock(),
    )
    try:
        scheduler = result.tool_scheduler
        # B1: the scheduler must have a SecurityMiddleware installed —
        # not the default-constructed bare middleware without sandbox.
        assert scheduler.security_middleware is not None
        # B1: the middleware must carry a Sandbox (capability gate).
        assert scheduler.security_middleware.sandbox is not None
        # B1: the middleware must carry a NetworkGuard (domain enforcement).
        assert scheduler.security_middleware.network_guard is not None
        # B1: the middleware must carry the EffectivePolicy (digest bound
        # to every approval decision).
        assert scheduler.security_middleware.effective_policy is not None
        # B1: the registry must be PRUNED to exactly the declared tools —
        # the subagent cannot invoke tools outside its declared scope.
        registry = scheduler.registry
        registered = set(registry._tools.keys())
        assert "read_file" in registered
        assert "list_directory" in registered
        # A tool NOT in the allowlist must not be present.
        assert "terminal" not in registered, (
            "subagent registry must be pruned to declared tools; terminal "
            "was not in the allowlist but is registered"
        )
    finally:
        await result.aclose()
        await db.close()


async def test_subagent_registry_pruning_drops_undeclared_tools(tmp_path):
    """B1: ``tool_allowlist`` must produce a genuine pruned view, not a
    full registry with name validation only.

    The previous spawner validated that declared tool names existed but
    still handed the subagent a scheduler wired to the *full* registry,
    so a subagent could invoke any registered tool.
    """
    policy = "sandbox:\n  mode: workspace-write\n"
    result, db = await _build_runtime(
        tmp_path, policy, tool_allowlist=["read_file"]
    )
    try:
        registered = set(result.tool_scheduler.registry._tools.keys())
        # The allowlist only contains read_file; nothing else should be
        # present (especially not dangerous tools like terminal / write_file).
        assert registered == {"read_file"}, (
            f"registry should be pruned to {{read_file}} but got {registered}"
        )
    finally:
        await result.aclose()
        await db.close()


# ───────────────────────── B1: browser_file_upload path ─────────────────────


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX dirfd contract")
def test_browser_file_upload_rejects_host_path_outside_workspace(tmp_path):
    """B1: ``browser_file_upload`` must reject a ``file_path`` that resolves
    outside ``workspace_root`` — no arbitrary host file exfiltration via
    the browser upload channel.

    The previous handler passed ``file_path`` straight to
    ``page.set_input_files`` with no containment check.
    """
    from khaos.tools.browser_tools import _read_upload_bytes

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    # A file inside the workspace should pass validation.
    inside = workspace / "ok.txt"
    inside.write_text("hello", encoding="utf-8")
    assert _read_upload_bytes(str(inside), str(workspace)) == (b"hello", "ok.txt")

    # A file outside the workspace must be rejected.
    outside = tmp_path / "secret.key"
    outside.write_text("AKIA" + "X" * 16, encoding="utf-8")
    result = _read_upload_bytes(str(outside), str(workspace))
    assert result is not None
    assert result["ok"] is False
    assert "outside the workspace root" in result["error"]


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX dirfd contract")
def test_browser_file_upload_rejects_symlink_escape(tmp_path):
    """B1: a symlink that escapes the workspace must be rejected.

    ``Path.resolve(strict=True)`` follows symlinks, so a symlink inside
    the workspace that points to ``/etc/passwd`` resolves outside the
    root and is rejected.
    """
    from khaos.tools.browser_tools import _read_upload_bytes

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("secret", encoding="utf-8")
    link = workspace / "escape.txt"
    link.symlink_to(target)

    result = _read_upload_bytes(str(link), str(workspace))
    assert result is not None
    assert result["ok"] is False


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="POSIX dirfd contract")
def test_browser_file_upload_enforces_size_limit(tmp_path):
    """B1: ``browser_file_upload`` enforces a 10 MiB size limit so the
    browser upload channel cannot be used for bulk exfiltration.
    """
    from khaos.tools.browser_tools import _UPLOAD_MAX_BYTES, _read_upload_bytes

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    oversized = workspace / "big.bin"
    oversized.write_bytes(b"\x00" * (_UPLOAD_MAX_BYTES + 1))

    result = _read_upload_bytes(str(oversized), str(workspace))
    assert result is not None
    assert result["ok"] is False
    assert "exceeds the upload limit" in result["error"]


async def test_browser_file_upload_requires_network_policy(tmp_path):
    """B1: the handler rejects when ``network_policy`` is not
    ``unrestricted-with-approval`` — defense in depth on top of the
    capability broker.
    """
    from khaos.tools.browser_tools import browser_file_upload

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    f = workspace / "ok.txt"
    f.write_text("hello", encoding="utf-8")

    # No network policy → must be rejected.
    result = await browser_file_upload(
        selector="#file",
        file_path=str(f),
        workspace_root=str(workspace),
        network_policy="none",
    )
    assert result["ok"] is False
    assert "network access" in result["error"]


# ───────────────────────── H1: NetworkGuard domain enforcement ──────────────


def test_network_enabled_with_allowlist_denies_unlisted_domain():
    """H1: ``network_enabled=True`` must NOT bypass the allowlist.

    Previously the first line of ``check_tool`` was
    ``if self.network_enabled: return allowed``, which made an allowlist
    like ``[pypi.org]`` silently grant *unrestricted* network access.
    """
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["pypi.org"],
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://evil.example.com"}
    )
    assert result.allowed is False
    assert result.domain == "evil.example.com"
    assert "not in allowlist" in result.reason


def test_network_enabled_with_allowlist_allows_listed_domain():
    """H1: an allowlisted domain is allowed when network is enabled."""
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["pypi.org"],
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://pypi.org/simple"}
    )
    assert result.allowed is True


def test_network_enabled_with_blocklist_still_blocks():
    """H1: ``blocked_domains`` always wins, even when network is enabled."""
    guard = NetworkGuard(
        network_enabled=True,
        blocked_domains=["evil.example.com"],
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://evil.example.com"}
    )
    assert result.allowed is False
    assert "blocked by policy" in result.reason


def test_network_enabled_with_allowlist_and_blocklist_blocklist_wins():
    """H1: priority is blocked > allowed > network_enabled.

    A domain in BOTH lists must be blocked (blocklist wins).
    """
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["example.com"],
        blocked_domains=["bad.example.com"],
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://bad.example.com"}
    )
    assert result.allowed is False


def test_network_enabled_empty_allowlist_allows_unblocked_domains():
    """H1: an empty allowlist with network enabled means unrestricted
    (subject to blocklist) — this preserves backward compatibility for
    callers that don't configure an allowlist.
    """
    guard = NetworkGuard(network_enabled=True)
    result = guard.check_tool(
        "terminal", {"command": "curl https://anything.com"}
    )
    assert result.allowed is True


def test_network_disabled_blocks_even_with_allowlist():
    """H1: when network is disabled, all network access is blocked
    regardless of the allowlist — the allowlist can only TIGHTEN an
    enabled network, not RELAX a disabled one.

    This is the deliberate semantic change from the H1 fix: previously
    an allowlist like ``[pypi.org]`` would silently grant pypi.org
    access even with ``network_enabled=False``.  Now ``network_enabled``
    is a TOTAL SWITCH — when off, all network access is blocked.
    """
    guard = NetworkGuard(
        network_enabled=False,
        allowed_domains=["pypi.org"],
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://pypi.org/simple"}
    )
    assert result.allowed is False, (
        "network_enabled=False must block ALL network access regardless "
        "of the allowlist (the allowlist cannot relax a disabled network)"
    )


# ───────────────────────── H2: commands.allow layered enforcement ───────────


def test_commands_allow_three_state_none_means_unset(tmp_path):
    """H2: ``commands_allowed=None`` means "no allow-list configured" —
    the CommandGuard must NOT enforce a whitelist (commands are allowed
    unless blocked).
    """
    project = SandboxPolicy(mode="workspace-write")  # commands_allowed=None
    eff = compile_effective_policy(project, workspace_root=tmp_path)
    assert eff.commands_allowed is None

    middleware = SecurityMiddleware(effective_policy=eff)
    # None means no whitelist — the guard's _allowed_commands stays None.
    assert middleware.command_guard._allowed_commands is None


def test_commands_allow_three_state_empty_means_deny_all(tmp_path):
    """H2: ``commands_allowed=[]`` means "deny all commands" — the
    CommandGuard must install an empty frozenset so every base command
    is rejected.
    """
    project = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=[],  # explicit deny-all
    )
    eff = compile_effective_policy(project, workspace_root=tmp_path)
    # An empty list compiles to an empty frozenset (not None).
    assert eff.commands_allowed is not None
    assert len(eff.commands_allowed) == 0

    middleware = SecurityMiddleware(effective_policy=eff)
    # Empty frozenset → guard rejects every command.
    assert middleware.command_guard._allowed_commands == frozenset()


def test_commands_allow_project_whitelist_survives_default_user_layer(tmp_path):
    """H2: the production bug — a project whitelist like
    ``commands.allow: [git, pytest]`` was erased by the default user
    layer (which had ``commands_allowed = []``), then the middleware
    treated the empty intersection as "unset" and allowed ALL commands.

    With three-state semantics:
    * default user layer has ``commands_allowed=None`` (unset);
    * project layer has ``commands_allowed=[git, pytest]``;
    * effective policy = project layer (only one configures a whitelist).
    """
    project = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=["git", "pytest"],
    )
    # Default user policy: commands_allowed=None (the new default).
    user = SandboxPolicy(mode="workspace-write")  # commands_allowed=None
    eff = compile_effective_policy(
        project, workspace_root=tmp_path, user_policy=user
    )
    assert eff.commands_allowed == frozenset({"git", "pytest"}), (
        "project whitelist must survive the default user layer "
        "(three-state: None means unset, not empty)"
    )

    middleware = SecurityMiddleware(effective_policy=eff)
    assert middleware.command_guard._allowed_commands == frozenset(
        {"git", "pytest"}
    )


def test_commands_allow_intersection_when_both_layers_configure(tmp_path):
    """H2: when BOTH layers configure a whitelist, the result is the
    intersection (stricter).  This is the only case where intersection
    is correct — previously intersection was always used and an empty
    user layer erased the project layer.
    """
    project = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=["git", "pytest", "ls"],
    )
    user = SandboxPolicy(
        mode="workspace-write",
        commands_allowed=["git", "ls"],
    )
    eff = compile_effective_policy(
        project, workspace_root=tmp_path, user_policy=user
    )
    assert eff.commands_allowed == frozenset({"git", "ls"})


# ───────────────────────── H3: aclose shared _close_task ────────────────────


async def test_concurrent_aclose_calls_wait_on_same_task():
    """H3: when two coroutines call ``aclose()`` concurrently, the second
    must NOT return immediately while cleanup is still in flight — both
    must wait on the SAME shared ``_close_task``.

    Previously the second caller saw ``_closing=True`` and returned at
    once, so a concurrent caller could observe a half-torn-down runtime.
    """
    memory = MagicMock()
    # Make memory.aclose slow so we can prove the second caller waits.
    async def _slow_close():
        await asyncio.sleep(0.05)
    memory.aclose = AsyncMock(side_effect=_slow_close)
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )
    # Launch both aclose calls concurrently.
    await asyncio.gather(result.aclose(), result.aclose())
    # The slow memory close must have run exactly once (idempotent), and
    # both callers observed the final closed state.
    assert memory.aclose.await_count == 1
    assert result._closed is True


async def test_aclose_component_failure_leaves_closed_false_for_retry():
    """H3: a component shutdown failure must set ``_close_failed=True``
    and leave ``_closed=False`` so the caller can observe the failure
    and retry (each component's shutdown is expected to be idempotent).

    H4: ``aclose`` now retries 3 times and then raises
    ``RuntimeCloseError`` so the production caller is forced to observe
    the failure.  Previously the failure was swallowed silently and the
    caller had no way to know cleanup was incomplete.

    After the exception, the runtime state must still allow a retry:
    ``_close_failed`` is True, ``_closed`` is False, and
    ``_close_task`` is None.
    """
    from khaos.exceptions import RuntimeCloseError

    office = MagicMock()
    office.shutdown = AsyncMock(side_effect=RuntimeError("office boom"))
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        office_authority=office,
        owns_office_authority=True,
    )
    # H4: aclose raises after exhausting retries.
    with pytest.raises(RuntimeCloseError):
        await result.aclose()
    assert result._close_failed is True
    assert result._closed is False
    # A retry must be possible: _close_task was reset.
    assert result._close_task is None


async def test_aclose_cancellation_does_not_abort_cleanup():
    """H3: if the caller of ``aclose()`` is cancelled, the cleanup task
    itself must keep running (it is shielded) so a subsequent ``aclose``
    can await the still-running task and observe the final state.

    Previously a cancelled ``aclose`` would leave the runtime in an
    indeterminate state with no owner to retry the cleanup.
    """
    memory = MagicMock()
    async def _slow_close():
        await asyncio.sleep(0.05)
    memory.aclose = AsyncMock(side_effect=_slow_close)
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=memory,
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
    )
    # Start aclose, then cancel it mid-flight.
    task = asyncio.ensure_future(result.aclose())
    await asyncio.sleep(0.01)  # let it enter the close task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    # The shared _close_task must still be running (or already done).
    # Give it time to finish, then a second aclose must observe _closed.
    await asyncio.sleep(0.1)
    await result.aclose()
    assert result._closed is True


async def test_aclose_releases_principal_browser_context():
    """H1 / H3: ``aclose`` must release the principal's per-session
    BrowserContext so cookies / DOM / page state cannot leak into a
    subsequent run by a different principal sharing the same process-wide
    BrowserManager.
    """
    manager = MagicMock()
    manager.close_runtime = AsyncMock(return_value={"ok": True})
    # Patch the module-level _manager that factory.aclose imports.
    import khaos.tools.browser_tools as bt

    original = bt._manager
    bt._manager = manager
    result = RuntimeResult(
        loop=MagicMock(),
        mode_manager=MagicMock(),
        task_manager=None,
        skill_generator=None,
        tool_scheduler=MagicMock(),
        memory_manager=MagicMock(aclose=AsyncMock()),
        skill_manager=MagicMock(),
        new_verify_fix_loop=None,
        principal_id="user-42",
        # H5: aclose passes session_id + runtime_id through so the
        # per-session context key is matched correctly.
        session_id="sess-1",
        runtime_id="rt-1",
    )
    try:
        await result.aclose()
        # H1 (lifecycle): ``close_runtime(runtime_id)`` is called (not
        # ``close_context(principal_id, ...)``) so ALL contexts the
        # runtime acquired — regardless of which (principal, session,
        # runtime) key they were originally created under — are released.
        # This closes the leak where a runtime acquired contexts under
        # multiple keys and ``close_context`` only released one of them.
        manager.close_runtime.assert_awaited_once_with("rt-1")
    finally:
        bt._manager = original


# ───────────────────────── H1: per-principal BrowserContext ─────────────────


def test_browser_manager_per_principal_isolation():
    """H1: ``BrowserManager`` maintains a per-principal context+page pair
    keyed by ``principal_id`` so different principals do not share
    cookies / DOM / page state.

    This test runs against the mock fallback path (no Playwright needed)
    by inspecting the manager's ``_contexts`` dict structure directly.
    """
    manager = BrowserManager()
    # Two different principals must map to two different context keys.
    # In mock mode ensure_page returns None (Playwright not installed),
    # but we can still verify the keying logic by calling _safe_execute
    # and observing that no exception leaks.  The structural guarantee
    # is that _contexts is keyed by principal_id.
    assert manager._contexts == {}
    # The key derivation rule: empty principal_id → "default".
    # We can't easily exercise ensure_page without Playwright, so verify
    # the key derivation directly via close_context (which uses the same
    # key derivation).
    import asyncio

    async def _run():
        # close_context on a never-created principal must be a no-op
        # that doesn't affect other principals.
        await manager.close_context("principal-A")
        await manager.close_context("principal-B")
    asyncio.run(_run())
    # No contexts were created; close_context is a no-op.
    assert manager._contexts == {}


def test_browser_manager_close_context_only_closes_target_principal():
    """H1: closing one principal's BrowserContext must not close another
    principal's context — isolation must hold in both directions.

    H5: the context key is now ``f"{principal_id}:{session_id}:{runtime_id}"``
    (not just ``principal_id``) so two concurrent local sessions under the
    same UID get independent contexts.  This test uses the default
    session_id / runtime_id (which collapse to ``"default"``) so the key
    for ``principal-A`` is ``"principal-A:default:default"``.
    """
    manager = BrowserManager()
    # Simulate two pre-existing principal contexts (H5 key format).
    fake_ctx_a = MagicMock()
    fake_ctx_a.close = AsyncMock()
    fake_ctx_b = MagicMock()
    fake_ctx_b.close = AsyncMock()
    manager._contexts = {
        "principal-A:default:default": {
            "context": fake_ctx_a, "page": MagicMock(), "refcount": 1,
        },
        "principal-B:default:default": {
            "context": fake_ctx_b, "page": MagicMock(), "refcount": 1,
        },
    }
    import asyncio

    asyncio.run(manager.close_context("principal-A"))
    # Only A's context must be closed and popped.
    fake_ctx_a.close.assert_awaited_once()
    fake_ctx_b.close.assert_not_awaited()
    assert "principal-A:default:default" not in manager._contexts
    assert "principal-B:default:default" in manager._contexts


# ───────────────────────── B1: full factory effective policy wiring ─────────


async def test_main_runtime_wires_effective_policy_into_middleware(tmp_path):
    """B1 / H2: the MAIN runtime (no tool_allowlist) must also wire the
    EffectivePolicy into the SecurityMiddleware so the main AgentLoop is
    bound by the same digest as the subagent.
    """
    policy = (
        "sandbox:\n"
        "  mode: workspace-write\n"
        "  network: false\n"
        "commands:\n"
        "  allow:\n"
        "    - git\n"
        "    - pytest\n"
        "  require_approval:\n"
        "    - rm\n"
    )
    result, db = await _build_runtime(tmp_path, policy)
    try:
        middleware = result.tool_scheduler.security_middleware
        assert middleware is not None
        assert middleware.effective_policy is not None
        # H2: commands.allow from the project policy must reach the
        # CommandGuard as a non-empty frozenset whitelist.
        assert middleware.command_guard._allowed_commands == frozenset(
            {"git", "pytest"}
        )
        # B1: the effective policy digest must be non-empty so approval
        # binding can include it.
        assert middleware.effective_policy_digest != ""
    finally:
        await result.aclose()
        await db.close()


# ───────────────────────── B1: SubAgent principal ownership ──────────────────
#
# B1 (M4 reopen): the SubAgent RPC service previously had NO tenant / principal
# isolation.  ``spawn`` / ``collect`` / ``status`` did not read the
# authenticated principal from the RPC payload, so any authenticated user
# could call global ``collect`` and observe another user's goal / result /
# error.  These tests pin the contract that the service stamps the
# principal onto the task, the spawner filters by it, and the DB persists
# it so a process restart cannot leak stale cross-principal data.


async def test_subagent_service_spawn_stamps_principal_onto_task(tmp_path):
    """B1: ``handle_spawn`` reads ``principal_id`` from the transport-
    authenticated :class:`RequestContext` (M4 batch 3.1.16A-4-2) and
    stamps it onto the created task.  The parent session is namespaced
    by principal so tasks from different principals don't share a
    session namespace.
    """
    from khaos.subagents.service import SubAgentService
    from khaos.subagents.spawner import SubAgentSpawner, SubAgentConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        spawner = SubAgentSpawner(SubAgentConfig(), db)
        service = SubAgentService(spawner, runner=None)
        result = await service.handle_spawn(
            RequestContext.for_rpc("user-alice"),
            {
                "goal": "secret-A",
                "context": "ctx",
                "tools": [],
                "timeout": 1,
            },
        )
        assert result["ok"] is True
        task_id = result["task_id"]
        task = spawner._tasks[task_id]
        # B1: principal_id is stamped from the authenticated ctx.
        assert task.principal_id == "user-alice"
        # B1: parent_session_id is namespaced per principal.
        assert task.parent_session_id == "subagent:user-alice"
        await spawner.wait_all(principal_id="user-alice")
    finally:
        await db.close()


async def test_subagent_service_collect_filters_by_principal(tmp_path):
    """B1: ``handle_collect`` only returns tasks owned by the calling
    principal.  Principal A spawns; principal B collects — B must
    receive ZERO results (not A's goal / result / error).
    """
    from khaos.subagents.service import SubAgentService
    from khaos.subagents.spawner import SubAgentSpawner, SubAgentConfig

    async def _runner(task):
        return f"result-for-{task.goal}"

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=4), db, runner=_runner)
        service = SubAgentService(spawner, runner=None)

        # Principal A spawns two tasks.
        for goal in ("A-secret-1", "A-secret-2"):
            await service.handle_spawn(
                RequestContext.for_rpc("user-alice"),
                {
                    "goal": goal,
                    "context": "",
                    "tools": [],
                    "timeout": 5,
                },
            )
        await spawner.wait_all(principal_id="user-alice")

        # Principal B collects — must see ZERO tasks.
        b_result = await service.handle_collect(
            RequestContext.for_rpc("user-bob"), {}
        )
        assert b_result["ok"] is True
        assert b_result["total"] == 0
        assert b_result["completed"] == 0
        assert b_result["results"] == []

        # Principal A collects — must see both tasks.
        a_result = await service.handle_collect(
            RequestContext.for_rpc("user-alice"), {}
        )
        assert a_result["ok"] is True
        assert a_result["total"] == 2
        assert a_result["completed"] == 2
        goals = {r["goal"] for r in a_result["results"]}
        assert goals == {"A-secret-1", "A-secret-2"}
        # B never observed A's goals.
        for r in a_result["results"]:
            assert "A-secret" in r["goal"]
    finally:
        await db.close()


async def test_subagent_service_status_filters_by_principal(tmp_path):
    """B1: ``handle_status`` only counts tasks owned by the calling
    principal.  Principal A has 2 tasks; principal B sees 0.
    """
    from khaos.subagents.service import SubAgentService
    from khaos.subagents.spawner import SubAgentSpawner, SubAgentConfig

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        spawner = SubAgentSpawner(SubAgentConfig(), db)
        service = SubAgentService(spawner, runner=None)
        await service.handle_spawn(
            RequestContext.for_rpc("user-alice"),
            {"goal": "g1", "context": "", "tools": [], "timeout": 1},
        )
        await service.handle_spawn(
            RequestContext.for_rpc("user-alice"),
            {"goal": "g2", "context": "", "tools": [], "timeout": 1},
        )
        await spawner.wait_all(principal_id="user-alice")

        a_status = await service.handle_status(
            RequestContext.for_rpc("user-alice"), {}
        )
        assert a_status["stats"]["total"] == 2
        assert a_status["stats"]["completed"] == 2

        b_status = await service.handle_status(
            RequestContext.for_rpc("user-bob"), {}
        )
        assert b_status["stats"]["total"] == 0
        assert b_status["stats"]["completed"] == 0
    finally:
        await db.close()


async def test_subagent_spawner_stats_filters_by_principal(tmp_path):
    """B1: ``SubAgentSpawner.stats`` only counts tasks owned by the
    given principal.  Cross-principal leakage must not appear in stats.
    """
    from khaos.subagents.spawner import SubAgentSpawner, SubAgentConfig, SubAgentTask

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=4), db)
        await spawner.spawn(SubAgentTask("t1", "g", "c", [], principal_id="alice"))
        await spawner.spawn(SubAgentTask("t2", "g", "c", [], principal_id="alice"))
        await spawner.spawn(SubAgentTask("t3", "g", "c", [], principal_id="bob"))
        await spawner.wait_all(principal_id="alice")
        await spawner.wait_all(principal_id="bob")

        assert spawner.stats(principal_id="alice")["total"] == 2
        assert spawner.stats(principal_id="bob")["total"] == 1
        # M2: empty principal_id now returns NOTHING (fail-closed), not
        # all tasks.  A caller bypassing the service with an empty
        # principal must not observe every principal's tasks.
        assert spawner.stats()["total"] == 0
    finally:
        await db.close()


async def test_subagent_spawner_collect_results_filters_by_principal(tmp_path):
    """B1: ``collect_results`` only returns results owned by the given
    principal.  Principal B must not observe principal A's result text.
    """
    from khaos.subagents.spawner import SubAgentSpawner, SubAgentConfig, SubAgentTask

    async def _runner(task):
        return f"secret-{task.principal_id}"

    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        spawner = SubAgentSpawner(SubAgentConfig(max_concurrent=4), db, runner=_runner)
        await spawner.spawn(SubAgentTask("t1", "g", "c", [], principal_id="alice"))
        await spawner.spawn(SubAgentTask("t2", "g", "c", [], principal_id="bob"))
        await spawner.wait_all(principal_id="alice")
        await spawner.wait_all(principal_id="bob")

        alice_results = await spawner.collect_results(principal_id="alice")
        assert alice_results == ["secret-alice"]
        bob_results = await spawner.collect_results(principal_id="bob")
        assert bob_results == ["secret-bob"]
        # Bob must never see Alice's secret.
        assert "secret-alice" not in bob_results
    finally:
        await db.close()


async def test_database_persists_subagent_principal_id(tmp_path):
    """B1: ``insert_subagent_task`` persists ``principal_id`` and
    ``list_subagent_tasks(principal_id)`` filters on disk.  This pins
    the DB-level isolation so a process restart cannot surface stale
    cross-principal rows.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        await db.create_session("sess-alice")
        await db.create_session("sess-bob")
        await db.insert_subagent_task(
            "t1", "sess-alice", "A-goal", "ctx", "[]", "completed",
            principal_id="user-alice",
        )
        await db.insert_subagent_task(
            "t2", "sess-bob", "B-goal", "ctx", "[]", "completed",
            principal_id="user-bob",
        )

        # Unfiltered — both rows are visible.
        all_rows = await db.list_subagent_tasks()
        assert len(all_rows) == 2
        assert {r["principal_id"] for r in all_rows} == {"user-alice", "user-bob"}

        # Principal-scoped — only the caller's rows are visible.
        alice_rows = await db.list_subagent_tasks(principal_id="user-alice")
        assert len(alice_rows) == 1
        assert alice_rows[0]["principal_id"] == "user-alice"
        assert alice_rows[0]["goal"] == "A-goal"

        bob_rows = await db.list_subagent_tasks(principal_id="user-bob")
        assert len(bob_rows) == 1
        assert bob_rows[0]["principal_id"] == "user-bob"

        # Principal with no tasks sees nothing.
        empty = await db.list_subagent_tasks(principal_id="user-carol")
        assert empty == []
    finally:
        await db.close()


async def test_database_subagent_principal_column_migration_is_idempotent(tmp_path):
    """B1: ``_ensure_subagent_tasks_principal_column`` is idempotent.
    Calling it multiple times must not raise.  A legacy DB (column
    missing) gets the column added; a fresh DB (column present from
    schema.sql) is a no-op.
    """
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    try:
        # First call — fresh DB has the column already (from schema.sql).
        await db._ensure_subagent_tasks_principal_column()
        # Second call — still a no-op.
        await db._ensure_subagent_tasks_principal_column()

        cursor = await db._conn.execute("PRAGMA table_info(subagent_tasks)")
        cols = {row["name"] for row in await cursor.fetchall()}
        assert "principal_id" in cols
    finally:
        await db.close()


async def test_subagent_runner_uses_task_principal_not_server_principal():
    """B1: ``SubAgentRunner.run`` passes ``task.principal_id`` (from the
    authenticated RPC payload) to ``build_runtime``, NOT the server-fixed
    ``self.principal_id``.  This ensures BrowserContext / Memory scope /
    audit events bind to the CALLING principal, not the server's UID.
    """
    from khaos.subagents.runner import SubAgentRunner
    from khaos.subagents.spawner import SubAgentTask

    captured: dict = {}

    async def _fake_build_runtime(cfg):
        captured["principal_id"] = cfg.principal_id
        # Return a minimal mock runtime whose aclose is a no-op and whose
        # loop.run yields no messages.
        runtime = MagicMock()
        runtime.aclose = AsyncMock()
        runtime.loop = MagicMock()

        async def _empty_run(*args, **kwargs):
            return
            yield  # pragma: no cover - generator marker

        runtime.loop.run = _empty_run
        return runtime

    # ``build_runtime`` is imported lazily inside ``run`` via
    # ``from khaos.runtime import build_runtime`` — so patch it on the
    # ``khaos.runtime`` module where the name is actually looked up.
    import khaos.runtime as runtime_mod

    original = runtime_mod.build_runtime
    runtime_mod.build_runtime = _fake_build_runtime
    try:
        # ``db`` must be an async mock — ``create_session`` is awaited.
        db = MagicMock()
        db.create_session = AsyncMock()
        runner = SubAgentRunner(
            router=MagicMock(),
            db=db,
            mode_manager=MagicMock(),
            principal_id="server-fixed-uid",
        )
        # The task carries the CALLING principal (set from RPC payload).
        task = SubAgentTask(
            id="t1", goal="g", context="c", tools=[],
            principal_id="user-alice",
        )
        await runner.run(task)
    finally:
        runtime_mod.build_runtime = original

    # The runtime was built with the TASK's principal, not the server's.
    assert captured["principal_id"] == "user-alice"
    assert captured["principal_id"] != "server-fixed-uid"


async def test_subagent_runner_falls_back_to_server_principal_when_task_unscoped():
    """B1: when the task has no principal (legacy / internal callers),
    the runner falls back to ``self.principal_id`` so the runtime still
    gets a non-empty principal.
    """
    from khaos.subagents.runner import SubAgentRunner
    from khaos.subagents.spawner import SubAgentTask

    captured: dict = {}

    async def _fake_build_runtime(cfg):
        captured["principal_id"] = cfg.principal_id
        runtime = MagicMock()
        runtime.aclose = AsyncMock()
        runtime.loop = MagicMock()

        async def _empty_run(*args, **kwargs):
            return
            yield  # pragma: no cover - generator marker

        runtime.loop.run = _empty_run
        return runtime

    import khaos.runtime as runtime_mod

    original = runtime_mod.build_runtime
    runtime_mod.build_runtime = _fake_build_runtime
    try:
        db = MagicMock()
        db.create_session = AsyncMock()
        runner = SubAgentRunner(
            router=MagicMock(),
            db=db,
            mode_manager=MagicMock(),
            principal_id="server-fixed-uid",
        )
        task = SubAgentTask(id="t1", goal="g", context="c", tools=[], principal_id="")
        await runner.run(task)
    finally:
        runtime_mod.build_runtime = original

    assert captured["principal_id"] == "server-fixed-uid"
