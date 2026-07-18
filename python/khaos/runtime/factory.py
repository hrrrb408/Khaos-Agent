"""Unified asynchronous runtime factory for every AgentLoop entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.audit import AuditLogger, resolve_safe_audit_log_path
from khaos.coding.task_manager import TaskManager
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.coding.execution import BackendSelector, ExecutionService
from khaos.exceptions import RuntimeCloseError
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.rust_bridge import get_token_engine
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_guard import NetworkGuard
from khaos.security.sandbox import Sandbox
from khaos.skills import SkillGenerator, SkillManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler

logger = logging.getLogger(__name__)


@dataclass
class RuntimeConfig:
    project_root: Path = field(default_factory=Path.cwd)
    config_path: Path | None = None
    mode_override: str | None = None
    confirm_callback: Any = None
    db: Any = None
    router: Any = None
    mode_manager: ModeManager | None = None
    audit_logger: AuditLogger | None = None
    sandbox: Sandbox | None = None
    network_guard: NetworkGuard | None = None
    task_manager: TaskManager | None = None
    coding_context_builder: Any = None
    agent_config: AgentConfig | None = None
    memory_manager: MemoryManager | None = None
    skill_manager: SkillManager | None = None
    tool_scheduler: ToolScheduler | None = None
    workspace_manager: WorkspaceManager | None = None
    execution_service: ExecutionService | None = None
    approval_broker: Any = None
    # B1: an externally-owned OfficeMutationAuthority (e.g. the server-level
    # authority shared across every chat / webhook / cron turn) can be
    # injected here.  When set, ``build_runtime`` reuses it instead of
    # creating a new one, so the aggregate storage baseline persists across
    # turns (closing the cross-turn quota bypass) and the lifecycle is owned
    # by the caller — ``RuntimeResult.aclose`` will NOT shut it down.
    office_authority: OfficeMutationAuthority | None = None
    principal_id: str = field(
        default_factory=lambda: f"local-uid:{os.getuid()}"
    )
    # H5: session_id + runtime_id extend the per-session BrowserContext key
    # so two concurrent local sessions under the same UID get independent
    # contexts (cookie / DOM / page isolation).  ``runtime_id`` defaults to
    # a fresh UUID per RuntimeConfig so a subagent spawned within a chat
    # turn gets its own context (or shares the parent's when explicitly
    # passed).  ``session_id`` is the chat session that owns this runtime.
    session_id: str = ""
    runtime_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    # B1: when set, ``build_runtime`` constructs the ToolScheduler's registry
    # by pruning the full runtime registry down to exactly these tool names.
    # SubAgent tasks declare a tool subset (``task.tools``); without this
    # field the subagent would receive a scheduler wired to the *full*
    # registry and could invoke any registered tool regardless of its
    # declared subset.  ``None`` (the default) means "no pruning" — the
    # full runtime registry is installed (the main AgentLoop path).
    tool_allowlist: list[str] | None = None


@dataclass
class RuntimeResult:
    loop: AgentLoop
    mode_manager: ModeManager
    task_manager: TaskManager | None
    skill_generator: SkillGenerator | None
    tool_scheduler: ToolScheduler
    memory_manager: MemoryManager
    skill_manager: SkillManager
    new_verify_fix_loop: Callable[[], VerifyFixLoop] | None
    execution_service: ExecutionService | None = None
    # H3: the OfficeMutationAuthority is owned by the runtime so aclose()
    # can fence every in-flight Office mutation before the process exits.
    office_authority: OfficeMutationAuthority | None = None
    # B1: when False, ``office_authority`` was injected (shared) and aclose
    # must NOT shut it down — the owner (AgentService / SubAgentService)
    # manages its lifecycle.  Defaults to True for ad-hoc constructions.
    owns_office_authority: bool = True
    # H1: the principal that owns this runtime.  ``aclose`` uses it to
    # release the principal's per-session ``BrowserContext`` so cookies /
    # DOM / page state cannot leak into a subsequent run by a different
    # principal sharing the same process-wide ``BrowserManager``.
    # H5: ``session_id`` + ``runtime_id`` extend the context key so two
    # concurrent local sessions under the same UID get independent contexts
    # — closing one runtime's context does NOT close another's page.
    principal_id: str = ""
    session_id: str = ""
    runtime_id: str = ""
    # H2: the AuditLogger is stored here so ``aclose()`` can close its file
    # descriptor — without this, configuring a file audit path would leak
    # the fd for the process's lifetime.  Closed LAST in ``_run_close``
    # (after every other component) because audit logging may be needed
    # during component shutdown (e.g. to record the shutdown itself).
    audit_logger: AuditLogger | None = None
    # H3: injected loggers are process/server-owned and must survive every
    # turn.  Only a logger constructed by ``build_runtime`` is runtime-owned.
    owns_audit_logger: bool = True
    # H4: persistent close failure quarantines the runtime in the orphan
    # registry.  The flag is observable and is cleared only after a later
    # cleanup succeeds.
    quarantined: bool = field(default=False, init=False)
    # B1: ``init=False`` so positional construction can never accidentally
    # bind a real component into ``_closed`` (which previously made
    # ``aclose()`` a no-op because the truthy component short-circuited it).
    # H3: a shared ``_close_task`` guarantees:
    #   * the first ``aclose`` creates and ``shield``s the cleanup task;
    #   * concurrent / retried ``aclose`` callers await the SAME task (they
    #     don't return immediately while cleanup is still in flight);
    #   * ``_closed`` is set ONLY when every safety-critical component has
    #     reached a terminal state — a cancelled or partially-failed aclose
    #     leaves ``_closed=False`` so the caller can retry;
    #   * a component shutdown failure marks the runtime ``_close_failed``
    #     (also ``_closed=False``) so the caller can observe and retry.
    _close_task: Any = field(default=None, init=False)
    _closed: bool = field(default=False, init=False)
    _close_failed: bool = field(default=False, init=False)
    # H4: serializes the aclose() retry logic so concurrent callers don't
    # each create a separate ``_close_task`` (which would run shutdown on
    # the same components multiple times concurrently).  ``init=False`` so
    # positional construction can never bind a component into it, and
    # ``default_factory`` so each RuntimeResult gets its own Lock without
    # being passed explicitly.
    _close_lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)

    async def aclose(self) -> None:
        """Release runtime-owned resources; database ownership stays with caller.

        H3: uses a shared ``_close_task`` so:

        * the first ``aclose`` creates and ``shield``s the cleanup task;
        * concurrent callers (and a retried aclose after cancellation)
          await the SAME task — they don't return immediately while
          cleanup is still in flight;
        * ``_closed`` is set ONLY after every safety-critical component
          has reached a terminal state.  A cancelled or partially-failed
          aclose leaves ``_closed=False`` so the caller can retry; a
          component shutdown failure sets ``_close_failed=True`` (also
          ``_closed=False``) so the caller can observe and retry.

        H4: if the in-flight ``_close_task`` is itself cancelled (e.g.
        event loop shutdown) or raises, ``_run_close`` clears
        ``_close_task`` in its ``finally`` so a subsequent ``aclose()``
        retry creates a FRESH task instead of re-awaiting the
        cancelled/failed task forever.

        H4: when a safety-critical component fails to shut down, ``aclose``
        raises ``RuntimeCloseError`` instead of silently returning.  The
        production callers (Chat / SubAgent) previously called ``aclose``
        once and discarded the result — now they are forced to observe
        the failure and retry.  A limited auto-retry (3 attempts) is
        built in so transient component failures don't propagate to the
        user.

        H4: an ``asyncio.Lock`` serializes the retry loop so concurrent
        ``aclose()`` callers don't each create a separate ``_close_task``
        (which would run shutdown on the same components multiple times
        concurrently).  Other callers wait on the lock, then see
        ``_closed=True`` (if the first caller succeeded) or
        ``_close_failed=True`` (if it exhausted retries) and return
        without re-running the retries.  The orphan-cleanup registry
        (``cleanup_orphan_runtimes``) resets ``_close_failed`` before
        retrying so a persistently-failing runtime gets a fresh attempt
        cycle.

        H1: releases the principal's per-session ``BrowserContext`` so
        cookies / DOM / page state cannot leak into a subsequent run by
        a different principal sharing the same process-wide BrowserManager.
        """
        import asyncio as _asyncio

        # Already fully closed — nothing to do (fast path, no lock).
        if self._closed:
            return
        # H4: serialize the retry logic so concurrent callers don't each
        # create a separate ``_close_task``.  The lock is held for the
        # entire retry loop; other callers wait, then observe the terminal
        # state set by the first caller.
        async with self._close_lock:
            # Re-check _closed inside the lock — another caller may have
            # completed the close while we were waiting on the lock.
            if self._closed:
                return
            # H4: a previous caller already exhausted the auto-retries.
            # Don't re-run them — the caller is expected to register the
            # runtime with the orphan-cleanup registry for further retries
            # (``cleanup_orphan_runtimes`` resets ``_close_failed`` before
            # retrying).  Returning here (rather than raising) means a
            # concurrent caller that was waiting on the lock observes the
            # first caller's ``RuntimeCloseError`` via ``asyncio.gather``
            # and doesn't re-run the retries itself.
            if self._close_failed:
                return
            # H4: limited auto-retry so transient component failures are
            # retried in-line; only persistent failures surface to the caller.
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                # A close task is already in flight — wait on the SAME task so
                # concurrent callers don't return before cleanup finishes.
                # H4: if the task was cancelled/raised, ``_run_close``'s
                # finally clears ``_close_task`` (so a retry creates a fresh
                # task).  In that case we fall through to the create-task
                # path below.
                if self._close_task is not None:
                    try:
                        await _asyncio.shield(self._close_task)
                    except _asyncio.CancelledError:
                        # Either the caller was cancelled (propagate) or the
                        # close task itself was cancelled (``_close_task`` is
                        # now None — fall through to retry).  Distinguish by
                        # checking ``_close_task``: if it's None, the task
                        # cleared itself.
                        if self._close_task is None:
                            # H4: the in-flight close task was self-cancelled;
                            # fall through to create a fresh task and retry.
                            pass
                        else:
                            # The caller was cancelled while the close task is
                            # still running; propagate the cancellation.
                            raise
                    else:
                        # The in-flight task finished (success or component
                        # failure).  If ``_closed`` is still False, the task
                        # cleared ``_close_task`` so we can retry.
                        if self._closed or self._close_task is not None:
                            return
                        # H4: ``_close_task`` was cleared by the failed path —
                        # fall through to retry.
                if self._closed:
                    return
                # Create the shared cleanup task and shield it so a
                # cancellation of the *caller* does not abort the cleanup
                # itself.
                self._close_task = _asyncio.ensure_future(self._run_close())
                try:
                    await _asyncio.shield(self._close_task)
                except _asyncio.CancelledError:
                    # The caller was cancelled, but the cleanup task keeps
                    # running.  Re-raise so the caller's cancellation
                    # propagates; a subsequent aclose() will await the
                    # still-running task (or, if the task self-cancelled and
                    # cleared ``_close_task``, create a fresh one).
                    raise
                # Check terminal state after the task completed.
                if self._closed:
                    return
                # H4: ``_close_failed`` is set — retry if attempts remain.
                if attempt < max_attempts and self._close_failed:
                    logger.warning(
                        "runtime aclose attempt %d/%d failed; retrying",
                        attempt, max_attempts,
                    )
                    continue
                # H4: all retries exhausted — raise so the caller observes
                # the failure and can escalate (register with the
                # orphan-cleanup registry via ``register_orphan_runtime``).
                if self._close_failed:
                    raise RuntimeCloseError(
                        f"runtime cleanup failed after {max_attempts} attempts; "
                        f"safety-critical components may not have reached a "
                        f"terminal state — principal={self.principal_id} "
                        f"session={self.session_id} runtime={self.runtime_id}"
                    )
                break

    async def _run_close(self) -> None:
        """Run the actual cleanup; idempotent and failure-tolerant.

        H3: ``_closed`` is set ONLY when every safety-critical component
        has reached a terminal state.  A component failure sets
        ``_close_failed=True`` and leaves ``_closed=False`` so the caller
        can retry (each component's shutdown is expected to be idempotent).

        H4: if this task itself is cancelled (e.g. event loop shutdown)
        or raises an unexpected exception, clear ``_close_task`` in the
        ``finally`` so a subsequent ``aclose()`` creates a fresh task and
        retries — otherwise every future ``aclose()`` would re-await this
        cancelled/failed task forever, permanently preventing cleanup.

        H4: ``_close_failed`` is reset at the start of each retry so the
        last attempt's failure doesn't poison the next attempt's result.
        """
        if self._closed:
            return
        # H4: reset _close_failed for this attempt — a previous attempt's
        # failure should not make the retry appear to have failed.
        self._close_failed = False
        failed = False
        try:
            # H3: fence Office mutations FIRST — wait for every in-flight
            # copy/move worker to settle (commit or roll back) and mark every
            # Office workspace read-only before any other component shuts down.
            # Without this, a mutation thread could keep writing to the
            # filesystem after the runtime has already closed.
            # B1: only close if owned — a shared/injected authority is managed
            # by the server (AgentService.shutdown).
            if (
                self.office_authority is not None
                and self.owns_office_authority
            ):
                try:
                    await self.office_authority.shutdown()
                except Exception:
                    failed = True
                    logger.debug(
                        "office authority shutdown failed", exc_info=True
                    )
            if self.memory_manager is not None:
                close = getattr(self.memory_manager, "aclose", None)
                if close is not None:
                    try:
                        await close()
                    except Exception:
                        failed = True
                        logger.debug(
                            "memory manager close failed", exc_info=True
                        )
            if self.execution_service is not None:
                try:
                    await self.execution_service.shutdown()
                except Exception:
                    failed = True
                    logger.debug(
                        "execution service close failed", exc_info=True
                    )
            # H1: release EVERY BrowserContext this runtime acquired so its
            # cookies / DOM / page state cannot leak into a subsequent run by
            # a different runtime sharing the same process-wide
            # BrowserManager.  A close failure is safety-critical: the
            # manager retains the live Context so this runtime must enter the
            # same retry/quarantine path as other owned resources.
            #
            # H1 (lifecycle): we use ``close_runtime(runtime_id)`` (not
            # ``close_context(principal_id, session_id, runtime_id)``)
            # because a runtime may have acquired contexts under multiple
            # keys (e.g. via different ``session_id``s during its
            # lifetime).  ``close_context`` only releases ONE key and
            # would leak the rest; ``close_runtime`` iterates every entry
            # whose ``_runtime_owners`` set lists this ``runtime_id`` and
            # decrements the refcount for each, so ALL contexts the
            # runtime acquired are released regardless of the key.  A
            # concurrent runtime sharing a context is NOT affected
            # (refcount only closes when the last owner releases).
            if self.runtime_id:
                try:
                    from khaos.tools.browser_tools import _manager as _browser_manager
                    await _browser_manager.close_runtime(self.runtime_id)
                except Exception:
                    failed = True
                    logger.debug(
                        "browser runtime close failed for runtime %s",
                        self.runtime_id,
                        exc_info=True,
                    )
            # H2: close the AuditLogger LAST — audit logging may be needed
            # during component shutdown (e.g. to record the shutdown event
            # itself), so the file descriptor must remain open until every
            # other component has settled.  Best-effort: a close failure
            # does NOT set ``_close_failed`` (audit logger close is not
            # safety-critical — the OS reclaims the fd on process exit).
            if self.audit_logger is not None and self.owns_audit_logger:
                try:
                    close_method = getattr(self.audit_logger, "close", None)
                    if close_method is not None:
                        close_method()
                except Exception:
                    logger.debug(
                        "audit logger close failed", exc_info=True
                    )
            # H3: only mark closed when every safety-critical component
            # reached a terminal state.  A component failure sets
            # ``_close_failed`` so the caller can observe and retry;
            # ``_closed`` stays False so a subsequent ``aclose`` will run
            # the cleanup again (each component's shutdown is expected to
            # be idempotent).
            if failed:
                self._close_failed = True
                # Reset ``_close_task`` so a retry actually re-runs cleanup.
                self._close_task = None
                return
            self._closed = True
        except BaseException:
            # H4: the close task itself was cancelled (CancelledError, e.g.
            # event loop shutdown) or raised an unexpected exception.  Clear
            # ``_close_task`` so a subsequent ``aclose()`` can create a
            # fresh task and retry — otherwise every future ``aclose()``
            # would re-await this cancelled/failed task forever, permanently
            # preventing cleanup.  Re-raise so the task transitions to the
            # cancelled/errored state and the original caller observes it.
            self._close_task = None
            raise


async def build_runtime(cfg: RuntimeConfig) -> RuntimeResult:
    """Build and initialize a complete runtime; this is the sole loop factory."""
    if cfg.db is None:
        raise ValueError("RuntimeConfig.db is required")
    root = cfg.project_root.expanduser().resolve()
    mode_manager = cfg.mode_manager or ModeManager(cfg.db, project_root=root)
    if cfg.mode_manager is None:
        await mode_manager.load()
    if cfg.mode_override:
        await mode_manager.switch(ModeManager.parse(cfg.mode_override))
    router = cfg.router
    if router is None:
        try:
            from khaos.grpc_server import load_router_from_config

            router = load_router_from_config(cfg.config_path or root / "config.yaml", project_root=root)
        except (OSError, ValueError, KeyError):
            logger.warning("runtime config router unavailable; using default", exc_info=True)
            router = create_default_router()
    # B1: load and compile the *layered* effective policy — user (∼/.khaos/
    # policy.yaml) ∩ project (<repo>/khaos_policy.yaml) ∩ platform — so it is
    # the single source of truth that every runtime component is built from.
    # No component may consult the raw project policy for enforcement.
    from khaos.security.effective_policy import load_effective_policy
    effective_policy = load_effective_policy(root)
    logger.info("effective security policy digest: %s", effective_policy.digest)
    permission_engine = PermissionEngine(
        cfg.db,
        commands_require_approval=effective_policy.commands_require_approval,
    )
    await permission_engine.load_rules()
    memory_manager = cfg.memory_manager or MemoryManager(
        MemoryStore(cfg.db), budget=MemoryBudget(),
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
    )
    skill_manager = cfg.skill_manager or SkillManager()
    skills_dir = root / "skills"
    if len(skill_manager.registry) == 0 and skills_dir.is_dir():
        skill_manager.load_from_dir(skills_dir)
    task_manager = cfg.task_manager
    if task_manager is None:
        task_manager = TaskManager(db=cfg.db)
        await task_manager.load()
    workspace_manager = cfg.workspace_manager or WorkspaceManager()
    execution_service = cfg.execution_service or ExecutionService(
        workspace_manager=workspace_manager,
        backend_selector=BackendSelector(),
    )
    # B1: the OfficeMutationAuthority is a server/project-lifecycle object.
    # When ``cfg.office_authority`` is injected (AgentService / SubAgentService
    # share one across every turn), reuse it so the aggregate storage baseline
    # persists across turns (closing the cross-turn quota bypass) and the
    # lifecycle is owned by the caller.  When not injected, create a new one
    # owned by this RuntimeResult (closed in aclose).
    # B1: when a shared ToolScheduler is passed in that already holds an
    # authority, reuse that authority too — never silently replace it.
    owns_office_authority = True
    if cfg.office_authority is not None:
        office_authority = cfg.office_authority
        owns_office_authority = False
    elif (
        cfg.tool_scheduler is not None
        and getattr(cfg.tool_scheduler, "office_authority", None) is not None
    ):
        # B1: shared scheduler already has an authority — reuse it rather
        # than silently replacing it with a fresh instance (which would
        # both lose the baseline and race with concurrent runtimes).
        office_authority = cfg.tool_scheduler.office_authority
        owns_office_authority = False
    else:
        office_authority = OfficeMutationAuthority()
    # B1: every security component is built from the *effective* policy,
    # not the raw project policy.  B2: root_capabilities is always installed
    # (even when empty) so an empty set means "deny all", not "no restriction".
    if cfg.sandbox is not None:
        sandbox = cfg.sandbox
    else:
        sandbox = Sandbox(
            mode=effective_policy.mode,
            workspace_root=root,
            root_capabilities=effective_policy.root_capabilities,
        )
    if cfg.network_guard is not None:
        network_guard = cfg.network_guard
    else:
        network_guard = NetworkGuard(
            network_enabled=effective_policy.network_enabled,
            # H3: three-state — pass ``None`` through unchanged so
            # NetworkGuard distinguishes "no allowlist" (unrestricted) from
            # "empty allowlist" (deny all).  ``list(None)`` would raise, so
            # only convert when non-None.
            allowed_domains=(
                list(effective_policy.network_allowed_domains)
                if effective_policy.network_allowed_domains is not None
                else None
            ),
            blocked_domains=list(effective_policy.network_blocked_domains),
        )
    # H2: resolve the AuditLogger BEFORE the scheduler block so it is in
    # scope for both the ``cfg.tool_scheduler is None`` branch (where it
    # is wired into the SecurityMiddleware) AND the RuntimeResult at the
    # end (where it is stored so ``aclose`` can close its fd).  Previously
    # the variable was only assigned inside the ``if scheduler is None``
    # block, so RuntimeResult couldn't reference it — the fd leaked.
    audit_logger = cfg.audit_logger
    owns_audit_logger = audit_logger is None
    scheduler = cfg.tool_scheduler
    if scheduler is None:
        # B1: when a tool allowlist is configured (SubAgent path), prune the
        # full runtime registry down to exactly the declared tool subset so
        # the subagent cannot invoke tools outside its declared scope.  The
        # pruned registry is wired into a fresh ToolScheduler whose
        # SecurityMiddleware carries the same EffectivePolicy / Sandbox /
        # NetworkGuard / AuditLogger as the main runtime — closing the
        # parallel-scheduler bypass where a subagent ran without any
        # security stack at all.
        if cfg.tool_allowlist is not None:
            registry = create_runtime_registry().prune(cfg.tool_allowlist)
        else:
            registry = create_runtime_registry()
        # M1: construct an AuditLogger from the EffectivePolicy when the
        # caller didn't inject one.  Previously only the gRPC server path
        # built an AuditLogger; CLI / TUI / tests passed ``None``, so
        # ``audit_enabled`` / ``audit_log_path`` were effectively ignored
        # outside the server.  Now every entry point uses the same trust
        # boundary (H2: ``resolve_safe_audit_log_path`` constrains the path
        # to ``~/.khaos/audit/`` with O_NOFOLLOW + owner/mode checks).
        if audit_logger is None and effective_policy.audit_enabled:
            audit_logger = AuditLogger(
                cfg.db,
                log_path=resolve_safe_audit_log_path(
                    effective_policy.audit_log_path
                ),
            )
        scheduler = ToolScheduler(
            registry, permission_engine,
            security_middleware=SecurityMiddleware(
                sandbox=sandbox,
                network_guard=network_guard,
                audit_logger=audit_logger,
                effective_policy=effective_policy,
            ),
            # H5: the runtime_id identifies this runtime to the
            # BrowserManager so two concurrent local sessions under the
            # same UID get independent BrowserContexts.  The broker uses
            # it (together with session_id + principal_id) to key the
            # per-session context.
            runtime_id=cfg.runtime_id,
        )
    scheduler.set_office_authority(office_authority)
    # B1: register the authority on the scheduler only (instance attribute).
    # The previous module-global ``file_tools._office_authority`` was removed
    # — direct callers must pass ``office_authority`` explicitly or fall back
    # to the legacy unfenced path (only safe for trusted inputs in tests).
    compressor = ContextCompressor(router, memory_manager=memory_manager)
    verify_factory = VerifyFixLoop
    skill_generator = SkillGenerator()
    loop = AgentLoop(
        cfg.agent_config or AgentConfig(), mode_manager, router, cfg.db,
        tool_scheduler=scheduler, confirm_callback=cfg.confirm_callback,
        context_compressor=compressor, memory_manager=memory_manager,
        error_handler=ErrorHandler(db=cfg.db, router=router, compressor=compressor),
        token_engine=get_token_engine(),
        skill_manager=skill_manager if len(skill_manager.registry) else None,
        verify_fix_factory=verify_factory,
        task_manager=task_manager,
        skill_generator=skill_generator, project_root=root,
        coding_context_builder=cfg.coding_context_builder,
        workspace_manager=workspace_manager,
        execution_service=execution_service,
        approval_broker=cfg.approval_broker,
        principal_id=cfg.principal_id,
        # H5: carry the runtime_id + session_id into the AgentLoop so the
        # tool_context it builds for the broker includes them — the broker
        # injects them into browser tools so two concurrent sessions get
        # independent BrowserContexts (closing one runtime's context does
        # NOT close a concurrent runtime's page).
        runtime_id=cfg.runtime_id,
        session_id=cfg.session_id,
    )
    return RuntimeResult(
        loop=loop,
        mode_manager=mode_manager,
        task_manager=task_manager,
        skill_generator=skill_generator,
        tool_scheduler=scheduler,
        memory_manager=memory_manager,
        skill_manager=skill_manager,
        new_verify_fix_loop=verify_factory,
        execution_service=execution_service,
        office_authority=office_authority,
        owns_office_authority=owns_office_authority,
        principal_id=cfg.principal_id,
        # H5: carry session_id + runtime_id so ``aclose`` can release the
        # per-session BrowserContext keyed by (principal, session, runtime).
        session_id=cfg.session_id,
        runtime_id=cfg.runtime_id,
        # H2: carry the AuditLogger so ``aclose`` can close its fd —
        # without this, configuring a file audit path would leak the fd
        # for the process's lifetime.
        audit_logger=audit_logger,
        owns_audit_logger=owns_audit_logger,
    )


# ──────────────────────── H3: orphan-cleanup registry ────────────────────────
#
# H3: when a runtime's ``aclose()`` exhausts its 3 auto-retries and raises
# ``RuntimeCloseError``, the production caller (AgentService / SubAgentRunner)
# is expected to catch the exception and call ``register_orphan_runtime``
# so the runtime's component references are not silently leaked.  The
# registry is a module-level list — ``cleanup_orphan_runtimes`` iterates it
# and retries ``aclose()`` on each orphan, removing the ones that succeed.
# This closes the gap where a persistently-failing runtime's resources
# (file descriptors, Office mutation fences, BrowserContexts) were lost
# because the caller discarded the runtime reference after the exception.

_orphan_runtimes: list[RuntimeResult] = []


def register_orphan_runtime(runtime: RuntimeResult) -> None:
    """Register a runtime whose ``aclose()`` failed as an orphan.

    H3: production callers should call this in the ``except`` clause
    when ``RuntimeCloseError`` is raised from ``runtime.aclose()`` so the
    runtime's component references are retained for a later retry via
    ``cleanup_orphan_runtimes()``.  Without this, the runtime's file
    descriptors / Office mutation fences / BrowserContexts would be
    silently leaked because the caller discarded the reference.

    Idempotent: registering the same runtime twice is a no-op (the
    registry deduplicates by identity).
    """
    runtime.quarantined = True
    for existing in _orphan_runtimes:
        if existing is runtime:
            return
    _orphan_runtimes.append(runtime)


async def cleanup_orphan_runtimes() -> int:
    """Retry ``aclose()`` on every registered orphan; remove the ones
    that succeed.

    H3: iterates ``_orphan_runtimes``, resets ``_close_failed`` /
    ``_close_task`` on each orphan (so it gets a FRESH 3-attempt
    auto-retry cycle — ``aclose()`` returns immediately when
    ``_close_failed`` is True to prevent concurrent callers from
    re-running the retries, see H4), then calls ``aclose()``.  Orphans
    that succeed (``_closed`` becomes True) are removed; orphans that
    raise ``RuntimeCloseError`` again are kept for a future retry.

    Returns the count of remaining orphans.
    """
    remaining: list[RuntimeResult] = []
    for runtime in _orphan_runtimes:
        # H4: reset the exhaustion flag so the orphan gets a fresh
        # 3-attempt auto-retry cycle.  ``aclose()`` returns immediately
        # when ``_close_failed`` is True (to prevent concurrent callers
        # from re-running the retries), so we MUST clear it here.
        runtime._close_failed = False
        runtime._close_task = None
        try:
            await runtime.aclose()
        except RuntimeCloseError:
            # Still failing — keep the orphan for a future retry.
            remaining.append(runtime)
            continue
        if not runtime._closed:
            # aclose returned without raising but didn't close (defensive
            # — shouldn't happen after the reset above, but keep the
            # orphan so a future retry can pick it up).
            remaining.append(runtime)
        else:
            runtime.quarantined = False
    _orphan_runtimes[:] = remaining
    return len(_orphan_runtimes)


async def close_runtime_or_register(runtime: RuntimeResult) -> None:
    """Close a production-owned runtime and retain persistent failures.

    Every runtime owner must use this helper instead of calling ``aclose``
    directly.  A failed close is registered before the exception escapes, so
    request teardown cannot discard the only references to live resources.
    """
    cancellation_requested = False
    while True:
        try:
            await runtime.aclose()
            break
        except asyncio.CancelledError:
            # ``RuntimeResult.aclose`` shields its inner close task, but a
            # cancelled owner used to leave immediately.  If that inner task
            # then failed, nobody completed the retry loop or retained the
            # runtime.  Temporarily consume this task's cancellation, finish
            # cleanup (or quarantine), then restore cancellation below.
            cancellation_requested = True
            current = asyncio.current_task()
            if current is not None and hasattr(current, "uncancel"):
                current.uncancel()
            continue
        except RuntimeCloseError:
            register_orphan_runtime(runtime)
            logger.error(
                "runtime cleanup failed; quarantined for bounded shutdown retry: "
                "principal=%s session=%s runtime=%s",
                runtime.principal_id,
                runtime.session_id,
                runtime.runtime_id,
            )
            if cancellation_requested:
                raise asyncio.CancelledError
            raise
    if not runtime._closed:
        register_orphan_runtime(runtime)
        logger.error(
            "runtime cleanup returned without terminal state; quarantined: "
            "principal=%s session=%s runtime=%s",
            runtime.principal_id,
            runtime.session_id,
            runtime.runtime_id,
        )
    if cancellation_requested:
        raise asyncio.CancelledError


async def drain_orphan_runtimes(
    *, timeout_seconds: float = 5.0, retry_interval: float = 0.05,
) -> int:
    """Retry quarantined runtimes until empty or a bounded deadline.

    Returns the remaining count.  The caller must surface a non-zero result;
    this function never silently drops a runtime that still owns resources.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + max(0.0, timeout_seconds)
    remaining = len(_orphan_runtimes)
    while remaining and loop.time() <= deadline:
        remaining = await cleanup_orphan_runtimes()
        if remaining and loop.time() < deadline:
            await asyncio.sleep(max(0.0, retry_interval))
    if remaining:
        logger.error(
            "%d quarantined runtime(s) remain after %.2fs shutdown deadline",
            remaining,
            timeout_seconds,
        )
    return remaining
