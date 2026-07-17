"""Unified asynchronous runtime factory for every AgentLoop entry point."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.audit import AuditLogger
from khaos.coding.task_manager import TaskManager
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.coding.execution import BackendSelector, ExecutionService
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
    # B1: ``init=False`` so positional construction can never accidentally
    # bind a real component into ``_closed`` (which previously made
    # ``aclose()`` a no-op because the truthy component short-circuited it).
    # H3: ``_closing`` prevents concurrent invocation; ``_closed`` is set
    # only after every safety-critical component has reached a terminal
    # state, so a cancelled aclose can be retried by the caller.
    _closing: bool = field(default=False, init=False)
    _closed: bool = field(default=False, init=False)

    async def aclose(self) -> None:
        """Release runtime-owned resources; database ownership stays with caller.

        H3: uses ``_closing`` + ``_closed`` so a cancelled cleanup can be
        retried.  ``_closed`` is set ONLY at the end — if we are cancelled
        mid-cleanup (e.g. event-loop shutdown), ``_closed`` stays False and
        ``_closing`` resets in the ``finally`` block, so the caller can call
        ``aclose`` again to finish the remaining steps.  Each component's
        shutdown is expected to be idempotent.
        """
        if self._closed or self._closing:
            return
        self._closing = True
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
                    logger.debug(
                        "office authority shutdown failed", exc_info=True
                    )
            if self.memory_manager is not None:
                close = getattr(self.memory_manager, "aclose", None)
                if close is not None:
                    try:
                        await close()
                    except Exception:
                        logger.debug(
                            "memory manager close failed", exc_info=True
                        )
            if self.execution_service is not None:
                try:
                    await self.execution_service.shutdown()
                except Exception:
                    logger.debug(
                        "execution service close failed", exc_info=True
                    )
            # H3: only mark closed after all safety-critical components have
            # reached a terminal state.  A cancelled aclose leaves _closed
            # False so the caller can retry.
            self._closed = True
        finally:
            self._closing = False


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
            allowed_domains=list(effective_policy.network_allowed_domains),
            blocked_domains=list(effective_policy.network_blocked_domains),
        )
    scheduler = cfg.tool_scheduler or ToolScheduler(
        create_runtime_registry(), permission_engine,
        security_middleware=SecurityMiddleware(
            sandbox=sandbox,
            network_guard=network_guard,
            audit_logger=cfg.audit_logger,
            effective_policy=effective_policy,
        ),
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
    )
