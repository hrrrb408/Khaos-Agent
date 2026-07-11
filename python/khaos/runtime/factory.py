"""Unified asynchronous runtime factory for every AgentLoop entry point."""

from __future__ import annotations

import logging
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
from khaos.coding.execution import BackendSelector, ExecutionService
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.rust_bridge import get_token_engine
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_guard import NetworkGuard
from khaos.security.policy import load_policy
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
    _closed: bool = False
    execution_service: ExecutionService | None = None

    async def aclose(self) -> None:
        """Release runtime-owned resources; database ownership stays with caller."""
        if self._closed:
            return
        self._closed = True
        if self.memory_manager is not None:
            close = getattr(self.memory_manager, "aclose", None)
            if close is not None:
                try:
                    await close()
                except Exception:
                    logger.debug("memory manager close failed", exc_info=True)
        if self.execution_service is not None:
            try:
                await self.execution_service.shutdown()
            except Exception:
                logger.debug("execution service close failed", exc_info=True)


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
    permission_engine = PermissionEngine(cfg.db)
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
    execution_service = cfg.execution_service or ExecutionService(BackendSelector().select(writable=False), workspace_manager)
    policy = load_policy(root / "khaos_policy.yaml")
    sandbox = cfg.sandbox or Sandbox.from_policy_mode(policy.mode, root)
    network_guard = cfg.network_guard or NetworkGuard(
        network_enabled=policy.network_enabled,
        allowed_domains=policy.network_allowed_domains,
        blocked_domains=policy.network_blocked_domains,
    )
    scheduler = cfg.tool_scheduler or ToolScheduler(
        create_runtime_registry(), permission_engine,
        security_middleware=SecurityMiddleware(
            policy=policy, sandbox=sandbox, network_guard=network_guard,
            audit_logger=cfg.audit_logger,
        ),
    )
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
    )
    return RuntimeResult(loop, mode_manager, task_manager, skill_generator, scheduler, memory_manager, skill_manager, verify_factory, execution_service)
