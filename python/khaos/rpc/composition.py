"""Composition helpers for the Python RPC application boundary.

This module builds optional subagent services and owns router configuration
loading. It deliberately does not own transport framing or request dispatch.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.db import Database
from khaos.routing import ModelRouter
from khaos.routing.router import create_default_router
from khaos.rust_bridge import get_token_engine
from khaos.skills import SkillManager
from khaos.subagents import (
    SubAgentConfig,
    SubAgentRunner,
    SubAgentService,
    SubAgentSpawner,
)
from khaos.tools import create_runtime_registry

logger = logging.getLogger(__name__)


async def _build_subagent_service(
    db: Database,
    project_root: Path | None,
    config_path: Path | None,
    *,
    office_authority: OfficeMutationAuthority | None = None,
    approval_broker: Any = None,
    audit_logger: Any = None,
    cleanup_authority: Any = None,
) -> SubAgentService:
    """Build the SubAgent service bound to the server's shared security stack.

    B1: previously this function constructed a *bare* ``ToolScheduler(
    create_runtime_registry(), permission_engine)`` with no
    ``SecurityMiddleware`` — so the subagent ran on a parallel, unsupervised
    execution path that bypassed EffectivePolicy / Sandbox / NetworkGuard /
    AuditLogger.  Now the runner receives ``tool_scheduler=None`` and
    ``build_runtime`` constructs a fresh scheduler per run with the full
    security stack compiled from the same layered effective policy as the
    main AgentLoop.  The server-level ``approval_broker`` /
    ``audit_logger`` / ``office_authority`` are inherited so approvals,
    audit events and the Office storage baseline are shared with the main
    runtime, not forked.

    C-1-5b: the server-level ``ModeManager(local-uid)`` /
    ``MemoryStore(local-uid)`` / ``MemoryManager`` singletons are REMOVED.
    Previously they were bound to ``principal_id=f"local-uid:{os.getuid()}"``
    and passed to ``SubAgentRunner``, which forwarded them to
    ``RuntimeConfig`` — so ``build_runtime`` reused the local-uid-bound
    instances instead of constructing per-turn ones scoped to
    ``task.principal_id``.  Now ``SubAgentRunner`` receives ``None`` for
    both, and ``build_runtime`` constructs a per-turn ``ModeManager`` +
    ``MemoryManager`` from ``cfg.principal_id`` (= ``task.principal_id``,
    set from the authenticated RPC payload).  This guarantees the
    subagent's mode switches / memory scope are bound to the CALLING
    principal, not the server's local UID.
    """
    root = project_root or Path.cwd()
    resolved_config = config_path or root / "config.yaml"
    router = load_router_from_config(resolved_config, project_root=root)
    skill_manager = SkillManager()
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        skill_manager.load_from_dir(skills_dir)
    runner = SubAgentRunner(
        router=router,
        db=db,
        # C-1-5b: do NOT pass server-level ModeManager / MemoryManager —
        # let ``build_runtime`` construct per-turn instances from
        # ``cfg.principal_id`` (= ``task.principal_id``).  Previously
        # these were bound to ``local-uid`` and reused across every
        # subagent run, so an API principal's subagent saw the local
        # user's mode state and memories.
        mode_manager=None,
        # B1: do NOT pass a bare ToolScheduler — let build_runtime construct
        # one per run with the full SecurityMiddleware stack and a registry
        # pruned to ``task.tools``.
        tool_scheduler=None,
        memory_manager=None,
        skill_manager=skill_manager if len(skill_manager.registry) > 0 else None,
        token_engine=get_token_engine(),
        office_authority=office_authority,
        approval_broker=approval_broker,
        # C-1-5b: no server-level principal_id — the runner relies on
        # ``task.principal_id`` (set from ``ctx.principal_id`` by
        # ``SubAgentService.handle_spawn``) and ``build_runtime``'s
        # fail-closed gate on empty principal_id.
        principal_id="",
        audit_logger=audit_logger,
        cleanup_authority=cleanup_authority,
        # B1: inherit the server's project_root / config_path so the subagent
        # loads the SAME ``khaos_policy.yaml`` and compiles the SAME
        # EffectivePolicy as the main AgentLoop — no second security
        # authority rooted at the process cwd.
        project_root=root,
        config_path=resolved_config,
    )
    spawner = SubAgentSpawner(
        SubAgentConfig(max_concurrent=3, max_spawn_depth=1, allow_nesting=False),
        db,
        runner=runner.run,
        registry=create_runtime_registry(),
    )
    # M6.9 BATCH 4: production spawns receive authority-owned narrow child
    # delegations when an authority daemon is deployed.  Without one the
    # issuer stays absent and children run with a fresh transport-root
    # commitment instead of the parent's digest — never a silent
    # parent-digest reuse.
    delegation_issuer = None
    authority_socket = os.environ.get("KHAOS_AUTHORITYD_SOCKET") or os.environ.get(
        "KHAOS_AUTHORITYD_BACKEND_SOCKET", ""
    )
    if authority_socket and os.environ.get("KHAOS_DEV_MODE") != "1":
        try:
            from khaos.security.authorityd_protocol import AuthorityDaemonClient
            from khaos.security.delegation_issuer import AuthorityDelegationIssuer
            from khaos.security.identity_isolation import (
                read_contract_from_environment,
            )

            contract = read_contract_from_environment()
            delegation_issuer = AuthorityDelegationIssuer(
                AuthorityDaemonClient(
                    Path(authority_socket),
                    expected_authority_uid=contract.authority_uid,
                )
            )
        except (OSError, PermissionError, ValueError) as exc:
            logger.warning("subagent delegation issuer unavailable: %s", exc)
            delegation_issuer = None
    return SubAgentService(spawner, runner, delegation_issuer=delegation_issuer)


async def _handle_optional_subagent(
    subagent_service: SubAgentService | None,
    action: str,
    ctx: RequestContext,
    payload: dict,
) -> dict:
    """Dispatch a SubAgent RPC action with the transport ``ctx``.

    M4 batch 3.1.16A-4-2: ``ctx`` is passed directly to the SubAgent
    handler — no longer stamped onto the payload.  The SubAgentService
    reads ``ctx.principal_id`` directly, so a compromised Gateway that
    sends ``principal_id: 'admin'`` in the payload cannot win.
    """
    if subagent_service is None:
        return {"ok": False, "error": "subagents not enabled"}
    if action == "spawn":
        return await subagent_service.handle_spawn(ctx, payload)
    if action == "collect":
        return await subagent_service.handle_collect(ctx, payload)
    if action == "status":
        return await subagent_service.handle_status(ctx, payload)
    return {"ok": False, "error": "unknown subagent action"}


def load_router_from_config(config_path: Path, project_root: Path | None = None) -> ModelRouter:
    """Load model router, merging user config for the project template path."""
    expanded_config = config_path.expanduser()
    if not expanded_config.exists():
        return create_default_router(str(expanded_config), honor_no_config=False)
    root = project_root or Path.cwd()
    project_config = (root / "config.yaml").resolve()
    resolved_config = expanded_config.resolve()
    if resolved_config == project_config:
        return create_default_router(
            honor_no_config=False,
            project_root=root,
        )
    return create_default_router(str(expanded_config), honor_no_config=False)


__all__ = ["_build_subagent_service", "_handle_optional_subagent", "load_router_from_config"]
