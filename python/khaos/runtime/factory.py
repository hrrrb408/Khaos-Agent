"""Unified asynchronous runtime factory for every AgentLoop entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import Any

from khaos.agent import AgentConfig, AgentLoop
from khaos.agent.compressor import ContextCompressor
from khaos.agent.error_handler import ErrorHandler
from khaos.audit import (
    AuditLogger,
    resolve_safe_audit_anchor_path,
    resolve_safe_audit_log_path,
)
from khaos.coding.execution import BackendSelector, ExecutionService
from khaos.coding.task_manager import TaskManager
from khaos.coding.verify_fix import VerifyFixLoop
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.db.state_root import project_id as compute_project_id
from khaos.exceptions import RuntimeCloseError
from khaos.memory import MemoryBudget, MemoryManager, MemoryStore
from khaos.modes import ModeManager
from khaos.permissions import PermissionEngine
from khaos.routing.router import create_default_router
from khaos.runtime.authority import RuntimeAuthoritySeal, is_production_mode
from khaos.runtime.lifecycle import CloseState
from khaos.rust_bridge import get_token_engine
from khaos.security.credential_broker import CredentialBroker
from khaos.security.effective_policy import EffectiveSecurityPolicy
from khaos.security.middleware import SecurityMiddleware
from khaos.security.network_broker import NetworkBrokerFactory
from khaos.security.network_guard import NetworkGuard
from khaos.security.resource_scope import ResourceScopeError, TypedResourcePartialOrder
from khaos.security.sandbox import Sandbox
from khaos.skills import SkillGenerator, SkillManager
from khaos.tools import create_runtime_registry
from khaos.tools.scheduler import ToolScheduler

logger = logging.getLogger(__name__)


class RuntimeCleanupAuthority:
    """Server-scoped owner of runtimes that failed terminal cleanup."""

    def __init__(self) -> None:
        self._runtimes: list[RuntimeResult] = []

    @property
    def count(self) -> int:
        """Return the number of quarantined runtimes retained by this owner."""
        return len(self._runtimes)

    def contains(self, runtime: RuntimeResult) -> bool:
        """Return whether this exact runtime is retained."""
        return any(existing is runtime for existing in self._runtimes)

    def register(self, runtime: RuntimeResult) -> None:
        """Retain one failed runtime for bounded retry, idempotently."""
        runtime.quarantined = True
        if not self.contains(runtime):
            self._runtimes.append(runtime)

    async def cleanup(self) -> int:
        """Retry every retained runtime once and return the remaining count."""
        remaining: list[RuntimeResult] = []
        for runtime in self._runtimes:
            # P2-1: reset the typed terminal state so a QUARANTINED runtime
            # can be retried.  Without this reset, ``aclose()`` would
            # re-raise the recorded error forever (the quarantine
            # re-raise in the fast path) and the runtime could never
            # recover even if the failing component is now available.
            runtime._close_failed = False
            runtime._close_task = None
            runtime._close_state = CloseState.OPEN
            runtime._close_error = None
            try:
                await runtime.aclose()
            except RuntimeCloseError:
                remaining.append(runtime)
                continue
            if not runtime._closed:
                remaining.append(runtime)
            else:
                runtime.quarantined = False
        self._runtimes = remaining
        return len(self._runtimes)

    async def drain(
        self, *, timeout_seconds: float = 5.0,
        retry_interval: float = 0.05,
    ) -> int:
        """Retry retained runtimes until empty or the bounded deadline."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout_seconds)
        remaining = len(self._runtimes)
        while remaining and loop.time() <= deadline:
            remaining = await self.cleanup()
            if remaining and loop.time() < deadline:
                await asyncio.sleep(max(0.0, retry_interval))
        if remaining:
            logger.error(
                "%d quarantined runtime(s) remain after %.2fs shutdown deadline",
                remaining,
                timeout_seconds,
            )
        return remaining


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
    browser_manager: Any = None
    cleanup_authority: RuntimeCleanupAuthority | None = None
    approval_broker: Any = None
    # B1: an externally-owned OfficeMutationAuthority (e.g. the server-level
    # authority shared across every chat / webhook / cron turn) can be
    # injected here.  When set, ``build_runtime`` reuses it instead of
    # creating a new one, so the aggregate storage baseline persists across
    # turns (closing the cross-turn quota bypass) and the lifecycle is owned
    # by the caller — ``RuntimeResult.aclose`` will NOT shut it down.
    office_authority: OfficeMutationAuthority | None = None
    credential_broker: CredentialBroker | None = None
    # C-1-5a: ``principal_id`` is REQUIRED — no implicit local-uid
    # fallback.  CLI/TUI callers explicitly pass
    # ``f"local-uid:{os.getuid()}"`` (the OS user identity is the
    # correct principal for single-user local scenarios).  RPC paths
    # pass the authenticated principal from ``RequestContext``.  If
    # a caller forgets to set it, ``build_runtime`` raises ValueError
    # (fail-closed) instead of silently running as the local OS user.
    principal_id: str = ""
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""
    source_transport: str = "unknown"
    foreground_session: bool = False
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
    # M4 batch 3.1.16A-4-4-3: the server-lifecycle ChannelRegistry and
    # the admin principal allowlist compiled into the immutable
    # EffectiveSecurityPolicy.  Populated by ``AgentService._build_runtime``
    # (production) so the four channel tools receive them via the
    # ``channel.read`` / ``channel.manage`` broker injection.  ``None``
    # (the default for ad-hoc / test runtimes) means the channel tools
    # fail-closed — ``channel_list`` / ``channel_health`` return
    # ``unavailable``, ``channel_enable`` / ``channel_disable`` return
    # ``forbidden``.
    channel_registry: Any = None
    channel_admins: frozenset[str] = field(default_factory=frozenset)
    cron_engine: Any = None
    subagent_spawner: Any = None
    # M4 batch 3.1.16A-5-1b (CRITICAL): project identity closure.  When
    # set (non-empty), ``build_runtime`` uses this value as the project
    # identity for every component (PermissionEngine, MemoryStore,
    # AuditLogger, TaskManager, AgentLoop) instead of recomputing it
    # from ``project_root``.  The RPC dispatcher verifies this matches
    # ``agent._bound_project_id`` and rejects drift (fail-closed).
    # Default ``''`` (CLI / tests) falls back to
    # ``compute_project_id(root)`` for backward compat.
    project_id: str = ""


@dataclass(frozen=True)
class ProductionRuntimeConfig:
    """Production-safe runtime input with no injectable security owners.

    The legacy :class:`RuntimeConfig` remains available for tests and trusted
    development adapters, where injected mocks are useful.  Production entry
    points should construct this type instead.  It intentionally has no
    ``tool_scheduler``, ``execution_service``, ``sandbox``, ``network_guard``,
    ``memory_manager``, ``browser_manager``, or ``workspace_manager`` fields;
    the factory must construct those owners from the effective policy.
    Borrowed lifecycle authorities (audit, approval, Office, and cleanup) are
    explicit because their ownership is validated separately by the factory.
    """

    project_root: Path = field(default_factory=Path.cwd)
    config_path: Path | None = None
    mode_override: str | None = None
    confirm_callback: Any = None
    db: Any = None
    router: Any = None
    mode_manager: ModeManager | None = None
    audit_logger: AuditLogger | None = None
    task_manager: TaskManager | None = None
    coding_context_builder: Any = None
    agent_config: AgentConfig | None = None
    skill_manager: SkillManager | None = None
    cleanup_authority: RuntimeCleanupAuthority | None = None
    approval_broker: Any = None
    office_authority: OfficeMutationAuthority | None = None
    credential_broker: CredentialBroker | None = None
    principal_id: str = ""
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""
    source_transport: str = "unknown"
    foreground_session: bool = False
    session_id: str = ""
    runtime_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    tool_allowlist: list[str] | None = None
    channel_registry: Any = None
    channel_admins: frozenset[str] = field(default_factory=frozenset)
    cron_engine: Any = None
    subagent_spawner: Any = None
    project_id: str = ""

    def as_runtime_config(self) -> RuntimeConfig:
        """Materialize the internal config after the structural boundary."""
        return RuntimeConfig(
            project_root=self.project_root,
            config_path=self.config_path,
            mode_override=self.mode_override,
            confirm_callback=self.confirm_callback,
            db=self.db,
            router=self.router,
            mode_manager=self.mode_manager,
            audit_logger=self.audit_logger,
            task_manager=self.task_manager,
            coding_context_builder=self.coding_context_builder,
            agent_config=self.agent_config,
            skill_manager=self.skill_manager,
            cleanup_authority=self.cleanup_authority,
            approval_broker=self.approval_broker,
            office_authority=self.office_authority,
            credential_broker=self.credential_broker,
            principal_id=self.principal_id,
            principal_kind=self.principal_kind,
            parent_principal_id=self.parent_principal_id,
            delegation_digest=self.delegation_digest,
            source_transport=self.source_transport,
            foreground_session=self.foreground_session,
            session_id=self.session_id,
            runtime_id=self.runtime_id,
            tool_allowlist=self.tool_allowlist,
            channel_registry=self.channel_registry,
            channel_admins=self.channel_admins,
            cron_engine=self.cron_engine,
            subagent_spawner=self.subagent_spawner,
            project_id=self.project_id,
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
    browser_manager: Any = None
    cleanup_authority: RuntimeCleanupAuthority = field(
        default_factory=RuntimeCleanupAuthority
    )
    # H3: the OfficeMutationAuthority is owned by the runtime so aclose()
    # can fence every in-flight Office mutation before the process exits.
    office_authority: OfficeMutationAuthority | None = None
    # B1: when False, ``office_authority`` was injected (shared) and aclose
    # must NOT shut it down — the owner (AgentService / SubAgentService)
    # manages its lifecycle.  Defaults to True for ad-hoc constructions.
    owns_office_authority: bool = True
    # Credential leases are runtime-owned by default.  A server may share a
    # preconfigured provider broker, in which case its lifecycle remains with
    # that server rather than one chat runtime.
    credential_broker: CredentialBroker | None = None
    owns_credential_broker: bool = True
    # H1: the principal that owns this runtime.  ``aclose`` uses it to
    # release the principal's per-session ``BrowserContext`` so cookies /
    # DOM / page state cannot leak into a subsequent run by a different
    # principal sharing the same process-wide ``BrowserManager``.
    # H5: ``session_id`` + ``runtime_id`` extend the context key so two
    # concurrent local sessions under the same UID get independent contexts
    # — closing one runtime's context does NOT close another's page.
    principal_id: str = ""
    principal_kind: str = ""
    parent_principal_id: str = ""
    delegation_digest: str = ""
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
    # P2-1 (close false-success): the typed terminal state machine.  The
    # legacy booleans ``_closed`` / ``_close_failed`` remain as backward-compat
    # property aliases below; new code reads ``close_state``.  ``OPEN`` means a
    # close has not yet been attempted; ``CLOSING`` means a close task is in
    # flight; ``CLOSED`` means every safety-critical component reached a
    # terminal state; ``QUARANTINED`` means a component failed terminally and
    # resources may still be live — a subsequent ``aclose()`` MUST re-raise
    # rather than silently return (Invariant E).
    _close_state: CloseState = field(init=False, default=CloseState.OPEN)
    # The typed error recorded when the runtime entered QUARANTINED, so every
    # later ``aclose()`` re-raises the SAME failure instead of an
    # information-free success.
    _close_error: Exception | None = field(default=None, init=False)
    # H4: serializes the aclose() retry logic so concurrent callers don't
    # each create a separate ``_close_task`` (which would run shutdown on
    # the same components multiple times concurrently).  ``init=False`` so
    # positional construction can never bind a component into it, and
    # ``default_factory`` so each RuntimeResult gets its own Lock without
    # being passed explicitly.
    _close_lock: asyncio.Lock = field(init=False, default_factory=asyncio.Lock)
    # P1-1: the authority seal minted by ``build_runtime`` binding this
    # runtime to (principal, project, policy_digest, runtime_id).
    # ``init=False`` so existing positional construction is unaffected;
    # ``build_runtime`` sets it via ``object.__setattr__`` after construction.
    # ``None`` for runtimes constructed directly in tests (no seal minted).
    authority_seal: RuntimeAuthoritySeal | None = field(init=False, default=None)
    # Built by the factory from the exact objects it just constructed.  This
    # is intentionally a data declaration, not a reflective graph scan; the
    # production composition verifier checks it against fixed live paths.
    composition_manifest: dict[str, object] | None = field(
        init=False, default=None
    )

    @property
    def close_state(self) -> CloseState:
        """Typed terminal state of this runtime's close lifecycle."""
        return self._close_state

    @property
    def close_error(self) -> Exception | None:
        """The typed failure when the runtime is quarantined, else None."""
        return self._close_error

    @property
    def admission_closed(self) -> bool:
        """Compatibility alias for the runtime generation fence."""
        return self.generation_admission_closed

    @property
    def generation_admission_closed(self) -> bool:
        """True once runtime teardown has been requested."""
        return self._close_state is not CloseState.OPEN

    @property
    def child_admission_closed(self) -> bool:
        """True once runtime teardown prevents child authority admission."""
        return self._close_state is not CloseState.OPEN

    @property
    def terminal_closed(self) -> bool:
        """True only after CLOSED plus every child owner proves terminal."""
        return (
            self._close_state is CloseState.CLOSED
            and self._closed
            and self._child_terminal_proofs_hold()
            and not self.owned_resources()
        )

    @property
    def is_quarantined(self) -> bool:
        """True when one or more runtime-owned resources remain unproven."""
        return self._close_state is CloseState.QUARANTINED

    def owned_resources(self) -> tuple[str, ...]:
        """Aggregate child-owner resources without hiding their references."""
        resources: list[str] = []
        runtime_state_closed = (
            self._close_state is CloseState.CLOSED and self._closed
        )
        for name, component in (
            ("execution_service", self.execution_service),
            ("browser_manager", self.browser_manager),
            (
                "credential_broker",
                self.credential_broker if self.owns_credential_broker else None,
            ),
            (
                "office_authority",
                self.office_authority if self.owns_office_authority else None,
            ),
        ):
            if component is None:
                continue
            owned = getattr(component, "owned_runtime_resources", None)
            if callable(owned):
                resources.extend(
                    f"{name}:{item}" for item in owned(self.runtime_id)
                )
                continue
            owned = getattr(component, "owned_resources", None)
            if callable(owned):
                resources.extend(f"{name}:{item}" for item in owned())
            elif not runtime_state_closed:
                resources.append(name)
        if not runtime_state_closed and not resources:
            resources.append("runtime")
        return tuple(resources)

    def terminal_postcondition(self) -> bool:
        """Require CLOSED plus terminal child-owner proofs."""
        if not self.terminal_closed:
            return False
        return not self.owned_resources()

    def _child_terminal_proofs_hold(self) -> bool:
        """Verify every runtime-owned child exposes an independent proof."""
        for name, component in (
            ("execution_service", self.execution_service),
            ("browser_manager", self.browser_manager),
            (
                "credential_broker",
                self.credential_broker if self.owns_credential_broker else None,
            ),
            (
                "office_authority",
                self.office_authority if self.owns_office_authority else None,
            ),
        ):
            if component is None:
                continue
            proof = getattr(component, "terminal_postcondition", None)
            terminal = getattr(component, "terminal_closed", None)
            owned = getattr(component, "owned_resources", None)
            if not callable(proof) or not callable(owned):
                logger.error("runtime child %s has no complete terminal proof API", name)
                return False
            if not bool(terminal) or not bool(proof()) or tuple(owned()):
                logger.error("runtime child %s lacks terminal proof", name)
                return False
        return True

    def _with_seal(self, seal: RuntimeAuthoritySeal) -> RuntimeResult:
        """Stamp the authority seal minted by ``build_runtime`` and return self.

        The field is ``init=False`` so positional construction can never bind
        a fake seal; only the factory (which mints it) sets it here.
        """
        self.authority_seal = seal
        return self

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
        without re-running the retries. The runtime cleanup authority
        resets ``_close_failed`` before
        retrying so a persistently-failing runtime gets a fresh attempt
        cycle.

        H1: releases the principal's per-session ``BrowserContext`` so
        cookies / DOM / page state cannot leak into a subsequent run by
        a different principal after this runtime-owned BrowserManager closes.
        """
        import asyncio as _asyncio

        # Already fully closed — nothing to do (fast path, no lock).
        if self._closed:
            return
        # P2-1 (close false-success): a runtime that previously entered
        # QUARANTINED (a safety-critical component failed terminally after
        # exhausting retries) must NOT let a later ``aclose()`` caller
        # believe the close succeeded.  Re-raise the recorded typed error so
        # the caller observes the same failure as the original caller — the
        # server-scoped ``RuntimeCleanupAuthority`` is the only path that
        # resets the quarantine state to retry.
        if self._close_state is CloseState.QUARANTINED:
            raise self._close_error if self._close_error is not None else RuntimeCloseError(
                f"runtime is quarantined; safety-critical components may not "
                f"have reached a terminal state — principal={self.principal_id} "
                f"session={self.session_id} runtime={self.runtime_id}"
            )
        # H4: serialize the retry logic so concurrent callers don't each
        # create a separate ``_close_task``.  The lock is held for the
        # entire retry loop; other callers wait, then observe the terminal
        # state set by the first caller.
        async with self._close_lock:
            # Re-check _closed inside the lock — another caller may have
            # completed the close while we were waiting on the lock.
            if self._closed:
                return
            # P2-1: same quarantine re-raise as the fast path, but inside the
            # lock so a concurrent caller that waited on the lock also
            # observes the first caller's terminal failure (and does not
            # re-run the retries).  The cleanup authority is the only caller
            # that resets ``_close_state`` before retrying.
            if self._close_state is CloseState.QUARANTINED:
                raise self._close_error if self._close_error is not None else RuntimeCloseError(
                    f"runtime is quarantined; safety-critical components may "
                    f"not have reached a terminal state — "
                    f"principal={self.principal_id} session={self.session_id} "
                    f"runtime={self.runtime_id}"
                )
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
                # The caller's cancellation propagates while the shielded
                # cleanup task remains alive for a later ``aclose()`` retry.
                await _asyncio.shield(self._close_task)
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
                # P2-1: all retries exhausted — transition the runtime to the
                # QUARANTINED terminal state, record the typed error, and raise
                # so the caller observes the failure and can escalate through
                # the runtime's server-scoped cleanup authority.  The recorded
                # error is re-raised by every subsequent ``aclose()`` (see the
                # fast path above) so a quarantine can never masquerade as a
                # clean close to a later caller.
                if self._close_failed:
                    err = RuntimeCloseError(
                        f"runtime cleanup failed after {max_attempts} attempts; "
                        f"safety-critical components may not have reached a "
                        f"terminal state — principal={self.principal_id} "
                        f"session={self.session_id} runtime={self.runtime_id}"
                    )
                    self._close_state = CloseState.QUARANTINED
                    self._close_error = err
                    raise err
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
        # P2-1: mark the close as in-flight so observers can distinguish a
        # running cleanup from an idle runtime (CLOSING vs OPEN).
        self._close_state = CloseState.CLOSING
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
                    await self.tool_scheduler.aclose()
                except Exception:
                    failed = True
                    logger.debug(
                        "tool scheduler process authority close failed", exc_info=True
                    )
                try:
                    await self.execution_service.shutdown()
                except Exception:
                    failed = True
                    logger.debug(
                        "execution service close failed", exc_info=True
                    )
            # H1: the BrowserManager is runtime-owned, so closing the manager
            # releases every Context it acquired without consulting mutable
            # module-global state. A close failure is safety-critical: live
            # page state remains reachable, so the runtime enters the same
            # retry/quarantine path as other owned resources.
            if self.browser_manager is not None:
                try:
                    browser_result = await self.browser_manager.close()
                    if not browser_result.get("ok", False):
                        failed = True
                except Exception:
                    failed = True
                    logger.debug(
                        "browser runtime close failed for runtime %s",
                        self.runtime_id,
                        exc_info=True,
                    )
            if self.credential_broker is not None and self.owns_credential_broker:
                try:
                    close = getattr(self.credential_broker, "aclose", None)
                    if callable(close):
                        await close()
                    else:
                        self.credential_broker.close()
                except Exception:
                    failed = True
                    logger.debug("credential broker close failed", exc_info=True)
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
                # P2-1: a failed attempt is retryable, so revert to OPEN
                # (not QUARANTINED — the QUARANTINED terminal state is set
                # only by ``aclose`` after exhausting retries).  This keeps
                # the retry path working while ensuring the final
                # exhaustion transitions to QUARANTINED and re-raises on
                # every later call.
                self._close_state = CloseState.OPEN
                # Reset ``_close_task`` so a retry actually re-runs cleanup.
                self._close_task = None
                return
            if not self._child_terminal_proofs_hold():
                self._close_failed = True
                self._close_state = CloseState.OPEN
                self._close_task = None
                return
            # P2-1: every safety-critical component reached a terminal state
            # — transition to CLOSED (the only information-free success).
            self._closed = True
            self._close_state = CloseState.CLOSED
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


def _enforce_no_security_injection(cfg: RuntimeConfig) -> None:
    """Reject injected security-critical components in production mode.

    The forbidden set is derived from the structural production type rather
    than maintained as a manually updated deny-list.  Any field present on
    the legacy/test config but absent from ``ProductionRuntimeConfig`` is
    rejected automatically when non-empty.  Adding a new security owner
    therefore requires adding it to the production-safe type deliberately;
    forgetting to update a tuple cannot reopen this boundary.
    """
    production_fields = {
        field_info.name for field_info in dataclass_fields(ProductionRuntimeConfig)
    }
    for field_info in dataclass_fields(RuntimeConfig):
        field_name = field_info.name
        if field_name in production_fields:
            continue
        if getattr(cfg, field_name, None) is not None:
            raise PermissionError(
                f"production RuntimeConfig.{field_name} must not be injected "
                f"(a {field_name} built outside the factory cannot be proven "
                f"to carry the runtime authority seal; let build_runtime "
                f"construct it from the effective policy).  This injection "
                f"is permitted only in development/test mode "
                f"(KHAOS_DEV_MODE=1)."
            )


def _enforce_borrowed_authority_match(
    cfg: RuntimeConfig, seal: RuntimeAuthoritySeal
) -> None:
    """Best-effort authority match for the two borrowed components.

    The borrowed AuditLogger (server-shared audit trail) IS injected by
    production callers, so it is validated rather than rejected: if it
    exposes the binding fields, they must agree with this runtime's seal on
    principal/project/policy (a server-shared logger legitimately serves
    many runtimes under the SAME principal/project/policy, so runtime_id is
    not matched — it is per-turn).
    """
    if cfg.audit_logger is not None:
        injected_digest = getattr(cfg.audit_logger, "policy_digest", None)
        injected_principal = getattr(cfg.audit_logger, "principal_id", None)
        injected_project = getattr(cfg.audit_logger, "project_id", None)
        if injected_digest is not None and injected_digest != seal.policy_digest:
            raise PermissionError(
                "injected AuditLogger policy_digest does not match the "
                "runtime's effective policy digest — a server-shared logger "
                "must be built from the same compiled policy."
            )
        if injected_principal is not None and injected_principal != seal.principal_id:
            raise PermissionError(
                "injected AuditLogger principal_id does not match the "
                "runtime principal — cross-principal audit sharing is denied."
            )
        if injected_project is not None and injected_project != seal.project_id:
            raise PermissionError(
                "injected AuditLogger project_id does not match the "
                "runtime project — cross-project audit sharing is denied."
            )


def _load_production_resource_order(
    effective_policy: EffectiveSecurityPolicy,
) -> TypedResourcePartialOrder | None:
    """Load the host-reviewed typed catalog used by production authorities."""
    if not is_production_mode():
        return None
    catalog_path = os.environ.get("KHAOS_TYPED_RESOURCE_CATALOG_PATH")
    if not catalog_path:
        raise PermissionError(
            "production runtime requires KHAOS_TYPED_RESOURCE_CATALOG_PATH"
        )
    try:
        loaded = TypedResourcePartialOrder.from_json_file(
            Path(catalog_path),
            expected_policy_digest=effective_policy.digest,
        )
    except ResourceScopeError as exc:
        raise PermissionError(
            f"production typed resource catalog is invalid: {exc}"
        ) from exc
    compiled = effective_policy.resource_order
    if compiled is None or loaded.catalog_digest != compiled.catalog_digest:
        raise PermissionError(
            "production typed resource catalog does not match the effective policy"
        )
    return loaded


async def build_runtime(
    cfg: RuntimeConfig | ProductionRuntimeConfig,
) -> RuntimeResult:
    """Build and initialize a complete runtime; this is the sole loop factory."""
    structural_production_config = isinstance(cfg, ProductionRuntimeConfig)
    if isinstance(cfg, ProductionRuntimeConfig):
        cfg = cfg.as_runtime_config()
    if cfg.db is None:
        raise ValueError("RuntimeConfig.db is required")
    # C-1-5a: fail-closed if principal_id is empty.  CLI/TUI explicitly
    # pass ``f"local-uid:{os.getuid()}"``; RPC paths pass the
    # authenticated principal from ``RequestContext``.  An empty
    # principal_id here means a caller forgot to set it — running as
    # the local OS user would be a silent privilege escalation.
    if not cfg.principal_id:
        raise ValueError(
            "RuntimeConfig.principal_id is required (CLI/TUI pass "
            "f'local-uid:{os.getuid()}'; RPC paths pass ctx.principal_id)"
        )
    # M6.4: a production runtime must carry a concrete principal kind.  The
    # legacy ``unknown`` transport remains available only to explicit local
    # fixtures; it is not a production identity proof.
    from khaos.security.principals import (
        PrincipalDelegationError,
        principal_for_transport,
        principal_from_kind,
    )
    try:
        if cfg.principal_kind:
            principal_from_kind(cfg.principal_id, cfg.principal_kind)
        elif cfg.source_transport != "unknown":
            principal_for_transport(cfg.principal_id, cfg.source_transport)
        elif is_production_mode() and structural_production_config:
            raise PrincipalDelegationError(
                "production runtime requires a typed principal transport"
            )
    except (PrincipalDelegationError, ValueError) as exc:
        raise ValueError("runtime principal identity is invalid") from exc
    # P1-1 (production Runtime injection): reject injected security-critical
    # components BEFORE touching any subsystem.  In production mode the five
    # components below must be constructed by the factory (they then carry
    # the authority seal implicitly).  This early check avoids partially
    # initializing a runtime (e.g. loading the mode manager) only to reject
    # it.  The borrowed AuditLogger digest match runs later, after the
    # effective policy is loaded.
    if is_production_mode():
        _enforce_no_security_injection(cfg)
    root = cfg.project_root.expanduser().resolve()
    mode_manager = cfg.mode_manager or ModeManager(
        cfg.db, project_root=root,
        principal_id=cfg.principal_id, session_id=cfg.session_id,
        project_id=cfg.project_id,
    )
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
            # Production-safe behaviour is the default.  Mock routing is a
            # test/development fixture only, never an implicit result of a
            # missing KHAOS_ENV deployment variable.
            if os.environ.get("KHAOS_DEV_MODE") != "1":
                logger.error("runtime config router unavailable; refusing mock fallback")
                raise
            logger.warning("development runtime config router unavailable; using mock", exc_info=True)
            router = create_default_router()
    # B1: load and compile the *layered* effective policy — user (∼/.khaos/
    # policy.yaml) ∩ project (<repo>/khaos_policy.yaml) ∩ platform — so it is
    # the single source of truth that every runtime component is built from.
    # No component may consult the raw project policy for enforcement.
    from khaos.security.effective_policy import load_effective_policy
    effective_policy = load_effective_policy(root)
    logger.info("effective security policy digest: %s", effective_policy.digest)
    typed_resource_order = _load_production_resource_order(effective_policy)
    # A2-3: bind the PermissionEngine to (principal_id, project_id,
    # policy_digest, runtime_id).  Rules loaded, granted, or revoked
    # through this engine are scoped to that triple — a different
    # principal's rules are invisible.  ``project_id`` is the same
    # identifier used by the state root (sha256(realpath(root))[:32]),
    # so every runtime under the same project shares the project_id
    # but is isolated by principal_id.
    #
    # M4 batch 3.1.16A-5-1b: prefer ``cfg.project_id`` (RPC-verified)
    # over ``compute_project_id(root)`` so the dispatcher's drift
    # check is the sole authority.  CLI / tests that don't set
    # ``cfg.project_id`` fall back to recompute.
    project_id = cfg.project_id or compute_project_id(root)
    # P1-1 (production Runtime injection): mint the runtime's authority seal
    # — the unforgeable binding of (principal, project, policy_digest,
    # runtime_id) that every production-built security component must carry.
    # In production mode the factory refuses to install an injected
    # security-critical component below, closing the "second authority"
    # backdoor.  Dev/test mode (KHAOS_DEV_MODE=1) still injects mocks freely.
    production_mode = is_production_mode()
    authority_seal = RuntimeAuthoritySeal.mint(
        principal_id=cfg.principal_id,
        project_id=project_id,
        policy_digest=effective_policy.digest,
        runtime_id=cfg.runtime_id,
    )
    if production_mode:
        _enforce_borrowed_authority_match(cfg, authority_seal)
    credential_broker = cfg.credential_broker
    if credential_broker is None and cfg.tool_scheduler is not None:
        shared_broker = getattr(cfg.tool_scheduler, "credential_broker", None)
        if isinstance(shared_broker, CredentialBroker):
            credential_broker = shared_broker
    owns_credential_broker = credential_broker is None
    if credential_broker is None:
        credential_broker = CredentialBroker(
            policy_digest=effective_policy.digest,
            principal_id=cfg.principal_id,
            # Production accepts only provider loaders registered by a trusted
            # server adapter.  Development keeps the migration adapter available
            # for existing tests, but it is never enabled by the production type.
            allow_context_adoption=not production_mode,
        )
    credential_broker.bind_runtime(
        policy_digest=effective_policy.digest,
        principal_id=cfg.principal_id,
    )
    # Round-14 §7: derive the exec-tool name set from the live registry so
    # the commands_require_approval gate covers every exec-style tool
    # (permission_level == "execute"), not a hard-coded literal.  Built once
    # here and reused for the scheduler registry below.
    if cfg.tool_allowlist is not None:
        runtime_registry = create_runtime_registry().prune(cfg.tool_allowlist)
    else:
        runtime_registry = create_runtime_registry()
    exec_tool_names = runtime_registry.exec_tool_names()
    # Construct the shared audit repository before any component that can
    # emit audit events.  Permission and error paths must use this same
    # anchored writer; constructing it later allowed direct DB writers to
    # bypass the chain authority.
    audit_logger = cfg.audit_logger
    owns_audit_logger = audit_logger is None
    if audit_logger is None and effective_policy.audit_enabled:
        audit_logger = AuditLogger(
            cfg.db,
            log_path=resolve_safe_audit_log_path(effective_policy.audit_log_path),
            anchor_path=(
                resolve_safe_audit_anchor_path(project_id)
                if os.environ.get("KHAOS_DEV_MODE") != "1"
                else None
            ),
            principal_id=cfg.principal_id,
            runtime_id=cfg.runtime_id,
            policy_digest=effective_policy.digest,
            project_id=project_id,
        )
        await audit_logger.verify_anchor()
    permission_engine = PermissionEngine(
        cfg.db,
        commands_require_approval=effective_policy.commands_require_approval,
        principal_id=cfg.principal_id,
        project_id=project_id,
        policy_digest=effective_policy.digest,
        runtime_id=cfg.runtime_id,
        exec_tool_names=exec_tool_names,
        audit_logger=audit_logger,
    )
    await permission_engine.load_rules()
    memory_manager = cfg.memory_manager or MemoryManager(
        MemoryStore(cfg.db, principal_id=cfg.principal_id, project_id=project_id),
        budget=MemoryBudget(),
        mode_getter=lambda: mode_manager.current_mode,
        intent_getter=lambda: getattr(mode_manager, "_intent_buffer", ""),
    )
    skill_manager = cfg.skill_manager or SkillManager()
    skills_dir = root / "skills"
    if len(skill_manager.registry) == 0 and skills_dir.is_dir():
        skill_manager.load_from_dir(skills_dir)
    task_manager = cfg.task_manager
    if task_manager is None:
        # A3-5: bind the TaskManager to the runtime's principal so every
        # coding task is owned by exactly one principal for its entire
        # lifecycle.  An unauthenticated runtime (``principal_id='legacy'``)
        # can only see its own 'legacy' tasks (quarantined to
        # ``status='failed'`` by the migration helper), so it can never
        # execute or surface an authenticated principal's tasks.
        #
        # M4 batch 3.1.16A-5-1b: also stamp ``project_id`` so coding
        # tasks are project-scoped (see A-5-1a schema closure).
        task_manager = TaskManager(
            db=cfg.db, principal_id=cfg.principal_id,
            project_id=project_id,
        )
        await task_manager.load()
    workspace_manager = cfg.workspace_manager or WorkspaceManager(
        policy_digest=effective_policy.digest,
        authorization_epoch=await permission_engine.authorization_snapshot(),
        resource_order=typed_resource_order,
    )
    injected_workspace_policy = getattr(workspace_manager, "policy_digest", None)
    if (
        production_mode
        and injected_workspace_policy is not None
        and injected_workspace_policy != effective_policy.digest
    ):
        raise PermissionError(
            "WorkspaceManager authority policy digest does not match the "
            "runtime effective policy; host Git control-plane effects cannot "
            "borrow a different policy authority."
        )
    execution_service = cfg.execution_service or ExecutionService(
        workspace_manager=workspace_manager,
        backend_selector=BackendSelector(),
        principal_id=cfg.principal_id,
        project_id=project_id,
        runtime_id=cfg.runtime_id,
    )
    execution_service.bind_runtime_authority(
        principal_id=cfg.principal_id,
        project_id=project_id,
        runtime_id=cfg.runtime_id,
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
        # Round-14 §7: reuse the registry already built for exec_tool_names
        # derivation above, instead of constructing a second identical one.
        registry = runtime_registry
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
            network_broker_factory=NetworkBrokerFactory(
                resource_order=typed_resource_order,
            ),
            credential_broker=credential_broker,
        )
    if production_mode:
        scheduler_resource_order = getattr(
            getattr(scheduler, "network_broker_factory", None),
            "resource_order",
            None,
        )
        if (
            typed_resource_order is None
            or scheduler_resource_order is None
            or scheduler_resource_order.catalog_digest
            != typed_resource_order.catalog_digest
        ):
            raise PermissionError(
                "production ToolScheduler must use the effective typed resource catalog"
            )
    scheduler.set_office_authority(office_authority)
    scheduler.credential_broker = credential_broker
    if cfg.browser_manager is None:
        from khaos.tools.browser_tools import BrowserManager

        browser_manager = BrowserManager()
    else:
        browser_manager = cfg.browser_manager
    # B1: register the authority on the scheduler only (instance attribute).
    # The previous module-global ``file_tools._office_authority`` was removed
    # — direct callers must pass ``office_authority`` explicitly or fall back
    # to the legacy unfenced path (only safe for trusted inputs in tests).
    # M4 batch 3.1.16A-4-4-1 (CRITICAL): the principal-scoped
    # PermissionEngine + AuditLogger are no longer wired into module-
    # global holders (the old ``init_permission_tools`` call).  The five
    # permission tools now receive them per-call via the
    # ``permission.read`` / ``permission.manage`` broker injection from
    # ``tool_context`` (assembled by ``AgentLoop`` from
    # ``tool_scheduler.permission_engine`` and
    # ``tool_scheduler.security_middleware.audit_logger``).  This closes
    # the cross-principal race where concurrent ``build_runtime`` calls
    # overwrote each other's holder — see ``permission_tools.py``
    # docstring for the race description.
    compressor = ContextCompressor(router, memory_manager=memory_manager)
    verify_factory = VerifyFixLoop
    skill_generator = SkillGenerator()
    cleanup_authority = cfg.cleanup_authority or RuntimeCleanupAuthority()
    loop = AgentLoop(
        cfg.agent_config or AgentConfig(), mode_manager, router, cfg.db,
        tool_scheduler=scheduler, confirm_callback=cfg.confirm_callback,
        context_compressor=compressor, memory_manager=memory_manager,
        error_handler=ErrorHandler(
            db=cfg.db,
            router=router,
            compressor=compressor,
            principal_id=cfg.principal_id,
            project_id=project_id,
            audit_logger=audit_logger,
        ),
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
        principal_kind=cfg.principal_kind,
        parent_principal_id=cfg.parent_principal_id,
        delegation_digest=cfg.delegation_digest,
        source_transport=cfg.source_transport,
        foreground_session=cfg.foreground_session,
        # H5: carry the runtime_id + session_id into the AgentLoop so the
        # tool_context it builds for the broker includes them — the broker
        # injects them into browser tools so two concurrent sessions get
        # independent BrowserContexts (closing one runtime's context does
        # NOT close a concurrent runtime's page).
        runtime_id=cfg.runtime_id,
        session_id=cfg.session_id,
        # M4 batch 3.1.16A-4-4-3: carry the channel registry + admin
        # allowlist into the AgentLoop so ``tool_context`` exposes them
        # to the broker — the four channel tools read them via the
        # ``channel.read`` / ``channel.manage`` capability injection.
        channel_registry=cfg.channel_registry,
        channel_admins=cfg.channel_admins,
        cron_engine=cfg.cron_engine,
        browser_manager=browser_manager,
        subagent_spawner=cfg.subagent_spawner,
        credential_broker=credential_broker,
        # M4 batch 3.1.16A-5-1b (CRITICAL): carry the RPC-verified
        # project identity into the AgentLoop so every message / turn
        # write is stamped with it.  ``self._bound_project_id`` (set
        # from this kwarg) is the value the RPC dispatcher compares
        # against ``ctx.project_id`` for drift detection (fail-closed
        # rejection).
        project_id=project_id,
    )
    from khaos.security.production_composition_manifest import (
        build_construction_manifest,
    )

    composition_manifest = build_construction_manifest(
        {
            "tool_scheduler": scheduler,
            "security_middleware": scheduler.security_middleware,
            "sandbox_backend": sandbox,
            "network_guard": network_guard,
            "local_audit_logger": audit_logger,
            "execution_service": execution_service,
            "workspace_authority": workspace_manager,
            "office_mutation_authority": office_authority,
            "credential_broker": credential_broker,
            "network_broker": scheduler.network_broker_factory,
            "approval_broker": loop.approval_broker,
            "process_supervisor": execution_service.process_supervisor,
            "execution_backend_selector": execution_service.backend_selector,
            "verification_backend": verify_factory,
        }
    )
    runtime = RuntimeResult(
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
        credential_broker=credential_broker,
        owns_credential_broker=owns_credential_broker,
        principal_id=cfg.principal_id,
        principal_kind=cfg.principal_kind,
        parent_principal_id=cfg.parent_principal_id,
        delegation_digest=cfg.delegation_digest,
        # H5: carry session_id + runtime_id so ``aclose`` can release the
        # per-session BrowserContext keyed by (principal, session, runtime).
        session_id=cfg.session_id,
        runtime_id=cfg.runtime_id,
        browser_manager=browser_manager,
        cleanup_authority=cleanup_authority,
        # H2: carry the AuditLogger so ``aclose`` can close its fd —
        # without this, configuring a file audit path would leak the fd
        # for the process's lifetime.
        audit_logger=audit_logger,
        owns_audit_logger=owns_audit_logger,
        # P1-1: stamp the authority seal so callers can verify the runtime
        # was built under a known (principal, project, policy, runtime) tuple.
    )._with_seal(authority_seal)
    runtime.composition_manifest = composition_manifest
    return runtime


async def build_production_runtime(cfg: ProductionRuntimeConfig) -> RuntimeResult:
    """Build only from the structural production-safe configuration type.

    Keeping this entry point separate prevents production callers from
    accidentally widening their API back to injectable ``RuntimeConfig``
    while preserving ``build_runtime`` for explicit test/development adapters.
    """
    if not isinstance(cfg, ProductionRuntimeConfig):
        raise TypeError("build_production_runtime requires ProductionRuntimeConfig")
    # Production composition calls the factory defined in this module
    # directly.  A public-package monkeypatch/compatibility hook would make a
    # development builder reachable from the production root and would turn
    # the structural config type into a cosmetic boundary.
    return await build_runtime(cfg)


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
            runtime.cleanup_authority.register(runtime)
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
        runtime.cleanup_authority.register(runtime)
        logger.error(
            "runtime cleanup returned without terminal state; quarantined: "
            "principal=%s session=%s runtime=%s",
            runtime.principal_id,
            runtime.session_id,
            runtime.runtime_id,
        )
    if cancellation_requested:
        raise asyncio.CancelledError
