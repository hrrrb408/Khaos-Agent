"""Authenticated Agent RPC application service.

The service owns agent turns, channel/webhook handling, runtime construction,
and process-scoped authority shutdown. JSON framing, authentication, and socket
lifecycle remain in khaos.grpc_server.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import stat
import sys
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from khaos.agent.approval import ApprovalBroker
from khaos.audit import (
    AuditAnchorError,
    AuditLogger,
    resolve_safe_audit_anchor_path,
    resolve_safe_audit_log_path,
)
from khaos.channels import (
    ChannelRegistry,
    ChannelType,
    PlatformMessage,
    WebhookHandler,
    WebhookRateLimiter,
    WebhookReplayGuard,
)
from khaos.coding.workspace.office_authority import OfficeMutationAuthority
from khaos.db import Database
from khaos.db.database import SessionBusyError
from khaos.exceptions import ServiceShutdownError
from khaos.memory import MemoryEventBridge, RuntimeMemoryContext
from khaos.modes import ModeManager
from khaos.rpc.models import ChatRequest, ConfirmRequest
from khaos.runtime import RequestContext
from khaos.runtime.context import local_principal_id
from khaos.scheduler import CronEngine
from khaos.security.middleware import SecurityMiddleware

logger = logging.getLogger(__name__)

CHAT_DRAIN_TIMEOUT = 10.0
_CHAT_STREAM_LEASE_SECONDS = 300.0


def _message_to_event(message) -> dict:
    event = message.event or ("done" if message.content == "done" and message.role == "system" else "message")
    if event in {"tool_call", "permission_request", "tool_result", "error"}:
        data = message.metadata
    elif event == "done":
        data = {"total_tokens": message.token_count, "stop_reason": message.stop_reason}
    else:
        data = {"role": message.role, "content": message.content, "token_count": message.token_count}
    return {"event": event, "data": data}


class AgentService:
    """Agent RPC service backed by AgentLoop."""

    def __init__(self, db: Database, project_root: Path | None = None, config_path: Path | None = None, router=None, *, boot_id: str = ""):
        self.db = db
        self.project_root = project_root or Path.cwd()
        self.config_path = config_path or self.project_root / "config.yaml"
        self._router = router
        # Round-5 Batch 5.2 (C-05): per-process boot_id used to tag
        # chat_streams rows so recovery never recovers the current
        # process's own active streams.  Passed through to
        # ``append_chat_stream_event`` via the chat flow.
        self._boot_id = boot_id
        self.pending_confirmations: dict[str, dict] = {}
        self.approval_broker = ApprovalBroker(db=db)
        # Shared coding-task tracker so the TUI / TaskService can observe
        # long-running coding turns alongside the AgentLoop.
        # A3-6: bind the server-lifecycle TaskManager to the local-uid
        # principal (matching the server-lifecycle AuditLogger / MemoryService
        # above) so tasks created via the JSON-line RPC path are owned by
        # the local user and invisible to any other authenticated principal.
        # Per-turn runtimes constructed by ``build_runtime`` carry their own
        # principal-scoped TaskManager via ``RuntimeConfig.principal_id``.
        #
        # C-1-5a: the server-level ``TaskManager(local-uid)`` singleton
        # is REMOVED.  ``TaskService`` now holds ``db`` and constructs
        # per-principal ``TaskManager`` instances on demand (cached for
        # the process lifetime).  This allows API principals to
        # ``create`` / ``list`` / ``get`` / ``cancel`` their own tasks
        # (previously ``create`` was rejected and ``list``/``get``
        # returned empty for API principals).  ``_build_runtime`` no
        # longer passes a shared task_manager — ``build_runtime``
        # constructs a per-turn manager from ``cfg.principal_id``
        # (factory.py:502-517).
        # H2: compile the *layered* effective policy (user ∩ project ∩
        # platform) once at startup — never consult the raw project policy
        # for enforcement decisions.  An untrusted repo can no longer
        # silently disable audit by setting ``audit.enabled: false`` in
        # its ``khaos_policy.yaml``: the effective policy's ``audit_enabled``
        # uses OR semantics (if the user layer requires audit, the project
        # cannot disable it).
        from khaos.security.effective_policy import load_effective_policy
        self._effective_policy = load_effective_policy(self.project_root)
        logger.info(
            "effective security policy digest: %s (audit_enabled=%s)",
            self._effective_policy.digest,
            self._effective_policy.audit_enabled,
        )
        # M4 batch 3.1.16B-1 (CRITICAL): bind the CronEngine to the
        # effective policy digest + project_id so every scheduled task
        # captures the security-context snapshot at creation time.  B-2
        # will compare these against the live values at ``start()`` and
        # ``_execute_task`` claim time to detect policy/project drift.
        # ``project_id`` is derived from the project root via
        # ``state_root.project_id`` (sha256(realpath(root))[:32]).
        from khaos.db.state_root import project_id as _compute_project_id
        # M4 batch 3.1.16A-4-1: store as a member so the RPC dispatcher
        # can build RequestContext with the correct project_id without
        # recomputing it per request.
        self._bound_project_id = _compute_project_id(self.project_root)
        _bound_project_id = self._bound_project_id
        # H1: a single server-lifecycle AuditLogger shared by the main runtime
        # AND every SubAgent run, so security events from both paths land in
        # the same audit trail.  ``log_path`` comes from the effective policy
        # (user ∩ project, OR semantics — an untrusted project cannot disable
        # audit).  H2: ``resolve_safe_audit_log_path`` constrains the path
        # to a trusted directory so an untrusted project cannot point audit
        # at an arbitrary host file (symlink / FIFO / device attacks).
        # M4 batch 3.1.16B-3: constructed BEFORE CronEngine so it can be
        # injected into the engine for drift-quarantine audit logging.
        self._audit_logger = (
            AuditLogger(
                self.db,
                log_path=resolve_safe_audit_log_path(
                    self._effective_policy.audit_log_path
                ),
                anchor_path=(
                    resolve_safe_audit_anchor_path(_bound_project_id)
                    if os.environ.get("KHAOS_DEV_MODE") != "1"
                    else None
                ),
                # A2-6: bind the server-lifecycle AuditLogger to the
                # local-uid principal (matching MemoryService / ModeManager
                # above) and stamp the effective policy digest on every row
                # so audit attribution matches the runtime that produced it.
                # ``runtime_id`` is left None at the server level; per-runtime
                # AuditLoggers constructed by ``build_runtime`` carry it.
                principal_id=local_principal_id(),
                policy_digest=self._effective_policy.digest,
                # M4 batch 3.1.16A-5-1b: stamp the server-bound project
                # identity on every audit row.  The dispatcher's drift
                # check guarantees every RPC reaching a service method
                # has ``ctx.project_id == self._bound_project_id``, so
                # this is the canonical project identity for all server-
                # lifecycle audit events (webhook / cron / channel
                # mutations).  Per-runtime AuditLoggers constructed by
                # ``build_runtime`` get the same value via
                # ``RuntimeConfig.project_id``.
                project_id=_bound_project_id,
            )
            if self._effective_policy.audit_enabled
            else None
        )
        self.cron_engine = CronEngine(
            db=db,
            executor=self._execute_scheduled_prompt,
            project_id=_bound_project_id,
            policy_digest=self._effective_policy.digest,
            # M4 batch 3.1.16B-3: inject the server-lifecycle AuditLogger
            # so drift quarantine events land in the audit trail.
            audit_logger=self._audit_logger,
        )
        self.channel_registry = ChannelRegistry()
        self._webhook_replay_guard = WebhookReplayGuard(
            consumer=self.db.consume_webhook_event
        )
        self._verified_webhook_limiter = WebhookRateLimiter()
        # M4 batch 3.1.16A-4-4-3: the module-global ``set_channel_registry``
        # call has been removed.  The four channel tools now receive
        # ``channel_registry`` + ``principal_id`` (+ ``channel_admins`` for
        # mutations) per-call via the ``channel.read`` / ``channel.manage``
        # broker injection from ``tool_context`` (assembled by
        # ``AgentLoop`` from ``self.channel_registry`` and
        # ``self._effective_policy.channel_admins``).  See
        # ``channel_tools.py`` docstring for the cross-principal mutation
        # risk that the holder posed.
        # B1: the OfficeMutationAuthority is a server-lifecycle object shared
        # across every chat / webhook / cron turn.  Reusing one instance keeps
        # the aggregate storage baseline stable across turns (closing the
        # cross-turn quota bypass).  Per-turn runtimes borrow it (via
        # RuntimeConfig.office_authority); RuntimeResult.aclose does NOT close
        # it — AgentService.shutdown does.
        self._office_authority = OfficeMutationAuthority()
        self._accepting_work = True
        # Readiness is distinct from object construction: the process must
        # have verified its audit anchor and started the scheduler before the
        # Gateway may advertise that the AgentService can accept work.
        self._ready = False
        self._active_chat_tasks: set[asyncio.Task] = set()
        self._active_runtimes: dict[int, object] = {}
        # Round-6 Batch 6.1: track active sessions to reject concurrent
        # chat RPCs on the same session_id (Review §八 Strategy B: reject).
        # A second chat() on a session that already has an active stream
        # gets SessionBusyError instead of racing on shared state.
        self._active_chat_sessions: set[str] = set()
        self.subagent_spawner = None
        # One application-scoped MemoryHost is created during startup and
        # borrowed by every main turn, RPC memory service, and subagent.
        # RuntimeResult never owns this shared host; AgentService does.
        self.memory_host = None
        from khaos.runtime import RuntimeCleanupAuthority

        self.runtime_cleanup_authority = RuntimeCleanupAuthority()
        self._office_shutdown_task: asyncio.Task | None = None
        self.shutdown_failed = False
        # M4 batch 3.1.15 (CRITICAL-1): idempotency flag for shutdown().
        # Set to True only on clean completion.  Allows the outer
        # emergency-cleanup path to safely re-call shutdown() without
        # double-closing shared authorities.
        self._shutdown_completed = False
        # M2 (round-3): admission lock serialises ``chat``'s admission
        # decision + owner reservation against ``shutdown``'s
        # ``_accepting_work = False`` flip + owner snapshot.  Without it,
        # a chat that passed the accepting_work check could be mid-await
        # in ``_build_runtime`` while shutdown snapshotted an empty
        # ``_active_chat_tasks`` and proceeded to dismantle shared
        # authorities — the chat would then resume and register a runtime
        # after shutdown believed all owners were drained.  The JSON-line
        # server's connection-handler registry is an outer guard for the
        # production RPC path, but ``AgentService`` is also a direct
        # caller (cron / webhook) and its lifecycle contract must hold
        # independently.
        self._admission_lock = asyncio.Lock()

    async def start(self) -> None:
        """Start process-scoped background services."""
        self._ready = False
        if self._audit_logger is not None:
            await self._audit_logger.verify_anchor()
        from khaos.runtime import build_memory_host

        host = await build_memory_host(
            db=self.db,
            project_root=self.project_root,
            config_path=self.config_path,
            mode="office",
            principal_id=local_principal_id(),
            project_id=self._bound_project_id,
            audit_logger=self._audit_logger,
            effective_policy=self._effective_policy,
        )
        # C-1-5a: ``TaskService`` now lazily constructs per-principal
        # TaskManagers on first use (``_manager(ctx)``), so there's no
        # server-level ``task_manager.load()`` at startup.
        try:
            await self.cron_engine.start()
        except BaseException:
            await host.close()
            raise
        self.memory_host = host
        self._ready = True

    def _browser_helper_health(self) -> dict[str, Any]:
        """Check the privileged helper endpoint without performing a mutation.

        The helper protocol requires a live, runtime-scoped capability before
        ``status`` can be called.  A process-wide readiness probe does not
        possess such a capability and must never mint a dummy one.  This check
        therefore proves the protected socket endpoint is present and labels
        the remaining live-RPC assertion explicitly for the per-sandbox path.
        """
        required = sys.platform.startswith("linux") and os.environ.get(
            "KHAOS_DEV_MODE"
        ) != "1"
        socket_name = os.environ.get(
            "KHAOS_BROWSER_KERNEL_HELPER_SOCKET",
            "/run/khaos/browser-kernel-helper.sock",
        )
        result: dict[str, Any] = {
            "required": required,
            "configured": bool(socket_name),
            "socket_present": False,
            "socket_protected": False,
            "probe": "socket_authority_only",
            "live_rpc": False,
        }
        if not required:
            result["ready"] = True
            return result
        try:
            socket_path = Path(socket_name)
            if not socket_path.is_absolute():
                result["error"] = "relative_socket_path"
                result["ready"] = False
                return result
            metadata = socket_path.lstat()
            result["socket_present"] = stat.S_ISSOCK(metadata.st_mode)
            parent = socket_path.parent
            parent_metadata = parent.lstat()
            parent_protected = (
                stat.S_ISDIR(parent_metadata.st_mode)
                and parent_metadata.st_uid == 0
                and not bool(parent_metadata.st_mode & 0o022)
            )
            socket_protected = not bool(metadata.st_mode & 0o077)
            result["socket_protected"] = socket_protected and parent_protected
        except OSError as exc:
            result["error"] = exc.__class__.__name__
        result["ready"] = bool(
            result["socket_present"] and result["socket_protected"]
        )
        return result

    async def health(self) -> dict[str, Any]:
        """Return the control-plane readiness contract for the Gateway."""
        db_health = await self.db.health_check()
        policy_compiled = bool(
            isinstance(self._effective_policy.digest, str)
            and len(self._effective_policy.digest) == 64
        )
        audit_required = bool(self._effective_policy.audit_enabled)
        audit_configured = self._audit_logger is not None
        audit_verified = not audit_required
        audit_error = ""
        if self._audit_logger is not None:
            try:
                await self._audit_logger.verify_anchor()
                audit_verified = True
            except (AuditAnchorError, OSError, RuntimeError, ValueError) as exc:
                audit_error = exc.__class__.__name__
                audit_verified = False
        audit_health: dict[str, Any] = {
            "required": audit_required,
            "configured": audit_configured,
            "verified": audit_verified,
            "ok": audit_verified if audit_required else True,
        }
        if audit_error:
            audit_health["error"] = audit_error
        helper_health = self._browser_helper_health()
        ready = bool(
            self._ready
            and db_health.get("ok") is True
            and policy_compiled
            and audit_health["ok"] is True
            and helper_health["ready"] is True
        )
        return {
            "status": "ready" if ready else "not_ready",
            "ready": ready,
            "project_id": self._bound_project_id,
            "policy_digest": self._effective_policy.digest,
            "checks": {
                "agent_started": self._ready,
                "db": db_health,
                "audit_anchor": audit_health,
                "policy": {"compiled": policy_compiled},
                "browser_kernel_helper": helper_health,
            },
        }

    async def stop_producers(self) -> None:
        """Reject new turns and stop background producers before teardown."""
        self._accepting_work = False
        await self.cron_engine.stop()

    async def shutdown(self) -> None:
        """Stop process-scoped background services."""
        # M4 batch 3.1.15 (CRITICAL-1): idempotency guard.  If a previous
        # shutdown() completed cleanly, this is a no-op.  If a previous
        # call raised, the flag is NOT set and re-entry is allowed (each
        # internal step is itself idempotent — cron stop via state machine,
        # chat drain via fresh snapshot, runtime drain via registry scan).
        if self._shutdown_completed:
            return
        self._ready = False
        # Stop producers, then cancel/wait every active turn while shared
        # authorities and the database are still available.
        await self.stop_producers()
        # Take the admission lock for the accepting_work flip and owner
        # snapshot so a concurrent ``chat`` cannot publish a runtime AFTER
        # this snapshot.  This lock acquisition is bounded: chat only holds
        # the lock for cheap dict mutations (reserve / publish), NOT across
        # ``_build_runtime`` (which is slow DB I/O) — so a wedged build
        # cannot block this shutdown from reaching the bounded drain below.
        # See ``chat()``'s reservation pattern.
        async with self._admission_lock:
            # stop_producers already set _accepting_work=False outside the
            # lock; re-assert it under the lock so chat's admission check
            # (under the same lock) cannot observe a stale True here.
            self._accepting_work = False
            current = asyncio.current_task()
            active_tasks = [
                task for task in self._active_chat_tasks
                if task is not current and not task.done()
            ]
        for task in active_tasks:
            task.cancel()
        if active_tasks:
            # M1: bounded drain with hard ownership semantics.  A task that
            # swallows CancelledError used to make ``wait_for(gather)``
            # raise TimeoutError, which the previous code only logged before
            # continuing to dismantle Office/Browser/Audit/DB — while the
            # swallowing task was still running and borrowing exactly those
            # authorities.  ``asyncio.wait`` returns the pending set so we
            # can fail closed: if any chat is still running at the deadline,
            # refuse teardown by raising ``ServiceShutdownError``.  The
            # residual runtime is still registered in ``_active_runtimes``
            # and will be closed or quarantined by the next owner.
            _done, pending = await asyncio.wait(
                active_tasks, timeout=CHAT_DRAIN_TIMEOUT,
            )
            if pending:
                logger.error(
                    "agent shutdown: %d chat task(s) did not terminate within "
                    "%.2fs (swallowed cancellation or wedged); refusing to "
                    "tear down shared authorities",
                    len(pending), CHAT_DRAIN_TIMEOUT,
                )
                self.shutdown_failed = True
                raise ServiceShutdownError(
                    f"{len(pending)} chat task(s) did not terminate within "
                    f"{CHAT_DRAIN_TIMEOUT}s; shared authorities cannot be "
                    f"torn down safely"
                )

        # Defensive ownership pass: a handler cancellation must normally run
        # chat's finally block, but retain/close anything still registered.
        from khaos.runtime import close_runtime_or_register
        for runtime in list(self._active_runtimes.values()):
            try:
                await close_runtime_or_register(runtime)
            except Exception:
                # close_runtime_or_register already quarantines terminal
                # failures.  Continue so drain can retry all retained owners.
                logger.exception("active runtime teardown failed")

        remaining = await self.runtime_cleanup_authority.drain(
            timeout_seconds=5.0
        )
        if remaining:
            logger.error(
                "server shutdown retaining %d quarantined runtime(s)", remaining
            )
            self.shutdown_failed = True
            raise ServiceShutdownError(
                f"{remaining} runtime(s) did not reach a terminal state"
            )
        # Fence every in-flight Office mutation after runtimes have settled.
        await self._shutdown_office_authority()
        if self.memory_host is not None:
            await self.memory_host.close()
            self.memory_host = None
        # The shared AuditLogger is process-owned and is closed exactly once,
        # after all runtime/authority shutdown events had a chance to log.
        if self._audit_logger is not None:
            self._audit_logger.close()
        self.shutdown_failed = False
        # M4 batch 3.1.15 (CRITICAL-1): mark shutdown as completed so
        # subsequent calls are no-ops.  Set ONLY on the clean exit path.
        self._shutdown_completed = True

    async def _shutdown_office_authority(
        self, *, attempts: int = 3, timeout_seconds: float = 5.0,
    ) -> None:
        """Close the shared mutation authority with bounded observable retry."""
        last_error: BaseException | None = None
        for attempt in range(1, attempts + 1):
            if self._office_shutdown_task is None:
                self._office_shutdown_task = asyncio.create_task(
                    self._office_authority.shutdown()
                )
            try:
                await asyncio.wait_for(
                    asyncio.shield(self._office_shutdown_task),
                    timeout=timeout_seconds,
                )
                self._office_shutdown_task = None
                return
            except TimeoutError as exc:
                # The shielded task still owns the mutation fence.  Do not
                # start a concurrent retry or tear down audit/database state.
                last_error = exc
                break
            except Exception as exc:
                last_error = exc
                self._office_shutdown_task = None
                logger.warning(
                    "office authority shutdown attempt %d/%d failed",
                    attempt, attempts, exc_info=True,
                )
        self.shutdown_failed = True
        logger.error("shared Office authority did not reach terminal state")
        raise ServiceShutdownError(
            "shared Office mutation authority shutdown failed"
        ) from last_error

    async def _execute_scheduled_prompt(
        self, task_id: str, prompt: str, principal_id: str = ""
    ) -> str:
        """Run a scheduled prompt through the normal office-mode agent path.

        M4 batch 3.1.10 (CRITICAL): the executor signature now accepts
        the task's ``principal_id`` so the scheduled prompt runs as the
        creator (not the server UID).  Without this, ``chat()`` would
        fall back to ``local-uid:{os.getuid()}`` and:

          * Memory writes would be attributed to the wrong principal.
          * BrowserContext / permission / audit decisions would bind
            to the local server identity instead of the creator.
          * A low-privilege remote principal could schedule a future
            execution that runs as a higher-privilege local user.

        ``CronEngine._execute_task`` calls this as a 3-arg executor;
        the engine keeps a 2-arg fallback for older test executors.
        """
        # M4 batch 3.1.16A-4-1: build a cron-sourced RequestContext
        # for this chat turn.  The ctx is constructed from the task's
        # bound principal_id (stamped at creation time) — not the
        # server's local-uid.
        cron_ctx = RequestContext.for_cron(
            principal_id,
            project_id=self._bound_project_id,
            policy_digest=self._effective_policy.digest,
        )
        contents: list[str] = []
        async for event in self.chat(
            cron_ctx,
            ChatRequest(f"cron:{task_id}", prompt, "office", principal_id=principal_id)
        ):
            if event.get("event") == "message":
                content = event.get("data", {}).get("content")
                if content:
                    contents.append(str(content))
        return "\n".join(contents)

    async def chat(self, ctx: RequestContext, request: ChatRequest) -> AsyncIterator[dict]:
        """Stream chat events.

        B1: hold the full RuntimeResult and close it in ``finally`` so the
        per-turn ExecutionService / MemoryManager are released even when
        ``loop.run`` raises or the client disconnects.  The shared
        OfficeMutationAuthority is borrowed (not owned), so ``aclose`` does
        NOT shut it down — ``AgentService.shutdown`` does.

        Reservation lifecycle (round-4 audit closure):

        The previous round-3 fix held ``_admission_lock`` across the whole
        ``_build_runtime`` await.  That closed the owner-snapshot race but
        introduced a worse problem: ``_build_runtime`` does real DB I/O
        (mode_manager.load / switch, permission_engine.load_rules,
        task_manager.load), so a slow or wedged build held the lock
        indefinitely and shutdown's ``CHAT_DRAIN_TIMEOUT`` deadline never
        started — shutdown blocked on lock acquisition before it could
        even begin the bounded wait.

        The reservation pattern splits admission from the build:

          1. Under ``_admission_lock`` (cheap): check ``_accepting_work``,
             register ``owner_task`` in ``_active_chat_tasks``.  This is
             the reservation — shutdown's snapshot WILL see it.
          2. OUTSIDE the lock: ``await _build_runtime(...)``.  A slow or
             wedged build no longer blocks shutdown; the owner task is
             already registered, so shutdown's cancel + bounded drain
             applies to it directly.
          3. Under ``_admission_lock`` again: if shutdown flipped
             ``_accepting_work`` during the build, abort (the owner task
             is about to be or has already been cancelled by shutdown).
             Otherwise publish the runtime in ``_active_runtimes``.

        The ``finally`` wraps the whole body — including the build — so a
        build failure or cancellation still discards the owner task from
        ``_active_chat_tasks`` (closing the round-3 M3 leak where the
        reservation was only cleaned up after a successful build).
        """
        if not ctx.project_id:
                ctx = RequestContext(
                    principal_id=ctx.principal_id,
                    project_id=self._bound_project_id,
                    session_id=ctx.session_id,
                    runtime_id=ctx.runtime_id,
                    source_transport=ctx.source_transport,
                    policy_digest=ctx.policy_digest,
                    principal_kind=ctx.principal_kind,
                    parent_principal_id=ctx.parent_principal_id,
                    delegation_digest=ctx.delegation_digest,
                )
        owner_task = asyncio.current_task()
        runtime = None
        # F-07 (third-round review): track whether a terminal event has
        # already been appended for this chat so every ``started``
        # corresponds to exactly one terminal (done / error / interrupted).
        session_id_for_terminal: str | None = None
        stream_id_for_terminal: str | None = None
        terminal_appended = False
        # Round-6 Batch 6.1: each chat RPC creates a new stream_id
        # (independent of session_id) so a session can have many streams.
        stream_id = str(uuid.uuid4())
        # Register the reservation BEFORE any await so shutdown's snapshot
        # cannot miss this chat.  Cheap dict mutation under the lock; the
        # expensive build is outside.
        async with self._admission_lock:
            if not self._accepting_work:
                raise ServiceShutdownError("AgentService is shutting down")
            session_id = request.session_id or str(uuid.uuid4())
            # Round-6 Batch 6.1: reject concurrent chat on the same
            # session (Review §八 Strategy B).  A session can have many
            # sequential streams, but not concurrent ones.
            if session_id in self._active_chat_sessions:
                raise SessionBusyError(
                    f"session {session_id} already has an active chat stream"
                )
            self._active_chat_sessions.add(session_id)
            if owner_task is not None:
                self._active_chat_tasks.add(owner_task)
        try:
            await self.db.create_session(
                session_id,
                request.mode or "office",
                principal_id=ctx.principal_id,
                project_id=ctx.project_id,
            )
            started_sequence = await self.db.append_chat_stream_event(
                stream_id=stream_id,
                session_id=session_id,
                principal_id=ctx.principal_id,
                project_id=ctx.project_id,
                event_type="started",
                data={"session_id": session_id, "stream_id": stream_id},
                now=time.time(),
                boot_id=self._boot_id,
                runtime_id=stream_id,
                # C-05: lease renewed on every non-terminal append below.
                # Initial lease is generous so a slow _build_runtime does
                # not get recovered by a concurrent process.
                lease_until=time.time() + _CHAT_STREAM_LEASE_SECONDS,
            )
            session_id_for_terminal = session_id
            stream_id_for_terminal = stream_id
            yield {
                "event": "started",
                "data": {"session_id": session_id, "stream_id": stream_id},
                "sequence": started_sequence,
            }
            # Build OUTSIDE the lock — a slow / wedged build no longer
            # blocks shutdown from acquiring the lock and running its
            # bounded drain.  Cancellation from shutdown propagates here.
            # M4 batch 3.1.16A-4-1: bind session_id into ctx so
            # downstream ModeManager / AgentLoop see the correct
            # (principal, session) pair.
            runtime = await self._build_runtime(
                ctx.with_session(session_id),
                session_id,
                request.mode,
            )
            # Publish under the lock so shutdown's snapshot of
            # _active_runtimes is consistent.  If shutdown closed
            # admission while we were building, abort — the owner task
            # has already been cancelled (or is about to be) and any
            # runtime we built must be torn down.
            async with self._admission_lock:
                if not self._accepting_work:
                    # shutdown began during the build; do not serve.  The
                    # finally block below closes/quarantines the runtime
                    # and discards the owner reservation.
                    raise ServiceShutdownError(
                        "AgentService began shutting down during runtime build"
                    )
                self._active_runtimes[id(runtime)] = runtime
            async for message in runtime.loop.run(request.message, session_id):
                event = _message_to_event(message)
                event_name = str(event["event"])
                is_terminal = event_name in {"done", "error", "interrupted"}
                sequence = await self.db.append_chat_stream_event(
                    stream_id=stream_id,
                    session_id=session_id,
                    principal_id=ctx.principal_id,
                    project_id=ctx.project_id,
                    event_type=event_name,
                    data=dict(event["data"]),
                    now=time.time(),
                    boot_id=self._boot_id,
                    runtime_id=stream_id,
                    # C-05: renew lease on every non-terminal append so
                    # the periodic recovery (if any other process runs
                    # it) does not reclaim an active chat waiting on a
                    # long tool call.  Terminal appends do not need a
                    # lease.
                    lease_until=(
                        None if is_terminal
                        else time.time() + _CHAT_STREAM_LEASE_SECONDS
                    ),
                )
                if str(event["event"]) in {"done", "error", "interrupted"}:
                    terminal_appended = True
                yield {**event, "sequence": sequence}
        except BaseException as exc:
            # F-07: shield a terminal ``error``/``interrupted`` append so
            # the durable ledger always has a terminal event even when
            # ``_build_runtime`` raises, the chat task is cancelled, or
            # the model router fails.  Subscribers polling the ledger
            # would otherwise wait the full 30 s idle deadline instead
            # of seeing an explicit failure.
            if stream_id_for_terminal is not None and not terminal_appended:
                event_type = (
                    "interrupted"
                    if isinstance(exc, asyncio.CancelledError)
                    else "error"
                )
                try:
                    await asyncio.shield(
                        self.db.append_chat_stream_event(
                            stream_id=stream_id_for_terminal,
                            session_id=session_id_for_terminal or "",
                            principal_id=ctx.principal_id,
                            project_id=ctx.project_id,
                            event_type=event_type,
                            data={
                                "reason": type(exc).__name__,
                                "message": str(exc) or type(exc).__name__,
                            },
                            now=time.time(),
                            boot_id=self._boot_id,
                            runtime_id=stream_id_for_terminal,
                            # Terminal append — no lease needed.
                            lease_until=None,
                        )
                    )
                    terminal_appended = True
                except Exception:
                    # The shield itself failed (DB locked, OOM, etc.).
                    # Re-raise the original exception; a separate
                    # recovery journal hook could pick this up later.
                    logger.exception(
                        "F-07: failed to append terminal %s for stream=%s",
                        event_type,
                        stream_id_for_terminal,
                    )
            raise
        finally:
            # Covers build failure, build cancellation, and normal exit.
            # Without this wrap, a _build_runtime raise would leak the
            # owner_task reference in _active_chat_tasks forever.
            from khaos.runtime import close_runtime_or_register
            if runtime is not None:
                try:
                    await close_runtime_or_register(runtime)
                finally:
                    self._active_runtimes.pop(id(runtime), None)
            if owner_task is not None:
                self._active_chat_tasks.discard(owner_task)
            # Round-6 Batch 6.1: release the session so the next turn
            # can start a new stream on the same session.
            if session_id is not None:
                self._active_chat_sessions.discard(session_id)

    async def chat_events(
        self,
        ctx: RequestContext,
        session_id: str = "",
        after_sequence: int = 0,
        stream_id: str = "",
        after_event_id: int | None = None,
    ) -> AsyncIterator[dict]:
        """Replay and tail one principal's durable chat event ledger.

        Batch 7.2 (round-7 §十四): the cursor is now the session-global
        ``event_id`` (passed via ``after_sequence`` for wire-compat), NOT
        the stream-local ``sequence``.  This fixes the cross-stream
        missed-events bug on reconnect.

        If ``stream_id`` is provided, tails that specific stream (a
        terminal event ENDS the stream-specific tail).  Otherwise tails
        ALL streams for the session — and a terminal event on ONE stream
        does NOT end the session-wide subscription (a session can produce
        future streams).
        """
        if not ctx.project_id:
                ctx = RequestContext(
                    principal_id=ctx.principal_id,
                    project_id=self._bound_project_id,
                    session_id=ctx.session_id,
                    runtime_id=ctx.runtime_id,
                    source_transport=ctx.source_transport,
                    policy_digest=ctx.policy_digest,
                    principal_kind=ctx.principal_kind,
                    parent_principal_id=ctx.parent_principal_id,
                    delegation_digest=ctx.delegation_digest,
                )
        if stream_id:
            # Stream-specific tail: no need to verify session ownership
            # separately — the DB query filters by principal+project.
            pass
        else:
            session = await self.db.get_session(
                session_id, principal_id=ctx.principal_id,
                project_id=ctx.project_id,
            )
            if session is None or session.get("project_id") != ctx.project_id:
                return
        # Batch 7.2 §十四: cursor is the session-global event_id.
        if after_event_id is not None and after_sequence:
            raise ValueError(
                "ambiguous replay cursor: use after_event_id only"
            )
        cursor = max(
            0,
            int(after_event_id if after_event_id is not None else after_sequence),
        )
        idle_deadline = time.monotonic() + 30.0
        while time.monotonic() < idle_deadline:
            events = await self.db.list_chat_stream_events(
                stream_id=stream_id,
                session_id=session_id,
                principal_id=ctx.principal_id,
                project_id=ctx.project_id,
                after_event_id=cursor,
            )
            if not events:
                await asyncio.sleep(0.05)
                continue
            idle_deadline = time.monotonic() + 30.0
            for event in events:
                cursor = int(event["event_id"])
                yield event
            # §十四: a terminal event only ends a STREAM-SPECIFIC tail.
            # In session-wide mode (no stream_id), a terminal on one
            # stream must NOT end the subscription — the session may
            # produce future streams.
            if stream_id and events[-1]["terminal"]:
                return

    async def switch_mode(self, ctx: RequestContext, session_id: str, target_mode: str) -> dict:
        # M4 batch 3.1.16A-4-1: use ctx.principal_id (transport-
        # authenticated) instead of the hardcoded ``local-uid``.
        # Previously a remote API principal A calling SwitchMode would
        # modify the local-uid's mode, then A's Chat runtime would
        # load A's principal — producing inconsistent authority and
        # UI state.  Now the switch is scoped to (ctx.principal_id,
        # session_id), matching the Chat runtime's principal binding.
        mode_manager = ModeManager(
            self.db,
            project_root=self.project_root,
            principal_id=ctx.principal_id,
            session_id=session_id,
            project_id=ctx.project_id,
        )
        await mode_manager.load()
        previous_mode = mode_manager.current_mode.value
        mode = ModeManager.parse(target_mode)
        await mode_manager.switch(mode)
        if self.memory_host is not None:
            try:
                runtime = RuntimeMemoryContext(
                    principal_id=ctx.principal_id,
                    project_id=ctx.project_id,
                    session_id=session_id or ctx.session_id or None,
                    task_id=None,
                    workspace_id=None,
                    mode=mode.value,
                    environment_fingerprint="rpc:mode",
                    environment={"source_transport": ctx.source_transport},
                )
                await MemoryEventBridge(self.memory_host.broker).record(
                    "MODE_CHANGED",
                    runtime,
                    {"from_mode": previous_mode, "to_mode": mode.value},
                )
            except Exception:
                logger.warning("mode memory event observation failed", exc_info=True)
        if session_id:
            await self.db.create_session(
                session_id, mode.value,
                principal_id=ctx.principal_id,
                # M4 batch 3.1.16A-5-1b: stamp the RPC-verified project
                # identity (owner-preserving ON CONFLICT — see
                # ``_build_runtime`` for the rationale).
                project_id=ctx.project_id,
            )
        return {"current_mode": mode.value}

    async def confirm_permission(self, ctx: RequestContext, request: ConfirmRequest) -> dict:
        # Round-14 §2: ctx.principal_id is the sole authority for the
        # resolving principal.  ConfirmRequest.principal_id is a payload
        # field and must never be trusted for authorization — a payload
        # value that disagrees with the transport principal is a forged
        # approval attempt.  Previously this passed ``request.principal_id``
        # through to ``ApprovalBroker.resolve``, relying on the dispatcher
        # overwrite (grpc_server.py ``if "principal_id" in payload``) to
        # mask the hole; any path that constructs a ConfirmRequest without
        # that overwrite would have become a forging primitive.
        if not ctx.principal_id or not request.binding_digest:
            return {"ok": False, "error": "approval principal/binding required"}
        if request.principal_id and request.principal_id != ctx.principal_id:
            return {
                "ok": False,
                "error": "payload principal_id does not match transport principal",
            }
        approved = await self.approval_broker.resolve(
                request.tool_call_id,
                request.approved,
                request.remember,
                principal_id=ctx.principal_id,
                session_id=request.session_id,
                binding_digest=request.binding_digest,
            )
        if self.memory_host is not None:
            try:
                runtime = RuntimeMemoryContext(
                    principal_id=ctx.principal_id,
                    project_id=ctx.project_id,
                    session_id=request.session_id or ctx.session_id or None,
                    task_id=getattr(request, "task_id", None),
                    workspace_id=getattr(request, "workspace_id", None),
                    mode="coding",
                    environment_fingerprint="rpc:approval",
                    environment={
                        "source_transport": ctx.source_transport,
                        "runtime_id": ctx.runtime_id,
                    },
                )
                await MemoryEventBridge(self.memory_host.broker).record_and_admit(
                    "APPROVAL_DECIDED",
                    runtime,
                    {
                        "decision": "approved" if approved and request.approved else "rejected",
                        "tool_call_id": request.tool_call_id,
                        "binding_digest": request.binding_digest,
                        "remember": bool(request.remember),
                    },
                    profile=self.memory_host.profile,
                    source_type="SYSTEM",
                )
            except Exception:
                logger.warning("approval memory event observation failed", exc_info=True)
        return {"ok": approved}

    async def handle_webhook(
        self,
        ctx: RequestContext,
        platform: str,
        channel_id: str,
        headers: dict[str, str],
        body: str,
        query: dict[str, str] | None = None,
    ) -> dict[str, str]:
        """Validate and process one inbound platform webhook."""
        channel = self.channel_registry.get(channel_id)
        if channel is None or not channel.is_enabled:
            return {"status": "channel_not_found_or_disabled"}
        try:
            channel_type = ChannelType.WEBHOOK_IN if platform == "generic" else ChannelType(platform)
        except ValueError:
            return {"status": "unsupported_platform"}
        if channel.channel_type != channel_type:
            return {"status": "channel_type_mismatch"}
        handler = WebhookHandler(
            channel_type,
            secret=channel.config.secret,
            on_message=lambda message: self._on_webhook_message(channel_id, message),
            channel_id=channel_id,
            replay_guard=self._webhook_replay_guard,
            verified_limiter=self._verified_webhook_limiter,
        )
        return await handler.handle(headers, body.encode("utf-8"), query)

    async def _on_webhook_message(self, channel_id: str, message: PlatformMessage) -> None:
        identity = {
            "channel_id": channel_id,
            "platform": message.channel.value,
            "sender": message.sender.platform_id or message.sender.id,
            "target": message.target,
        }
        identity_digest = hashlib.sha256(
            json.dumps(
                identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        ).hexdigest()[:24]
        session_id = f"webhook:{channel_id}:{message.channel.value}:{identity_digest}"
        principal_id = (
            f"webhook:{channel_id}:{message.channel.value}:"
            f"{identity['sender'] or 'unknown'}"
        )
        # M4 batch 3.1.16A-4-1: build a webhook-sourced RequestContext
        # for this chat turn.  The ctx is constructed from the derived
        # webhook principal (not the original RPC caller's principal —
        # webhook turns belong to the webhook sender, not the Gateway
        # operator who dispatched the webhook event).
        webhook_ctx = RequestContext.for_webhook(
            principal_id,
            project_id=self._bound_project_id,
            policy_digest=self._effective_policy.digest,
        )
        async for _event in self.chat(webhook_ctx, ChatRequest(
            session_id,
            message.to_agent_input(),
            principal_id=principal_id,
        )):
            pass
        self.channel_registry.record_success(channel_id, received=True)

    def list_channels(self, ctx: RequestContext) -> dict[str, object]:
        return {"channels": self.channel_registry.get_health_report()}

    def set_channel_enabled(self, ctx: RequestContext, channel_id: str, enabled: bool) -> dict[str, object]:
        # C-2-4 (HIGH 4): channel mutations via REST must be gated on
        # the admin principal allowlist compiled into the
        # :class:`EffectiveSecurityPolicy` — symmetric to the tool
        # path (``channel_tools._require_admin``).  Previously the
        # REST path (Go ``POST /api/channels/{id}/enable`` → Python
        # ``AgentService.set_channel_enabled``) bypassed admin
        # validation entirely, so any authenticated principal could
        # enable/disable any channel.
        #
        # ``channel_admins`` is sourced from
        # ``self._effective_policy.channel_admins`` (user ∪ project,
        # OR semantics).  An empty allowlist means NO principal can
        # mutate channels — fail-closed until an admin is explicitly
        # declared in ``khaos_policy.yaml``'s
        # ``channels.admin_principals``.
        admins = self._effective_policy.channel_admins
        if not admins or ctx.principal_id not in admins:
            return {
                "ok": False,
                "error": "principal is not a channel admin",
                "status": "forbidden",
            }
        changed = self.channel_registry.enable(channel_id) if enabled else self.channel_registry.disable(channel_id)
        return {"ok": changed, "channel_id": channel_id}

    async def _build_runtime(
        self, ctx: RequestContext, session_id: str, mode: str,
    ):
        """Build a per-turn runtime that borrows the shared Office authority.

        B1: returns the full ``RuntimeResult`` so ``chat`` can ``aclose`` it
        in ``finally``.  The shared ``self._office_authority`` is injected so
        the aggregate storage baseline persists across turns (closing the
        cross-turn quota bypass).

        H1: reuses the server-lifecycle ``self._audit_logger`` so security
        events from the main AgentLoop and every SubAgent run land in the
        SAME audit trail (no parallel unsupervised audit path).

        M4 batch 3.1.16A-4-1: takes a :class:`RequestContext` instead of
        a bare ``principal_id`` string.  The context is the sole
        authority for principal identity; ``RuntimeConfig`` now
        receives ``session_id`` from ``ctx.session_id`` (previously
        always ``""``, which broke ModeManager's (principal, session)
        binding).  ``principal_id`` still falls back to ``local-uid``
        for legacy callers that construct ctx via
        :meth:`RequestContext.for_cli` without a session_id — but the
        RPC path always provides a non-empty ctx.principal_id.
        """
        # Direct CLI/TUI callers may use ``RequestContext.for_cli`` without a
        # project claim; the server-bound project is the only safe default in
        # that local path.  An explicit claim is never rewritten: a mismatch
        # is a fail-closed drift error before any session or audit write.
        project_id = ctx.project_id or self._bound_project_id
        if project_id != self._bound_project_id:
            raise ValueError("request project_id does not match server binding")
        await self.db.create_session(
            session_id, mode or "office",
            principal_id=ctx.principal_id,
            # M4 batch 3.1.16A-5-1b: stamp the RPC-verified project
            # identity on the session row.  ``create_session``'s
            # ``ON CONFLICT`` clause does NOT touch ``project_id``
            # (owner-preserving), so once a session is bound to a
            # (principal, project) pair a later ``create_session``
            # call from a different project cannot re-stamp it.
            project_id=project_id,
        )
        from khaos.runtime import ProductionRuntimeConfig, build_production_runtime

        # The server owns the physical audit chain, but each runtime must
        # write under the authenticated request identity.  A bound sink is
        # intentionally borrowed; the runtime cannot close or rebind it.
        request_audit_logger = (
            self._audit_logger.bind(
                principal_id=ctx.principal_id,
                project_id=project_id,
                policy_digest=ctx.policy_digest or self._effective_policy.digest,
                runtime_id=ctx.runtime_id or None,
                source_transport=ctx.source_transport,
            )
            if self._audit_logger is not None
            else None
        )

        return await build_production_runtime(ProductionRuntimeConfig(
            project_root=self.project_root, config_path=self.config_path,
            mode_override=mode or None, confirm_callback=self._wait_for_confirmation,
            db=self.db, audit_logger=request_audit_logger,
            # C-1-5a: do NOT pass a shared task_manager — let
            # ``build_runtime`` construct a per-turn TaskManager from
            # ``cfg.principal_id`` (factory.py:502-517).  Previously
            # this passed the server-level ``TaskManager(local-uid)``
            # singleton, which meant per-turn coding tasks landed in
            # the local-uid cache — invisible to the API principal's
            # ``TaskService.list``.
            approval_broker=self.approval_broker,
            router=self._router,
            office_authority=self._office_authority,
            memory_host=self.memory_host,
            principal_id=ctx.principal_id,
            principal_kind=ctx.principal_kind,
            parent_principal_id=ctx.parent_principal_id,
            delegation_digest=ctx.delegation_digest,
            source_transport=ctx.source_transport,
            foreground_session=False,
            session_id=session_id,
            # M4 batch 3.1.16A-5-1b (CRITICAL): inject the RPC-verified
            # project identity so ``AgentLoop._bound_project_id`` (and
            # every component constructed by ``build_runtime``:
            # PermissionEngine, MemoryStore, AuditLogger, TaskManager)
            # comes from ``ctx.project_id`` (server-bound) instead of
            # being recomputed from ``project_root``.  The dispatcher's
            # drift check above guarantees ``ctx.project_id ==
            # agent._bound_project_id`` here.
            project_id=ctx.project_id,
            # M4 batch 3.1.16A-4-4-3: inject the server-lifecycle
            # ChannelRegistry + the effective policy's compiled
            # ``channel_admins`` allowlist so the four channel tools
            # receive them via the ``channel.read`` / ``channel.manage``
            # broker injection (no module-global holder, no
            # cross-principal mutation).
            channel_registry=self.channel_registry,
            channel_admins=self._effective_policy.channel_admins,
            cron_engine=self.cron_engine,
            subagent_spawner=self.subagent_spawner,
            cleanup_authority=self.runtime_cleanup_authority,
        ))

    async def _wait_for_confirmation(self, request: dict) -> dict:
        return await self.approval_broker.wait(
            request["id"],
            timeout=120.0,
            binding_digest=request["binding_digest"],
        )

    def _build_security_middleware(self) -> SecurityMiddleware:
        """Build the full security stack from the effective policy.

        Wiring chain (see 批次 5 of the Codex-alignment doc):
        policy → Sandbox(mode) + NetworkGuard(network_*) + policy-extended
        guards + audit_logger → SecurityMiddleware → ToolScheduler.pre_check.

        H2: every enforcement decision is made from the *effective* policy
        (user ∩ project ∩ platform), not the raw project policy — an
        untrusted repo can no longer disable audit or relax network by
        editing its own ``khaos_policy.yaml``.

        Components are optional and imported lazily so the server starts even
        before all batches are present; a missing class simply means that
        layer is not enforced yet.
        """
        eff = self._effective_policy
        sandbox = None
        network_guard = None
        # Sandbox: capability constraint layer.
        try:
            from khaos.security.sandbox import Sandbox

            sandbox = Sandbox(
                mode=eff.mode,
                workspace_root=self.project_root,
                root_capabilities=eff.root_capabilities,
            )
        except ImportError:
            pass
        # NetworkGuard: network access control.
        try:
            from khaos.security.network_guard import NetworkGuard

            network_guard = NetworkGuard(
                network_enabled=eff.network_enabled,
                # H3: three-state — pass None through so NetworkGuard
                # distinguishes "no allowlist" (unrestricted) from "empty
                # allowlist" (deny all).
                allowed_domains=(
                    list(eff.network_allowed_domains)
                    if eff.network_allowed_domains is not None
                    else None
                ),
                blocked_domains=list(eff.network_blocked_domains),
            )
        except ImportError:
            pass
        audit_logger = self._audit_logger
        return SecurityMiddleware(
            effective_policy=eff,
            sandbox=sandbox,
            network_guard=network_guard,
            audit_logger=audit_logger,
        )

__all__ = ["AgentService"]
