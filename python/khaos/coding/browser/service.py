"""Coding-facing browser/app orchestration over existing security owners.

This module intentionally contains no subprocess, Playwright launch, network
policy, approval broker, or completion implementation of its own.  It binds
typed app/session/action records to the already-composed ExecutionService,
BrowserManager, NetworkGuard, and ApprovalBroker boundaries.
"""

from __future__ import annotations

import asyncio
import inspect
import socket
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from khaos.coding.browser.artifacts import BrowserArtifactStore
from khaos.coding.browser.contracts import (
    AppHealth,
    AppInstance,
    AppInstanceState,
    AppLaunchProfile,
    BrowserAction,
    BrowserActionKind,
    BrowserActionResult,
    BrowserArtifactRef,
    BrowserAssertion,
    BrowserCheckAction,
    BrowserContractError,
    BrowserEffectClass,
    BrowserEffectStatus,
    BrowserObservation,
    BrowserResultStatus,
    BrowserRunResult,
    BrowserSessionBinding,
    BrowserSessionState,
    BrowserVerificationEvidence,
    BrowserVerificationSpec,
    _origin,
    redact_untrusted,
)
from khaos.coding.browser.metrics import BrowserMetrics
from khaos.coding.browser.state import BrowserStateJournalError
from khaos.coding.execution import (
    ExecutionRequest,
    FileSystemAccess,
    NetworkPolicy,
    PermissionProfile,
    ResourceBudget,
)
from khaos.security.credential_broker import CredentialBrokerError, CredentialLease
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes


class BrowserServiceError(BrowserContractError):
    """A typed browser/app service failure."""

    def __init__(self, message: str, *, category: str = "browser-infrastructure-failure") -> None:
        super().__init__(message)
        self.category = category


class BrowserEnvironmentBlocked(BrowserServiceError):
    """The current platform/profile cannot provide a real browser effect."""

    def __init__(self, message: str) -> None:
        super().__init__(message, category="environment-blocked")


@dataclass
class _AppRecord:
    instance: AppInstance
    profile: AppLaunchProfile
    handle: Any
    root: Path


@dataclass
class _SessionRecord:
    binding: BrowserSessionBinding
    app: _AppRecord
    page: Any
    next_sequence: int = 1
    last_observation: BrowserObservation | None = None
    console: list[str] | None = None
    network: list[str] | None = None
    sensitive_values: list[str] | None = None


ReadinessProbe = Callable[[AppLaunchProfile, int, str], bool | Awaitable[bool]]


class BrowserCodingService:
    """Own bounded Coding browser sessions while reusing existing authority."""

    MAX_APPS = 8
    MAX_SESSIONS = 8
    MAX_EVENT_ITEMS = 128
    MAX_NAVIGATION_SECONDS = 30.0
    MAX_ACTION_SECONDS = 30.0
    MAX_READINESS_SECONDS = 15.0

    def __init__(
        self,
        *,
        browser_manager: Any,
        execution_service: Any,
        network_guard: Any = None,
        approval_broker: Any = None,
        workspace_manager: Any = None,
        artifact_store: BrowserArtifactStore | None = None,
        app_profiles: tuple[AppLaunchProfile, ...] | list[AppLaunchProfile] = (),
        readiness_probe: ReadinessProbe | None = None,
        policy_digest: str = "",
        runtime_id: str = "",
        state_repository: Any = None,
        supervision_service: Any = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if browser_manager is None:
            raise ValueError("BrowserCodingService requires the composed BrowserManager")
        if execution_service is None:
            raise ValueError("BrowserCodingService requires the composed ExecutionService")
        if type(app_profiles) not in (tuple, list):
            raise ValueError("app_profiles must be a bounded sequence")
        self.browser_manager = browser_manager
        self.execution_service = execution_service
        self.network_guard = network_guard
        self.approval_broker = approval_broker
        self.workspace_manager = workspace_manager
        self.artifact_store = artifact_store or BrowserArtifactStore()
        self.readiness_probe = readiness_probe
        if policy_digest and (type(policy_digest) is not str or len(policy_digest) != 64):
            raise BrowserContractError("browser service policy digest is malformed")
        self.policy_digest = policy_digest
        self.runtime_id = runtime_id or f"browser-runtime-{uuid.uuid4().hex[:24]}"
        if state_repository is not None and not callable(
            getattr(state_repository, "record", None)
        ):
            raise ValueError("state_repository must expose async record()")
        self.state_repository = state_repository
        self.supervision_service = supervision_service
        self._clock = clock
        self._metric_started_at = time.monotonic()
        self._metrics: dict[str, int] = BrowserMetrics().to_payload()
        self._closed = False
        self._lock = asyncio.Lock()
        self._reserved_ports: set[int] = set()
        # Endpoint binding can happen before an AppInstance is published.
        # Retain a failed unbind as an owned resource so a bind/launch failure
        # cannot make a port disappear from the service's cleanup proof.
        self._quarantined_endpoints: set[int] = set()
        self._profiles: dict[str, AppLaunchProfile] = {}
        for profile in app_profiles:
            self.register_app_profile(profile)
        self._apps: dict[str, _AppRecord] = {}
        self._sessions: dict[str, _SessionRecord] = {}

    @property
    def terminal_closed(self) -> bool:
        return self._closed

    def owned_resources(self) -> tuple[str, ...]:
        resources = [f"app:{key}" for key in self._apps]
        resources.extend(f"session:{key}" for key in self._sessions)
        resources.extend(
            f"endpoint:127.0.0.1:{port}"
            for port in sorted(self._quarantined_endpoints)
        )
        resources.extend(
            f"port-reservation:127.0.0.1:{port}"
            for port in sorted(self._reserved_ports)
        )
        if not self._closed:
            resources.append("browser-coding-service")
        return tuple(resources)

    def terminal_postcondition(self) -> bool:
        return (
            self._closed
            and not self._apps
            and not self._sessions
            and not self._reserved_ports
            and not self._quarantined_endpoints
        )

    def metrics_snapshot(self) -> BrowserMetrics:
        """Return bounded evaluation metrics without browser content."""
        return BrowserMetrics(**self._metrics)

    def _metric(self, name: str, amount: int = 1) -> None:
        if name not in self._metrics or type(amount) is not int or amount < 0:
            raise BrowserContractError("browser metric update is invalid")
        self._metrics[name] = min(1_000_000_000, self._metrics[name] + amount)

    def _metric_once_elapsed(self, name: str) -> None:
        if name not in {"browser_time_to_first_observation", "browser_time_to_green"}:
            raise BrowserContractError("browser timing metric is invalid")
        if self._metrics[name] == 0:
            elapsed = max(0, int((time.monotonic() - self._metric_started_at) * 1000))
            self._metrics[name] = min(1_000_000_000, elapsed)

    def set_supervision_service(self, supervision_service: Any) -> None:
        """Attach the already-composed descriptive supervision owner."""
        if self._closed:
            raise BrowserServiceError("browser coding service is closed")
        self.supervision_service = supervision_service

    async def _journal(
        self,
        *,
        resource_id: str,
        resource_kind: str,
        task_id: str,
        workspace_id: str,
        workspace_generation: int,
        principal_id: str,
        project_id: str,
        event_type: str,
        lifecycle_state: str,
        payload: dict[str, object],
        quarantine_reason: str = "",
    ) -> None:
        if self.state_repository is None:
            return
        try:
            await _maybe_await(
                self.state_repository.record(
                    resource_id=resource_id,
                    resource_kind=resource_kind,
                    task_id=task_id,
                    workspace_id=workspace_id,
                    workspace_generation=workspace_generation,
                    principal_id=principal_id,
                    project_id=project_id,
                    event_type=event_type,
                    lifecycle_state=lifecycle_state,
                    payload=payload,
                    quarantine_reason=quarantine_reason,
                )
            )
        except BrowserStateJournalError as exc:
            raise BrowserServiceError(
                "browser lifecycle journal is unavailable", category="quarantined"
            ) from exc
        except Exception as exc:
            raise BrowserServiceError(
                "browser lifecycle journal failed", category="quarantined"
            ) from exc

    async def _journal_app(
        self, record: _AppRecord, *, event_type: str, reason: str = ""
    ) -> None:
        instance = record.instance
        await self._journal(
            resource_id=instance.instance_id,
            resource_kind="app",
            task_id=instance.task_id,
            workspace_id=instance.workspace_id,
            workspace_generation=instance.workspace_generation,
            principal_id=instance.principal_id,
            project_id=instance.project_id,
            event_type=event_type,
            lifecycle_state=instance.state.value,
            payload=instance.to_payload(),
            quarantine_reason=reason,
        )

    async def _journal_session(
        self, record: _SessionRecord, *, event_type: str, reason: str = ""
    ) -> None:
        binding = record.binding
        await self._journal(
            resource_id=binding.session_id,
            resource_kind="session",
            task_id=binding.task_id,
            workspace_id=binding.workspace_id,
            workspace_generation=binding.workspace_generation,
            principal_id=binding.principal_id,
            project_id=binding.project_id,
            event_type=event_type,
            lifecycle_state=binding.state.value,
            payload=binding.to_payload(),
            quarantine_reason=reason,
        )

    async def _journal_action(
        self, record: _SessionRecord, result: BrowserActionResult
    ) -> None:
        binding = record.binding
        observation = result.observation
        action_payload = result.action.to_payload()
        credential_name = action_payload.pop("credential_name", "")
        if credential_name:
            # Even an opaque provider/name can reveal an operator's account
            # inventory. Keep only a non-reversible label digest and avoid a
            # credential-shaped durable field.
            action_payload["lease_name_digest"] = canonical_digest(credential_name)
        payload: dict[str, object] = {
            "action": action_payload,
            "status": result.status.value,
            "effect_status": result.effect_status.value,
            "observation_digest": (
                observation.observation_digest if observation is not None else ""
            ),
            "error_category": result.error_category,
            "error": result.error,
        }
        await self._journal(
            resource_id=f"{binding.session_id}:{result.action.action_id}",
            resource_kind="action",
            task_id=binding.task_id,
            workspace_id=binding.workspace_id,
            workspace_generation=binding.workspace_generation,
            principal_id=binding.principal_id,
            project_id=binding.project_id,
            event_type="action.completed",
            lifecycle_state=result.status.value,
            payload=payload,
        )

    async def _emit_supervision(
        self,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        event_type: str,
        browser_event: str,
        resource_id: str,
        status: str,
        reason: str = "",
    ) -> None:
        """Publish bounded lifecycle metadata through the existing supervisor.

        Supervision is descriptive and cannot authorize an effect.  A missing
        or unavailable presentation sink therefore never changes the browser
        result; the durable browser journal remains the lifecycle projection.
        """
        emit = getattr(self.supervision_service, "emit", None)
        if not callable(emit):
            return
        payload: dict[str, object] = {
            "activity": {
                "operation": "browser_coding",
                "kind": "browser_app",
                "stage": browser_event,
                "scope": [resource_id],
                "status": status,
            },
            "browser_event": browser_event,
            "resource_id": resource_id,
            "status": status,
        }
        if reason:
            payload["reason_digest"] = canonical_digest({"reason": reason})
        kwargs = {
            "task_id": task_id,
            "workspace_id": workspace_id,
            "principal_id": principal_id,
            "project_id": project_id,
            "event_type": event_type,
            "payload": payload,
            "repository_generation": workspace_generation,
        }
        try:
            result = emit(**kwargs)
        except TypeError:
            # Small test/development sinks commonly use the executor's
            # ``emit(event, payload)`` shape.  Production composition uses the
            # keyword-only TaskSupervisionService above.
            try:
                result = emit(event_type, payload)
            except Exception:  # noqa: BLE001 - supervision cannot authorize effects
                return
        except Exception:  # noqa: BLE001 - supervision cannot authorize effects
            return
        try:
            await _maybe_await(result)
        except Exception:  # noqa: BLE001 - supervision cannot authorize effects
            return

    @staticmethod
    def _observation_metadata(observation: BrowserObservation) -> dict[str, object]:
        return {
            "binding_digest": observation.binding_digest,
            "action_id": observation.action_id,
            "sequence": observation.sequence,
            "origin": observation.origin,
            "observation_digest": observation.observation_digest,
            "semantic_item_count": len(observation.semantic_text),
            "console_item_count": len(observation.console),
            "network_item_count": len(observation.network),
            "artifact_refs": tuple(item.to_payload() for item in observation.artifacts),
        }

    def register_app_profile(self, profile: AppLaunchProfile) -> None:
        """Register one trusted profile; model input cannot register profiles."""
        if self._closed:
            raise BrowserServiceError("browser coding service is closed")
        if type(profile) is not AppLaunchProfile:
            raise BrowserContractError("only typed trusted AppLaunchProfile values may be registered")
        current = self._profiles.get(profile.profile_id)
        if current is not None and current.profile_digest != profile.profile_digest:
            raise BrowserContractError("app profile identity is already bound to another digest")
        if len(self._profiles) >= 64 and current is None:
            raise BrowserContractError("app profile registry limit exceeded")
        self._profiles[profile.profile_id] = profile

    def app_profile(self, profile_id: str) -> AppLaunchProfile:
        try:
            return self._profiles[profile_id]
        except KeyError as exc:
            raise BrowserServiceError(
                "app profile is not registered by the trusted composition root",
                category="app-launch-failure",
            ) from exc

    async def create_app_instance(
        self,
        profile_id: str,
        *,
        task_id: str,
        workspace: Any,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        runtime_id: str = "",
    ) -> AppInstance:
        """Launch one task-owned local app through ExecutionService."""
        async with self._lock:
            if self._closed:
                raise BrowserServiceError("browser coding service is closed")
            if len(self._apps) >= self.MAX_APPS:
                raise BrowserServiceError("browser app instance limit exceeded", category="environment-blocked")
            profile = self.app_profile(profile_id)
            workspace_id, root = self._validate_workspace(
                workspace,
                task_id=task_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                runtime_id=runtime_id,
            )
            port = self._allocate_port(profile)
            try:
                self._bind_local_endpoint(port)
                origin = profile.origin(port)
                execution_id = f"khaos-app-{uuid.uuid4().hex[:24]}"
                request = self._app_execution_request(
                    profile,
                    port=port,
                    root=root,
                    task_id=task_id,
                    workspace_id=workspace_id,
                    execution_id=execution_id,
                )
                start = getattr(self.execution_service, "start_managed_process", None)
                if not callable(start):
                    raise BrowserEnvironmentBlocked("ExecutionService has no managed-process owner")
                handle = await _maybe_await(start(request))
            except (PermissionError, RuntimeError, OSError, BrowserContractError):
                self._metric("app_launch_failures")
                self._release_endpoint_and_port(port)
                raise
            except asyncio.CancelledError:
                self._metric("app_launch_failures")
                self._release_endpoint_and_port(port)
                raise
            except Exception as exc:
                self._metric("app_launch_failures")
                self._release_endpoint_and_port(port)
                raise BrowserEnvironmentBlocked(
                    f"managed app launch is unavailable: {type(exc).__name__}"
                ) from exc
            actual_execution_id = str(getattr(handle, "execution_id", "") or execution_id)
            instance_id = f"app-{uuid.uuid4().hex[:24]}"
            instance = AppInstance(
                instance_id=instance_id,
                profile_id=profile.profile_id,
                profile_digest=profile.profile_digest,
                task_id=task_id,
                workspace_id=workspace_id,
                workspace_generation=workspace_generation,
                principal_id=principal_id,
                project_id=project_id,
                execution_id=actual_execution_id,
                listen_address="127.0.0.1",
                port=port,
                origin=origin,
                state=AppInstanceState.STARTING,
                health=AppHealth.STARTING,
            )
            record = _AppRecord(instance=instance, profile=profile, handle=handle, root=root)
            self._apps[instance_id] = record
            await self._emit_supervision(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                event_type="step.started",
                browser_event="app_starting",
                resource_id=instance_id,
                status=instance.state.value,
            )
            try:
                await self._journal_app(record, event_type="app.starting")
            except BrowserServiceError:
                self._metric("app_launch_failures")
                record.instance = replace(
                    record.instance,
                    state=AppInstanceState.QUARANTINED,
                    health=AppHealth.DEGRADED,
                    instance_digest="",
                )
                raise
            try:
                ready = await asyncio.wait_for(
                    self._probe_readiness(profile, port, origin),
                    timeout=self.MAX_READINESS_SECONDS,
                )
            except (TimeoutError, OSError, BrowserContractError) as exc:
                self._metric("app_launch_failures")
                await self._retire_failed_app(record)
                raise BrowserEnvironmentBlocked(
                    f"app readiness could not be proven: {type(exc).__name__}"
                ) from exc
            if not ready:
                self._metric("app_launch_failures")
                await self._retire_failed_app(record)
                raise BrowserServiceError("app readiness probe failed", category="app-launch-failure")
            ready_instance = replace(
                instance,
                state=AppInstanceState.READY,
                health=AppHealth.READY,
                instance_digest="",
            )
            record.instance = ready_instance
            self._metric("app_launches")
            try:
                await self._journal_app(record, event_type="app.ready")
            except BrowserServiceError:
                self._metric("app_launch_failures")
                record.instance = replace(
                    record.instance,
                    state=AppInstanceState.QUARANTINED,
                    health=AppHealth.DEGRADED,
                    instance_digest="",
                )
                raise
            await self._emit_supervision(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                event_type="verification.progress",
                browser_event="app_ready",
                resource_id=instance_id,
                status=ready_instance.state.value,
            )
            return ready_instance

    async def create_session(
        self,
        app_instance_id: str,
        *,
        task_id: str,
        workspace_id: str,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        repository_generation: int = 0,
        runtime_id: str = "",
        session_id: str = "",
    ) -> BrowserSessionBinding:
        """Bind a BrowserManager context to the exact app and workspace."""
        async with self._lock:
            if self._closed:
                raise BrowserServiceError("browser coding service is closed")
            if len(self._sessions) >= self.MAX_SESSIONS:
                raise BrowserServiceError("browser session limit exceeded", category="environment-blocked")
            try:
                app = self._apps[app_instance_id]
            except KeyError as exc:
                raise BrowserServiceError("unknown app instance", category="stale") from exc
            instance = app.instance
            if (
                instance.task_id != task_id
                or instance.workspace_id != workspace_id
                or instance.principal_id != principal_id
                or instance.project_id != project_id
                or instance.workspace_generation != workspace_generation
                or instance.state is not AppInstanceState.READY
            ):
                raise BrowserServiceError("app instance identity or generation is stale", category="stale")
            effective_runtime = runtime_id or self.runtime_id
            effective_session = session_id or f"browser-session-{uuid.uuid4().hex[:24]}"
            self._bind_local_endpoint(instance.port)
            binding = BrowserSessionBinding(
                principal_id=principal_id,
                project_id=project_id,
                task_id=task_id,
                workspace_id=workspace_id,
                workspace_generation=workspace_generation,
                repository_generation=repository_generation,
                session_id=effective_session,
                runtime_id=effective_runtime,
                browser_runtime_id=f"browser-generation-{id(self.browser_manager):x}",
                browser_context_id=f"{principal_id}:{effective_session}:{effective_runtime}",
                app_instance_id=instance.instance_id,
                app_instance_digest=instance.instance_digest,
                allowed_origins=(instance.origin,),
                policy_digest=self.policy_digest,
                state=BrowserSessionState.STARTING,
            )
            record = _SessionRecord(
                binding=binding, app=app, page=None, console=[], network=[]
            )
            self._sessions[effective_session] = record
            await self._emit_supervision(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                event_type="verification.progress",
                browser_event="session_starting",
                resource_id=effective_session,
                status=binding.state.value,
            )
            try:
                await self._journal_session(record, event_type="session.starting")
            except BrowserServiceError:
                record.binding = replace(
                    record.binding,
                    state=BrowserSessionState.QUARANTINED,
                    binding_digest="",
                )
                raise
            launch = getattr(self.browser_manager, "launch", None)
            ensure = getattr(self.browser_manager, "ensure_page", None)
            try:
                if not callable(launch) or not callable(ensure):
                    raise BrowserEnvironmentBlocked(
                        "BrowserManager lacks the composed page lifecycle"
                    )
                launch_result = await _maybe_await(
                    launch(
                        headless=True,
                        browser_type="chromium",
                        principal_id=principal_id,
                        project_id=project_id,
                        runtime_id=effective_runtime,
                        task_id=task_id,
                    )
                )
                if isinstance(launch_result, dict) and not launch_result.get("ok", False):
                    raise BrowserEnvironmentBlocked("real browser launch was rejected")
                page = await _maybe_await(
                    ensure(
                        principal_id,
                        session_id=effective_session,
                        runtime_id=effective_runtime,
                        project_id=project_id,
                        network_guard=self.network_guard,
                        local_service_endpoints=(
                            (instance.listen_address, instance.port),
                        ),
                    )
                )
                if page is None:
                    raise BrowserEnvironmentBlocked("real browser page is unavailable")
                record.page = page
                self._attach_event_hooks(record)
                await self._page_operation(
                    record,
                    lambda current_page: _page_goto(
                        current_page,
                        f"{instance.origin}{app.profile.readiness_path}",
                    ),
                )
                final_url = str(getattr(page, "url", "") or "")
                self._assert_allowed_url(record, final_url)
                record.binding = replace(
                    record.binding,
                    state=BrowserSessionState.READY,
                    binding_digest="",
                )
            except asyncio.CancelledError:
                await self._retire_failed_session(record)
                raise
            except Exception as exc:
                await self._retire_failed_session(record)
                if isinstance(exc, BrowserServiceError):
                    raise
                raise BrowserEnvironmentBlocked(
                    f"browser session could not bind to the owned app: {type(exc).__name__}"
                ) from exc
            try:
                await self._journal_session(record, event_type="session.ready")
            except BrowserServiceError:
                record.binding = replace(
                    record.binding,
                    state=BrowserSessionState.QUARANTINED,
                    binding_digest="",
                )
                raise
            self._metric("browser_sessions")
            await self._emit_supervision(
                task_id=task_id,
                workspace_id=workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                event_type="verification.progress",
                browser_event="session_ready",
                resource_id=effective_session,
                status=record.binding.state.value,
            )
            return binding

    async def open_app(
        self,
        profile_id: str,
        *,
        task_id: str,
        workspace: Any,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        repository_generation: int = 0,
        runtime_id: str = "",
    ) -> BrowserRunResult:
        """Open an app and session, returning a bounded result envelope."""
        instance: AppInstance | None = None
        try:
            instance = await self.create_app_instance(
                profile_id,
                task_id=task_id,
                workspace=workspace,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                runtime_id=runtime_id,
            )
            binding = await self.create_session(
                instance.instance_id,
                task_id=task_id,
                workspace_id=instance.workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                repository_generation=repository_generation,
                runtime_id=runtime_id,
            )
            return BrowserRunResult(BrowserResultStatus.PASS, session=binding)
        except BrowserEnvironmentBlocked as exc:
            await self._cleanup_failed_open(instance)
            return BrowserRunResult(
                BrowserResultStatus.ENVIRONMENT_BLOCKED,
                error_category=exc.category,
                error=str(exc),
            )
        except BrowserServiceError as exc:
            await self._cleanup_failed_open(instance)
            status = BrowserResultStatus.STALE if exc.category == "stale" else BrowserResultStatus.FAIL
            return BrowserRunResult(status, error_category=exc.category, error=str(exc))
        except asyncio.CancelledError:
            await asyncio.shield(self._cleanup_failed_open(instance))
            raise
        except Exception as exc:  # noqa: BLE001 - convert unexpected adapter failures
            await self._cleanup_failed_open(instance)
            return BrowserRunResult(
                BrowserResultStatus.ENVIRONMENT_BLOCKED,
                error_category="browser-infrastructure-failure",
                error=f"browser app open failed: {type(exc).__name__}",
            )

    async def restart_app(
        self,
        instance_id: str,
        *,
        workspace: Any,
        workspace_generation: int,
        principal_id: str,
        project_id: str,
        task_id: str,
        repository_generation: int = 0,
        runtime_id: str = "",
    ) -> BrowserRunResult:
        """Restart one task-owned app without reusing its old browser identity."""
        record = self._apps.get(instance_id)
        if record is None:
            return BrowserRunResult(
                BrowserResultStatus.STALE,
                error_category="stale",
                error="browser app instance is stale or unknown",
            )
        instance = record.instance
        if (
            instance.task_id != task_id
            or instance.principal_id != principal_id
            or instance.project_id != project_id
            or workspace_generation < instance.workspace_generation
            or str(getattr(workspace, "id", "")) != instance.workspace_id
        ):
            raise BrowserServiceError(
                "browser app restart identity or generation is stale",
                category="stale",
            )
        for session_id, session in tuple(self._sessions.items()):
            if session.app.instance.instance_id == instance_id:
                await self.close_session(session_id)
        await self.close_app_instance(instance_id)
        self._metric("app_restarts")
        return await self.open_app(
            record.profile.profile_id,
            task_id=task_id,
            workspace=workspace,
            principal_id=principal_id,
            project_id=project_id,
            workspace_generation=workspace_generation,
            repository_generation=repository_generation,
            runtime_id=runtime_id,
        )

    async def _cleanup_failed_open(self, instance: AppInstance | None) -> None:
        """Best-effort cleanup that retains any unproven owner as quarantine."""
        if instance is None:
            return
        for session_id, record in tuple(self._sessions.items()):
            if record.app.instance.instance_id != instance.instance_id:
                continue
            try:
                await self.close_session(session_id)
            except BrowserServiceError:
                return
        try:
            await self.close_app_instance(instance.instance_id)
        except BrowserServiceError:
            return

    async def observe(self, session_id: str) -> BrowserObservation:
        record = self._session(session_id)
        self._require_ready(record)

        async def collect(page: Any) -> dict[str, Any]:
            url = str(getattr(page, "url", "") or "")
            title = await _maybe_await(page.title()) if callable(getattr(page, "title", None)) else ""
            body_text = ""
            locator = getattr(page, "locator", None)
            if callable(locator):
                body = locator("body")
                inner_text = getattr(body, "inner_text", None)
                if callable(inner_text):
                    body_text = await _maybe_await(inner_text(timeout=5000))
            return {
                "url": url,
                "title": _redact_known(title, record.sensitive_values, limit=512),
                "semantic_text": tuple(
                    line
                    for line in _redact_known(
                        body_text, record.sensitive_values, limit=8192
                    ).splitlines()
                    if line
                )[: self.MAX_EVENT_ITEMS],
                "console": tuple(
                    _redact_known(item, record.sensitive_values, limit=1024)
                    for item in (record.console or ())
                )[-self.MAX_EVENT_ITEMS :],
                "network": tuple(
                    _redact_known(item, record.sensitive_values, limit=1024)
                    for item in (record.network or ())
                )[-self.MAX_EVENT_ITEMS :],
            }

        result = await self._page_operation(record, collect)
        url = str(result.get("url") or "")
        origin = self._assert_allowed_url(record, url)
        observation = BrowserObservation(
            binding_digest=record.binding.binding_digest,
            action_id=f"observe-{uuid.uuid4().hex[:24]}",
            sequence=record.next_sequence - 1,
            url=url,
            origin=origin,
            title=str(result.get("title") or ""),
            semantic_text=tuple(result.get("semantic_text") or ()),
            accessibility=(),
            console=tuple(result.get("console") or ()),
            network=tuple(result.get("network") or ()),
        )
        record.last_observation = observation
        self._metric("browser_observations")
        self._metric_once_elapsed("browser_time_to_first_observation")
        self._metric(
            "browser_context_bytes",
            sum(
                len(item.encode("utf-8"))
                for item in (
                    observation.title,
                    *observation.semantic_text,
                    *observation.console,
                    *observation.network,
                )
            ),
        )
        await self._journal(
            resource_id=f"{record.binding.session_id}:{observation.action_id}",
            resource_kind="observation",
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            workspace_generation=record.binding.workspace_generation,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            event_type="observation.captured",
            lifecycle_state="captured",
            payload=self._observation_metadata(observation),
        )
        await self._emit_supervision(
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            workspace_generation=record.binding.workspace_generation,
            event_type="verification.progress",
            browser_event="observation_captured",
            resource_id=record.binding.session_id,
            status="captured",
        )
        return observation

    def assert_session_scope(
        self,
        session_id: str,
        *,
        principal_id: str = "",
        project_id: str = "",
        task_id: str = "",
        workspace_id: str = "",
        workspace_generation: int = 0,
        runtime_id: str = "",
    ) -> BrowserSessionBinding:
        """Recheck the caller scope before every model-facing session action."""
        record = self._session(session_id)
        binding = record.binding
        for name, value in (
            ("principal_id", principal_id),
            ("project_id", project_id),
            ("task_id", task_id),
            ("workspace_id", workspace_id),
            ("runtime_id", runtime_id),
        ):
            if value and getattr(binding, name) != value:
                raise BrowserServiceError(
                    f"browser session {name} scope is stale", category="stale"
                )
        if workspace_generation and binding.workspace_generation != workspace_generation:
            raise BrowserServiceError(
                "browser session workspace generation is stale", category="stale"
            )
        return binding

    async def screenshot(self, session_id: str, *, action_id: str = "screenshot") -> BrowserArtifactRef:
        record = self._session(session_id)
        self._require_ready(record)
        if record.sensitive_values:
            raise BrowserServiceError(
                "screenshots are disabled after credential injection",
                category="credential-protection",
            )

        async def capture(page: Any) -> bytes:
            screenshot = getattr(page, "screenshot", None)
            if not callable(screenshot):
                raise BrowserEnvironmentBlocked("browser page cannot produce a screenshot")
            payload = await _maybe_await(screenshot(type="png"))
            if type(payload) is not bytes:
                raise BrowserContractError("browser screenshot did not return bounded bytes")
            return payload

        payload = await self._page_operation(record, capture)
        artifact = self.artifact_store.put("screenshot", payload)
        self._metric("screenshots_created")
        return artifact

    async def perform(
        self,
        action: BrowserAction,
        *,
        approval_context: dict[str, Any] | None = None,
        request_arguments_digest: str = "",
        credential_lease: Any = None,
        credential_broker: Any = None,
    ) -> BrowserActionResult:
        """Perform one semantic action with exact session/sequence binding."""
        if type(action) is not BrowserAction:
            raise BrowserContractError("perform requires a typed BrowserAction")
        self._metric("browser_actions")
        record = self._session(action.session_id)
        if record.binding.state is BrowserSessionState.PAUSED:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.PAUSED,
                    BrowserEffectStatus.NOT_APPLIED,
                    error_category="paused",
                    error="browser session is paused",
                ),
            )
        if record.binding.state is not BrowserSessionState.READY:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.STALE,
                    BrowserEffectStatus.NOT_APPLIED,
                    error_category="stale",
                    error="browser session is not ready",
                ),
            )
        if action.sequence != record.next_sequence:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.STALE,
                    BrowserEffectStatus.NOT_APPLIED,
                    error_category="stale",
                    error="browser action sequence is stale",
                ),
            )
        if record.last_observation is not None and action.precondition_digest and action.precondition_digest != record.last_observation.observation_digest:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.STALE,
                    BrowserEffectStatus.NOT_APPLIED,
                    error_category="stale",
                    error="browser observation precondition is stale",
                ),
            )
        expected_effect = self._expected_effect(record, action)
        if not self._effect_is_compatible(action.effect_class, expected_effect):
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.FAIL,
                    BrowserEffectStatus.NOT_APPLIED,
                    error_category="action-contract-failure",
                    error="action effect class cannot be downgraded",
                ),
            )
        requires_approval = self._requires_approval(record, action, expected_effect)
        if requires_approval:
            self._metric("browser_approval_requests")
        if requires_approval and not self._approval_matches(
            action, approval_context, request_arguments_digest
        ):
            self._metric("browser_policy_denials")
            return await self._record_action_result(
                    record,
                    BrowserActionResult(
                        action,
                        BrowserResultStatus.FAIL,
                        BrowserEffectStatus.NOT_APPLIED,
                        error_category="approval-required",
                        error="sensitive browser effect requires an existing ApprovalBroker grant",
                    ),
                )
        try:
            result = await asyncio.wait_for(
                self._execute_action(
                    record,
                    action,
                    credential_lease=credential_lease,
                    credential_broker=credential_broker,
                ),
                timeout=self.MAX_ACTION_SECONDS,
            )
        except asyncio.CancelledError:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.CANCELLED,
                    BrowserEffectStatus.UNKNOWN,
                    error_category="cancelled",
                    error="browser action was cancelled",
                ),
            )
        except BrowserEnvironmentBlocked as exc:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.ENVIRONMENT_BLOCKED,
                    BrowserEffectStatus.UNKNOWN,
                    error_category=exc.category,
                    error=str(exc),
                ),
            )
        except BrowserServiceError as exc:
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.FAIL,
                    BrowserEffectStatus.UNKNOWN,
                    error_category=exc.category,
                    error=str(exc),
                ),
            )
        except Exception as exc:  # noqa: BLE001 - action is negative observation
            return await self._record_action_result(
                record,
                BrowserActionResult(
                    action,
                    BrowserResultStatus.FAIL,
                    BrowserEffectStatus.UNKNOWN,
                    error_category="browser-infrastructure-failure",
                    error=f"{type(exc).__name__}: {exc}",
                ),
            )
        record.next_sequence += 1
        observation = result if isinstance(result, BrowserObservation) else None
        return await self._record_action_result(
            record,
            BrowserActionResult(
                action,
                BrowserResultStatus.PASS,
                BrowserEffectStatus.APPLIED,
                observation=observation,
            ),
        )

    async def run_verification(
        self,
        spec: BrowserVerificationSpec,
        *,
        plan_id: str,
        check_id: str,
        run_id: str,
        workspace: Any,
        task_id: str,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        repository_generation: int,
        runtime_id: str = "",
    ) -> BrowserRunResult:
        """Run a trusted typed browser check and produce observation evidence."""
        if type(spec) is not BrowserVerificationSpec:
            raise BrowserContractError("browser verification requires a typed spec")
        self._metric("browser_verification_checks")
        instance: AppInstance | None = None
        session: BrowserSessionBinding | None = None
        action_results: list[BrowserActionResult] = []
        try:
            profile = self.app_profile(spec.app_profile_id)
            if spec.profile_digest and spec.profile_digest != profile.profile_digest:
                raise BrowserServiceError("browser spec profile digest is stale", category="stale")
            instance = await self.create_app_instance(
                profile.profile_id,
                task_id=task_id,
                workspace=workspace,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                runtime_id=runtime_id,
            )
            session = await self.create_session(
                instance.instance_id,
                task_id=task_id,
                workspace_id=instance.workspace_id,
                principal_id=principal_id,
                project_id=project_id,
                workspace_generation=workspace_generation,
                repository_generation=repository_generation,
                runtime_id=runtime_id,
            )
            record = self._session(session.session_id)
            initial_url = f"{instance.origin}{spec.start_path}"
            navigate = BrowserAction(
                action_id=f"verification-navigate-{uuid.uuid4().hex[:24]}",
                session_id=session.session_id,
                sequence=1,
                kind=BrowserActionKind.NAVIGATE,
                effect_class=BrowserEffectClass.LOCAL_NAVIGATION,
                target_url=initial_url,
            )
            action_results.append(await self.perform(navigate))
            if action_results[-1].status is not BrowserResultStatus.PASS:
                raise BrowserServiceError("browser verification navigation failed", category="browser-assertion-failure")
            sequence = 2
            for descriptor in spec.actions:
                action = self._materialize_check_action(descriptor, session.session_id, sequence)
                action_results.append(await self.perform(action))
                if action_results[-1].status is not BrowserResultStatus.PASS:
                    raise BrowserServiceError("browser verification action failed", category="browser-assertion-failure")
                sequence += 1
            observation = await self.observe(session.session_id)
            if spec.expected_origin and observation.origin != spec.expected_origin:
                raise BrowserServiceError("browser verification origin assertion failed", category="browser-assertion-failure")
            await self._assertions_match(record, observation, spec.assertions)
            evidence = BrowserVerificationEvidence(
                run_id=run_id,
                plan_id=plan_id,
                check_id=check_id,
                workspace_id=instance.workspace_id,
                workspace_generation=workspace_generation,
                repository_generation=repository_generation,
                session_id=session.session_id,
                app_instance_digest=instance.instance_digest,
                binding_digest=session.binding_digest,
                observation_digest=observation.observation_digest,
                action_digests=tuple(item.action.action_digest for item in action_results),
                assertion_digests=tuple(item.assertion_digest for item in spec.assertions),
                status=BrowserResultStatus.PASS,
                artifact_refs=tuple(item.artifact_id for item in observation.artifacts),
                created_at=self._clock(),
            )
            await self._journal(
                resource_id=evidence.evidence_digest,
                resource_kind="evidence",
                task_id=task_id,
                workspace_id=instance.workspace_id,
                workspace_generation=workspace_generation,
                principal_id=principal_id,
                project_id=project_id,
                event_type="verification.evidence",
                lifecycle_state=evidence.status.value,
                payload=evidence.to_payload(),
            )
            self._metric("browser_evidence_bytes", len(canonical_json_bytes(evidence.to_payload())))
            self._metric_once_elapsed("browser_time_to_green")
            return BrowserRunResult(BrowserResultStatus.PASS, session=session, action_results=tuple(action_results), observation=observation, evidence=evidence)
        except BrowserEnvironmentBlocked as exc:
            self._metric("browser_verification_failures")
            return BrowserRunResult(BrowserResultStatus.ENVIRONMENT_BLOCKED, session=session, action_results=tuple(action_results), error_category=exc.category, error=str(exc))
        except BrowserServiceError as exc:
            self._metric("browser_verification_failures")
            status = BrowserResultStatus.STALE if exc.category == "stale" else BrowserResultStatus.FAIL
            return BrowserRunResult(status, session=session, action_results=tuple(action_results), error_category=exc.category, error=str(exc))
        finally:
            # Evidence remains an observation after the app/session is closed;
            # cleanup is never allowed to turn a failed effect into PASS.
            if session is not None:
                await self.close_session(session.session_id)
            if instance is not None:
                await self.close_app_instance(instance.instance_id)

    async def observe_result(self, session_id: str) -> BrowserRunResult:
        try:
            observation = await self.observe(session_id)
        except BrowserEnvironmentBlocked as exc:
            return BrowserRunResult(BrowserResultStatus.ENVIRONMENT_BLOCKED, error_category=exc.category, error=str(exc))
        except BrowserServiceError as exc:
            return BrowserRunResult(BrowserResultStatus.STALE, error_category=exc.category, error=str(exc))
        return BrowserRunResult(BrowserResultStatus.PASS, session=self._session(session_id).binding, observation=observation)

    async def close_session(self, session_id: str) -> None:
        async with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return
            binding = replace(record.binding, state=BrowserSessionState.STOPPING, binding_digest="")
            record.binding = binding
            close_context = getattr(self.browser_manager, "close_context", None)
            if callable(close_context):
                try:
                    await _maybe_await(
                        close_context(
                            record.binding.principal_id,
                            session_id=record.binding.session_id,
                            runtime_id=record.binding.runtime_id,
                        )
                    )
                except BaseException as exc:
                    record.binding = replace(
                        record.binding,
                        state=BrowserSessionState.QUARANTINED,
                        binding_digest="",
                    )
                    raise BrowserServiceError(
                        f"browser context cleanup is unproven: {type(exc).__name__}",
                        category="quarantined",
                    ) from exc
            record.binding = replace(
                record.binding,
                state=BrowserSessionState.STOPPED,
                binding_digest="",
            )
            await self._journal_session(record, event_type="session.stopped")
            record.sensitive_values = None
            self._sessions.pop(session_id, None)
            await self._emit_supervision(
                task_id=record.binding.task_id,
                workspace_id=record.binding.workspace_id,
                principal_id=record.binding.principal_id,
                project_id=record.binding.project_id,
                workspace_generation=record.binding.workspace_generation,
                event_type="verification.progress",
                browser_event="session_stopped",
                resource_id=session_id,
                status=BrowserSessionState.STOPPED.value,
            )

    async def _retire_failed_session(self, record: _SessionRecord) -> None:
        """Close a failed admission without losing an unproven context."""
        close_context = getattr(self.browser_manager, "close_context", None)
        if not callable(close_context):
            record.binding = replace(
                record.binding,
                state=BrowserSessionState.QUARANTINED,
                binding_digest="",
            )
            raise BrowserServiceError(
                "failed browser session has no context cleanup owner",
                category="quarantined",
            )
        try:
            await _maybe_await(
                close_context(
                    record.binding.principal_id,
                    session_id=record.binding.session_id,
                    runtime_id=record.binding.runtime_id,
                )
            )
        except BaseException as exc:
            record.binding = replace(
                record.binding,
                state=BrowserSessionState.QUARANTINED,
                binding_digest="",
            )
            raise BrowserServiceError(
                f"failed browser context cleanup is unproven: {type(exc).__name__}",
                category="quarantined",
            ) from exc
        record.binding = replace(
            record.binding,
            state=BrowserSessionState.STOPPED,
            binding_digest="",
        )
        try:
            await self._journal_session(record, event_type="session.stopped")
        except BrowserServiceError:
            record.binding = replace(
                record.binding,
                state=BrowserSessionState.QUARANTINED,
                binding_digest="",
            )
            await self._emit_supervision(
                task_id=record.binding.task_id,
                workspace_id=record.binding.workspace_id,
                principal_id=record.binding.principal_id,
                project_id=record.binding.project_id,
                workspace_generation=record.binding.workspace_generation,
                event_type="verification.failed",
                browser_event="session_quarantined",
                resource_id=record.binding.session_id,
                status=BrowserSessionState.QUARANTINED.value,
            )
            raise
        record.sensitive_values = None
        self._sessions.pop(record.binding.session_id, None)

    async def close_app_instance(self, instance_id: str) -> None:
        """Terminate one app only after all of its browser sessions are gone."""
        async with self._lock:
            record = self._apps.get(instance_id)
            if record is None:
                return
            if any(item.app.instance.instance_id == instance_id for item in self._sessions.values()):
                raise BrowserServiceError(
                    "cannot terminate an app with a live browser session",
                    category="quarantined",
                )
            record.instance = replace(
                record.instance,
                state=AppInstanceState.STOPPING,
                health=AppHealth.STALE,
                instance_digest="",
            )
            await self._terminate_handle(record)
            record.instance = replace(
                record.instance,
                state=AppInstanceState.STOPPED,
                health=AppHealth.STALE,
                instance_digest="",
            )
            await self._journal_app(record, event_type="app.stopped")
            try:
                self._release_endpoint_and_port(record.instance.port)
            except BrowserServiceError:
                record.instance = replace(
                    record.instance,
                    state=AppInstanceState.QUARANTINED,
                    health=AppHealth.DEGRADED,
                    instance_digest="",
                )
                raise
            self._apps.pop(instance_id, None)
            await self._emit_supervision(
                task_id=record.instance.task_id,
                workspace_id=record.instance.workspace_id,
                principal_id=record.instance.principal_id,
                project_id=record.instance.project_id,
                workspace_generation=record.instance.workspace_generation,
                event_type="verification.progress",
                browser_event="app_stopped",
                resource_id=instance_id,
                status=AppInstanceState.STOPPED.value,
            )

    async def _retire_failed_app(self, record: _AppRecord) -> None:
        """Terminate a failed app and retain it when terminal proof is incomplete."""
        try:
            await self._terminate_handle(record)
        except BrowserServiceError:
            record.instance = replace(
                record.instance,
                state=AppInstanceState.QUARANTINED,
                health=AppHealth.DEGRADED,
                instance_digest="",
            )
            await self._emit_supervision(
                task_id=record.instance.task_id,
                workspace_id=record.instance.workspace_id,
                principal_id=record.instance.principal_id,
                project_id=record.instance.project_id,
                workspace_generation=record.instance.workspace_generation,
                event_type="verification.failed",
                browser_event="app_quarantined",
                resource_id=record.instance.instance_id,
                status=AppInstanceState.QUARANTINED.value,
            )
            raise
        try:
            self._release_endpoint_and_port(record.instance.port)
        except BrowserServiceError:
            record.instance = replace(
                record.instance,
                state=AppInstanceState.QUARANTINED,
                health=AppHealth.DEGRADED,
                instance_digest="",
            )
            await self._emit_supervision(
                task_id=record.instance.task_id,
                workspace_id=record.instance.workspace_id,
                principal_id=record.instance.principal_id,
                project_id=record.instance.project_id,
                workspace_generation=record.instance.workspace_generation,
                event_type="verification.failed",
                browser_event="app_quarantined",
                resource_id=record.instance.instance_id,
                status=AppInstanceState.QUARANTINED.value,
            )
            raise
        self._apps.pop(record.instance.instance_id, None)

    async def pause(self, session_id: str) -> BrowserSessionBinding:
        record = self._session(session_id)
        if record.binding.state is not BrowserSessionState.READY:
            raise BrowserServiceError("browser session is not pausable", category="stale")
        record.binding = replace(record.binding, state=BrowserSessionState.PAUSED, binding_digest="")
        await self._emit_supervision(
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            workspace_generation=record.binding.workspace_generation,
            event_type="task.paused",
            browser_event="session_paused",
            resource_id=session_id,
            status=BrowserSessionState.PAUSED.value,
        )
        return record.binding

    async def resume(self, session_id: str) -> BrowserSessionBinding:
        record = self._session(session_id)
        if record.binding.state is not BrowserSessionState.PAUSED:
            raise BrowserServiceError("browser session is not paused", category="stale")
        record.binding = replace(record.binding, state=BrowserSessionState.READY, binding_digest="")
        await self._emit_supervision(
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            workspace_generation=record.binding.workspace_generation,
            event_type="task.resumed",
            browser_event="session_resumed",
            resource_id=session_id,
            status=BrowserSessionState.READY.value,
        )
        return record.binding

    async def cancel(self, session_id: str) -> None:
        record = self._session(session_id)
        await self._emit_supervision(
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            workspace_generation=record.binding.workspace_generation,
            event_type="verification.progress",
            browser_event="session_cancelled",
            resource_id=session_id,
            status=BrowserSessionState.STOPPING.value,
        )
        await self.close_session(session_id)

    async def invalidate_generation(self, workspace_id: str, workspace_generation: int) -> None:
        for session_id, record in tuple(self._sessions.items()):
            if record.binding.workspace_id == workspace_id and record.binding.workspace_generation != workspace_generation:
                record.binding = replace(record.binding, state=BrowserSessionState.STALE, binding_digest="")
                await self.close_session(session_id)
        for instance_id, record in tuple(self._apps.items()):
            if record.instance.workspace_id == workspace_id and record.instance.workspace_generation != workspace_generation:
                await self._terminate_handle(record)
                try:
                    self._release_endpoint_and_port(record.instance.port)
                except BrowserServiceError:
                    record.instance = replace(
                        record.instance,
                        state=AppInstanceState.QUARANTINED,
                        health=AppHealth.DEGRADED,
                        instance_digest="",
                    )
                    raise
                self._apps.pop(instance_id, None)

    async def rewind(self, workspace_id: str, workspace_generation: int) -> None:
        """Invalidate browser evidence after a rewind; external effects remain unchanged."""
        await self.invalidate_generation(workspace_id, workspace_generation)

    async def recover_persisted_resources(
        self, *, principal_id: str, project_id: str
    ) -> tuple[dict[str, object], ...]:
        """Reconcile resources left by a prior runtime without reusing identity.

        Recovery is explicit because a new runtime must not silently claim a
        concurrently live runtime's browser context.  The composed
        ExecutionService/BrowserManager are asked to terminate the old
        resource; success records the old identity as ``stale``.  Any missing
        or failed terminal proof records ``quarantined`` instead.
        """
        if self.state_repository is None:
            return ()
        rows = await self.state_repository.list_live_resources(
            principal_id=principal_id, project_id=project_id
        )
        recovered: list[dict[str, object]] = []
        for row in rows:
            resource_id = str(row["resource_id"])
            resource_kind = str(row["resource_kind"])
            payload = dict(row["payload"])
            reason = ""
            terminal = True
            try:
                if resource_kind == "app":
                    execution_id = str(payload.get("execution_id") or "")
                    terminate = getattr(self.execution_service, "terminate", None)
                    if not execution_id or not callable(terminate):
                        raise BrowserServiceError(
                            "persisted app has no execution terminal owner",
                            category="quarantined",
                        )
                    await _maybe_await(terminate(execution_id))
                elif resource_kind == "session":
                    close_context = getattr(self.browser_manager, "close_context", None)
                    if not callable(close_context):
                        raise BrowserServiceError(
                            "persisted browser session has no context owner",
                            category="quarantined",
                        )
                    await _maybe_await(
                        close_context(
                            str(payload.get("principal_id") or principal_id),
                            session_id=str(payload.get("session_id") or resource_id),
                            runtime_id=str(payload.get("runtime_id") or ""),
                        )
                    )
                else:
                    terminal = False
            except BaseException as exc:  # noqa: BLE001 - retain quarantine proof
                terminal = False
                reason = f"{type(exc).__name__}: recovery terminal proof failed"
            lifecycle_state = "stale" if terminal else "quarantined"
            payload["recovery"] = "reconciled" if terminal else "quarantine"
            await self.state_repository.record(
                resource_id=resource_id,
                resource_kind=resource_kind,
                task_id=str(row["task_id"]),
                workspace_id=str(row["workspace_id"]),
                workspace_generation=int(row["workspace_generation"]),
                principal_id=principal_id,
                project_id=project_id,
                event_type=("recovery.reconciled" if terminal else "recovery.quarantined"),
                lifecycle_state=lifecycle_state,
                payload=payload,
                quarantine_reason=reason,
            )
            recovered.append(
                {
                    "resource_id": resource_id,
                    "resource_kind": resource_kind,
                    "lifecycle_state": lifecycle_state,
                    "quarantine_reason": reason,
                }
            )
        return tuple(recovered)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            for session_id in tuple(self._sessions):
                await self.close_session(session_id)
            for instance_id in tuple(self._apps):
                await self.close_app_instance(instance_id)
            for port in tuple(self._quarantined_endpoints):
                self._release_endpoint_and_port(port)
            self.artifact_store.close()
        except BaseException:
            # Keep ownership visible through the failed terminal proof instead
            # of claiming a clean close while a page/app may still be live.
            self._closed = False
            raise
        self._closed = True

    async def aclose(self) -> None:
        await self.close()

    def _validate_workspace(
        self,
        workspace: Any,
        *,
        task_id: str,
        principal_id: str,
        project_id: str,
        workspace_generation: int,
        runtime_id: str = "",
    ) -> tuple[str, Path]:
        if workspace is None:
            raise BrowserServiceError("active TaskWorkspace is required", category="stale")
        workspace_id = str(getattr(workspace, "id", ""))
        if not workspace_id or str(getattr(workspace, "task_id", "")) != task_id:
            raise BrowserServiceError("workspace task identity is stale", category="stale")
        for field, expected in (("principal_id", principal_id), ("project_id", project_id)):
            actual = str(getattr(workspace, field, expected) or expected)
            if actual != expected:
                raise BrowserServiceError(f"workspace {field} identity is stale", category="stale")
        actual_generation = getattr(workspace, "generation", None)
        if actual_generation != workspace_generation or type(actual_generation) is not int or actual_generation <= 0:
            raise BrowserServiceError("workspace generation is stale", category="stale")
        if self.workspace_manager is not None:
            require = getattr(self.workspace_manager, "require", None)
            if callable(require):
                require(
                    workspace_id,
                    task_id=task_id,
                    principal_id=principal_id,
                    project_id=project_id,
                    runtime_id=runtime_id or self.runtime_id,
                )
        root = Path(getattr(workspace, "worktree_path", "")).expanduser().resolve(strict=True)
        if not root.is_dir():
            raise BrowserServiceError("workspace root is unavailable", category="stale")
        return workspace_id, root

    def _app_execution_request(
        self,
        profile: AppLaunchProfile,
        *,
        port: int,
        root: Path,
        task_id: str,
        workspace_id: str,
        execution_id: str,
    ) -> ExecutionRequest:
        environment = {key: value for key, value in profile.environment}
        environment["PORT"] = str(port)
        allowed = frozenset({"PATH", "LANG", "LC_ALL", "TMPDIR", "PORT", *environment})
        permission = PermissionProfile(
            filesystem=FileSystemAccess.READ_ONLY,
            network=NetworkPolicy.NONE,
            workspace_roots=(root,),
            environment_keys=allowed,
            resources=ResourceBudget(timeout_seconds=300.0, cpu_time_seconds=300.0),
            local_listen_ports=(port,),
        )
        return ExecutionRequest(
            argv=profile.launch_argv(port),
            cwd=root if profile.cwd == "." else root / profile.cwd,
            environment=environment,
            allowed_environment_keys=allowed,
            network_policy=NetworkPolicy.NONE,
            budget=permission.resources,
            task_id=task_id,
            workspace_id=workspace_id,
            access_mode=FileSystemAccess.READ_ONLY.value,
            correlation_id=execution_id,
            permission_profile=permission,
            local_listen_ports=(port,),
        )

    def _allocate_port(self, profile: AppLaunchProfile) -> int:
        low, high = profile.port_range
        attempts = 32
        candidates = [0] if low == 0 else list(range(low, min(high, low + attempts - 1) + 1))
        for candidate in candidates:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(("127.0.0.1", candidate))
                port = int(sock.getsockname()[1])
                if port in self._reserved_ports:
                    continue
                self._reserved_ports.add(port)
                return port
            except OSError:
                continue
            finally:
                sock.close()
        raise BrowserEnvironmentBlocked("no task-owned loopback port is available")

    def _release_port(self, port: int) -> None:
        self._reserved_ports.discard(port)

    def _bind_local_endpoint(self, port: int) -> None:
        try:
            if self.network_guard is not None:
                bind = getattr(self.network_guard, "bind_local_service_endpoint", None)
                if callable(bind):
                    bind("127.0.0.1", port)
            bind_manager = getattr(self.browser_manager, "bind_local_service_endpoint", None)
            if callable(bind_manager):
                bind_manager("127.0.0.1", port)
        except BaseException:
            # The endpoint may have been accepted by one owner before the
            # second owner rejected it. Keep it visible until both owners
            # prove unbind, even when no AppInstance exists yet.
            self._quarantined_endpoints.add(port)
            raise

    def _release_local_endpoint(self, port: int) -> None:
        errors: list[str] = []
        for owner in (self.network_guard, self.browser_manager):
            unbind = getattr(owner, "unbind_local_service_endpoint", None)
            if callable(unbind):
                try:
                    unbind("127.0.0.1", port)
                except BaseException:  # noqa: BLE001 - retain endpoint quarantine
                    errors.append(type(owner).__name__)
        if errors:
            raise BrowserServiceError(
                "local browser endpoint cleanup is unproven: " + ",".join(errors),
                category="quarantined",
            )

    def _release_endpoint_and_port(self, port: int) -> None:
        """Release an endpoint and reservation only after both are proven."""
        try:
            self._release_local_endpoint(port)
        except BaseException:
            self._quarantined_endpoints.add(port)
            raise
        self._quarantined_endpoints.discard(port)
        self._release_port(port)

    async def _probe_readiness(self, profile: AppLaunchProfile, port: int, origin: str) -> bool:
        if self.readiness_probe is not None:
            return bool(await _call_readiness_probe(self.readiness_probe, profile, port, origin))
        deadline = time.monotonic() + self.MAX_READINESS_SECONDS
        target = f"{origin}{profile.readiness_path}"
        if self.network_guard is not None:
            authorize = getattr(self.network_guard, "authorize_url", None)
            if callable(authorize):
                await _maybe_await(authorize(target))
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", port), timeout=0.5
                )
                writer.write(
                    f"GET {profile.readiness_path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n".encode()
                )
                await writer.drain()
                line = await asyncio.wait_for(reader.readline(), timeout=0.5)
                writer.close()
                await writer.wait_closed()
                parts = line.decode("ascii", errors="replace").split()
                return len(parts) >= 2 and parts[0] in {"HTTP/1.0", "HTTP/1.1"} and int(parts[1]) in profile.expected_statuses
            except (TimeoutError, OSError, ValueError):
                await asyncio.sleep(0.05)
        return False

    async def _terminate_handle(self, record: _AppRecord) -> None:
        handle = record.handle
        errors: list[BaseException] = []
        terminate = getattr(self.execution_service, "terminate", None)
        if callable(terminate):
            try:
                await _maybe_await(terminate(record.instance.execution_id))
            except BaseException as exc:  # noqa: BLE001 - preserve cleanup proof
                errors.append(exc)
        close = getattr(handle, "aclose", None) or getattr(handle, "close", None)
        if callable(close):
            try:
                await _maybe_await(close())
            except BaseException as exc:  # noqa: BLE001 - preserve cleanup proof
                errors.append(exc)
        terminal = getattr(handle, "terminal_postcondition", None)
        if callable(terminal):
            try:
                if not bool(terminal()):
                    errors.append(RuntimeError("managed app handle lacks terminal proof"))
            except BaseException as exc:  # noqa: BLE001 - preserve cleanup proof
                errors.append(exc)
        elif getattr(handle, "terminal_closed", True) is False:
            errors.append(RuntimeError("managed app handle remains open"))
        if errors:
            raise BrowserServiceError(
                "managed app cleanup is unproven: " + type(errors[0]).__name__,
                category="quarantined",
            ) from errors[0]

    def _session(self, session_id: str) -> _SessionRecord:
        if not isinstance(session_id, str) or not session_id:
            raise BrowserContractError("session_id is required")
        try:
            return self._sessions[session_id]
        except KeyError as exc:
            raise BrowserServiceError("browser session is stale or unknown", category="stale") from exc

    @staticmethod
    def _require_ready(record: _SessionRecord) -> None:
        if record.binding.state is BrowserSessionState.PAUSED:
            raise BrowserServiceError("browser session is paused", category="paused")
        if record.binding.state is not BrowserSessionState.READY:
            raise BrowserServiceError("browser session is stale", category="stale")

    async def _page_operation(self, record: _SessionRecord, operation: Callable[[Any], Any]) -> Any:
        execute = getattr(self.browser_manager, "execute_page_operation", None)
        if callable(execute):
            result = await _maybe_await(
                execute(
                    operation,
                    principal_id=record.binding.principal_id,
                    session_id=record.binding.session_id,
                    runtime_id=record.binding.runtime_id,
                    project_id=record.binding.project_id,
                    network_guard=self.network_guard,
                    local_service_endpoints=(
                        (
                            record.app.instance.listen_address,
                            record.app.instance.port,
                        ),
                    ),
                )
            )
        else:
            # Compatibility seam for a fully fake manager in unit tests.  The
            # production manager always exposes execute_page_operation, whose
            # _safe_execute path retains the Playwright route guard and rejects
            # mock mode as non-real evidence.
            safe = getattr(self.browser_manager, "_safe_execute", None)
            if callable(safe):
                result = await _maybe_await(
                    safe(
                        real=operation,
                        mock=lambda: {"ok": False, "mock": True},
                        principal_id=record.binding.principal_id,
                        session_id=record.binding.session_id,
                        runtime_id=record.binding.runtime_id,
                        project_id=record.binding.project_id,
                        network_guard=self.network_guard,
                        local_service_endpoints=(
                            (
                                record.app.instance.listen_address,
                                record.app.instance.port,
                            ),
                        ),
                    )
                )
            else:
                result = await _maybe_await(operation(record.page))
        if isinstance(result, dict) and result.get("mock"):
            raise BrowserEnvironmentBlocked("mock browser output cannot become Coding evidence")
        if isinstance(result, dict) and result.get("ok") is False:
            raise BrowserServiceError(str(result.get("error") or "browser operation failed"))
        return result

    def _attach_event_hooks(self, record: _SessionRecord) -> None:
        page_on = getattr(record.page, "on", None)
        if not callable(page_on):
            return

        def append_console(message: Any) -> None:
            values = record.console or []
            values.append(
                _redact_known(
                    getattr(message, "text", message),
                    record.sensitive_values,
                    limit=512,
                )
            )
            del values[:-self.MAX_EVENT_ITEMS]
            record.console = values

        def append_network(message: Any) -> None:
            values = record.network or []
            value = getattr(message, "url", message)
            values.append(_redact_known(value, record.sensitive_values, limit=512))
            del values[:-self.MAX_EVENT_ITEMS]
            record.network = values

        try:
            page_on("console", append_console)
            page_on("request", append_network)
            page_on("response", append_network)
        except Exception as exc:  # noqa: BLE001 - event hooks cannot weaken browser controls
            # Observability hooks are best-effort; the route guard and typed
            # action path remain mandatory security boundaries.
            del exc
            return

    def _assert_allowed_url(self, record: _SessionRecord, url: str) -> str:
        if not url:
            raise BrowserServiceError("page URL is unavailable", category="browser-infrastructure-failure")
        parsed = urlsplit(url)
        if parsed.username or parsed.password or parsed.fragment:
            raise BrowserServiceError("page URL contains unsafe authority data", category="browser-infrastructure-failure")
        origin = _url_origin(url)
        if origin not in record.binding.allowed_origins:
            raise BrowserServiceError("page URL is outside the task-owned app origin", category="stale")
        return origin

    def _expected_effect(self, record: _SessionRecord, action: BrowserAction) -> BrowserEffectClass:
        if action.kind is BrowserActionKind.NAVIGATE:
            target = action.target_url
            if not target:
                raise BrowserContractError("navigate requires target_url")
            return (
                BrowserEffectClass.LOCAL_NAVIGATION
                if _url_origin(target) in record.binding.allowed_origins
                else BrowserEffectClass.EXTERNAL_WRITE
            )
        if action.kind in {BrowserActionKind.READ, BrowserActionKind.SCREENSHOT, BrowserActionKind.SCROLL, BrowserActionKind.WAIT_FOR}:
            return BrowserEffectClass.READ_ONLY
        if action.kind is BrowserActionKind.UPLOAD:
            return BrowserEffectClass.UPLOAD
        if action.kind is BrowserActionKind.DOWNLOAD:
            return BrowserEffectClass.DOWNLOAD
        if action.kind is BrowserActionKind.CLOSE:
            return BrowserEffectClass.READ_ONLY
        return BrowserEffectClass.UI_INPUT

    @staticmethod
    def _effect_is_compatible(actual: BrowserEffectClass, expected: BrowserEffectClass) -> bool:
        if actual is expected:
            return True
        return actual in {BrowserEffectClass.UNKNOWN, BrowserEffectClass.DESTRUCTIVE_WRITE}

    def _requires_approval(self, record: _SessionRecord, action: BrowserAction, expected: BrowserEffectClass) -> bool:
        if expected in {BrowserEffectClass.EXTERNAL_WRITE, BrowserEffectClass.FORM_SUBMIT, BrowserEffectClass.UPLOAD, BrowserEffectClass.DOWNLOAD, BrowserEffectClass.DESTRUCTIVE_WRITE}:
            return True
        return action.kind in {BrowserActionKind.CLICK, BrowserActionKind.TYPE, BrowserActionKind.SELECT, BrowserActionKind.PRESS_KEY, BrowserActionKind.OPEN_NEW_PAGE}

    async def _record_action_result(
        self, record: _SessionRecord, result: BrowserActionResult
    ) -> BrowserActionResult:
        """Journal an action outcome without persisting sensitive arguments."""
        await self._journal_action(record, result)
        await self._emit_supervision(
            task_id=record.binding.task_id,
            workspace_id=record.binding.workspace_id,
            principal_id=record.binding.principal_id,
            project_id=record.binding.project_id,
            workspace_generation=record.binding.workspace_generation,
            event_type=(
                "verification.progress"
                if result.status is BrowserResultStatus.PASS
                else "verification.failed"
            ),
            browser_event="action_completed",
            resource_id=f"{record.binding.session_id}:{result.action.action_id}",
            status=result.status.value,
            reason=result.error,
        )
        return result

    def _approval_matches(
        self,
        action: BrowserAction,
        approval_context: dict[str, Any] | None,
        request_arguments_digest: str,
    ) -> bool:
        if not isinstance(approval_context, dict):
            return False
        binding_digest = str(approval_context.get("binding_digest") or approval_context.get("approval_id") or "")
        if len(binding_digest) < 16:
            return False
        if action.approval_digest and action.approval_digest != binding_digest:
            return False
        expected_arguments = str(approval_context.get("arguments_digest") or "")
        if expected_arguments and expected_arguments != request_arguments_digest:
            return False
        approval_policy = str(approval_context.get("policy_digest") or "")
        return not self.policy_digest or approval_policy == self.policy_digest

    async def _execute_action(
        self,
        record: _SessionRecord,
        action: BrowserAction,
        *,
        credential_lease: Any = None,
        credential_broker: Any = None,
    ) -> BrowserObservation | None:
        page = record.page
        if action.kind is BrowserActionKind.NAVIGATE:
            target = action.target_url
            if not target:
                raise BrowserContractError("navigate requires target_url")
            if _url_origin(target) not in record.binding.allowed_origins:
                raise BrowserServiceError(
                    "browser navigation is outside the task-owned app origin",
                    category="origin-escape",
                )
            await self._page_operation(record, lambda current: _page_goto(current, target))
            self._assert_allowed_url(record, str(getattr(page, "url", "") or ""))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.CLICK:
            if not action.selector:
                raise BrowserContractError("click requires a semantic selector")
            await self._page_operation(record, lambda current: _page_call(current, "click", action.selector, timeout=10000))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.TYPE:
            if not action.selector:
                raise BrowserContractError("type requires a semantic selector")
            if action.credential_name:
                credential_value = await self._materialize_browser_credential(
                    record,
                    action,
                    credential_lease=credential_lease,
                    credential_broker=credential_broker,
                )
                await self._page_operation(
                    record,
                    lambda current: _page_call(
                        current, "fill", action.selector, credential_value
                    ),
                )
                return await self.observe(record.binding.session_id)
            await self._page_operation(record, lambda current: _page_call(current, "fill", action.selector, action.value))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.SELECT:
            await self._page_operation(record, lambda current: _page_call(current, "select_option", action.selector, action.value))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.PRESS_KEY:
            await self._page_operation(record, lambda current: _page_call(current, "press", action.selector, action.key))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.SCROLL:
            await self._page_operation(record, lambda current: _page_call(current, "keyboard.press", "PageDown"))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.WAIT_FOR:
            await self._page_operation(record, lambda current: _page_call(current, "wait_for_selector", action.selector, state="visible", timeout=10000))
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.READ:
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.SCREENSHOT:
            await self.screenshot(record.binding.session_id, action_id=action.action_id)
            return await self.observe(record.binding.session_id)
        if action.kind is BrowserActionKind.UPLOAD:
            return await self._upload(record, action)
        if action.kind is BrowserActionKind.DOWNLOAD:
            raise BrowserServiceError("download requires an explicit bounded page download adapter", category="browser-infrastructure-failure")
        if action.kind is BrowserActionKind.CLOSE:
            await self.close_session(record.binding.session_id)
            return None
        raise BrowserServiceError("unsupported browser action", category="browser-infrastructure-failure")

    async def _materialize_browser_credential(
        self,
        record: _SessionRecord,
        action: BrowserAction,
        *,
        credential_lease: Any,
        credential_broker: Any,
    ) -> str:
        """Materialize one opaque credential lease only inside a form fill."""
        if not isinstance(credential_lease, CredentialLease):
            raise BrowserServiceError(
                "credential fill requires an injected opaque CredentialLease",
                category="credential-required",
            )
        if credential_broker is None or not callable(
            getattr(credential_broker, "materialize_async", None)
        ):
            raise BrowserServiceError(
                "credential fill requires the existing CredentialBroker",
                category="credential-required",
            )
        if action.credential_name not in credential_lease.scope.names:
            raise BrowserServiceError(
                "credential lease name is outside the requested browser field",
                category="credential-scope-mismatch",
            )
        operation = "browser_fill"
        binding = {
            "principal_id": record.binding.principal_id,
            "project_id": record.binding.project_id,
            "task_id": record.binding.task_id,
            "workspace_id": record.binding.workspace_id,
            "workspace_generation": record.binding.workspace_generation,
            "session_id": record.binding.session_id,
            "app_instance_id": record.binding.app_instance_id,
            "app_instance_digest": record.binding.app_instance_digest,
            "origin": record.binding.allowed_origins[0],
            "selector": action.selector,
            "credential_name": action.credential_name,
            "policy_digest": record.binding.policy_digest,
            "purpose": operation,
        }
        try:
            environment = await credential_broker.materialize_async(
                credential_lease,
                binding=binding,
                operation=operation,
                timeout=10.0,
            )
        except (CredentialBrokerError, PermissionError) as exc:
            raise BrowserServiceError(
                "browser credential materialization was denied",
                category="credential-denied",
            ) from exc
        if type(environment) is not dict or len(environment) != 1:
            raise BrowserServiceError(
                "browser credential provider must return exactly one bounded value",
                category="credential-denied",
            )
        value = next(iter(environment.values()))
        if type(value) is not str or not value:
            raise BrowserServiceError(
                "browser credential provider returned an invalid value",
                category="credential-denied",
            )
        if record.sensitive_values is None:
            record.sensitive_values = []
        if value not in record.sensitive_values:
            record.sensitive_values.append(value)
        return value

    async def _upload(self, record: _SessionRecord, action: BrowserAction) -> BrowserObservation:
        if not action.selector or not action.file_path:
            raise BrowserContractError("upload requires selector and workspace-relative file_path")
        from khaos.tools.browser_tools import _read_upload_bytes

        result = _read_upload_bytes(action.file_path, str(record.app.root))
        if isinstance(result, dict):
            raise BrowserServiceError(
                str(result.get("error") or "secure workspace upload failed"),
                category="browser-infrastructure-failure",
            )
        payload, filename = result
        await self._page_operation(
            record,
            lambda page: _page_call(
                page,
                "set_input_files",
                action.selector,
                files=[{"name": filename, "buffer": payload}],
            ),
        )
        return await self.observe(record.binding.session_id)

    @staticmethod
    def _materialize_check_action(descriptor: BrowserCheckAction, session_id: str, sequence: int) -> BrowserAction:
        effect = BrowserEffectClass.READ_ONLY
        if descriptor.kind is BrowserActionKind.NAVIGATE:
            effect = BrowserEffectClass.LOCAL_NAVIGATION
        elif descriptor.kind is BrowserActionKind.UPLOAD:
            effect = BrowserEffectClass.UPLOAD
        elif descriptor.kind in {BrowserActionKind.CLICK, BrowserActionKind.TYPE, BrowserActionKind.SELECT, BrowserActionKind.PRESS_KEY}:
            effect = BrowserEffectClass.UI_INPUT
        return BrowserAction(
            action_id=f"verification-action-{uuid.uuid4().hex[:24]}",
            session_id=session_id,
            sequence=sequence,
            kind=descriptor.kind,
            effect_class=effect,
            selector=descriptor.selector,
            value=descriptor.value,
            target_url=descriptor.target_url,
            key=descriptor.key,
            wait_for=descriptor.wait_for,
            file_path=descriptor.file_path,
        )

    @staticmethod
    async def _assertions_match(
        record: _SessionRecord,
        observation: BrowserObservation,
        assertions: tuple[BrowserAssertion, ...],
    ) -> None:
        text = "\n".join(observation.semantic_text).casefold()
        for assertion in assertions:
            if assertion.kind == "text-present" and assertion.expected.casefold() not in text:
                raise BrowserServiceError("browser text assertion failed", category="browser-assertion-failure")
            if assertion.kind == "url-origin" and observation.origin != _origin(assertion.expected, label="assertion origin"):
                raise BrowserServiceError("browser origin assertion failed", category="browser-assertion-failure")
            if assertion.kind == "title-contains" and assertion.expected.casefold() not in observation.title.casefold():
                raise BrowserServiceError("browser title assertion failed", category="browser-assertion-failure")
            if assertion.kind == "selector-visible":
                # Visibility requires a fresh page query and is intentionally
                # checked by the service, not inferred from untrusted text.
                locator_factory = getattr(record.page, "locator", None)
                if not callable(locator_factory):
                    raise BrowserEnvironmentBlocked("browser page cannot query selectors")
                locator = locator_factory(assertion.selector)
                is_visible = getattr(locator, "is_visible", None)
                if not callable(is_visible):
                    raise BrowserEnvironmentBlocked("browser page cannot prove selector visibility")
                visible = await _maybe_await(is_visible(timeout=5000))
                if not visible:
                    raise BrowserServiceError("browser selector assertion failed", category="browser-assertion-failure")


def _redact_known(value: object, secrets: list[str] | None, *, limit: int) -> str:
    """Apply generic and exact in-memory credential redaction to observations."""
    result = redact_untrusted(value, limit=limit)
    for secret in secrets or ():
        if secret:
            result = result.replace(secret, "<redacted>")
    return result


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _call_readiness_probe(probe: ReadinessProbe, profile: AppLaunchProfile, port: int, origin: str) -> bool:
    signature = inspect.signature(probe)
    count = len(
        [
            parameter
            for parameter in signature.parameters.values()
            if parameter.kind in {parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD}
        ]
    )
    if count <= 1:
        value = probe(origin)
    elif count == 2:
        value = probe(port, origin)
    else:
        value = probe(profile, port, origin)
    return bool(await _maybe_await(value))


async def _page_goto(page: Any, url: str) -> Any:
    goto = getattr(page, "goto", None)
    if not callable(goto):
        raise BrowserEnvironmentBlocked("browser page cannot navigate")
    return await _maybe_await(goto(url, wait_until="domcontentloaded", timeout=30000))


async def _page_call(page: Any, method: str, *args: Any, **kwargs: Any) -> Any:
    target = page
    for component in method.split("."):
        target = getattr(target, component, None)
    if not callable(target):
        raise BrowserEnvironmentBlocked(f"browser page does not support {method}")
    return await _maybe_await(target(*args, **kwargs))


def _url_origin(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.hostname is None:
        raise BrowserContractError("browser URL is not a plain HTTP(S) URL")
    host = parsed.hostname.casefold()
    if host not in {"127.0.0.1", "localhost"}:
        return f"{parsed.scheme}://{host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{parsed.scheme}://127.0.0.1:{port}"


__all__ = [
    "BrowserCodingService",
    "BrowserEnvironmentBlocked",
    "BrowserServiceError",
]
