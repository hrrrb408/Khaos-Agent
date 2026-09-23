"""Bounded MCP client surfaces owned by the Khaos extension lifecycle.

This module deliberately contains no process-spawn implementation.  Local
stdio is opened through an injected process owner (normally the existing
ExecutionService/ProcessSupervisor composition), while remote HTTP uses the
existing network policy port.  An MCP server can produce metadata and data;
it cannot create Khaos approval, verification, workspace, or completion
facts.
"""

from __future__ import annotations

import asyncio
import hashlib
import inspect
import ipaddress
import os
import stat
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import httpcore
import httpx

from khaos.coding.context_engine.contracts import (
    ContextItem,
    ContextItemKind,
    ContextLayer,
    ContextSource,
    ContextTrust,
)
from khaos.coding.execution.environment import scrub_spawn_environment
from khaos.extensions.admission import CapabilityAdmissionService
from khaos.extensions.contracts import (
    AdmissionStatus,
    CapabilityDescriptor,
    CapabilityKind,
    CapabilityRequest,
    EffectKind,
    ExtensionDescriptor,
    ExtensionLifecycleState,
    ExtensionSource,
    ExtensionType,
    McpTransportKind,
)
from khaos.extensions.registry import ExtensionRegistry, ExtensionRegistryError
from khaos.extensions.schema import validate_arguments, validate_external_schema
from khaos.security.host_network import ValidatedTarget
from khaos.security.protocol_boundary import (
    canonical_digest,
    canonical_json_bytes,
    strict_json_loads,
)

MCP_PROTOCOL_VERSION = "2025-03-26"
SUPPORTED_MCP_PROTOCOL_VERSIONS = (MCP_PROTOCOL_VERSION, "2024-11-05")
MAX_MCP_PROTOCOL_BYTES = 256 * 1024
MAX_MCP_RESULT_BYTES = 128 * 1024
MAX_MCP_RESOURCE_BYTES = 256 * 1024


class McpErrorCode(StrEnum):
    """Stable, non-authoritative MCP failure codes."""

    INVALID_CONFIGURATION = "invalid_configuration"
    HANDSHAKE_FAILED = "handshake_failed"
    PROTOCOL_ERROR = "protocol_error"
    SERVER_ERROR = "server_error"
    SCHEMA_INVALID = "schema_invalid"
    SCHEMA_ERROR = "schema_invalid"
    LIMIT_EXCEEDED = "limit_exceeded"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    TRANSPORT_FAILED = "transport_failed"
    TRANSPORT_ERROR = "transport_failed"
    APPROVAL_REQUIRED = "approval_required"
    POLICY_DENIED = "policy_denied"
    ADMISSION_DENIED = "admission_denied"
    STALE = "stale"
    UNAVAILABLE = "unavailable"
    QUARANTINED = "quarantined"
    ENDPOINT_DENIED = "endpoint_denied"


class McpSessionState(StrEnum):
    """Runtime state separate from registry discovery state."""

    NEW = "NEW"
    STARTING = "STARTING"
    READY = "READY"
    DEGRADED = "DEGRADED"
    CLOSING = "CLOSING"
    CLOSED = "CLOSED"
    QUARANTINED = "QUARANTINED"


class McpError(RuntimeError):
    """Typed MCP lifecycle/transport error."""

    def __init__(self, code: McpErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class McpLimits:
    """Hard protocol, discovery, call, and lifecycle budgets."""

    max_message_bytes: int = MAX_MCP_PROTOCOL_BYTES
    max_result_bytes: int = MAX_MCP_RESULT_BYTES
    max_resource_bytes: int = MAX_MCP_RESOURCE_BYTES
    max_tools: int = 256
    max_resources: int = 256
    max_prompts: int = 256
    max_pages: int = 64
    max_concurrent_calls: int = 8
    max_in_flight_tasks: int = 32
    request_timeout_seconds: float = 30.0
    max_restarts: int = 2
    max_notifications_per_minute: int = 120
    max_calls: int = 256
    max_total_bytes: int = 4 * 1024 * 1024
    max_wall_time_seconds: float = 300.0

    def __post_init__(self) -> None:
        for name in (
            "max_message_bytes", "max_result_bytes", "max_resource_bytes",
            "max_tools", "max_resources", "max_prompts", "max_pages",
            "max_concurrent_calls", "max_in_flight_tasks", "max_restarts",
            "max_notifications_per_minute", "max_calls", "max_total_bytes",
        ):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be positive")
        if type(self.request_timeout_seconds) not in {int, float} or self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if (
            type(self.max_wall_time_seconds) not in {int, float}
            or self.max_wall_time_seconds <= 0
            or self.max_wall_time_seconds > 3_600
        ):
            raise ValueError("max_wall_time_seconds is outside its bound")
        if (
            self.max_message_bytes > 4 * 1024 * 1024
            or self.max_result_bytes > 4 * 1024 * 1024
            or self.max_resource_bytes > 4 * 1024 * 1024
            or self.max_total_bytes > 16 * 1024 * 1024
        ):
            raise ValueError("MCP byte budgets are too large")


class McpTransport(Protocol):
    """Minimal request/close port implemented by a managed transport owner."""

    async def request(self, method: str, params: Mapping[str, object], *, timeout: float) -> object:
        """Send one bounded MCP request and return its decoded response."""

    async def notify(self, method: str, params: Mapping[str, object]) -> None:
        """Send one bounded notification."""

    async def close(self) -> None:
        """Close the transport and prove its owned resources are terminal."""


class McpProcessOwner(Protocol):
    """Existing process/lifecycle owner used for local stdio MCP."""

    async def start_stdio(
        self,
        descriptor: ExtensionDescriptor,
        argv: tuple[str, ...],
        environment: Mapping[str, str],
    ) -> McpTransport:
        """Start through the canonical process supervisor and return a transport."""
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class McpCallResult:
    """Bounded MCP tool result; output is never an authority projection."""

    capability_id: str
    status: str
    output: object = None
    error_code: str = ""
    error_summary: str = ""
    output_bytes: int = 0
    output_digest: str = ""
    request_digest: str = ""
    binding_digest: str = ""
    ignored_authority_fields: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.capability_id or len(self.capability_id) > 256:
            raise ValueError("MCP capability id is invalid")
        if self.status not in {"success", "failure", "denied", "unavailable", "stale", "quarantined"}:
            raise ValueError("MCP call status is invalid")
        if type(self.error_code) is not str or len(self.error_code) > 128:
            raise ValueError("MCP error code is invalid")
        if type(self.error_summary) is not str or len(self.error_summary.encode("utf-8")) > 2048:
            raise ValueError("MCP error summary is invalid")
        for name in ("request_digest", "binding_digest", "output_digest"):
            value = getattr(self, name)
            if value and (len(value) != 64 or any(character not in "0123456789abcdef" for character in value)):
                raise ValueError(f"MCP {name} is invalid")
        if type(self.output_bytes) is not int or self.output_bytes < 0:
            raise ValueError("MCP output byte count is invalid")
        if type(self.ignored_authority_fields) is not tuple:
            raise ValueError("MCP ignored fields are invalid")

    @property
    def success(self) -> bool:
        return self.status == "success"

    def to_model_payload(self) -> dict[str, object]:
        """Return a bounded diagnostic/result projection for model context."""
        return {
            "status": self.status,
            "output": _thaw_json(self.output),
            "error_code": self.error_code or None,
            "error_summary": self.error_summary or None,
            "output_bytes": self.output_bytes,
            "output_digest": self.output_digest,
            "request_digest": self.request_digest,
            "binding_digest": self.binding_digest,
            "ignored_authority_fields": list(self.ignored_authority_fields),
        }

    def to_context_item(self, *, workspace_id: str, generation: str | None = None) -> ContextItem:
        """Label a result as low-trust extension output for Context Engine."""
        payload = canonical_json_bytes(self.to_model_payload()).decode("utf-8")
        return ContextItem(
            kind=ContextItemKind.EXTENSION_DIAGNOSTIC,
            payload=payload,
            layer=ContextLayer.L3,
            source=ContextSource.EXTENSION,
            trust=ContextTrust.UNTRUSTED_EXTENSION_DIAGNOSTIC,
            workspace_id=workspace_id,
            generation=generation,
            metadata={
                "extension_trust_label": "EXTENSION_DIAGNOSTIC",
                "result_digest": self.output_digest,
            },
        )


@dataclass(frozen=True, slots=True)
class McpDataResult:
    """Bounded resource/prompt data, separate from tool invocation results."""

    capability_id: str
    kind: CapabilityKind
    status: str
    data: object = None
    data_bytes: int = 0
    data_digest: str = ""
    error_code: str = ""
    error_summary: str = ""
    trust_label: str = "EXTENSION_RESOURCE"

    def __post_init__(self) -> None:
        if type(self.capability_id) is not str or not self.capability_id or len(self.capability_id) > 256:
            raise ValueError("MCP data capability id is invalid")
        try:
            object.__setattr__(self, "kind", CapabilityKind(str(self.kind)))
        except ValueError as exc:
            raise ValueError("MCP data capability kind is invalid") from exc
        if self.status not in {"success", "failure", "denied", "unavailable", "stale", "quarantined"}:
            raise ValueError("MCP data status is invalid")
        if type(self.data_bytes) is not int or self.data_bytes < 0:
            raise ValueError("MCP data byte count is invalid")
        if self.data is not None:
            try:
                encoded = canonical_json_bytes(_thaw_json(self.data))
            except Exception as exc:
                raise ValueError("MCP data is not JSON-safe") from exc
            if len(encoded) > 4 * 1024 * 1024:
                raise ValueError("MCP data exceeds its bound")
            if self.data_bytes not in {0, len(encoded)}:
                raise ValueError("MCP data byte count does not match data")
            object.__setattr__(self, "data", _freeze_json(_thaw_json(self.data)))
            object.__setattr__(self, "data_bytes", len(encoded))
            expected_digest = canonical_digest(_thaw_json(self.data))
            if self.data_digest and self.data_digest != expected_digest:
                raise ValueError("MCP data digest does not match data")
            object.__setattr__(self, "data_digest", expected_digest)
        elif self.data_bytes != 0 or self.data_digest:
            raise ValueError("MCP empty data cannot carry size or digest")
        for name in ("data_digest",):
            value = getattr(self, name)
            if value and (len(value) != 64 or any(character not in "0123456789abcdef" for character in value)):
                raise ValueError(f"MCP {name} is invalid")
        for name in ("error_code", "error_summary", "trust_label"):
            value = getattr(self, name)
            if type(value) is not str or "\x00" in value:
                raise ValueError(f"MCP {name} is invalid")
        if len(self.error_code) > 128 or len(self.error_summary.encode("utf-8")) > 2048 or not self.trust_label or len(self.trust_label) > 128:
            raise ValueError("MCP data diagnostics exceed their bound")

    def to_context_item(self, *, workspace_id: str, generation: str | None = None) -> ContextItem:
        payload = canonical_json_bytes({
            "status": self.status,
            "data": _thaw_json(self.data),
            "data_bytes": self.data_bytes,
            "data_digest": self.data_digest,
            "error_code": self.error_code or None,
            "error_summary": self.error_summary or None,
        }).decode("utf-8")
        kind = ContextItemKind.EXTENSION_RESOURCE if self.kind is CapabilityKind.RESOURCE else ContextItemKind.EXTENSION_INSTRUCTION
        trust = ContextTrust.UNTRUSTED_EXTENSION_RESOURCE if self.kind is CapabilityKind.RESOURCE else ContextTrust.UNTRUSTED_EXTENSION_INSTRUCTION
        return ContextItem(
            kind=kind,
            payload=payload,
            layer=ContextLayer.L3,
            source=ContextSource.EXTENSION,
            trust=trust,
            workspace_id=workspace_id,
            generation=generation,
            metadata={"extension_trust_label": self.trust_label},
        )


class HttpxMcpTransport:
    """Small JSON-RPC HTTP transport with redirect and response bounds."""

    def __init__(
        self,
        endpoint: str,
        *,
        limits: McpLimits | None = None,
        host_checker: Callable[[str], bool] | None = None,
        network_authority: object | None = None,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.endpoint = validate_mcp_endpoint(endpoint)
        self.limits = limits or McpLimits()
        self.host_checker = host_checker
        self.network_authority = network_authority
        if client is not None and network_authority is not None:
            raise McpError(
                McpErrorCode.ENDPOINT_DENIED,
                "an injected HTTP client cannot be combined with network authority",
            )
        self._client = client
        self._owns_client = client is None
        self._validated_target: ValidatedTarget | None = None
        self._request_id = 0
        self._lock = asyncio.Lock()

    async def request(self, method: str, params: Mapping[str, object], *, timeout: float) -> object:
        async with self._lock:
            self._request_id += 1
            request_id = self._request_id
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": dict(params),
        }
        encoded = canonical_json_bytes(payload)
        if len(encoded) > self.limits.max_message_bytes:
            raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP request exceeds byte budget")
        if self.host_checker is not None:
            host = urlsplit(self.endpoint).hostname or ""
            if not self.host_checker(host):
                raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint rejected by network policy")
        target = await self._validate_network_endpoint()
        client = await self._get_client(target)
        try:
            response = await client.post(
                self.endpoint,
                content=encoded,
                headers={"content-type": "application/json", "accept": "application/json"},
                timeout=timeout,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "MCP HTTP transport failed") from exc
        if response.status_code in {301, 302, 303, 304, 305, 307, 308}:
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP redirects require independent endpoint validation")
        if response.status_code >= 400:
            code = McpErrorCode.SERVER_ERROR if response.status_code >= 500 else McpErrorCode.TRANSPORT_FAILED
            raise McpError(code, f"MCP endpoint returned HTTP {response.status_code}")
        if len(response.content) > self.limits.max_message_bytes:
            raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP response exceeds byte budget")
        try:
            return strict_json_loads(response.content, max_bytes=self.limits.max_message_bytes)
        except Exception as exc:
            raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP response is not strict JSON") from exc

    async def notify(self, method: str, params: Mapping[str, object]) -> None:
        payload = {"jsonrpc": "2.0", "method": method, "params": dict(params)}
        encoded = canonical_json_bytes(payload)
        if len(encoded) > self.limits.max_message_bytes:
            raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP notification exceeds byte budget")
        target = await self._validate_network_endpoint()
        client = await self._get_client(target)
        try:
            response = await client.post(
                self.endpoint,
                content=encoded,
                headers={"content-type": "application/json", "accept": "application/json"},
                timeout=self.limits.request_timeout_seconds,
                follow_redirects=False,
            )
        except httpx.HTTPError as exc:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "MCP HTTP notification failed") from exc
        if response.status_code >= 400 or response.status_code in {301, 302, 303, 304, 305, 307, 308}:
            code = McpErrorCode.SERVER_ERROR if response.status_code >= 500 else McpErrorCode.TRANSPORT_FAILED
            raise McpError(code, "MCP notification was not accepted")

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _get_client(self, target: ValidatedTarget | None = None) -> httpx.AsyncClient:
        if self._client is None:
            self._client = _new_http_client(target)
        elif self._owns_client and target is not None and target != self._validated_target:
            await self._client.aclose()
            self._client = _new_http_client(target)
        self._validated_target = target or self._validated_target
        return self._client

    async def _validate_network_endpoint(self) -> ValidatedTarget | None:
        """Run the existing async network authority before every HTTP hop."""
        if self.network_authority is None:
            return None
        validator = getattr(self.network_authority, "authorize_url", None)
        if not callable(validator):
            validator = getattr(self.network_authority, "validate_url", None)
        if not callable(validator):
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP network authority is malformed")
        try:
            result = validator(self.endpoint)
            if inspect.isawaitable(result):
                result = await result
            if isinstance(result, ValidatedTarget):
                return result
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP network authority returned no validated target")
        except Exception as exc:
            if isinstance(exc, McpError):
                raise
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint failed network authority validation") from exc
        return None


class _PinnedNetworkBackend:
    """Connect only to the DNS snapshot approved for one HTTP hop."""

    def __init__(self, target: ValidatedTarget) -> None:
        self._hostname = target.hostname
        self._addresses = target.addresses
        self._backend: Any = httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> Any:
        normalized = host.decode("ascii") if isinstance(host, bytes) else host
        if normalized.casefold().rstrip(".") != self._hostname:
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP transport attempted an unvalidated hostname")
        last_error: Exception | None = None
        for address in self._addresses:
            try:
                return await self._backend.connect_tcp(
                    address,
                    port,
                    timeout=timeout,
                    local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as exc:  # noqa: BLE001 - backend exceptions vary by runtime
                last_error = exc
        if last_error is not None:
            raise last_error
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP network authority returned no addresses")

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> Any:
        del path, timeout, socket_options
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP transport cannot use Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


def _new_http_client(target: ValidatedTarget | None) -> httpx.AsyncClient:
    """Create an HTTP client with a pinned backend when authority supplies one."""
    if target is None:
        return httpx.AsyncClient(follow_redirects=False, trust_env=False)
    transport = httpx.AsyncHTTPTransport(trust_env=False, retries=0)
    pool = cast(Any, transport)._pool
    pool._network_backend = _PinnedNetworkBackend(target)
    return httpx.AsyncClient(transport=transport, follow_redirects=False, trust_env=False)


class ScriptedMcpTransport:
    """Deterministic transport double for conformance and adversarial tests."""

    def __init__(self, handlers: Mapping[str, object] | Callable[[str, Mapping[str, object]], object]) -> None:
        self.handlers = handlers
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.notifications: list[tuple[str, dict[str, object]]] = []
        self.closed = False

    async def request(self, method: str, params: Mapping[str, object], *, timeout: float) -> object:
        del timeout
        if self.closed:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "scripted transport is closed")
        self.calls.append((method, dict(params)))
        if callable(self.handlers):
            value = self.handlers(method, params)
        else:
            value = self.handlers.get(method)
        if isinstance(value, BaseException):
            raise value
        if callable(value):
            value = value(method, params)
        if asyncio.iscoroutine(value):
            value = await value
        if value is None:
            raise McpError(McpErrorCode.PROTOCOL_ERROR, f"no scripted response for {method}")
        return value

    async def notify(self, method: str, params: Mapping[str, object]) -> None:
        if self.closed:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "scripted transport is closed")
        self.notifications.append((method, dict(params)))

    async def close(self) -> None:
        self.closed = True


class McpServerSession:
    """One task/session-owned MCP server lifecycle and capability surface."""

    def __init__(
        self,
        descriptor: ExtensionDescriptor,
        *,
        registry: ExtensionRegistry | None = None,
        admission: CapabilityAdmissionService | None = None,
        transport: McpTransport | None = None,
        process_owner: McpProcessOwner | None = None,
        limits: McpLimits | None = None,
        task_id: str = "mcp-task",
        principal_id: str = "mcp-principal",
        project_id: str = "mcp-project",
        workspace_id: str = "",
        workspace_generation: int = 0,
        network_host_checker: Callable[[str], bool] | None = None,
        network_authority: object | None = None,
        workspace_root: Path | None = None,
        on_event: Callable[[str, Mapping[str, object]], Awaitable[None] | None] | None = None,
    ) -> None:
        if descriptor.extension_type is not ExtensionType.MCP_SERVER:
            raise ValueError("MCP session requires an MCP_SERVER descriptor")
        self.descriptor = descriptor
        self.registry = registry
        self.admission = admission
        self.transport = transport
        self.process_owner = process_owner
        self.limits = limits or McpLimits()
        self.task_id = task_id
        self.principal_id = principal_id
        self.project_id = project_id
        self.workspace_id = workspace_id
        self.workspace_generation = workspace_generation
        self.network_host_checker = network_host_checker
        self.network_authority = network_authority
        self.workspace_root = workspace_root.resolve() if workspace_root else None
        self.on_event = on_event
        self.state = McpSessionState.NEW
        self._capabilities: dict[str, CapabilityDescriptor] = {}
        self._by_kind_name: dict[tuple[CapabilityKind, str], str] = {}
        self._calls = asyncio.Semaphore(self.limits.max_concurrent_calls)
        self._task_slots = asyncio.BoundedSemaphore(self.limits.max_in_flight_tasks)
        self._in_flight = 0
        self._state_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None
        self._restarts = 0
        self._process_transport_owned = False
        self._notification_times: list[float] = []
        self._task_started_at = time.monotonic()
        self._task_budget_lock = asyncio.Lock()
        self._task_calls = 0
        self._task_bytes = 0
        self._extension_calls = 0
        self._mcp_calls = 0
        self._mcp_failures = 0

    @property
    def capabilities(self) -> tuple[CapabilityDescriptor, ...]:
        return tuple(sorted(self._capabilities.values(), key=lambda item: item.capability_id))

    @property
    def active_calls(self) -> int:
        return self._in_flight

    @property
    def task_calls(self) -> int:
        return self._task_calls

    @property
    def task_bytes(self) -> int:
        return self._task_bytes

    def metrics_snapshot(self) -> dict[str, int]:
        """Return bounded extension metrics without provider content."""
        return {
            "extension_calls": self._extension_calls,
            "mcp_calls": self._mcp_calls,
            "mcp_failures": self._mcp_failures,
            "hook_invocations": 0,
            "hook_failures": 0,
        }

    async def start(self) -> tuple[CapabilityDescriptor, ...]:
        """Open, handshake, discover, validate, and explicitly publish availability."""
        async with self._state_lock:
            if self.state is McpSessionState.READY:
                return self.capabilities
            if self.state in {McpSessionState.CLOSING, McpSessionState.CLOSED, McpSessionState.QUARANTINED}:
                raise McpError(McpErrorCode.UNAVAILABLE, f"MCP session is {self.state.value}")
            self.state = McpSessionState.STARTING
        try:
            await self._ensure_transport()
            await self._handshake()
            await self._discover_all()
            await self._publish_registry()
            self.state = McpSessionState.READY
            await self._emit("mcp.connected", {"extension_id": self.descriptor.extension_id, "capability_count": len(self._capabilities)})
            return self.capabilities
        except McpError:
            await self._cleanup_start_failure()
            raise
        except Exception as exc:
            await self._cleanup_start_failure()
            raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP startup failed") from exc

    async def close(self) -> None:
        """Close once through a shared task; cancellation cannot skip cleanup."""
        if self._close_task is not None and not self._close_task.done():
            await asyncio.shield(self._close_task)
            return
        if self.state is McpSessionState.CLOSED:
            return
        self._close_task = asyncio.create_task(self._close_impl())
        try:
            await asyncio.shield(self._close_task)
        except asyncio.CancelledError:
            await asyncio.shield(self._close_task)
            raise

    async def restart(self) -> tuple[CapabilityDescriptor, ...]:
        """Perform bounded close/reconnect/revalidation after degradation."""
        if self._restarts >= self.limits.max_restarts:
            await self._mark_quarantined("MCP restart budget exhausted")
            raise McpError(McpErrorCode.QUARANTINED, "MCP restart budget exhausted")
        self._restarts += 1
        await self._close_impl(reset_for_restart=True)
        return await self.start()

    async def call_tool(
        self,
        capability: str,
        arguments: Mapping[str, object],
        *,
        request: CapabilityRequest | None = None,
    ) -> McpCallResult:
        """Admit and invoke one MCP tool with bounded, low-trust output."""
        descriptor = self._find_capability(capability, CapabilityKind.TOOL)
        if descriptor is None:
            return self._failure(capability, McpErrorCode.UNAVAILABLE, "MCP tool is unavailable", "unavailable")
        if self.state is not McpSessionState.READY:
            return self._failure(descriptor.capability_id, McpErrorCode.UNAVAILABLE, f"MCP session is {self.state.value}", "unavailable")
        if not isinstance(arguments, Mapping):
            return self._failure(descriptor.capability_id, McpErrorCode.SCHEMA_INVALID, "MCP tool arguments are not an object", "failure")
        try:
            arguments_value = dict(arguments)
            arguments_valid = validate_arguments(dict(descriptor.input_schema), arguments_value)
        except (TypeError, ValueError):
            return self._failure(descriptor.capability_id, McpErrorCode.SCHEMA_INVALID, "MCP tool arguments do not match its schema", "failure")
        if not arguments_valid:
            return self._failure(descriptor.capability_id, McpErrorCode.SCHEMA_INVALID, "MCP tool arguments do not match its schema", "failure")
        if request is None:
            try:
                request = self._request_for(descriptor, arguments_value)
            except (TypeError, ValueError):
                return self._failure(descriptor.capability_id, McpErrorCode.SCHEMA_INVALID, "MCP tool request is malformed", "failure")
        elif request.capability_id != descriptor.capability_id or dict(request.arguments) != dict(arguments):
            return self._failure(descriptor.capability_id, McpErrorCode.STALE, "request and tool arguments disagree", "stale")
        if self.admission is None:
            return self._failure(descriptor.capability_id, McpErrorCode.ADMISSION_DENIED, "no unified admission service is bound", "denied")
        admission = await self.admission.admit(request)
        if not admission.admitted:
            status, code = _admission_failure(admission.status, admission.reason_code)
            return McpCallResult(
                capability_id=descriptor.capability_id,
                status=status,
                error_code=code.value,
                error_summary=admission.reason,
                request_digest=admission.request_digest,
            )
        binding = admission.binding
        if binding is None:
            return self._failure(descriptor.capability_id, McpErrorCode.STALE, "admission did not produce an invocation binding", "stale", request_digest=admission.request_digest)
        valid = self.admission.validate_invocation(binding, request)
        if not valid.admitted:
            return self._failure(descriptor.capability_id, McpErrorCode.STALE, valid.reason, "stale", request_digest=valid.request_digest)
        if not await self._acquire_task_slot():
            return self._failure(descriptor.capability_id, McpErrorCode.LIMIT_EXCEEDED, "MCP in-flight task budget is exhausted", "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        request_bytes = len(canonical_json_bytes({"name": descriptor.name, "arguments": arguments_value}))
        budget_ok, budget_reason = await self._reserve_task_budget(request_bytes)
        if not budget_ok:
            self._task_slots.release()
            return self._failure(descriptor.capability_id, McpErrorCode.LIMIT_EXCEEDED, budget_reason, "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        request_started = False
        try:
            async with self._calls:
                self._in_flight += 1
                request_started = True
                raw = await asyncio.wait_for(
                    self._request("tools/call", {"name": descriptor.name, "arguments": arguments_value}),
                    timeout=self.limits.request_timeout_seconds,
                )
                response_bytes = len(canonical_json_bytes(raw))
                if not await self._charge_task_bytes(response_bytes):
                    return self._failure(descriptor.capability_id, McpErrorCode.LIMIT_EXCEEDED, "MCP task byte budget is exhausted", "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        except TimeoutError:
            await self._handle_transport_failure("MCP tool call timed out")
            return self._failure(descriptor.capability_id, McpErrorCode.TIMEOUT, "MCP tool call timed out", "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        except asyncio.CancelledError:
            try:
                await asyncio.shield(self._handle_transport_failure("MCP tool call cancelled"))
            except (McpError, asyncio.CancelledError):
                pass
            return self._failure(descriptor.capability_id, McpErrorCode.CANCELLED, "MCP tool call was cancelled", "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        except McpError as exc:
            await self._handle_transport_failure(str(exc))
            return self._failure(descriptor.capability_id, exc.code, str(exc), "failure", request_digest=valid.request_digest, binding_digest=binding.binding_digest)
        finally:
            if request_started:
                self._in_flight -= 1
            self._task_slots.release()
        try:
            result_value = _unwrap_result(raw)
        except McpError as exc:
            await self._handle_transport_failure(str(exc))
            return self._failure(
                descriptor.capability_id,
                exc.code,
                str(exc),
                "failure",
                request_digest=valid.request_digest,
                binding_digest=binding.binding_digest,
            )
        return self._result_from_raw(
            descriptor.capability_id,
            result_value,
            request_digest=valid.request_digest,
            binding_digest=binding.binding_digest,
            output_schema=descriptor.output_schema,
        )

    async def read_resource(
        self,
        resource: str,
        *,
        request: CapabilityRequest | None = None,
    ) -> McpDataResult:
        """Fetch one resource as extension context, never as instructions."""
        descriptor = self._find_capability(resource, CapabilityKind.RESOURCE)
        if descriptor is None:
            return self._data_failure(resource, CapabilityKind.RESOURCE, "unavailable", McpErrorCode.UNAVAILABLE, "MCP resource is unavailable")
        if self.state is not McpSessionState.READY:
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "unavailable", McpErrorCode.UNAVAILABLE, f"MCP session is {self.state.value}")
        if self.admission is None:
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "denied", McpErrorCode.ADMISSION_DENIED, "no unified admission service is bound")
        expected_arguments = {"uri": descriptor.resource_uri or descriptor.name}
        try:
            request = request or self._request_for(descriptor, expected_arguments)
        except (TypeError, ValueError):
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.SCHEMA_INVALID, "resource request is malformed")
        if request.capability_id != descriptor.capability_id or dict(request.arguments) != expected_arguments:
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "stale", McpErrorCode.STALE, "resource request is stale")
        admission = await self.admission.admit(request)
        if not admission.admitted:
            status, code = _admission_failure(admission.status, admission.reason_code)
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, status, code, admission.reason)
        binding = admission.binding
        if binding is None:
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "stale", McpErrorCode.STALE, "admission did not produce an invocation binding")
        valid = self.admission.validate_invocation(binding, request)
        if not valid.admitted:
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "stale", McpErrorCode.STALE, valid.reason)
        if not await self._acquire_task_slot():
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.LIMIT_EXCEEDED, "MCP in-flight task budget is exhausted")
        request_bytes = len(canonical_json_bytes({"uri": descriptor.resource_uri or descriptor.name}))
        budget_ok, budget_reason = await self._reserve_task_budget(request_bytes)
        if not budget_ok:
            self._task_slots.release()
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.LIMIT_EXCEEDED, budget_reason)
        request_started = False
        try:
            async with self._calls:
                self._in_flight += 1
                request_started = True
                raw = await asyncio.wait_for(
                    self._request("resources/read", {"uri": descriptor.resource_uri or descriptor.name}),
                    timeout=self.limits.request_timeout_seconds,
                )
            if not await self._charge_task_bytes(len(canonical_json_bytes(raw))):
                return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.LIMIT_EXCEEDED, "MCP task byte budget is exhausted")
            raw = _unwrap_result(raw)
            data, size = _bounded_value(raw, self.limits.max_resource_bytes)
            digest = canonical_digest(_thaw_json(data))
            return McpDataResult(descriptor.capability_id, CapabilityKind.RESOURCE, "success", data=data, data_bytes=size, data_digest=digest)
        except asyncio.CancelledError:
            try:
                await asyncio.shield(self._handle_transport_failure("MCP resource read cancelled"))
            except (McpError, asyncio.CancelledError):
                pass
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.CANCELLED, "MCP resource read was cancelled")
        except TimeoutError:
            await self._handle_transport_failure("MCP resource read timed out")
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", McpErrorCode.TIMEOUT, "MCP resource read timed out")
        except McpError as exc:
            await self._handle_transport_failure(str(exc))
            return self._data_failure(descriptor.capability_id, CapabilityKind.RESOURCE, "failure", exc.code, str(exc))
        finally:
            if request_started:
                self._in_flight -= 1
            self._task_slots.release()

    async def get_prompt(
        self,
        prompt: str,
        arguments: Mapping[str, object] | None = None,
        *,
        request: CapabilityRequest | None = None,
    ) -> McpDataResult:
        """Fetch a prompt as low-trust extension instruction context."""
        descriptor = self._find_capability(prompt, CapabilityKind.PROMPT)
        if descriptor is None:
            return self._data_failure(prompt, CapabilityKind.PROMPT, "unavailable", McpErrorCode.UNAVAILABLE, "MCP prompt is unavailable", trust_label="EXTENSION_INSTRUCTION")
        if self.state is not McpSessionState.READY:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "unavailable", McpErrorCode.UNAVAILABLE, f"MCP session is {self.state.value}", trust_label="EXTENSION_INSTRUCTION")
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, Mapping):
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.SCHEMA_INVALID, "MCP prompt arguments are not an object", trust_label="EXTENSION_INSTRUCTION")
        arguments = dict(arguments)
        try:
            arguments_valid = validate_arguments(dict(descriptor.input_schema), arguments)
        except (TypeError, ValueError):
            arguments_valid = False
        if not arguments_valid:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.SCHEMA_INVALID, "MCP prompt arguments do not match its schema", trust_label="EXTENSION_INSTRUCTION")
        if self.admission is None:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "denied", McpErrorCode.ADMISSION_DENIED, "no unified admission service is bound", trust_label="EXTENSION_INSTRUCTION")
        try:
            request = request or self._request_for(descriptor, arguments)
        except (TypeError, ValueError):
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.SCHEMA_INVALID, "prompt request is malformed", trust_label="EXTENSION_INSTRUCTION")
        if request.capability_id != descriptor.capability_id or dict(request.arguments) != arguments:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "stale", McpErrorCode.STALE, "prompt request is stale", trust_label="EXTENSION_INSTRUCTION")
        admission = await self.admission.admit(request)
        if not admission.admitted:
            status, code = _admission_failure(admission.status, admission.reason_code)
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, status, code, admission.reason, trust_label="EXTENSION_INSTRUCTION")
        binding = admission.binding
        if binding is None:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "stale", McpErrorCode.STALE, "admission did not produce an invocation binding", trust_label="EXTENSION_INSTRUCTION")
        if not self.admission.validate_invocation(binding, request).admitted:
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "stale", McpErrorCode.STALE, "prompt invocation is stale", trust_label="EXTENSION_INSTRUCTION")
        if not await self._acquire_task_slot():
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.LIMIT_EXCEEDED, "MCP in-flight task budget is exhausted", trust_label="EXTENSION_INSTRUCTION")
        request_bytes = len(canonical_json_bytes({"name": descriptor.name, "arguments": arguments}))
        budget_ok, budget_reason = await self._reserve_task_budget(request_bytes)
        if not budget_ok:
            self._task_slots.release()
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.LIMIT_EXCEEDED, budget_reason, trust_label="EXTENSION_INSTRUCTION")
        request_started = False
        try:
            async with self._calls:
                self._in_flight += 1
                request_started = True
                raw = await asyncio.wait_for(self._request("prompts/get", {"name": descriptor.name, "arguments": dict(arguments)}), timeout=self.limits.request_timeout_seconds)
            if not await self._charge_task_bytes(len(canonical_json_bytes(raw))):
                return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.LIMIT_EXCEEDED, "MCP task byte budget is exhausted", trust_label="EXTENSION_INSTRUCTION")
            raw = _unwrap_result(raw)
            data, size = _bounded_value(raw, self.limits.max_resource_bytes)
            return McpDataResult(descriptor.capability_id, CapabilityKind.PROMPT, "success", data=data, data_bytes=size, data_digest=canonical_digest(_thaw_json(data)), trust_label="EXTENSION_INSTRUCTION")
        except asyncio.CancelledError:
            try:
                await asyncio.shield(self._handle_transport_failure("MCP prompt fetch cancelled"))
            except (McpError, asyncio.CancelledError):
                pass
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.CANCELLED, "MCP prompt fetch was cancelled", trust_label="EXTENSION_INSTRUCTION")
        except TimeoutError:
            await self._handle_transport_failure("MCP prompt fetch timed out")
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", McpErrorCode.TIMEOUT, "MCP prompt fetch timed out", trust_label="EXTENSION_INSTRUCTION")
        except McpError as exc:
            await self._handle_transport_failure(str(exc))
            return self._data_failure(descriptor.capability_id, CapabilityKind.PROMPT, "failure", exc.code, str(exc), trust_label="EXTENSION_INSTRUCTION")
        finally:
            if request_started:
                self._in_flight -= 1
            self._task_slots.release()

    async def handle_notification(
        self,
        method: str,
        params: Mapping[str, object] | None = None,
    ) -> bool:
        """Re-discover a changed tool list before it can be invoked again.

        The transport owner may forward server notifications here.  A list
        change never mutates the canonical registry in place: changed
        capabilities first put this session into ``DEGRADED`` and require a
        normal close/restart handshake to publish a fresh available snapshot.
        """
        if method != "notifications/tools/list_changed":
            return False
        if params is not None and not isinstance(params, Mapping):
            await self._mark_degraded("MCP tool-list notification parameters are malformed")
            return False
        now = time.monotonic()
        cutoff = now - 60.0
        self._notification_times = [value for value in self._notification_times if value > cutoff]
        if len(self._notification_times) >= self.limits.max_notifications_per_minute:
            await self._mark_degraded("MCP notification rate limit exceeded")
            return False
        self._notification_times.append(now)
        if self.state is not McpSessionState.READY:
            return False
        previous = tuple(
            (item.capability_id, item.capability_digest)
            for item in self.capabilities
        )
        try:
            await self._discover_all()
        except McpError as exc:
            await self._handle_transport_failure(f"MCP tool-list revalidation failed: {exc}")
            return False
        current = tuple(
            (item.capability_id, item.capability_digest)
            for item in self.capabilities
        )
        if current == previous:
            return False
        await self._mark_degraded("MCP capability list changed; revalidation is required")
        return True

    async def _ensure_transport(self) -> None:
        if self.transport is not None:
            return
        if self.descriptor.transport is McpTransportKind.STDIO:
            if self.process_owner is None:
                raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio MCP requires an injected process owner")
            argv, environment = validate_stdio_configuration(
                self.descriptor,
                workspace_root=self.workspace_root,
            )
            self.transport = await self.process_owner.start_stdio(self.descriptor, argv, environment)
            self._process_transport_owned = True
            return
        if self.descriptor.transport in {McpTransportKind.HTTP, McpTransportKind.SSE}:
            if self.descriptor.transport is McpTransportKind.SSE:
                raise McpError(McpErrorCode.INVALID_CONFIGURATION, "SSE MCP transport requires a managed stream adapter")
            self.transport = HttpxMcpTransport(
                self.descriptor.transport_identity,
                limits=self.limits,
                host_checker=self.network_host_checker,
                network_authority=self.network_authority,
            )
            self._process_transport_owned = True
            return
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "MCP transport is not configured")

    async def _handshake(self) -> None:
        response = await self._request(
            "initialize",
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "khaos", "version": "0.1.0"},
            },
        )
        value = _unwrap_result(response)
        if not isinstance(value, Mapping):
            raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP initialize result is not an object")
        protocol_version = value.get("protocolVersion")
        if protocol_version not in SUPPORTED_MCP_PROTOCOL_VERSIONS:
            raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP protocol version is unsupported")
        capabilities = value.get("capabilities", {})
        if not isinstance(capabilities, Mapping):
            raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP server capabilities are malformed")
        server_info = value.get("serverInfo")
        if server_info is not None:
            if not isinstance(server_info, Mapping):
                raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP serverInfo is malformed")
            for field in ("name", "version"):
                field_value = server_info.get(field)
                if type(field_value) is not str or not field_value or len(field_value.encode("utf-8")) > 256:
                    raise McpError(McpErrorCode.HANDSHAKE_FAILED, "MCP serverInfo is malformed")
        if self.transport is not None:
            await self._notify("notifications/initialized", {})

    async def _notify(self, method: str, params: Mapping[str, object]) -> None:
        """Send a bounded notification through the owned transport."""
        now = time.monotonic()
        cutoff = now - 60.0
        self._notification_times = [value for value in self._notification_times if value > cutoff]
        if len(self._notification_times) >= self.limits.max_notifications_per_minute:
            raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP notification rate limit exceeded")
        self._notification_times.append(now)
        if self.transport is not None:
            await self.transport.notify(method, params)

    async def _discover_all(self) -> None:
        discovered: list[CapabilityDescriptor] = []
        for method, key, kind, maximum in (
            ("tools/list", "tools", CapabilityKind.TOOL, self.limits.max_tools),
            ("resources/list", "resources", CapabilityKind.RESOURCE, self.limits.max_resources),
            ("prompts/list", "prompts", CapabilityKind.PROMPT, self.limits.max_prompts),
        ):
            cursor: str | None = None
            cursors: set[str] = set()
            for _page in range(self.limits.max_pages):
                params: dict[str, object] = {}
                if cursor:
                    params["cursor"] = cursor
                response = await self._request(method, params)
                value = _unwrap_result(response)
                if not isinstance(value, Mapping):
                    raise McpError(McpErrorCode.PROTOCOL_ERROR, f"{method} result is not an object")
                entries = value.get(key, [])
                if not isinstance(entries, list):
                    raise McpError(McpErrorCode.PROTOCOL_ERROR, f"{method} list is malformed")
                for entry in entries:
                    if not isinstance(entry, Mapping):
                        raise McpError(McpErrorCode.PROTOCOL_ERROR, f"{method} entry is malformed")
                    capability = _capability_from_mcp_entry(self.descriptor, kind, entry)
                    discovered.append(capability)
                    if sum(item.kind is kind for item in discovered) > maximum:
                        raise McpError(McpErrorCode.LIMIT_EXCEEDED, f"{method} exceeds capability limit")
                next_cursor = value.get("nextCursor")
                if next_cursor is None:
                    break
                if type(next_cursor) is not str or not next_cursor or next_cursor in cursors or len(next_cursor) > 512:
                    raise McpError(McpErrorCode.PROTOCOL_ERROR, f"{method} cursor is invalid")
                cursors.add(next_cursor)
                cursor = next_cursor
            else:
                raise McpError(McpErrorCode.LIMIT_EXCEEDED, f"{method} page limit exceeded")
        by_id: dict[str, CapabilityDescriptor] = {}
        for capability in discovered:
            if capability.capability_id in by_id:
                raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP capability identity collision")
            by_id[capability.capability_id] = capability
        self._capabilities = by_id
        self._by_kind_name = {(CapabilityKind(str(item.kind)), item.name): item.capability_id for item in discovered}

    async def _publish_registry(self) -> None:
        if self.registry is None:
            return
        try:
            self.registry.discover(self.descriptor)
            self.registry.validate(self.descriptor.extension_id, self.capabilities)
            self.registry.mark_available(self.descriptor.extension_id)
        except (ExtensionRegistryError, ValueError) as exc:
            raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP capabilities failed registry validation") from exc

    async def _request(self, method: str, params: Mapping[str, object]) -> object:
        if self.transport is None:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "MCP transport is not open")
        if method in {"tools/call", "resources/read", "prompts/get"}:
            self._extension_calls += 1
            self._mcp_calls += 1
        try:
            response = await self.transport.request(method, params, timeout=self.limits.request_timeout_seconds)
        except McpError:
            raise
        except Exception as exc:
            raise McpError(McpErrorCode.TRANSPORT_FAILED, "MCP transport request failed") from exc
        try:
            encoded = canonical_json_bytes(response)
        except Exception as exc:
            raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP response is not JSON-safe") from exc
        if len(encoded) > self.limits.max_message_bytes:
            raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP response exceeds byte budget")
        return response

    async def _close_impl(self, *, reset_for_restart: bool = False) -> None:
        async with self._state_lock:
            if self.state is McpSessionState.CLOSED and not reset_for_restart:
                return
            self.state = McpSessionState.CLOSING
        transport = self.transport
        error: BaseException | None = None
        if transport is not None:
            try:
                await asyncio.shield(transport.close())
            except asyncio.CancelledError as exc:
                error = exc
            except Exception as exc:  # noqa: BLE001 - transport cleanup must enter quarantine
                error = exc
        if error is not None:
            # Keep the owner attached while cleanup is unproven.  Dropping the
            # handle here would make a later reconciliation unable to retry
            # termination and would create a false CLOSED/READY path.
            await self._mark_quarantined("MCP transport did not prove terminal cleanup")
            raise McpError(McpErrorCode.QUARANTINED, "MCP transport cleanup is unproven") from error
        self.transport = None
        self._process_transport_owned = False
        self.state = McpSessionState.NEW if reset_for_restart else McpSessionState.CLOSED
        await self._emit("mcp.disconnected", {"extension_id": self.descriptor.extension_id, "terminal": not reset_for_restart})
        if self.registry is not None:
            try:
                # A closed session must not leave its capabilities AVAILABLE;
                # a later invocation would otherwise bypass the transport
                # lifecycle fence.  Restart revalidates the disabled record
                # and explicitly publishes availability again.
                self.registry.disable(self.descriptor.extension_id, "MCP transport closed")
            except ExtensionRegistryError:
                pass

    async def _cleanup_start_failure(self) -> None:
        """Reclaim a partially started owner before exposing a failure."""
        transport = self.transport
        if transport is not None:
            try:
                await asyncio.shield(transport.close())
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - uncertain cleanup is quarantined
                await self._mark_quarantined("MCP startup cleanup is unproven")
                return
            self.transport = None
            self._process_transport_owned = False
        self.state = McpSessionState.DEGRADED
        if self.registry is not None:
            try:
                record = self.registry.get(self.descriptor.extension_id)
                if record.state not in {
                    ExtensionLifecycleState.DISABLED,
                    ExtensionLifecycleState.QUARANTINED,
                }:
                    self.registry.disable(self.descriptor.extension_id, "MCP startup failed")
            except ExtensionRegistryError:
                pass
        await self._emit("mcp.degraded", {"extension_id": self.descriptor.extension_id, "reason": "MCP startup failed"})

    async def _handle_transport_failure(self, reason: str) -> None:
        """Mark a failure and prove transport cleanup without false health."""
        await self._mark_degraded(reason)
        transport = self.transport
        if transport is None:
            return
        try:
            await asyncio.shield(transport.close())
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - uncertain cleanup remains quarantined
            await self._mark_quarantined("MCP transport failure cleanup is unproven")
            return
        self.transport = None
        self._process_transport_owned = False

    async def _acquire_task_slot(self) -> bool:
        """Acquire a bounded task slot without waiting indefinitely."""
        try:
            await asyncio.wait_for(
                self._task_slots.acquire(),
                timeout=self.limits.request_timeout_seconds,
            )
        except TimeoutError:
            return False
        return True

    async def _reserve_task_budget(self, request_bytes: int) -> tuple[bool, str]:
        """Reserve one invocation under task calls/bytes/wall-time limits."""
        async with self._task_budget_lock:
            if time.monotonic() - self._task_started_at > self.limits.max_wall_time_seconds:
                return False, "MCP task wall-time budget is exhausted"
            if self._task_calls >= self.limits.max_calls:
                return False, "MCP task call budget is exhausted"
            if self._task_bytes + request_bytes > self.limits.max_total_bytes:
                return False, "MCP task byte budget is exhausted"
            self._task_calls += 1
            self._task_bytes += request_bytes
            return True, ""

    async def _charge_task_bytes(self, response_bytes: int) -> bool:
        async with self._task_budget_lock:
            if self._task_bytes + response_bytes > self.limits.max_total_bytes:
                return False
            self._task_bytes += response_bytes
            return True

    async def _mark_degraded(self, reason: str = "MCP transport degraded") -> None:
        self.state = McpSessionState.DEGRADED
        if self.registry is not None:
            try:
                self.registry.mark_degraded(self.descriptor.extension_id, reason)
            except ExtensionRegistryError:
                pass
        await self._emit("mcp.degraded", {"extension_id": self.descriptor.extension_id, "reason": reason})

    async def _mark_quarantined(self, reason: str) -> None:
        self.state = McpSessionState.QUARANTINED
        if self.registry is not None:
            try:
                self.registry.quarantine(self.descriptor.extension_id, reason)
            except ExtensionRegistryError:
                pass
        await self._emit("mcp.quarantined", {"extension_id": self.descriptor.extension_id, "reason": reason})

    async def _emit(self, event: str, payload: Mapping[str, object]) -> None:
        if self.on_event is None:
            return
        value = self.on_event(event, payload)
        if asyncio.iscoroutine(value):
            await value

    def _find_capability(self, value: str, kind: CapabilityKind) -> CapabilityDescriptor | None:
        if value in self._capabilities and self._capabilities[value].kind is kind:
            return self._capabilities[value]
        capability_id = self._by_kind_name.get((kind, value))
        return self._capabilities.get(capability_id) if capability_id else None

    def _request_for(self, capability: CapabilityDescriptor, arguments: Mapping[str, object]) -> CapabilityRequest:
        return CapabilityRequest(
            capability_id=capability.capability_id,
            extension_id=self.descriptor.extension_id,
            task_id=self.task_id,
            principal_id=self.principal_id,
            project_id=self.project_id,
            workspace_id=self.workspace_id,
            workspace_generation=self.workspace_generation,
            arguments=dict(arguments),
            extension_digest=self.descriptor.descriptor_digest,
            capability_digest=capability.capability_digest,
            network_host=urlsplit(self.descriptor.transport_identity).hostname if self.descriptor.transport_identity else None,
        )

    def _result_from_raw(
        self,
        capability_id: str,
        raw: object,
        *,
        request_digest: str,
        binding_digest: str,
        output_schema: Mapping[str, object] | None = None,
    ) -> McpCallResult:
        try:
            value, size = _bounded_value(raw, self.limits.max_result_bytes)
        except McpError as exc:
            return self._failure(capability_id, exc.code, str(exc), "failure", request_digest=request_digest, binding_digest=binding_digest)
        sanitized, ignored = _strip_authority_fields(value)
        if output_schema is not None:
            try:
                output_valid = validate_arguments(output_schema, _thaw_json(sanitized))
            except (TypeError, ValueError):
                output_valid = False
            if not output_valid:
                return self._failure(
                    capability_id,
                    McpErrorCode.SCHEMA_INVALID,
                    "MCP tool output does not match its output schema",
                    "failure",
                    request_digest=request_digest,
                    binding_digest=binding_digest,
                )
        digest = canonical_digest(_thaw_json(sanitized))
        return McpCallResult(
            capability_id=capability_id,
            status="success",
            output=sanitized,
            output_bytes=size,
            output_digest=digest,
            request_digest=request_digest,
            binding_digest=binding_digest,
            ignored_authority_fields=tuple(sorted(ignored)),
        )

    def _failure(self, capability_id: str, code: McpErrorCode, summary: str, status: str, *, request_digest: str = "", binding_digest: str = "") -> McpCallResult:
        self._mcp_failures += 1
        return McpCallResult(capability_id=capability_id, status=status, error_code=code.value, error_summary=summary, request_digest=request_digest, binding_digest=binding_digest)

    def _data_failure(
        self,
        capability_id: str,
        kind: CapabilityKind,
        status: str,
        code: McpErrorCode,
        summary: str,
        *,
        trust_label: str = "",
    ) -> McpDataResult:
        self._mcp_failures += 1
        return McpDataResult(
            capability_id,
            kind,
            status,
            error_code=code.value,
            error_summary=summary,
            trust_label=trust_label,
        )


def _admission_failure(
    status: AdmissionStatus | str,
    reason_code: str,
) -> tuple[str, McpErrorCode]:
    """Map admission outcomes to stable MCP-facing, non-authoritative errors."""
    try:
        admission_status = AdmissionStatus(str(status))
    except ValueError:
        admission_status = AdmissionStatus.UNAVAILABLE
    if reason_code in {item.value for item in McpErrorCode}:
        return (
            "quarantined" if admission_status is AdmissionStatus.QUARANTINED else "stale" if admission_status is AdmissionStatus.STALE else "denied",
            McpErrorCode(reason_code),
        )
    if admission_status is AdmissionStatus.REQUIRES_APPROVAL:
        return "denied", McpErrorCode.APPROVAL_REQUIRED
    if admission_status is AdmissionStatus.DENIED:
        return "denied", McpErrorCode.POLICY_DENIED
    if admission_status is AdmissionStatus.STALE:
        return "stale", McpErrorCode.STALE
    if admission_status is AdmissionStatus.QUARANTINED:
        return "quarantined", McpErrorCode.QUARANTINED
    return "unavailable", McpErrorCode.UNAVAILABLE


def validate_mcp_endpoint(endpoint: str, *, allow_private: bool = False) -> str:
    """Normalize an MCP HTTP endpoint and reject common SSRF targets."""
    if type(endpoint) is not str or not endpoint or len(endpoint.encode("utf-8")) > 8192 or "\x00" in endpoint:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint is malformed")
    parsed = urlsplit(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint scheme or authority is invalid")
    host = parsed.hostname.casefold().rstrip(".")
    try:
        address = ipaddress.ip_address(host)
        special = address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast
    except ValueError:
        special = host == "localhost" or host.endswith((".localhost", ".local"))
        if any(not label or len(label) > 63 for label in host.split(".")):
            raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint hostname is invalid")
    if special and not allow_private:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint targets a private or special address")
    try:
        port = parsed.port
    except ValueError as exc:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint port is invalid") from exc
    if port is not None and not 1 <= port <= 65535:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP endpoint port is invalid")
    return endpoint


def validate_redirect(original_endpoint: str, redirect_endpoint: str, *, allow_private: bool = False) -> str:
    """Validate redirects as fresh endpoints; no implicit same-host trust."""
    original = validate_mcp_endpoint(original_endpoint, allow_private=allow_private)
    redirected = validate_mcp_endpoint(redirect_endpoint, allow_private=allow_private)
    original_scheme = urlsplit(original).scheme.casefold()
    redirected_scheme = urlsplit(redirected).scheme.casefold()
    if original_scheme == "https" and redirected_scheme != "https":
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP redirect cannot downgrade HTTPS")
    original_host = (urlsplit(original).hostname or "").casefold().rstrip(".")
    redirected_host = (urlsplit(redirected).hostname or "").casefold().rstrip(".")
    if original_host != redirected_host:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP redirect changes host without explicit validation")
    return redirected


def validate_resource_uri(uri: str) -> str:
    """Validate an MCP resource identifier without authorizing host paths."""
    if type(uri) is not str or not uri or "\x00" in uri or len(uri.encode("utf-8")) > 4096:
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP resource URI is malformed")
    if any(ord(character) < 0x20 for character in uri):
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP resource URI contains a control character")
    parsed = urlsplit(uri)
    if parsed.scheme.casefold() in {"file", "data", "javascript"} or parsed.username or parsed.password:
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP resource URI uses a forbidden scheme or authority")
    if any(segment == ".." for segment in parsed.path.split("/")):
        raise McpError(McpErrorCode.ENDPOINT_DENIED, "MCP resource URI attempts path traversal")
    return uri


def validate_stdio_configuration(
    descriptor: ExtensionDescriptor,
    *,
    workspace_root: Path | None = None,
) -> tuple[tuple[str, ...], dict[str, str]]:
    """Validate a local command before handing it to the process owner."""
    if descriptor.transport is not McpTransportKind.STDIO:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio configuration used for another transport")
    config = descriptor.config
    raw_argv = config.get("argv")
    if not isinstance(raw_argv, (list, tuple)) or not raw_argv or len(raw_argv) > 64:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio argv must be a bounded non-empty list")
    argv = tuple(raw_argv)
    if any(type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > 4096 for value in argv):
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio argv contains an invalid value")
    executable = Path(argv[0])
    if not executable.is_absolute() or not executable.exists() or not executable.is_file():
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio argv[0] must be an existing absolute executable")
    try:
        info = executable.stat()
    except OSError as exc:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable cannot be inspected") from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(executable, os.X_OK):
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio argv[0] is not executable")
    canonical = executable.resolve()
    if workspace_root is not None:
        root = workspace_root.resolve()
        if canonical == root or root in canonical.parents:
            raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable is inside the model-writable workspace")
    if canonical.name.casefold() in {"npx", "pnpx", "uvx", "pipx", "bunx"}:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "package-manager launchers are not implicit MCP executables")
    if config.get("shell") is True:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio shell execution is forbidden")
    raw_env = config.get("env", {})
    if not isinstance(raw_env, Mapping) or len(raw_env) > 128:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio environment is malformed")
    if any(type(key) is not str or type(value) is not str or len(key) > 256 or len(value) > 4096 for key, value in raw_env.items()):
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio environment contains an invalid value")
    forbidden_environment = {
        "PATH", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "KHAOS_GATEWAY_CAPABILITY",
        "KHAOS_PYTHON_CAPABILITY", "KHAOS_AGENT_CAPABILITY",
    }
    if any(str(key).upper() in forbidden_environment for key in raw_env):
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio environment contains a launch or authority variable")
    environment = scrub_spawn_environment(dict(raw_env))
    source = descriptor.source if isinstance(descriptor.source, ExtensionSource) else ExtensionSource(str(descriptor.source))
    derived_artifact = canonical_digest(
        {
            "source": source.to_payload(),
            "name": descriptor.name,
            "version": descriptor.version,
        }
    )
    if descriptor.artifact_digest == derived_artifact:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable requires an explicit artifact digest")
    if _digest_file(canonical) != descriptor.artifact_digest:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable identity has drifted")
    return (str(canonical), *argv[1:]), environment


def _digest_file(path: Path) -> str:
    """Hash a bounded regular executable through a no-follow descriptor."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable cannot be opened") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 * 1024:
            raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable exceeds its identity bound")
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        final_info = os.fstat(descriptor)
        if not stat.S_ISREG(final_info.st_mode) or final_info.st_size != info.st_size:
            raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable changed while hashing")
        return digest.hexdigest()
    except OSError as exc:
        raise McpError(McpErrorCode.INVALID_CONFIGURATION, "stdio executable could not be hashed") from exc
    finally:
        os.close(descriptor)


def _unwrap_result(response: object) -> object:
    if not isinstance(response, Mapping):
        return response
    if response.get("jsonrpc") == "2.0":
        if "error" in response:
            raise McpError(McpErrorCode.SERVER_ERROR, "MCP server returned a JSON-RPC error")
        if "result" not in response:
            raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP JSON-RPC response has no result")
        return response["result"]
    return response


def _capability_from_mcp_entry(
    descriptor: ExtensionDescriptor,
    kind: CapabilityKind,
    entry: Mapping[str, object],
) -> CapabilityDescriptor:
    name_key = "uri" if kind is CapabilityKind.RESOURCE else "name"
    name = entry.get(name_key)
    if type(name) is not str or not name or len(name.encode("utf-8")) > 256:
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP capability name is malformed")
    cap_id = f"mcp:{descriptor.extension_id}:{kind.value.casefold()}:{hashlib.sha256(name.encode('utf-8')).hexdigest()[:20]}"
    if kind is CapabilityKind.RESOURCE:
        name = validate_resource_uri(name)
    description = entry.get("description", "")
    if type(description) is not str:
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP capability description is malformed")
    schema = entry.get("inputSchema", {"type": "object", "properties": {}, "required": [], "additionalProperties": False})
    if not isinstance(schema, Mapping):
        raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP inputSchema is malformed")
    output_schema = entry.get("outputSchema")
    if output_schema is not None:
        if not isinstance(output_schema, Mapping):
            raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP outputSchema is malformed")
        try:
            validate_external_schema(output_schema, path="capability.output_schema")
        except ValueError as exc:
            raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP outputSchema failed validation") from exc
    raw_effects = entry.get("effects", [])
    if not isinstance(raw_effects, list):
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP effects declaration is malformed")
    effects: list[EffectKind] = []
    known = {item.value: item for item in EffectKind}
    for value in raw_effects:
        if type(value) is not str or value not in known:
            raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP capability declares an unknown effect")
        effects.append(known[value])
    metadata = {key: entry[key] for key in ("title", "annotations") if key in entry}
    try:
        return CapabilityDescriptor(
            capability_id=cap_id,
            extension_id=descriptor.extension_id,
            kind=kind,
            name=name,
            description=description,
            input_schema=dict(schema),
            output_schema=dict(output_schema) if output_schema is not None else None,
            effects=tuple(effects),
            resource_uri=name if kind is CapabilityKind.RESOURCE else None,
            prompt_name=name if kind is CapabilityKind.PROMPT else None,
            metadata=metadata,
        )
    except ValueError as exc:
        raise McpError(McpErrorCode.SCHEMA_INVALID, "MCP capability schema failed validation") from exc


def _bounded_value(value: object, maximum: int) -> tuple[object, int]:
    try:
        encoded = canonical_json_bytes(value)
    except Exception as exc:
        raise McpError(McpErrorCode.PROTOCOL_ERROR, "MCP value is not JSON-safe") from exc
    if len(encoded) > maximum:
        raise McpError(McpErrorCode.LIMIT_EXCEEDED, "MCP value exceeds its byte budget")
    return _freeze_json(value), len(encoded)


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(child) for key, child in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(child) for child in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(child) for child in value)
    return value


def _thaw_json(value: object) -> object:
    """Convert immutable transport projections back to JSON values."""
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw_json(child) for child in value]
    return value


def _strip_authority_fields(value: object, *, path: str = "result") -> tuple[object, set[str]]:
    ignored: set[str] = set()
    if isinstance(value, Mapping):
        result: dict[str, object] = {}
        for key, child in value.items():
            name = str(key)
            if name.casefold() in {"approval_granted", "completed", "completion_authority", "sandbox", "trusted", "verified", "verification_passed"}:
                ignored.add(f"{path}.{name}")
                continue
            cleaned, child_ignored = _strip_authority_fields(child, path=f"{path}.{name}")
            ignored.update(child_ignored)
            result[name] = cleaned
        return MappingProxyType(result), ignored
    if isinstance(value, (tuple, list)):
        values: list[object] = []
        for index, child in enumerate(value):
            cleaned, child_ignored = _strip_authority_fields(child, path=f"{path}[{index}]")
            ignored.update(child_ignored)
            values.append(cleaned)
        return tuple(values), ignored
    return value, ignored


__all__ = [
    "MCP_PROTOCOL_VERSION",
    "SUPPORTED_MCP_PROTOCOL_VERSIONS",
    "HttpxMcpTransport",
    "McpCallResult",
    "McpDataResult",
    "McpError",
    "McpErrorCode",
    "McpLimits",
    "McpProcessOwner",
    "McpServerSession",
    "McpSessionState",
    "McpTransport",
    "ScriptedMcpTransport",
    "validate_mcp_endpoint",
    "validate_redirect",
    "validate_resource_uri",
    "validate_stdio_configuration",
]
