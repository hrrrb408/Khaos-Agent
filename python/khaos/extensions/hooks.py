"""Bounded Hook observation/advice dispatch for the extension plane."""

from __future__ import annotations

import asyncio
import contextvars
import inspect
import logging
import math
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from threading import RLock
from types import MappingProxyType

from khaos.extensions.admission import CapabilityAdmissionService
from khaos.extensions.contracts import (
    AdmissionStatus,
    CapabilityRequest,
    ExtensionProvenance,
)
from khaos.security.protocol_boundary import canonical_digest, canonical_json_bytes

logger = logging.getLogger(__name__)

MAX_HOOK_EVENT_BYTES = 32 * 1024
MAX_HOOK_PAYLOAD_KEYS = 128
MAX_HOOK_RESULT_BYTES = 32 * 1024
MAX_HOOKS_PER_EVENT = 64
MAX_HOOK_TOOL_REQUESTS = 16


class HookMode(StrEnum):
    """Hook authority posture; blocking is opt-in and fail-closed."""

    OBSERVE = "OBSERVE"
    ADVISE = "ADVISE"
    BLOCKING = "BLOCKING"


class HookResultStatus(StrEnum):
    """Independent annotation outcome, not a task authority state."""

    CONTINUE = "CONTINUE"
    ADVICE = "ADVICE"
    BLOCKED = "BLOCKED"
    FAILED = "FAILED"


@dataclass(frozen=True, slots=True)
class HookEvent:
    """Immutable event projection delivered to a Hook."""

    event_id: str
    event_type: str
    task_id: str
    principal_id: str
    project_id: str
    workspace_id: str = ""
    sequence: int = 0
    payload: Mapping[str, object] = field(default_factory=dict, repr=False)
    causal_chain_id: str = ""
    parent_event_id: str | None = None
    depth: int = 0

    def __post_init__(self) -> None:
        for name in ("event_id", "event_type", "task_id", "principal_id", "project_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > 256:
                raise ValueError(f"hook event {name} is invalid")
        if type(self.workspace_id) is not str or len(self.workspace_id.encode("utf-8")) > 256:
            raise ValueError("hook event workspace_id is invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("hook event sequence is invalid")
        if type(self.depth) is not int or self.depth < 0 or self.depth > 1:
            raise ValueError("hook event depth exceeds the recursion bound")
        if self.causal_chain_id == "":
            object.__setattr__(self, "causal_chain_id", self.event_id)
        elif type(self.causal_chain_id) is not str or len(self.causal_chain_id) > 256:
            raise ValueError("hook causal chain id is invalid")
        if self.parent_event_id is not None and (type(self.parent_event_id) is not str or len(self.parent_event_id) > 256):
            raise ValueError("hook parent event id is invalid")
        payload = dict(self.payload)
        if len(payload) > MAX_HOOK_PAYLOAD_KEYS:
            raise ValueError("hook event payload has too many keys")
        _validate_projection(payload)
        if len(canonical_json_bytes(payload)) > MAX_HOOK_EVENT_BYTES:
            raise ValueError("hook event payload exceeds its bound")
        object.__setattr__(self, "payload", _freeze_projection(payload))

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_payload())

    def to_payload(self) -> dict[str, object]:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "task_id": self.task_id,
            "principal_id": self.principal_id,
            "project_id": self.project_id,
            "workspace_id": self.workspace_id,
            "sequence": self.sequence,
            "payload": _thaw_projection(self.payload),
            "causal_chain_id": self.causal_chain_id,
            "parent_event_id": self.parent_event_id,
            "depth": self.depth,
        }


@dataclass(frozen=True, slots=True)
class HookDescriptor:
    """Declarative hook registration metadata."""

    hook_id: str
    extension_id: str
    mode: HookMode | str
    event_types: tuple[str, ...]
    provenance: ExtensionProvenance | str = ExtensionProvenance.LOCAL_TRUSTED_CONFIG
    timeout_seconds: float = 2.0
    max_result_bytes: int = MAX_HOOK_RESULT_BYTES
    enabled: bool = True
    descriptor_digest: str = ""

    def __post_init__(self) -> None:
        for name in ("hook_id", "extension_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value.encode("utf-8")) > 256:
                raise ValueError(f"hook {name} is invalid")
        object.__setattr__(self, "mode", HookMode(str(self.mode)))
        values = tuple(sorted(set(self.event_types)))
        if not values or any(type(value) is not str or not value or len(value) > 128 for value in values):
            raise ValueError("hook event types are invalid")
        object.__setattr__(self, "event_types", values)
        object.__setattr__(self, "provenance", ExtensionProvenance(str(self.provenance)))
        if (
            type(self.timeout_seconds) not in {int, float}
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 60
        ):
            raise ValueError("hook timeout is outside its bound")
        if type(self.max_result_bytes) is not int or not 256 <= self.max_result_bytes <= MAX_HOOK_RESULT_BYTES:
            raise ValueError("hook result budget is invalid")
        if type(self.enabled) is not bool:
            raise ValueError("hook enabled must be boolean")
        expected = canonical_digest(self._payload(include_digest=False))
        if self.descriptor_digest and self.descriptor_digest != expected:
            raise ValueError("hook descriptor digest does not match metadata")
        object.__setattr__(self, "descriptor_digest", expected)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "hook_id": self.hook_id,
            "extension_id": self.extension_id,
            "mode": str(self.mode),
            "event_types": list(self.event_types),
            "provenance": str(self.provenance),
            "timeout_seconds": self.timeout_seconds,
            "max_result_bytes": self.max_result_bytes,
            "enabled": self.enabled,
        }
        if include_digest:
            payload["descriptor_digest"] = self.descriptor_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


@dataclass(frozen=True, slots=True)
class HookToolRequest:
    """A requested tool effect that must pass normal capability admission."""

    capability_id: str
    arguments: Mapping[str, object] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if type(self.capability_id) is not str or not self.capability_id or len(self.capability_id) > 256:
            raise ValueError("hook tool request capability id is invalid")
        values = dict(self.arguments)
        _validate_projection(values, reject_authority=True)
        if len(canonical_json_bytes(values)) > 128 * 1024:
            raise ValueError("hook tool request arguments exceed their bound")
        object.__setattr__(self, "arguments", _freeze_projection(values))


@dataclass(frozen=True, slots=True)
class HookResult:
    """Typed Hook output with no verification/completion/approval fields."""

    status: HookResultStatus | str = HookResultStatus.CONTINUE
    annotation: str = ""
    suggestions: tuple[str, ...] = ()
    tool_requests: tuple[HookToolRequest, ...] = ()
    ignored_fields: tuple[str, ...] = ()
    output_digest: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", HookResultStatus(str(self.status)))
        if type(self.annotation) is not str or len(self.annotation.encode("utf-8")) > 4096:
            raise ValueError("hook annotation is invalid")
        suggestions = tuple(self.suggestions)
        if len(suggestions) > 32 or any(type(item) is not str or len(item.encode("utf-8")) > 1024 for item in suggestions):
            raise ValueError("hook suggestions exceed their bound")
        object.__setattr__(self, "suggestions", suggestions)
        requests = tuple(self.tool_requests)
        if len(requests) > MAX_HOOK_TOOL_REQUESTS or any(type(item) is not HookToolRequest for item in requests):
            raise ValueError("hook tool requests exceed their bound")
        object.__setattr__(self, "tool_requests", requests)
        ignored = tuple(sorted(set(self.ignored_fields)))
        object.__setattr__(self, "ignored_fields", ignored)
        if self.output_digest and (len(self.output_digest) != 64 or any(character not in "0123456789abcdef" for character in self.output_digest)):
            raise ValueError("hook output digest is invalid")

    def to_payload(self) -> dict[str, object]:
        return {
            "status": str(self.status),
            "annotation": self.annotation,
            "suggestions": list(self.suggestions),
            "tool_requests": [
                {"capability_id": item.capability_id, "arguments_digest": canonical_digest(_thaw_projection(item.arguments))}
                for item in self.tool_requests
            ],
            "ignored_fields": list(self.ignored_fields),
            "output_digest": self.output_digest,
        }


@dataclass(frozen=True, slots=True)
class HookFailure:
    """Bounded failure record; observer/advice failures do not block the task."""

    hook_id: str
    code: str
    summary: str
    blocking: bool


@dataclass(frozen=True, slots=True)
class HookInvocation:
    """One causal hook invocation projection."""

    hook_id: str
    event_id: str
    causal_chain_id: str
    depth: int
    status: HookResultStatus
    result_digest: str = ""
    extension_id: str = ""

    def __post_init__(self) -> None:
        for name in ("hook_id", "event_id", "causal_chain_id"):
            value = getattr(self, name)
            if type(value) is not str or not value or "\x00" in value or len(value.encode("utf-8")) > 256:
                raise ValueError(f"hook invocation {name} is invalid")
        if self.extension_id and ("\x00" in self.extension_id or len(self.extension_id.encode("utf-8")) > 256):
            raise ValueError("hook invocation extension_id is invalid")
        if type(self.depth) is not int or self.depth < 0 or self.depth > 1:
            raise ValueError("hook invocation depth exceeds its bound")
        object.__setattr__(self, "status", HookResultStatus(str(self.status)))
        if self.result_digest and (len(self.result_digest) != 64 or any(character not in "0123456789abcdef" for character in self.result_digest)):
            raise ValueError("hook invocation result digest is invalid")


@dataclass(frozen=True, slots=True)
class HookDispatchReport:
    """Complete bounded dispatch projection for supervision/context."""

    event_id: str
    invocations: tuple[HookInvocation, ...] = ()
    results: tuple[HookResult, ...] = ()
    failures: tuple[HookFailure, ...] = ()
    blocked: bool = False
    storm_limited: bool = False

    @property
    def continued(self) -> bool:
        return not self.blocked


HookHandler = Callable[[HookEvent], object | Awaitable[object]]


class HookDispatcher:
    """Deterministic, bounded dispatcher with no direct effect path."""

    def __init__(
        self,
        *,
        admission: CapabilityAdmissionService | None = None,
        max_hooks_per_event: int = MAX_HOOKS_PER_EVENT,
        max_chain_depth: int = 1,
    ) -> None:
        if max_hooks_per_event <= 0 or max_hooks_per_event > MAX_HOOKS_PER_EVENT:
            raise ValueError("max_hooks_per_event is invalid")
        if max_chain_depth != 1:
            raise ValueError("Hook recursion depth must be exactly 1")
        self.admission = admission
        self.max_hooks_per_event = max_hooks_per_event
        self.max_chain_depth = max_chain_depth
        self._hooks: dict[str, tuple[HookDescriptor, HookHandler]] = {}
        self._active: set[tuple[str, str]] = set()
        self._lock = RLock()
        self._chain_depth: contextvars.ContextVar[int] = contextvars.ContextVar("khaos_hook_depth", default=0)
        self._hook_invocations = 0
        self._hook_failures = 0

    def metrics_snapshot(self) -> dict[str, int]:
        """Return bounded Hook counters without callback output."""
        with self._lock:
            return {
                "extension_calls": 0,
                "mcp_calls": 0,
                "mcp_failures": 0,
                "hook_invocations": self._hook_invocations,
                "hook_failures": self._hook_failures,
            }

    def register(self, descriptor: HookDescriptor, handler: HookHandler) -> None:
        """Register declarative metadata plus an already-owned callback."""
        if type(descriptor) is not HookDescriptor or not callable(handler):
            raise TypeError("hook registration is malformed")
        if descriptor.mode is HookMode.BLOCKING and descriptor.provenance not in {
            ExtensionProvenance.BUILTIN,
            ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
        }:
            raise ValueError("blocking hooks require builtin or trusted-config provenance")
        with self._lock:
            if descriptor.hook_id in self._hooks:
                raise ValueError("hook id is already registered")
            self._hooks[descriptor.hook_id] = (descriptor, handler)

    def disable(self, hook_id: str) -> None:
        """Disable future hook work; running callbacks are not retroactively undone."""
        with self._lock:
            registration = self._hooks.get(hook_id)
            if registration is None:
                return
            descriptor, handler = registration
            self._hooks[hook_id] = (HookDescriptor(
                hook_id=descriptor.hook_id,
                extension_id=descriptor.extension_id,
                mode=descriptor.mode,
                event_types=descriptor.event_types,
                provenance=descriptor.provenance,
                timeout_seconds=descriptor.timeout_seconds,
                max_result_bytes=descriptor.max_result_bytes,
                enabled=False,
            ), handler)

    async def dispatch(self, event: HookEvent) -> HookDispatchReport:
        """Run matching hooks in stable order under one causal-depth fence."""
        with self._lock:
            registrations = [
                registration
                for registration in self._hooks.values()
                if registration[0].enabled and event.event_type in registration[0].event_types
            ]
        registrations.sort(key=lambda item: item[0].hook_id)
        storm_limited = len(registrations) > self.max_hooks_per_event
        registrations = registrations[: self.max_hooks_per_event]
        if self._chain_depth.get() >= self.max_chain_depth:
            with self._lock:
                self._hook_failures += len(registrations)
            return HookDispatchReport(event_id=event.event_id, storm_limited=True)
        with self._lock:
            self._hook_invocations += len(registrations)
        token = self._chain_depth.set(self._chain_depth.get() + 1)
        invocations: list[HookInvocation] = []
        results: list[HookResult] = []
        failures: list[HookFailure] = []
        blocked = False
        try:
            for descriptor, handler in registrations:
                key = (descriptor.hook_id, event.causal_chain_id)
                with self._lock:
                    already_active = key in self._active
                    if not already_active:
                        self._active.add(key)
                if already_active:
                    failures.append(HookFailure(descriptor.hook_id, "reentrant", "hook re-entry was suppressed", descriptor.mode is HookMode.BLOCKING))
                    blocked = blocked or descriptor.mode is HookMode.BLOCKING
                    continue
                try:
                    try:
                        raw = handler(event)
                        if inspect.isawaitable(raw):
                            raw = await asyncio.wait_for(raw, timeout=descriptor.timeout_seconds)
                        result = _normalize_result(raw, max_bytes=descriptor.max_result_bytes)
                    except TimeoutError:
                        failures.append(HookFailure(descriptor.hook_id, "timeout", "hook exceeded its time budget", descriptor.mode is HookMode.BLOCKING))
                        blocked = blocked or descriptor.mode is HookMode.BLOCKING
                        continue
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:  # noqa: BLE001 - third-party hook failures are typed and isolated
                        logger.debug("extension hook failed: %s", type(exc).__name__)
                        failures.append(HookFailure(descriptor.hook_id, "failed", "hook failed without exposing its exception", descriptor.mode is HookMode.BLOCKING))
                        blocked = blocked or descriptor.mode is HookMode.BLOCKING
                        continue
                    if descriptor.mode is HookMode.OBSERVE:
                        result = HookResult(status=HookResultStatus.CONTINUE, annotation=result.annotation, suggestions=result.suggestions, ignored_fields=result.ignored_fields, output_digest=result.output_digest)
                        result = _with_result_digest(result)
                    elif descriptor.mode is HookMode.ADVISE:
                        if result.status is HookResultStatus.BLOCKED:
                            result = HookResult(status=HookResultStatus.ADVICE, annotation=result.annotation, suggestions=result.suggestions, tool_requests=result.tool_requests, ignored_fields=result.ignored_fields, output_digest=result.output_digest)
                            result = _with_result_digest(result)
                    elif result.status is HookResultStatus.BLOCKED:
                        blocked = True
                    elif result.status is HookResultStatus.FAILED:
                        failures.append(HookFailure(descriptor.hook_id, "reported_failure", result.annotation or "blocking hook reported failure", True))
                        blocked = True
                    results.append(result)
                    invocations.append(HookInvocation(
                        descriptor.hook_id,
                        event.event_id,
                        event.causal_chain_id,
                        event.depth,
                        HookResultStatus(str(result.status)),
                        result.output_digest,
                        descriptor.extension_id,
                    ))
                    if result.tool_requests:
                        requests_admitted = await self._admit_tool_requests(event, descriptor, result.tool_requests, failures)
                        if descriptor.mode is HookMode.BLOCKING and not requests_admitted:
                            blocked = True
                finally:
                    with self._lock:
                        self._active.discard(key)
        finally:
            self._chain_depth.reset(token)
        with self._lock:
            self._hook_failures += len(failures)
        return HookDispatchReport(
            event_id=event.event_id,
            invocations=tuple(invocations),
            results=tuple(results),
            failures=tuple(failures),
            blocked=blocked,
            storm_limited=storm_limited,
        )

    async def _admit_tool_requests(
        self,
        event: HookEvent,
        descriptor: HookDescriptor,
        requests: Sequence[HookToolRequest],
        failures: list[HookFailure],
    ) -> bool:
        if self.admission is None:
            failures.append(HookFailure(descriptor.hook_id, "admission_unavailable", "hook tool requests were not executed because unified admission is unavailable", descriptor.mode is HookMode.BLOCKING))
            return False
        admitted = True
        for request in requests[:MAX_HOOK_TOOL_REQUESTS]:
            try:
                admission_request = CapabilityRequest(
                    capability_id=request.capability_id,
                    task_id=event.task_id,
                    principal_id=event.principal_id,
                    project_id=event.project_id,
                    workspace_id=event.workspace_id,
                    arguments=dict(request.arguments),
                )
                result = await self.admission.admit(admission_request)
                if result.status is not AdmissionStatus.ADMITTED:
                    admitted = False
                    failures.append(HookFailure(descriptor.hook_id, "tool_request_not_admitted", f"hook tool request was {result.status!s}", descriptor.mode is HookMode.BLOCKING))
            except (TypeError, ValueError):
                admitted = False
                failures.append(HookFailure(descriptor.hook_id, "tool_request_invalid", "hook tool request was malformed", descriptor.mode is HookMode.BLOCKING))
        return admitted


def _normalize_result(value: object, *, max_bytes: int) -> HookResult:
    if isinstance(value, HookResult):
        if len(canonical_json_bytes(value.to_payload())) > max_bytes:
            raise ValueError("hook result exceeds its byte budget")
        return _with_result_digest(value)
    if value is None:
        return HookResult()
    if not isinstance(value, Mapping):
        raise TypeError("hook result must be an object")
    ignored = [str(key) for key in value if str(key).casefold() in {"approval_granted", "completed", "completion_authority", "trusted", "verified", "verification_passed"}]
    annotation = value.get("annotation", value.get("message", ""))
    suggestions = value.get("suggestions", ())
    raw_requests = value.get("tool_requests", ())
    if not isinstance(suggestions, (list, tuple)) or not isinstance(raw_requests, (list, tuple)):
        raise TypeError("hook result collections are malformed")
    requests = tuple(
        item if isinstance(item, HookToolRequest) else HookToolRequest(
            capability_id=item.get("capability_id", "") if isinstance(item, Mapping) else "",
            arguments=item.get("arguments", {}) if isinstance(item, Mapping) else {},
        )
        for item in raw_requests[:MAX_HOOK_TOOL_REQUESTS]
    )
    status = value.get("status", HookResultStatus.CONTINUE.value)
    result = HookResult(
        status=status,
        annotation=str(annotation) if annotation is not None else "",
        suggestions=tuple(str(item) for item in suggestions[:32]),
        tool_requests=requests,
        ignored_fields=tuple(ignored),
    )
    if len(canonical_json_bytes(result.to_payload())) > max_bytes:
        raise ValueError("hook result exceeds its byte budget")
    return _with_result_digest(result)


def _with_result_digest(result: HookResult) -> HookResult:
    """Derive output identity from the sanitized result, never provider claims."""
    payload = result.to_payload()
    payload["output_digest"] = ""
    return replace(result, output_digest=canonical_digest(payload))


def _freeze_projection(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_projection(child) for key, child in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_projection(child) for child in value)
    return value


def _thaw_projection(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_projection(child) for key, child in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_projection(child) for child in value]
    return value


def _validate_projection(value: object, *, reject_authority: bool = False, path: str = "payload") -> None:
    forbidden = {"content", "diff", "patch", "prompt", "source", "stdout", "stderr", "transcript", "model_output"}
    if reject_authority:
        forbidden |= {"approval_granted", "completed", "completion_authority", "sandbox", "trusted", "verified", "verification_passed"}
    if isinstance(value, Mapping):
        for key, child in value.items():
            if type(key) is not str:
                raise ValueError(f"{path} has a non-text key")
            if key.casefold() in forbidden:
                raise ValueError(f"{path}.{key} is not allowed in a Hook projection")
            _validate_projection(child, reject_authority=reject_authority, path=f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _validate_projection(child, reject_authority=reject_authority, path=f"{path}[{index}]")
    elif value is None or type(value) in {str, int, float, bool}:
        return
    else:
        raise ValueError(f"{path} is not JSON-compatible")


__all__ = [
    "HookDescriptor",
    "HookDispatchReport",
    "HookDispatcher",
    "HookEvent",
    "HookFailure",
    "HookHandler",
    "HookInvocation",
    "HookMode",
    "HookResult",
    "HookResultStatus",
    "HookToolRequest",
]
