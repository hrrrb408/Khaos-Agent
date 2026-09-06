"""Unified, policy-bound admission for all extension capabilities."""

from __future__ import annotations

import inspect
import ipaddress
import uuid
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit

from khaos.extensions.contracts import (
    AdmissionStatus,
    CapabilityAdmissionResult,
    CapabilityRequest,
    EffectiveCapability,
    EffectKind,
    ExtensionLifecycleState,
    ExtensionProvenance,
    InvocationBinding,
    structural_effects,
)
from khaos.extensions.registry import ExtensionRegistry, ExtensionRegistryError
from khaos.security.protocol_boundary import canonical_digest


class CapabilityAdmissionError(RuntimeError):
    """Raised only for malformed service wiring, never for user denial."""


ApprovalChecker = Callable[[CapabilityRequest, frozenset[EffectKind]], bool | Awaitable[bool]]


@dataclass(frozen=True, slots=True)
class ExtensionPolicy:
    """Effective policy projection consumed by extension admission.

    Empty allowlists mean "no additional restriction" only for extension IDs
    and effects.  Network hosts and credential names are deliberately
    fail-closed: a capability with either effect must have an explicit,
    owner-scoped allowlist entry.
    """

    allowed_extension_ids: frozenset[str] = frozenset()
    denied_extension_ids: frozenset[str] = frozenset()
    allowed_provenance: frozenset[ExtensionProvenance | str] = frozenset({
        ExtensionProvenance.BUILTIN,
        ExtensionProvenance.LOCAL_TRUSTED_CONFIG,
        ExtensionProvenance.REMOTE_CONFIGURED,
    })
    allowed_effects: frozenset[EffectKind | str] = frozenset()
    denied_effects: frozenset[EffectKind | str] = frozenset()
    require_approval_effects: frozenset[EffectKind | str] = frozenset({
        EffectKind.WRITE_WORKSPACE,
        EffectKind.EXECUTE_PROCESS,
        EffectKind.NETWORK,
        EffectKind.READ_CREDENTIAL,
        EffectKind.EXTERNAL_WRITE,
        EffectKind.EXTERNAL_DELETE,
    })
    allowed_network_hosts: frozenset[str] = frozenset()
    allowed_credential_names: frozenset[str] = frozenset()
    allow_project_declared: bool = False
    allow_local_untrusted: bool = False
    allow_remote_configured: bool = True
    policy_digest: str = ""

    def __post_init__(self) -> None:
        for name in (
            "allowed_extension_ids", "denied_extension_ids", "allowed_provenance",
            "allowed_effects", "denied_effects", "require_approval_effects",
            "allowed_network_hosts", "allowed_credential_names",
        ):
            values = frozenset(getattr(self, name))
            if any(type(value) is not str and not hasattr(value, "value") for value in values):
                raise ValueError(f"{name} contains an invalid value")
            object.__setattr__(self, name, values)
        object.__setattr__(self, "allowed_provenance", frozenset(
            ExtensionProvenance(str(value)) for value in self.allowed_provenance
        ))
        for name in ("allowed_effects", "denied_effects", "require_approval_effects"):
            object.__setattr__(self, name, frozenset(
                EffectKind(str(value)) for value in getattr(self, name)
            ))
        object.__setattr__(self, "allowed_network_hosts", frozenset(
            _normalize_host(value) for value in self.allowed_network_hosts
        ))
        for name in ("allow_project_declared", "allow_local_untrusted", "allow_remote_configured"):
            if type(getattr(self, name)) is not bool:
                raise ValueError(f"{name} must be boolean")
        digest = canonical_digest(self._payload(include_digest=False))
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("policy_digest does not match policy")
        object.__setattr__(self, "policy_digest", digest)

    def _payload(self, *, include_digest: bool) -> dict[str, object]:
        payload: dict[str, object] = {
            "allowed_extension_ids": sorted(self.allowed_extension_ids),
            "denied_extension_ids": sorted(self.denied_extension_ids),
            "allowed_provenance": sorted(str(value) for value in self.allowed_provenance),
            "allowed_effects": sorted(str(value) for value in self.allowed_effects),
            "denied_effects": sorted(str(value) for value in self.denied_effects),
            "require_approval_effects": sorted(str(value) for value in self.require_approval_effects),
            "allowed_network_hosts": sorted(self.allowed_network_hosts),
            "allowed_credential_names": sorted(self.allowed_credential_names),
            "allow_project_declared": self.allow_project_declared,
            "allow_local_untrusted": self.allow_local_untrusted,
            "allow_remote_configured": self.allow_remote_configured,
        }
        if include_digest:
            payload["policy_digest"] = self.policy_digest
        return payload

    def to_payload(self) -> dict[str, object]:
        return self._payload(include_digest=True)


class CapabilityAdmissionService:
    """Single capability admission owner for MCP, Hooks, and Skills.

    This service returns typed decisions.  It never executes a handler, opens
    a socket, reads a credential, mutates a workspace, or decides verification
    or completion.  The caller must hand an admitted binding to the existing
    execution/approval owners.
    """

    def __init__(
        self,
        registry: ExtensionRegistry,
        *,
        policy: ExtensionPolicy | None = None,
        approval_checker: ApprovalChecker | None = None,
        network_host_checker: Callable[[str], bool] | None = None,
        credential_checker: Callable[[str], bool] | None = None,
    ) -> None:
        self.registry = registry
        self.policy = policy or ExtensionPolicy()
        self.approval_checker = approval_checker
        self.network_host_checker = network_host_checker
        self.credential_checker = credential_checker

    async def admit(self, request: CapabilityRequest) -> CapabilityAdmissionResult:
        """Evaluate a request and issue a binding only after all gates pass."""
        if type(request) is not CapabilityRequest:
            raise TypeError("request must be a CapabilityRequest")
        result, effects = self._evaluate(request)
        if result is not None:
            return result
        expected_identity = self._identity_snapshot(request)
        if expected_identity is None:
            return self._result(
                request,
                AdmissionStatus.UNAVAILABLE,
                "capability_missing",
                "capability disappeared during admission",
            )
        if effects & self.policy.require_approval_effects:
            approved = False
            if self.approval_checker is not None and request.approval_digest:
                try:
                    checked = self.approval_checker(request, frozenset(effects))
                    approved = bool(await checked) if inspect.isawaitable(checked) else bool(checked)
                except Exception:  # noqa: BLE001 - approval failure is fail-closed
                    approved = False
            if not approved:
                return self._result(
                    request,
                    AdmissionStatus.REQUIRES_APPROVAL,
                    "approval_required",
                    "the existing approval owner has not approved this exact effect set",
                    required_effects=effects,
                )
        return self._admitted(request, effects, expected_identity=expected_identity)

    def admit_sync(self, request: CapabilityRequest) -> CapabilityAdmissionResult:
        """Synchronous test/CLI adapter; async approval checkers fail closed."""
        if type(request) is not CapabilityRequest:
            raise TypeError("request must be a CapabilityRequest")
        result, effects = self._evaluate(request)
        if result is not None:
            return result
        expected_identity = self._identity_snapshot(request)
        if expected_identity is None:
            return self._result(
                request,
                AdmissionStatus.UNAVAILABLE,
                "capability_missing",
                "capability disappeared during admission",
            )
        if effects & self.policy.require_approval_effects:
            if self.approval_checker is None or not request.approval_digest:
                return self._result(
                    request,
                    AdmissionStatus.REQUIRES_APPROVAL,
                    "approval_required",
                    "the existing approval owner has not approved this exact effect set",
                    required_effects=effects,
                )
            checked = self.approval_checker(request, frozenset(effects))
            if inspect.isawaitable(checked) or not checked:
                return self._result(
                    request,
                    AdmissionStatus.REQUIRES_APPROVAL,
                    "approval_not_verified",
                    "approval verification is unavailable or denied",
                    required_effects=effects,
                )
        return self._admitted(request, effects, expected_identity=expected_identity)

    def validate_invocation(
        self,
        binding: InvocationBinding,
        request: CapabilityRequest,
    ) -> CapabilityAdmissionResult:
        """Re-read identity and policy immediately before transport dispatch."""
        if type(binding) is not InvocationBinding or type(request) is not CapabilityRequest:
            raise TypeError("binding and request have invalid types")
        request_digest = canonical_digest(request.to_payload())
        if not self._owner_scope_matches(request):
            return self._result(
                request,
                AdmissionStatus.DENIED,
                "owner_scope_denied",
                "request owner is outside the extension registry scope",
            )
        if request.policy_digest and request.policy_digest != self.policy.policy_digest:
            return self._result(request, AdmissionStatus.STALE, "policy_drift", "effective policy changed")
        if binding.effective.policy_digest != self.policy.policy_digest:
            return self._result(request, AdmissionStatus.STALE, "binding_policy_drift", "invocation binding uses a stale policy")
        if (
            binding.effective.capability_id != request.capability_id
            or (
                request.extension_id is not None
                and binding.effective.extension_id != request.extension_id
            )
            or binding.effective.task_id != request.task_id
            or binding.effective.principal_id != request.principal_id
            or binding.effective.project_id != request.project_id
            or binding.effective.workspace_id != request.workspace_id
            or binding.effective.workspace_generation != request.workspace_generation
            or binding.approval_digest != request.approval_digest
            or binding.effective.credential_name != request.credential_name
        ):
            return self._result(
                request,
                AdmissionStatus.STALE,
                "binding_scope_mismatch",
                "invocation binding is bound to a different task, owner, workspace, or approval",
            )
        if binding.arguments_digest != request.arguments_digest:
            return self._result(request, AdmissionStatus.STALE, "arguments_drift", "invocation arguments changed")
        if binding.request_digest is not None and binding.request_digest != request_digest:
            return self._result(request, AdmissionStatus.STALE, "request_drift", "invocation request changed")
        try:
            capability = self.registry.get_capability(request.capability_id)
            record = self.registry.extension_for_capability(request.capability_id)
        except ExtensionRegistryError:
            capability = None
            record = None
        if capability is None or record is None:
            return self._result(request, AdmissionStatus.UNAVAILABLE, "capability_missing", "capability is no longer registered")
        if record.state is not ExtensionLifecycleState.AVAILABLE:
            status = AdmissionStatus.QUARANTINED if record.state is ExtensionLifecycleState.QUARANTINED else AdmissionStatus.UNAVAILABLE
            return self._result(request, status, "extension_not_available", f"extension lifecycle is {record.state}")
        if capability.capability_digest != binding.effective.capability_digest or record.descriptor.descriptor_digest != binding.effective.extension_digest:
            return self._result(request, AdmissionStatus.STALE, "descriptor_drift", "capability or extension descriptor changed")
        expected_network_host = request.network_host or _host_from_identity(record.descriptor.transport_identity)
        if EffectKind.NETWORK in binding.effective.effects:
            try:
                expected_network_host = _normalize_host(expected_network_host or "")
            except ValueError:
                return self._result(request, AdmissionStatus.STALE, "network_host_invalid", "invocation endpoint is no longer valid")
        if binding.effective.network_host != expected_network_host:
            return self._result(request, AdmissionStatus.STALE, "network_target_drift", "invocation endpoint changed")
        return CapabilityAdmissionResult(
            status=AdmissionStatus.ADMITTED,
            reason_code="binding_valid",
            reason="invocation binding remains current",
            request_digest=request_digest,
            effective=binding.effective,
            binding=binding,
        )

    def _evaluate(self, request: CapabilityRequest) -> tuple[CapabilityAdmissionResult | None, frozenset[EffectKind]]:
        if not self._owner_scope_matches(request):
            return self._result(
                request,
                AdmissionStatus.DENIED,
                "owner_scope_denied",
                "request owner is outside the extension registry scope",
            ), frozenset()
        if request.policy_digest and request.policy_digest != self.policy.policy_digest:
            return self._result(request, AdmissionStatus.STALE, "policy_drift", "request policy digest is stale"), frozenset()
        try:
            capability = self.registry.get_capability(request.capability_id)
            record = self.registry.extension_for_capability(request.capability_id)
        except ExtensionRegistryError:
            capability = None
            record = None
        if capability is None or record is None:
            return self._result(request, AdmissionStatus.UNAVAILABLE, "capability_missing", "capability is not registered"), frozenset()
        if record.state is ExtensionLifecycleState.QUARANTINED:
            return self._result(request, AdmissionStatus.QUARANTINED, "extension_quarantined", record.reason or "extension is quarantined"), frozenset()
        if record.state is not ExtensionLifecycleState.AVAILABLE:
            return self._result(request, AdmissionStatus.UNAVAILABLE, "extension_not_available", f"extension lifecycle is {record.state}"), frozenset()
        descriptor = record.descriptor
        if request.extension_id and request.extension_id != descriptor.extension_id:
            return self._result(request, AdmissionStatus.STALE, "extension_binding_mismatch", "request extension does not match capability"), frozenset()
        if request.capability_digest and request.capability_digest != capability.capability_digest:
            return self._result(request, AdmissionStatus.STALE, "capability_digest_mismatch", "request capability digest is stale"), frozenset()
        if request.extension_digest and request.extension_digest != descriptor.descriptor_digest:
            return self._result(request, AdmissionStatus.STALE, "extension_digest_mismatch", "request extension digest is stale"), frozenset()
        if descriptor.extension_id in self.policy.denied_extension_ids:
            return self._result(request, AdmissionStatus.DENIED, "extension_denied", "extension is denied by effective policy"), frozenset()
        if self.policy.allowed_extension_ids and descriptor.extension_id not in self.policy.allowed_extension_ids:
            return self._result(request, AdmissionStatus.DENIED, "extension_not_allowlisted", "extension is not in the effective allowlist"), frozenset()
        if not self._provenance_allowed(descriptor.provenance):
            return self._result(request, AdmissionStatus.DENIED, "provenance_denied", "extension provenance is not executable under policy"), frozenset()
        effects: set[EffectKind] = set(structural_effects(descriptor))
        effects.update(EffectKind(str(effect)) for effect in capability.effects)
        requested_effects = {EffectKind(str(effect)) for effect in request.requested_effects}
        if requested_effects and not requested_effects.issubset(effects):
            return self._result(request, AdmissionStatus.DENIED, "effect_widening", "request asks for an effect not declared by the capability"), frozenset()
        if self.policy.allowed_effects and not effects.issubset(self.policy.allowed_effects):
            return self._result(request, AdmissionStatus.DENIED, "effect_not_allowlisted", "capability effect is outside effective policy"), frozenset(effects)
        denied = effects & self.policy.denied_effects
        if denied:
            return self._result(request, AdmissionStatus.DENIED, "effect_denied", "capability effect is denied by effective policy"), frozenset(effects)
        if EffectKind.NETWORK in effects:
            host = request.network_host or _host_from_identity(descriptor.transport_identity)
            if not host:
                return self._result(request, AdmissionStatus.DENIED, "network_host_missing", "network capability has no normalized endpoint host"), frozenset(effects)
            try:
                normalized_host = _normalize_host(host)
            except ValueError:
                return self._result(
                    request,
                    AdmissionStatus.DENIED,
                    "network_host_invalid",
                    "network host is malformed",
                ), frozenset(effects)
            if normalized_host not in self.policy.allowed_network_hosts:
                return self._result(request, AdmissionStatus.DENIED, "network_host_denied", "network host is not explicitly allowlisted"), frozenset(effects)
            if self.network_host_checker is not None:
                try:
                    network_allowed = bool(self.network_host_checker(normalized_host))
                except Exception:  # noqa: BLE001 - external policy failure is fail-closed
                    network_allowed = False
                if not network_allowed:
                    return self._result(request, AdmissionStatus.DENIED, "network_policy_denied", "network policy rejected the endpoint"), frozenset(effects)
        if EffectKind.READ_CREDENTIAL in effects:
            if not request.credential_name or request.credential_name not in self.policy.allowed_credential_names:
                return self._result(request, AdmissionStatus.DENIED, "credential_not_allowlisted", "credential name is not explicitly allowlisted"), frozenset(effects)
            if self.credential_checker is not None:
                try:
                    credential_allowed = bool(self.credential_checker(request.credential_name))
                except Exception:  # noqa: BLE001 - external policy failure is fail-closed
                    credential_allowed = False
                if not credential_allowed:
                    return self._result(request, AdmissionStatus.DENIED, "credential_policy_denied", "credential policy rejected the request"), frozenset(effects)
        return None, frozenset(effects)

    def _admitted(
        self,
        request: CapabilityRequest,
        effects: frozenset[EffectKind],
        *,
        expected_identity: tuple[str, str] | None = None,
    ) -> CapabilityAdmissionResult:
        try:
            record = self.registry.extension_for_capability(request.capability_id)
            capability = self.registry.get_capability(request.capability_id)
        except ExtensionRegistryError:
            record = None
            capability = None
        if record is None or capability is None:
            return self._result(request, AdmissionStatus.UNAVAILABLE, "capability_missing", "capability disappeared during admission")
        if record.state is not ExtensionLifecycleState.AVAILABLE:
            status = AdmissionStatus.QUARANTINED if record.state is ExtensionLifecycleState.QUARANTINED else AdmissionStatus.UNAVAILABLE
            return self._result(request, status, "extension_not_available", f"extension lifecycle is {record.state}")
        current_identity = (capability.capability_digest, record.descriptor.descriptor_digest)
        if expected_identity is not None and current_identity != expected_identity:
            return self._result(request, AdmissionStatus.STALE, "descriptor_drift", "capability or extension descriptor changed during admission")
        current_effects = set(structural_effects(record.descriptor))
        current_effects.update(EffectKind(str(effect)) for effect in capability.effects)
        if frozenset(current_effects) != effects:
            return self._result(request, AdmissionStatus.STALE, "effect_drift", "capability effects changed during admission")
        network_host = request.network_host or _host_from_identity(record.descriptor.transport_identity)
        if EffectKind.NETWORK in effects:
            try:
                network_host = _normalize_host(network_host or "")
            except ValueError:
                return self._result(request, AdmissionStatus.DENIED, "network_host_invalid", "network host is malformed")
        effective = EffectiveCapability(
            capability_id=capability.capability_id,
            extension_id=record.descriptor.extension_id,
            capability_digest=capability.capability_digest,
            extension_digest=record.descriptor.descriptor_digest,
            task_id=request.task_id,
            principal_id=request.principal_id,
            project_id=request.project_id,
            workspace_id=request.workspace_id,
            workspace_generation=request.workspace_generation,
            policy_digest=self.policy.policy_digest,
            effects=tuple(sorted(effects, key=lambda item: item.value)),
            approval_required=bool(effects & self.policy.require_approval_effects),
            sandbox_required=True,
            network_host=network_host,
            credential_name=request.credential_name,
        )
        binding = InvocationBinding(
            invocation_id=f"ext-inv:{uuid.uuid4().hex}",
            effective=effective,
            arguments_digest=request.arguments_digest,
            approval_digest=request.approval_digest,
            request_digest=canonical_digest(request.to_payload()),
        )
        return CapabilityAdmissionResult(
            status=AdmissionStatus.ADMITTED,
            reason_code="admitted",
            reason="capability admitted by the unified extension policy",
            request_digest=canonical_digest(request.to_payload()),
            effective=effective,
            binding=binding,
        )

    def _identity_snapshot(self, request: CapabilityRequest) -> tuple[str, str] | None:
        """Capture descriptor identity before an async approval wait."""
        try:
            capability = self.registry.get_capability(request.capability_id)
            record = self.registry.extension_for_capability(request.capability_id)
        except ExtensionRegistryError:
            return None
        if capability is None or record is None:
            return None
        return capability.capability_digest, record.descriptor.descriptor_digest

    def _result(
        self,
        request: CapabilityRequest,
        status: AdmissionStatus,
        reason_code: str,
        reason: str,
        *,
        required_effects: Iterable[EffectKind] = (),
    ) -> CapabilityAdmissionResult:
        return CapabilityAdmissionResult(
            status=status,
            reason_code=reason_code,
            reason=reason,
            request_digest=canonical_digest(request.to_payload()),
            required_effects=tuple(required_effects),
        )

    def _provenance_allowed(self, provenance: ExtensionProvenance | str) -> bool:
        provenance = ExtensionProvenance(str(provenance))
        if provenance is ExtensionProvenance.PROJECT_DECLARED:
            return self.policy.allow_project_declared and provenance in self.policy.allowed_provenance
        if provenance is ExtensionProvenance.LOCAL_UNTRUSTED:
            return self.policy.allow_local_untrusted and provenance in self.policy.allowed_provenance
        if provenance is ExtensionProvenance.REMOTE_CONFIGURED:
            return self.policy.allow_remote_configured and provenance in self.policy.allowed_provenance
        return provenance in self.policy.allowed_provenance

    def _owner_scope_matches(self, request: CapabilityRequest) -> bool:
        owner_scope = self.registry.owner_scope
        return owner_scope is None or owner_scope == (request.principal_id, request.project_id)


def _normalize_host(value: str) -> str:
    if type(value) is not str or not value or "\x00" in value:
        raise ValueError("network host is invalid")
    candidate = value.strip().casefold().rstrip(".")
    if "://" in candidate:
        parsed = urlsplit(candidate)
        if parsed.scheme not in {"http", "https"} or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("network endpoint is invalid")
        candidate = parsed.hostname or ""
    if not candidate or "/" in candidate or "@" in candidate or len(candidate) > 255:
        raise ValueError("network host is invalid")
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if candidate == "localhost" or candidate.endswith(".localhost"):
            raise ValueError("localhost is not implicitly safe")
        if any(label == "" or len(label) > 63 for label in candidate.split(".")):
            raise ValueError("network host is invalid")
        return candidate
    if address.is_private or address.is_loopback or address.is_link_local or address.is_reserved or address.is_unspecified or address.is_multicast:
        raise ValueError("private or special network address is not allowed")
    return candidate


def _host_from_identity(identity: str) -> str | None:
    if not identity:
        return None
    try:
        parsed = urlsplit(identity)
        return parsed.hostname
    except ValueError:
        return None


__all__ = [
    "CapabilityAdmissionError",
    "CapabilityAdmissionService",
    "ExtensionPolicy",
]
