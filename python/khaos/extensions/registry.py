"""The single discovery/validation/lifecycle registry for extensions."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace
from threading import RLock

from khaos.extensions.contracts import (
    CapabilityDescriptor,
    ExtensionDescriptor,
    ExtensionLifecycleState,
    ExtensionRecord,
    ExtensionType,
    structural_effects,
)


class ExtensionRegistryError(RuntimeError):
    """Raised when a registry operation would violate an extension fence."""


_TERMINAL_DISCOVERY_STATES = {
    ExtensionLifecycleState.REJECTED,
    ExtensionLifecycleState.QUARANTINED,
}
_ALLOWED_TRANSITIONS: dict[ExtensionLifecycleState, frozenset[ExtensionLifecycleState]] = {
    ExtensionLifecycleState.DISCOVERED: frozenset({
        ExtensionLifecycleState.VALIDATED,
        ExtensionLifecycleState.REJECTED,
        ExtensionLifecycleState.DISABLED,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.VALIDATED: frozenset({
        ExtensionLifecycleState.AVAILABLE,
        ExtensionLifecycleState.REJECTED,
        ExtensionLifecycleState.DISABLED,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.AVAILABLE: frozenset({
        ExtensionLifecycleState.DEGRADED,
        ExtensionLifecycleState.DRAINING,
        ExtensionLifecycleState.DISABLED,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.DEGRADED: frozenset({
        ExtensionLifecycleState.VALIDATED,
        ExtensionLifecycleState.AVAILABLE,
        ExtensionLifecycleState.DRAINING,
        ExtensionLifecycleState.DISABLED,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.DRAINING: frozenset({
        ExtensionLifecycleState.DISABLED,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.DISABLED: frozenset({
        ExtensionLifecycleState.VALIDATED,
        ExtensionLifecycleState.AVAILABLE,
        ExtensionLifecycleState.QUARANTINED,
    }),
    ExtensionLifecycleState.REJECTED: frozenset({ExtensionLifecycleState.DISABLED}),
    ExtensionLifecycleState.QUARANTINED: frozenset({ExtensionLifecycleState.DISABLED}),
}


class ExtensionRegistry:
    """Own extension identity, validation, collision, and lifecycle state.

    The registry intentionally does not register external tools into the
    canonical :class:`ToolRegistry`.  A capability becoming visible here is
    therefore never sufficient to execute it; callers must pass through the
    shared admission service and then an existing execution owner.
    """

    def __init__(
        self,
        *,
        protected_names: Iterable[str] = (),
        tool_registry: object | None = None,
        principal_id: str | None = None,
        project_id: str | None = None,
    ) -> None:
        if (principal_id is None) != (project_id is None):
            raise ValueError("principal_id and project_id must be provided together")
        if principal_id is not None and (
            type(principal_id) is not str
            or not principal_id
            or "\x00" in principal_id
            or len(principal_id.encode("utf-8")) > 256
            or type(project_id) is not str
            or not project_id
            or "\x00" in project_id
            or len(project_id.encode("utf-8")) > 256
        ):
            raise ValueError("extension registry owner scope is malformed")
        names = {str(name) for name in protected_names if str(name)}
        if tool_registry is not None:
            names_method = getattr(tool_registry, "names", None)
            if callable(names_method):
                names_value = names_method()
                if isinstance(names_value, Iterable):
                    names.update(str(name) for name in names_value)
        self._protected_names = frozenset(names)
        self._records: dict[str, ExtensionRecord] = {}
        self._capability_index: dict[str, str] = {}
        self._lock = RLock()
        self._owner_scope = (
            (principal_id, project_id)
            if principal_id is not None and project_id is not None
            else None
        )

    @property
    def protected_names(self) -> frozenset[str]:
        return self._protected_names

    @property
    def owner_scope(self) -> tuple[str, str] | None:
        """Return the immutable principal/project scope of this registry."""
        return self._owner_scope

    def discover(self, descriptor: ExtensionDescriptor) -> ExtensionRecord:
        """Add a candidate without making it executable."""
        if type(descriptor) is not ExtensionDescriptor:
            raise TypeError("descriptor must be an ExtensionDescriptor")
        with self._lock:
            existing = self._records.get(descriptor.extension_id)
            if existing is not None:
                if existing.descriptor.identity_digest != descriptor.identity_digest:
                    raise ExtensionRegistryError(
                        "extension id is already bound to a different source/version/artifact/config"
                    )
                return existing
            state = (
                ExtensionLifecycleState.DISABLED
                if not descriptor.enabled
                else ExtensionLifecycleState.DISCOVERED
            )
            record = ExtensionRecord(
                descriptor=descriptor,
                state=state,
                state_generation=1,
            )
            self._records[descriptor.extension_id] = record
            return record

    def validate(
        self,
        extension: str | ExtensionDescriptor,
        capabilities: Iterable[CapabilityDescriptor] = (),
    ) -> ExtensionRecord:
        """Validate and publish typed capabilities, still requiring availability."""
        with self._lock:
            record = self._resolve_record(extension)
            if record.state in _TERMINAL_DISCOVERY_STATES:
                raise ExtensionRegistryError(
                    f"extension {record.descriptor.extension_id} is {record.state}"
                )
            capability_values = tuple(capabilities)
            self._validate_capabilities(record.descriptor, capability_values)
            self._remove_capability_index(record)
            for capability in capability_values:
                self._capability_index[capability.capability_id] = capability.extension_id
            return self._transition(
                replace(record, capabilities=capability_values),
                ExtensionLifecycleState.VALIDATED,
                reason="descriptor and capabilities validated",
            )

    def register(
        self,
        descriptor: ExtensionDescriptor,
        capabilities: Iterable[CapabilityDescriptor] = (),
    ) -> ExtensionRecord:
        """Discover and validate one extension; availability remains explicit."""
        self.discover(descriptor)
        return self.validate(descriptor.extension_id, capabilities)

    def mark_available(self, extension: str) -> ExtensionRecord:
        """Make a validated, enabled extension eligible for admission."""
        return self._set_state(extension, ExtensionLifecycleState.AVAILABLE, "available after explicit lifecycle start")

    def mark_degraded(self, extension: str, reason: str) -> ExtensionRecord:
        """Record a health failure; new capability admissions are rejected."""
        return self._set_state(extension, ExtensionLifecycleState.DEGRADED, reason)

    def disable(self, extension: str, reason: str = "disabled by operator") -> ExtensionRecord:
        """Close the admission fence and leave draining to the lifecycle owner."""
        return self._set_state(extension, ExtensionLifecycleState.DISABLED, reason)

    def begin_draining(self, extension: str, reason: str = "draining") -> ExtensionRecord:
        """Prevent new work while an owner drains existing work."""
        return self._set_state(extension, ExtensionLifecycleState.DRAINING, reason)

    def quarantine(self, extension: str, reason: str) -> ExtensionRecord:
        """Retain a non-terminal resource owner in quarantine."""
        return self._set_state(extension, ExtensionLifecycleState.QUARANTINED, reason)

    def reconcile(self, extension: str, *, terminal: bool, reason: str = "") -> ExtensionRecord:
        """Reconcile a disabled/draining owner without claiming false health."""
        record = self.get(extension)
        if not terminal:
            return self.quarantine(extension, reason or "resource owner is not terminal")
        if record.state is ExtensionLifecycleState.QUARANTINED:
            return self.disable(extension, reason or "quarantined owner reconciled")
        if record.state is ExtensionLifecycleState.DRAINING:
            return self.disable(extension, reason or "drain complete")
        return record

    def get(self, extension: str) -> ExtensionRecord:
        with self._lock:
            return self._resolve_record(extension)

    def get_capability(self, capability_id: str) -> CapabilityDescriptor | None:
        """Return a capability only from a validated registry snapshot."""
        with self._lock:
            extension_id = self._capability_index.get(capability_id)
            if extension_id is None:
                return None
            record = self._records.get(extension_id)
            if record is None:
                return None
            return next(
                (item for item in record.capabilities if item.capability_id == capability_id),
                None,
            )

    def extension_for_capability(self, capability_id: str) -> ExtensionRecord | None:
        with self._lock:
            extension_id = self._capability_index.get(capability_id)
            if extension_id is None or extension_id not in self._records:
                return None
            return self._records[extension_id]

    def list(self, *, states: Iterable[ExtensionLifecycleState | str] | None = None) -> tuple[ExtensionRecord, ...]:
        """Return deterministic immutable snapshots for read-only surfaces."""
        allowed = None if states is None else {ExtensionLifecycleState(str(state)) for state in states}
        with self._lock:
            records = tuple(self._records.values())
        if allowed is not None:
            records = tuple(record for record in records if record.state in allowed)
        return tuple(sorted(records, key=lambda record: record.descriptor.extension_id))

    def capabilities(self, *, include_unavailable: bool = False) -> tuple[CapabilityDescriptor, ...]:
        """Return capability metadata without registering executable handlers."""
        records = self.list()
        values: list[CapabilityDescriptor] = []
        for record in records:
            if not include_unavailable and record.state is not ExtensionLifecycleState.AVAILABLE:
                continue
            values.extend(record.capabilities)
        return tuple(sorted(values, key=lambda item: item.capability_id))

    def is_admissible(self, extension_id: str) -> bool:
        with self._lock:
            record = self._records.get(extension_id)
            return record is not None and record.state is ExtensionLifecycleState.AVAILABLE

    def _resolve_record(self, extension: str | ExtensionDescriptor) -> ExtensionRecord:
        extension_id = extension.extension_id if isinstance(extension, ExtensionDescriptor) else str(extension)
        record = self._records.get(extension_id)
        if record is None:
            raise ExtensionRegistryError(f"unknown extension: {extension_id}")
        return record

    def _set_state(
        self,
        extension: str,
        state: ExtensionLifecycleState,
        reason: str,
    ) -> ExtensionRecord:
        with self._lock:
            record = self._resolve_record(extension)
            return self._transition(record, state, reason)

    def _transition(
        self,
        record: ExtensionRecord,
        state: ExtensionLifecycleState,
        reason: str,
    ) -> ExtensionRecord:
        current_state = ExtensionLifecycleState(str(record.state))
        if current_state is not state and state not in _ALLOWED_TRANSITIONS[current_state]:
            raise ExtensionRegistryError(
                f"invalid extension lifecycle transition {current_state} -> {state}"
            )
        if state is ExtensionLifecycleState.AVAILABLE:
            if not record.descriptor.enabled:
                raise ExtensionRegistryError("disabled descriptor cannot become available")
            if current_state not in {ExtensionLifecycleState.VALIDATED, ExtensionLifecycleState.DEGRADED}:
                raise ExtensionRegistryError("only validated/degraded extensions can become available")
        if not reason:
            reason = record.reason
        updated = replace(record, state=state, reason=reason, state_generation=record.state_generation + 1)
        self._records[record.descriptor.extension_id] = updated
        return updated

    def _remove_capability_index(self, record: ExtensionRecord) -> None:
        for capability in record.capabilities:
            if self._capability_index.get(capability.capability_id) == record.descriptor.extension_id:
                del self._capability_index[capability.capability_id]

    def _validate_capabilities(
        self,
        descriptor: ExtensionDescriptor,
        capabilities: tuple[CapabilityDescriptor, ...],
    ) -> None:
        seen_ids: set[str] = set()
        seen_names: set[str] = set()
        for capability in capabilities:
            if type(capability) is not CapabilityDescriptor:
                raise ExtensionRegistryError("capabilities must be CapabilityDescriptor values")
            if capability.extension_id != descriptor.extension_id:
                raise ExtensionRegistryError("capability extension id does not match descriptor")
            if capability.capability_id in seen_ids:
                raise ExtensionRegistryError("duplicate capability id")
            seen_ids.add(capability.capability_id)
            if capability.name in seen_names:
                raise ExtensionRegistryError("duplicate capability name within extension")
            seen_names.add(capability.name)
            if capability.name in self._protected_names:
                raise ExtensionRegistryError(
                    f"capability name collides with protected builtin: {capability.name}"
                )
            if _is_protected_namespace(capability.name):
                raise ExtensionRegistryError(
                    f"capability name uses a protected namespace: {capability.name}"
                )
            if descriptor.extension_type is ExtensionType.MCP_SERVER and str(capability.kind) not in {
                "TOOL", "RESOURCE", "PROMPT"
            }:
                raise ExtensionRegistryError("MCP server declared a non-MCP capability")
            # Evaluating this property makes the structural transport effect
            # part of validation even when the provider claims READ_ONLY.
            structural_effects(descriptor)
            existing = self._capability_index.get(capability.capability_id)
            if existing is not None and existing != descriptor.extension_id:
                raise ExtensionRegistryError("capability id collides with another extension")


def _is_protected_namespace(name: str) -> bool:
    normalized = name.casefold()
    return normalized.startswith(("khaos.", "system.", "builtin.", "approval.", "completion."))


__all__ = ["ExtensionRegistry", "ExtensionRegistryError"]
