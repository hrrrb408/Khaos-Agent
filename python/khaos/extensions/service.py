"""Composition façade for extension lifecycle and read-only CLI surfaces."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Protocol

from khaos.extensions.admission import CapabilityAdmissionService, ExtensionPolicy
from khaos.extensions.contracts import (
    CapabilityDescriptor,
    ExtensionDescriptor,
    ExtensionLifecycleState,
    ExtensionRecord,
)
from khaos.extensions.registry import ExtensionRegistry


@dataclass(frozen=True, slots=True)
class ExtensionDoctorReport:
    """Bounded operator diagnostics; no raw provider output."""

    records: tuple[dict[str, object], ...]
    blockers: tuple[str, ...] = ()

    @property
    def healthy(self) -> bool:
        return not self.blockers


class ExtensionRepositoryPort(Protocol):
    """Minimal persistence port used by the lifecycle façade."""

    async def save_record(
        self,
        record: ExtensionRecord,
        *,
        principal_id: str,
        project_id: str,
    ) -> None:
        """Persist one owner-scoped extension projection."""


class ExtensionService:
    """Own the composition of registry, admission, and optional persistence."""

    def __init__(
        self,
        *,
        registry: ExtensionRegistry | None = None,
        policy: ExtensionPolicy | None = None,
        repository: ExtensionRepositoryPort | None = None,
    ) -> None:
        self.registry = registry or ExtensionRegistry()
        self.admission = CapabilityAdmissionService(self.registry, policy=policy)
        self.repository = repository
        self._metrics: dict[str, int] = {
            "extension_calls": 0,
            "mcp_calls": 0,
            "mcp_failures": 0,
            "hook_invocations": 0,
            "hook_failures": 0,
        }

    def metrics_snapshot(self) -> dict[str, int]:
        """Return the bounded extension counters owned by this composition."""
        return dict(self._metrics)

    def record_metrics(self, metrics: object) -> None:
        """Merge adapter counters without accepting provider output or authority."""
        for name in self._metrics:
            value = metrics.get(name) if isinstance(metrics, Mapping) else getattr(metrics, name, None)
            if value is not None and type(value) is int and value >= 0:
                self._metrics[name] = value

    async def register(
        self,
        descriptor: ExtensionDescriptor,
        capabilities: Iterable[CapabilityDescriptor] = (),
        *,
        principal_id: str = "",
        project_id: str = "",
    ) -> ExtensionRecord:
        """Discover/validate and optionally persist metadata; availability is explicit."""
        record = self.registry.register(descriptor, capabilities)
        if self.repository is not None and principal_id and project_id:
            await self.repository.save_record(record, principal_id=principal_id, project_id=project_id)
        return record

    async def enable(
        self,
        extension_id: str,
        *,
        principal_id: str = "",
        project_id: str = "",
    ) -> ExtensionRecord:
        """Re-enable metadata; a live owner must publish availability separately.

        A CLI/configuration operation has no process or network owner to
        handshake with.  It therefore cannot make a capability AVAILABLE;
        the next task/session must revalidate and publish it after startup.
        """
        record = self.registry.get(extension_id)
        if not record.descriptor.enabled:
            raise RuntimeError("extension descriptor is disabled by configuration")
        if record.state is ExtensionLifecycleState.DISABLED:
            record = self.registry.validate(extension_id, record.capabilities)
        elif record.state is not ExtensionLifecycleState.VALIDATED:
            raise RuntimeError("only a disabled or validated extension can be enabled")
        if self.repository is not None and principal_id and project_id:
            await self.repository.save_record(record, principal_id=principal_id, project_id=project_id)
        return record

    async def disable(
        self,
        extension_id: str,
        *,
        reason: str = "disabled by operator",
        principal_id: str = "",
        project_id: str = "",
    ) -> ExtensionRecord:
        """Stop new admissions and persist the lifecycle projection."""
        record = self.registry.disable(extension_id, reason)
        if self.repository is not None and principal_id and project_id:
            await self.repository.save_record(record, principal_id=principal_id, project_id=project_id)
        return record

    def list(self) -> tuple[ExtensionRecord, ...]:
        """Return deterministic registry snapshots for API/TUI/CLI."""
        return self.registry.list()

    def show(self, extension_id: str) -> dict[str, object]:
        """Return a bounded descriptor/capability projection."""
        return self.registry.get(extension_id).to_payload()

    def doctor(self) -> ExtensionDoctorReport:
        """Report lifecycle blockers without treating provider claims as health."""
        records = self.registry.list()
        blockers = tuple(
            f"{record.descriptor.extension_id}:{record.reason or str(record.state)}"
            for record in records
            if record.state in {
                ExtensionLifecycleState.REJECTED,
                ExtensionLifecycleState.DEGRADED,
                ExtensionLifecycleState.QUARANTINED,
            }
        )
        return ExtensionDoctorReport(
            records=tuple(record.to_payload() for record in records),
            blockers=blockers,
        )

    def list_payload(self) -> tuple[dict[str, object], ...]:
        return tuple(record.to_payload() for record in self.registry.list())


__all__ = ["ExtensionDoctorReport", "ExtensionRepositoryPort", "ExtensionService"]
