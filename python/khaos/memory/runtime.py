"""Canonical Memory Runtime/Host composition.

There is one provider registry, one Broker, one ledger, one profile, one
verification verifier, and one audit sink per application host.  A
``MemoryRuntime`` is only a typed view over that host with a full runtime
binding; it never constructs a provider or a second Broker.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, cast

from khaos.memory.core.contracts import RuntimeMemoryContext


@dataclass(frozen=True, slots=True)
class MemoryRuntimeBinding:
    """Security-owned identity and execution binding for one memory call."""

    principal_id: str
    project_id: str
    session_id: str | None
    task_id: str | None
    workspace_id: str | None
    mode: str
    available_capabilities: frozenset[str] = frozenset()
    environment_fingerprint: str = ""
    repo_id: str | None = None
    commit_sha: str | None = None
    branch: str | None = None
    environment: dict[str, Any] = field(default_factory=dict)

    def context(self) -> RuntimeMemoryContext:
        """Create the immutable Broker context from this host binding."""

        return RuntimeMemoryContext(
            principal_id=self.principal_id,
            project_id=self.project_id,
            session_id=self.session_id,
            task_id=self.task_id,
            workspace_id=self.workspace_id,
            mode=self.mode,
            available_capabilities=self.available_capabilities,
            environment_fingerprint=self.environment_fingerprint,
            repo_id=self.repo_id,
            commit_sha=self.commit_sha,
            branch=self.branch,
            environment=dict(self.environment),
        )


class MemoryHost:
    """Application-scoped owner of the canonical Memory V2 composition."""

    def __init__(
        self,
        broker: Any,
        *,
        provider_manager: Any = None,
        profile: Any = None,
        profile_registry: Any = None,
        profile_store: Any = None,
        transfer_service: Any = None,
        codegraph: Any = None,
        owns_lifecycle: bool = True,
    ) -> None:
        if broker is None:
            raise ValueError("MemoryHost requires the canonical MemoryBroker")
        self.broker = broker
        self.provider_manager = provider_manager
        self.profile = profile
        self.profile_registry = profile_registry
        self.profile_store = profile_store
        self.transfer_service = transfer_service
        self.codegraph = codegraph
        self.owns_lifecycle = owns_lifecycle

    def runtime(self, binding: MemoryRuntimeBinding) -> MemoryRuntime:
        """Return a full-scope view over this host."""

        return MemoryRuntime(self, binding)

    def context(self, binding: MemoryRuntimeBinding) -> RuntimeMemoryContext:
        """Build a context without allowing a provider to fill missing fields."""

        return binding.context()

    async def close(self) -> None:
        """Close the provider registry only when this host owns it."""

        if not self.owns_lifecycle or self.provider_manager is None:
            return
        registry = getattr(self.provider_manager, "registry", None)
        close = getattr(registry, "close", None)
        if callable(close):
            await cast(Callable[..., Awaitable[Any]], close)()


class MemoryRuntime:
    """Per-turn typed view; all operations delegate to one ``MemoryHost``."""

    def __init__(self, host: MemoryHost, binding: MemoryRuntimeBinding) -> None:
        self.host = host
        self.binding = binding
        self.context = binding.context()

    @property
    def broker(self) -> Any:
        """Return the host Broker; no provider fallback exists."""

        return self.host.broker

    @property
    def provider_manager(self) -> Any:
        """Return the shared provider lifecycle manager."""

        return self.host.provider_manager


__all__ = ["MemoryHost", "MemoryRuntime", "MemoryRuntimeBinding"]
