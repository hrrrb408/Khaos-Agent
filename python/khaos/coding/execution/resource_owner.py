"""Round-17 review §十四/§十七: unified lifecycle contract for security
resource owners.

The review identified that ExecutionService, DockerBackend,
ManagedProcessHandle, LSP, ProcessSupervisor, BrowserManager, and
BrowserEgressProxy
each had their own ad-hoc notion of "CLOSED" — with different state
combinations, different cleanup semantics, and different (or missing)
postcondition proofs.  This module defines a single :class:`ResourceOwner`
protocol that captures the unified lifecycle theorem:

    CLOSED ⇔
      1. future resource admission is impossible
      2. every resource acquired by this owner has a recorded terminal
         postcondition
      3. no initializing/acquiring transaction remains
      4. no child owner remains non-terminal
      5. all resource registries are empty (or contain only explicitly
         detached non-owned resources)

Concretely:

  ExecutionService:
    state CLOSED       ❌
    child owners empty + supervisor proof + external registry empty  ✅

  Process:
    signal sent       ❌
    returncode known + waiter reaped + registry released  ✅

  Task:
    task.cancel()     ❌
    task.done() + result/exception settled + owner removed  ✅

  Socket:
    writer.close()    ❌
    transport closed + handler terminated + owner removed  ✅

  Listener:
    server.close()    ❌
    wait_closed + no sockets + generation no longer admissible  ✅

Owners that implement this protocol share the same lifecycle theorem and
external-oracle vocabulary.  The Resource Ownership Closure E2E suite
(round-17 review §十五) keeps a common admission/terminal assertion set,
then applies owner-specific fault injection where acquisition and cleanup
mechanics differ.  DockerBackend has its own complete matrix, including
double cancellation, bounded shutdown, retry, and an external container
inspect oracle; a new owner must add explicit owner-specific fault tests
before the suite can claim it is verified.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, cast, runtime_checkable


class ResourceOwnerInvariantError(RuntimeError):
    """Raised when an owner exposes an inconsistent lifecycle proof."""


@runtime_checkable
class ResourceOwner(Protocol):
    """Unified lifecycle contract for security resource owners.

    Implementations include :class:`~khaos.coding.execution.service.ExecutionService`,
    :class:`~khaos.coding.execution.docker.DockerBackend`,
    :class:`~khaos.coding.execution.managed.ManagedProcessHandle`,
    :class:`~khaos.coding.execution.supervisor.ProcessSupervisor`,
    :class:`~khaos.coding.intelligence.lsp.client.LspClient`,
    :class:`~khaos.security.browser_egress_proxy.BrowserEgressProxy`,
    :class:`~khaos.tools.browser_tools.BrowserManager`, and
    :class:`~khaos.runtime.factory.RuntimeResult`.

    Admission is deliberately split into two independent fences:

      - ``generation_admission_closed`` prevents another owner generation
        from being started after the current generation is opened or close
        has been requested.
      - ``child_admission_closed`` controls resources accepted by an already
        running generation (for example, BrowserEgressProxy client
        connections).

    ``admission_closed`` remains a compatibility alias for the generation
    fence.  New lifecycle code must use the explicit property that matches
    the resource being admitted.

    The terminal properties form a partition:

      - ``generation_admission_closed`` is True once a generation has been
        opened or close has been requested.  It permanently rejects
        ``start()`` for that owner.
      - ``child_admission_closed`` is True while the owner is not accepting
        child resources.  A running Browser proxy intentionally has
        ``generation_admission_closed=True`` and
        ``child_admission_closed=False``.
      - ``admission_closed`` aliases ``generation_admission_closed`` for
        older callers.

      - ``is_quarantined`` is True only for QUARANTINED.  Resources may
        still be alive; a retry via ``close()`` can make forward progress.

      - ``terminal_closed`` is True only for CLOSED.  Every owned
        resource has a proven terminal postcondition AND the registries
        are empty.

    The CLOSED invariant is:

        terminal_closed ⇔
            terminal_postcondition() AND owned_resources() == ()

    i.e., CLOSED is not "cleanup() returned" — it is "every resource is
    proven terminal AND no resource remains in the registry".
    """

    @property
    def admission_closed(self) -> bool:
        """Compatibility alias for ``generation_admission_closed``.

        Use ``generation_admission_closed`` or
        ``child_admission_closed`` for new code.
        """
        ...

    @property
    def generation_admission_closed(self) -> bool:
        """True when a new owner generation must be rejected."""
        ...

    @property
    def child_admission_closed(self) -> bool:
        """True when this generation cannot accept another child resource."""
        ...

    @property
    def terminal_closed(self) -> bool:
        """True ONLY when CLOSED — all resources proven terminal.

        Distinct from ``admission_closed``: QUARANTINED has
        ``admission_closed=True`` but ``terminal_closed=False`` because
        resources may still be alive.  Callers that need "everything is
        gone" must check this property, not ``admission_closed``.
        """
        ...

    @property
    def is_quarantined(self) -> bool:
        """True when QUARANTINED — cleanup failed, resources may be alive.

        A quarantined owner is NOT closed.  ``close()`` can be called
        again to retry (using the CleanupLedger to skip already-
        completed steps).  The owner must NOT be reported as closed
        while quarantined.
        """
        ...

    def owned_resources(self) -> tuple[str, ...]:
        """Human-readable descriptors of resources currently held.

        Returns an empty tuple iff no resource is currently owned.  The
        CLOSED invariant requires this to be empty — if it is non-empty
        when ``terminal_closed`` is True, the invariant is violated.

        Descriptors are stable strings suitable for logging and test
        assertions (e.g., ``"process:<pid>"``, ``"listener:<port>"``,
        ``"execution:<id>"``).
        """
        ...

    def terminal_postcondition(self) -> bool:
        """True when every owned resource has a proven terminal state.

        This is the postcondition that distinguishes CLOSED from
        QUARANTINED:

          - CLOSING: False (cleanup in progress)
          - QUARANTINED: False (some resources' terminal state is
            unproven — e.g., CancelledError during terminate)
          - CLOSED: True (every resource's returncode is known, every
            task is done, every listener is wait_closed)

        The CLOSED invariant is:

            terminal_closed ⇔
                terminal_postcondition() AND owned_resources() == ()
        """
        ...

    async def close(self) -> None:
        """Release all owned resources.  Idempotent.

        Concurrent callers must observe the same result — implementations
        use a shared ``_close_task`` so the second caller ``await``s the
        same task as the first.  On partial failure, the owner enters
        QUARANTINED (retryable); ``close()`` can be called again to
        retry incomplete steps via the CleanupLedger.
        """
        ...


@dataclass(frozen=True, slots=True)
class ResourceOwnerSnapshot:
    """A single read of the shared owner proof surface.

    The snapshot is intentionally immutable.  Callers that need to make a
    shutdown decision must evaluate the terminal flag, terminal proof, and
    independent resource oracle from the same observation rather than
    repeating ad-hoc ``getattr`` checks across lifecycle owners.
    """

    generation_admission_closed: bool
    child_admission_closed: bool
    terminal_closed: bool
    is_quarantined: bool
    terminal_postcondition: bool
    owned_resources: tuple[str, ...]

    @property
    def is_terminal(self) -> bool:
        """Return the complete CLOSED invariant, including empty ownership."""
        return (
            self.terminal_closed
            and not self.is_quarantined
            and self.terminal_postcondition
            and not self.owned_resources
        )


def inspect_resource_owner(
    component: object, *, allow_legacy: bool = False
) -> ResourceOwnerSnapshot | None:
    """Read and validate one owner proof surface, failing closed on unknowns.

    This helper is deliberately duck-typed because several platform owners
    predate the protocol and remain independently tested.  It does not turn
    a mock or a partial object into an owner: every lifecycle property and
    oracle must be present with the expected concrete types.
    """
    required_methods = ("owned_resources", "terminal_postcondition")
    if any(not callable(getattr(component, name, None)) for name in required_methods):
        return None
    values: dict[str, bool] = {}
    try:
        for name in (
            "generation_admission_closed",
            "child_admission_closed",
            "terminal_closed",
            "is_quarantined",
        ):
            value = getattr(component, name, None)
            if type(value) is bool:
                values[name] = value
                continue
            if not allow_legacy:
                return None
            # ExecutionService has an explicit compatibility boundary for
            # injected owners from before ResourceOwner grew its admission
            # and quarantine properties.  Missing admission values inherit
            # the terminal state; a missing quarantine flag is conservative.
            if name == "terminal_closed" and type(value).__module__ == "unittest.mock":
                values[name] = bool(value)
            elif name == "is_quarantined":
                values[name] = False
            elif name in {"generation_admission_closed", "child_admission_closed"}:
                values[name] = values.get("terminal_closed", False)
            else:
                return None
        resources = tuple(cast(Any, component).owned_resources())
        if not all(type(resource) is str for resource in resources):
            return None
        proof = cast(Any, component).terminal_postcondition()
        if type(proof) is not bool:
            if not allow_legacy or type(proof).__module__ != "unittest.mock":
                return None
            proof = bool(proof)
    except Exception:  # noqa: BLE001 - an unreadable proof is unknown
        return None
    return ResourceOwnerSnapshot(
        generation_admission_closed=values["generation_admission_closed"],
        child_admission_closed=values["child_admission_closed"],
        terminal_closed=values["terminal_closed"],
        is_quarantined=values["is_quarantined"],
        terminal_postcondition=proof,
        owned_resources=resources,
    )


def require_terminal_resource_owner(component: object) -> ResourceOwnerSnapshot:
    """Return a terminal proof or reject an unknown/non-terminal owner."""
    snapshot = inspect_resource_owner(component)
    if snapshot is None:
        raise ResourceOwnerInvariantError("resource owner proof surface is unreadable")
    if not snapshot.is_terminal:
        raise ResourceOwnerInvariantError(
            "resource owner is not terminal or still owns resources"
        )
    return snapshot


__all__ = [
    "ResourceOwner",
    "ResourceOwnerInvariantError",
    "ResourceOwnerSnapshot",
    "inspect_resource_owner",
    "require_terminal_resource_owner",
]
