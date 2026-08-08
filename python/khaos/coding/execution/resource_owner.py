"""Round-17 review §十四/§十七: unified lifecycle contract for security
resource owners.

The review identified that LSP, ProcessSupervisor, and BrowserEgressProxy
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

Owners that implement this protocol can be uniformly tested by the
Resource Ownership Closure E2E suite (round-17 review §十五) against a
single behavior matrix: cancel-before-acquisition, cancel-during-
acquisition, cancel-after-publication, cleanup-exception, cleanup-
CancelledError, concurrent-close, start-during-close, start-after-close,
first-close-failure-retry, and CLOSED ⇒ no-live-owned-resource.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ResourceOwner(Protocol):
    """Unified lifecycle contract for security resource owners.

    Implementations include :class:`~khaos.coding.execution.service.ExecutionService`,
    :class:`~khaos.coding.execution.managed.ManagedProcessHandle`,
    :class:`~khaos.coding.execution.supervisor.ProcessSupervisor`,
    :class:`~khaos.coding.intelligence.lsp.client.LspClient`, and
    :class:`~khaos.security.browser_egress_proxy.BrowserEgressProxy`.

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
