"""Office Workspace mutation authority — git-independent lifecycle fence.

The Office mode file tools (``copy_file`` / ``move_file`` / ``write_file`` …)
historically ran through a bare ``asyncio.to_thread`` call.  Cancellation or a
scheduler timeout only cancelled the *awaiting* task; the underlying thread
kept running and could still publish a side effect via the final atomic rename
*after* the tool call had already been reported as failed/cancelled to the
caller (H1).

This module closes that hole by reusing the same three root-agnostic safety
primitives the Coding-mode ``WorkspaceManager`` already relies on:

* ``WorkspaceStorageAuthority`` — ``assess`` / ``mutate`` /
  ``capture_workspace_snapshot`` are pure ``os.walk`` walks and do NOT touch
  git.  They give us baseline capture, aggregate byte/entry accounting (M1),
  and identity-bound rollback.
* ``WorkspaceMutationFence`` — keyed purely by ``workspace_id`` string, fully
  root-agnostic.  Gives us per-root serialization.
* The ``asyncio.shield`` cancellation pattern from
  ``WorkspaceManager.mutate_with_storage_authority``: a ``to_thread`` future
  cannot be force-cancelled, so we hold the fence until the authority has
  committed or rolled back, and only then propagate ``CancelledError``.

Unlike ``TaskWorkspace`` (which is bound to a git worktree, a base SHA and a
git identity), an ``OfficeWorkspace`` is just a root directory plus its storage
baseline.  Office mode has no worktree semantics, so we keep a dedicated,
narrow dataclass rather than polluting ``TaskWorkspace`` with empty git fields.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

from khaos.coding.workspace.boundary import MutationCancelled
from khaos.coding.workspace.storage import (
    WorkspaceMutation,
    WorkspaceStorageAuthority,
    WorkspaceStorageLimits,
    WorkspaceStorageSnapshot,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)

logger = logging.getLogger(__name__)
T = TypeVar("T")


class OfficeMutationError(RuntimeError):
    """Raised when an Office Workspace mutation cannot be completed safely."""


@dataclass
class OfficeWorkspace:
    """One Office root and its captured storage baseline.

    ``writable`` is flipped to ``False`` once the workspace is quarantined or
    shut down; subsequent mutations fail closed immediately.
    """

    id: str
    root: Path
    baseline: WorkspaceStorageSnapshot | None
    limits: WorkspaceStorageLimits
    writable: bool = True
    # Per-root asyncio lock — created lazily by the authority so the workspace
    # dataclass stays cheap to construct.
    mutation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class OfficeMutationAuthority:
    """Serialize, account and roll back Office file-tool mutations.

    One authority instance is shared per runtime.  Each distinct Office root is
    opened once (baseline captured) and then every mutation against it is
    funneled through the storage authority + a per-root fence, mirroring the
    Coding-mode contract.
    """

    def __init__(
        self,
        storage_authority: WorkspaceStorageAuthority | None = None,
        storage_limits: WorkspaceStorageLimits | None = None,
    ) -> None:
        self._storage_authority = storage_authority or WorkspaceStorageAuthority()
        self._storage_limits = storage_limits or WorkspaceStorageLimits()
        self._workspaces: dict[str, OfficeWorkspace] = {}
        self._by_root: dict[Path, str] = {}
        self._registry_lock = asyncio.Lock()
        # Track in-flight mutation tasks so shutdown can wait for them to
        # settle — see ``wait_for_inflight`` / ``shutdown``.
        self._inflight: set[asyncio.Task] = set()
        # H3: once ``_closing`` is set, no new mutation may register a
        # worker.  ``shutdown()`` sets this atomically with ``writable=False``
        # so a queued mutation that passed the outer writable check is
        # caught by the re-check inside the lock.
        self._closing: bool = False

    async def workspace_for_root(self, root: Path) -> OfficeWorkspace:
        """Return (creating if necessary) the Office workspace for ``root``.

        The baseline is captured synchronously; on failure the workspace is
        still opened but marked non-writable so subsequent mutations fail
        closed instead of running without accounting.
        """
        canonical = root.expanduser().resolve()
        async with self._registry_lock:
            existing_id = self._by_root.get(canonical)
            if existing_id is not None:
                return self._workspaces[existing_id]
            workspace_id = self._workspace_id(canonical)
            baseline = await asyncio.to_thread(capture_workspace_snapshot, canonical)
            if baseline is None or not baseline.complete:
                logger.warning(
                    "Office storage baseline for %s is incomplete; "
                    "workspace opened read-only",
                    canonical,
                )
            workspace = OfficeWorkspace(
                id=workspace_id,
                root=canonical,
                baseline=baseline,
                limits=self._storage_limits,
                writable=baseline is not None and baseline.complete,
            )
            self._workspaces[workspace_id] = workspace
            self._by_root[canonical] = workspace_id
            return workspace

    async def mutate(
        self,
        workspace: OfficeWorkspace,
        operation: Callable[[threading.Event], WorkspaceMutation[T]],
    ) -> T:
        """Apply one Office mutation under the storage authority + fence.

        H2 cooperative cancellation:

        * A ``threading.Event`` is created per mutation and passed to the
          operation.  The operation checks it just before the final atomic
          rename/link; if set, ``MutationCancelled`` is raised, the temp
          tree is cleaned up, and no side effect lands.

        * When the caller cancels (``CancelledError``), the event is set
          *and* we keep waiting (under the lock) for the worker to settle —
          a ``to_thread`` future cannot be force-cancelled.  If the worker
          already committed (returned a value) before checking the event,
          we return the success result (H1 invariant: a call must never
          report failure while the side effect has landed).  If the worker
          aborted (``MutationCancelled``) or raised, we propagate
          ``CancelledError``.

        H3 concurrency:

        * ``writable`` and ``_closing`` are checked *outside* the lock for
          fast-path rejection, then *re-checked inside* the lock so a
          quarantine or shutdown that landed while we were queued on the
          lock is caught before any worker is created.
        """
        # H3: fast-path check outside the lock.
        if self._closing or not workspace.writable:
            raise OfficeMutationError(
                f"Office workspace {workspace.id} is not writable"
            )
        # H2: acquire the per-root fence BEFORE creating the worker so a
        # cancellation while queued on the lock cannot orphan a running
        # thread.
        async with workspace.mutation_lock:
            # H3: re-check inside the lock — a previous mutation may have
            # quarantined the workspace, or shutdown may have started,
            # while we were queued.
            if self._closing or not workspace.writable:
                raise OfficeMutationError(
                    f"Office workspace {workspace.id} became non-writable "
                    f"while waiting for the mutation lock"
                )
            # H2: cooperative cancel flag — checked by the operation just
            # before the atomic publish.
            cancel_event = threading.Event()

            def wrapped_operation() -> WorkspaceMutation[T]:
                return operation(cancel_event)

            worker = asyncio.create_task(
                asyncio.to_thread(
                    self._storage_authority.mutate,
                    workspace.id,
                    workspace.root,
                    workspace.baseline,
                    workspace.limits,
                    wrapped_operation,
                )
            )
            self._inflight.add(worker)
            cancelled = False
            try:
                while not worker.done():
                    try:
                        return await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        # H2: signal the worker to abort before publish.
                        # ``to_thread`` cannot be force-cancelled, so we
                        # keep looping (under the lock) until the worker
                        # settles.  H1: if the worker already committed,
                        # the next ``await asyncio.shield(worker)`` returns
                        # its success result — a call must never report
                        # failure while the side effect has landed.
                        cancelled = True
                        cancel_event.set()
                        # ``uncancel`` *now* (not after the loop) so the
                        # next ``await`` actually waits for the worker
                        # instead of re-raising CancelledError immediately.
                        current = asyncio.current_task()
                        if current is not None and hasattr(current, "uncancel"):
                            current.uncancel()
                    except MutationCancelled:
                        # H2: the worker cooperatively aborted before the
                        # atomic publish (it checked ``cancel_event`` and
                        # raised).  This is re-raised by ``asyncio.shield``
                        # directly — NOT as ``CancelledError`` — so without
                        # this catch it would bypass the conversion below
                        # and propagate as ``MutationCancelled`` to the
                        # caller.  If the caller cancelled, propagate
                        # ``CancelledError`` (the side effect did not land,
                        # so the H1 invariant is not violated).  If the
                        # caller did NOT cancel, re-raise as-is (shouldn't
                        # happen in practice — ``cancel_event`` is only set
                        # by this method when ``CancelledError`` is caught).
                        if cancelled:
                            raise asyncio.CancelledError()
                        raise
                # Worker settled without returning (it raised).
                exc = worker.exception()
                if exc is not None:
                    # H2: if the worker raised ``MutationCancelled`` (or
                    # any non-violation exception) and the caller cancelled,
                    # propagate ``CancelledError`` — the side effect did
                    # not land.  ``WorkspaceStorageViolation`` is propagated
                    # as-is so the outer except can quarantine.
                    if not isinstance(exc, WorkspaceStorageViolation) and cancelled:
                        raise asyncio.CancelledError()
                    raise exc
                if cancelled:
                    # Defensive: worker returned a value but we were
                    # cancelled — shouldn't happen (we'd have returned
                    # inside the while loop), but fail safe.
                    raise asyncio.CancelledError()
                return worker.result()
            except WorkspaceStorageViolation as exc:
                if exc.quarantine_required:
                    await asyncio.shield(self.quarantine(workspace))
                raise
            finally:
                self._inflight.discard(worker)

    async def quarantine(self, workspace: OfficeWorkspace) -> None:
        """Fail closed: mark the workspace non-writable and release accounting."""
        async with self._registry_lock:
            workspace.writable = False
            logger.error(
                "Office workspace %s quarantined after storage violation",
                workspace.id,
            )

    async def wait_for_inflight(self) -> None:
        """Block until no mutation worker is still running.

        Called at turn end / shutdown / mode-switch so a cancelled call cannot
        keep mutating the filesystem after its result event has been emitted.

        H3: loops until ``_inflight`` is stably empty.  With ``_closing=True``
        no new workers can be registered, so the loop normally executes once;
        the repetition is defensive against any race in the registration path.
        """
        while self._inflight:
            pending = list(self._inflight)
            # Shield: we are *waiting* for them to settle, not trying to cancel.
            await asyncio.gather(*pending, return_exceptions=True)

    async def shutdown(self) -> None:
        """Wait for in-flight mutations, then mark every workspace read-only.

        H3: ``_closing`` and ``writable=False`` are set *atomically* (under
        ``_registry_lock``) *before* waiting for in-flight workers.  This
        closes the race where a mutation that passed the outer writable
        check could create a new worker after ``wait_for_inflight`` snapshotted
        the set but before ``writable`` was flipped.  With ``_closing=True``,
        any mutation that reaches the lock re-check will fail closed without
        creating a worker.
        """
        async with self._registry_lock:
            self._closing = True
            for workspace in self._workspaces.values():
                workspace.writable = False
        await self.wait_for_inflight()

    @staticmethod
    def _workspace_id(root: Path) -> str:
        digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
        return f"office-{digest}"
