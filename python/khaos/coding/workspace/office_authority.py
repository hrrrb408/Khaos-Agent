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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generic, TypeVar

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
        operation: Callable[[], WorkspaceMutation[T]],
    ) -> T:
        """Apply one Office mutation under the storage authority + fence.

        H1/H2 cancellation semantics:

        * H2: the per-root ``mutation_lock`` is acquired *before* the worker
          task is created.  A cancellation that arrives while queued on the
          lock simply unwinds — no worker is orphaned, no destination can
          appear.  Previously the worker was created first and could keep
          running after the caller had already received the cancellation.

        * H1: a ``to_thread`` future cannot be force-cancelled, so we
          ``asyncio.shield`` the worker until the authority has committed or
          rolled back.  If the worker has *already committed* (returned a
          value) by the time cancellation propagates, we return the success
          result rather than raising ``CancelledError`` — a call must never
          report failure while the side effect has already landed.  Only
          when the worker raised (did not commit) do we propagate the
          worker's exception (or ``CancelledError`` if the worker was
          interrupted before it could even start).
        """
        if not workspace.writable:
            raise OfficeMutationError(
                f"Office workspace {workspace.id} is not writable"
            )
        # H2: acquire the per-root fence BEFORE creating the worker so a
        # cancellation while queued on the lock cannot orphan a running
        # thread.  The lock serializes mutations per root; holding it before
        # worker creation guarantees the worker only starts once we are
        # committed to waiting for it.
        async with workspace.mutation_lock:
            worker = asyncio.create_task(
                asyncio.to_thread(
                    self._storage_authority.mutate,
                    workspace.id,
                    workspace.root,
                    workspace.baseline,
                    workspace.limits,
                    operation,
                )
            )
            self._inflight.add(worker)
            cancelled = False
            try:
                while not worker.done():
                    try:
                        return await asyncio.shield(worker)
                    except asyncio.CancelledError:
                        # ``to_thread`` cannot be force-cancelled.  Keep
                        # looping (under the lock) until the worker settles,
                        # so the authority has either committed or rolled
                        # back before we release the fence.  H1: do NOT
                        # raise CancelledError here — if the worker later
                        # commits, we return its success result.
                        # We must ``uncancel`` the current task *now* (not
                        # after the loop) so the next ``await`` actually
                        # waits for the worker instead of re-raising
                        # CancelledError immediately.  Python 3.11+ keeps a
                        # cancellation count; without ``uncancel`` the
                        # count stays > 0 and every subsequent await
                        # raises CancelledError, turning this loop into a
                        # busy-spin that never lets the worker finish.
                        cancelled = True
                        current = asyncio.current_task()
                        if current is not None and hasattr(current, "uncancel"):
                            current.uncancel()
                # Worker has settled.  H1: if it committed successfully,
                # return the result — do NOT mask a success as cancellation.
                # If it raised (e.g. WorkspaceStorageViolation), propagate
                # that exception (it is the real outcome, not the cancel).
                exc = worker.exception()
                if exc is not None:
                    raise exc
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
        """
        if not self._inflight:
            return
        pending = list(self._inflight)
        # Shield: we are *waiting* for them to settle, not trying to cancel.
        await asyncio.gather(*pending, return_exceptions=True)

    async def shutdown(self) -> None:
        """Wait for in-flight mutations, then mark every workspace read-only."""
        await self.wait_for_inflight()
        async with self._registry_lock:
            for workspace in self._workspaces.values():
                workspace.writable = False

    @staticmethod
    def _workspace_id(root: Path) -> str:
        digest = hashlib.sha256(str(root).encode("utf-8")).hexdigest()[:16]
        return f"office-{digest}"
