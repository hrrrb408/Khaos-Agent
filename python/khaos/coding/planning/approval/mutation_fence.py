"""Unified per-workspace mutation fence (Batch 2.6 §5).

Serializes ALL workspace mutations through a single per-workspace lock:

* execution lease acquire (live validation + consume)
* RepositoryIndexer generation update
* planned Git/HEAD update
* Workspace cleanup
* Task terminal transition
* Batch 3 planned mutation entry

Lock ordering: **fence first** → manager locks → store transactions.
This guarantees no deadlock between concurrent paths because the fence
is always the outermost lock.

The fence is per-workspace (keyed by ``workspace_id``). Each workspace
gets its own ``asyncio.Lock`` so unrelated workspaces never block each
other. An owner string tracks *who* holds the fence (e.g.
``"lease:{lease_id}"``, ``"cleanup:{workspace_id}""``,
``"cancel:{task_id}"``) so that non-owner planned mutations can be
rejected even when the fence is held.

This batch (2.6) does NOT execute real git/file mutations — it only
provides the fence, the hook points, and the ``PlannedHeadMutationAdapter``
stub. Real mutations arrive in Batch 3.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from contextlib import contextmanager
from typing import Any, AsyncIterator, Callable, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    import asyncio

logger = logging.getLogger(__name__)


class WorkspaceMutationFence:
    """Per-workspace mutation fence (Batch 2.6 §5).

    Maintains one ``asyncio.Lock`` per workspace_id plus an owner string
    so that planned mutations can verify they are being executed by the
    fence holder (non-owner rejection).

    All acquisition is **async** (``asyncio.Lock``). Sync code paths
    (e.g. :meth:`PlanExecutionGate.acquire_lease`) must use
    :meth:`assert_owner` to verify the fence is already held — they
    cannot acquire it themselves. The async caller is responsible for
    acquiring the fence before calling sync gate methods.
    """

    def __init__(self) -> None:
        import threading

        self._locks: dict[str, "asyncio.Lock"] = {}
        self._owners: dict[str, str] = {}
        self._poisoned: dict[str, dict[str, str]] = {}
        self._sync_locks: dict[str, Any] = {}
        # Protects _locks and _owners dicts (not the asyncio locks themselves).
        self._registry_lock = threading.Lock()

    def _get_or_create_lock(self, workspace_id: str) -> "asyncio.Lock":
        import asyncio

        with self._registry_lock:
            if workspace_id not in self._locks:
                self._locks[workspace_id] = asyncio.Lock()
            return self._locks[workspace_id]

    @asynccontextmanager
    async def use(
        self, workspace_id: str, *, owner: str
    ) -> AsyncIterator[None]:
        """Acquire the fence for a workspace mutation.

        ``owner`` identifies who holds the fence (e.g.
        ``"lease:{lease_id}"``). Planned mutations verify ownership via
        :meth:`assert_owner`.
        """
        with self._registry_lock:
            reasons = self._poisoned.get(workspace_id, {})
        if reasons:
            raise PermissionError(
                f"workspace {workspace_id!r} is poisoned: "
                f"{','.join(sorted(reasons.values()))}"
            )
        import asyncio

        lock = self._get_or_create_lock(workspace_id)
        with self._registry_lock:
            sync_lock = self._sync_locks.setdefault(workspace_id, __import__("threading").Lock())
        await asyncio.to_thread(sync_lock.acquire)
        acquired_async = False
        try:
            await lock.acquire()
            acquired_async = True
            with self._registry_lock:
                reasons = self._poisoned.get(workspace_id, {})
                if reasons:
                    raise PermissionError(
                        f"workspace {workspace_id!r} is poisoned: "
                        f"{','.join(sorted(reasons.values()))}"
                    )
                self._owners[workspace_id] = owner
            yield
        finally:
            with self._registry_lock:
                self._owners.pop(workspace_id, None)
            if acquired_async:
                lock.release()
            sync_lock.release()

    @contextmanager
    def use_sync(self, workspace_id: str, *, owner: str) -> Any:
        """Startup/recovery acquisition of the same canonical workspace fence."""
        import threading

        with self._registry_lock:
            lock = self._sync_locks.setdefault(workspace_id, threading.Lock())
        lock.acquire()
        try:
            with self._registry_lock:
                self._owners[workspace_id] = owner
            yield
        finally:
            with self._registry_lock:
                self._owners.pop(workspace_id, None)
            lock.release()

    def transfer_owner(self, workspace_id: str, new_owner: str) -> None:
        """Transfer fence ownership to a new owner.

        Used when the lease_id is minted AFTER the fence is acquired
        (the fence is acquired with ``owner="lease:pending"`` and then
        transferred to ``owner="lease:{lease_id}"`` once the lease is
        consumed).
        """
        with self._registry_lock:
            if workspace_id in self._owners:
                self._owners[workspace_id] = new_owner

    def assert_owner(self, workspace_id: str, owner: str) -> None:
        """Sync: raise :class:`PermissionError` if fence is not held by ``owner``.

        Used by sync code paths (e.g. :class:`PlannedExecutionGuard`
        methods) to verify the fence is held by the expected lease
        owner before performing a planned mutation.
        """
        with self._registry_lock:
            if self._poisoned.get(workspace_id):
                raise PermissionError(
                    f"workspace {workspace_id!r} is poisoned: "
                    f"{','.join(sorted(self._poisoned[workspace_id].values()))}"
                )
            current = self._owners.get(workspace_id)
            if current != owner:
                raise PermissionError(
                    f"workspace mutation fence for {workspace_id!r} is not "
                    f"held by {owner!r} (current owner: {current!r})"
                )

    def is_locked(self, workspace_id: str) -> bool:
        """Return True if the fence is currently held for ``workspace_id``."""
        with self._registry_lock:
            lock = self._locks.get(workspace_id)
            return lock is not None and lock.locked()

    def current_owner(self, workspace_id: str) -> str | None:
        """Return the current fence owner for ``workspace_id`` (or None)."""
        with self._registry_lock:
            return self._owners.get(workspace_id)

    def poison(self, workspace_id: str, reason: str, *, owner: str = "legacy") -> None:
        """Quarantine a workspace before its mutation lock is released."""
        with self._registry_lock:
            self._poisoned.setdefault(workspace_id, {})[owner] = reason

    def clear_poison(self, workspace_id: str, *, owner: str = "legacy") -> None:
        with self._registry_lock:
            reasons = self._poisoned.get(workspace_id)
            if reasons is None:
                return
            reasons.pop(owner, None)
            if not reasons:
                self._poisoned.pop(workspace_id, None)

    def is_poisoned(self, workspace_id: str) -> bool:
        with self._registry_lock:
            return workspace_id in self._poisoned


class PlannedHeadMutationAdapter:
    """Stub adapter for planned Git/HEAD mutations (Batch 2.6 §5/§6).

    This batch does NOT perform real git operations. It only:

    * Verifies the execution lease is active (via the coordinator).
    * Verifies the workspace mutation fence is held by the lease owner.
    * Records the intended HEAD mutation (for audit / Batch 3 handoff).
    * Verifies HEAD/generation hasn't drifted since lease validation.

    Real git operations arrive in Batch 3.
    """

    def __init__(
        self,
        fence: WorkspaceMutationFence,
        coordinator: Any,
    ) -> None:
        self._fence = fence
        self._coordinator = coordinator
        # workspace_id -> last planned mutation record
        self._planned: dict[str, dict[str, Any]] = {}

    def plan_head_update(
        self,
        ctx: Any,
        *,
        new_head: str,
        expected_current_head: str,
        expected_generation: int,
    ) -> dict[str, Any]:
        """Plan a HEAD update without executing it (stub).

        Verifies:
        1. The execution lease is active (coordinator.require_owner).
        2. The fence is held by ``"lease:{ctx.lease_id}"``.
        3. The expected HEAD/generation matches the context's lease.

        Does NOT perform any real git operation.
        """
        # 1. Verify lease is active
        self._coordinator.require_owner(ctx)

        # 2. Verify fence is held by this lease
        self._fence.assert_owner(
            ctx.workspace_id, f"lease:{ctx.lease_id}"
        )

        # 3. Verify HEAD/generation hasn't drifted
        lease = self._coordinator._runtime._store.get_lease(ctx.lease_id)
        if lease is None:
            raise PermissionError(
                f"lease {ctx.lease_id} not found for planned HEAD update"
            )
        if lease["head_sha"] != expected_current_head:
            raise PermissionError(
                f"HEAD drift: expected {expected_current_head!r}, "
                f"lease has {lease['head_sha']!r}"
            )
        if int(lease["repository_generation"]) != int(expected_generation):
            raise PermissionError(
                f"generation drift: expected {expected_generation}, "
                f"lease has {lease['repository_generation']}"
            )

        # 4. Record the planned mutation (stub — no real git op)
        record: dict[str, Any] = {
            "workspace_id": ctx.workspace_id,
            "new_head": new_head,
            "expected_current_head": expected_current_head,
            "expected_generation": expected_generation,
            "lease_id": ctx.lease_id,
            "status": "planned",
        }
        self._planned[ctx.workspace_id] = record
        logger.info(
            "planned HEAD update for workspace %s: %s -> %s (stub, no real op)",
            ctx.workspace_id, expected_current_head, new_head,
        )
        return record

    @property
    def planned_mutations(self) -> dict[str, dict[str, Any]]:
        """Return a copy of all planned mutations (for test inspection)."""
        return dict(self._planned)


def fenced_acquire_lease(
    coordinator: Any,
    fence: WorkspaceMutationFence,
    guard: Any,
    *,
    authorization_id: str,
    nonce: str,
    expected_plan_id: str,
    expected_task_id: str,
    expected_workspace_id: str,
    expected_repository_id: str,
    owner_execution_id: str = "exec_default",
):
    """Async context manager: acquire fence → lease → yield ctx → release.

    Batch 2.6 §5 flow:
    1. Acquire the workspace mutation fence (owner="lease:pending").
    2. Call ``guard.authorize()`` (sync: live validation + lease-first consume).
    3. Transfer fence ownership to ``"lease:{lease_id}"``.
    4. Yield the :class:`AuthorizedExecutionContext`.
    5. On exit: release the lease, release the fence.

    This is the ONLY sanctioned way for Batch 3 callers to acquire an
    execution context when a fence is configured. The fence is held for
    the entire Batch 3 execution, serializing cleanup/cancel/indexer
    updates with the active lease.
    """

    @asynccontextmanager
    async def _ctx() -> AsyncIterator[Any]:
        async with fence.use(
            expected_workspace_id, owner="lease:pending"
        ):
            ctx = guard.authorize(
                authorization_id=authorization_id,
                nonce=nonce,
                expected_plan_id=expected_plan_id,
                expected_task_id=expected_task_id,
                expected_workspace_id=expected_workspace_id,
                expected_repository_id=expected_repository_id,
                owner_execution_id=owner_execution_id,
            )
            # Transfer fence ownership to the actual lease.
            fence.transfer_owner(
                expected_workspace_id, f"lease:{ctx.lease_id}"
            )
            try:
                yield ctx
            finally:
                try:
                    released = coordinator._runtime.gate.release_lease(ctx.lease_id)
                    if not released:
                        raise RuntimeError("execution lease release was not committed")
                except Exception as exc:
                    reason = f"lease-release-failed:{type(exc).__name__}"
                    fence.poison(expected_workspace_id, reason)
                    try:
                        coordinator._runtime._store.poison_workspace(
                            expected_workspace_id, ctx.lease_id, reason=reason,
                        )
                    except Exception as poison_exc:
                        raise RuntimeError(
                            "lease release failed and durable quarantine could not be recorded"
                        ) from poison_exc
                    raise

    return _ctx()
