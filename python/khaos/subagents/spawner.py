"""Single-layer subagent spawner (Phase 8: batching + stats + nesting)."""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Optional

from khaos.exceptions import ServiceShutdownError, SubAgentLimitError, ToolNotFoundError

logger = logging.getLogger(__name__)


@dataclass
class SubAgentConfig:
    """Subagent concurrency and nesting limits."""

    max_concurrent: int = 3
    max_spawn_depth: int = 2
    allow_nesting: bool = False


@dataclass
class SubAgentTask:
    """One subagent task.

    B1: ``principal_id`` binds the task to the authenticated caller so
    ``collect`` / ``status`` only return the caller's own tasks — a
    different principal cannot observe another's goal / result / error.
    """

    id: str
    goal: str
    context: str
    tools: list[str]
    timeout: int = 300
    status: str = "pending"
    result: Optional[str] = None
    error: Optional[str] = None
    parent_session_id: str = "root"
    depth: int = 1
    # B1: the principal that owns this task.  Set by the service from
    # the authenticated RPC payload; used by ``wait_all`` / ``stats`` /
    # ``collect_results`` to filter results.
    principal_id: str = ""


Runner = Callable[[SubAgentTask], Awaitable[str]]


class SubAgentSpawner:
    """Spawn and manage subagents.

    Phase 8 enhancements:
    - ``registry`` 可选参数：传入后 spawn 会校验 task.tools 中的工具是否已注册。
    - ``spawn_batch``：批量 spawn，超过并发上限的跳过（不抛异常）。
    - ``stats``：返回 active/total/completed/failed/pending 统计。
    - 嵌套深度由 ``SubAgentConfig.max_spawn_depth`` 控制（Phase 8 默认提升到 2）。
    """

    def __init__(
        self,
        config: SubAgentConfig,
        db,
        runner: Runner | None = None,
        registry=None,  # ToolRegistry，可选
    ):
        self.config = config
        self.db = db
        self.runner = runner or self._default_runner
        self.registry = registry
        self._active_tasks: dict[str, asyncio.Task] = {}
        self._tasks: dict[str, SubAgentTask] = {}
        # H1: once shutdown begins, every subsequent spawn is rejected so a
        # detached RPC caller cannot keep the spawner alive while the server
        # is tearing shared authorities (Office / Browser / Audit / DB) down.
        self._shutting_down: bool = False
        # M2: serialize spawn vs shutdown so a spawn that has passed its
        # _shutting_down check and is mid-DB-await cannot be missed by a
        # concurrent shutdown's _active_tasks snapshot (which would leave
        # the spawned task as an untracked orphan still borrowing shared
        # authorities).  Both operations hold this lock across the whole
        # critical section: spawn from its shutdown-check through inserting
        # the new task into _active_tasks; shutdown from flipping
        # _shutting_down through snapshotting _active_tasks.
        self._spawn_lock: asyncio.Lock = asyncio.Lock()
        # M1 (round-5): track the owner task (the spawn coroutine) for each
        # initializing reservation so shutdown can cancel + await it within
        # the total deadline.  Previously shutdown only cancelled
        # ``_active_tasks`` (published runners) and treated initializing
        # reservations as "done by definition" — but the spawn coroutine
        # doing the DB work was still alive and could complete (inserting
        # a row / launching a runner) AFTER shutdown returned.
        self._initializing_owners: dict[str, asyncio.Task] = {}
        # H2 (round-5): track terminal states that have been set in memory
        # but not yet persisted to the DB.  Reconcile retries these on every
        # shutdown until the UPDATE succeeds.  Previously reconcile changed
        # memory status to ``failed`` BEFORE the DB write; if the write
        # failed, the next shutdown saw a terminal memory status and skipped
        # the task — the DB row stayed ``running`` forever.
        self._pending_persistence: set[str] = set()
        # M2 (round-6): track in-flight reconcile owner tasks so a
        # subsequent shutdown can see they're still running (and the
        # caller retains ownership of the shared authorities they
        # borrow).  ``asyncio.wait`` with a timeout returns without
        # cancelling the inner task on timeout, so we must NOT lose
        # the reference — otherwise a wedged DB reconcile would leak
        # the task and the DB connection it holds.
        self._reconcile_owners: set[asyncio.Task] = set()

    @property
    def active_count(self) -> int:
        # H1 (round-5): count initializing reservations too, not just
        # published runners.  The reservation pattern defers runner
        # publication until after DB I/O, so counting only
        # ``_active_tasks`` lets concurrent spawns bypass
        # ``max_concurrent`` during the DB work window:
        #
        #   max_concurrent=1
        #   Spawn A: active_count=0 → reserve A (initializing)
        #   Spawn B: active_count=0 → reserve B (initializing)  ← BUG
        #   DB resumes: A and B both publish runners
        #   Final: 2 runners (limit was 1)
        #
        # Counting initializing closes that window.
        initializing = sum(
            1 for t in self._tasks.values() if t.status == "initializing"
        )
        return len(self._active_tasks) + initializing

    def _ensure_task_id(self, task: SubAgentTask) -> None:
        """生成稳定的 task_id（UUID4 形式）当为空时。

        M3: 旧的 ``task_N`` 计数器在进程重启后会重置为 0，``ON CONFLICT(id)
        DO UPDATE`` 会覆盖旧任务记录（包括其他 principal 的历史）。  UUID4
        保证全局唯一性，跨重启不会冲突。
        """
        if not task.id:
            task.id = f"task_{uuid.uuid4().hex}"

    def _validate_tools(self, task: SubAgentTask) -> None:
        """校验 task.tools 中的工具是否已注册（需要传入 registry）。"""
        if self.registry is None:
            return
        for name in task.tools:
            try:
                self.registry.get(name)
            except ToolNotFoundError as exc:
                raise SubAgentLimitError(
                    f"task {task.id} 引用了未注册的工具: {name}"
                ) from exc

    async def spawn(self, task: SubAgentTask) -> SubAgentTask:
        """Start a single subagent task.

        嵌套规则：
        - ``allow_nesting=False``（默认）：只允许 ``depth == 1``，任何 ``depth > 1``
          都被拒绝（沿用 ADR-002 的单层语义）。
        - ``allow_nesting=True``：允许嵌套，但仍受 ``max_spawn_depth`` 上限约束。

        Reservation lifecycle (round-5 audit closure):

        The round-4 reservation pattern split validation from DB work to
        avoid holding ``_spawn_lock`` across slow DB I/O.  Round-5 closes
        the remaining lifecycle gaps:

          1. Under ``_spawn_lock`` (cheap): shutdown check, depth /
             concurrency validation, task-id assignment.  Register the
             task in ``_tasks`` with status ``initializing`` AND register
             the spawn coroutine (``asyncio.current_task()``) in
             ``_initializing_owners`` so shutdown can cancel + await it.
             ``active_count`` now counts initializing reservations too,
             closing the H1 max_concurrent bypass.
          2. OUTSIDE the lock: DB ``create_session`` +
             ``insert_subagent_task``.  A slow / wedged DB no longer
             blocks shutdown.  If this raises (cancellation or DB
             error), the ``except`` cleans up ``_initializing_owners``
             and marks the task for reconcile retry.
          3. Under ``_spawn_lock`` again: pop the initializing owner.
             If shutdown flipped ``_shutting_down`` during the DB work,
             persist a ``failed/cancelled`` terminal row via
             ``_persist_terminal`` (which tracks retry state) and return
             without launching the runner.  Otherwise flip status to
             ``running``, create the ``_run_task`` asyncio task, and
             register it in ``_active_tasks``.
        """
        owner = asyncio.current_task()
        # Step 1: validate + reserve under the lock.  No DB I/O here.
        async with self._spawn_lock:
            # H1: reject new work the moment shutdown begins.  A detached RPC
            # caller (one whose ``Spawn`` handler already returned) cannot
            # keep registering new background tasks while the server is
            # dismantling shared authorities.
            if self._shutting_down:
                raise SubAgentLimitError("subagent spawner is shutting down")
            if task.depth > 1 and not self.config.allow_nesting:
                raise SubAgentLimitError(
                    f"subagents cannot spawn nested subagents "
                    f"(depth={task.depth}, nesting disabled)"
                )
            if task.depth > self.config.max_spawn_depth:
                raise SubAgentLimitError(
                    f"subagent nesting exceeds configured depth "
                    f"(depth={task.depth} > max={self.config.max_spawn_depth})"
                )
            if self.active_count >= self.config.max_concurrent:
                raise SubAgentLimitError(f"并发数已达上限 ({self.config.max_concurrent})")
            self._ensure_task_id(task)
            self._validate_tools(task)
            # Reserve the task as ``initializing`` so shutdown's snapshot
            # cannot miss it while the DB work below is in flight.
            task.status = "initializing"
            self._tasks[task.id] = task
            # M1 (round-5): register the spawn coroutine as the owner so
            # shutdown can cancel + await it within the total deadline.
            # Without this, shutdown treats initializing reservations as
            # "done by definition" but the spawn coroutine is still alive
            # doing DB work and could complete after shutdown returned.
            if owner is not None:
                self._initializing_owners[task.id] = owner

        # Steps 2+3: DB work + publish/abort.  Wrapped in a single
        # try/except so cancellation landing at ANY point (during the DB
        # awaits OR while waiting to re-acquire the lock in step 3)
        # cleans up the initializing owner registry and marks the task
        # for reconcile retry.  Without this, a cancellation during
        # step 3 (between the lock acquire and the owner pop) would
        # leave the owner registered forever, and shutdown's next
        # snapshot would keep seeing it as an in-flight owner.
        aborted = False
        try:
            # Step 2: DB work OUTSIDE the lock.  A slow / wedged DB call
            # no longer blocks shutdown from acquiring the lock and
            # running its bounded drain.  Cancellation from shutdown
            # propagates here.
            await self.db.create_session(task.parent_session_id)
            await self.db.insert_subagent_task(
                task.id,
                task.parent_session_id,
                task.goal,
                task.context,
                json.dumps(task.tools),
                task.status,
                # B1: persist the principal so list_subagent_tasks(principal_id)
                # can filter rows on disk, not just in-memory.
                task.principal_id,
            )
            # Step 3: re-acquire the lock to publish or abort.
            async with self._spawn_lock:
                self._initializing_owners.pop(task.id, None)
                if self._shutting_down:
                    # Shutdown began while we were doing the DB work.  The
                    # task was admitted (its reservation is in the snapshot)
                    # but never started running.  Persist a cancelled
                    # terminal state so the DB row does not stay
                    # ``initializing`` forever, and DO NOT launch the runner
                    # (shared authorities may already be torn down).
                    task.status = "failed"
                    task.error = "cancelled"
                    aborted = True
                else:
                    task.status = "running"
                    async_task = asyncio.create_task(self._run_task(task))
                    self._active_tasks[task.id] = async_task
                    # Capture task.id at registration time; the callback
                    # receives the asyncio Task as its argument.
                    _tid = task.id
                    async_task.add_done_callback(
                        lambda _t, tid=_tid: self._active_tasks.pop(tid, None)
                    )
        except BaseException:
            # Cancellation or DB failure during step 2 or step 3.
            # Clean up the owner registry (idempotent pop — step 3 may
            # have already popped it).  Mark for reconcile retry so the
            # next shutdown persists the terminal state if the row exists.
            async with self._spawn_lock:
                self._initializing_owners.pop(task.id, None)
            task.status = "failed"
            task.error = "cancelled"
            self._pending_persistence.add(task.id)
            raise

        # M3 (round-5): persist the aborted terminal state via
        # ``_persist_terminal`` so a DB failure is tracked in
        # ``_pending_persistence`` and retried by the next shutdown's
        # reconcile — no longer best-effort swallowed.  This is OUTSIDE
        # the try/except so a persist failure doesn't re-trigger the
        # except block (which would re-add to _pending_persistence and
        # re-raise, hiding the abort from the caller).
        if aborted:
            try:
                await self._persist_terminal(task)
            except Exception:  # noqa: BLE001 — reconcile will retry
                logger.error(
                    "spawn: could not persist cancelled terminal state for "
                    "task %s (DB work raced with shutdown); will retry on "
                    "next shutdown reconcile",
                    task.id, exc_info=True,
                )
        return task

    async def _persist_terminal(self, task: SubAgentTask) -> None:
        """Persist a terminal state to the DB with retry tracking.

        H2/H3 (round-5): mark the task as pending-persistence BEFORE the
        DB write and only clear that flag AFTER a successful UPDATE.
        This lets the next shutdown's reconcile retry tasks whose
        terminal state was set in memory but never reached the DB (e.g.
        the DB was wedged or the write was cancelled).

        M1 (round-6): validate the UPDATE rowcount.  If the row does
        not exist (spawn was cancelled BEFORE
        ``insert_subagent_task`` ran), the zero-row UPDATE is NOT
        success — fall back to an INSERT so the task's terminal state
        is durably present for later ``collect`` / ``status`` / audit
        queries.  Previously the spawner cleared
        ``_pending_persistence`` on a zero-row UPDATE, so the task
        vanished from every later query even though its in-memory
        state was terminal.

        The caller is responsible for setting ``task.status`` /
        ``task.error`` / ``task.result`` to their terminal values BEFORE
        calling this helper.  This helper does NOT change business
        state — it only persists what's already there and tracks whether
        the persist succeeded.
        """
        self._pending_persistence.add(task.id)
        rowcount = await self.db.update_subagent_task(
            task.id, task.status, task.result, task.error, finished=True,
        )
        if rowcount == 0:
            # M1 (round-6): the row was never INSERTed (spawn was
            # cancelled before ``insert_subagent_task`` ran, or the DB
            # was reset between INSERT and UPDATE).  INSERT the
            # terminal row directly so the task is durably present for
            # later queries instead of vanishing.  ``tools`` is
            # serialized as JSON for parity with the normal spawn
            # path; if the in-memory task lost its tools list (edge
            # case), persist an empty list.
            #
            # The parent session may not exist either (spawn was
            # cancelled before ``create_session`` ran), so create it
            # idempotently first — ``create_session`` uses
            # ``ON CONFLICT DO UPDATE``, so this is safe even if the
            # session already exists.
            await self.db.create_session(task.parent_session_id)
            tools_json = json.dumps(task.tools or [])
            await self.db.insert_subagent_task(
                task.id,
                task.parent_session_id,
                task.goal,
                task.context,
                tools_json,
                task.status,
                task.principal_id,
            )
            # The INSERT path leaves ``result`` / ``error`` /
            # ``finished_at`` unset; re-issue the UPDATE so the
            # terminal state is complete.  This second UPDATE is
            # guaranteed to affect exactly one row (we just INSERTed
            # it), so no further rowcount check is needed.
            await self.db.update_subagent_task(
                task.id, task.status, task.result, task.error, finished=True,
            )
        # Only clear after a successful persist.  If either await above
        # raised, the flag stays set and reconcile retries.
        self._pending_persistence.discard(task.id)

    async def spawn_batch(self, tasks: list[SubAgentTask]) -> list[SubAgentTask]:
        """批量 spawn 多个子任务。

        逻辑：
        1. 检查批量数量不超过 max_concurrent（连同当前已 active 的）
        2. 依次 spawn 每个任务
        3. 如果某个 spawn 失败（并发超限 / 工具未注册 / 深度超限），
           跳过并记录错误，不中断其余任务
        4. 返回所有成功 spawn 的任务
        """
        spawned: list[SubAgentTask] = []
        available = self.config.max_concurrent - self.active_count
        if available <= 0:
            logger.warning(
                "spawn_batch skipped all %d tasks: concurrency full (%d/%d)",
                len(tasks),
                self.active_count,
                self.config.max_concurrent,
            )
            return spawned
        for task in tasks:
            if len(spawned) >= available:
                logger.warning(
                    "spawn_batch reached concurrency limit, skipping remaining %d tasks",
                    len(tasks) - len(spawned),
                )
                break
            try:
                await self.spawn(task)
                spawned.append(task)
            except SubAgentLimitError as exc:
                logger.warning("spawn_batch skipped task: %s", exc)
            except ToolNotFoundError as exc:
                logger.warning("spawn_batch skipped task due to unknown tool: %s", exc)
        return spawned

    def stats(self, principal_id: str = "") -> dict[str, int]:
        """返回当前统计：active/total/completed/failed/pending。

        B1: when ``principal_id`` is set, only tasks owned by that
        principal are counted — a different principal cannot observe
        another's task counts.

        M2: when ``principal_id`` is empty, returns an EMPTY stats dict
        (NOT all tasks).  The only caller that could pass empty principal
        is the Python service, which now rejects it up-front.  If someone
        bypasses the service and calls the spawner directly with empty
        principal, they get NOTHING, not everything.
        """
        tasks = self._tasks_for_principal(principal_id)
        completed = sum(1 for t in tasks if t.status == "completed")
        failed = sum(1 for t in tasks if t.status == "failed")
        pending = sum(1 for t in tasks if t.status == "pending")
        active = sum(
            1 for t in tasks if t.id in self._active_tasks
        )
        return {
            "active": active,
            "total": len(tasks),
            "completed": completed,
            "failed": failed,
            "pending": pending,
        }

    def _tasks_for_principal(self, principal_id: str) -> list[SubAgentTask]:
        """B1: return tasks owned by ``principal_id``.

        M2: when ``principal_id`` is empty, return an EMPTY list (NOT
        all tasks).  The previous "legacy path — return all" behavior
        was a fail-open security boundary: a caller bypassing the
        Python service with an empty principal could observe every
        principal's tasks.  The only caller that could pass empty
        principal is the Python service, and we just made it reject
        empty principal.  If someone bypasses the service and calls
        the spawner directly with empty principal, they get NOTHING.
        """
        if not principal_id:
            return []
        return [t for t in self._tasks.values() if t.principal_id == principal_id]

    async def wait_all(self, timeout: int = 600, principal_id: str = "") -> list[SubAgentTask]:
        """Wait for active tasks owned by ``principal_id`` (B1).

        M2: when ``principal_id`` is empty, returns an EMPTY list
        immediately (NOT all tasks).  See ``_tasks_for_principal`` for
        the rationale.
        """
        if not principal_id:
            return []
        # B1: only wait for tasks owned by this principal.
        owned_active = {
            tid: task for tid, task in self._active_tasks.items()
            if tid in self._tasks and self._tasks[tid].principal_id == principal_id
        }
        if owned_active:
            await asyncio.wait_for(asyncio.gather(*owned_active.values()), timeout=timeout)
        return self._tasks_for_principal(principal_id)

    async def cancel(self, task_id: str) -> None:
        """Cancel one active task.

        H2 (round-5): use ``_persist_terminal`` so a failed DB write is
        tracked in ``_pending_persistence`` and retried by the next
        shutdown's reconcile.  Previously the memory status was flipped
        to ``failed`` before the DB write; if the write failed, the row
        stayed ``running`` and reconcile skipped it (memory was already
        terminal).
        """
        task = self._active_tasks.get(task_id)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        subtask = self._tasks.get(task_id)
        if subtask is None:
            return
        # Only flip + persist if the task hasn't already reached a
        # terminal state via _run_task's own cancel branch.  If it has
        # AND the persist failed, ``_pending_persistence`` carries it
        # for reconcile retry.
        if subtask.status not in {"completed", "failed"}:
            subtask.status = "failed"
            subtask.error = "cancelled"
            try:
                await self._persist_terminal(subtask)
            except Exception:  # noqa: BLE001 — reconcile will retry
                logger.error(
                    "cancel: could not persist terminal state for task %s; "
                    "will retry on next shutdown reconcile",
                    task_id, exc_info=True,
                )

    async def shutdown(self, *, timeout: float = 30.0) -> None:
        """Production shutdown authority for the spawner.

        H1: ``SubAgentService.Spawn`` returns ``running`` while the Spawner
        runs the task on a detached background ``asyncio.Task``.  Without
        this method, server shutdown dismantled Office / Browser / Audit /
        DB while detached subagent runs were still in-flight — those runs
        borrow exactly those shared authorities.

        H1b (round-4): the ``_shutting_down`` flip and snapshot acquire
        ``_spawn_lock``, but ``spawn`` only holds the lock for cheap
        validation + reservation — DB I/O runs outside — so a slow DB
        call cannot block this shutdown from reaching its bounded drain.

        The snapshot covers BOTH ``_active_tasks`` (running runners) AND
        ``_tasks`` entries still in ``initializing`` (reserved but the
        spawn's DB work had not finished when shutdown began).  Both are
        in-flight owners; both must be reconciled.

        M1 (round-5): the snapshot also captures ``_initializing_owners``
        (the spawn coroutines doing DB work).  Previously shutdown only
        cancelled ``_active_tasks`` (published runners) and treated
        initializing reservations as "done by definition" — but the
        spawn coroutine was still alive and could complete after
        shutdown returned.  Now shutdown cancels + drains BOTH runner
        tasks AND initializing owner tasks within the same total
        deadline.

        M2 (round-5): the total deadline covers the reconcile pass too.
        Previously ``timeout`` only bounded ``asyncio.wait``; each DB
        UPDATE in reconcile was an unbounded ``await``, so a wedged DB
        made shutdown hang forever.  Now the remaining budget after the
        drain is passed to reconcile via ``asyncio.wait_for``.

        M1 (round-4): only ``done`` tasks are reconciled to a terminal
        DB state.  ``pending`` tasks (still running, swallowed cancel)
        are LEFT at their current status — falsely marking a still-
        running task ``failed/cancelled`` would hide that it still
        borrows shared authorities.  Pending at the deadline raises
        ``ServiceShutdownError``.

        M2 (round-4): DB reconciliation failures propagate as
        ``ServiceShutdownError`` instead of being swallowed.  Silently
        logging them would let shutdown close the DB while a row is
        still ``running`` — exactly the durability gap this reconcile
        pass exists to close.
        """
        import time
        deadline = time.monotonic() + timeout
        async with self._spawn_lock:
            self._shutting_down = True
            # Snapshot every reserved task — both running and initializing.
            # ``_tasks`` is the superset (spawn adds to it before the DB
            # work and before promoting to _active_tasks).
            snapshot_ids = [
                tid for tid, t in self._tasks.items()
                if t.status in ("running", "initializing", "pending")
            ]
            # Capture the id → asyncio.Task mapping at snapshot time so we
            # can match ``done`` entries by identity AFTER the wait, even
            # though each task's done-callback pops it from
            # ``_active_tasks`` during the wait.
            snapshot_active_map = {
                tid: self._active_tasks[tid]
                for tid in snapshot_ids
                if tid in self._active_tasks
            }
            active_snapshot = list(snapshot_active_map.values())
            # M1 (round-5): also snapshot initializing owner tasks (the
            # spawn coroutines doing DB work).  These are NOT in
            # ``_active_tasks`` (the runner hasn't been published yet) so
            # the previous shutdown missed them.
            snapshot_init_owners = {
                tid: self._initializing_owners[tid]
                for tid in snapshot_ids
                if tid in self._initializing_owners
            }
            init_owner_snapshot = list(snapshot_init_owners.values())
        # Cancel + drain active runners AND initializing owners within
        # the same total deadline.  Both are in-flight owners borrowing
        # shared authorities.
        all_to_cancel = active_snapshot + init_owner_snapshot
        for task in all_to_cancel:
            task.cancel()
        done: set = set()
        pending: set = set()
        if all_to_cancel:
            remaining = max(deadline - time.monotonic(), 0.0)
            done, pending = await asyncio.wait(all_to_cancel, timeout=remaining)
        # M1 (round-4): reconcile ONLY the done tasks.  ``done`` here is
        # the set of asyncio Tasks that terminated; their SubAgentTask
        # may still be non-terminal if _run_task's body never ran.  We do
        # NOT touch pending tasks' DB rows — they are still alive.
        done_ids: set[str] = set()
        for tid, atask in snapshot_active_map.items():
            if atask in done:
                done_ids.add(tid)
        for tid, atask in snapshot_init_owners.items():
            if atask in done:
                done_ids.add(tid)
        # Also include initializing reservations whose owner was never
        # registered (defensive — covers direct _tasks injection in
        # tests where spawn's owner registration didn't run).
        for tid in snapshot_ids:
            subtask = self._tasks.get(tid)
            if subtask is not None and subtask.status == "initializing":
                if tid not in snapshot_init_owners:
                    done_ids.add(tid)
        # H2 (round-5): a previous shutdown's reconcile may have flipped
        # a task's memory status to terminal but failed the DB write
        # (it's in ``_pending_persistence``).  Such tasks are NOT in the
        # snapshot above (they're already terminal in memory), so without
        # this they would never be retried — the DB row would stay
        # ``running`` forever.  Include them in the reconcile pass so
        # every shutdown retries until persistence succeeds.
        for tid in list(self._pending_persistence):
            if tid in self._tasks:
                done_ids.add(tid)
        # M2 (round-5): bound reconcile by the remaining deadline.  A
        # wedged DB must not make shutdown hang forever.
        # M2 (round-6): run reconcile in its own owner task and use
        # ``asyncio.wait`` (NOT ``wait_for``) so a cancellation-resistant
        # DB coroutine cannot make shutdown exceed the total deadline.
        # ``wait_for`` cancels the inner coroutine on timeout and then
        # WAITS for it to actually terminate — if the inner coroutine
        # swallows ``CancelledError`` (e.g. a wedged aiosqlite connection
        # that catches it for connection-pool cleanup), ``wait_for`` hangs
        # forever.  ``asyncio.wait`` with a timeout returns immediately
        # on timeout WITHOUT cancelling the inner task, leaving it
        # pending.  We raise ``ServiceShutdownError`` and leave the
        # reconcile task alive — the caller retains ownership (the task
        # is registered in ``_reconcile_owners`` so a subsequent
        # shutdown can re-drain it).
        remaining = deadline - time.monotonic()
        if done_ids:
            if remaining <= 0:
                raise ServiceShutdownError(
                    f"no budget remaining for terminal state reconciliation; "
                    f"{len(done_ids)} task(s) need persistence, "
                    f"{len(self._pending_persistence)} pending"
                )
            reconcile_task = asyncio.create_task(
                self._reconcile_terminal_states(done_ids)
            )
            # Track the reconcile owner so a subsequent shutdown can
            # see it's still in flight (and cancel + drain it if the
            # DB eventually un-wedges).  Without this tracking the
            # task would be orphaned if shutdown raises below.
            self._reconcile_owners.add(reconcile_task)
            reconcile_task.add_done_callback(
                self._reconcile_owners.discard
            )
            done_reconcile, pending_reconcile = await asyncio.wait(
                {reconcile_task}, timeout=remaining,
            )
            if pending_reconcile:
                # The reconcile task is still running — do NOT cancel
                # it (cancellation may not propagate through a wedged
                # DB await).  Leave it registered in
                # ``_reconcile_owners`` so the caller / next shutdown
                # retains ownership.  Raise so the caller refuses to
                # tear down shared authorities.
                logger.error(
                    "subagent spawner shutdown: terminal state "
                    "reconciliation did not complete within %.2fs budget; "
                    "%d task(s) still pending persistence, reconcile "
                    "owner retained",
                    remaining, len(self._pending_persistence),
                )
                raise ServiceShutdownError(
                    f"terminal state reconciliation did not complete within "
                    f"remaining {remaining:.2f}s budget; "
                    f"{len(self._pending_persistence)} task(s) still pending"
                )
            # Reconcile completed — surface any exception it raised
            # (e.g. a DB write failure that left tasks in
            # ``_pending_persistence`` for the next shutdown).
            exc = reconcile_task.exception()
            if exc is not None:
                raise exc
        if pending:
            unfinished = len(pending)
            logger.error(
                "subagent spawner shutdown: %d task(s) did not terminate "
                "within %.2fs (swallowed cancellation or wedged); refusing "
                "to release shared authority ownership",
                unfinished,
                timeout,
            )
            raise ServiceShutdownError(
                f"{unfinished} subagent task(s) did not terminate within "
                f"{timeout}s; shared authorities cannot be torn down safely"
            )

    async def _reconcile_terminal_states(self, task_ids: set[str]) -> None:
        """H2 (round-5): persist terminal DB state for done shutdown tasks.

        Walks the given task IDs and, for any whose terminal state has
        NOT been persisted yet (either because the in-memory status is
        still non-terminal, or because a previous persist attempt failed
        and the task is in ``_pending_persistence``), writes the terminal
        state to the DB via ``_persist_terminal``.

        This is the authoritative safety net for:

        - cancel-before-first-run (``_run_task``'s body never executed —
          Python does not enter a coroutine body that is cancelled before
          its first scheduling slot)
        - ``_run_task`` DB write failure (terminal memory state set but
          persist failed)
        - ``spawn`` abort DB write failure (same)
        - previous shutdown's reconcile failure / timeout (retry until
          durable)

        H2 (round-5): the previous reconcile changed memory status to
        ``failed`` BEFORE the DB write.  If the write failed, the next
        shutdown saw a terminal memory status and skipped the task —
        the DB row stayed ``running`` forever.  Now ``_persist_terminal``
        tracks ``_pending_persistence`` independently of business state,
        so reconcile retries until the UPDATE succeeds.

        M2 (round-4): failures propagate as ``ServiceShutdownError`` so
        the caller refuses to tear down shared authorities while a row
        is still non-terminal.
        """
        TERMINAL = {"completed", "failed"}
        # Determine which tasks need a terminal DB write:
        # - done tasks whose in-memory status is still non-terminal
        #   (cancel-before-first-run)
        # - tasks whose terminal state was set but not yet persisted
        #   (retry on subsequent shutdown)
        needs_write: list[str] = []
        for task_id in task_ids:
            subtask = self._tasks.get(task_id)
            if subtask is None:
                continue
            if subtask.status in TERMINAL:
                # Already terminal in memory — only reconcile if not yet
                # persisted (previous attempt failed or was cancelled).
                if task_id in self._pending_persistence:
                    needs_write.append(task_id)
            else:
                # Non-terminal in memory but task is done — needs a
                # terminal write (cancel-before-first-run case).
                needs_write.append(task_id)
        failures: list[str] = []
        for task_id in needs_write:
            subtask = self._tasks[task_id]
            if subtask.status not in TERMINAL:
                subtask.status = "failed"
                subtask.error = "cancelled"
            try:
                await self._persist_terminal(subtask)
            except Exception:  # noqa: BLE001 — surface as shutdown failure
                # M2 (round-4): do NOT swallow.  Silently logging would let
                # shutdown close the DB while a row is still ``running``,
                # which is exactly the durability gap this reconcile pass
                # exists to close.  Record the failure and raise after the
                # loop so the caller observes it.  _pending_persistence
                # retains the task for the next shutdown's retry.
                logger.error(
                    "subagent shutdown: could not persist terminal state "
                    "for task %s — durability gap, refusing to continue "
                    "teardown",
                    task_id,
                    exc_info=True,
                )
                failures.append(task_id)
        if failures:
            raise ServiceShutdownError(
                f"could not persist terminal state for {len(failures)} "
                f"subagent task(s): {failures}; DB may be closed under live rows"
            )

    async def collect_results(self, principal_id: str = "") -> list[str]:
        """Collect completed task results (B1: filtered by principal)."""
        tasks = self._tasks_for_principal(principal_id)
        return [task.result or "" for task in tasks if task.status == "completed"]

    async def _run_task(self, task: SubAgentTask) -> None:
        """Execute a subagent task to terminal state.

        H3 (round-5): the terminal DB write goes through
        ``_persist_terminal`` so a failed write is tracked in
        ``_pending_persistence`` and retried by the next shutdown's
        reconcile.  Previously:

          - success path: ``status = "completed"`` then DB write; if the
            write raised, the ``except Exception`` branch set
            ``status = "failed"`` and tried ANOTHER write — which could
            also fail and propagate unhandled through the fire-and-forget
            asyncio Task.
          - cancel path: ``status = "failed"`` then DB write wrapped in
            ``except (CancelledError, Exception)`` and swallowed — so the
            row stayed ``running`` and reconcile (which saw terminal
            memory state) skipped it.

        Now both paths set the terminal memory state, then call
        ``_persist_terminal`` exactly once.  A failure leaves
        ``_pending_persistence`` set so reconcile retries.
        """
        try:
            task.result = await asyncio.wait_for(self.runner(task), timeout=task.timeout)
            task.status = "completed"
            task.error = None
        except asyncio.CancelledError:
            # H1: a cancelled subagent (server shutdown / explicit cancel)
            # must leave an explicit terminal state.  Persist
            # ``failed/cancelled`` BEFORE re-raising so observers see the
            # terminal transition.
            #
            # H3 (round-5): use ``_persist_terminal`` so a failed write
            # is retried by reconcile.  The write itself may be cancelled
            # (the server is tearing the DB down concurrently); swallow
            # only that failure and surface the original cancellation.
            task.status = "failed"
            task.error = "cancelled"
            current = asyncio.current_task()
            if current is not None and hasattr(current, "uncancel"):
                current.uncancel()
            try:
                await self._persist_terminal(task)
            except BaseException:
                # Cancellation may propagate through the DB write;
                # _pending_persistence is already set so reconcile retries.
                logger.error(
                    "subagent task %s cancelled but could not persist terminal state",
                    task.id, exc_info=True,
                )
            raise
        except Exception as exc:
            task.status = "failed"
            task.error = str(exc)
        # H3 (round-5): persist the terminal state (success or exception
        # path).  Use ``_persist_terminal`` so a failed write is tracked
        # for reconcile retry.  Do not propagate — ``_run_task`` is a
        # fire-and-forget asyncio Task; an unhandled exception would only
        # be logged at GC time and the terminal state would never be
        # retried.
        try:
            await self._persist_terminal(task)
        except Exception:  # noqa: BLE001 — reconcile will retry
            logger.error(
                "subagent task %s terminal state could not be persisted; "
                "will retry on next shutdown reconcile",
                task.id, exc_info=True,
            )

    async def _default_runner(self, task: SubAgentTask) -> str:
        await asyncio.sleep(0)
        return f"completed: {task.goal}"
