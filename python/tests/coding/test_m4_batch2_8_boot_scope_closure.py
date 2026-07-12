"""M4 Batch 2.8 boot-scoped receipts and canonical mutation scopes."""
from __future__ import annotations

import asyncio
import sqlite3
import time
from dataclasses import replace

import pytest

from _m4_batch2_helpers import FakeContextProvider, SyncBroker, high_risk, make_plan
from test_m4_batch2_5_runtime_authority import DeepFakePlanningService
from khaos.coding.intelligence.index.repository import RepositoryIndexer
from khaos.coding.intelligence.index.store import IndexStore
from khaos.coding.planning.approval import (
    ApprovalRuntime,
    PersistedPlanRepository,
    PlanApprovalStore,
)
from khaos.coding.planning.approval.models import (
    ApprovalAuthenticator,
    AuthenticatedSession,
)
from khaos.coding.task_manager import CodingTask, TaskManager, TaskStatus
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState


def _real_runtime(tmp_path, *, store=None, sync=None):
    store = store or PlanApprovalStore(
        sqlite3.connect(tmp_path / "approval.sqlite", check_same_thread=False)
    )
    sync = sync or SyncBroker()
    task_manager = TaskManager()
    workspace_manager = WorkspaceManager(root=tmp_path / "worktrees")
    index_store = IndexStore(
        sqlite3.connect(tmp_path / "index.sqlite", check_same_thread=False)
    )
    indexer = RepositoryIndexer(index_store)
    runtime = ApprovalRuntime(
        store=store, broker=sync.real, context_provider=FakeContextProvider(),
        plan_repository=PersistedPlanRepository(store),
        planning_service=DeepFakePlanningService(), task_manager=task_manager,
        workspace_manager=workspace_manager, repository_indexer=indexer,
    )
    runtime._test_sync = sync
    runtime.initialize()
    return runtime, task_manager, workspace_manager, indexer


def _register_workspace(manager, root, *, workspace_id="ws1", task_id="task1"):
    workspace = TaskWorkspace(
        workspace_id, task_id, root, root, "HEAD", "abc123", "test-branch",
        WorkspaceState.RUNNING, (root,),
    )
    manager._workspaces[workspace_id] = workspace
    manager._task_ids.add(task_id)
    return workspace


def _mint_unapplied(runtime, *, plan_id="boot-receipt", plan=None):
    plan = plan or make_plan(plan_id=plan_id, risks=(high_risk(),))
    request = runtime.service.request_approval(plan)
    sync = runtime._test_sync
    sync.register_plan_approval(
        approval_request_id=request.approval_request_id,
        binding={"binding_digest": request.binding_digest},
        summary={"plan_id": plan.plan_id}, expires_at=9999999999.0,
    )
    session = AuthenticatedSession(
        session_id=f"session-{plan_id}", principal_id="user", principal_type="user",
        authenticated_at=time.time(), session_expiry=time.time() + 600,
        granted_capabilities=(ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,),
    )
    authenticator = sync.real._authenticator
    authenticator.register_session(session)
    context = authenticator.issue_context(
        session=session, approval_request_id=request.approval_request_id,
        authenticated_source="api",
    )
    receipt = sync.resolve_plan_approval(
        broker_request_id=request.broker_request_id, approved=True,
        context=context, reason="approved", binding_digest=request.binding_digest,
    )
    return plan, request, receipt


def _approved_plan(runtime, *, plan_id="execution-plan"):
    plan, request, receipt = _mint_unapplied(runtime, plan_id=plan_id)
    runtime.service.apply_broker_decision(receipt)
    authorization = runtime.authorize_execution(
        plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
    )
    return plan, request, authorization


def _approved_scoped_plan(runtime, *, plan_id, repository_id, workspace_id):
    plan = make_plan(
        plan_id=plan_id, repository_id=repository_id, workspace_id=workspace_id,
        risks=(high_risk(),),
    )
    plan, request, receipt = _mint_unapplied(runtime, plan=plan)
    runtime.service.apply_broker_decision(receipt)
    authorization = runtime.authorize_execution(
        plan_id=plan.plan_id, approval_request_id=request.approval_request_id,
    )
    return plan, authorization


def test_old_broker_cannot_issue_after_new_boot_but_old_receipt_recovers(tmp_path):
    runtime_a, _, _, _ = _real_runtime(tmp_path)
    plan, request, old_receipt = _mint_unapplied(runtime_a, plan_id="old-valid")
    old_key = old_receipt.signer_key_id

    store_b = PlanApprovalStore(
        sqlite3.connect(tmp_path / "approval.sqlite", check_same_thread=False)
    )
    runtime_b, _, _, _ = _real_runtime(
        tmp_path, store=store_b, sync=SyncBroker()
    )
    assert runtime_b.service.apply_broker_decision(old_receipt).status.value == "approved"
    verifier = {item.key_id: item for item in store_b.load_receipt_verifiers()}[old_key]
    assert verifier.verify_payload_digest(
        old_receipt.canonical_payload_digest, old_receipt.broker_signature
    )

    with pytest.raises(RuntimeError, match="stale"):
        runtime_a.service.request_approval(plan)


def test_old_broker_post_rotation_resolve_raises_and_inserts_nothing(tmp_path):
    runtime_a, _, _, _ = _real_runtime(tmp_path)
    plan = make_plan(plan_id="pending-a", risks=(high_risk(),))
    request = runtime_a.service.request_approval(plan)
    sync = runtime_a._test_sync
    sync.register_plan_approval(
        approval_request_id=request.approval_request_id,
        binding={"binding_digest": request.binding_digest}, summary={},
        expires_at=9999999999.0,
    )
    session = AuthenticatedSession(
        "session-a", "user", "user", time.time(), time.time() + 600,
        (ApprovalAuthenticator.CAPABILITY_PLAN_APPROVAL,),
    )
    sync.real._authenticator.register_session(session)
    context = sync.real._authenticator.issue_context(
        session=session, approval_request_id=request.approval_request_id
    )
    _real_runtime(
        tmp_path,
        store=PlanApprovalStore(sqlite3.connect(tmp_path / "approval.sqlite")),
        sync=SyncBroker(),
    )
    with pytest.raises(PermissionError, match="boot"):
        sync.resolve_plan_approval(
            broker_request_id=request.broker_request_id, approved=True,
            context=context, binding_digest=request.binding_digest,
        )
    assert runtime_a._store._conn.execute(
        "SELECT COUNT(*) FROM plan_approval_receipts WHERE approval_request_id=?",
        (request.approval_request_id,),
    ).fetchone()[0] == 0


def test_decided_at_tamper_cannot_fake_prior_boot_issuance(tmp_path):
    runtime, _, _, _ = _real_runtime(tmp_path)
    _, _, receipt = _mint_unapplied(runtime, plan_id="tamper-time")
    tampered = replace(receipt, decided_at=receipt.decided_at - 1000)
    from khaos.coding.planning.approval.service import ApprovalConflictError
    with pytest.raises(ApprovalConflictError):
        runtime.service.apply_broker_decision(tampered)


def test_real_task_cancel_waits_for_execution_fence_and_uses_durable_scope(tmp_path):
    runtime, tasks, workspaces, _ = _real_runtime(tmp_path)
    _register_workspace(workspaces, tmp_path, workspace_id="ws1", task_id="task1")
    tasks._tasks["task1"] = CodingTask("task1", "cancel", TaskStatus.RUNNING)
    plan, _, authorization = _approved_plan(runtime, plan_id="cancel-race")

    async def scenario():
        context_manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        await context_manager.__aenter__()
        cancel = asyncio.create_task(tasks.cancel("task1"))
        await asyncio.sleep(0.02)
        assert not cancel.done()
        await context_manager.__aexit__(None, None, None)
        assert (await cancel).value == "updated"

    runtime._test_sync._loop.run_until_complete(scenario())
    assert runtime._store.active_lease_scope_for_task("task1") is None
    assert tasks._tasks["task1"].status == TaskStatus.CANCELLED


def test_real_indexer_uses_explicit_workspace_not_repository_id(tmp_path):
    runtime, _, workspaces, indexer = _real_runtime(tmp_path)
    root = tmp_path / "source"
    root.mkdir()
    (root / "main.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    _register_workspace(workspaces, root, workspace_id="ws-1", task_id="task1")
    plan = make_plan(
        plan_id="index-race", workspace_id="ws-1", repository_id="repo-1",
        risks=(high_risk(),),
    )
    request = runtime.service.request_approval(plan)
    # Canonical scope errors fail closed before any generation write.
    with pytest.raises(RuntimeError, match="workspace_id"):
        runtime._test_sync._loop.run_until_complete(indexer.index("repo-1", root))
    report = runtime._test_sync._loop.run_until_complete(
        indexer.index("repo-1", root, workspace_id="ws-1")
    )
    assert report["parsed_files"] == 1
    assert runtime.mutation_fence.current_owner("repo-1") is None
    assert request.workspace_id == "ws-1"


def test_real_indexer_waits_for_execution_on_same_canonical_workspace(tmp_path):
    runtime, _, workspaces, indexer = _real_runtime(tmp_path)
    root = tmp_path / "concurrent-source"
    root.mkdir()
    (root / "main.py").write_text("value = 1\n", encoding="utf-8")
    _register_workspace(workspaces, root, workspace_id="ws-1", task_id="task1")
    plan, authorization = _approved_scoped_plan(
        runtime, plan_id="index-execution-race",
        repository_id="repo-1", workspace_id="ws-1",
    )

    async def scenario():
        context_manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id="ws-1", expected_repository_id="repo-1",
            owner_execution_id="owner",
        )
        await context_manager.__aenter__()
        indexing = asyncio.create_task(
            indexer.index("repo-1", root, workspace_id="ws-1")
        )
        await asyncio.sleep(0.02)
        assert not indexing.done()
        await context_manager.__aexit__(None, None, None)
        report = await indexing
        assert report["parsed_files"] == 1

    runtime._test_sync._loop.run_until_complete(scenario())


def test_real_indexer_allows_different_workspace_scopes_in_parallel(tmp_path):
    runtime, _, workspaces, indexer = _real_runtime(tmp_path)
    roots = []
    for workspace_id in ("ws-1", "ws-2"):
        root = tmp_path / workspace_id
        root.mkdir()
        _register_workspace(
            workspaces, root, workspace_id=workspace_id,
            task_id=f"task-{workspace_id}",
        )
        roots.append(root)
    active = 0
    maximum = 0
    original = indexer._index_impl

    async def observed(repository_id, root, *, full_reindex=False):
        nonlocal active, maximum
        active += 1
        maximum = max(maximum, active)
        await asyncio.sleep(0.02)
        active -= 1
        return {"parsed_files": 0}

    indexer._index_impl = observed

    async def scenario():
        await asyncio.gather(
            indexer.index("repo-1", roots[0], workspace_id="ws-1"),
            indexer.index("repo-1", roots[1], workspace_id="ws-2"),
        )

    try:
        runtime._test_sync._loop.run_until_complete(scenario())
    finally:
        indexer._index_impl = original
    assert maximum == 2


def test_multiple_active_workspaces_for_one_task_fail_closed(tmp_path):
    runtime, _, _, _ = _real_runtime(tmp_path)
    conn = runtime._store._conn
    for lease_id, workspace_id in (("l1", "ws-1"), ("l2", "ws-2")):
        conn.execute(
            "INSERT INTO plan_execution_leases "
            "(lease_id,task_id,workspace_id,repository_id,plan_id,head_sha,"
            "repository_generation,evidence_digest,binding_digest,authorization_id,"
            "expiry,owner_execution_id,status,server_epoch,boot_id,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (lease_id, "task-x", workspace_id, "repo-1", "p", "h", 1, "e", "b",
             f"a-{lease_id}", time.time() + 60, "owner", "active",
             runtime.boot_context.server_epoch, runtime.boot_context.boot_id, time.time()),
        )
    conn.commit()
    with pytest.raises(RuntimeError, match="multiple workspaces"):
        runtime._coordinator.resolve_task_workspace("task-x")


def test_release_fault_poison_blocks_mutations_until_controlled_recovery(tmp_path):
    runtime, _, workspaces, indexer = _real_runtime(tmp_path)
    root = tmp_path / "poison-source"
    root.mkdir()
    (root / "main.py").write_text("value = 1\n", encoding="utf-8")
    _register_workspace(workspaces, root, workspace_id="ws1", task_id="task1")
    plan, _, authorization = _approved_plan(runtime, plan_id="release-fault")
    original_release = runtime.gate.release_lease
    runtime.gate.release_lease = lambda lease_id: (_ for _ in ()).throw(
        sqlite3.OperationalError("release fault")
    )

    async def fail_release():
        context_manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        await context_manager.__aenter__()
        with pytest.raises(sqlite3.OperationalError, match="release fault"):
            await context_manager.__aexit__(None, None, None)

    runtime._test_sync._loop.run_until_complete(fail_release())
    assert runtime.mutation_fence.is_poisoned("ws1")
    with pytest.raises(PermissionError, match="poisoned"):
        runtime._test_sync._loop.run_until_complete(
            indexer.index("repo1", root, workspace_id="ws1")
        )
    with pytest.raises(PermissionError, match="poisoned"):
        runtime._test_sync._loop.run_until_complete(
            workspaces.cleanup("ws1", force=True)
        )

    async def blocked_acquire():
        manager = runtime.acquire_execution_context(
            authorization_id="forged", nonce="forged", expected_plan_id="p",
            expected_task_id="task1", expected_workspace_id="ws1",
            expected_repository_id="repo1", owner_execution_id="owner-2",
        )
        await manager.__aenter__()

    with pytest.raises(PermissionError, match="poisoned"):
        runtime._test_sync._loop.run_until_complete(blocked_acquire())
    runtime.gate.release_lease = original_release
    assert runtime.recover_poisoned_workspace("ws1", force=True)
    assert not runtime.mutation_fence.is_poisoned("ws1")
    assert runtime._store._conn.execute(
        "SELECT COUNT(*) FROM workspace_mutation_audit WHERE workspace_id='ws1'"
    ).fetchone()[0] == 2
    report = runtime._test_sync._loop.run_until_complete(
        indexer.index("repo1", root, workspace_id="ws1")
    )
    assert report["parsed_files"] == 1


def test_release_audit_fault_rolls_back_and_poison_reaper_recovers(tmp_path):
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    _register_workspace(workspaces, tmp_path, workspace_id="ws1", task_id="task1")
    plan, _, authorization = _approved_plan(runtime, plan_id="audit-fault")
    runtime._store._conn.execute(
        "CREATE TRIGGER fail_release_audit BEFORE INSERT ON workspace_mutation_audit "
        "WHEN NEW.event_type='released' BEGIN SELECT RAISE(ABORT,'audit fault'); END"
    )

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        ctx = await manager.__aenter__()
        with pytest.raises(sqlite3.IntegrityError, match="audit fault"):
            await manager.__aexit__(None, None, None)
        assert runtime._store.get_lease(ctx.lease_id)["status"] == "active"

    runtime._test_sync._loop.run_until_complete(scenario())
    assert runtime.mutation_fence.is_poisoned("ws1")
    runtime._store._conn.execute("DROP TRIGGER fail_release_audit")
    assert runtime.recover_poisoned_workspace("ws1", force=True)


def test_closed_release_connection_keeps_workspace_poisoned_until_reconnect(tmp_path):
    runtime, _, workspaces, _ = _real_runtime(tmp_path)
    _register_workspace(workspaces, tmp_path, workspace_id="ws1", task_id="task1")
    plan, _, authorization = _approved_plan(runtime, plan_id="connection-fault")

    async def scenario():
        manager = runtime.acquire_execution_context(
            authorization_id=authorization.authorization_id, nonce=authorization.nonce,
            expected_plan_id=plan.plan_id, expected_task_id=plan.task_id,
            expected_workspace_id=plan.workspace_id,
            expected_repository_id=plan.repository_id, owner_execution_id="owner",
        )
        await manager.__aenter__()
        runtime._store._conn.close()
        with pytest.raises(RuntimeError, match="durable quarantine"):
            await manager.__aexit__(None, None, None)

    runtime._test_sync._loop.run_until_complete(scenario())
    assert runtime.mutation_fence.is_poisoned("ws1")
    replacement = PlanApprovalStore(
        sqlite3.connect(tmp_path / "approval.sqlite", check_same_thread=False)
    )
    runtime._store = replacement
    assert runtime.recover_poisoned_workspace("ws1", force=True) is False
    # The durable poison write could not commit, so an operator must first
    # reconstruct quarantine from the still-ACTIVE lease before reaping.
    lease = replacement._conn.execute(
        "SELECT lease_id FROM plan_execution_leases WHERE workspace_id='ws1' "
        "AND status='active'"
    ).fetchone()
    replacement.poison_workspace("ws1", lease["lease_id"], reason="connection-fault")
    assert runtime.recover_poisoned_workspace("ws1", force=True)
    assert not runtime.mutation_fence.is_poisoned("ws1")
