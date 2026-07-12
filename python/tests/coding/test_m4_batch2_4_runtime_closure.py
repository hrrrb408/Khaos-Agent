from __future__ import annotations

import sqlite3
import time
from dataclasses import replace

import pytest

from _m4_batch2_helpers import FakeContextProvider, SyncBroker, make_gate, make_plan, make_service
from khaos.coding.planning.approval import (
    ApprovalAuthenticator, ApprovalRuntime, AuthenticatedSession,
    PersistedPlanRepository, PlanApprovalStore,
    PlannedExecutionGuard, WorkspaceExecutionLeaseCoordinator,
)
from khaos.coding.planning.approval.repository import UnsafeTestPlanRepository
from khaos.coding.planning.approval.validator import ShallowTestPlanValidator


def _authorized_guard():
    plan=make_plan(); service,store,context,_,repo=make_service(); request=service.request_approval(plan)
    gate=make_gate(store=store,context=context,plan_repository=repo); gate.rotate_epoch()
    auth=gate.authorize_execution(plan_id=plan.plan_id,approval_request_id=request.approval_request_id)
    guard=PlannedExecutionGuard(gate)
    ctx=guard.authorize(auth.authorization_id,auth.nonce,expected_plan_id=plan.plan_id,expected_task_id=plan.task_id,expected_workspace_id=plan.workspace_id,expected_repository_id=plan.repository_id,owner_execution_id="owner")
    return plan,service,store,context,gate,guard,ctx


def test_authorized_context_contains_active_lease_capability():
    _,_,_,_,gate,guard,ctx=_authorized_guard()
    assert ctx.lease_id and ctx.owner_execution_id == "owner" and ctx.lease_expiry > time.time()
    assert ctx.server_epoch == gate.server_epoch and ctx.boot_id == gate.boot_id
    assert ctx.authorization_id == ctx.authorization.authorization_id and ctx.binding_digest
    guard.require_active_execution_context(ctx)


@pytest.mark.parametrize("failure",["release","expiry","manual","head","generation","terminal"])
def test_execution_context_fails_closed_on_live_lease_drift(failure):
    _,_,store,context,gate,guard,ctx=_authorized_guard()
    if failure == "release": gate.release_lease(ctx.lease_id)
    elif failure == "expiry": store._conn.execute("UPDATE plan_execution_leases SET expiry=? WHERE lease_id=?",(time.time()-1,ctx.lease_id))
    elif failure == "manual": ctx=replace(ctx,execution_context_id="forged")
    elif failure == "head": context.set(head_sha="other")
    elif failure == "generation": context.set(repository_generation=2)
    else: context.set(task_terminal=True,task_active=False)
    with pytest.raises(PermissionError): guard.require_active_execution_context(ctx)


def test_every_batch3_stub_requires_active_context():
    _,_,_,_,gate,guard,ctx=_authorized_guard(); gate.release_lease(ctx.lease_id)
    calls=((guard.planned_workspace_edit,{"edit":{}}),(guard.planned_tool_invocation,{"invocation":{}}),(guard.planned_verification_execution,{"verification":{}}),(guard.planned_changeset_creation,{"changeset_spec":{}}),(guard.planned_changeset_apply,{"changeset_id":"x"}))
    for method,kwargs in calls:
        with pytest.raises(PermissionError): method(ctx,**kwargs)


class DeepFakePlanningService:
    def validate_plan(self, plan, **kwargs):
        from khaos.coding.planning.contracts import PlanValidationResult
        return PlanValidationResult(True, plan.status)


def _runtime(store):
    # Batch 2.5: runtime requires a real ApprovalBroker with authenticator.
    sync=SyncBroker()
    return ApprovalRuntime(store=store,broker=sync.real,context_provider=FakeContextProvider(),plan_repository=PersistedPlanRepository(store),planning_service=DeepFakePlanningService())


def test_production_runtime_dependencies_fail_closed():
    store=PlanApprovalStore(sqlite3.connect(":memory:"))
    sync=SyncBroker()
    with pytest.raises(TypeError): ApprovalRuntime(store=store,broker=sync.real,context_provider=FakeContextProvider(),plan_repository=UnsafeTestPlanRepository(),planning_service=DeepFakePlanningService())
    with pytest.raises(TypeError): ApprovalRuntime(store=store,broker=sync.real,context_provider=FakeContextProvider(),plan_repository=PersistedPlanRepository(store),planning_service=None)
    with pytest.raises(TypeError): ApprovalRuntime(store=store,broker=sync.real,context_provider=FakeContextProvider(),plan_repository=PersistedPlanRepository(store),planning_service=ShallowTestPlanValidator())
    with pytest.raises(TypeError): ApprovalRuntime(store=store,broker=SyncBroker(),context_provider=FakeContextProvider(),plan_repository=PersistedPlanRepository(store),planning_service=DeepFakePlanningService())


def test_runtime_initialize_rotates_epoch_and_guards_readiness():
    store=PlanApprovalStore(sqlite3.connect(":memory:")); one=_runtime(store)
    with pytest.raises(RuntimeError): one.authorize_execution(plan_id="x",approval_request_id="y")
    first=one.initialize(); two=_runtime(store); second=two.initialize()
    assert first.server_epoch + 1 == second.server_epoch and first.boot_id != second.boot_id
    two.shutdown(); assert not two.ready


def test_authenticated_session_request_binding_revocation_and_replay():
    auth=ApprovalAuthenticator(secret_key="test-key"); now=time.time()
    session=AuthenticatedSession("s","principal","user",now,now+300,(auth.CAPABILITY_PLAN_APPROVAL,))
    auth.register_session(session); ctx=auth.issue_context(session=session,approval_request_id="request-a")
    assert auth.verify_context(ctx,expected_approval_request_id="request-a",consume=True)
    assert not auth.verify_context(ctx,expected_approval_request_id="request-a",consume=True)
    other=auth.issue_context(session=session,approval_request_id="request-a")
    assert not auth.verify_context(other,expected_approval_request_id="request-b")
    auth.revoke_session("s"); assert not auth.verify_context(other,expected_approval_request_id="request-a")
    with pytest.raises(TypeError): auth.issue_context(actor_id="fake",actor_type="admin",session_request_id="s")  # type: ignore[call-arg]
    assert not hasattr(auth,"secret_key")


def test_receipt_writer_is_not_publicly_obtainable():
    store=PlanApprovalStore(sqlite3.connect(":memory:"))
    assert not hasattr(store,"receipt_writer_token") and not hasattr(store,"insert_receipt") and not hasattr(store,"_broker_receipt_writer")
    with pytest.raises(PermissionError): store._insert_receipt(object(),receipt_id="r",token_hash="t",approval_request_id="a",broker_request_id="b",binding_digest="d",decision="approved",expires_at=time.time()+60)


@pytest.mark.parametrize(("column","value"),[("canonical_plan_json","{"),("content_hash","tampered"),("binding_digest","tampered"),("schema_version","future.v9")])
def test_persisted_snapshot_corruption_fails_closed(column,value):
    store=PlanApprovalStore(sqlite3.connect(":memory:")); repo=PersistedPlanRepository(store); plan=make_plan(); assert repo.register(plan)
    assert repo.get(plan.plan_id) is not None
    store._conn.execute(f"UPDATE plan_snapshots SET {column}=? WHERE plan_id=?",(value,plan.plan_id))
    assert repo.get(plan.plan_id) is None


def test_lease_coordinator_requires_owner_before_generation_update():
    _,_,_,_,_,guard,ctx=_authorized_guard()
    class ReadyRuntime:
        ready=True
        gate=guard._gate
        def require_ready(self): return None
    coordinator=WorkspaceExecutionLeaseCoordinator(ReadyRuntime())
    coordinator.before_generation_or_head_update(ctx)
    with pytest.raises(PermissionError): coordinator.before_generation_or_head_update(replace(ctx,owner_execution_id="old-owner"))
