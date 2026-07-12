"""M4 Batch 2.7 receipt authority and mandatory mutation-fence closure."""
from __future__ import annotations

import asyncio
import inspect
import sqlite3

import pytest

from _m4_batch2_helpers import FakeContextProvider, FakeMutationParticipant, SyncBroker
from test_m4_batch2_5_runtime_authority import (
    DeepFakePlanningService,
    _authorize_and_acquire_lease,
    _runtime,
    _seed_approved_request,
    _store,
)
from khaos.agent.approval import ApprovalBroker
from khaos.coding.planning.approval import (
    ApprovalRuntime,
    PersistedPlanRepository,
    PlanApprovalStore,
    PlanExecutionGate,
    PlannedExecutionGuard,
)
from khaos.coding.planning.approval.receipt_crypto import ReceiptPublicVerifier
from khaos.coding.planning.approval.runtime import BootContext, RuntimeCapability


def test_broker_and_public_package_do_not_expose_receipt_signer() -> None:
    broker = ApprovalBroker()
    assert not hasattr(broker, "receipt_signer")
    assert "ReceiptSigner" not in dir(__import__(
        "khaos.coding.planning.approval", fromlist=["ReceiptSigner"]
    ))
    assert "private" not in repr(broker._receipt_public_verifier()).casefold()


def test_store_persists_only_public_verification_material() -> None:
    runtime = _runtime(_store())
    runtime.initialize()
    columns = {
        row[1] for row in runtime._store._conn.execute(
            "PRAGMA table_info(receipt_verification_keys)"
        )
    }
    assert columns == {
        "key_id", "public_key", "key_version", "boot_epoch", "created_at", "active"
    }
    assert "receipt_signing_keys" not in {
        row[0] for row in runtime._store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    verifiers = runtime._store.load_receipt_verifiers()
    assert verifiers and all(isinstance(item, ReceiptPublicVerifier) for item in verifiers)
    assert all(not hasattr(item, "sign") for item in verifiers)


def test_legacy_hmac_table_is_dropped_fail_closed() -> None:
    conn = sqlite3.connect(":memory:")
    conn.execute("CREATE TABLE receipt_signing_keys (key_id TEXT, secret_key TEXT)")
    conn.execute("INSERT INTO receipt_signing_keys VALUES ('old', 'private-secret')")
    PlanApprovalStore(conn)
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE name='receipt_signing_keys'"
    ).fetchone() is None


def test_forged_verifier_and_writer_cannot_be_registered() -> None:
    store = _store()
    fake = ReceiptPublicVerifier("fake", "ZmFrZQ==", 1, 1)
    with pytest.raises(PermissionError):
        store._install_runtime_receipt_writer(
            lambda **fields: None, runtime_token=object(), runtime_capability=object()
        )
    with pytest.raises(PermissionError):
        store._persist_receipt_verifier(fake, runtime_token=object())
    assert store.load_receipt_verifiers() == []


def test_direct_forged_outbox_write_is_rejected() -> None:
    store = _store()
    with pytest.raises(PermissionError):
        store._insert_signed_receipt(
            runtime_token=object(), receipt_id="fake", token_hash="fake",
            approval_request_id="a", broker_request_id="b", binding_digest="d",
            decision="approved", expires_at=9999999999.0,
            canonical_payload_digest="0" * 64, broker_signature="fake",
            signer_key_id="fake",
        )


def test_real_broker_receipt_and_old_public_key_survive_restart(tmp_path) -> None:
    db = tmp_path / "approval.sqlite"
    conn1 = sqlite3.connect(db)
    runtime = _runtime(PlanApprovalStore(conn1))
    runtime.initialize()
    _, _, receipt = _seed_approved_request(runtime, plan_id="receipt_rotation")
    old_key = receipt.signer_key_id
    old_signature = receipt.broker_signature
    old_digest = receipt.canonical_payload_digest
    conn1.close()

    store2 = PlanApprovalStore(sqlite3.connect(db))
    verifier = {item.key_id: item for item in store2.load_receipt_verifiers()}[old_key]
    assert verifier.verify_payload_digest(old_digest, old_signature)


def test_runtime_capability_and_copied_boot_context_are_not_authority() -> None:
    with pytest.raises(TypeError):
        RuntimeCapability(BootContext(1, "copied"))
    store = _store()
    with pytest.raises(TypeError):
        PlanExecutionGate(
            store, FakeContextProvider(), runtime_capability=BootContext(1, "copied"),
            plan_repository=PersistedPlanRepository(store),
            planning_service=DeepFakePlanningService(),
        )


@pytest.mark.parametrize("missing", ["task", "workspace", "indexer"])
def test_execution_runtime_requires_every_mutation_participant(missing: str) -> None:
    participants = {
        "task": FakeMutationParticipant(),
        "workspace": FakeMutationParticipant(),
        "indexer": FakeMutationParticipant(),
    }
    participants[missing] = None
    store = _store()
    sync = SyncBroker()
    runtime = ApprovalRuntime(
        store=store, broker=sync.real, context_provider=FakeContextProvider(),
        plan_repository=PersistedPlanRepository(store),
        planning_service=DeepFakePlanningService(),
        task_manager=participants["task"], workspace_manager=participants["workspace"],
        repository_indexer=participants["indexer"],
    )
    with pytest.raises(TypeError, match="execution-ready"):
        runtime.initialize()
    assert not runtime.ready


def test_ready_runtime_shares_one_fence_with_all_participants() -> None:
    participants = [FakeMutationParticipant() for _ in range(3)]
    store = _store()
    sync = SyncBroker()
    runtime = ApprovalRuntime(
        store=store, broker=sync.real, context_provider=FakeContextProvider(),
        plan_repository=PersistedPlanRepository(store),
        planning_service=DeepFakePlanningService(),
        task_manager=participants[0], workspace_manager=participants[1],
        repository_indexer=participants[2],
    )
    runtime.initialize()
    assert runtime.ready and runtime.mutation_fence is not None
    assert all(item.fence is runtime.mutation_fence for item in participants)
    assert runtime.guard._mutation_fence is runtime.mutation_fence


def test_guard_without_fence_and_bare_gate_acquire_fail_closed() -> None:
    runtime = _runtime(_store())
    runtime.initialize()
    guard = PlannedExecutionGuard(runtime.gate, lease_authority=object())
    assert guard._mutation_fence is None
    with pytest.raises(PermissionError, match="bare lease acquisition"):
        runtime.acquire_lease()
    with pytest.raises(PermissionError, match="mutation fence authority"):
        runtime.gate.acquire_lease(
            authorization_id="a", nonce="n", expected_plan_id="p",
            expected_task_id="t", expected_workspace_id="w",
            expected_repository_id="r", owner_execution_id="exec",
        )


def test_runtime_acquire_holds_fence_and_shutdown_revokes_context() -> None:
    runtime = _runtime(_store())
    runtime.initialize()
    plan, request, _ = _seed_approved_request(runtime, plan_id="fenced_context")
    _, ctx, guard = _authorize_and_acquire_lease(runtime, plan, request)
    assert runtime.mutation_fence.current_owner(plan.workspace_id) == f"lease:{ctx.lease_id}"
    guard.require_active_execution_context(ctx)
    runtime.shutdown()
    with pytest.raises((PermissionError, RuntimeError)):
        guard.require_active_execution_context(ctx)


@pytest.mark.parametrize(
    "method,kwargs",
    [
        ("planned_workspace_edit", {"edit": {}}),
        ("planned_tool_invocation", {"invocation": {}}),
        ("planned_verification_execution", {"verification": {}}),
        ("planned_changeset_creation", {"changeset_spec": {}}),
        ("planned_changeset_apply", {"changeset_id": "x"}),
    ],
)
def test_every_batch3_stub_requires_fenced_active_context(method, kwargs) -> None:
    runtime = _runtime(_store())
    runtime.initialize()
    with pytest.raises(PermissionError):
        getattr(runtime.guard, method)(object(), **kwargs)


def test_fence_serializes_acquire_with_index_cleanup_and_cancel() -> None:
    async def scenario() -> None:
        runtime = _runtime(_store())
        runtime.initialize()
        fence = runtime.mutation_fence
        entered: list[str] = []

        async def acquire_owner() -> None:
            async with fence.use("w1", owner="lease:pending"):
                entered.append("acquire-start")
                await asyncio.sleep(0.02)
                entered.append("acquire-end")

        async def mutation(owner: str) -> None:
            await asyncio.sleep(0)
            async with fence.use("w1", owner=owner):
                entered.append(owner)

        await asyncio.gather(
            acquire_owner(), mutation("index:w1"), mutation("cleanup:w1"),
            mutation("cancel:t1"),
        )
        assert entered[:2] == ["acquire-start", "acquire-end"]
        assert set(entered[2:]) == {"index:w1", "cleanup:w1", "cancel:t1"}

    asyncio.run(scenario())


def test_approval_runtime_has_no_execution_side_effect_api() -> None:
    source = inspect.getsource(ApprovalRuntime.acquire_execution_context)
    forbidden = ("terminal", "test_run", "ChangeSet", "ToolScheduler", "write_text")
    assert all(token not in source for token in forbidden)
