"""Focused regression tests for the Memory V2 production closure edges."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from khaos.coding.execution import HostExecutionBackend
from khaos.coding.verification import VerificationPipeline
from khaos.coding.verification.models import VerificationPlan, VerificationStep
from khaos.db import Database
from khaos.memory import (
    EvidenceRef,
    MemoryAuthority,
    MemoryBroker,
    MemoryBudget,
    MemoryCandidate,
    MemoryEvent,
    MemoryEventType,
    MemoryForgetRequest,
    MemoryObjectIdentity,
    MemoryStatus,
    OnlineMemoryBenchmark,
    OnlineMemoryTask,
    RelationCandidate,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
)
from khaos.memory.core.authority import (
    _TRUSTED_ISSUER_CAPABILITY,
    VerificationReceiptIssuer,
    VerificationReceiptVerifier,
)
from khaos.memory.core.contracts import ForgetResult, MemoryCapabilities
from khaos.memory.ledger import SqliteEventLedger
from khaos.memory.providers import (
    MemoryHttpProvider,
    NativeMemoryProvider,
    ProviderManifest,
)


def _runtime(
    *,
    principal_id: str = "principal:alice",
    project_id: str = "project:memory-v2",
    session_id: str | None = "session:closure",
) -> RuntimeMemoryContext:
    return RuntimeMemoryContext(
        principal_id=principal_id,
        project_id=project_id,
        session_id=session_id,
        task_id="task:closure",
        workspace_id="workspace:closure",
        mode="coding",
        available_capabilities=frozenset({"python", "offline"}),
        environment_fingerprint="closure-test",
        environment={"platform": "test"},
    )


async def _broker(tmp_path: Path) -> tuple[Database, MemoryBroker]:
    database = Database(tmp_path / "khaos.db")
    await database.connect()
    await database.run_migrations()
    provider = NativeMemoryProvider(database)
    return database, MemoryBroker(provider, SqliteEventLedger(database))


async def _event(
    broker: MemoryBroker,
    runtime: RuntimeMemoryContext,
    event_type: MemoryEventType,
    *,
    source_type: SourceType,
    payload: dict[str, object],
) -> MemoryEvent:
    event = MemoryEvent.create(
        event_type,
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
        session_id=runtime.session_id,
        task_id=runtime.task_id,
        workspace_id=runtime.workspace_id,
        source_type=source_type,
        trust_hint=(
            TrustHint.USER_STATED
            if source_type is SourceType.USER
            else TrustHint.TOOL_OBSERVED
            if source_type is SourceType.TOOL
            else TrustHint.AGENT_INFERRED
        ),
        payload=payload,
    )
    await broker.record_event(event)
    return event


def _candidate(
    event_id: str,
    *,
    claim: str,
    key: str,
    authority: MemoryAuthority = MemoryAuthority.USER_STATED,
    memory_type: str = "PROJECT_FACT",
    namespace: str = "private",
    scope: str = "global",
) -> MemoryCandidate:
    return MemoryCandidate(
        memory_type=memory_type,
        claim=claim,
        key=key,
        authority=authority,
        confidence=0.9,
        source_event_ids=(event_id,),
        evidence_refs=(EvidenceRef(SourceType.USER, f"event:{event_id}", event_id=event_id),),
        namespace=namespace,
        scope=scope,
    )


def _http_provider() -> MemoryHttpProvider:
    return MemoryHttpProvider(
        ProviderManifest(
            provider_id="remote-memory",
            network_required=True,
            endpoint="https://memory.example.test",
            capabilities=MemoryCapabilities(forget=True),
        )
    )


async def test_http_forget_carries_complete_runtime_and_object_identity():
    provider = _http_provider()
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"forgotten_ids": ["remote-1"]})

    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://memory.example.test",
    )
    runtime = _runtime()
    identity = MemoryObjectIdentity(
        memory_id="remote-1",
        provider_id=provider.provider_id,
        project_id=runtime.project_id,
        namespace="private",
        principal_id=runtime.principal_id,
        session_id=runtime.session_id,
    )
    try:
        result = await provider.forget(
            MemoryForgetRequest(
                ("remote-1",),
                runtime,
                mode="hard",
                namespace="private",
                scope="global",
                identities=(identity,),
            )
        )
    finally:
        await provider.stop()

    assert result == ForgetResult(("remote-1",), "hard")
    payload = requests[0]
    assert payload["memory_ids"] == ["remote-1"]
    assert payload["mode"] == "hard"
    assert payload["namespace"] == "private"
    assert payload["scope"] == "global"
    assert payload["identities"] == [
        {
            "memory_id": "remote-1",
            "provider_id": "remote-memory",
            "project_id": runtime.project_id,
            "namespace": "private",
            "principal_id": runtime.principal_id,
            "session_id": runtime.session_id,
        }
    ]
    assert payload["runtime"] == {
        "principal_id": runtime.principal_id,
        "project_id": runtime.project_id,
        "session_id": runtime.session_id,
        "task_id": runtime.task_id,
        "workspace_id": runtime.workspace_id,
        "mode": runtime.mode,
        "repo_id": None,
        "branch": None,
        "commit_sha": None,
    }


async def test_broker_never_calls_remote_forget_for_foreign_or_unidentifiable_id(tmp_path):
    database, broker = await _broker(tmp_path)
    provider = _http_provider()
    forget_calls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal forget_calls
        if request.url.path == "/memory/forget":
            forget_calls += 1
            return httpx.Response(200, json={"forgotten_ids": ["remote-1"]})
        return httpx.Response(
            200,
            json={
                "memory": {
                    "memory_id": "remote-1",
                    "content": "foreign secret",
                    "project_id": "project:other",
                    "principal_id": "principal:other",
                    "namespace": "private",
                    "scope": "global",
                    "status": "ACTIVE",
                    "source_type": "USER",
                }
            },
        )

    provider._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://memory.example.test",
    )
    broker.provider = provider
    try:
        result = await broker.forget(("remote-1",), _runtime(), mode="hard")
    finally:
        await provider.stop()
        await database.close()

    assert result.forgotten_ids == ()
    assert forget_calls == 0


async def test_low_authority_current_claim_cannot_supersede_user_fact(tmp_path):
    database, broker = await _broker(tmp_path)
    runtime = _runtime()
    try:
        user_event = await _event(
            broker,
            runtime,
            MemoryEventType.USER_MESSAGE,
            source_type=SourceType.USER,
            payload={"content": "I use uv"},
        )
        trusted = await broker.propose_memory(
            _candidate(
                user_event.event_id,
                claim="package_manager: uv",
                key="package_manager",
            ),
            runtime,
        )
        system_event = await _event(
            broker,
            runtime,
            MemoryEventType.ASSISTANT_MESSAGE,
            source_type=SourceType.SYSTEM,
            payload={"content": "inferred alternative"},
        )
        low = await broker.propose_memory(
            _candidate(
                system_event.event_id,
                claim="package_manager: pip",
                key="package_manager",
                authority=MemoryAuthority.AGENT_INFERRED,
            ),
            runtime,
        )
        current = await broker.get_current(runtime, scope="global", key="package_manager")
        assert trusted.accepted and current is not None
        assert current.memory_id == trusted.memory_id
        assert current.content.endswith("uv")
        assert low.accepted and low.status is MemoryStatus.ACTIVE
        historical = await broker.search(
            "package_manager",
            runtime,
            MemoryBudget(max_hits=8),
            include_historical=True,
        )
        assert all(hit.status != MemoryStatus.SUPERSEDED.value for hit in historical.primary_hits)
    finally:
        await database.close()


async def test_about_relation_does_not_fake_temporal_evidence(tmp_path):
    database, broker = await _broker(tmp_path)
    runtime = _runtime()
    try:
        event = await _event(
            broker,
            runtime,
            MemoryEventType.USER_MESSAGE,
            source_type=SourceType.USER,
            payload={"content": "project fact"},
        )
        decision = await broker.propose_memory(
            MemoryCandidate(
                memory_type="PROJECT_FACT",
                claim="deployment uses uv",
                key="deployment",
                authority=MemoryAuthority.USER_STATED,
                confidence=0.9,
                source_event_ids=(event.event_id,),
                relations=(RelationCandidate("ABOUT", "entity", "deployment"),),
            ),
            runtime,
        )
        assert decision.accepted
        resolution = await broker.resolve_evidence(
            "deployment uses uv",
            runtime,
            MemoryBudget(max_hits=8, max_graph_hops=1),
            required_types=("temporal", "provenance"),
        )
        assert "temporal" in resolution.missing_requirements
        assert "provenance" not in resolution.missing_requirements
    finally:
        await database.close()


async def test_compliance_export_contains_no_deleted_plaintext(tmp_path):
    database, broker = await _broker(tmp_path)
    runtime = _runtime()
    package_path = tmp_path / "after-compliance.json"
    try:
        event = await _event(
            broker,
            runtime,
            MemoryEventType.USER_MESSAGE,
            source_type=SourceType.USER,
            payload={"content": "private content that must disappear"},
        )
        decision = await broker.propose_memory(
            _candidate(event.event_id, claim="secret-note: private content that must disappear", key="secret-note"),
            runtime,
        )
        assert decision.memory_id
        result = await broker.forget((decision.memory_id,), runtime, mode="compliance")
        assert result.forgotten_ids == (decision.memory_id,)
        from khaos.memory.transfer import MemoryTransferService

        await MemoryTransferService(broker).export(runtime, package_path)
        encoded = package_path.read_text(encoding="utf-8")
        assert "private content that must disappear" not in encoded
        assert "MEMORY_REVOKED" in encoded
    finally:
        await database.close()


async def test_verification_pipeline_records_digest_and_promotes_candidate(tmp_path):
    database, broker = await _broker(tmp_path)
    runtime = replace(_runtime(), task_id=None, workspace_id=None)
    try:
        pipeline = VerificationPipeline(backend=HostExecutionBackend())
        plan = VerificationPlan(
            (
                VerificationStep(
                    "echo",
                    "preflight",
                    (sys.executable, "-c", "print('memory-v2-ok')"),
                    tmp_path,
                ),
            )
        )
        candidate = MemoryCandidate(
            memory_type="PROJECT_FACT",
            claim="verified: memory-v2-ok",
            authority=MemoryAuthority.AGENT_INFERRED,
            confidence=0.7,
            evidence_refs=(EvidenceRef(SourceType.SYSTEM, "verification-candidate"),),
            key="verified-memory-v2",
        )
        outcome = await pipeline.run_with_memory(
            plan,
            broker=broker,
            runtime=runtime,
            candidate=candidate,
            verification_run_id="verification:closure",
        )
        assert outcome.passed is True
        assert outcome.promotion is not None
        assert outcome.promotion.status is MemoryStatus.VERIFIED
        async with database.read_connection() as conn:
            rows = await (
                await conn.execute(
                    "SELECT event_type, payload_json FROM memory_events "
                    "WHERE project_id = ? ORDER BY recorded_at, event_id",
                    (runtime.project_id,),
                )
            ).fetchall()
        result_payloads = [
            json.loads(row["payload_json"])
            for row in rows
            if row["event_type"] == MemoryEventType.VERIFICATION_RESULT.value
        ]
        assert result_payloads and result_payloads[0]["result_digest"]
        assert result_payloads[0]["target_digest"]
    finally:
        await database.close()


async def test_verification_receipt_is_digest_bound_and_single_use(tmp_path):
    database, broker = await _broker(tmp_path)
    runtime = _runtime()
    try:
        pipeline = VerificationPipeline()
        candidate = MemoryCandidate(
            memory_type="PROJECT_FACT",
            claim="receipt-bound fact",
            authority=MemoryAuthority.VERIFICATION_CONFIRMED,
            confidence=0.8,
            evidence_refs=(EvidenceRef(SourceType.VERIFICATION, "run:receipt"),),
            verification_run_id="run:receipt",
            verification_result_digest="result:receipt",
        )
        issuer = pipeline.memory_receipt_issuer(broker.verification_verifier)
        receipt = issuer.issue(
            candidate,
            "run:receipt",
            result_digest="result:receipt",
            principal_id=runtime.principal_id,
            project_id=runtime.project_id,
            session_id=runtime.session_id,
            task_id=runtime.task_id,
            workspace_id=runtime.workspace_id,
        )
        first = await broker.propose_memory(
            replace(candidate, verification_proof=receipt.token),
            runtime,
        )
        second = await broker.propose_memory(
            replace(candidate, verification_proof=receipt.token),
            runtime,
        )
        assert first.status is MemoryStatus.VERIFIED
        assert second.status is MemoryStatus.QUARANTINED
        assert second.reason == "verification_authority_missing"
    finally:
        await database.close()


def test_verification_issuer_requires_private_pipeline_capability():
    verifier = VerificationReceiptVerifier()
    with pytest.raises(PermissionError):
        VerificationReceiptIssuer(verifier, owner=object(), _capability=_TRUSTED_ISSUER_CAPABILITY)


async def test_online_benchmark_runs_real_mutations_in_fresh_states(tmp_path):
    runtimes: list[Database] = []
    counter = 0

    async def fresh_state() -> tuple[MemoryBroker, RuntimeMemoryContext]:
        nonlocal counter
        counter += 1
        database = Database(tmp_path / f"online-{counter}.db")
        await database.connect()
        await database.run_migrations()
        runtimes.append(database)
        return MemoryBroker(
            NativeMemoryProvider(database),
            SqliteEventLedger(database),
        ), _runtime(session_id=f"session:online:{counter}")

    async def mutate(task_name: str, broker: MemoryBroker, runtime: RuntimeMemoryContext) -> None:
        event = await _event(
            broker,
            runtime,
            MemoryEventType.USER_MESSAGE,
            source_type=SourceType.USER,
            payload={"content": task_name},
        )
        decision = await broker.propose_memory(
            _candidate(event.event_id, claim=f"online:{task_name}", key=f"online:{task_name}"),
            runtime,
        )
        assert decision.accepted

    tasks = (
        OnlineMemoryTask(
            "task-a",
            "online:alpha",
            lambda broker, runtime: mutate("alpha", broker, runtime),
            expected_terms=("online:alpha",),
        ),
        OnlineMemoryTask(
            "task-b",
            "online:beta",
            lambda broker, runtime: mutate("beta", broker, runtime),
            expected_terms=("online:beta",),
        ),
    )
    try:
        report = await OnlineMemoryBenchmark(fresh_state).run(
            tasks,
            repetitions=3,
            order_variants=("chronological", "shuffled", "adversarial"),
        )
    finally:
        for database in runtimes:
            await database.close()

    assert report.status == "COMPLETED"
    assert report.state_isolated is True
    assert len(report.runs) == 18
    assert report.promotion_count == 0
    assert report.false_promotion_count == 0
    assert all(run.mutation_digest for run in report.runs)
    assert all(run.initial_state_digest != run.final_state_digest for run in report.runs)
