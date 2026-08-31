"""M7.7 provenance-bound retrieval and low-trust projection regressions."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest
from khaos.db import Database
from khaos.memory import (
    EvidenceResolution,
    MemoryAuthority,
    MemoryBroker,
    MemoryCandidate,
    MemoryCurrentness,
    MemoryEvent,
    MemoryEventType,
    MemoryHit,
    MemoryRetrievalNeed,
    MemoryRetrievalPolicy,
    MemoryRetrievalRequest,
    MemoryRetrievalScope,
    MemoryRetrievalService,
    MemoryRetrievalUnavailable,
    MemorySourceKind,
    NativeMemoryProvider,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
)
from khaos.memory.core.contracts import canonical_json
from khaos.memory.ledger import SqliteEventLedger


def _runtime(
    *,
    principal_id: str = "principal:a",
    project_id: str = "project:a",
    task_id: str | None = "task:a",
    session_id: str | None = "session:a",
    repo_id: str | None = "repo:a",
    commit_sha: str | None = "B2",
) -> RuntimeMemoryContext:
    return RuntimeMemoryContext(
        principal_id=principal_id,
        project_id=project_id,
        session_id=session_id,
        task_id=task_id,
        workspace_id="workspace:a",
        mode="coding",
        repo_id=repo_id,
        commit_sha=commit_sha,
        environment_fingerprint="test",
    )


def _hit(
    memory_id: str,
    *,
    principal_id: str = "principal:a",
    project_id: str = "project:a",
    source_kind: MemorySourceKind = MemorySourceKind.PROJECT_CONVENTION,
    provenance: dict[str, object] | None = None,
    content: str | None = None,
    record_digest: str = "",
) -> MemoryHit:
    return MemoryHit(
        provider_id="test-provider",
        external_id=memory_id,
        memory_id=memory_id,
        content=content or memory_id,
        raw_score=-1.0,
        source_type=SourceType.USER,
        source_ref="test",
        provider_metadata={},
        authority_hint=MemoryAuthority.AGENT_INFERRED.value,
        confidence_hint=0.5,
        principal_id=principal_id,
        project_id=project_id,
        namespace="private",
        scope="coding",
        source_kind=source_kind.value,
        provenance=provenance or {
            "principal_id": principal_id,
            "project_id": project_id,
        },
        record_digest=record_digest,
    )


class _Broker:
    def __init__(self, hits: list[MemoryHit]) -> None:
        self.hits = hits

    async def search(self, _query, _runtime, _budget, *, include_historical=False):
        del include_historical
        return EvidenceResolution(tuple(self.hits))


def _request(
    runtime: RuntimeMemoryContext,
    policy: MemoryRetrievalPolicy,
    *,
    needs: tuple[MemoryRetrievalNeed, ...] = (
        MemoryRetrievalNeed.PROJECT_CONVENTIONS,
    ),
    scope: MemoryRetrievalScope = MemoryRetrievalScope.PROJECT_HISTORY,
    repository_generation: str | None = None,
    published_plan_revision_id: str | None = None,
    max_records: int | None = None,
    query: str = "memory",
) -> MemoryRetrievalRequest:
    return MemoryRetrievalRequest.from_runtime(
        runtime,
        policy=policy,
        query=query,
        scope=scope,
        needs=needs,
        repository_generation=repository_generation,
        published_plan_revision_id=published_plan_revision_id,
        max_records=max_records,
    )


def test_policy_and_request_are_canonical_and_immutable():
    policy = MemoryRetrievalPolicy.production()
    assert policy.policy_digest == MemoryRetrievalPolicy.production().policy_digest
    with pytest.raises(TypeError):
        policy.max_records_per_source_kind[MemorySourceKind.SUMMARY.value] = 99
    with pytest.raises(FrozenInstanceError):
        policy.max_records = 100

    request = _request(_runtime(), policy)
    assert request.query_text_digest
    assert request.request_digest
    assert request.policy_digest == policy.policy_digest


def test_event_payload_redacts_authority_and_secret_material_before_hashing():
    event = MemoryEvent.create(
        MemoryEventType.APPROVAL_DECIDED,
        principal_id="principal:a",
        project_id="project:a",
        payload={
            "approval_receipt": "receipt-secret",
            "nested": {"api_key": "key-secret"},
            "note": "Authorization: Bearer token-secret",
            "safe": "ordinary observation",
        },
    )

    serialized = canonical_json(event.payload)
    assert "receipt-secret" not in serialized
    assert "key-secret" not in serialized
    assert "token-secret" not in serialized
    assert "ordinary observation" in serialized
    assert event.payload["approval_receipt"] == "[REDACTED_SECRET]"
    assert event.payload["nested"]["api_key"] == "[REDACTED_SECRET]"


@pytest.mark.asyncio
async def test_tenant_and_project_identity_are_enforced_before_projection():
    policy = MemoryRetrievalPolicy(max_records=8)
    runtime = _runtime()
    broker = _Broker(
        [
            _hit("owner-b", principal_id="principal:b"),
            _hit("project-b", project_id="project:b"),
            _hit("owner-a"),
        ]
    )
    service = MemoryRetrievalService(broker, policy)
    bundle = await service.retrieve(_request(runtime, policy), runtime)
    assert [item.memory_id for item in bundle.items] == ["owner-a"]


@pytest.mark.asyncio
async def test_memory_provider_failure_is_advisory():
    class FailingBroker:
        async def search(self, *_args, **_kwargs):
            raise RuntimeError("index unavailable")

    policy = MemoryRetrievalPolicy()
    runtime = _runtime()
    with pytest.raises(MemoryRetrievalUnavailable):
        await MemoryRetrievalService(FailingBroker(), policy).retrieve(
            _request(runtime, policy), runtime
        )


@pytest.mark.asyncio
async def test_repository_freshness_excludes_wrong_repo_and_marks_stale():
    policy = MemoryRetrievalPolicy(max_records=8)
    runtime = _runtime()
    hits = [
        _hit(
            "wrong-repo",
            source_kind=MemorySourceKind.REPOSITORY_OBSERVATION,
            provenance={
                "principal_id": runtime.principal_id,
                "project_id": runtime.project_id,
                "repository_id": "repo:other",
                "base_revision": "B2",
                "repository_generation": "G2",
            },
        ),
        _hit(
            "stale-repo",
            source_kind=MemorySourceKind.REPOSITORY_OBSERVATION,
            provenance={
                "principal_id": runtime.principal_id,
                "project_id": runtime.project_id,
                "repository_id": "repo:a",
                "base_revision": "B1",
                "repository_generation": "G1",
            },
        ),
        _hit(
            "current-repo",
            source_kind=MemorySourceKind.REPOSITORY_OBSERVATION,
            provenance={
                "principal_id": runtime.principal_id,
                "project_id": runtime.project_id,
                "repository_id": "repo:a",
                "base_revision": "B2",
                "repository_generation": "G2",
            },
        ),
    ]
    service = MemoryRetrievalService(_Broker(hits), policy)
    request = _request(
        runtime,
        policy,
        needs=(MemoryRetrievalNeed.REPOSITORY_HINTS,),
        repository_generation="G2",
    )
    bundle = await service.retrieve(request, runtime)
    assert [item.memory_id for item in bundle.items] == ["current-repo", "stale-repo"]
    assert bundle.items[0].currentness is MemoryCurrentness.CURRENT
    assert bundle.items[1].currentness is MemoryCurrentness.STALE


@pytest.mark.asyncio
async def test_plan_history_is_historical_even_when_it_is_highly_relevant():
    policy = MemoryRetrievalPolicy(max_records=8)
    runtime = _runtime()
    hit = _hit(
        "plan-p1",
        source_kind=MemorySourceKind.PLAN_HISTORY,
        provenance={
            "principal_id": runtime.principal_id,
            "project_id": runtime.project_id,
            "plan_revision_id": "P1",
        },
    )
    request = _request(
        runtime,
        policy,
        needs=(MemoryRetrievalNeed.PLAN_HISTORY,),
        published_plan_revision_id="P2",
    )
    bundle = await MemoryRetrievalService(_Broker([hit]), policy).retrieve(request, runtime)
    assert bundle.items[0].currentness is MemoryCurrentness.HISTORICAL


@pytest.mark.asyncio
async def test_results_are_bounded_and_deterministic():
    policy = MemoryRetrievalPolicy(
        max_records=4,
        max_total_bytes=2048,
        max_records_per_source_kind={MemorySourceKind.PROJECT_CONVENTION.value: 8},
    )
    runtime = _runtime()
    hits = [_hit(f"memory-{index:05d}") for index in range(10000)]
    service = MemoryRetrievalService(_Broker(hits), policy)
    request = _request(runtime, policy, max_records=10000)
    first = await service.retrieve(request, runtime)
    second = await service.retrieve(request, runtime)
    assert first.selected_count == 4
    assert first.total_candidate_count == 10000
    assert first.truncated is True
    assert [item.memory_id for item in first.items] == [item.memory_id for item in second.items]
    assert first.bundle_digest == second.bundle_digest


@pytest.mark.asyncio
async def test_malformed_record_digest_is_not_projected():
    policy = MemoryRetrievalPolicy()
    runtime = _runtime()
    hit = _hit("tampered", record_digest="not-the-canonical-digest")
    bundle = await MemoryRetrievalService(_Broker([hit]), policy).retrieve(
        _request(runtime, policy), runtime
    )
    assert bundle.items == ()
    assert bundle.truncated is True


@pytest.mark.asyncio
async def test_native_memory_writes_provenance_digest_and_owner_scope(tmp_path: Path):
    database = Database(tmp_path / "khaos.db")
    await database.connect()
    await database.run_migrations()
    provider = NativeMemoryProvider(database)
    broker = MemoryBroker(provider, SqliteEventLedger(database))
    runtime = _runtime()
    event = MemoryEvent.create(
        MemoryEventType.USER_MESSAGE,
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
        session_id=runtime.session_id,
        task_id=runtime.task_id,
        repo_id=runtime.repo_id,
        commit_sha=runtime.commit_sha,
        source_type=SourceType.USER,
        trust_hint=TrustHint.USER_STATED,
        payload={"content": "project convention: use pytest"},
    )
    await broker.record_event(event)
    decision = await broker.propose_memory(
        MemoryCandidate(
            memory_type="PROJECT_FACT",
            claim="use pytest",
            key="test_command",
            authority=MemoryAuthority.USER_STATED,
            confidence=0.9,
            source_event_ids=(event.event_id,),
            namespace="private",
            source_kind=MemorySourceKind.PROJECT_CONVENTION,
        ),
        runtime,
    )
    assert decision.accepted is True
    async with database.read_connection() as conn:
        row = await (
            await conn.execute(
                "SELECT source_kind, provenance_json, record_digest FROM memory_nodes WHERE memory_id = ?",
                (decision.memory_id,),
            )
        ).fetchone()
    assert row["source_kind"] == MemorySourceKind.PROJECT_CONVENTION.value
    assert "repository_id" in row["provenance_json"]
    assert row["record_digest"]
    policy = MemoryRetrievalPolicy.production()
    bundle = await MemoryRetrievalService(broker, policy).retrieve(
        _request(
            runtime,
            policy,
            needs=(MemoryRetrievalNeed.PROJECT_CONVENTIONS,),
            query="pytest",
        ),
        runtime,
    )
    assert [item.source_kind for item in bundle.items] == [MemorySourceKind.PROJECT_CONVENTION]
    await database.close()


@pytest.mark.asyncio
async def test_native_promotion_refreshes_integrity_digest(tmp_path: Path):
    database = Database(tmp_path / "khaos.db")
    await database.connect()
    await database.run_migrations()
    provider = NativeMemoryProvider(database)
    broker = MemoryBroker(provider, SqliteEventLedger(database))
    runtime = _runtime()
    event = MemoryEvent.create(
        MemoryEventType.USER_MESSAGE,
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
        session_id=runtime.session_id,
        task_id=runtime.task_id,
        repo_id=runtime.repo_id,
        commit_sha=runtime.commit_sha,
        source_type=SourceType.USER,
        trust_hint=TrustHint.USER_STATED,
        payload={"content": "promotion digest test"},
    )
    await broker.record_event(event)
    decision = await broker.propose_memory(
        MemoryCandidate(
            memory_type="PROJECT_FACT",
            claim="promotion digest test",
            key="promotion_digest",
            authority=MemoryAuthority.USER_STATED,
            confidence=0.9,
            source_event_ids=(event.event_id,),
            namespace="private",
            source_kind=MemorySourceKind.PROJECT_CONVENTION,
        ),
        runtime,
    )
    promoted = await broker.promote_memory(decision.memory_id, runtime, user_approved=True)
    assert promoted.accepted is True
    async with database.read_connection() as conn:
        row = await (
            await conn.execute(
                "SELECT status, record_digest FROM memory_nodes WHERE memory_id = ?",
                (decision.memory_id,),
            )
        ).fetchone()
    assert row["status"] == "VERIFIED"
    assert row["record_digest"]
    await database.close()
