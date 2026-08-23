"""Regression coverage for the production-facing Memory V2 surfaces."""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from khaos.db import Database
from khaos.memory import (
    AMLAdapterError,
    BenchmarkCase,
    CodeGraphService,
    MemoryAMLAdapter,
    MemoryAuthority,
    MemoryBenchmarkHarness,
    MemoryBroker,
    MemoryCandidate,
    MemoryEvent,
    MemoryEventType,
    MemoryObservability,
    MemoryProfileStore,
    MemoryStatus,
    MemoryTransferError,
    MemoryTransferService,
    RuntimeMemoryContext,
    SourceType,
    TrustHint,
    aml_add,
    aml_search,
)
from khaos.memory.conformance import run_provider_conformance
from khaos.memory.core.contracts import MemoryCapabilities, ProviderHealth
from khaos.memory.ledger import SqliteEventLedger
from khaos.memory.providers import (
    MemoryProviderManager,
    MemoryProviderRegistry,
    NativeMemoryProvider,
    ProviderLifecycleError,
    ProviderManifest,
    build_native_registry,
)


def _runtime() -> RuntimeMemoryContext:
    return RuntimeMemoryContext(
        principal_id="principal:alice",
        project_id="project:memory-v2",
        session_id="session:production",
        task_id="task:memory-v2",
        workspace_id="workspace:memory-v2",
        mode="coding",
        environment_fingerprint="test-environment",
        environment={"platform": "test"},
    )


async def _broker(tmp_path: Path, *, profile=None, codegraph=None, observability=None):
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    provider = NativeMemoryProvider(db)
    broker = MemoryBroker(
        provider,
        SqliteEventLedger(db),
        profile=profile,
        codegraph=codegraph,
        observability=observability,
    )
    return db, broker


async def _event_and_candidate(broker: MemoryBroker, runtime: RuntimeMemoryContext):
    event = MemoryEvent.create(
        MemoryEventType.USER_MESSAGE,
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
        session_id=runtime.session_id,
        source_type=SourceType.USER,
        trust_hint=TrustHint.USER_STATED,
        payload={"content": "I prefer the native provider"},
    )
    await broker.record_event(event)
    candidate = MemoryCandidate(
        memory_type="USER_MEMORY",
        claim="preferred_memory_provider: khaos-native",
        key="preferred_memory_provider",
        authority=MemoryAuthority.USER_STATED,
        confidence=0.95,
        source_event_ids=(event.event_id,),
        scope="global",
        namespace="private",
    )
    return event, candidate


async def test_profile_provider_registry_and_lifecycle_are_persisted(tmp_path):
    db, broker = await _broker(tmp_path)
    runtime = _runtime()
    registry = build_native_registry(db)
    handle = await registry.activate("khaos-native")
    manager = MemoryProviderManager(registry, broker, database=db)
    await manager.persist()

    profile_store = MemoryProfileStore(db)
    from khaos.memory import CODING_PROFILE

    await profile_store.set(
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
        profile=CODING_PROFILE,
    )

    assert handle.state.value == "healthy"
    assert await profile_store.get(
        principal_id=runtime.principal_id,
        project_id=runtime.project_id,
    ) == "coding"
    statuses = await manager.statuses()
    assert statuses[0].active is True
    assert statuses[0].healthy is True

    async with db.read_connection() as conn:
        provider_row = await (
            await conn.execute(
                "SELECT lifecycle_state, active FROM memory_provider_registry "
                "WHERE provider_id = ?",
                ("khaos-native",),
            )
        ).fetchone()
        assert provider_row["lifecycle_state"] == "healthy"
        assert provider_row["active"] == 1

    await registry.close()


async def test_provider_switch_replays_ledger_and_preserves_broker_boundary(tmp_path):
    db, broker = await _broker(tmp_path)
    runtime = _runtime()
    registry = MemoryProviderRegistry()
    native_manifest = ProviderManifest(
        provider_id="khaos-native",
        capabilities=NativeMemoryProvider(db).capabilities(),
    )

    class MirrorProvider(NativeMemoryProvider):
        provider_id = "mirror-native"

    mirror_manifest = ProviderManifest(
        provider_id="mirror-native",
        capabilities=MirrorProvider(db).capabilities(),
    )
    registry.register(native_manifest, lambda _manifest: NativeMemoryProvider(db))
    registry.register(mirror_manifest, lambda _manifest: MirrorProvider(db))
    native = await registry.activate("khaos-native")
    broker.provider = native.provider
    manager = MemoryProviderManager(registry, broker, database=db)
    event, candidate = await _event_and_candidate(broker, runtime)
    decision = await broker.propose_memory(candidate, runtime)
    assert decision.accepted is True

    switched = await manager.set_provider("mirror-native", runtime)
    assert switched.provider_id == "mirror-native"
    assert broker.provider.provider_id == "mirror-native"
    assert registry.active_id() == "mirror-native"
    resolution = await broker.search("native provider", runtime, budget=type("B", (), {"max_hits": 8})())
    assert any(hit.memory_id == decision.memory_id for hit in resolution.primary_hits)
    assert event.event_id in resolution.primary_hits[0].event_ids
    await registry.close()


async def test_codegraph_is_rebuildable_scoped_and_source_inspectable(tmp_path):
    from khaos.memory import CODING_PROFILE

    source_root = tmp_path / "workspace"
    source_root.mkdir()
    (source_root / "main.py").write_text(
        "from helper import greet\n\n\ndef main():\n    return greet('world')\n",
        encoding="utf-8",
    )
    (source_root / "helper.py").write_text(
        "def greet(name):\n    return f'hello {name}'\n",
        encoding="utf-8",
    )
    db, broker = await _broker(tmp_path, profile=CODING_PROFILE)
    runtime = _runtime()
    graph = CodeGraphService(db)
    broker.codegraph = graph
    report = await graph.build(runtime, source_root)
    assert report.files == 2
    assert report.nodes >= 4
    assert report.edges >= 1

    resolution = await broker.search("greet", runtime, budget=type("B", (), {"max_hits": 8})())
    graph_hits = [hit for hit in resolution.primary_hits if hit.external_id.startswith("codegraph:")]
    assert graph_hits
    node_id = graph_hits[0].external_id.removeprefix("codegraph:")
    source = await broker.source(runtime, f"codegraph:{node_id}")
    assert source is not None
    assert source["project_id"] == runtime.project_id
    assert await broker.evidence(runtime, f"codegraph:{node_id}") is not None


async def test_aml_adapter_and_convenience_functions_use_broker_policy(tmp_path):
    db, broker = await _broker(tmp_path)
    runtime = _runtime()
    item = {
        "claim": "editor: vim",
        "memory_type": "USER_MEMORY",
        "authority": "USER_STATED",
        "evidence_refs": ["conversation:1"],
        "key": "editor",
    }
    decision = await aml_add(broker, item, runtime)
    assert decision.accepted is True
    result = await aml_search(broker, "vim", runtime)
    assert result["results"][0]["id"] == decision.memory_id

    adapter = MemoryAMLAdapter(broker)
    with pytest.raises(AMLAdapterError):
        await adapter.add({"claim": "invalid", "memory_type": "UNKNOWN"}, runtime)
    forgotten = await adapter.forget((decision.memory_id,), runtime)
    assert forgotten["forgotten_ids"] == [decision.memory_id]
    assert (await adapter.search("vim", runtime))["results"] == []


async def test_benchmark_observability_and_finite_metrics_are_bounded(tmp_path):
    db, broker = await _broker(tmp_path)
    runtime = _runtime()
    _, candidate = await _event_and_candidate(broker, runtime)
    assert (await broker.propose_memory(candidate, runtime)).accepted

    report = await MemoryBenchmarkHarness(broker).run(
        [BenchmarkCase("provider", "native provider", ("khaos-native",))],
        runtime,
        repetitions=3,
    )
    assert len(report.runs) == 9
    assert report.metrics["recall"] == 1.0
    async with db.read_connection() as conn:
        row = await (
            await conn.execute(
                "SELECT COUNT(*) AS count FROM memory_benchmark_runs "
                "WHERE project_id = ?",
                (runtime.project_id,),
            )
        ).fetchone()
        assert row["count"] == 9

    metrics = MemoryObservability(db)
    await metrics.record("memory.test", 3.0, runtime, unit="count")
    await metrics.record("memory.test", 5.0, runtime, unit="count")
    summary = await metrics.summary("memory.test", runtime)
    assert summary.count == 2
    assert summary.p50 == 3.0
    assert summary.p95 == 5.0
    with pytest.raises(ValueError, match="finite"):
        await metrics.record("memory.test", math.nan, runtime)


async def test_provider_conformance_reports_each_mandatory_check(tmp_path):
    db, broker = await _broker(tmp_path)
    report = await run_provider_conformance(broker, _runtime())
    assert report.passed is True
    assert len(report.checks) == 12
    assert all(report.checks.values())


async def test_transfer_package_is_digest_bound_and_idempotent(tmp_path):
    db, broker = await _broker(tmp_path)
    runtime = _runtime()
    _, candidate = await _event_and_candidate(broker, runtime)
    decision = await broker.propose_memory(candidate, runtime)
    assert decision.accepted
    service = MemoryTransferService(broker)
    package_path = tmp_path / "memory.json"
    exported = await service.export(runtime, package_path)
    imported = await service.import_package(runtime, package_path)
    assert exported["digest"] == imported["digest"]
    assert imported["replayed_nodes"] >= 1

    package = package_path.read_text(encoding="utf-8")
    package_path.write_text(package.replace("khaos-memory-v2", "tampered"), encoding="utf-8")
    with pytest.raises(MemoryTransferError, match="digest|format"):
        await service.import_package(runtime, package_path)


def test_provider_manifest_rejects_string_collections():
    with pytest.raises(ProviderLifecycleError, match="permissions"):
        ProviderManifest.from_mapping(
            {"id": "bad-provider", "permissions": "network"}
        )
