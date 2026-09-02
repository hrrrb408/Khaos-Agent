"""M8.1 unified workspace-bound repository intelligence tests."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from khaos.coding.intelligence.repository import (
    FreshnessPolicy,
    IntelligenceFreshness,
    MutationEvent,
    MutationType,
    RepoContextRequest,
    RepoIntelligenceService,
    RepoIntelligenceUnavailableError,
    RepoQueryKind,
    RepoQueryRequest,
    RepoResourceLimits,
    repository_id_for_workspace,
)
from khaos.coding.intelligence.query_service import ContextIntelligenceService
from khaos.coding.planning.approval.mutation_fence import WorkspaceMutationFence


pytestmark = pytest.mark.posix_host


class _WorkspaceManager:
    def __init__(self, *workspaces: SimpleNamespace) -> None:
        self.workspaces = {workspace.id: workspace for workspace in workspaces}

    def get(self, workspace_id: str):
        return self.workspaces.get(workspace_id)

    def require(self, workspace_id: str, **_kwargs):
        return self.get(workspace_id)


def _workspace(root: Path, workspace_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        id=workspace_id,
        task_id=f"task-{workspace_id}",
        principal_id="principal-1",
        project_id="project-1",
        worktree_path=root,
        base_sha="base-1",
        git_identity=None,
        creator_runtime_id=f"runtime-{workspace_id}",
        generation=1,
    )


def _request(
    workspace: SimpleNamespace,
    kind: RepoQueryKind,
    *,
    query: str = "",
    path: str = "",
    symbol_id: str = "",
    target_files: tuple[str, ...] = (),
    target_symbols: tuple[str, ...] = (),
    policy: FreshnessPolicy = FreshnessPolicy.PREFER_CURRENT,
    limit: int = 32,
) -> RepoQueryRequest:
    return RepoQueryRequest(
        workspace_id=workspace.id,
        task_id=workspace.task_id,
        principal_id=workspace.principal_id,
        project_id=workspace.project_id,
        kind=kind,
        query=query,
        path=path,
        symbol_id=symbol_id,
        target_files=target_files,
        target_symbols=target_symbols,
        freshness_policy=policy,
        limit=limit,
    )


def _query(service: RepoIntelligenceService, request: RepoQueryRequest):
    return asyncio.run(service.query(request))


def _persistent_database(tmp_path: Path) -> Path:
    """Place derived state outside the model-writable repository root."""
    return tmp_path.parent / f"{tmp_path.name}-repo-intelligence.db"


def test_initial_index_is_reused_and_queries_are_typed(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text(
        "def run():\n    return 'marker'\n", encoding="utf-8"
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    first = _query(
        service,
        _request(workspace, RepoQueryKind.DEFINITIONS, query="run"),
    )
    cached = _query(
        service,
        _request(workspace, RepoQueryKind.DEFINITIONS, query="run"),
    )
    second = _query(
        service,
        _request(workspace, RepoQueryKind.REPOSITORY_OVERVIEW),
    )

    assert first.freshness is IntelligenceFreshness.CURRENT
    assert first.symbols[0].path == "src/app.py"
    assert cached == first
    assert second.overview is not None
    assert second.overview.file_count == 1
    metrics = service.metrics_snapshot()
    assert metrics.full_index_count == 1
    assert metrics.query_count == 3
    assert metrics.cache_hit_count == 1
    assert metrics.cache_miss_count == 2
    assert metrics.incremental_refresh_count == 0


def test_mutation_event_refreshes_only_changed_paths(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run():\n    return 'old'\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    first = _query(service, _request(workspace, RepoQueryKind.DEFINITIONS, query="run"))
    service.mark_dirty(
        MutationEvent(
            workspace_id=workspace.id,
            mutation_type=MutationType.UPDATE,
            paths=("app.py",),
        )
    )
    source.write_text("def run():\n    return 'new'\n", encoding="utf-8")
    updated = _query(service, _request(workspace, RepoQueryKind.DEFINITIONS, query="run"))

    assert updated.freshness is IntelligenceFreshness.CURRENT
    assert updated.generation.generation > first.generation.generation
    assert updated.symbols[0].content_digest != first.symbols[0].content_digest
    metrics = service.metrics_snapshot()
    assert metrics.full_index_count == 1
    assert metrics.incremental_refresh_count == 1
    assert metrics.reparsed_file_count == 1

    source.unlink()
    service.mark_dirty(
        MutationEvent(
            workspace_id=workspace.id,
            mutation_type=MutationType.DELETE,
            paths=("app.py",),
        )
    )
    deleted = _query(service, _request(workspace, RepoQueryKind.DEFINITIONS, query="run"))
    assert deleted.symbols == ()


def test_incremental_refresh_uses_the_workspace_mutation_fence(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): return 'old'\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    manager = _WorkspaceManager(workspace)
    manager._mutation_fence = WorkspaceMutationFence()
    service = RepoIntelligenceService(manager)

    first = _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    source.write_text("def run(): return 'new'\n", encoding="utf-8")
    service.mark_dirty(
        MutationEvent(workspace.id, MutationType.UPDATE, ("app.py",))
    )
    updated = _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))

    assert updated.freshness is IntelligenceFreshness.CURRENT
    assert updated.generation.generation > first.generation.generation
    assert manager._mutation_fence.current_owner(workspace.id) is None
    asyncio.run(service.close())


@pytest.mark.parametrize(
    ("filename", "language"),
    (("main.py", "python"), ("main.go", "go"), ("main.rs", "rust"), ("main.ts", "typescript")),
)
def test_supported_languages_share_one_query_contract(
    tmp_path: Path, filename: str, language: str
) -> None:
    contents = {
        "python": "def run(): pass\n",
        "go": "package main\nfunc Run() {}\n",
        "rust": "fn run() {}\n",
        "typescript": "export function run(): void {}\n",
    }
    (tmp_path / filename).write_text(contents[language], encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    result = _query(
        service,
        _request(workspace, RepoQueryKind.SYMBOLS, query="run", limit=8),
    )

    assert result.freshness is IntelligenceFreshness.CURRENT
    assert result.symbols
    assert result.symbols[0].language == language


def test_lexical_search_is_explicit_fallback_and_unsupported_is_metadata_only(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("UNIQUE_MARKER\n", encoding="utf-8")
    (tmp_path / "data.json").write_text('{"key": "value"}\n', encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    result = _query(
        service,
        _request(workspace, RepoQueryKind.SEARCH_TEXT, query="UNIQUE_MARKER"),
    )
    overview = _query(
        service,
        _request(workspace, RepoQueryKind.REPOSITORY_OVERVIEW),
    )

    assert result.text_matches
    assert result.lexical_fallback is True
    metadata = {item.path: item for item in overview.files}
    assert metadata["README.md"].semantic_support is False
    assert metadata["data.json"].semantic_support is False


def test_search_prefers_semantic_definition_over_lexical_coincidence(
    tmp_path: Path,
) -> None:
    (tmp_path / "runtime.py").write_text(
        "class RuntimeManager:\n    pass\n", encoding="utf-8"
    )
    (tmp_path / "runtime_notes.py").write_text(
        "note = 'RuntimeManager appears in this note'\n", encoding="utf-8"
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    result = _query(
        service,
        _request(workspace, RepoQueryKind.SEARCH_TEXT, query="RuntimeManager"),
    )

    assert [(item.name, item.path) for item in result.symbols] == [
        ("RuntimeManager", "runtime.py")
    ]
    assert result.text_matches == ()
    assert result.semantic_support is True
    assert result.lexical_fallback is False


def test_context_ranks_definition_relations_and_tests_before_lexical_hits(
    tmp_path: Path,
) -> None:
    (tmp_path / "target.py").write_text(
        "def target():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "caller.py").write_text(
        "from target import target\n"
        "def caller():\n"
        "    return target()\n",
        encoding="utf-8",
    )
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_target.py").write_text(
        "from target import target\n"
        "def test_target():\n"
        "    assert target() == 1\n",
        encoding="utf-8",
    )
    (tmp_path / "keyword_target.py").write_text(
        "note = 'target appears only as an unrelated keyword'\n",
        encoding="utf-8",
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    result = asyncio.run(
        service.select_context(
            RepoContextRequest(
                workspace_id=workspace.id,
                task_id=workspace.task_id,
                principal_id=workspace.principal_id,
                project_id=workspace.project_id,
                query="target",
                target_files=("target.py",),
                target_symbols=("target",),
                max_files=4,
                max_structure_entries=32,
            )
        )
    )

    paths = [item.path for item in result.files]
    scores = {item.path: item.relevance_score for item in result.files}
    assert paths[0] == "target.py"
    assert set(paths[1:3]) == {"caller.py", "tests/test_target.py"}
    assert "keyword_target.py" in result.structure_paths
    assert scores["target.py"] > scores["caller.py"] > scores["keyword_target.py"]
    assert scores["tests/test_target.py"] > scores["keyword_target.py"]
    assert any(relation.kind == "CALLER" for relation in result.relations)
    assert any(relation.kind == "RELATED_TEST" for relation in result.relations)


def test_explicit_context_symbol_target_is_not_a_substring_match(
    tmp_path: Path,
) -> None:
    (tmp_path / "exact.py").write_text(
        "def target():\n    return 1\n", encoding="utf-8"
    )
    (tmp_path / "near.py").write_text(
        "def target_helper():\n    return 2\n", encoding="utf-8"
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    result = asyncio.run(
        service.select_context(
            RepoContextRequest(
                workspace_id=workspace.id,
                task_id=workspace.task_id,
                principal_id=workspace.principal_id,
                project_id=workspace.project_id,
                query="",
                target_symbols=("target",),
                max_files=1,
            )
        )
    )

    assert [item.path for item in result.files] == ["exact.py"]
    assert [item.name for item in result.symbols] == ["target"]


def test_rejected_binary_keeps_bounded_metadata_only_record(tmp_path: Path) -> None:
    (tmp_path / "payload.py").write_bytes(b"safe\x00binary")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    overview = _query(service, _request(workspace, RepoQueryKind.REPOSITORY_OVERVIEW))
    context = asyncio.run(
        service.select_context(
            RepoContextRequest(
                workspace_id=workspace.id,
                task_id=workspace.task_id,
                principal_id=workspace.principal_id,
                project_id=workspace.project_id,
                query="payload",
                target_files=("payload.py",),
                max_files=1,
            )
        )
    )

    payload = {item.path: item for item in overview.files}["payload.py"]
    assert payload.parser_source == "metadata"
    assert payload.semantic_support is False
    assert payload.content_digest
    assert context.files == ()
    assert "metadata_only:payload.py" in context.truncation_reasons


def test_workspace_isolation_and_concurrent_queries(tmp_path: Path) -> None:
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "same.py").write_text("def only_a(): pass\n", encoding="utf-8")
    (root_b / "same.py").write_text("def only_b(): pass\n", encoding="utf-8")
    workspace_a = _workspace(root_a, "ws-a")
    workspace_b = _workspace(root_b, "ws-b")
    service = RepoIntelligenceService(_WorkspaceManager(workspace_a, workspace_b))

    async def run_queries():
        return await asyncio.gather(
            service.query(_request(workspace_a, RepoQueryKind.SYMBOLS, query="only")),
            service.query(_request(workspace_b, RepoQueryKind.SYMBOLS, query="only")),
        )

    first, second = asyncio.run(run_queries())
    assert {item.path for item in first.symbols} == {"same.py"}
    assert {item.name for item in first.symbols} == {"only_a"}
    assert {item.name for item in second.symbols} == {"only_b"}
    assert first.generation.workspace_id == workspace_a.id
    assert second.generation.workspace_id == workspace_b.id


def test_same_workspace_queries_share_one_refresh_and_cancelled_waiter_isolated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "app.py").write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))

    async def scenario() -> None:
        handle = service._handle_for(
            workspace, repository_id_for_workspace(workspace)
        )
        entered = asyncio.Event()
        release = asyncio.Event()
        original_index = handle.indexer.index

        async def gated_index(
            repository_id: str,
            root: Path,
            *,
            workspace_id: str | None = None,
            full_reindex: bool = False,
        ) -> dict[str, object]:
            entered.set()
            await release.wait()
            return await original_index(
                repository_id,
                root,
                workspace_id=workspace_id,
                full_reindex=full_reindex,
            )

        monkeypatch.setattr(handle.indexer, "index", gated_index)
        holder = asyncio.create_task(
            service.query(_request(workspace, RepoQueryKind.SYMBOLS, query="run"))
        )
        await entered.wait()
        waiter = asyncio.create_task(
            service.query(_request(workspace, RepoQueryKind.SYMBOLS, query="run"))
        )
        await asyncio.sleep(0)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        release.set()
        result = await holder

        assert result.freshness is IntelligenceFreshness.CURRENT
        assert [item.name for item in result.symbols] == ["run"]
        assert service.metrics_snapshot().full_index_count == 1
        await service.close()

    asyncio.run(scenario())


def test_workspace_require_type_error_fails_closed(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")

    class _BrokenRequireManager(_WorkspaceManager):
        def require(self, _workspace_id: str, **_kwargs):
            raise TypeError("owner contract is broken")

    service = RepoIntelligenceService(_BrokenRequireManager(workspace))
    with pytest.raises(RepoIntelligenceUnavailableError, match="owner validation failed"):
        _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))


def test_typed_relationship_queries_share_the_indexed_graph(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def target():\n    return 1\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "from a import target\n"
        "def caller():\n"
        "    return target()\n",
        encoding="utf-8",
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))
    _query(service, _request(workspace, RepoQueryKind.REPOSITORY_OVERVIEW))

    callees = _query(
        service, _request(workspace, RepoQueryKind.CALLEES, query="caller")
    )
    callers = _query(
        service, _request(workspace, RepoQueryKind.CALLERS, query="target")
    )
    imports = _query(
        service, _request(workspace, RepoQueryKind.IMPORTS, path="b.py")
    )
    importers = _query(
        service, _request(workspace, RepoQueryKind.IMPORTERS, path="a.py")
    )
    related = _query(
        service, _request(workspace, RepoQueryKind.RELATED_FILES, path="a.py")
    )

    assert {(item.kind, item.source_path, item.target_path) for item in callees.relations} == {
        ("CALLEE", "b.py", "a.py")
    }
    assert {(item.kind, item.source_path, item.target_path) for item in callers.relations} == {
        ("CALLER", "b.py", "a.py")
    }
    assert {(item.kind, item.source_path, item.target_path) for item in imports.relations} == {
        ("IMPORT", "b.py", "a.py")
    }
    assert {(item.kind, item.source_path, item.target_path) for item in importers.relations} == {
        ("REVERSE_IMPORT", "b.py", "a.py")
    }
    assert {item.target_path for item in related.relations} == {"a.py"}


def test_shared_database_connection_keeps_workspace_indexes_isolated(
    tmp_path: Path,
) -> None:
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "same.py").write_text("def only_a(): pass\n", encoding="utf-8")
    (root_b / "same.py").write_text("def only_b(): pass\n", encoding="utf-8")
    workspace_a = _workspace(root_a, "ws-a")
    workspace_b = _workspace(root_b, "ws-b")
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    service = RepoIntelligenceService(
        _WorkspaceManager(workspace_a, workspace_b), database=connection
    )

    async def run_queries():
        return await asyncio.gather(
            service.query(_request(workspace_a, RepoQueryKind.SYMBOLS, query="only")),
            service.query(_request(workspace_b, RepoQueryKind.SYMBOLS, query="only")),
        )

    first, second = asyncio.run(run_queries())
    assert {item.name for item in first.symbols} == {"only_a"}
    assert {item.name for item in second.symbols} == {"only_b"}
    asyncio.run(service.close())


def test_persistent_index_restarts_without_full_reindex(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    first = _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    asyncio.run(first_service.close())

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    second = _query(restarted, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))

    assert second.generation == first.generation
    assert second.symbols[0].symbol_id == first.symbols[0].symbol_id
    assert restarted.metrics_snapshot().full_index_count == 0
    asyncio.run(restarted.close())


def test_persisted_stale_without_pending_paths_rebuilds_for_prefer_current(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    asyncio.run(first_service.close())

    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE repo_intelligence_state SET freshness='stale', "
        "full_refresh_required=0, pending_paths_json='[]' WHERE workspace_id=?",
        (workspace.id,),
    )
    connection.commit()
    connection.close()

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    rebuilt = _query(
        restarted, _request(workspace, RepoQueryKind.SYMBOLS, query="run")
    )

    assert rebuilt.freshness is IntelligenceFreshness.CURRENT
    assert restarted.metrics_snapshot().full_index_count == 1
    asyncio.run(restarted.close())


def test_persisted_mutation_is_reconciled_after_restart(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def old_name(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    first = _query(
        first_service,
        _request(workspace, RepoQueryKind.SYMBOLS, query="old_name"),
    )

    source.write_text("def new_name(): pass\n", encoding="utf-8")
    first_service.mark_dirty(
        MutationEvent(workspace.id, MutationType.UPDATE, ("app.py",))
    )
    asyncio.run(first_service.close())

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    current = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="new_name",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )

    assert first.symbols[0].name == "old_name"
    assert current.freshness is IntelligenceFreshness.CURRENT
    assert [item.name for item in current.symbols] == ["new_name"]
    assert restarted.metrics_snapshot().full_index_count == 0
    assert restarted.metrics_snapshot().incremental_refresh_count == 1
    asyncio.run(restarted.close())


def test_probe_detected_mutation_is_durable_before_allow_stale_result(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("def old_name(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="old_name"))

    source.write_text("def new_name(): pass\n", encoding="utf-8")
    stale = _query(
        first_service,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="old_name",
            target_files=("app.py",),
            policy=FreshnessPolicy.ALLOW_STALE,
        ),
    )
    assert stale.freshness is IntelligenceFreshness.STALE
    asyncio.run(first_service.close())

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    current = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="new_name",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )
    assert current.freshness is IntelligenceFreshness.CURRENT
    assert [item.name for item in current.symbols] == ["new_name"]
    assert restarted.metrics_snapshot().full_index_count == 0
    asyncio.run(restarted.close())


def test_persisted_move_removes_ghost_symbols_after_restart(tmp_path: Path) -> None:
    source = tmp_path / "old.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))

    source.rename(tmp_path / "new.py")
    first_service.mark_dirty(
        MutationEvent(workspace.id, MutationType.MOVE, ("old.py", "new.py"))
    )
    asyncio.run(first_service.close())

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    moved = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="run",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )

    assert moved.freshness is IntelligenceFreshness.CURRENT
    assert {(item.name, item.path) for item in moved.symbols} == {("run", "new.py")}
    assert restarted.metrics_snapshot().full_index_count == 0
    asyncio.run(restarted.close())


def test_manifest_corruption_forces_rebuild_before_current_query(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    asyncio.run(first_service.close())

    connection = sqlite3.connect(database)
    # Resolve the project identity from durable state rather than relying on a
    # private handle that was cleared during close.
    connection.execute(
        "DELETE FROM code_files WHERE project_id IN "
        "(SELECT index_project_id FROM repo_intelligence_state WHERE workspace_id=?)",
        (workspace.id,),
    )
    connection.commit()
    connection.close()

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    rebuilt = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="run",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )

    assert rebuilt.freshness is IntelligenceFreshness.CURRENT
    assert [item.path for item in rebuilt.symbols] == ["app.py"]
    assert restarted.metrics_snapshot().full_index_count == 1
    asyncio.run(restarted.close())


def test_malformed_generation_forces_rebuild(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    asyncio.run(first_service.close())

    connection = sqlite3.connect(database)
    connection.execute(
        "UPDATE repo_intelligence_state SET generation=-1 WHERE workspace_id=?",
        (workspace.id,),
    )
    connection.commit()
    connection.close()

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    rebuilt = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="run",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )
    assert rebuilt.freshness is IntelligenceFreshness.CURRENT
    assert restarted.metrics_snapshot().full_index_count == 1
    asyncio.run(restarted.close())


def test_semantic_graph_corruption_forces_rebuild(tmp_path: Path) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)
    first_service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    _query(first_service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))
    asyncio.run(first_service.close())

    connection = sqlite3.connect(database)
    connection.execute(
        "DELETE FROM repository_symbols WHERE repository_id IN "
        "(SELECT index_project_id FROM repo_intelligence_state WHERE workspace_id=?)",
        (workspace.id,),
    )
    connection.commit()
    connection.close()

    restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
    rebuilt = _query(
        restarted,
        _request(
            workspace,
            RepoQueryKind.SYMBOLS,
            query="run",
            policy=FreshnessPolicy.REQUIRE_CURRENT,
        ),
    )

    assert rebuilt.freshness is IntelligenceFreshness.CURRENT
    assert [item.name for item in rebuilt.symbols] == ["run"]
    assert restarted.metrics_snapshot().full_index_count == 1
    asyncio.run(restarted.close())


def test_cancelled_refresh_is_rebuilt_after_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "a.py").write_text("def first(): pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def second(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    database = _persistent_database(tmp_path)

    async def scenario() -> None:
        service = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
        await service.query(_request(workspace, RepoQueryKind.SYMBOLS, query="first"))
        handle = service._handles[workspace.id]
        service.mark_dirty(MutationEvent(workspace.id, MutationType.ROLLBACK))
        entered = asyncio.Event()

        async def partial_index(
            repository_id: str,
            root: Path,
            *,
            workspace_id: str | None = None,
            full_reindex: bool = False,
        ) -> dict[str, object]:
            await handle.indexer._refresh_file(
                repository_id,
                root,
                handle.root_identity,
                root / "a.py",
                True,
            )
            entered.set()
            await asyncio.Event().wait()
            return {}

        monkeypatch.setattr(handle.indexer, "index", partial_index)
        task = asyncio.create_task(
            service.query(
                _request(
                    workspace,
                    RepoQueryKind.SYMBOLS,
                    query="second",
                    policy=FreshnessPolicy.REQUIRE_CURRENT,
                )
            )
        )
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await service.close()

        restarted = RepoIntelligenceService(_WorkspaceManager(workspace), database=database)
        rebuilt = await restarted.query(
            _request(
                workspace,
                RepoQueryKind.SYMBOLS,
                query="second",
                policy=FreshnessPolicy.REQUIRE_CURRENT,
            )
        )
        assert rebuilt.freshness is IntelligenceFreshness.CURRENT
        assert [item.name for item in rebuilt.symbols] == ["second"]
        assert restarted.metrics_snapshot().full_index_count == 1
        await restarted.close()

    asyncio.run(scenario())


def test_resource_limits_report_partial_without_unbounded_index(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / f"{index}.py").write_text(f"def f_{index}(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(
        _WorkspaceManager(workspace),
        limits=RepoResourceLimits(max_files=2, max_index_bytes=1024),
    )

    result = _query(service, _request(workspace, RepoQueryKind.REPOSITORY_OVERVIEW))

    assert result.freshness is IntelligenceFreshness.PARTIAL
    assert result.truncated is True
    assert len(result.files) <= 2


def test_successful_file_tool_mutation_marks_only_affected_paths_dirty(
    tmp_path: Path,
) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    context = ContextIntelligenceService(_WorkspaceManager(workspace))

    first = _query(
        context.repo_intelligence,
        _request(workspace, RepoQueryKind.SYMBOLS, query="run"),
    )
    source.write_text("def run(): return 1\n", encoding="utf-8")
    context.invalidate_from_tool_result(
        workspace_id=workspace.id,
        tool_name="write_file",
        arguments={"path": "app.py", "content": "def run(): return 1\n"},
    )
    updated = _query(
        context.repo_intelligence,
        _request(workspace, RepoQueryKind.SYMBOLS, query="run"),
    )

    assert updated.generation.generation > first.generation.generation
    assert context.repo_intelligence.metrics_snapshot().full_index_count == 1
    assert context.repo_intelligence.metrics_snapshot().incremental_refresh_count == 1


def test_move_mutation_removes_old_symbols_and_indexes_new_path(tmp_path: Path) -> None:
    source = tmp_path / "old.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    context = ContextIntelligenceService(_WorkspaceManager(workspace))
    first = _query(
        context.repo_intelligence,
        _request(workspace, RepoQueryKind.SYMBOLS, query="run"),
    )

    source.rename(tmp_path / "new.py")
    context.invalidate_from_tool_result(
        workspace_id=workspace.id,
        tool_name="move_file",
        arguments={"src": "old.py", "dst": "new.py"},
    )
    moved = _query(
        context.repo_intelligence,
        _request(workspace, RepoQueryKind.SYMBOLS, query="run"),
    )

    assert moved.generation.generation > first.generation.generation
    assert {item.path for item in moved.symbols} == {"new.py"}


def test_copy_mutation_indexes_destination_and_preserves_source(tmp_path: Path) -> None:
    source = tmp_path / "source.py"
    source.write_text("def copied_name(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))
    _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="copied_name"))

    destination = tmp_path / "destination.py"
    destination.write_bytes(source.read_bytes())
    service.mark_dirty(
        MutationEvent(workspace.id, MutationType.COPY, ("destination.py",))
    )
    copied = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="copied_name")
    )

    assert {item.path for item in copied.symbols} == {"destination.py", "source.py"}
    assert copied.freshness is IntelligenceFreshness.CURRENT
    assert service.metrics_snapshot().incremental_refresh_count == 1


def test_mutation_event_matrix_reconciles_create_delete_rename_restore_and_rollback(
    tmp_path: Path,
) -> None:
    source = tmp_path / "old.py"
    source.write_text("def old_name(): pass\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))
    _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="old_name"))

    created = tmp_path / "created.py"
    created.write_text("def created_name(): pass\n", encoding="utf-8")
    service.mark_dirty(MutationEvent(workspace.id, MutationType.CREATE, ("created.py",)))
    created_result = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="created_name")
    )
    assert [item.path for item in created_result.symbols] == ["created.py"]

    created.unlink()
    service.mark_dirty(MutationEvent(workspace.id, MutationType.DELETE, ("created.py",)))
    deleted_result = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="created_name")
    )
    assert deleted_result.symbols == ()

    source.rename(tmp_path / "renamed.py")
    service.mark_dirty(
        MutationEvent(workspace.id, MutationType.RENAME, ("old.py", "renamed.py"))
    )
    renamed_result = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="old_name")
    )
    assert {(item.name, item.path) for item in renamed_result.symbols} == {
        ("old_name", "renamed.py")
    }

    (tmp_path / "renamed.py").write_text(
        "def restored_name(): pass\n", encoding="utf-8"
    )
    service.mark_dirty(
        MutationEvent(workspace.id, MutationType.RESTORE, ("renamed.py",))
    )
    restored_result = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="restored_name")
    )
    assert [item.name for item in restored_result.symbols] == ["restored_name"]

    (tmp_path / "renamed.py").write_text(
        "def rolled_back_name(): pass\n", encoding="utf-8"
    )
    service.mark_dirty(MutationEvent(workspace.id, MutationType.ROLLBACK))
    rollback_result = _query(
        service, _request(workspace, RepoQueryKind.SYMBOLS, query="rolled_back_name")
    )
    metrics = service.metrics_snapshot()
    assert [item.name for item in rollback_result.symbols] == ["rolled_back_name"]
    assert metrics.incremental_refresh_count >= 3
    assert metrics.full_index_count == 3


def test_dependency_mutation_re_resolves_reverse_dependents(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("def target(): pass\n", encoding="utf-8")
    (tmp_path / "b.py").write_text(
        "from a import target\n"
        "def caller():\n"
        "    return target()\n",
        encoding="utf-8",
    )
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))
    initial = _query(
        service, _request(workspace, RepoQueryKind.IMPORTS, path="b.py")
    )
    assert initial.relations[0].status == "resolved"

    (tmp_path / "a.py").write_text("def replacement(): pass\n", encoding="utf-8")
    service.mark_dirty(MutationEvent(workspace.id, MutationType.UPDATE, ("a.py",)))
    updated = _query(
        service, _request(workspace, RepoQueryKind.IMPORTS, path="b.py")
    )

    assert updated.relations
    assert updated.relations[0].status != "resolved"
    assert updated.relations[0].target_symbol_id is None
    assert service.metrics_snapshot().incremental_refresh_count == 1


def test_context_recaptures_after_source_race(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = tmp_path / "app.py"
    source.write_text("def run(): return 'old'\n", encoding="utf-8")
    workspace = _workspace(tmp_path, "ws-1")
    service = RepoIntelligenceService(_WorkspaceManager(workspace))
    _query(service, _request(workspace, RepoQueryKind.SYMBOLS, query="run"))

    from khaos.coding.workspace.boundary import SafeWorkspaceFS

    original_read_bytes = SafeWorkspaceFS.read_bytes
    changed = False

    def mutate_after_capture(filesystem, target, *, max_bytes=65536):
        nonlocal changed
        raw = original_read_bytes(filesystem, target, max_bytes=max_bytes)
        if not changed:
            changed = True
            source.write_text("def run(): return 'new'\n", encoding="utf-8")
        return raw

    monkeypatch.setattr(SafeWorkspaceFS, "read_bytes", mutate_after_capture)
    result = asyncio.run(
        service.select_context(
            RepoContextRequest(
                workspace_id=workspace.id,
                task_id=workspace.task_id,
                principal_id=workspace.principal_id,
                project_id=workspace.project_id,
                query="run",
                target_files=("app.py",),
                max_files=1,
            )
        )
    )

    assert changed is True
    assert result.freshness is IntelligenceFreshness.CURRENT
    assert result.files[0].content == "def run(): return 'new'\n"
    assert service.metrics_snapshot().incremental_refresh_count == 1
