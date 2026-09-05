from types import SimpleNamespace

import pytest

from khaos.coding.workspace.boundary import WorkspaceBoundaryError
from khaos.coding.intelligence.repository import (
    RepoIntelligenceService,
    RepoIntelligenceUnavailableError,
)
from khaos.tools.code_search_tools import code_search, code_symbols
from khaos.tools.registry import create_runtime_registry


async def test_code_search_requires_active_task_workspace(tmp_path):
    with pytest.raises(PermissionError, match="active TaskWorkspace"):
        await code_search(str(tmp_path), "khaos")


async def test_code_symbols_requires_active_task_workspace(tmp_path):
    with pytest.raises(PermissionError, match="active TaskWorkspace"):
        await code_symbols(str(tmp_path / "app.py"))


@pytest.mark.posix_host
async def test_repo_code_symbols_normalizes_absolute_workspace_path(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("def run(): pass\n", encoding="utf-8")
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
        base_sha="base",
        git_identity=None,
        creator_runtime_id="runtime",
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)
    intelligence = RepoIntelligenceService(manager)

    result = await code_symbols(
        str(source),
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        principal_id=workspace.principal_id,
        project_id=workspace.project_id,
        repo_intelligence=intelligence,
    )

    assert result["path"] == str(source)
    assert result["symbols"][0]["name"] == "run"
    await intelligence.close()


@pytest.mark.parametrize(
    ("filename", "content", "language"),
    (
        ("main.py", "def run(): pass\n", "python"),
        ("main.go", "package main\nfunc Run() {}\n", "go"),
        ("main.rs", "fn run() {}\n", "rust"),
        ("main.ts", "export function run(): void {}\n", "typescript"),
    ),
)
@pytest.mark.posix_host
async def test_repo_code_symbols_uses_semantic_path_for_supported_languages(
    tmp_path, filename, content, language
):
    source = tmp_path / filename
    source.write_text(content, encoding="utf-8")
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
        base_sha="base",
        git_identity=None,
        creator_runtime_id="runtime",
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)
    intelligence = RepoIntelligenceService(manager)

    result = await code_symbols(
        str(source),
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        principal_id=workspace.principal_id,
        project_id=workspace.project_id,
        repo_intelligence=intelligence,
    )

    assert result["freshness"] == "current"
    assert result["semantic_support"] is True
    assert result["symbols"]
    assert result["symbols"][0]["language"] == language
    await intelligence.close()


@pytest.mark.posix_host
async def test_repo_code_search_honors_root_glob_and_language_scope(tmp_path):
    source_root = tmp_path / "src"
    other_root = tmp_path / "other"
    source_root.mkdir()
    other_root.mkdir()
    (source_root / "main.go").write_text(
        "package main\nfunc Run() {}\n", encoding="utf-8"
    )
    (source_root / "main.py").write_text("def Run(): pass\n", encoding="utf-8")
    (other_root / "main.go").write_text(
        "package other\nfunc Run() {}\n", encoding="utf-8"
    )
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
        base_sha="base",
        git_identity=None,
        creator_runtime_id="runtime",
    )
    manager = SimpleNamespace(
        get=lambda workspace_id: workspace if workspace_id == workspace.id else None
    )
    intelligence = RepoIntelligenceService(manager)

    result = await code_search(
        "src",
        "Run",
        glob="*.go",
        language="go",
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        principal_id=workspace.principal_id,
        project_id=workspace.project_id,
        repo_intelligence=intelligence,
    )

    assert result["count"] == 1
    assert result["matches"][0]["path"] == str(source_root / "main.go")
    assert result["semantic_support"] is True
    await intelligence.close()


async def test_coding_search_requires_the_runtime_shared_repository_service(tmp_path):
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)

    with pytest.raises(PermissionError, match="runtime repository intelligence"):
        await code_search(
            ".",
            "run",
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )
    with pytest.raises(PermissionError, match="runtime repository intelligence"):
        await code_symbols(
            "app.py",
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )


@pytest.mark.posix_host
async def test_code_search_exposes_bounded_fallback_when_semantic_index_is_unavailable(
    tmp_path,
):
    source = tmp_path / "app.py"
    source.write_text("FALLBACK_MARKER = True\n", encoding="utf-8")
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)
    intelligence = RepoIntelligenceService(manager)
    await intelligence.close()

    result = await code_search(
        ".",
        "FALLBACK_MARKER",
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        repo_intelligence=intelligence,
    )

    assert result["count"] == 1
    assert result["freshness"] == "unavailable"
    assert result["semantic_support"] is False
    assert result["lexical_fallback"] is True
    assert result["fallback_reason"] == "semantic_repository_unavailable"
    assert intelligence.metrics_snapshot().lexical_fallback_count == 1


@pytest.mark.posix_host
async def test_code_search_fails_closed_on_generation_contract_failure(
    tmp_path, monkeypatch
):
    source = tmp_path / "app.py"
    source.write_text("GENERATION_CORRUPTION_MARKER = True\n", encoding="utf-8")
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)
    intelligence = RepoIntelligenceService(manager)

    async def fail_closed(_request):
        raise RepoIntelligenceUnavailableError("generation integrity is corrupt")

    monkeypatch.setattr(intelligence, "query", fail_closed)
    with pytest.raises(RepoIntelligenceUnavailableError, match="generation integrity"):
        await code_search(
            ".",
            "GENERATION_CORRUPTION_MARKER",
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
            repo_intelligence=intelligence,
        )
    await intelligence.close()


@pytest.mark.posix_host
async def test_code_search_fallback_reports_depth_bound(tmp_path):
    nested = tmp_path
    for index in range(33):
        nested = nested / f"level-{index}"
        nested.mkdir()
    (nested / "deep.py").write_text("DEPTH_BOUND_MARKER = True\n", encoding="utf-8")
    workspace = SimpleNamespace(
        id="workspace",
        task_id="task",
        principal_id="principal",
        project_id="project",
        worktree_path=tmp_path,
    )
    manager = SimpleNamespace(get=lambda workspace_id: workspace if workspace_id == workspace.id else None)
    intelligence = RepoIntelligenceService(manager)
    await intelligence.close()

    result = await code_search(
        ".",
        "DEPTH_BOUND_MARKER",
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
        repo_intelligence=intelligence,
    )

    assert result["matches"] == []
    assert result["truncated"] is True
    assert "max_fallback_depth" in result["truncation_reasons"]


def test_runtime_registry_binds_code_search_tools():
    registry = create_runtime_registry()

    assert registry.get("code_search").handler is not None
    assert registry.get("code_symbols").permission_level == "read"


@pytest.mark.posix_host
async def test_coding_code_search_rejects_symlink_escape(tmp_path):
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir()
    (outside / "secret.py").write_text("SECRET = True\n", encoding="utf-8")
    (tmp_path / "leak.py").symlink_to(outside / "secret.py")
    (tmp_path / "safe.py").write_text("def visible(): pass\n", encoding="utf-8")
    workspace = SimpleNamespace(task_id="task", worktree_path=tmp_path)
    manager = SimpleNamespace(get=lambda _workspace_id: workspace)
    context = {"workspace_manager": manager, "task_id": "task", "workspace_id": "ws"}

    result = await code_search(".", "SECRET", **context)
    assert result["matches"] == []
    with pytest.raises(WorkspaceBoundaryError):
        await code_symbols("leak.py", **context)
