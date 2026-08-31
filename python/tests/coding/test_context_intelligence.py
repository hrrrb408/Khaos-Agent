"""M7.2 context contracts, freshness, and workspace-bound retrieval tests."""

from __future__ import annotations

import asyncio
import sys
import threading
from dataclasses import fields, replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from khaos.agent.control.goal import GoalSpec
from khaos.coding.intelligence.context import (
    ContextContractError,
    ContextEvidenceKind,
    ContextFreshness,
    ContextRequest,
    ContextTarget,
)
from khaos.coding.intelligence.query_service import (
    ContextInputError,
    ContextIntelligenceService,
    ContextUnavailableError,
)
from khaos.coding.intelligence.registry import LanguageRegistry


class _WorkspaceManager:
    def __init__(self, workspace: SimpleNamespace | None) -> None:
        self.workspace = workspace

    def get(self, workspace_id: str):
        if self.workspace is not None and self.workspace.id == workspace_id:
            return self.workspace
        return None

    def require(self, workspace_id: str, **_kwargs):
        return self.get(workspace_id)


def _workspace(root: Path, *, workspace_id: str = "ws-1") -> SimpleNamespace:
    return SimpleNamespace(
        id=workspace_id,
        task_id="task-1",
        principal_id="principal-1",
        project_id="project-1",
        worktree_path=root,
        base_sha="base-1",
        git_identity=None,
        creator_runtime_id="runtime-1",
    )


def _goal() -> GoalSpec:
    return GoalSpec.from_user_goal("修复 foo.py 中的审批问题", goal_spec_id="goal-1")


def _request(
    service: ContextIntelligenceService,
    workspace: SimpleNamespace,
    goal: GoalSpec,
    *,
    query: str = "foo.py",
    target_files: tuple[str, ...] = (),
    target_symbols: tuple[str, ...] = (),
    max_files: int = 16,
    max_symbols: int = 128,
    max_bytes: int = 256 * 1024,
    max_file_bytes: int = 64 * 1024,
) -> ContextRequest:
    return ContextRequest(
        task_id=workspace.task_id,
        principal_id=workspace.principal_id,
        project_id=workspace.project_id,
        goal_spec_id=goal.goal_spec_id,
        goal_spec_digest=goal.semantic_digest,
        workspace_id=workspace.id,
        repository_id=service.repository_id_for_workspace(workspace),
        base_revision=workspace.base_sha,
        query=query,
        target_files=target_files,
        target_symbols=target_symbols,
        runtime_id=workspace.creator_runtime_id,
        max_files=max_files,
        max_symbols=max_symbols,
        max_bytes=max_bytes,
        max_file_bytes=max_file_bytes,
    )


def _retrieve(service, request, goal):
    return asyncio.run(service.retrieve(request, goal))


def test_context_request_is_deeply_typed_and_immutable() -> None:
    target = ContextTarget(relative_path="src/foo.py", symbol="run")
    assert target.relative_path == "src/foo.py"
    with pytest.raises((AttributeError, TypeError)):
        target.relative_path = "other.py"  # type: ignore[misc]
    with pytest.raises(ContextContractError):
        ContextTarget(relative_path="../escape.py")
    with pytest.raises(ContextContractError):
        ContextRequest(
            task_id="t",
            principal_id="p",
            project_id="project",
            goal_spec_id="g",
            goal_spec_digest="0" * 64,
            workspace_id="w",
            repository_id="r",
            query="q",
            target_files=["foo.py"],  # type: ignore[arg-type]
        )

    semantic_fields = {
        field.name
        for contract in (ContextRequest, ContextTarget)
        for field in fields(contract)
    }
    assert "trusted" not in semantic_fields
    assert "authoritative" not in semantic_fields


def test_context_request_digest_is_unicode_safe_and_order_independent(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    first = _request(
        service,
        workspace,
        goal,
        query="中文审批 foo.py",
        target_files=("b.py", "a.py"),
    )
    second = _request(
        service,
        workspace,
        goal,
        query="中文审批 foo.py",
        target_files=("a.py", "b.py"),
    )
    assert first.request_digest == second.request_digest
    assert first.changed_files == ()


@pytest.mark.posix_host
def test_fresh_bundle_is_deterministic_and_rebuilds_after_mutation(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "foo.py").write_text("def approve():\n    return 'old'\n", encoding="utf-8")
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(service, workspace, goal, target_files=("foo.py",))

    first = _retrieve(service, request, goal)
    second = _retrieve(service, request, goal)
    assert first.freshness is ContextFreshness.FRESH
    assert first.bundle_digest == second.bundle_digest
    assert [item.relative_path for item in first.documents] == ["foo.py"]

    (root / "foo.py").write_text("def approve():\n    return 'new'\n", encoding="utf-8")
    service.invalidate(workspace.id, ("foo.py",))
    updated = _retrieve(service, request, goal)
    assert updated.freshness is ContextFreshness.FRESH
    assert "'new'" in updated.documents[0].content
    assert updated.bundle_digest != first.bundle_digest


def test_goal_and_repository_binding_mismatch_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(service, workspace, goal)

    with pytest.raises(ContextInputError):
        _retrieve(
            service,
            ContextRequest(
                task_id=request.task_id,
                principal_id=request.principal_id,
                project_id=request.project_id,
                goal_spec_id=request.goal_spec_id,
                goal_spec_digest="1" * 64,
                workspace_id=request.workspace_id,
                repository_id=request.repository_id,
                base_revision=request.base_revision,
                query=request.query,
                runtime_id=request.runtime_id,
            ),
            goal,
        )


def test_base_revision_binding_is_exact_and_not_wildcard(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(service, workspace, goal)

    service._validate_workspace_binding(request, workspace)

    with pytest.raises(ContextInputError):
        service._validate_workspace_binding(
            replace(request, base_revision="other", request_digest=""),
            workspace,
        )
    with pytest.raises(ContextInputError):
        service._validate_workspace_binding(
            replace(request, base_revision=None, request_digest=""),
            workspace,
        )

    unbound_workspace = _workspace(root, workspace_id="ws-without-base")
    unbound_workspace.base_sha = None
    unbound_request = _request(service, unbound_workspace, goal)
    service._validate_workspace_binding(unbound_request, unbound_workspace)

    with pytest.raises(ContextInputError):
        service._validate_workspace_binding(
            replace(unbound_request, base_revision="base-1", request_digest=""),
            unbound_workspace,
        )
    with pytest.raises(ContextInputError):
        _retrieve(
            service,
            ContextRequest(
                task_id=request.task_id,
                principal_id=request.principal_id,
                project_id=request.project_id,
                goal_spec_id=request.goal_spec_id,
                goal_spec_digest=request.goal_spec_digest,
                workspace_id=request.workspace_id,
                repository_id="wrong-repository",
                base_revision=request.base_revision,
                query=request.query,
                runtime_id=request.runtime_id,
            ),
            goal,
        )


@pytest.mark.posix_host
def test_deleted_and_renamed_files_are_not_served_from_cache(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    original = root / "foo.py"
    original.write_text("def old_name():\n    return 1\n", encoding="utf-8")
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request_old = _request(service, workspace, goal, target_files=("foo.py",))
    _retrieve(service, request_old, goal)

    original.rename(root / "bar.py")
    deleted_view = _retrieve(service, request_old, goal)
    assert all(item.relative_path != "foo.py" for item in deleted_view.documents)
    request_new = _request(service, workspace, goal, target_files=("bar.py",))
    renamed_view = _retrieve(service, request_new, goal)
    assert [item.relative_path for item in renamed_view.documents] == ["bar.py"]

    (root / "bar.py").unlink()
    removed_view = _retrieve(service, request_new, goal)
    assert all(item.relative_path != "bar.py" for item in removed_view.documents)


@pytest.mark.posix_host
def test_same_named_symbols_keep_distinct_generation_bound_identity(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    (root / "one").mkdir(parents=True)
    (root / "two").mkdir()
    (root / "one" / "module.py").write_text("def run():\n    return 1\n", encoding="utf-8")
    (root / "two" / "module.py").write_text("def run():\n    return 2\n", encoding="utf-8")
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(
        service,
        workspace,
        goal,
        query="run",
        target_symbols=("run",),
        max_files=2,
    )
    bundle = _retrieve(service, request, goal)
    runs = [symbol for symbol in bundle.symbols if symbol.qualified_name == "run"]
    assert {symbol.relative_path for symbol in runs} == {
        "one/module.py",
        "two/module.py",
    }
    assert len({symbol.symbol_id for symbol in runs}) == 2


@pytest.mark.posix_host
def test_parser_relationship_evidence_is_not_duplicated_for_simple_names(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "calls.py").write_text(
        "def target():\n    return 1\n\ndef caller():\n    return target()\n",
        encoding="utf-8",
    )
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(
        service,
        workspace,
        goal,
        query="target",
        target_symbols=("target",),
        target_files=("calls.py",),
    )

    bundle = _retrieve(service, request, goal)
    evidence_kinds = {
        evidence.kind
        for evidence in bundle.evidence
        if evidence.subject_path == "calls.py"
    }
    assert ContextEvidenceKind.CALLEE in evidence_kinds
    assert ContextEvidenceKind.CALLER in evidence_kinds


@pytest.mark.posix_host
def test_context_is_bounded_and_records_truncation(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    for index in range(4):
        (root / f"file-{index}.py").write_text(
            f"def function_{index}():\n    return '{index}'\n",
            encoding="utf-8",
        )
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(
        service,
        workspace,
        goal,
        query="function",
        max_files=1,
        max_symbols=1,
        max_bytes=10,
        max_file_bytes=10,
    )
    bundle = _retrieve(service, request, goal)
    assert bundle.truncated is True
    assert bundle.truncation_reasons
    assert len(bundle.documents) <= 1
    assert sum(len(document.content.encode("utf-8")) for document in bundle.documents) <= 10


def test_symlink_and_missing_workspace_never_fall_back_to_host(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("def secret():\n    return 'host'\n", encoding="utf-8")
    (root / "link.py").symlink_to(outside)
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(service, workspace, goal, target_files=("link.py",))
    with pytest.raises(ContextUnavailableError):
        _retrieve(service, request, goal)

    unavailable = ContextIntelligenceService(_WorkspaceManager(None))
    with pytest.raises(ContextUnavailableError):
        _retrieve(unavailable, request, goal)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows fail-closed contract")
def test_windows_context_retrieval_is_unavailable_without_host_fallback(
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "foo.py").write_text("VALUE = 'workspace'\n", encoding="utf-8")
    workspace = _workspace(root)
    service = ContextIntelligenceService(_WorkspaceManager(workspace))
    goal = _goal()
    request = _request(service, workspace, goal, target_files=("foo.py",))

    with pytest.raises(ContextUnavailableError, match="safe workspace context"):
        _retrieve(service, request, goal)


class _BlockingRegistry(LanguageRegistry):
    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()
        self._blocked_once = False

    def parse(self, *, file_path: str, content: bytes, previous_state=None):
        if not self._blocked_once:
            self._blocked_once = True
            self.started.set()
            assert self.release.wait(timeout=5)
        return super().parse(
            file_path=file_path,
            content=content,
            previous_state=previous_state,
        )


@pytest.mark.posix_host
def test_query_mutation_race_retries_without_stale_as_fresh(tmp_path: Path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    source = root / "foo.py"
    source.write_text("def value():\n    return 'old'\n", encoding="utf-8")
    workspace = _workspace(root)
    registry = _BlockingRegistry()
    service = ContextIntelligenceService(_WorkspaceManager(workspace), registry=registry)
    goal = _goal()
    request = _request(service, workspace, goal, target_files=("foo.py",))

    async def run_race():
        pending = asyncio.create_task(service.retrieve(request, goal))
        assert await asyncio.to_thread(registry.started.wait, 5)
        source.write_text("def value():\n    return 'new'\n", encoding="utf-8")
        registry.release.set()
        return await pending

    bundle = asyncio.run(run_race())
    assert bundle.freshness is ContextFreshness.FRESH
    assert "'new'" in bundle.documents[0].content


@pytest.mark.posix_host
def test_cache_is_workspace_scoped_and_restart_rebuild_is_deterministic(tmp_path: Path) -> None:
    root_a = tmp_path / "workspace-a"
    root_b = tmp_path / "workspace-b"
    root_a.mkdir()
    root_b.mkdir()
    (root_a / "foo.py").write_text("VALUE = 'A'\n", encoding="utf-8")
    (root_b / "foo.py").write_text("VALUE = 'B'\n", encoding="utf-8")
    workspace_a = _workspace(root_a, workspace_id="ws-a")
    workspace_b = _workspace(root_b, workspace_id="ws-b")
    workspace_b.task_id = "task-1"
    workspace_b.principal_id = "principal-1"
    workspace_b.project_id = "project-1"
    manager = _WorkspaceManager(workspace_a)
    service = ContextIntelligenceService(manager)
    goal = _goal()
    first = _retrieve(service, _request(service, workspace_a, goal, target_files=("foo.py",)), goal)

    manager.workspace = workspace_b
    second = _retrieve(service, _request(service, workspace_b, goal, target_files=("foo.py",)), goal)
    assert "'A'" in first.documents[0].content
    assert "'B'" in second.documents[0].content

    restarted = ContextIntelligenceService(manager)
    rebuilt = _retrieve(
        restarted,
        _request(restarted, workspace_b, goal, target_files=("foo.py",)),
        goal,
    )
    assert rebuilt.bundle_digest == second.bundle_digest
