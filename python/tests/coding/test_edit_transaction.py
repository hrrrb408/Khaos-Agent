"""M8.2 edit transaction contracts and storage-boundary regressions."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
from pathlib import Path

import khaos.coding.edit_transaction as edit_transaction_module
import pytest
from khaos.coding.edit_transaction import (
    EditOperation,
    EditTransaction,
    EditTransactionApplyError,
    EditTransactionError,
    EditTransactionPreconditionError,
    EditTransactionService,
    EditTransactionStaleError,
    TextEdit,
)
from khaos.coding.planning.contracts import PlanOperation
from khaos.coding.planning.tool_router import PlanToolRouter
from khaos.coding.planning.tool_routing import relative_resource_targets
from khaos.coding.workspace.boundary import SafeWorkspaceFS
from khaos.coding.workspace.manager import WorkspaceManager
from khaos.coding.workspace.models import TaskWorkspace, WorkspaceState
from khaos.coding.workspace.storage import (
    WorkspaceStorageLimits,
    WorkspaceStorageViolation,
    capture_workspace_snapshot,
)
from khaos.permissions.resource import (
    AuthorizationResource,
    AuthorizationResourceKind,
    resolve_edit_transaction,
)
from khaos.runtime_profile import RuntimeProfile
from khaos.tools.registry import PlanToolRole

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="TaskWorkspace dirfd edit transactions are POSIX-only",
)


def _digest(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def _manager_for(root: Path, *, byte_limit: int = 512 * 1024 * 1024):
    limits = WorkspaceStorageLimits(byte_limit, 100_000)
    root_info = root.stat()
    manager = WorkspaceManager(
        root=root.parent / "managed-worktrees",
        storage_limits=limits,
        runtime_profile=RuntimeProfile.TESTING,
    )
    workspace = TaskWorkspace(
        id="workspace",
        task_id="task",
        repository_root=root.parent,
        worktree_path=root,
        base_ref="HEAD",
        base_sha="base",
        branch_name="task/edit-transaction",
        state=WorkspaceState.READY,
        writable_roots=(root,),
        storage_baseline=capture_workspace_snapshot(root),
        storage_limits=limits,
        root_device=root_info.st_dev,
        root_inode=root_info.st_ino,
    )
    manager._workspaces[workspace.id] = workspace
    manager._task_ids.add(workspace.task_id)
    return manager, workspace


def _operation(
    kind: str,
    path: str,
    *,
    expected: str | None = None,
    content: str | None = None,
    expected_exists: bool | None = True,
    destination: str | None = None,
) -> EditOperation:
    return EditOperation(
        operation=kind,
        path=path,
        expected_exists=expected_exists,
        expected_digest=expected,
        content=content,
        destination_path=destination,
    )


@pytest.mark.asyncio
async def test_typed_transaction_is_immutable_and_digest_bound(tmp_path: Path):
    transaction = EditTransaction(
        "transaction-1",
        "workspace",
        1,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old"),
                content="new",
            ),
        ),
    )

    assert transaction.transaction_digest == transaction.transaction_digest
    assert transaction.transaction_digest != EditTransaction(
        "transaction-1",
        "workspace",
        2,
        transaction.operations,
    ).transaction_digest
    with pytest.raises((AttributeError, TypeError)):
        transaction.base_generation = 2  # type: ignore[misc]
    with pytest.raises(EditTransactionError):
        EditTransaction(
            "transaction-2",
            "workspace",
            1,
            (
                _operation(
                    "update",
                    "app.py",
                    expected=_digest("old"),
                    content="new",
                ),
                _operation(
                    "delete",
                    "APP.PY",
                    expected=_digest("old"),
                ),
            ),
        )


@pytest.mark.asyncio
async def test_preview_is_deterministic_and_does_not_write(tmp_path: Path):
    (tmp_path / "app.py").write_text("alpha\nbeta\n", encoding="utf-8")
    (tmp_path / "old.txt").write_text("legacy\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "preview-1",
        workspace.id,
        workspace.generation,
        (
            EditOperation(
                "update",
                "app.py",
                expected_exists=True,
                expected_digest=_digest("alpha\nbeta\n"),
                text_edits=(TextEdit(6, 10, "gamma"),),
            ),
            EditOperation(
                "rename",
                "old.txt",
                expected_exists=True,
                expected_digest=_digest("legacy\n"),
                destination_path="new.txt",
            ),
        ),
    )
    service = EditTransactionService()

    first = await service.preview(
        transaction,
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )
    second = await service.preview(
        transaction,
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )

    assert first.to_payload() == second.to_payload()
    assert "alpha" in first.operations[0].diff
    assert "gamma" in first.operations[0].diff
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "alpha\nbeta\n"
    assert (tmp_path / "old.txt").exists()
    assert not (tmp_path / "new.txt").exists()
    assert workspace.generation == 1


@pytest.mark.asyncio
async def test_preview_serializes_with_workspace_mutations(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "preview-serialized",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="new\n",
            ),
        ),
    )

    async with manager.workspace_storage_scope(workspace.id, workspace.task_id):
        pending = asyncio.create_task(
            EditTransactionService().preview(
                transaction,
                workspace_manager=manager,
                task_id=workspace.task_id,
                workspace_id=workspace.id,
            )
        )
        await asyncio.sleep(0.01)
        assert not pending.done()

    preview = await pending
    assert preview.base_generation == 1
    assert target.read_text(encoding="utf-8") == "old\n"


@pytest.mark.asyncio
async def test_preview_rechecks_generation_after_waiting_for_storage_lock(
    tmp_path: Path,
):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "preview-stale-after-wait",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="new\n",
            ),
        ),
    )

    async with manager.workspace_storage_scope(workspace.id, workspace.task_id):
        pending = asyncio.create_task(
            EditTransactionService().preview(
                transaction,
                workspace_manager=manager,
                task_id=workspace.task_id,
                workspace_id=workspace.id,
            )
        )
        await asyncio.sleep(0.01)
        workspace.generation += 1

    with pytest.raises(EditTransactionStaleError):
        await pending
    assert target.read_text(encoding="utf-8") == "old\n"


@pytest.mark.asyncio
async def test_apply_supports_all_operations_and_advances_generation(tmp_path: Path):
    (tmp_path / "app.py").write_text("old\n", encoding="utf-8")
    (tmp_path / "remove.txt").write_text("remove\n", encoding="utf-8")
    (tmp_path / "move.txt").write_text("move\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "apply-1",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="new\n",
            ),
            _operation(
                "delete",
                "remove.txt",
                expected=_digest("remove\n"),
            ),
            _operation(
                "create",
                "created.txt",
                expected_exists=False,
                content="created\n",
            ),
            _operation(
                "rename",
                "move.txt",
                expected=_digest("move\n"),
                destination="moved.txt",
            ),
        ),
    )

    result = await EditTransactionService().apply(
        transaction,
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )

    assert result.resulting_generation == 2
    assert workspace.generation == 2
    assert (tmp_path / "app.py").read_text(encoding="utf-8") == "new\n"
    assert (tmp_path / "created.txt").read_text(encoding="utf-8") == "created\n"
    assert (tmp_path / "moved.txt").read_text(encoding="utf-8") == "move\n"
    assert not (tmp_path / "remove.txt").exists()
    assert not (tmp_path / "move.txt").exists()
    assert len(result.operations) == 4
    assert not list(manager.file_recovery_root(workspace.id).iterdir())


@pytest.mark.asyncio
async def test_stale_generation_is_refused_before_any_write(tmp_path: Path):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    service = EditTransactionService()
    first = EditTransaction(
        "stale-1",
        workspace.id,
        1,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="first\n",
            ),
        ),
    )
    await service.apply(
        first,
        workspace_manager=manager,
        task_id=workspace.task_id,
        workspace_id=workspace.id,
    )
    stale = EditTransaction(
        "stale-2",
        workspace.id,
        1,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="second\n",
            ),
        ),
    )

    with pytest.raises(EditTransactionStaleError):
        await service.apply(
            stale,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )
    assert target.read_text(encoding="utf-8") == "first\n"
    assert workspace.generation == 2


@pytest.mark.asyncio
async def test_same_generation_transactions_have_one_winner(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    service = EditTransactionService()
    transactions = (
        EditTransaction(
            "concurrent-a",
            workspace.id,
            workspace.generation,
            (_operation("update", "a.txt", expected=_digest("a\n"), content="A\n"),),
        ),
        EditTransaction(
            "concurrent-b",
            workspace.id,
            workspace.generation,
            (_operation("update", "b.txt", expected=_digest("b\n"), content="B\n"),),
        ),
    )

    outcomes = await asyncio.gather(
        *(
            service.apply(
                transaction,
                workspace_manager=manager,
                task_id=workspace.task_id,
                workspace_id=workspace.id,
            )
            for transaction in transactions
        ),
        return_exceptions=True,
    )

    assert sum(not isinstance(outcome, Exception) for outcome in outcomes) == 1
    assert sum(isinstance(outcome, EditTransactionStaleError) for outcome in outcomes) == 1
    assert workspace.generation == 2
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") in {"a\n", "A\n"}
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") in {"b\n", "B\n"}
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") != "A\n" or (
        (tmp_path / "b.txt").read_text(encoding="utf-8") == "b\n"
    )
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") != "B\n" or (
        (tmp_path / "a.txt").read_text(encoding="utf-8") == "a\n"
    )


@pytest.mark.asyncio
async def test_preconditions_are_checked_for_every_file_before_publish(tmp_path: Path):
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "precondition-1",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "a.txt",
                expected="0" * 64,
                content="changed-a\n",
            ),
            _operation(
                "update",
                "b.txt",
                expected=_digest("b\n"),
                content="changed-b\n",
            ),
        ),
    )

    with pytest.raises(EditTransactionPreconditionError):
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )
    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "a\n"
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") == "b\n"
    assert workspace.generation == 1


@pytest.mark.asyncio
async def test_mid_transaction_failure_rolls_back_deleted_file(tmp_path: Path, monkeypatch):
    (tmp_path / "delete.txt").write_text("delete\n", encoding="utf-8")
    (tmp_path / "update.txt").write_text("update\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "rollback-1",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "delete",
                "delete.txt",
                expected=_digest("delete\n"),
            ),
            _operation(
                "update",
                "update.txt",
                expected=_digest("update\n"),
                content="changed\n",
            ),
        ),
    )
    original_write_bytes = SafeWorkspaceFS.write_bytes

    def fail_update(self, path, content, **kwargs):
        if str(path) == "update.txt":
            raise OSError("injected second-operation failure")
        return original_write_bytes(self, path, content, **kwargs)

    monkeypatch.setattr(SafeWorkspaceFS, "write_bytes", fail_update)
    with pytest.raises(EditTransactionApplyError):
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert (tmp_path / "delete.txt").read_text(encoding="utf-8") == "delete\n"
    assert (tmp_path / "update.txt").read_text(encoding="utf-8") == "update\n"
    assert workspace.generation == 1
    assert not list(manager.file_recovery_root(workspace.id).iterdir())


@pytest.mark.asyncio
async def test_failure_after_second_publish_rolls_back_before_third_operation(
    tmp_path: Path,
    monkeypatch,
):
    (tmp_path / "a.txt").write_text("a\n", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "rollback-after-second-publish",
        workspace.id,
        workspace.generation,
        (
            _operation("update", "a.txt", expected=_digest("a\n"), content="A\n"),
            _operation("update", "b.txt", expected=_digest("b\n"), content="B\n"),
            _operation("create", "c.txt", expected_exists=False, content="C\n"),
        ),
    )
    original_write_bytes = SafeWorkspaceFS.write_bytes

    def fail_after_second_publish(self, path, content, **kwargs):
        original_write_bytes(self, path, content, **kwargs)
        if str(path) == "b.txt":
            raise OSError("injected failure before third operation")

    monkeypatch.setattr(SafeWorkspaceFS, "write_bytes", fail_after_second_publish)
    with pytest.raises(EditTransactionApplyError):
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert (tmp_path / "a.txt").read_text(encoding="utf-8") == "a\n"
    assert (tmp_path / "b.txt").read_text(encoding="utf-8") == "b\n"
    assert not (tmp_path / "c.txt").exists()
    assert workspace.generation == 1
    assert not list(manager.file_recovery_root(workspace.id).iterdir())


@pytest.mark.asyncio
async def test_post_publish_failure_is_recorded_for_rollback(
    tmp_path: Path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "rollback-post-publish-1",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="new\n",
            ),
        ),
    )
    original_write_bytes = SafeWorkspaceFS.write_bytes

    def fail_after_publish(self, path, content, **kwargs):
        original_write_bytes(self, path, content, **kwargs)
        raise OSError("injected post-publish failure")

    monkeypatch.setattr(SafeWorkspaceFS, "write_bytes", fail_after_publish)
    with pytest.raises(EditTransactionApplyError):
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert target.read_text(encoding="utf-8") == "old\n"
    assert workspace.generation == 1
    assert not list(manager.file_recovery_root(workspace.id).iterdir())


@pytest.mark.asyncio
async def test_post_publish_external_content_drift_quarantines_without_rollback(
    tmp_path: Path,
    monkeypatch,
):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "rollback-external-drift",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "update",
                "app.py",
                expected=_digest("old\n"),
                content="new\n",
            ),
        ),
    )
    original_write_bytes = SafeWorkspaceFS.write_bytes

    def fail_after_external_write(self, path, content, **kwargs):
        original_write_bytes(self, path, content, **kwargs)
        if str(path) == "app.py":
            target.write_text("external\n", encoding="utf-8")
            raise OSError("injected post-publish external drift")

    monkeypatch.setattr(SafeWorkspaceFS, "write_bytes", fail_after_external_write)
    with pytest.raises(WorkspaceStorageViolation) as caught:
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert caught.value.quarantine_required is True
    assert workspace.state is WorkspaceState.FAILED
    assert target.read_text(encoding="utf-8") == "external\n"
    assert workspace.generation == 1


@pytest.mark.asyncio
async def test_final_live_drift_is_not_reported_as_success(tmp_path: Path, monkeypatch):
    target = tmp_path / "app.py"
    target.write_text("old\n", encoding="utf-8")
    manager, workspace = _manager_for(tmp_path)
    transaction = EditTransaction(
        "final-live-drift",
        workspace.id,
        workspace.generation,
        (_operation("update", "app.py", expected=_digest("old\n"), content="new\n"),),
    )
    original_snapshot = edit_transaction_module._snapshot
    injected = False

    def drift_after_publish(filesystem, path, **kwargs):
        nonlocal injected
        snapshot = original_snapshot(filesystem, path, **kwargs)
        if (
            not injected
            and path == "app.py"
            and snapshot.exists
            and snapshot.digest == _digest("new\n")
        ):
            injected = True
            target.write_text("external\n", encoding="utf-8")
        return snapshot

    monkeypatch.setattr(edit_transaction_module, "_snapshot", drift_after_publish)
    with pytest.raises(WorkspaceStorageViolation) as caught:
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert caught.value.quarantine_required is True
    assert workspace.state is WorkspaceState.FAILED
    assert target.read_text(encoding="utf-8") == "external\n"
    assert workspace.generation == 1


@pytest.mark.asyncio
async def test_storage_overage_uses_existing_authority_rollback(tmp_path: Path):
    manager, workspace = _manager_for(tmp_path, byte_limit=1)
    transaction = EditTransaction(
        "quota-1",
        workspace.id,
        workspace.generation,
        (
            _operation(
                "create",
                "too-large.txt",
                expected_exists=False,
                content="x" * 8192,
            ),
        ),
    )

    with pytest.raises(WorkspaceStorageViolation) as caught:
        await EditTransactionService().apply(
            transaction,
            workspace_manager=manager,
            task_id=workspace.task_id,
            workspace_id=workspace.id,
        )

    assert caught.value.rollback_succeeded is True
    assert caught.value.quarantine_required is False
    assert not (tmp_path / "too-large.txt").exists()
    assert workspace.generation == 1


def test_transaction_resource_exposes_all_workspace_relative_targets(tmp_path: Path):
    resource = AuthorizationResource(
        kind=AuthorizationResourceKind.WORKSPACE,
        principal_id="owner",
        project_id="project",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        canonical_target=json.dumps(
            {
                "operations": [
                    {"path": str(tmp_path / "src/a.py")},
                    {
                        "path": str(tmp_path / "old.py"),
                        "destination_path": str(tmp_path / "new.py"),
                    },
                ]
            },
            separators=(",", ":"),
        ),
        root_device=1,
        root_inode=2,
        workspace_root=str(tmp_path),
    )

    assert relative_resource_targets(resource) == (
        "src/a.py",
        "old.py",
        "new.py",
    )


def test_transaction_resource_binds_payload_digest_without_disclosing_content(
    tmp_path: Path,
):
    arguments = {
        "transaction_id": "resource-1",
        "base_generation": 1,
        "operations": [
            {
                "operation": "update",
                "path": "src/a.py",
                "expected_exists": True,
                "expected_digest": "a" * 64,
                "content": "secret-one",
                "text_edits": [],
            }
        ],
    }
    first, kind = resolve_edit_transaction("apply_edit_transaction", arguments, tmp_path)
    arguments["operations"][0]["content"] = "secret-two"
    second, _ = resolve_edit_transaction("apply_edit_transaction", arguments, tmp_path)

    assert kind is AuthorizationResourceKind.WORKSPACE
    assert first != second
    assert "secret-one" not in first
    assert "secret-two" not in second


def test_transaction_resource_rejects_malformed_text_edits(tmp_path: Path):
    with pytest.raises(PermissionError):
        resolve_edit_transaction(
            "apply_edit_transaction",
            {
                "transaction_id": "resource-invalid-1",
                "base_generation": 1,
                "operations": [
                    {
                        "operation": "update",
                        "path": "src/a.py",
                        "expected_exists": True,
                        "expected_digest": "a" * 64,
                        "text_edits": [
                            {"start": 4, "end": 2, "replacement": "x"}
                        ],
                    }
                ],
            },
            tmp_path,
        )


@pytest.mark.parametrize(
    "operation",
    [
        PlanOperation.MODIFY,
        PlanOperation.DOCUMENT,
        PlanOperation.CONFIGURE,
        PlanOperation.CREATE,
        PlanOperation.DELETE,
        PlanOperation.RENAME,
    ],
)
def test_transaction_plan_role_matches_one_atomic_workspace_step(
    tmp_path: Path,
    operation: PlanOperation,
):
    resource = AuthorizationResource(
        kind=AuthorizationResourceKind.WORKSPACE,
        principal_id="owner",
        project_id="project",
        task_id="task",
        workspace_id="workspace",
        workspace_generation=1,
        canonical_target=json.dumps(
            {
                "operations": [
                    {
                        "path": str(tmp_path / "old.py"),
                        "destination_path": str(tmp_path / "new.py"),
                    }
                ]
            },
            separators=(",", ":"),
        ),
        root_device=1,
        root_inode=2,
        workspace_root=str(tmp_path),
    )
    step = type(
        "Step",
        (),
        {"operation": operation, "target_files": ("old.py", "new.py")},
    )()
    tool = type("Tool", (), {"plan_tool_role": PlanToolRole.FILE_TRANSACTION})()

    assert PlanToolRouter._matching_steps((step,), tool, {}, resource) == [step]
