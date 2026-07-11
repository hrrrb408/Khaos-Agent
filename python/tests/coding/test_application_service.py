import pytest

from khaos.agent.approval import ApprovalBroker
from khaos.coding.workspace.application import ChangeSetApplicationService
from khaos.coding.workspace.apply import OutputMode
from khaos.coding.workspace.models import ChangeSet


@pytest.mark.asyncio
async def test_changeset_application_rejects_replay():
    from unittest.mock import AsyncMock, MagicMock
    manager = MagicMock()
    workspace = MagicMock(task_id="task", state="ready")
    workspace.id = "w"
    workspace.worktree_path = MagicMock()
    workspace.base_sha = "b"
    manager.get.return_value = workspace
    manager._git = AsyncMock(side_effect=lambda _root, *args, **_kwargs: "patch" if args[0] == "diff" else "head")
    change = ChangeSet.create(id="c", workspace_id="w", base_sha="b", head_sha=None, patch="patch", diff_stat="", changed_files=())
    service = ChangeSetApplicationService(manager, ApprovalBroker())
    key = await service.request_approval(task_id="task", workspace_id="w", changeset=change, operation=OutputMode.PATCH_ONLY, requester="session", expiry=10**12)
    await service.approval_broker.approve_operation(key, "session")
    # Patch-only needs no repository and proves the one-shot binding.
    assert await service.apply(task_id="task", workspace_id="w", changeset=change, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=10**12, requester="session") == "patch"
    with pytest.raises(PermissionError):
        await service.apply(task_id="task", workspace_id="w", changeset=change, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=10**12, requester="session")
