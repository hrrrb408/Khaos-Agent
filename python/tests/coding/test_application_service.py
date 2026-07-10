import time

import pytest

from khaos.agent.approval import ApprovalBroker
from khaos.coding.workspace.application import ChangeSetApplicationService
from khaos.coding.workspace.apply import OutputMode
from khaos.coding.workspace.models import ChangeSet


@pytest.mark.asyncio
async def test_changeset_application_rejects_replay():
    from unittest.mock import MagicMock
    manager = MagicMock()
    workspace = MagicMock(task_id="task", state="ready")
    manager.get.return_value = workspace
    change = ChangeSet.create(id="c", workspace_id="w", base_sha="b", head_sha=None, patch="patch", diff_stat="", changed_files=())
    service = ChangeSetApplicationService(manager, ApprovalBroker())
    key = change.approval_key(OutputMode.PATCH_ONLY.value)
    # Patch-only needs no repository and proves the one-shot binding.
    assert await service.apply(task_id="task", workspace_id="w", changeset=change, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=time.time() + 10) == "patch"
    with pytest.raises(PermissionError):
        await service.apply(task_id="task", workspace_id="w", changeset=change, operation=OutputMode.PATCH_ONLY, approval_key=key, expiry=time.time() + 10)
