import pytest

from khaos.coding.workspace.apply import OutputMode


def test_output_modes_are_explicit_and_safe_by_default():
    assert OutputMode.COMMIT_IN_WORKTREE.value == "commit-in-worktree"
    assert OutputMode.APPLY_TO_CURRENT_BRANCH.value == "apply-to-current-branch"
