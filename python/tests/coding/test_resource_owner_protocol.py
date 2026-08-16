"""Shared ResourceOwner proof-surface tests."""

from __future__ import annotations

import pytest
from khaos.coding.execution.resource_owner import (
    ResourceOwnerInvariantError,
    inspect_resource_owner,
    require_terminal_resource_owner,
)


class _Owner:
    generation_admission_closed = True
    child_admission_closed = True
    terminal_closed = True
    is_quarantined = False

    def __init__(self, resources: tuple[str, ...] = ()) -> None:
        self.resources = resources
        self.proof = True

    def owned_resources(self) -> tuple[str, ...]:
        return self.resources

    def terminal_postcondition(self) -> bool:
        return self.proof


def test_shared_owner_snapshot_requires_empty_terminal_oracle() -> None:
    owner = _Owner()
    snapshot = inspect_resource_owner(owner)
    assert snapshot is not None
    assert snapshot.is_terminal
    assert require_terminal_resource_owner(owner) == snapshot

    owner.resources = ("process:42",)
    snapshot = inspect_resource_owner(owner)
    assert snapshot is not None
    assert not snapshot.is_terminal
    with pytest.raises(ResourceOwnerInvariantError, match="not terminal"):
        require_terminal_resource_owner(owner)


def test_quarantined_or_unreadable_owner_fails_closed() -> None:
    owner = _Owner()
    owner.is_quarantined = True
    assert inspect_resource_owner(owner) is not None
    with pytest.raises(ResourceOwnerInvariantError):
        require_terminal_resource_owner(owner)

    class _PartialOwner:
        terminal_closed = True
        is_quarantined = False

        def owned_resources(self) -> tuple[str, ...]:
            return ()

        def terminal_postcondition(self) -> bool:
            return True

    assert inspect_resource_owner(_PartialOwner()) is None
