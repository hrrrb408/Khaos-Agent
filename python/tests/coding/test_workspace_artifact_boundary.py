"""Contract tests for bounded ChangeSet artifact ownership."""

import hashlib
import inspect

import khaos.coding.workspace.manager as workspace_manager_module
from khaos.coding.workspace.artifacts import (
    copy_verified_artifact,
    read_verified_artifact,
    write_exclusive_artifact,
)


def test_artifact_owner_round_trips_digest_bound_bytes(tmp_path) -> None:
    source = tmp_path / "source.patch"
    destination = tmp_path / "nested" / "copy.patch"
    exclusive = tmp_path / "exclusive.patch"
    payload = b"diff --git a/file b/file\n+safe\n"
    source.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    assert read_verified_artifact(source, len(payload), digest, 1024) == payload
    copy_verified_artifact(source, destination, len(payload), digest)
    write_exclusive_artifact(exclusive, payload)

    assert destination.read_bytes() == payload
    assert exclusive.read_bytes() == payload


def test_workspace_manager_does_not_redefine_artifact_io() -> None:
    source = inspect.getsource(workspace_manager_module)
    assert "def _read_verified_artifact(" not in source
    assert "def _write_exclusive_artifact(" not in source
    assert "def _copy_verified_artifact(" not in source
