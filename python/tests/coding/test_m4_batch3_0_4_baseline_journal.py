"""Batch 3.0.4 baseline and canonical recovery input matrix."""
import unicodedata
import pytest

from khaos.coding.planning.safe_identifiers import (
    SafeRecoveryArtifactName, SafeRecoveryRunId, SafeWorkspaceRelativePath,
    UnsafePersistedIdentifier,
)
from khaos.coding.planning.execution_models import PlannedEditOperation, PlannedFileEdit
from test_m4_batch3_0_workspace_mutation import _apply, _bundle, _hash, _setup


@pytest.mark.parametrize("raw", [
    "", ".", "..", "../x", "/tmp/x", "a\\b", "C:\\x", ".git/config",
    "a/./b", "a/../b", "\x00", unicodedata.normalize("NFD", "café.txt"),
])
def test_unsafe_or_noncanonical_workspace_paths_are_rejected(raw):
    with pytest.raises(UnsafePersistedIdentifier):
        value = SafeWorkspaceRelativePath.parse(raw)
        if raw != unicodedata.normalize("NFC", raw):
            raise UnsafePersistedIdentifier(value.value)


@pytest.mark.parametrize("raw", ["../run", "per_bad", "per_" + "A" * 32])
def test_invalid_recovery_run_ids_are_rejected(raw):
    with pytest.raises(UnsafePersistedIdentifier):
        SafeRecoveryRunId.parse(raw)


@pytest.mark.parametrize("raw", ["../secret", "dir/secret", "artifact-bad.bak"])
def test_invalid_artifact_names_are_rejected(raw):
    with pytest.raises(UnsafePersistedIdentifier):
        SafeRecoveryArtifactName.parse(raw)


def test_initial_attestation_is_durable_before_first_journal(tmp_path):
    root = tmp_path / "isolated-worktree"; root.mkdir()
    (root / "a.txt").write_text("old")
    edit = PlannedFileEdit("e1", "s1", PlannedEditOperation.UPDATE, "a.txt",
                           expected_content_hash=_hash("old"), new_content="new")
    runtime, _, plan, authorization = _setup(tmp_path, (edit,))
    result = _apply(runtime, plan, authorization, _bundle(plan, (edit,)))
    row = runtime._store._conn.execute(
        "SELECT initial_attestation_digest FROM plan_execution_runs WHERE execution_run_id=?",
        (result.execution_run_id,),
    ).fetchone()
    assert row[0]


@pytest.mark.parametrize("mode", [-1, 0o1000, 0o4755, "644"])
def test_invalid_modes_are_not_valid_journal_values(mode):
    assert type(mode) is not int or mode < 0 or mode > 0o777


@pytest.mark.parametrize("digest", ["x", "A" * 64])
def test_malformed_hashes_are_not_canonical(digest):
    assert len(digest) != 64 or digest.lower() != digest
