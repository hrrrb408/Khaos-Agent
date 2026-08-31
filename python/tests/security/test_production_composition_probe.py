from pathlib import Path

import pytest
from khaos.security import production_composition_probe
from khaos.security.identity_isolation import IdentityIsolationError


def test_failure_detail_is_bounded_and_names_the_real_exception() -> None:
    detail = production_composition_probe._failure_detail(
        PermissionError("  delegated cgroup v2 limits unavailable: " + "x" * 600)
    )

    assert detail.startswith("PermissionError: delegated cgroup v2 limits unavailable:")
    assert len(detail) <= production_composition_probe._FAILURE_DETAIL_LIMIT + len(
        "PermissionError: "
    )
    assert detail.endswith("...")


def test_mapping_contains_expected_namespace_and_host_ids() -> None:
    mapping = "0 65534 1\n10004 10001 1\n"

    assert production_composition_probe._mapping_contains_pair(mapping, 10004, 10001)
    assert not production_composition_probe._mapping_contains_pair(mapping, 10003, 10001)
    assert not production_composition_probe._mapping_contains_pair(mapping, 10004, 10003)


def test_probe_request_binds_immutable_execution_authority(tmp_path: Path) -> None:
    request = production_composition_probe._probe_request(
        command=("/bin/sh", "-c", "printf exact"),
        workspace=tmp_path,
        policy_digest="policy-digest",
    )

    assert request.execution_authority is not None
    assert request.execution_authority.is_valid()
    assert request.execution_authority.spawn_plan.principal_kind == "automation"
    assert request.execution_authority.spawn_plan.parent_principal_id == (
        "automation:compose-security-e2e"
    )
    assert len(request.execution_authority.spawn_plan.delegation_digest) == 64
    assert request.permission_profile is not None
    assert request.permission_profile.validate_resolved() is None


def test_production_probe_uses_the_named_volume_for_io_limits() -> None:
    source = Path(
        production_composition_probe.__file__
    ).read_text(encoding="utf-8")

    assert 'workspace_parent = Path("/app/data")' in source
    assert 'dir=workspace_parent' in source


@pytest.mark.posix_host
def test_production_probes_share_a_safe_anchor_database_path(tmp_path: Path) -> None:
    database_path = production_composition_probe._composition_probe_database_path(tmp_path)

    assert database_path == tmp_path / ".khaos-production-probe" / "composition.db"
    assert database_path.parent.is_dir()
    assert database_path.parent.stat().st_mode & 0o777 == 0o700


def test_production_probe_rejects_a_symlinked_database_root(tmp_path: Path) -> None:
    probe_root = tmp_path / ".khaos-production-probe"
    probe_root.symlink_to(tmp_path / "elsewhere", target_is_directory=True)

    try:
        production_composition_probe._composition_probe_database_path(tmp_path)
    except SystemExit as exc:
        assert "not a real directory" in str(exc)
    else:
        raise AssertionError("symlinked production probe database root was accepted")


def test_production_composition_diagnostics_use_artifact_filename_stem() -> None:
    source = Path(
        production_composition_probe.__file__
    ).read_text(encoding="utf-8")

    assert "diagnostic_stem=output.stem" in source
    assert 'output_dir / f"{diagnostic_stem}.junit.xml"' in source


def test_lifecycle_producer_reuses_verified_production_workspace() -> None:
    from khaos.security import production_lifecycle_probe

    source = Path(production_lifecycle_probe.__file__).read_text(encoding="utf-8")
    assert "_verified_production_runtime(workspace_parent)" in source


def test_production_probes_bind_execution_services_to_verified_authority() -> None:
    composition_source = Path(
        production_composition_probe.__file__
    ).read_text(encoding="utf-8")
    from khaos.security import production_lifecycle_probe

    lifecycle_source = Path(
        production_lifecycle_probe.__file__
    ).read_text(encoding="utf-8")

    for source in (composition_source, lifecycle_source):
        assert "runtime_profile=RuntimeProfile.PRODUCTION" in source
        assert "authority_broker=authority_broker" in source


def test_production_producers_share_one_runtime_composition_digest_recipe() -> None:
    from khaos.security import production_lifecycle_probe

    manifest = {"schema": "runtime-manifest", "components": {"backend": "linux"}}
    assert production_composition_probe._runtime_composition_digest(manifest) == (
        production_lifecycle_probe._runtime_composition_digest(manifest)
    )


def test_production_probe_binds_and_restores_temp_root(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TMPDIR", "/tmp/original-khaos-probe-root")
    production_composition_probe.tempfile.tempdir = None

    with production_composition_probe._production_probe_temp_root(tmp_path):
        assert production_composition_probe.tempfile.gettempdir() == str(tmp_path)

    assert production_composition_probe.os.environ["TMPDIR"] == (
        "/tmp/original-khaos-probe-root"
    )


def test_identity_oracle_retries_transient_empty_namespace_maps(monkeypatch) -> None:
    attempts = 0
    expected = object()

    def fake_read(_pid: int) -> object:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise IdentityIsolationError("Linux process namespace maps are empty")
        return expected

    monkeypatch.setattr(
        production_composition_probe,
        "read_linux_process_identity",
        fake_read,
    )
    monkeypatch.setattr(production_composition_probe.time, "sleep", lambda _seconds: None)

    assert production_composition_probe._read_linux_process_identity_when_ready(123) is expected
    assert attempts == 3
