from pathlib import Path

from khaos.security import production_composition_probe
from khaos.security.identity_isolation import IdentityIsolationError


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
    assert request.permission_profile is not None
    assert request.permission_profile.validate_resolved() is None


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
