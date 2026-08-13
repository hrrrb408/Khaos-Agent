"""Platform identity admission gates."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from khaos.security.identity_isolation import (
    AuthorityIdentityContract,
    IdentityIsolationError,
    require_distinct_linux_identities,
    validate_private_unix_socket,
)


def test_linux_identities_must_be_distinct() -> None:
    with pytest.raises(IdentityIsolationError):
        require_distinct_linux_identities(agent_uid=1000, authority_uid=1000, job_uid=1001)


def test_production_macos_contract_requires_native_handles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "darwin")
    contract = AuthorityIdentityContract(501, 502, 503)
    with pytest.raises(IdentityIsolationError, match="launchd_service"):
        contract.validate(production=True)


def test_private_socket_rejects_non_socket(tmp_path: Path) -> None:
    path = tmp_path / "not-a-socket"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(IdentityIsolationError):
        validate_private_unix_socket(path, expected_uid=os.getuid())
