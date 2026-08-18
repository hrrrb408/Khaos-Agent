"""Platform identity admission gates."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.posix_host
from khaos.security.identity_isolation import (
    AuthorityIdentityContract,
    IdentityIsolationError,
    linux_job_namespace_args,
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


def test_linux_job_namespace_has_explicit_uid_mapping(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.delenv("KHAOS_JOB_UID", raising=False)
    assert linux_job_namespace_args() == (
        "--unshare-user",
        "--uid",
        "65534",
        "--gid",
        "65534",
        "--cap-drop",
        "ALL",
    )


def test_linux_production_job_identity_requires_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    monkeypatch.delenv("KHAOS_AGENT_UID", raising=False)
    monkeypatch.delenv("KHAOS_AUTHORITYD_UID", raising=False)
    monkeypatch.delenv("KHAOS_JOB_UID", raising=False)
    with pytest.raises(IdentityIsolationError, match="agent, authority, and job"):
        linux_job_namespace_args()


def test_linux_production_job_identity_is_distinct(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    monkeypatch.setenv("KHAOS_DEV_MODE", "0")
    monkeypatch.setenv("KHAOS_AGENT_UID", "10001")
    monkeypatch.setenv("KHAOS_AUTHORITYD_UID", "10003")
    monkeypatch.setenv("KHAOS_JOB_UID", "10004")
    monkeypatch.setattr(os, "geteuid", lambda: 10001)
    assert linux_job_namespace_args()[-6:] == (
        "--uid", "10004", "--gid", "10004", "--cap-drop", "ALL",
    )


def test_linux_job_namespace_args_drop_all_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """M5.6: bwrap construction includes --cap-drop ALL; the payload's
    zero-capability postcondition is verified by the Rust launcher."""
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    monkeypatch.setenv("KHAOS_DEV_MODE", "1")
    monkeypatch.delenv("KHAOS_JOB_UID", raising=False)
    args = linux_job_namespace_args()
    assert args[args.index("--cap-drop") + 1] == "ALL"


@pytest.mark.parametrize("mode", ["1", "0"])
def test_linux_job_uid_zero_is_forbidden(
    monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    monkeypatch.setenv("KHAOS_DEV_MODE", mode)
    if mode == "0":
        monkeypatch.setattr(
            "khaos.security.identity_isolation.os.geteuid", lambda: 10001
        )
        monkeypatch.setenv("KHAOS_AGENT_UID", "10001")
        monkeypatch.setenv("KHAOS_AUTHORITYD_UID", "10003")
    monkeypatch.setenv("KHAOS_JOB_UID", "0")
    with pytest.raises(IdentityIsolationError, match="UID 0 is forbidden"):
        linux_job_namespace_args()


def test_linux_production_contract_rejects_root_job_uid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("khaos.security.identity_isolation.sys_platform", lambda: "linux")
    contract = AuthorityIdentityContract(agent_uid=10001, authority_uid=10003, job_uid=0)
    with pytest.raises(IdentityIsolationError, match="non-root"):
        contract.validate(production=True)
