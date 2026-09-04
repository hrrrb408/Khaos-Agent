"""Portability and test-hygiene contracts for the Trusted Git boundary."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from khaos.coding.workspace import trusted_git as trusted_git_module
from khaos.coding.workspace import trusted_git_preflight as preflight_module
from khaos.coding.workspace.trusted_git import TrustedGitError, TrustedGitRunner
from khaos.coding.workspace.trusted_git_locator import (
    PlatformTrustedGitLocator,
    StaticTrustedGitLocator,
    trusted_git_exec_path,
)
from khaos.coding.workspace.trusted_git_policy import (
    TrustedGitExecutablePolicy,
    TrustedGitExecutablePolicyError,
    digest_file,
)
from khaos.coding.workspace.trusted_git_preflight import (
    TrustedGitAvailability,
    TrustedGitPreflightResult,
    build_trusted_git_environment,
    classify_invocation_failure,
    diagnose_trusted_git,
    format_preflight_error,
)
from khaos.runtime_profile import RuntimeProfile
from khaos.security.authority_broker import AuthorityBroker


def _validated_candidate() -> Path:
    policy = TrustedGitExecutablePolicy()
    for candidate in PlatformTrustedGitLocator().candidates():
        try:
            return policy.validate(candidate).path
        except TrustedGitExecutablePolicyError:
            continue
    pytest.fail("the platform did not expose a policy-valid Trusted Git candidate")


def _local_policy() -> TrustedGitExecutablePolicy:
    owner_uid = getattr(os, "getuid", lambda: 0)()
    return TrustedGitExecutablePolicy(trusted_owner_uid=owner_uid)


def _local_executable(tmp_path: Path, name: str = "git") -> Path:
    candidate = tmp_path / name
    candidate.write_bytes(b"trusted fixture executable")
    candidate.chmod(0o755)
    return candidate


def test_locator_is_static_and_ignores_caller_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    attacker = tmp_path / "git"
    attacker.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    attacker.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    locator = PlatformTrustedGitLocator()
    candidates = locator.candidates()
    selected = _validated_candidate()
    canonical_candidates = {
        candidate.resolve(strict=True) for candidate in candidates
    }

    assert selected in canonical_candidates
    assert selected != attacker.resolve(strict=True)
    assert all("/opt/homebrew/bin" not in str(candidate) for candidate in candidates)
    assert all("/usr/local/bin" not in str(candidate) for candidate in candidates)


def test_untrusted_candidate_is_rejected_by_policy(tmp_path: Path) -> None:
    candidate = tmp_path / "git"
    candidate.write_bytes(b"attacker")
    candidate.chmod(0o755)

    with pytest.raises(TrustedGitExecutablePolicyError):
        TrustedGitExecutablePolicy().validate(candidate)


def test_policy_requires_absolute_regular_private_owned_file(tmp_path: Path) -> None:
    policy = _local_policy()
    candidate = _local_executable(tmp_path)

    with pytest.raises(TrustedGitExecutablePolicyError) as relative_error:
        policy.validate(Path("git"))
    assert relative_error.value.category == "candidate_not_found"

    directory = tmp_path / "directory-git"
    directory.mkdir()
    with pytest.raises(TrustedGitExecutablePolicyError):
        policy.validate(directory)

    candidate.chmod(0o775)
    with pytest.raises(TrustedGitExecutablePolicyError):
        policy.validate(candidate)

    candidate.chmod(0o755)
    with pytest.raises(TrustedGitExecutablePolicyError):
        TrustedGitExecutablePolicy(
            trusted_owner_uid=policy.trusted_owner_uid + 1
        ).validate(candidate)
    identity = policy.validate(candidate)
    assert identity.owner_uid == policy.trusted_owner_uid
    assert identity.mode & 0o022 == 0


def test_policy_rejects_writable_parent_and_symlinked_parent(tmp_path: Path) -> None:
    policy = _local_policy()
    parent = tmp_path / "parent"
    parent.mkdir()
    candidate = _local_executable(parent)

    parent.chmod(0o777)
    try:
        with pytest.raises(TrustedGitExecutablePolicyError):
            policy.validate(candidate)
    finally:
        parent.chmod(0o755)

    alias = tmp_path / "alias"
    try:
        alias.symlink_to(parent, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink fixture unavailable: {exc}")
    with pytest.raises(TrustedGitExecutablePolicyError):
        policy.validate(alias / "git")


def test_policy_pins_identity_and_digest_and_rejects_drift(tmp_path: Path) -> None:
    policy = _local_policy()
    candidate = _local_executable(tmp_path)
    identity = policy.validate(candidate)

    policy.revalidate(identity)
    assert digest_file(candidate) == identity.sha256

    candidate.write_bytes(b"changed fixture executable")
    candidate.chmod(0o755)
    with pytest.raises(TrustedGitExecutablePolicyError) as digest_error:
        policy.revalidate(identity)
    assert digest_error.value.category == "identity_drift"

    replacement = tmp_path / "replacement"
    replacement.write_bytes(b"replacement fixture executable")
    replacement.chmod(0o755)
    os.replace(replacement, candidate)
    with pytest.raises(TrustedGitExecutablePolicyError) as inode_error:
        policy.revalidate(identity)
    assert inode_error.value.category == "identity_drift"


def test_trusted_git_environment_is_pinned_and_scrubbed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate = _validated_candidate()
    monkeypatch.setenv("GIT_CONFIG_COUNT", "1")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", "alias.status")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "!touch attacker")
    monkeypatch.setenv("GIT_EXEC_PATH", str(tmp_path / "attacker-git-core"))

    environment = build_trusted_git_environment(candidate, home=tmp_path)

    assert environment["PATH"] in {"/usr/bin:/bin", r"C:\Windows\System32;C:\Program Files\Git\cmd"}
    assert environment["GIT_CONFIG_SYSTEM"] == os.devnull
    assert environment["GIT_CONFIG_GLOBAL"] == os.devnull
    assert "GIT_CONFIG_COUNT" not in environment
    assert "GIT_CONFIG_KEY_0" not in environment
    assert "GIT_CONFIG_VALUE_0" not in environment
    if trusted_git_exec_path(candidate) is not None:
        assert environment["GIT_EXEC_PATH"] == str(trusted_git_exec_path(candidate))
    else:
        assert "GIT_EXEC_PATH" not in environment


def test_preflight_classifies_apple_license_blocker_without_hardcoding_exit_alone() -> None:
    assert (
        classify_invocation_failure(
            returncode=69,
            stderr="xcodebuild license agreements",
            platform="darwin",
        )
        is TrustedGitAvailability.INVOCATION_BLOCKED
    )
    assert (
        classify_invocation_failure(
            returncode=69,
            stderr="generic git failure",
            platform="darwin",
        )
        is TrustedGitAvailability.INVOCATION_FAILED
    )
    assert (
        classify_invocation_failure(
            returncode=69,
            stderr="xcodebuild license agreements",
            platform="linux",
        )
        is TrustedGitAvailability.INVOCATION_FAILED
    )


def test_environment_blocker_error_does_not_recommend_privileged_repair() -> None:
    result = TrustedGitPreflightResult(
        TrustedGitAvailability.INVOCATION_BLOCKED,
        Path("/usr/bin/git"),
        returncode=69,
        diagnostic="You have not agreed to the Xcode license. sudo xcodebuild -license",
    )
    message = format_preflight_error(result)
    assert "ENVIRONMENT_BLOCKED" in message
    assert "sudo" not in message


@pytest.mark.asyncio
async def test_runner_preflight_fallback_is_cached_by_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "authority"
    root.mkdir()
    info = root.stat()
    broker = AuthorityBroker()
    runner = TrustedGitRunner.for_authority_root(
        root,
        (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode)),
        authority_broker=broker,
    )
    calls = 0
    original = trusted_git_module.run_trusted_git_preflight

    async def counted(*args, **kwargs):
        nonlocal calls
        calls += 1
        return await original(*args, **kwargs)

    monkeypatch.setattr(trusted_git_module, "run_trusted_git_preflight", counted)
    try:
        first = await runner.ensure_preflight()
        second = await runner.ensure_preflight()
        assert first.status is TrustedGitAvailability.AVAILABLE
        assert second == first
        expected_calls = (
            2
            if sys.platform == "darwin" and runner.executable != Path("/usr/bin/git")
            else 1
        )
        assert calls == expected_calls
    finally:
        await runner.close()
        broker.close()


@pytest.mark.asyncio
async def test_generic_preflight_failure_does_not_try_next_static_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "authority"
    root.mkdir()
    info = root.stat()
    first = _local_executable(tmp_path, "first-git")
    second = _local_executable(tmp_path, "second-git")
    policy = _local_policy()
    broker = AuthorityBroker()
    runner = TrustedGitRunner.for_authority_root(
        root,
        (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode)),
        authority_broker=broker,
        locator=StaticTrustedGitLocator((first, second)),
        executable_policy=policy,
    )
    calls: list[Path] = []

    async def failed(identity, owner, **kwargs) -> TrustedGitPreflightResult:
        _ = owner, kwargs
        calls.append(identity.path)
        return TrustedGitPreflightResult(
            TrustedGitAvailability.INVOCATION_FAILED,
            identity.path,
            identity,
            returncode=1,
            diagnostic="generic fixture failure",
        )

    monkeypatch.setattr(trusted_git_module, "run_trusted_git_preflight", failed)
    try:
        with pytest.raises(TrustedGitError, match="INVOCATION_FAILED"):
            await runner.ensure_preflight()
        assert calls == [first.resolve(strict=True)]
    finally:
        await runner.close()
        broker.close()


@pytest.mark.asyncio
@pytest.mark.skipif(os.name == "nt", reason="fixture uses a POSIX executable script")
async def test_injected_trusted_preflight_can_run_without_host_git(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    root.mkdir()
    info = root.stat()
    candidate = tmp_path / "trusted-git"
    candidate.write_text("#!/bin/sh\nprintf 'git version fixture\\n'\n", encoding="utf-8")
    candidate.chmod(0o755)
    policy = _local_policy()
    broker = AuthorityBroker()
    runner = TrustedGitRunner.for_authority_root(
        root,
        (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode)),
        authority_broker=broker,
        locator=StaticTrustedGitLocator((candidate,)),
        executable_policy=policy,
    )
    try:
        result = await runner.ensure_preflight()
        assert result.status is TrustedGitAvailability.AVAILABLE
        assert result.stdout == "git version fixture"
    finally:
        await runner.close()
        broker.close()


def test_production_runner_rejects_injected_trusted_git_policy(tmp_path: Path) -> None:
    root = tmp_path / "authority"
    root.mkdir()
    info = root.stat()
    broker = AuthorityBroker()
    with pytest.raises(TrustedGitError, match="only the platform Trusted Git policy"):
        TrustedGitRunner.for_authority_root(
            root,
            (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode)),
            authority_broker=broker,
            runtime_profile=RuntimeProfile.PRODUCTION,
            locator=StaticTrustedGitLocator(()),
        )
    broker.close()


@pytest.mark.asyncio
async def test_doctor_reports_all_candidates_and_selected_identity() -> None:
    report = await diagnose_trusted_git()

    assert report.status is TrustedGitAvailability.AVAILABLE
    assert report.selected is not None
    assert report.selected.identity is not None
    assert report.selected.identity.path in {
        candidate.resolve(strict=True)
        for candidate in PlatformTrustedGitLocator().candidates()
        if candidate.exists()
    }
    assert report.as_dict()["candidates"]


@pytest.mark.asyncio
async def test_doctor_distinguishes_missing_and_policy_rejected_candidates(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "missing-git"
    missing_report = await diagnose_trusted_git(
        locator=StaticTrustedGitLocator((missing,))
    )
    assert missing_report.status is TrustedGitAvailability.MISSING
    assert missing_report.classification == "MISSING"

    rejected = _local_executable(tmp_path, "rejected-git")
    rejected_report = await diagnose_trusted_git(
        locator=StaticTrustedGitLocator((rejected,))
    )
    assert rejected_report.status is TrustedGitAvailability.TRUST_REJECTED
    assert rejected_report.candidates[0].policy["category"] == "trust_policy_rejected"


@pytest.mark.asyncio
async def test_doctor_exposes_environment_blocker_without_using_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = _validated_candidate()

    async def blocked(*args, **kwargs) -> TrustedGitPreflightResult:
        _ = args, kwargs
        return TrustedGitPreflightResult(
            TrustedGitAvailability.INVOCATION_BLOCKED,
            candidate,
            returncode=69,
            stderr="toolchain gate",
            diagnostic="host toolchain blocked Git",
        )

    monkeypatch.setattr(preflight_module, "run_trusted_git_preflight", blocked)
    report = await diagnose_trusted_git(
        locator=StaticTrustedGitLocator((candidate,))
    )
    assert report.status is TrustedGitAvailability.INVOCATION_BLOCKED
    assert report.classification == "ENVIRONMENT_BLOCKED"
