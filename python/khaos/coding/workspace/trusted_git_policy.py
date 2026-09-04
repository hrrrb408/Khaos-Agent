"""Strict trust policy and identity handling for platform Git candidates."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path

FileIdentity = tuple[int, int, int, int]


class TrustedGitExecutablePolicyError(RuntimeError):
    """Raised when a Git candidate or its pinned identity is not trusted."""

    def __init__(self, message: str, *, category: str = "trust_policy_rejected") -> None:
        super().__init__(message)
        self.category = category


@dataclass(frozen=True, slots=True)
class TrustedGitExecutableIdentity:
    """The immutable executable facts bound to one Trusted Git runner."""

    path: Path
    file_identity: FileIdentity
    sha256: str

    @property
    def owner_uid(self) -> int:
        """Return the owner UID captured in ``file_identity``."""
        return self.file_identity[2]

    @property
    def mode(self) -> int:
        """Return the complete mode captured in ``file_identity``."""
        return self.file_identity[3]


def _identity(info: os.stat_result) -> FileIdentity:
    return (int(info.st_dev), int(info.st_ino), int(info.st_uid), int(info.st_mode))


def _binary_open_flags() -> int:
    """Return no-follow binary read flags on every supported platform."""
    return os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)


def _same_file_snapshot(current: os.stat_result, expected: os.stat_result) -> bool:
    return (
        current.st_dev,
        current.st_ino,
        current.st_uid,
        current.st_mode,
        current.st_nlink,
        current.st_size,
        current.st_mtime_ns,
        current.st_ctime_ns,
    ) == (
        expected.st_dev,
        expected.st_ino,
        expected.st_uid,
        expected.st_mode,
        expected.st_nlink,
        expected.st_size,
        expected.st_mtime_ns,
        expected.st_ctime_ns,
    )


def _digest_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    while chunk := os.read(descriptor, 1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def digest_file(path: Path) -> str:
    """Hash one file through a no-follow binary descriptor."""
    try:
        descriptor = os.open(path, _binary_open_flags())
    except OSError as exc:
        raise TrustedGitExecutablePolicyError(
            f"Git executable is unavailable: {path}",
            category="candidate_not_found",
        ) from exc
    try:
        return _digest_descriptor(descriptor)
    finally:
        os.close(descriptor)


class TrustedGitExecutablePolicy:
    """Validate and revalidate a root-owned, immutable Git executable.

    ``trusted_owner_uid`` exists to make pure policy tests deterministic with
    temporary fixtures.  A non-root test owner still accepts the unavoidable
    root-owned ancestors of a temporary path.  The production factory always
    uses the default ``0`` and never exposes this as a runtime/developer
    override.
    """

    def __init__(self, *, trusted_owner_uid: int = 0) -> None:
        if type(trusted_owner_uid) is not int or trusted_owner_uid < 0:
            raise ValueError("trusted Git owner UID must be a non-negative integer")
        self.trusted_owner_uid = trusted_owner_uid

    def validate(self, candidate: Path) -> TrustedGitExecutableIdentity:
        """Resolve and validate one platform candidate, then fingerprint it."""
        if not isinstance(candidate, Path) or not candidate.is_absolute():
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate must be absolute: {candidate}",
                category="candidate_not_found",
            )
        # Validate the path supplied by the locator before resolving the leaf.
        # A final symlink may resolve to a trusted target, but a mutable
        # symlinked parent must never become an invisible candidate boundary.
        self._validate_parent_chain(candidate, label="Git candidate")
        try:
            executable = candidate.resolve(strict=True)
        except OSError as exc:
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate is unavailable: {candidate}",
                category="candidate_not_found",
            ) from exc
        except RuntimeError as exc:
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate has an invalid symlink path: {candidate}"
            ) from exc
        if not executable.is_absolute():
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate is not absolute: {candidate}"
            )

        self._validate_parent_chain(executable)
        try:
            descriptor = os.open(executable, _binary_open_flags())
        except OSError as exc:
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate is unavailable: {executable}",
                category="candidate_not_found",
            ) from exc
        try:
            info = os.fstat(descriptor)
            self._validate_file_info(executable, info)
            digest = _digest_descriptor(descriptor)
            after = os.fstat(descriptor)
        except TrustedGitExecutablePolicyError:
            raise
        except OSError as exc:
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate could not be fingerprinted: {executable}"
            ) from exc
        finally:
            os.close(descriptor)
        if not _same_file_snapshot(after, info):
            raise TrustedGitExecutablePolicyError(
                f"Git executable candidate changed while being fingerprinted: {executable}",
                category="identity_drift",
            )
        return TrustedGitExecutableIdentity(executable, _identity(info), digest)

    def revalidate(
        self,
        identity: TrustedGitExecutableIdentity,
        *,
        expected_digest: str | None = None,
        label: str = "Git executable",
    ) -> None:
        """Recheck the pinned inode/mode/owner/parent chain and digest."""
        path = identity.path
        if not isinstance(path, Path) or not path.is_absolute():
            raise TrustedGitExecutablePolicyError(
                f"{label} path must be absolute: {path}",
                category="candidate_not_found",
            )
        self._validate_parent_chain(path, label=label)
        try:
            descriptor = os.open(path, _binary_open_flags())
        except OSError as exc:
            raise TrustedGitExecutablePolicyError(
                f"{label} is unavailable: {path}", category="candidate_not_found"
            ) from exc
        try:
            current = os.fstat(descriptor)
            self._validate_file_info(path, current, label=label)
            if _identity(current) != identity.file_identity:
                raise TrustedGitExecutablePolicyError(
                    f"{label} identity drifted: {path}", category="identity_drift"
                )
            digest = _digest_descriptor(descriptor)
            after = os.fstat(descriptor)
        except TrustedGitExecutablePolicyError:
            raise
        except OSError as exc:
            raise TrustedGitExecutablePolicyError(
                f"{label} could not be read: {path}"
            ) from exc
        finally:
            os.close(descriptor)
        if not _same_file_snapshot(current, after):
            raise TrustedGitExecutablePolicyError(
                f"{label} changed while being revalidated: {path}",
                category="identity_drift",
            )
        expected = expected_digest if expected_digest is not None else identity.sha256
        if digest != expected or digest != identity.sha256:
            raise TrustedGitExecutablePolicyError(
                f"{label} content digest drifted: {path}", category="identity_drift"
            )

    def inspect(self, candidate: Path) -> dict[str, object]:
        """Return bounded machine-readable facts for the doctor command."""
        record: dict[str, object] = {
            "candidate": str(candidate),
            "canonical_path": None,
            "owner_uid": None,
            "mode": None,
            "parent_chain": "unknown",
            "identity": None,
            "digest": None,
            "status": "trust_rejected",
            "category": "trust_policy_rejected",
            "diagnostic": "",
        }
        try:
            canonical = candidate.resolve(strict=True)
            record["canonical_path"] = str(canonical)
            info = canonical.stat()
            record["owner_uid"] = int(info.st_uid)
            record["mode"] = oct(stat.S_IMODE(info.st_mode))
            record["identity"] = list(_identity(info))
            try:
                self._validate_parent_chain(candidate, label="Git candidate")
                self._validate_parent_chain(canonical)
            except TrustedGitExecutablePolicyError:
                record["parent_chain"] = "rejected"
            else:
                record["parent_chain"] = "trusted"
            identity = self.validate(candidate)
            record["status"] = "policy_validated"
            record["digest"] = identity.sha256
        except (OSError, RuntimeError, TrustedGitExecutablePolicyError) as exc:
            if isinstance(exc, TrustedGitExecutablePolicyError):
                record["category"] = exc.category
            else:
                record["category"] = (
                    "trust_policy_rejected"
                    if isinstance(exc, RuntimeError)
                    else "candidate_not_found"
                )
            record["diagnostic"] = str(exc)
        return record

    def _validate_file_info(
        self, path: Path, info: os.stat_result, *, label: str = "Git executable"
    ) -> None:
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != self.trusted_owner_uid
            or info.st_mode & 0o022
        ):
            raise TrustedGitExecutablePolicyError(
                f"{label} must be absolute, root-owned, regular, and immutable: {path}"
            )

    def _validate_parent_chain(
        self, executable: Path, *, label: str = "Git executable"
    ) -> None:
        for parent in executable.parents:
            try:
                info = parent.lstat()
            except OSError as exc:
                raise TrustedGitExecutablePolicyError(
                    f"{label} parent chain is unavailable: {parent}",
                    category="candidate_not_found",
                ) from exc
            if (
                stat.S_ISLNK(info.st_mode)
                or not stat.S_ISDIR(info.st_mode)
                or not self._is_trusted_parent_owner(info.st_uid)
                or info.st_mode & 0o022
            ):
                raise TrustedGitExecutablePolicyError(
                    f"{label} parent chain is not trusted: {parent}"
                )

    def _is_trusted_parent_owner(self, owner_uid: int) -> bool:
        """Accept root ancestors when pure tests use a non-root fixture owner."""
        return owner_uid == self.trusted_owner_uid or (
            self.trusted_owner_uid != 0 and owner_uid == 0
        )


__all__ = [
    "FileIdentity",
    "TrustedGitExecutableIdentity",
    "TrustedGitExecutablePolicy",
    "TrustedGitExecutablePolicyError",
    "digest_file",
]
