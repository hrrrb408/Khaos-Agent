"""Validated persisted identifiers used by mutation and crash recovery."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from pathlib import PurePosixPath


class UnsafePersistedIdentifier(ValueError):
    pass


@dataclass(frozen=True)
class SafeWorkspaceRelativePath:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "SafeWorkspaceRelativePath":
        if not isinstance(raw, str) or not raw or raw in {".", ".."} or "\x00" in raw or "\\" in raw:
            raise UnsafePersistedIdentifier("invalid workspace path")
        normalized = unicodedata.normalize("NFC", raw)
        if raw != normalized:
            raise UnsafePersistedIdentifier("workspace path is not NFC")
        pure = PurePosixPath(normalized)
        if (pure.is_absolute() or normalized != pure.as_posix()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or any(part.casefold() == ".git" for part in pure.parts)
                or re.match(r"^[A-Za-z]:", normalized)):
            raise UnsafePersistedIdentifier("unsafe workspace path")
        return cls(normalized)


@dataclass(frozen=True)
class SafeRecoveryRunId:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "SafeRecoveryRunId":
        if not isinstance(raw, str) or not re.fullmatch(r"per_[0-9a-f]{32}", raw):
            raise UnsafePersistedIdentifier("invalid recovery run id")
        return cls(raw)


@dataclass(frozen=True)
class SafeRecoveryArtifactName:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "SafeRecoveryArtifactName":
        if not isinstance(raw, str) or not re.fullmatch(r"artifact-[0-9a-f]{32}\.bak", raw):
            raise UnsafePersistedIdentifier("invalid recovery artifact name")
        return cls(raw)


@dataclass(frozen=True)
class SafeSealTombstoneName:
    value: str

    @classmethod
    def parse(cls, raw: str) -> "SafeSealTombstoneName":
        if not isinstance(raw, str) or not re.fullmatch(r"seal-[0-9a-f]{32}\.json", raw):
            raise UnsafePersistedIdentifier("invalid seal tombstone name")
        return cls(raw)
