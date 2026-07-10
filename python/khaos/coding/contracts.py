"""Phase 0 contracts for the Coding runtime alignment.

These contracts are intentionally dependency-free and do not alter runtime
behavior. Later phases provide concrete adapters and services.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, Sequence


@dataclass(frozen=True)
class SourcePosition:
    line: int
    character: int


@dataclass(frozen=True)
class SourceRange:
    start: SourcePosition
    end: SourcePosition
    encoding: Literal["utf-8", "utf-16"] = "utf-8"


@dataclass(frozen=True)
class ParsedFile:
    path: Path
    language: str
    symbols: tuple[object, ...] = ()
    imports: tuple[object, ...] = ()
    diagnostics: tuple[object, ...] = ()


class LanguageAdapter(Protocol):
    language_id: str
    extensions: frozenset[str]

    def parse(self, path: Path, content: bytes) -> ParsedFile: ...


@dataclass(frozen=True)
class VerificationStep:
    id: str
    stage: str
    command: tuple[str, ...]
    cwd: Path
    timeout_seconds: int
    required: bool = True
    source: str = "fallback"


class ExecutionBackend(Protocol):
    name: str

    async def probe(self) -> object: ...

    async def execute(self, request: object) -> object: ...

    async def terminate(self, execution_id: str) -> None: ...


@dataclass(frozen=True)
class TaskWorkspace:
    id: str
    task_id: str
    repository_root: Path
    worktree_path: Path
    base_ref: str
    base_sha: str
    branch_name: str
    writable_roots: tuple[Path, ...]


@dataclass(frozen=True)
class ChangeSet:
    id: str
    workspace_id: str
    base_sha: str
    changed_files: tuple[Path, ...]
    patch_artifact: Path
    verification_report_id: str
