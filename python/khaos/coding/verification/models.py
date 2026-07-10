from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DetectedProject:
    root: Path
    ecosystem: str
    frameworks: tuple[str, ...]
    confidence: float
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class VerificationStep:
    id: str
    stage: str
    command: tuple[str, ...]
    cwd: Path
    required: bool = True
    source: str = "detected"
    timeout_seconds: float = 120.0


@dataclass(frozen=True)
class VerificationPlan:
    steps: tuple[VerificationStep, ...]
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class VerificationStepResult:
    step_id: str
    status: str
    return_code: int | None
    stdout: str = ""
    stderr: str = ""
    diagnostics: dict[str, object] = field(default_factory=dict)
