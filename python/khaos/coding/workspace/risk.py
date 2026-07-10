"""Deterministic ChangeSet risk classification."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RiskReport:
    level: str
    reasons: tuple[str, ...]


def assess_patch(patch: str, changed_files: tuple[str, ...]) -> RiskReport:
    reasons: list[str] = []
    if any(path.startswith(".github/") or path in {"Dockerfile", "docker-compose.yml"} for path in changed_files):
        reasons.append("ci-or-container-config")
    if any("secret" in path.lower() or path.endswith((".pem", ".key")) for path in changed_files):
        reasons.append("credential-like-file")
    if "rm -rf" in patch or "curl |" in patch:
        reasons.append("dangerous-command-pattern")
    return RiskReport("critical" if reasons else "low", tuple(reasons))
