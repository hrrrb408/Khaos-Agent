# KHAOS-PRIVILEGED-SPAWN owner=EvidenceProvenanceFetcher threat-model=untrusted-gh-cli-output boundary=evidence-provenance-lookup
"""GitHub-API provenance fetchers for closure evidence re-verification.

The closure builder must not trust a local ``VERIFIED`` bundle: every
manifest is re-resolved through the GitHub Actions API (via the ``gh``
CLI, mirroring ``scripts/fetch_security_evidence.py``) before a CLOSED
claim is possible.  Any HTTP error, missing object, or digest mismatch
fails closed.
"""

from __future__ import annotations

import json
import subprocess
from typing import Callable


class EvidenceProvenanceError(RuntimeError):
    """A GitHub API lookup for evidence provenance failed."""


def _gh(repository: str, *args: str) -> bytes:
    result = subprocess.run(
        ["gh", "api", "--repo", repository, *args],
        check=False,
        capture_output=True,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise EvidenceProvenanceError(
            f"gh api {' '.join(args)} failed ({result.returncode}): {detail}"
        )
    return result.stdout


def gh_fetch_json(repository: str) -> Callable[[str], object]:
    """Return a ``fetch_json(api_path)`` closure backed by ``gh api``."""

    def fetch_json(path: str) -> object:
        return json.loads(_gh(repository, path).decode("utf-8"))

    return fetch_json


def gh_fetch_artifact(repository: str) -> Callable[[str], bytes]:
    """Return a ``fetch_artifact(artifact_id)`` closure backed by ``gh api``.

    The artifact zip is downloaded and streamed through memory once; its
    SHA256 is what the caller compares, so the transfer must be the exact
    artifact bytes.
    """

    def fetch_artifact(artifact_id: str) -> bytes:
        if not artifact_id.isdigit():
            raise EvidenceProvenanceError("artifact id must be numeric")
        return _gh(repository, f"actions/artifacts/{artifact_id}/zip")

    return fetch_artifact


__all__ = [
    "EvidenceProvenanceError",
    "gh_fetch_artifact",
    "gh_fetch_json",
]
