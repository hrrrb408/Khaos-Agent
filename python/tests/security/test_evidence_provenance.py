"""Adversarial tests for exact GitHub provenance endpoint binding."""

from __future__ import annotations

import pytest

from khaos.security import evidence_provenance


def test_gh_api_qualifies_repository_without_ambient_repo_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_bounded_process(argv, *, timeout_seconds, max_output_bytes):
        captured["argv"] = argv
        captured["timeout_seconds"] = timeout_seconds
        captured["max_output_bytes"] = max_output_bytes
        return b"{}", b""

    monkeypatch.setattr(evidence_provenance, "_bounded_process", fake_bounded_process)

    assert evidence_provenance.gh_api_bytes(
        "hrrrb408/Khaos-Agent",
        "actions/runs?head_sha=abc",
    ) == b"{}"
    assert captured["argv"] == [
        "gh",
        "api",
        "repos/hrrrb408/Khaos-Agent/actions/runs?head_sha=abc",
    ]


@pytest.mark.parametrize("repository", ["https://github.com/hrrrb408/Khaos-Agent", "owner", "owner/../repo"])
def test_gh_api_rejects_untrusted_repository_path(repository: str) -> None:
    with pytest.raises(evidence_provenance.EvidenceProvenanceError, match="owner/name"):
        evidence_provenance.gh_api_bytes(repository, "compare/a...main")
