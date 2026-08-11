"""Release tag governance must reject unsigned or lightweight v* tags."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


def _module():
    path = Path(__file__).resolve().parents[3] / "scripts" / "verify_release_tag.py"
    spec = importlib.util.spec_from_file_location("verify_release_tag", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_release_tag_requires_v_namespace() -> None:
    module = _module()
    with pytest.raises(module.ReleaseTagError, match="protected v\*"):
        module.verify_release_tag(
            "release-1",
            "hrrrb408/Khaos-Agent",
            "token",
            git_output=lambda *_args: "",
        )


def test_release_tag_requires_annotated_tag_object() -> None:
    module = _module()

    def git_output(*args: str) -> str:
        if args[-1].endswith("^{tag}"):
            return "a" * 40
        if args[:2] == ("cat-file", "-t"):
            return "commit"
        return "b" * 40

    with pytest.raises(module.ReleaseTagError, match="annotated"):
        module.verify_release_tag(
            "v1.2.3",
            "hrrrb408/Khaos-Agent",
            "token",
            git_output=git_output,
        )


def test_release_tag_requires_github_valid_signature() -> None:
    module = _module()

    def git_output(*args: str) -> str:
        if args[-1].endswith("^{tag}"):
            return "a" * 40
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        return "b" * 40

    with pytest.raises(module.ReleaseTagError, match="not GitHub-verified"):
        module.verify_release_tag(
            "v1.2.3",
            "hrrrb408/Khaos-Agent",
            "token",
            git_output=git_output,
            fetch_verification=lambda *_args: {
                "verified": False,
                "reason": "unknown_key",
            },
        )


def test_release_tag_accepts_github_valid_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    module = _module()

    def git_output(*args: str) -> str:
        if args[-1].endswith("^{tag}"):
            return "a" * 40
        if args[:2] == ("cat-file", "-t"):
            return "tag"
        return "b" * 40

    monkeypatch.setattr(module.subprocess, "run", lambda *_args, **_kwargs: type(
        "Completed", (), {"returncode": 1, "stdout": "", "stderr": "no local key"}
    )())
    assert (
        module.verify_release_tag(
            "v1.2.3",
            "hrrrb408/Khaos-Agent",
            "token",
            git_output=git_output,
            fetch_verification=lambda *_args: {
                "verified": True,
                "reason": "valid",
            },
        )
        == "b" * 40
    )
