#!/usr/bin/env python3
"""Fail closed unless a release tag is annotated and GitHub-verified signed."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from typing import Any

TAG_RE = re.compile(r"^v[0-9A-Za-z][0-9A-Za-z._-]*$")
GITHUB_API = "https://api.github.com"


class ReleaseTagError(RuntimeError):
    """Raised when a release tag cannot satisfy the cryptographic contract."""


def _git_output(*args: str) -> str:
    environment = dict(os.environ)
    for key in (
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_KEY_0",
        "GIT_CONFIG_VALUE_0",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
    ):
        environment.pop(key, None)
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise ReleaseTagError(
            completed.stderr.strip() or f"git {' '.join(args)} failed"
        )
    return completed.stdout.strip()


def _github_tag_verification(
    repository: str,
    tag_object_sha: str,
    token: str,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
) -> dict[str, Any]:
    if not token:
        raise ReleaseTagError("GitHub token is required for tag signature verification")
    url = (
        f"{GITHUB_API}/repos/{repository}/git/tags/"
        f"{urllib.parse.quote(tag_object_sha, safe='')}"
    )
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with opener(request, timeout=20) as response:
            payload = json.load(response)
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
        raise ReleaseTagError("GitHub tag verification API request failed") from exc
    if not isinstance(payload, dict):
        raise ReleaseTagError("GitHub tag verification response is not an object")
    verification = payload.get("verification")
    if not isinstance(verification, dict):
        raise ReleaseTagError("GitHub tag verification metadata is missing")
    return verification


def verify_release_tag(
    tag: str,
    repository: str,
    token: str,
    *,
    git_output: Callable[..., str] = _git_output,
    fetch_verification: Callable[[str, str, str], dict[str, Any]] = _github_tag_verification,
) -> str:
    """Verify and return the commit SHA targeted by a signed annotated tag."""
    if TAG_RE.fullmatch(tag) is None:
        raise ReleaseTagError("release tag must match the protected v* namespace")
    if not re.fullmatch(r"[^/]+/[^/]+", repository):
        raise ReleaseTagError("repository must be owner/name")

    ref = f"refs/tags/{tag}"
    tag_object_sha = git_output("rev-parse", "--verify", f"{ref}^{{tag}}")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", tag_object_sha):
        raise ReleaseTagError("release tag object SHA is invalid")
    if git_output("cat-file", "-t", tag_object_sha) != "tag":
        raise ReleaseTagError("release tag is not an annotated tag object")
    commit_sha = git_output("rev-list", "-n", "1", f"{ref}^{{}}")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", commit_sha):
        raise ReleaseTagError("release tag target commit SHA is invalid")

    verification = fetch_verification(repository, tag_object_sha, token)
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        reason = verification.get("reason", "unknown")
        raise ReleaseTagError(
            f"release tag signature is not GitHub-verified (reason={reason})"
        )

    # GitHub's tag-object verification is the CI trust root: it performs the
    # cryptographic signature check against the signing identity registered on
    # GitHub.  A runner-local GPG keyring is intentionally not treated as a
    # second, ambient trust source.
    local_verify = subprocess.run(
        ["git", "verify-tag", "--raw", tag],
        capture_output=True,
        text=True,
        check=False,
    )
    print(
        f"verified signed annotated tag {tag} -> {commit_sha} "
        f"(github=valid, local-keyring={'valid' if local_verify.returncode == 0 else 'unavailable'})"
    )
    return commit_sha


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--token", default=os.environ.get("GH_TOKEN", ""))
    args = parser.parse_args(argv)
    try:
        verify_release_tag(args.tag, args.repo, args.token)
    except ReleaseTagError as exc:
        print(f"release tag verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
