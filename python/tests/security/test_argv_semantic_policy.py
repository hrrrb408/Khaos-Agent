"""Command-specific argv semantic policy tests (M6.9 BATCH 9).

SAFE previously meant "the executable/subcommand name is on the allow
list": ``git branch -D main`` (destroys a ref), ``git branch new-branch``
(creates a ref), ``git -c core.pager=sh log`` (config-mediated execution),
and ``git diff --output=<file>`` (writes a file) were all classified
read-only.  SAFE now requires the complete argv semantics to be proven
side-effect-free; everything else falls to SEMANTIC_UNKNOWN -> approval.
"""

from __future__ import annotations

import pytest
from khaos.security.shell_semantics import ShellSemanticStatus, analyze_argv


def _safe(argv: list[str]) -> bool:
    return analyze_argv(argv).status is ShellSemanticStatus.SAFE


def _unknown(argv: list[str]) -> bool:
    return analyze_argv(argv).status is ShellSemanticStatus.SEMANTIC_UNKNOWN


@pytest.mark.parametrize(
    "argv",
    [
        ["git", "branch"],
        ["git", "branch", "--list"],
        ["git", "branch", "-l"],
        ["git", "branch", "-a"],
        ["git", "branch", "-av"],
        ["git", "branch", "--all"],
        ["git", "branch", "-vv"],
        ["git", "branch", "--show-current"],
        ["git", "branch", "--list", "feature-*"],
        ["git", "branch", "--contains", "HEAD"],
        ["git", "branch", "-l", "main"],
        ["git", "status"],
        ["git", "status", "--short"],
        ["git", "diff"],
        ["git", "diff", "--stat"],
        ["git", "diff", "--no-textconv"],
        ["git", "diff", "--no-ext-diff"],
        ["git", "log", "--oneline", "-5"],
        ["git", "show", "HEAD"],
        ["git", "rev-parse", "HEAD"],
        ["git", "ls-files"],
        ["git", "cat-file", "-p", "HEAD"],
    ],
)
def test_proven_read_only_argv_stays_safe(argv: list[str]) -> None:
    assert _safe(argv), argv


@pytest.mark.parametrize(
    "argv",
    [
        # git branch mutations must never be SAFE.
        ["git", "branch", "-d", "foo"],
        ["git", "branch", "-D", "foo"],
        ["git", "branch", "--delete", "foo"],
        ["git", "branch", "-m", "old", "new"],
        ["git", "branch", "-M", "old", "new"],
        ["git", "branch", "--move", "old", "new"],
        ["git", "branch", "-c", "old", "new"],
        ["git", "branch", "-C", "old", "new"],
        ["git", "branch", "--copy", "old", "new"],
        ["git", "branch", "--set-upstream-to", "origin/main"],
        ["git", "branch", "--unset-upstream"],
        ["git", "branch", "-f", "topic", "main"],
        ["git", "branch", "--force", "topic", "main"],
        ["git", "branch", "new-branch"],
        ["git", "branch", "new-branch", "main"],
        # Config-mediated execution (globals must precede the subcommand).
        ["git", "-c", "core.pager=sh", "log"],
        ["git", "-c", "diff.external=rm", "diff"],
        ["git", "--config-env", "core.pager=ENV", "log"],
        ["git", "--exec-path=/tmp", "log"],
        ["git", "--paginate", "log"],
        ["git", "-p", "log"],
        # Output files and external diff/textconv.
        ["git", "diff", "--output=/tmp/pwned", "HEAD"],
        ["git", "log", "--output=/tmp/pwned"],
        ["git", "show", "--output=/tmp/pwned", "HEAD"],
        ["git", "diff", "--ext-diff", "HEAD"],
        ["git", "diff", "--textconv", "HEAD"],
        ["git", "status", "--output=/tmp/pwned"],
        # stdin-driven command dispatch is unmodeled.
        ["git", "cat-file", "--batch-command"],
        # Unknown subcommands stay unknown.
        ["git", "push"],
        ["git", "commit"],
        ["git", "checkout", "main"],
        ["git", "clean", "-fd"],
        # find executing/writing predicates.
        ["find", ".", "-exec", "cat", "{}", ";"],
        ["find", ".", "-execdir", "sh", "-c", "id", ";"],
        ["find", ".", "-delete"],
        ["find", ".", "-fprint", "/tmp/pwned"],
        ["find", ".", "-fprint0", "/tmp/pwned"],
        ["find", ".", "-fls", "/tmp/pwned"],
        ["find", ".", "-ok", "rm", "{}", ";"],
        # Callbacks via = syntax.
        ["rg", "--pre=sh", "pattern"],
    ],
)
def test_mutating_or_unproven_argv_requires_approval(argv: list[str]) -> None:
    result = analyze_argv(argv)
    assert result.status is not ShellSemanticStatus.SAFE, argv
    assert result.requires_approval is True, argv
    assert result.read_only is False, argv


@pytest.mark.parametrize(
    "argv",
    [
        ["rg", "--pre", "./helper", "pattern"],
        ["rg", "pattern"],
        ["find", ".", "-name", "*.py"],
        ["grep", "-r", "pattern", "."],
        ["cat", "README.md"],
        ["ls", "-la"],
        ["echo", "hello"],
    ],
)
def test_read_only_utilities_keep_their_contract(argv: list[str]) -> None:
    # rg --pre is a callback (unknown); plain utilities stay safe.
    if argv[0] == "rg" and "--pre" in argv:
        assert _unknown(argv)
    else:
        assert _safe(argv), argv


def test_git_branch_cluster_flags_are_letter_checked() -> None:
    # -av is a valid all+verbose query cluster...
    assert _safe(["git", "branch", "-av"])
    # ...but -vd (verbose + delete) carries a mutating letter.
    assert _unknown(["git", "branch", "-vd"])
    assert _unknown(["git", "branch", "-Dv"])
    assert _unknown(["git", "branch", "-rD"])


def test_positional_branch_name_requires_query_flag() -> None:
    # Listing a pattern is a query; creating a named branch is not.
    assert _safe(["git", "branch", "--list", "main"])
    assert _unknown(["git", "branch", "main"])
    # Query flag after the positional still proves list semantics.
    assert _safe(["git", "branch", "main", "--list"])


def test_safe_is_not_just_subcommand_name_matching() -> None:
    """The original bug: any argv after an allowed subcommand was SAFE."""
    for argv in (
        ["git", "branch", "-D", "main"],
        ["git", "log", "--output=/tmp/x"],
        ["git", "diff", "--ext-diff"],
    ):
        assert analyze_argv(argv).status is ShellSemanticStatus.SEMANTIC_UNKNOWN
