"""Adversarial and differential coverage for the shell semantic authority."""

from __future__ import annotations

import shutil
import subprocess

import pytest

from khaos.security.shell_semantics import (
    ShellSemanticStatus,
    analyze_argv,
    analyze_shell_script,
)


@pytest.mark.parametrize(
    "script",
    [
        "ls -la",
        "cat README.md | grep security",
        "git status --short",
        r"echo \*",
    ],
)
def test_only_literal_read_only_graphs_are_safe(script: str) -> None:
    result = analyze_shell_script(script)

    assert result.status is ShellSemanticStatus.SAFE
    assert result.read_only is True
    assert result.requires_approval is False


@pytest.mark.parametrize(
    "script,feature",
    [
        ("echo {a,b}", "brace-expansion"),
        ("cat *.py", "glob-expansion"),
        ("echo $HOME", "parameter-expansion"),
        ("echo $(cat secret.txt)", "command-substitution"),
        ("cat <(cat input)", "process-substitution"),
        ("cat <<EOF\ncontent\nEOF", "heredoc"),
        ("cat <<< value", "redirection"),
        ("(cat file)", "subshell"),
        ("echo hi > output.txt", "redirection"),
        ("rg --pre ./preprocessor pattern", "executable-callback"),
        ("find . -exec cat {} \\;", "executable-callback"),
    ],
)
def test_shell_features_are_semantic_unknown(script: str, feature: str) -> None:
    result = analyze_shell_script(script)

    assert result.status is ShellSemanticStatus.SEMANTIC_UNKNOWN
    assert result.read_only is False
    assert result.requires_approval is True
    assert feature in result.reason or feature in result.ast.features


def test_nested_blocked_executable_remains_hard_blocked() -> None:
    result = analyze_shell_script("echo $(sudo id)")

    assert result.status is ShellSemanticStatus.BLOCKED
    assert result.requires_approval is True


def test_argv_contract_does_not_apply_shell_expansion() -> None:
    result = analyze_argv(["echo", "$(touch", "pwned)"])

    assert result.status is ShellSemanticStatus.SAFE
    assert result.read_only is True


@pytest.mark.parametrize(
    "script",
    [
        "echo {a,b}",
        "echo $HOME",
        "echo $(cat file)",
        "cat <(cat file)",
        "cat <<EOF\nvalue\nEOF",
        "rg --pre ./helper pattern",
    ],
)
def test_bash_syntax_acceptance_does_not_create_a_security_shortcut(script: str) -> None:
    """Differential check: Bash syntax validity never implies literal effect."""
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is unavailable")

    syntax = subprocess.run(
        [bash, "-n", "-c", script],
        check=False,
        capture_output=True,
        text=True,
    )
    assert syntax.returncode == 0, syntax.stderr
    assert analyze_shell_script(script).status is not ShellSemanticStatus.SAFE


def test_path_qualified_executable_never_inherits_basename_classification() -> None:
    """A workspace-owned binary named ``ls`` is not the system ``ls``.

    The classifier used the basename of the executable word, so
    ``/workspace/ls`` inherited the read-only classification of the
    system ``ls``.  Path-qualified executables must stay
    SEMANTIC_UNKNOWN (approval required); only bare names resolved
    through the scrubbed trusted PATH may be classified.
    """
    for script in (
        "/workspace/ls -la",
        "./ls -la",
        "../bin/ls -la",
        "/workspace/git status",
    ):
        result = analyze_shell_script(script)
        assert result.status is ShellSemanticStatus.SEMANTIC_UNKNOWN, script
    # Bare names keep their classification.
    assert analyze_shell_script("ls -la").status is ShellSemanticStatus.SAFE
