"""Conservative Bash/Zsh semantic analysis for ``terminal_shell``.

This module is deliberately a *non-executing* parser.  It produces an
immutable semantic AST and only calls a shell command read-only when the
complete executable graph is made of literal words with no expansion,
redirection, callback, assignment, or subshell semantics.  Every construct
that can change the executable graph is represented as a feature and causes
``semantic-unknown`` unless a nested literal command is explicitly blocked.

The parser is intentionally conservative rather than a shell interpreter:
unknown syntax is an approval requirement, never an approval shortcut.  This
keeps the authority boundary fail-closed without depending on ``shlex`` or a
shell process for security decisions.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path


class ShellSemanticStatus(str, Enum):
    """Semantic outcome used by command policy and permission shortcuts."""

    SAFE = "safe"
    SEMANTIC_UNKNOWN = "semantic-unknown"
    BLOCKED = "blocked"


# These sets are intentionally small.  A command not covered by an explicit
# argument policy is unknown, even when its executable happens to look like a
# common read-only utility.
READ_ONLY_EXECUTABLES = frozenset(
    {
        "cat",
        "date",
        "echo",
        "grep",
        "head",
        "ls",
        "pwd",
        "rg",
        "tail",
        "test",
        "true",
        "wc",
        "which",
    }
)

MUTATING_EXECUTABLES = frozenset(
    {
        "chmod",
        "chown",
        "cp",
        "curl",
        "dd",
        "git",
        "kill",
        "mkdir",
        "mv",
        "npm",
        "pip",
        "python",
        "python3",
        "rm",
        "rmdir",
        "tee",
        "touch",
    }
)

BLOCKED_EXECUTABLES = frozenset(
    {
        "sudo",
        "su",
        "passwd",
        "visudo",
        "chroot",
        "iptables",
        "nft",
        "ufw",
        "fdisk",
        "parted",
        "mount",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "systemctl",
        "service",
        "crontab",
        "at",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "insmod",
        "modprobe",
    }
)

SHELL_EVALUATORS = frozenset(
    {"eval", "source", ".", "exec", "command", "builtin", "sh", "bash", "zsh"}
)

# These options make an otherwise read-looking command execute a callback.
# ``rg --pre`` is especially important: the callback is not visible as the
# first executable in the argv vector.
CALLBACK_OPTIONS = frozenset(
    {
        "--pre",
        "--pre-glob",
        "-exec",
        "-execdir",
        "--exec",
        "--exec-batch",
        "--execdir",
    }
)

# M6.9 BATCH 9: SAFE is not "the subcommand name is allowed" — it is
# "the complete argv semantics are proven side-effect-free under the
# defined execution model".  These predicates encode the per-command
# argument contracts; anything not explicitly proven stays SEMANTIC_UNKNOWN
# and goes to approval.

# Git global options that mediate execution or redirect effects:
# -c/--config-env inject arbitrary configuration (external diff, textconv,
# pager, aliases, core.editor); --exec-path relocates helper lookup;
# --paginate spawns $PAGER.  None of these can appear in a SAFE argv.
_GIT_FORBIDDEN_GLOBALS = frozenset(
    {
        "-c",
        "--config-env",
        "--exec-path",
        "--paginate",
        "-p",
    }
)

# Git diff/log/show options that write files or execute external tools.
# (--no-textconv/--no-ext-diff *disable* those paths and stay allowed.)
_GIT_DIFF_FORBIDDEN = frozenset(
    {
        "--output",
        "--ext-diff",
        "--textconv",
    }
)

# Only explicitly query-shaped ``git branch`` argv is read-only.  Bare
# ``git branch <name>`` CREATES a branch; -d/-D/-m/-M/-c/-C mutate refs;
# --set-upstream-to/--unset-upstream rewrite config.
_GIT_BRANCH_MUTATING_FLAGS = frozenset(
    {
        "-d",
        "-D",
        "-m",
        "-M",
        "-c",
        "-C",
        "-f",
        "--force",
        "-u",
        "--set-upstream-to",
        "--unset-upstream",
        "--edit-description",
        "--delete",
        "--move",
        "--copy",
    }
)
_GIT_BRANCH_QUERY_FLAGS = frozenset(
    {
        "-l",
        "--list",
        "-v",
        "-vv",
        "--verbose",
        "-a",
        "--all",
        "-r",
        "--remotes",
        "-q",
        "--quiet",
        "--show-current",
        "--contains",
        "--no-contains",
        "--merged",
        "--no-merged",
        "--points-at",
        "--sort",
        "--format",
        "--column",
        "--no-column",
    }
)
# Single-letter cluster flags allowed when composed only of query letters.
_GIT_BRANCH_SAFE_CLUSTER_LETTERS = frozenset("lavrq")

# find(1) predicates that execute callbacks or write files.
_FIND_FORBIDDEN = frozenset(
    {
        "-exec",
        "-execdir",
        "-ok",
        "-okdir",
        "-delete",
        "-fprint",
        "-fprint0",
        "-fprintf",
        "-fprintf0",
        "-fls",
    }
)

_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VARIABLE_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_SCRIPT_BYTES = 1024 * 1024
_MAX_PARSE_DEPTH = 8


@dataclass(frozen=True, slots=True)
class ShellWord:
    """One shell word after quote removal, retaining semantic provenance."""

    text: str
    literal: bool
    quoted: bool
    assignment: bool = False


@dataclass(frozen=True, slots=True)
class ShellCommandNode:
    """A command node in the parsed executable graph."""

    words: tuple[ShellWord, ...]
    operator_before: str = ""
    redirection: bool = False
    callback: bool = False

    @property
    def executable(self) -> str:
        for word in self.words:
            if not word.assignment:
                return Path(word.text).name
        return ""


@dataclass(frozen=True, slots=True)
class ShellAst:
    """Immutable shell AST summary used in approval/effect binding."""

    commands: tuple[ShellCommandNode, ...]
    operators: tuple[str, ...]
    features: tuple[str, ...]

    def canonical(self) -> dict[str, object]:
        return {
            "commands": [
                {
                    "operator_before": command.operator_before,
                    "redirection": command.redirection,
                    "callback": command.callback,
                    "words": [
                        {
                            "text": word.text,
                            "literal": word.literal,
                            "quoted": word.quoted,
                            "assignment": word.assignment,
                        }
                        for word in command.words
                    ],
                }
                for command in self.commands
            ],
            "operators": list(self.operators),
            "features": list(self.features),
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.canonical(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ShellAnalysis:
    """Security decision derived from the complete shell AST."""

    status: ShellSemanticStatus
    read_only: bool
    requires_approval: bool
    reason: str
    ast: ShellAst
    blocked_executable: str = ""

    @property
    def semantic_digest(self) -> str:
        return self.ast.digest

    @property
    def executables(self) -> tuple[str, ...]:
        return tuple(
            command.executable for command in self.ast.commands if command.executable
        )


class ShellParseError(ValueError):
    """The input cannot be represented by the bounded shell AST."""


def analyze_shell_script(script: str, *, _depth: int = 0) -> ShellAnalysis:
    """Parse and classify a Bash/Zsh script without executing it.

    ``SAFE`` is deliberately hard to reach.  A valid script containing an
    unknown semantic feature is ``SEMANTIC_UNKNOWN`` and therefore requires
    approval.  A literal blocked executable remains ``BLOCKED`` so existing
    hard denials keep their fail-closed behavior.
    """

    if not isinstance(script, str) or not script.strip():
        ast = ShellAst((), (), ())
        return ShellAnalysis(
            ShellSemanticStatus.SAFE, True, False, "empty shell script", ast
        )
    if len(script.encode("utf-8")) > _MAX_SCRIPT_BYTES:
        ast = ShellAst((), (), ("script-size",))
        return ShellAnalysis(
            ShellSemanticStatus.SEMANTIC_UNKNOWN,
            False,
            True,
            "shell script exceeds semantic parser budget",
            ast,
        )
    if _depth > _MAX_PARSE_DEPTH:
        ast = ShellAst((), (), ("expansion-depth",))
        return ShellAnalysis(
            ShellSemanticStatus.SEMANTIC_UNKNOWN,
            False,
            True,
            "shell expansion nesting exceeds semantic parser budget",
            ast,
        )

    ast, nested_blocked = _parse(script, _depth)
    blocked = next(
        (
            command.executable
            for command in ast.commands
            if command.executable in BLOCKED_EXECUTABLES
        ),
        "",
    )
    if blocked or nested_blocked:
        return ShellAnalysis(
            ShellSemanticStatus.BLOCKED,
            False,
            True,
            f"blocked executable in shell graph: {blocked or 'nested command'}",
            ast,
            blocked,
        )

    unknown_features = set(ast.features)
    unknown_features.discard("comment")
    if unknown_features:
        return ShellAnalysis(
            ShellSemanticStatus.SEMANTIC_UNKNOWN,
            False,
            True,
            "shell semantic graph is not proven literal: "
            + ", ".join(sorted(unknown_features)),
            ast,
        )

    if not ast.commands:
        return ShellAnalysis(
            ShellSemanticStatus.SAFE, True, False, "no executable command", ast
        )

    for command in ast.commands:
        if not command.words:
            continue
        if command.redirection or command.callback:
            return ShellAnalysis(
                ShellSemanticStatus.SEMANTIC_UNKNOWN,
                False,
                True,
                "shell command has redirection or executable callback semantics",
                ast,
            )
        if any(not word.literal or word.assignment for word in command.words):
            return ShellAnalysis(
                ShellSemanticStatus.SEMANTIC_UNKNOWN,
                False,
                True,
                "shell command contains non-literal words or assignments",
                ast,
            )
        if not _command_is_literal_read_only(command):
            return ShellAnalysis(
                ShellSemanticStatus.SEMANTIC_UNKNOWN,
                False,
                True,
                f"argv semantic policy does not prove read-only: {command.executable}",
                ast,
            )

    return ShellAnalysis(
        ShellSemanticStatus.SAFE,
        True,
        False,
        "literal read-only executable graph",
        ast,
    )


def analyze_argv(argv: list[str] | tuple[str, ...]) -> ShellAnalysis:
    """Analyze an argv vector without applying shell expansion semantics."""

    words = tuple(
        ShellWord(str(item), literal=True, quoted=False)
        for item in argv
        if isinstance(item, str) and item
    )
    command = ShellCommandNode(words=words)
    ast = ShellAst((command,) if words else (), (), ())
    if not words:
        return ShellAnalysis(
            ShellSemanticStatus.SEMANTIC_UNKNOWN,
            False,
            True,
            "argv is empty",
            ast,
        )
    if command.executable in BLOCKED_EXECUTABLES:
        return ShellAnalysis(
            ShellSemanticStatus.BLOCKED,
            False,
            True,
            f"blocked executable: {command.executable}",
            ast,
            command.executable,
        )
    if _command_is_literal_read_only(command):
        return ShellAnalysis(
            ShellSemanticStatus.SAFE,
            True,
            False,
            "literal read-only argv policy",
            ast,
        )
    return ShellAnalysis(
        ShellSemanticStatus.SEMANTIC_UNKNOWN,
        False,
        True,
        f"argv semantic policy does not prove read-only: {command.executable}",
        ast,
    )


def _command_is_literal_read_only(command: ShellCommandNode) -> bool:
    """Apply command-specific argv policy after lexical proof.

    SAFE means the *complete argv semantics* are proven side-effect-free
    under the defined execution model — never merely that the executable
    or subcommand name looks read-only.
    """
    raw_word = next(
        (word.text for word in command.words if not word.assignment), ""
    )
    executable = command.executable
    # A path-qualified executable is NOT the system binary its basename
    # names: ``/workspace/ls`` must never inherit the read-only
    # classification of the system ``ls`` — only bare names, resolved
    # through the scrubbed trusted spawn PATH, may be classified.
    if raw_word != executable:
        return False
    if executable in MUTATING_EXECUTABLES or executable in SHELL_EVALUATORS:
        if executable == "git":
            return _git_argv_is_read_only(command)
        return False
    if executable == "find":
        return _find_argv_is_read_only(command)
    if executable not in READ_ONLY_EXECUTABLES:
        return False
    callback_args = {word.text.split("=", 1)[0] for word in command.words[1:]}
    return not bool(callback_args & CALLBACK_OPTIONS)


def _git_argv_is_read_only(command: ShellCommandNode) -> bool:
    """Prove a git argv is side-effect-free, subcommand by subcommand."""

    args = [word.text for word in command.words[1:]]
    if not args:
        return False
    # Global options precede the subcommand: everything before the first
    # non-option word must itself be option-shaped and non-forbidden.
    # (``-p``/``-c`` after the subcommand are subcommand options with
    # different meanings, e.g. ``git cat-file -p``.)
    subcommand_index = 0
    while subcommand_index < len(args) and args[subcommand_index].startswith("-"):
        option = args[subcommand_index].split("=", 1)[0]
        if option in _GIT_FORBIDDEN_GLOBALS:
            return False
        subcommand_index += 1
    if subcommand_index >= len(args):
        # Only options and no subcommand: unproven.
        return False
    subcommand = args[subcommand_index]
    rest = args[subcommand_index + 1 :]
    if subcommand == "branch":
        return _git_branch_argv_is_query_only(rest)
    if subcommand in {"status", "rev-parse", "ls-files"}:
        # Query commands with no forbidden globals and no output files.
        return not any(arg.startswith("--output") for arg in rest)
    if subcommand in {"diff", "log", "show"}:
        for arg in rest:
            option = arg.split("=", 1)[0]
            if option in _GIT_DIFF_FORBIDDEN:
                return False
        return True
    if subcommand == "cat-file":
        # --batch-command reads subcommands from stdin; all current
        # subcommands are reads, but stdin-driven command dispatch is a
        # semantic surface we do not model: stay unknown.
        return not any(arg.startswith("--batch-command") for arg in rest)
    return False


def _git_branch_argv_is_query_only(args: list[str]) -> bool:
    """``git branch`` is SAFE only as an explicit query/list invocation."""

    if not args:
        # Bare ``git branch`` lists local branches.
        return True
    saw_query_flag = False
    for arg in args:
        if arg.startswith("--"):
            option = arg.split("=", 1)[0]
            if option in _GIT_BRANCH_MUTATING_FLAGS:
                return False
            if option not in _GIT_BRANCH_QUERY_FLAGS:
                return False
            if option != "--show-current":
                saw_query_flag = True
            continue
        if arg.startswith("-") and len(arg) > 1:
            if arg in _GIT_BRANCH_MUTATING_FLAGS:
                return False
            if arg in _GIT_BRANCH_QUERY_FLAGS:
                saw_query_flag = True
                continue
            # Short-flag clusters like -av are fine when every letter is a
            # query letter (a=all, l=list, v=verbose, r=remotes, q=quiet).
            if len(arg) > 2 and all(
                letter in _GIT_BRANCH_SAFE_CLUSTER_LETTERS for letter in arg[1:]
            ):
                saw_query_flag = True
                continue
            return False
    # Positional arguments (branch names/patterns) are only a query when
    # an explicit list/query flag appears anywhere in the argv; bare
    # ``git branch foo`` creates a branch.
    positionals = [arg for arg in args if not arg.startswith("-")]
    return not (positionals and not saw_query_flag)


def _find_argv_is_read_only(command: ShellCommandNode) -> bool:
    """find(1) is SAFE only without executing or file-writing predicates."""

    args = {word.text.split("=", 1)[0] for word in command.words[1:]}
    return not bool(args & _FIND_FORBIDDEN)


def _parse(script: str, depth: int) -> tuple[ShellAst, bool]:
    commands: list[ShellCommandNode] = []
    operators: list[str] = []
    features: set[str] = set()
    words: list[ShellWord] = []
    current: list[str] = []
    current_literal = True
    current_quoted = False
    current_assignment = False
    current_redirection = False
    current_callback = False
    operator_before = ""
    nested_blocked = False
    heredoc_delimiter: str | None = None
    heredoc_pending = False
    i = 0
    word_start = True

    def flush_word() -> None:
        nonlocal current, current_literal, current_quoted, current_assignment
        nonlocal heredoc_delimiter, heredoc_pending, word_start
        if not current:
            return
        text = "".join(current)
        assignment = bool(_ASSIGNMENT_RE.match(text)) and not words
        words.append(ShellWord(text, current_literal, current_quoted, assignment))
        if heredoc_pending and heredoc_delimiter is None:
            heredoc_delimiter = text
            heredoc_pending = False
        current = []
        current_literal = True
        current_quoted = False
        current_assignment = False
        word_start = True

    def flush_command() -> None:
        nonlocal words, operator_before, current_redirection, current_callback
        if words:
            current_callback = current_callback or any(
                word.text.split("=", 1)[0] in CALLBACK_OPTIONS
                for word in words[1:]
            )
            if current_callback:
                features.add("executable-callback")
            commands.append(
                ShellCommandNode(
                    tuple(words),
                    operator_before,
                    current_redirection,
                    current_callback,
                )
            )
        words = []
        operator_before = ""
        current_redirection = False
        current_callback = False

    def mark_unknown(feature: str) -> None:
        features.add(feature)

    while i < len(script):
        if heredoc_delimiter is not None:
            # A here-document body is data, not an executable command graph.
            # Skip complete lines until the delimiter; the entire construct is
            # still unknown because its expansion/IO semantics are not trusted.
            newline = script.find("\n", i)
            end = len(script) if newline < 0 else newline
            line = script[i:end].rstrip("\r")
            if line == heredoc_delimiter or line == "-" + heredoc_delimiter:
                heredoc_delimiter = None
            i = len(script) if newline < 0 else newline + 1
            continue

        char = script[i]
        nxt = script[i + 1] if i + 1 < len(script) else ""

        if char == "\\":
            if not nxt:
                mark_unknown("trailing-escape")
                i += 1
                continue
            current.append(nxt)
            current_quoted = True
            word_start = False
            i += 2
            continue
        if char == "'":
            end = _find_single_quote(script, i + 1)
            if end < 0:
                mark_unknown("unterminated-single-quote")
                break
            current_quoted = True
            current.extend(script[i + 1 : end])
            word_start = False
            i = end + 1
            continue
        if char == '"':
            end, quote_features, blocked = _consume_double_quote(script, i + 1, depth)
            features.update(quote_features)
            nested_blocked = nested_blocked or blocked
            if end < 0:
                mark_unknown("unterminated-double-quote")
                break
            current_quoted = True
            current_literal = current_literal and not quote_features
            current.extend(script[i + 1 : end])
            word_start = False
            i = end + 1
            continue
        if char in " \t\r":
            flush_word()
            i += 1
            continue
        if char == "\n":
            flush_word()
            if heredoc_delimiter is not None:
                i += 1
                continue
            flush_command()
            operators.append("newline")
            operator_before = "newline"
            i += 1
            word_start = True
            continue
        if char == "#" and word_start:
            features.add("comment")
            newline = script.find("\n", i)
            i = len(script) if newline < 0 else newline
            continue

        substitution = _consume_expansion(script, i, depth)
        if substitution is not None:
            consumed, expansion_features, blocked = substitution
            features.update(expansion_features)
            nested_blocked = nested_blocked or blocked
            current_literal = False
            current.extend(script[i : i + consumed])
            word_start = False
            i += consumed
            continue

        if char == "`":
            end = _find_backtick(script, i + 1)
            mark_unknown("command-substitution")
            nested = script[i + 1 : end] if end >= 0 else ""
            if nested:
                nested_blocked = nested_blocked or (
                    analyze_shell_script(nested, _depth=depth + 1).status
                    is ShellSemanticStatus.BLOCKED
                )
            current_literal = False
            current.extend(script[i : end + 1] if end >= 0 else script[i:])
            word_start = False
            i = len(script) if end < 0 else end + 1
            continue

        operator, operator_length = _operator_at(script, i)
        if operator:
            flush_word()
            operators.append(operator)
            if operator.startswith(("<", ">")) or operator in {"&>", "&>>"}:
                current_redirection = True
                mark_unknown("redirection")
                if operator.startswith("<<"):
                    heredoc_pending = True
                    mark_unknown("heredoc")
            elif operator in {"(", ")"}:
                mark_unknown("subshell")
            elif operator in {";;", ";&", ";;&"}:
                mark_unknown("compound-command")
            if operator in {"<(", ">("}:
                mark_unknown("process-substitution")
            if operator not in {"<", ">", ">>", "<>", "|", "|&", "||", "&&", ";", "&", "\n"}:
                mark_unknown("shell-operator")
            if operator in {"|", "|&", "||", "&&", ";", "&"}:
                flush_command()
                operator_before = operator
            i += operator_length
            word_start = True
            continue

        if char in "*?[":
            mark_unknown("glob-expansion")
            current_literal = False
        elif char == "{" or char == "}":
            mark_unknown("brace-expansion")
            current_literal = False
        elif char == "~" and word_start:
            mark_unknown("tilde-expansion")
            current_literal = False
        if char == "=" and current and not words:
            current_assignment = True
            mark_unknown("environment-assignment")
        current.append(char)
        word_start = False
        i += 1

    flush_word()
    flush_command()
    if heredoc_delimiter is not None:
        mark_unknown("unterminated-heredoc")
    ast = ShellAst(tuple(commands), tuple(operators), tuple(sorted(features)))
    return ast, nested_blocked


def _operator_at(script: str, index: int) -> tuple[str, int]:
    for operator in (
        "<<<",
        "&>>",
        "<<-",
        ">>&",
        "<(",
        ">(",
        "&&",
        "||",
        "|&",
        ">>",
        "<<",
        "<>",
        ">&",
        "<&",
        ">|",
        ";;&",
        ";;",
        ";&",
    ):
        if script.startswith(operator, index):
            return operator, len(operator)
    if script[index] in "|;&()<>":
        return script[index], 1
    return "", 0


def _find_single_quote(script: str, start: int) -> int:
    return script.find("'", start)


def _find_backtick(script: str, start: int) -> int:
    index = start
    while index < len(script):
        if script[index] == "\\":
            index += 2
            continue
        if script[index] == "`":
            return index
        index += 1
    return -1


def _consume_double_quote(
    script: str, start: int, depth: int
) -> tuple[int, set[str], bool]:
    index = start
    features: set[str] = set()
    nested_blocked = False
    while index < len(script):
        char = script[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index, features, nested_blocked
        expansion = _consume_expansion(script, index, depth)
        if expansion is not None:
            consumed, found, blocked = expansion
            features.update(found)
            nested_blocked = nested_blocked or blocked
            index += consumed
            continue
        if char == "`":
            features.add("command-substitution")
            end = _find_backtick(script, index + 1)
            if end >= 0:
                nested_blocked = nested_blocked or (
                    analyze_shell_script(script[index + 1 : end], _depth=depth + 1).status
                    is ShellSemanticStatus.BLOCKED
                )
                index = end + 1
            else:
                return -1, features, nested_blocked
            continue
        index += 1
    return -1, features, nested_blocked


def _consume_expansion(
    script: str, index: int, depth: int
) -> tuple[int, set[str], bool] | None:
    if script[index] != "$" or index + 1 >= len(script):
        return None
    if script.startswith("$((", index):
        end = _matching_delimiter(script, index + 2, "(", ")")
        return (end + 1 if end >= 0 else len(script) - index), {"arithmetic-expansion"}, False
    if script.startswith("$(", index):
        end = _matching_delimiter(script, index + 1, "(", ")")
        inner = script[index + 2 : end] if end >= 0 else ""
        blocked = bool(
            inner
            and analyze_shell_script(inner, _depth=depth + 1).status
            is ShellSemanticStatus.BLOCKED
        )
        return (end + 1 if end >= 0 else len(script) - index), {"command-substitution"}, blocked
    if script.startswith("${", index):
        end = _matching_delimiter(script, index + 1, "{", "}")
        return (end + 1 if end >= 0 else len(script) - index), {"parameter-expansion"}, False
    next_char = script[index + 1]
    if next_char in "@$?*!#-0123456789":
        return 2, {"parameter-expansion"}, False
    if _VARIABLE_RE.match(script, index + 1):
        match = _VARIABLE_RE.match(script, index + 1)
        assert match is not None
        return match.end() - index, {"parameter-expansion"}, False
    return None


def _matching_delimiter(script: str, start: int, opening: str, closing: str) -> int:
    depth = 1
    index = start + 1
    quote = ""
    while index < len(script):
        char = script[index]
        if char == "\\":
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
        elif char == opening:
            depth += 1
        elif char == closing:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1
