"""Final environment scrubbing for every model-reachable subprocess."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Mapping

_PINNED_GIT_CONFIG_SUPPRESSIONS = frozenset(
    {"GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"}
)

# Git reinterprets these variables as configuration or executable hooks:
# GIT_EXTERNAL_DIFF runs an arbitrary helper for `git diff`, the
# GIT_CONFIG_KEY_n/GIT_CONFIG_VALUE_n pairs enumerate inline `-c` config,
# and GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE/GIT_OBJECT_DIRECTORY retarget
# which repository the command operates on.  None of them may cross an
# untrusted spawn boundary, or a SAFE-classified read-only git command's
# real executable graph silently diverges from its classified argv.
GIT_SEMANTIC_ENV = frozenset(
    {
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "PAGER",
        "GIT_CONFIG_COUNT",
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    }
)
_GIT_SEMANTIC_PREFIXES = ("GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_")

# Exact names cover provider credentials, local capability handles, credential
# stores, and transport endpoints that are commonly present in a developer
# shell.  The suffix rules below cover provider-specific names without
# requiring the execution layer to know every integration in advance.
NON_INHERITABLE_SECRET_ENV = frozenset(
    {
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_SECURITY_TOKEN",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CONFIG_FILE",
        "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET",
        "AZURE_TENANT_ID",
        "AZURE_SUBSCRIPTION_ID",
        "DOCKER_CONFIG",
        "DOCKER_HOST",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GITLAB_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "GOOGLE_OAUTH_ACCESS_TOKEN",
        "KHAOS_GATEWAY_CAPABILITY",
        "KHAOS_PYTHON_CAPABILITY",
        "KHAOS_PYTHON_CAPABILITY_FD",
        "KHAOS_AGENT_CAPABILITY",
        "KUBECONFIG",
        "NETRC",
        "NPM_CONFIG_USERCONFIG",
        "PIP_CONFIG_FILE",
        "SSH_AGENT_PID",
        "SSH_AUTH_SOCK",
        "GIT_SSH_COMMAND",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "AUTHORIZATION",
        "PROXY_AUTHORIZATION",
        "COOKIE",
        "COOKIE_HEADER",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
    }
)

_SECRET_SUFFIXES = (
    "_API_KEY",
    "_TOKEN",
    "_SECRET",
    "_PASSWORD",
    "_PASSWD",
    "_PASSPHRASE",
    "_CREDENTIALS",
    "_PRIVATE_KEY",
    "_ACCESS_KEY",
)
_SECRET_NAME = re.compile(
    r"(?:^|_)(?:APIKEY|TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|"
    r"CREDENTIALS|PRIVATE_KEY|ACCESS_KEY)(?:$|_)",
    re.IGNORECASE,
)

TASK_ENVIRONMENT_KEYS = frozenset(
    {
        # Go fixtures and repositories without a go.mod need the standard
        # module-mode switch for a bounded ``go test`` invocation.  It is a
        # non-secret build setting, unlike credential/proxy variables.
        "GO111MODULE",
        "PATH",
        "PYTHONDONTWRITEBYTECODE",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "SHELL",
        "VIRTUAL_ENV",
        "CONDA_PREFIX",
        "PWD",
        "OLDPWD",
        "CI",
        "GITHUB_ACTIONS",
        "DOCKER_CONTAINER",
    }
)

_ENV_ASSIGNMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def split_command_environment(
    argv: tuple[str, ...],
) -> tuple[dict[str, str], tuple[str, ...]]:
    """Split a leading ``NAME=value`` prefix without invoking a shell.

    Test and terminal commands are model-controlled argv, not shell scripts.
    Supporting the POSIX assignment prefix here preserves that no-shell
    boundary while allowing common build commands such as
    ``GO111MODULE=off go test`` to be represented in the immutable spawn
    authority and the final child environment.
    """
    assignments: dict[str, str] = {}
    index = 0
    while index < len(argv):
        token = argv[index]
        if not isinstance(token, str) or "\x00" in token:
            raise ValueError("command argv contains an invalid environment prefix")
        name, separator, value = token.partition("=")
        if not separator or _ENV_ASSIGNMENT_NAME.fullmatch(name) is None:
            break
        if is_non_inheritable_secret_key(name):
            raise PermissionError(
                f"environment assignment is not permitted for protected key: {name}"
            )
        if name in assignments:
            raise ValueError(f"duplicate environment assignment: {name}")
        assignments[name] = value
        index += 1
    command = argv[index:]
    if not command:
        raise ValueError("environment assignment prefix has no command")
    return assignments, command


def validate_command_environment(
    assignments: Mapping[str, str],
    *,
    allowed_keys: Iterable[str],
) -> None:
    """Fail closed when a command prefix requests an unapproved env key."""
    allowed = frozenset(allowed_keys)
    for key, value in assignments.items():
        if (
            key not in allowed
            or not isinstance(value, str)
            or "\x00" in value
            or is_non_inheritable_secret_key(key)
        ):
            raise PermissionError(
                f"environment assignment is outside the approved task contract: {key}"
            )


def is_non_inheritable_secret_key(
    key: str, *, preserve: Iterable[str] = ()
) -> bool:
    """Return whether ``key`` must not cross an untrusted spawn boundary."""
    if key in preserve:
        return False
    upper = key.upper()
    return (
        key in NON_INHERITABLE_SECRET_ENV
        or key in GIT_SEMANTIC_ENV
        or upper.startswith(_GIT_SEMANTIC_PREFIXES)
        or upper.endswith(_SECRET_SUFFIXES)
        or _SECRET_NAME.search(upper) is not None
    )


def scrub_spawn_environment(
    environment: Mapping[str, str], *, preserve: Iterable[str] = ()
) -> dict[str, str]:
    """Copy ``environment`` while removing secrets and launch capabilities.

    The input is never mutated.  ``preserve`` is only for a trusted outer
    launcher contract whose metadata is consumed and stripped before the
    final model-controlled child (for example the browser kernel launcher).
    Normal execution paths should use the default empty set.
    """
    preserved = frozenset(preserve)
    return {
        key: value
        for key, value in environment.items()
        if (
            key in _PINNED_GIT_CONFIG_SUPPRESSIONS
            and value == os.devnull
        )
        or not is_non_inheritable_secret_key(key, preserve=preserved)
    }


def environment_from_spawn_plan(spawn_plan: object | None) -> dict[str, str]:
    """Materialize the immutable, non-secret environment in a spawn plan.

    Process-backed tool handlers receive the plan from the scheduler after
    approval.  Reconstructing the request environment from that plan keeps
    executable resolution, sandbox setup, and the approved identity bound to
    the same values.  A handler must not silently fall back to its own parent
    environment when a plan is present.
    """
    if spawn_plan is None:
        return {}
    pairs = getattr(spawn_plan, "environment", None)
    if type(pairs) is not tuple:
        raise PermissionError("resolved spawn plan environment is malformed")
    environment: dict[str, str] = {}
    for pair in pairs:
        if (
            type(pair) is not tuple
            or len(pair) != 2
            or type(pair[0]) is not str
            or type(pair[1]) is not str
            or not pair[0]
            or "\x00" in pair[0]
            or "\x00" in pair[1]
            or is_non_inheritable_secret_key(pair[0])
        ):
            raise PermissionError("resolved spawn plan environment is unsafe")
        if pair[0] in environment:
            raise PermissionError("resolved spawn plan environment has duplicate keys")
        environment[pair[0]] = pair[1]
    if tuple(sorted(environment.items())) != pairs:
        raise PermissionError("resolved spawn plan environment is not canonical")
    return environment


def build_task_environment(
    *,
    home: str,
    tmpdir: str,
    base_environment: Mapping[str, str] | None = None,
    allowed_keys: Iterable[str] = TASK_ENVIRONMENT_KEYS,
) -> dict[str, str]:
    """Build a child environment with synthetic HOME/TMP and no credentials.

    ``base_environment`` is injectable for deterministic tests.  Production
    callers may omit it to snapshot the parent environment, but only the
    small allowlist crosses into the task and all provider/API credential
    names are removed again by :func:`scrub_spawn_environment`.
    """
    if not isinstance(home, str) or not home or "\x00" in home:
        raise ValueError("task HOME is invalid")
    if not isinstance(tmpdir, str) or not tmpdir or "\x00" in tmpdir:
        raise ValueError("task TMPDIR is invalid")
    source = base_environment if base_environment is not None else os.environ
    allowed = frozenset(allowed_keys)
    environment = {
        key: value
        for key, value in source.items()
        if key in allowed and isinstance(value, str) and "\x00" not in value
    }
    environment.setdefault("PATH", os.defpath)
    if "PYTHONDONTWRITEBYTECODE" in allowed:
        # Python tooling must not turn an otherwise clean task workspace into
        # an untracked-change set before the pre-edit checkpoint.  This is a
        # runtime hygiene contract, not a request-controlled value.
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["HOME"] = home
    environment["TMPDIR"] = tmpdir
    environment["TMP"] = tmpdir
    environment["TEMP"] = tmpdir
    return scrub_spawn_environment(environment)
