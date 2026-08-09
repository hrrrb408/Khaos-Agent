"""Final environment scrubbing for every model-reachable subprocess."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping

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


def is_non_inheritable_secret_key(
    key: str, *, preserve: Iterable[str] = ()
) -> bool:
    """Return whether ``key`` must not cross an untrusted spawn boundary."""
    if key in preserve:
        return False
    upper = key.upper()
    return (
        key in NON_INHERITABLE_SECRET_ENV
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
        if not is_non_inheritable_secret_key(key, preserve=preserved)
    }
