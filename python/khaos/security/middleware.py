"""Security middleware that wraps tool execution with safety checks.

Orchestrates CommandGuard, PathGuard, SecretScanner into a unified
pre-execution / post-execution pipeline that ToolScheduler calls.

When a :class:`SandboxPolicy` is supplied, its lists are merged into the
existing guards so behaviour stays backward-compatible: policy-denied paths
extend PathGuard's protected set, policy-blocked commands extend
CommandGuard's blocked set, and ``secrets_scan_on_output`` gates the
post-execution secret scan.

B1/M1: when an ``EffectiveSecurityPolicy`` is supplied (the production
path), it is the single source of truth — its denied_paths, commands_blocked,
secrets_scan_on_output and ``digest`` drive the middleware, and the digest
is exposed so the scheduler can bind it into every approval decision.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from khaos.security.command_guard import CommandGuard
from khaos.security.path_guard import PathGuard
from khaos.security.secret_scanner import ScanResult, SecretScanner

if TYPE_CHECKING:
    from khaos.audit.logger import AuditLogger
    from khaos.security.effective_policy import EffectiveSecurityPolicy
    from khaos.security.network_guard import NetworkGuard
    from khaos.security.policy import SandboxPolicy
    from khaos.security.sandbox import Sandbox

logger = logging.getLogger(__name__)

COMMAND_TOOLS = frozenset({"terminal", "process", "test_run"})
READ_PATH_TOOLS = frozenset({
    "read_file", "search_files", "file_info", "list_directory", "tree_view",
    "file_search_content",
})
READ_PATH_PARAMS = frozenset({"path", "root"})
WRITE_PATH_TOOLS = frozenset({"write_file", "patch", "multi_edit", "copy_file", "move_file"})
WRITE_PATH_PARAMS = frozenset({"path", "file_path", "src", "dst"})

# M1: command forms that dump the process environment — the most common
# source of API key / token leakage.  ``export -p`` and ``declare -p`` print
# every exported variable; ``set`` with no args prints every variable
# (including non-exported).  ``env`` / ``printenv`` are the obvious ones.
# Each entry is matched as a *whole base command* (first token) OR as a
# base+flag combination so ``env -i`` (intentional empty env) is allowed
# while bare ``env`` is blocked.
_ENV_DUMP_BASE_COMMANDS = frozenset({"env", "printenv"})
_ENV_DUMP_SUBCOMMANDS = frozenset({"set", "export", "declare"})

# M1: tool arguments whose values are scanned for secrets BEFORE the tool
# executes (secrets_scan_before_tool_result).  These are the parameters most
# likely to carry an accidental secret: command strings, file contents,
# URLs, JS expressions, search patterns, and patch text.
_SECRET_SCAN_ARG_KEYS = frozenset({
    "command", "text", "content", "url", "expression",
    "pattern", "old", "new", "message", "query",
})


@dataclass
class SecurityCheckResult:
    """统一安全检查结果。"""

    allowed: bool
    risk_level: str
    reason: str = ""
    check_type: str = ""
    original_result: Any = None


class SecurityMiddleware:
    """工具执行的安全中间件。"""

    def __init__(
        self,
        command_guard: CommandGuard | None = None,
        path_guard: PathGuard | None = None,
        secret_scanner: SecretScanner | None = None,
        enabled: bool = True,
        policy: "SandboxPolicy | None" = None,
        sandbox: "Sandbox | None" = None,
        network_guard: "NetworkGuard | None" = None,
        audit_logger: "AuditLogger | None" = None,
        *,
        effective_policy: "EffectiveSecurityPolicy | None" = None,
    ):
        self.command_guard = command_guard or CommandGuard()
        self.path_guard = path_guard or PathGuard()
        self.secret_scanner = secret_scanner or SecretScanner()
        self.enabled = enabled
        self.policy = policy
        self.sandbox = sandbox
        self.network_guard = network_guard
        self.audit_logger = audit_logger
        # B1: the effective policy is the compiled user ∩ project ∩ platform
        # intersection.  When present, it (not the raw project policy) drives
        # denied_paths / commands_blocked / secrets_scan_on_output, and its
        # digest is exposed for approval binding (M1).
        self.effective_policy = effective_policy
        # secrets_scan_on_output: prefer the effective policy, then the raw
        # policy, then the default (True).
        if effective_policy is not None:
            self._scan_on_output = effective_policy.secrets_scan_on_output
        elif policy is not None:
            self._scan_on_output = policy.secrets_scan_on_output
        else:
            self._scan_on_output = True
        # M1: secrets_scan_before_tool_result — scan tool arguments BEFORE
        # execution so a tool call that would exfiltrate secrets (e.g. a
        # ``web_fetch`` URL containing a token, a ``terminal`` command
        # containing an API key, a ``write_file`` whose content includes a
        # private key) is blocked before the side effect happens.  OR
        # semantics: the effective policy wins; otherwise the raw policy;
        # otherwise the safe default (True).
        if effective_policy is not None:
            self._scan_before_tool_result = (
                effective_policy.secrets_scan_before_tool_result
            )
        elif policy is not None:
            self._scan_before_tool_result = (
                policy.secrets_scan_before_tool_result
            )
        else:
            self._scan_before_tool_result = True
        # M1: secrets_block_env_dump — block terminal commands that dump the
        # process environment (``env``, ``printenv``, ``set``, ``export -p``)
        # because the environment is the most common place API keys / tokens
        # leak from.  Same OR-semantics source chain as above.
        if effective_policy is not None:
            self._block_env_dump = effective_policy.secrets_block_env_dump
        elif policy is not None:
            self._block_env_dump = policy.secrets_block_env_dump
        else:
            self._block_env_dump = True
        # Merge policy lists into the existing guards so the detection layer
        # also enforces the policy's extra denials (defense in depth).
        # B1: prefer effective_policy; fall back to raw policy for callers
        # that haven't been migrated yet.
        source_policy = self._merge_source_policy()
        if source_policy is not None:
            self._apply_policy(source_policy)

    @property
    def effective_policy_digest(self) -> str:
        """Stable digest of the effective policy (M1).

        Empty string when no effective policy is compiled (e.g. ad-hoc
        middleware in tests).  The scheduler includes this in every
        approval ``profile_digest`` so an approval is provably bound to the
        exact policy under which it was made.
        """
        if self.effective_policy is not None:
            return self.effective_policy.digest
        return ""

    def _merge_source_policy(self) -> "SandboxPolicy | None":
        """Return the policy whose denied_paths / commands_blocked to merge.

        B1: when an effective policy is present, we synthesise a lightweight
        ``SandboxPolicy`` view from its fields so ``_apply_policy`` can
        reuse its existing merge logic without needing a separate code path.

        M1: ``commands_allowed`` is also threaded through so the production
        CommandGuard actually receives the policy's command allow-list —
        previously the effective policy compiled it into its digest but
        SecurityMiddleware dropped it on the floor, leaving
        ``CommandGuard._allowed_commands`` at its default ``None`` (no
        whitelist enforcement at all).

        H2: ``commands_allowed`` is preserved in three-state form:
        ``None`` (no allow-list configured) stays ``None``; an empty
        frozenset becomes an empty list (deny all); a non-empty frozenset
        becomes the corresponding list.  This preserves the distinction
        that ``_apply_policy`` relies on.
        """
        if self.effective_policy is not None:
            from khaos.security.policy import SandboxPolicy

            ep = self.effective_policy
            return SandboxPolicy(
                denied_paths=list(ep.denied_paths),
                commands_allowed=(
                    list(ep.commands_allowed)
                    if ep.commands_allowed is not None
                    else None
                ),
                commands_blocked=list(ep.commands_blocked),
            )
        return self.policy

    def _apply_policy(self, policy: "SandboxPolicy") -> None:
        """Merge policy lists into the existing guards (additive, instance-level)."""
        # Extend PathGuard's protected set with policy-denied paths.
        if policy.denied_paths:
            extra = frozenset(
                str(path)
                for path in policy.denied_paths
                if path and path != "."
            )
            if extra:
                existing = getattr(self.path_guard, "_protected", frozenset())
                self.path_guard._protected = existing | extra
        # Rebuild CommandGuard when the policy introduces an allow-list OR
        # a block-list.  Done instance-level (extra_blocked) — never mutates
        # the module global, so one middleware's policy can't leak into
        # another guard.
        #
        # H2: three-state ``commands_allowed``:
        #   * ``None``  → layer does not configure an allow-list; preserve
        #                 the guard's existing ``_allowed_commands`` (which
        #                 may itself be ``None`` = no whitelist).
        #   * ``[]``    → layer explicitly denies all commands; install an
        #                 empty frozenset so every base command is rejected.
        #   * non-empty → layer whitelists these base commands; install the
        #                 frozenset.
        allowed_raw = policy.commands_allowed
        blocked_list = [c for c in (policy.commands_blocked or []) if c]
        need_rebuild = allowed_raw is not None or bool(blocked_list)
        if need_rebuild:
            if allowed_raw is None:
                # Only block-list configured; preserve existing whitelist.
                new_allowed = self.command_guard._allowed_commands
            else:
                # Explicit allow-list (possibly empty = deny all).
                new_allowed = frozenset(c for c in allowed_raw if c)
            self.command_guard = CommandGuard(
                block_dangerous=self.command_guard.block_dangerous,
                confirm_risky=self.command_guard.confirm_risky,
                allowed_commands=new_allowed,
                extra_blocked=frozenset(blocked_list),
            )

    async def pre_check(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """工具执行前的安全检查。

        检查顺序（优先级从高到低）：
        sandbox capability → network → command → path write → path read。

        当任何检查拦截时，若有 ``audit_logger``，自动记录一条安全事件。
        """
        result = self._run_checks(tool_name, arguments)
        # Record security events for blocks, so denials are queryable/exportable.
        if not result.allowed and self.audit_logger is not None:
            try:
                await self.audit_logger.log_security_event(
                    event_type=result.check_type or "blocked",
                    tool_name=tool_name,
                    reason=result.reason,
                    detail={
                        "risk_level": result.risk_level,
                        "arguments_keys": list(arguments.keys()),
                    },
                )
            except Exception as exc:  # noqa: BLE001 — audit must never block enforcement
                logger.warning("security event audit failed: %s", exc)
        return result

    def _run_checks(self, tool_name: str, arguments: dict) -> SecurityCheckResult:
        """Run the actual check pipeline (no side effects)."""
        if not self.enabled:
            return SecurityCheckResult(allowed=True, risk_level="safe")

        # 沙箱 capability 检查（优先级最高）
        if self.sandbox is not None:
            sandbox_result = self.sandbox.check_tool(tool_name)
            if not sandbox_result.allowed:
                return SecurityCheckResult(
                    allowed=False,
                    risk_level="blocked",
                    reason=sandbox_result.reason,
                    check_type="sandbox",
                )
            if tool_name in WRITE_PATH_TOOLS:
                for param in WRITE_PATH_PARAMS:
                    path = arguments.get(param, "")
                    if not path:
                        continue
                    sandbox_path = self.sandbox.check_write_path(str(path))
                    if not sandbox_path.allowed:
                        return SecurityCheckResult(
                            allowed=False,
                            risk_level="blocked",
                            reason=sandbox_path.reason,
                            check_type="sandbox_path",
                        )
            if tool_name in READ_PATH_TOOLS:
                for param in READ_PATH_PARAMS:
                    path = arguments.get(param, "")
                    if not path:
                        continue
                    sandbox_path = self.sandbox.check_read_path(str(path))
                    if not sandbox_path.allowed:
                        return SecurityCheckResult(
                            allowed=False,
                            risk_level="blocked",
                            reason=sandbox_path.reason,
                            check_type="sandbox_path",
                        )

        # 网络访问检查
        if self.network_guard is not None:
            net_result = self.network_guard.check_tool(tool_name, arguments)
            if not net_result.allowed:
                return SecurityCheckResult(
                    allowed=False,
                    risk_level="blocked",
                    reason=net_result.reason,
                    check_type="network",
                )

        if tool_name in COMMAND_TOOLS:
            command = str(arguments.get("command", ""))
            if command:
                # M1: block environment-dump commands when the policy
                # requires it (secrets_block_env_dump).  These commands
                # print every exported environment variable — the most
                # common source of API key / token leakage.  ``env -i``
                # (intentional empty env) and ``printenv VAR`` (specific
                # var) are allowed; bare ``env`` / ``printenv`` / ``set``
                # / ``export -p`` / ``declare -p`` are blocked.
                if self._block_env_dump and _is_env_dump_command(command):
                    return SecurityCheckResult(
                        allowed=False,
                        risk_level="blocked",
                        reason=(
                            "environment-dump command blocked by "
                            "secrets_block_env_dump policy (would print "
                            "process environment which may contain secrets)"
                        ),
                        check_type="env_dump",
                    )
                result = self.command_guard.check(command)
                if result.risk_level in {"dangerous", "blocked"}:
                    return SecurityCheckResult(
                        allowed=False,
                        risk_level=result.risk_level,
                        reason=result.reason,
                        check_type="command",
                        original_result=result,
                    )
                if result.risk_level == "risky":
                    logger.warning("Risky command: %s - %s", command, result.reason)

        # M1: pre-execution secret scan of tool arguments
        # (secrets_scan_before_tool_result).  Scans the values of the
        # arguments most likely to carry an accidental secret — command
        # strings, file contents, URLs, JS expressions, search patterns,
        # patch text — and blocks the tool call BEFORE the side effect
        # happens.  This is the symmetric counterpart of the post-execution
        # ``secrets_scan_on_output`` scan.
        if self.enabled and self._scan_before_tool_result and self.secret_scanner is not None:
            secret_hit = self._scan_arguments_for_secrets(tool_name, arguments)
            if secret_hit is not None:
                return secret_hit

        if tool_name in WRITE_PATH_TOOLS:
            for param in WRITE_PATH_PARAMS:
                path = arguments.get(param, "")
                if path:
                    result = self.path_guard.check_write(str(path))
                    if not result.safe:
                        return SecurityCheckResult(
                            allowed=False,
                            risk_level=result.risk_level,
                            reason=result.reason,
                            check_type="path_write",
                            original_result=result,
                        )

        if tool_name in READ_PATH_TOOLS:
            path = str(arguments.get("path", "") or arguments.get("root", ""))
            if path:
                result = self.path_guard.check_read(path)
                if not result.safe:
                    return SecurityCheckResult(
                        allowed=False,
                        risk_level=result.risk_level,
                        reason=result.reason,
                        check_type="path_read",
                        original_result=result,
                    )

        return SecurityCheckResult(allowed=True, risk_level="safe")

    async def post_check(self, tool_name: str, output: Any) -> tuple[ScanResult, Any]:
        """Scan and redact tool output before it reaches model context."""
        if not self.enabled or not self._scan_on_output or self.secret_scanner is None:
            return ScanResult(has_secrets=False), output

        text = ""
        if isinstance(output, str):
            text = output
        elif isinstance(output, dict):
            text = str(output)
        result = self.secret_scanner.scan_text(text)
        if not result.has_secrets:
            return result, output

        def redact(value: Any) -> Any:
            if isinstance(value, str):
                sanitized = value
                if any(secret.category == "Private Key" for secret in result.secrets):
                    sanitized = re.sub(
                        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
                        "[REDACTED PRIVATE KEY]",
                        sanitized,
                        flags=re.DOTALL,
                    )
                for secret in result.secrets:
                    sanitized = sanitized.replace(secret.matched_text, secret.masked)
                return sanitized
            if isinstance(value, dict):
                return {key: redact(item) for key, item in value.items()}
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value

        logger.warning("secret detected and redacted in %s output", tool_name)
        return result, redact(output)

    def _scan_arguments_for_secrets(
        self, tool_name: str, arguments: dict
    ) -> "SecurityCheckResult | None":
        """M1: scan tool arguments for secrets before execution.

        Returns a blocking ``SecurityCheckResult`` if a secret is found in
        any of the scanned argument values, or ``None`` if the arguments
        are clean.  Only the argument keys in ``_SECRET_SCAN_ARG_KEYS``
        are scanned — these are the parameters most likely to carry an
        accidental secret (command strings, file contents, URLs, JS
        expressions, search patterns, patch text).

        The scan uses the same ``SecretScanner`` as the post-execution
        scan so the detection vocabulary is identical.
        """
        for key in _SECRET_SCAN_ARG_KEYS:
            value = arguments.get(key)
            if not isinstance(value, str) or not value:
                continue
            scan = self.secret_scanner.scan_text(value)
            if scan.has_secrets:
                categories = sorted({s.category for s in scan.secrets})
                return SecurityCheckResult(
                    allowed=False,
                    risk_level="blocked",
                    reason=(
                        f"secret detected in tool argument {key!r} "
                        f"(categories: {categories}); tool call blocked "
                        f"by secrets_scan_before_tool_result policy"
                    ),
                    check_type="secret_in_arguments",
                )
        return None


def _is_env_dump_command(command: str) -> bool:
    """M1: return True if ``command`` would dump the process environment.

    Blocks:
    * ``env`` / ``printenv`` with no arguments (prints every exported var);
    * ``set`` with no arguments (prints every variable, including non-exported);
    * ``export -p`` / ``declare -p`` / ``declare -xp`` (print exported vars).

    Allows:
    * ``env -i cmd`` / ``env VAR=val cmd`` (intentional env manipulation);
    * ``printenv VAR`` (specific var — already known to the caller);
    * ``export VAR=val`` (assignment, not dump).
    """
    parts = command.strip().split()
    if not parts:
        return False
    base = parts[0]
    # ``env`` / ``printenv`` with no further args → dump everything.
    if base in _ENV_DUMP_BASE_COMMANDS and len(parts) == 1:
        return True
    # ``printenv`` with args prints specific vars → allow (caller already
    # knows the var name).  ``env`` with args is env manipulation → allow.
    # ``set`` / ``export`` / ``declare`` with NO args → dump everything.
    if base in _ENV_DUMP_SUBCOMMANDS and len(parts) == 1:
        return True
    # ``export -p`` / ``declare -p`` / ``declare -xp`` → print exported.
    if base in {"export", "declare"} and len(parts) == 2 and parts[1] in {"-p", "-xp", "-px"}:
        return True
    return False
