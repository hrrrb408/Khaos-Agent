"""Permission rules, target normalization, and audit logging."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import shlex
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from urllib.parse import urlparse

from khaos.exceptions import PermissionDeniedError
from khaos.permissions.resource import AuthorizationResource

logger = logging.getLogger(__name__)


# Round-14 §7 / Round-15 A-4: tools that can invoke a shell command and
# therefore must respect ``commands_require_approval``.  Used as the default
# for ``PermissionEngine.exec_tool_names`` when the runtime does not derive
# the set from the live ``ToolRegistry``.  The runtime factory passes the
# registry-derived ``permission_level == "execute"`` set so a newly added
# exec-style tool is gated automatically instead of bypassing the policy
# approval requirement.
#
# Round-15 A-4: this default MUST track every tool the registry registers
# with ``permission_level == "execute"`` (registry.py), otherwise a non-
# factory PermissionEngine (CLI / admin adapter / library caller / future
# runtime) silently under-gates the missing tools.  ``sandbox_exec`` runs
# arbitrary commands inside Docker and ``sandbox_build`` builds images; both
# are ``permission_level="execute"`` and must be gated.
_DEFAULT_EXEC_TOOLS = frozenset({
    "terminal", "terminal_argv", "terminal_shell", "process",
    "sandbox_exec", "sandbox_build",
})


class ApprovalMode(Enum):
    """Supported permission approval policies."""

    AUTO_APPROVE = "auto-approve"
    SUGGEST = "suggest"
    ASK_EVERY = "ask-every"
    DENY = "deny"



# Round-15 B-2: transports that are "interactive" — a human is present and can
# confirm approvals.  ``""`` (unknown) is treated as interactive for backward
# compatibility (the CLI/TUI default before explicit transport tracking).
# Everything else (``"webhook"``, ``"cron"``, ``"rpc"``) is unattended: a
# malicious inbound message must not auto-approve even read-only shell.
_INTERACTIVE_TRANSPORTS = frozenset({"cli", "tui", ""})


def _is_interactive_transport(source_transport: str) -> bool:
    """Return True when a human can confirm approvals for this turn.

    Non-interactive transports (webhook / cron / rpc) drive turns without a
    human present, so the read-only terminal auto-approve shortcut is unsafe
    there — a malicious inbound message could read secrets unattended.
    """
    return str(source_transport or "") in _INTERACTIVE_TRANSPORTS


@dataclass
class PermissionRule:
    """Persistent permission rule."""

    id: Optional[int]
    pattern: str
    permission_level: str
    approval: ApprovalMode
    mode: str
    granted_at: float = 0.0
    policy_digest: str = ""
    generation: int = 0


@dataclass
class PermissionDecision:
    """Result of checking a tool call against permission rules."""

    approved: ApprovalMode
    reason: str
    target: str
    matched_rule: Optional[PermissionRule] = None
    requires_user_confirm: bool = False


class PermissionEngine:
    """Rule matching and audit logging for tool calls.

    M4 batch 3.1.16A-2 (CRITICAL #3): every engine is bound to exactly
    one ``(principal_id, project_id, policy_digest)`` triple at
    construction.  Rule load / grant / revoke are all scoped to that
    principal, so one principal can never match, grant, or revoke
    another principal's rules.  Legacy rows (``principal_id='legacy'``)
    in the database are filtered out by ``list_permission_rules`` and
    are therefore never loaded into the in-memory cache.

    The in-memory ``_rules`` cache is preserved because each engine is
    constructed per-runtime (per ``AgentLoop``), each runtime belongs to
    exactly one principal, and ``load_rules`` is called once at startup
    — the cache is implicitly principal-scoped.  Concurrent runtimes
    under different principals hold separate engines with separate
    caches; concurrent runtimes under the same principal share the
    database but each reload their own cache via ``load_rules``.
    """

    def __init__(
        self,
        db,
        default_mode: ApprovalMode = ApprovalMode.ASK_EVERY,
        *,
        commands_require_approval: "frozenset[str] | None" = None,
        principal_id: str = "legacy",
        project_id: str = "",
        policy_digest: str = "",
        runtime_id: str = "",
        exec_tool_names: "frozenset[str] | None" = None,
    ):
        self.db = db
        self._default_mode = default_mode
        self._rules: list[PermissionRule] = []
        # H3: policy-level command approval list.  Checked BEFORE persistent
        # rules so an auto-approve rule can never bypass a policy that
        # requires explicit confirmation for a command.
        self._commands_require_approval = commands_require_approval or frozenset()
        # Round-14 §7: the set of tool names that can invoke a shell command
        # and therefore must respect ``commands_require_approval``.  Defaults
        # to the known exec tools; the runtime factory derives this from the
        # live ``ToolRegistry`` (``permission_level == "execute"``) so a newly
        # registered exec-style tool is automatically gated instead of
        # bypassing the policy approval requirement.
        self._exec_tool_names = frozenset(exec_tool_names) if exec_tool_names else _DEFAULT_EXEC_TOOLS
        # A2-3: principal binding.  Every rule loaded, granted, or revoked
        # through this engine is scoped to (principal_id, project_id,
        # policy_digest).  ``principal_id='legacy'`` is the fail-closed
        # default — an engine constructed without an authenticated
        # principal can only match other 'legacy' rules (which should
        # only exist as migration leftovers).
        self._principal_id = principal_id
        self._project_id = project_id
        self._policy_digest = policy_digest
        self._runtime_id = runtime_id
        self._authorization_epoch = 0

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    async def load_rules(self) -> None:
        """Load persisted rules from SQLite, scoped to this principal.

        Round-15 A-1: every row loaded from the DB is run through
        ``validate_rule_pattern``.  The trust boundary is the DB row (a
        restored backup, a pre-fix migration, or any direct SQL insert can
        write a ``"*"`` AUTO_APPROVE rule that bypassed the Python
        ``grant_rule`` guard), so loading must validate too — otherwise the
        Round-14 §3 guard is defeated by writing the rule any other way.
        A row whose pattern is overbroad is quarantined (logged + skipped)
        rather than raising, because it may be a legitimate-but-stale
        carryover rather than an attack.
        """
        self._authorization_epoch = await self.db.bind_authorization_context(
            self._principal_id, self._project_id, self._policy_digest
        )
        rows = await self.db.list_permission_rules(
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
            generation=self._authorization_epoch,
        )
        self._rules = self._materialize_rules(rows)

    async def check(
        self,
        tool_name: str,
        params: dict,
        permission_level: str,
        mode: str,
        resource: AuthorizationResource | None = None,
        *,
        source_transport: str = "",
    ) -> PermissionDecision:
        """Check whether a tool call is approved, denied, or needs confirmation.

        Round-15 B-2: ``source_transport`` gates the read-only-terminal
        auto-approve shortcut.  An unattended transport (``"webhook"`` /
        ``"cron"`` / ``"rpc"``) must NOT auto-approve even read-only shell,
        because a malicious inbound message could otherwise drive
        ``cat ~/.ssh/id_rsa`` / ``grep AKIA .`` with no human approval and
        exfiltrate the output.  Only interactive transports
        (``"cli"`` / ``"tui"`` / unknown-empty) keep the convenience
        shortcut.
        """
        target = (
            resource.canonical_target
            if resource is not None
            else self.normalize_target(tool_name, params)
        )
        if self._authorization_epoch == 0:
            # Factory startup loads eagerly; direct/library callers remain safe
            # by binding the authoritative context before their first check.
            await self.load_rules()
        context = await self.db.get_authorization_context(
            self._principal_id, self._project_id
        )
        if context is None or str(context["policy_digest"]) != self._policy_digest:
            self._rules = []
            return PermissionDecision(
                approved=ApprovalMode.DENY,
                reason="Effective policy changed; runtime authorization is stale",
                target=target,
            )
        current_epoch = int(context["epoch"])
        if current_epoch != self._authorization_epoch:
            self._authorization_epoch = current_epoch
            rows = await self.db.list_permission_rules(
                principal_id=self._principal_id,
                project_id=self._project_id,
                policy_digest=self._policy_digest,
                generation=current_epoch,
            )
            # Round-15 A-1: validate on epoch-reload too (same reason as
            # load_rules — a concurrent grant via another path could have
            # inserted an overbroad rule).
            self._rules = self._materialize_rules(rows)
        # H4: policy-level required-approval list runs BEFORE every other
        # shortcut, including the read-only terminal shortcut.  Otherwise a
        # command classified as read-only (cat / grep / ls / rg / head /
        # tail …) would be AUTO_APPROVE'd even when the effective policy
        # explicitly requires confirmation for it, contradicting the
        # "policy approval requirement covers automatic approval" contract.
        # H3 (preserved): this also runs before the persistent-rule loop, so
        # a remembered auto-approve rule cannot bypass a command the
        # effective policy demands confirmation for.
        if self._commands_require_approval and tool_name in self._exec_tool_names:
            command_text = _command_text(params)
            if _matches_required_approval(command_text, self._commands_require_approval):
                return PermissionDecision(
                    approved=ApprovalMode.ASK_EVERY,
                    reason=f"Policy requires approval for command: {target}",
                    target=target,
                    requires_user_confirm=True,
                )
        if (
            tool_name in {"terminal", "terminal_argv", "terminal_shell"}
            and _is_read_only_terminal_call(params)
            # Round-15 B-2: the read-only auto-approve shortcut is a
            # CONVENIENCE for interactive sessions.  An unattended transport
            # (webhook / cron / rpc) must not auto-approve even read-only
            # shell — a malicious inbound message could otherwise read
            # secrets (``cat ~/.ssh/id_rsa``) with no human in the loop.
            and _is_interactive_transport(source_transport)
        ):
            # P1-3 (round-13): read-only auto-approve is now a DEFAULT
            # shortcut — it fires ONLY when no persistent rule matched.
            # Previously it fired BEFORE the rule loop, so a remembered
            # DENY rule for a "read-only" command (cat/grep/ls/rg…) was
            # silently bypassed.  We set a flag and fall through to the
            # rule loop; if no rule matches, we auto-approve at the end.
            _read_only_terminal = True
        else:
            _read_only_terminal = False
        for rule in self._rules:
            if rule.mode != "all" and rule.mode != mode:
                continue
            if rule.permission_level != permission_level:
                continue
            if fnmatch.fnmatch(target, rule.pattern):
                return PermissionDecision(
                    approved=rule.approval,
                    reason=f"Matched rule: {rule.pattern}",
                    target=target,
                    matched_rule=rule,
                    requires_user_confirm=rule.approval == ApprovalMode.ASK_EVERY,
                )

        # P1-3: read-only terminal shortcut fires AFTER the rule loop —
        # explicit DENY rules take precedence over the convenience default.
        if _read_only_terminal:
            return PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="Read-only terminal command (no deny rule matched)",
                target=target,
                requires_user_confirm=False,
            )
        if self._default_mode == ApprovalMode.AUTO_APPROVE:
            return PermissionDecision(
                approved=ApprovalMode.AUTO_APPROVE,
                reason="No matching rule, default: auto-approve",
                target=target,
            )
        if self._default_mode == ApprovalMode.DENY:
            return PermissionDecision(
                approved=ApprovalMode.DENY,
                reason="No matching rule, default: deny",
                target=target,
            )
        return PermissionDecision(
            approved=self._default_mode,
            reason=f"No matching rule, default: {self._default_mode.value}",
            target=target,
            requires_user_confirm=True,
        )

    async def grant_rule(self, rule: PermissionRule) -> PermissionRule:
        """Persist and cache a permission rule scoped to this principal.

        Round-14 §3: an ``AUTO_APPROVE`` (or ``SUGGEST``) rule whose
        pattern is so broad it matches every target for its
        ``permission_level`` silently disables the approval gate for
        that entire level — the ask-every default (ADR-003) is voided
        by a single ``"*"``.  ``validate_rule_pattern`` rejects such
        overbroad *auto-grant* patterns at the engine layer (defense
        in depth) so neither the permission tool nor any future caller
        can install one.  ``ASK_EVERY`` / ``DENY`` rules are never a
        relaxation and are exempt.
        """
        validate_rule_pattern(
            rule.pattern, rule.approval, source="PermissionEngine.grant_rule"
        )
        rule_id = await self.db.insert_permission_rule(
            rule.pattern,
            rule.permission_level,
            rule.approval.value,
            rule.mode,
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
        )
        context = await self.db.get_authorization_context(
            self._principal_id, self._project_id
        )
        if context is None:
            raise PermissionDeniedError("authorization context disappeared after grant")
        self._authorization_epoch = int(context["epoch"])
        await self._reload_current_rules()
        for persisted in self._rules:
            if persisted.id == rule_id:
                return persisted
        raise PermissionDeniedError("persisted permission rule could not be reloaded")

    async def revoke_rule(self, rule_id: int) -> None:
        """Remove a permission rule from storage and cache.

        M4 batch 3.1.16A-2: fail closed — if ``delete_permission_rule``
        returns 0 rows, the rule either does not exist or belongs to a
        different principal.  Either way the caller is attempting an
        unauthorized revoke, so ``PermissionDeniedError`` is raised
        rather than silently succeeding (the old behaviour silently
        removed the rule from the in-memory cache even when the DB
        delete was a no-op, masking the cross-principal revoke attempt).
        """
        rowcount = await self.db.delete_permission_rule(
            rule_id,
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
        )
        if rowcount == 0:
            raise PermissionDeniedError(
                f"Permission rule {rule_id} not owned by principal "
                f"{self._principal_id!r} (or does not exist); revoke refused"
            )
        context = await self.db.get_authorization_context(
            self._principal_id, self._project_id
        )
        self._authorization_epoch = int(context["epoch"]) if context else 0
        await self._reload_current_rules()

    async def _reload_current_rules(self) -> None:
        rows = await self.db.list_permission_rules(
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
            generation=self._authorization_epoch,
        )
        # Round-15 A-1: validate on this reload path too.
        self._rules = self._materialize_rules(rows)

    def _materialize_rules(self, rows: Any) -> list[PermissionRule]:
        """Build ``PermissionRule`` objects from DB rows, validating patterns.

        Round-15 A-1: every row is run through ``validate_rule_pattern``.
        A row whose pattern is overbroad for a relaxing approval
        (``AUTO_APPROVE``/``SUGGEST``) is quarantined — logged and skipped
        — rather than loaded into ``self._rules`` where it would silently
        auto-approve every target.  ``ASK_EVERY``/``DENY`` rules always
        pass (a blanket deny is legitimate).  This closes the bypass where
        a ``"*"`` rule written via DB restore / direct SQL / a pre-fix
        version matched without ever being validated.
        """
        rules: list[PermissionRule] = []
        for row in rows:
            approval = ApprovalMode(str(row["approval"]))
            pattern = str(row["pattern"])
            try:
                validate_rule_pattern(
                    pattern, approval, source="PermissionEngine.load"
                )
            except ValueError as exc:
                logger.warning(
                    "quarantining overbroad %s permission rule id=%s "
                    "pattern=%r: %s", approval.value, row["id"], pattern, exc
                )
                continue
            rules.append(
                PermissionRule(
                    id=int(row["id"]),
                    pattern=pattern,
                    permission_level=str(row["permission_level"]),
                    approval=approval,
                    mode=str(row["mode"]),
                    granted_at=float(row["granted_at"] or 0),
                    policy_digest=str(row["policy_digest"]),
                    generation=int(row["generation"]),
                )
            )
        return rules

    async def authorization_snapshot(self) -> int:
        """Return the current epoch after verifying this runtime's policy."""
        if self._authorization_epoch == 0:
            await self.load_rules()
        context = await self.db.get_authorization_context(
            self._principal_id, self._project_id
        )
        if context is None or str(context["policy_digest"]) != self._policy_digest:
            raise PermissionDeniedError(
                "Effective policy changed; runtime authorization is stale"
            )
        return int(context["epoch"])

    async def validate_dispatch_epoch(self, expected_epoch: int) -> None:
        """Fail closed if authorization changed after permission checking."""
        current_epoch = await self.authorization_snapshot()
        if current_epoch != expected_epoch:
            raise PermissionDeniedError(
                "Authorization changed before tool dispatch; re-approval required"
            )

    async def audit(
        self,
        tool_name: str,
        target: str,
        result: str,
        detail: dict | None = None,
        session_id: str | None = None,
        risk_level: str = "safe",
        *,
        task_id: str | None = None,
        operation_id: str | None = None,
        authority_generation: int | None = None,
        source_transport: str | None = None,
    ) -> None:
        """Write a tool permission/execution audit log.

        ``risk_level`` (new, optional) tags the severity of the audited
        decision (e.g. ``"safe"``, ``"risky"``, ``"blocked"``). Existing
        callers that omit it keep the historical ``"safe"`` default.

        M4 batch 3.1.16A-2: every audit row is stamped with this
        engine's ``principal_id``, ``runtime_id`` and ``policy_digest``
        so an operator can attribute each row to a specific
        principal/runtime/policy triple.  Optional context fields
        (``task_id``, ``operation_id``, ``authority_generation``,
        ``source_transport``) let callers enrich the row without
        reaching into ``detail``.
        """
        enriched = dict(detail or {})
        if risk_level and "risk_level" not in enriched:
            enriched["risk_level"] = risk_level
        await self.db.insert_audit_log(
            action=tool_name,
            target=target,
            result=result,
            detail=json.dumps(enriched, ensure_ascii=False),
            session_id=session_id,
            principal_id=self._principal_id,
            runtime_id=self._runtime_id,
            task_id=task_id,
            operation_id=operation_id,
            policy_digest=self._policy_digest,
            authority_generation=authority_generation,
            source_transport=source_transport,
            project_id=self._project_id,
        )

    def normalize_target(self, tool_name: str, params: dict) -> str:
        """Normalize a file path, command, URL, or generic call target."""
        if tool_name in {"read_file", "write_file", "patch", "search_files"}:
            path = params.get("path") or params.get("root") or params.get("query") or "."
            return os.path.realpath(os.path.normpath(str(path)))
        if tool_name in {"terminal", "process"}:
            command = str(params.get("command") or params.get("id") or "")
            return normalize_command_target(command)
        if "url" in params:
            parsed = urlparse(str(params["url"]))
            return f"{parsed.scheme}://{parsed.netloc}"
        return f"{tool_name}:{json.dumps(params, sort_keys=True)}"

    def _match_pattern(self, pattern: str, target: str) -> bool:
        """Match a normalized target with a glob pattern."""
        return fnmatch.fnmatch(target, pattern)


def validate_rule_pattern(
    pattern: str, approval: ApprovalMode, *, source: str = "grant_permission"
) -> None:
    """Reject permission-rule patterns that are unsafely overbroad.

    Round-14 §3: a remembered rule is matched with ``fnmatch`` against
    the normalized target.  A pattern with *no* fixed (non-glob) prefix
    — e.g. ``"*"``, ``"**"``, ``"?"``, ``"*/**"``, ``"[a-z]*"`` —
    matches every target for its ``permission_level`` and ``mode``.
    Combined with ``ApprovalMode.AUTO_APPROVE`` that silently turns off
    the approval gate for the whole level, voiding the ask-every
    default (ADR-003).  Such a rule is almost always a mistake or a
    social-engineering attack; reject it for any *relaxing* approval
    mode (``AUTO_APPROVE`` / ``SUGGEST``).

    ``ASK_EVERY`` and ``DENY`` never relax enforcement, so overbroad
    patterns are permitted for them (a blanket ``DENY`` is legitimate).

    A pattern is considered overbroad when it has fewer than
    :data:`MIN_RULE_SPECIFICITY` leading fixed characters before the
    first glob meta character (``*``, ``?``, ``[``).  This still allows
    sensible broad rules like ``"/home/u/*"``, ``"terminal:git *"``,
    ``"https://api.example.com/*"`` while catching ``"*"``,
    ``"**"``, ``"/*"`` (single separator + glob) and character classes.
    """
    if approval in (ApprovalMode.ASK_EVERY, ApprovalMode.DENY):
        return
    if pattern is None:
        raise ValueError(f"{source}: pattern must not be empty")
    text = str(pattern).strip()
    if not text:
        raise ValueError(f"{source}: pattern must not be empty")
    fixed_prefix = 0
    for char in text:
        if char in ("*", "?", "["):
            break
        fixed_prefix += 1
    if fixed_prefix < MIN_RULE_SPECIFICITY:
        raise ValueError(
            f"{source}: auto-approve pattern {pattern!r} is too broad "
            f"(needs at least {MIN_RULE_SPECIFICITY} non-glob leading "
            f"characters); a '*' / '**' style rule would silently "
            f"disable the approval gate for its permission level"
        )


# Minimum number of leading non-glob characters an AUTO_APPROVE /
# SUGGEST rule pattern must carry before its first ``*`` / ``?`` / ``[``.
# Tuned to reject ``"*"``, ``"**"``, ``"/*"``, ``"?*"``, ``"[a-z]*"``
# while accepting concrete prefixes like ``"/home/u"`` or ``"terminal:"``.
MIN_RULE_SPECIFICITY = 2


def normalize_command_target(command: str) -> str:
    """Normalize a command into base command plus arguments."""
    segments = split_command_segments(command)
    if not segments:
        return ""
    first = segments[0]
    try:
        parts = shlex.split(first)
    except ValueError:
        return first.strip()
    return " ".join(parts)


def split_command_segments(command: str) -> list[str]:
    """Split a shell command at high-level shell control operators."""
    separators = {"|", ";", "&"}
    segments: list[str] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    while i < len(command):
        char = command[i]
        nxt = command[i + 1] if i + 1 < len(command) else ""
        if char == "'" and not in_double:
            in_single = not in_single
        elif char == '"' and not in_single:
            in_double = not in_double
        if not in_single and not in_double:
            two = char + nxt
            if two in {"&&", "||"}:
                _append_segment(segments, current)
                current = []
                i += 2
                continue
            if char in separators:
                _append_segment(segments, current)
                current = []
                i += 1
                continue
        current.append(char)
        i += 1
    _append_segment(segments, current)
    return segments


def _append_segment(segments: list[str], chars: list[str]) -> None:
    segment = "".join(chars).strip()
    if segment:
        segments.append(segment)


def _is_read_only_terminal_call(params: dict) -> bool:
    from khaos.tools.terminal_tools import is_read_only_command

    return is_read_only_command(_command_text(params))


def _command_text(params: dict) -> str:
    argv = params.get("argv")
    if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
        return shlex.join(argv)
    return str(params.get("script") or params.get("command") or params.get("id") or "")


def _matches_required_approval(command_text: str, approval_list: "frozenset[str]") -> bool:
    """Whether any segment of ``command_text`` triggers required approval.

    Each shell segment is normalized to ``base_cmd args`` and matched against
    the approval list.  An entry matches when the normalized segment equals it
    (e.g. ``rm``), starts with it followed by a space (e.g. ``git push origin``
    matches ``git push``), or matches it via fnmatch.  Every segment of a
    pipeline/chain is checked so ``ls; rm x`` is caught.
    """
    if not command_text or not approval_list:
        return False
    segments = split_command_segments(command_text)
    for raw in segments:
        normalized = normalize_command_target(raw)
        if not normalized:
            continue
        for entry in approval_list:
            entry = entry.strip()
            if not entry:
                continue
            if (
                normalized == entry
                or normalized.startswith(entry + " ")
                or fnmatch.fnmatch(normalized, entry)
            ):
                return True
    return False
