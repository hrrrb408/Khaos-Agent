"""Permission rules, target normalization, and audit logging."""

from __future__ import annotations

import fnmatch
import json
import logging
import os
import shlex
import time
from dataclasses import dataclass, replace
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from khaos.audit.logger import AuditLogger
from khaos.exceptions import PermissionDeniedError
from khaos.permissions.resource import AuthorizationResource
from khaos.permissions.rules import (
    is_relaxing_approval,
    legacy_pattern_to_typed,
    match_typed_rule,
    validate_typed_rule,
)

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


class SourceTransport(str, Enum):
    """Authenticated origin of a turn.

    Only ``CLI`` and ``TUI`` represent a human-present interactive
    transport. Values not represented by this enum are deliberately not
    treated as interactive; legacy callers must map their origin explicitly.
    """

    CLI = "cli"
    TUI = "tui"
    RPC = "rpc"
    WEBHOOK = "webhook"
    CRON = "cron"
    SUBAGENT = "subagent"
    INTERNAL_VERIFICATION = "internal_verification"


class TransportClass(str, Enum):
    """Coarse trust class used to scope persistent permission grants."""

    INTERACTIVE = "interactive"
    UNATTENDED = "unattended"
    ALL = "all"


class GrantLifetime(str, Enum):
    """Lifetime/scope of a persistent permission grant."""

    ONCE = "once"
    TURN = "turn"
    SESSION = "session"
    TASK = "task"
    PROJECT_INTERACTIVE = "project_interactive"
    PROJECT_ALL_TRANSPORTS = "project_all_transports"



# Round-15 B-2 / review P1-2: only explicit human-present transports can use
# the read-only terminal convenience. Empty, missing, and future values are
# unattended by default so a forgotten security field cannot grant access.
_INTERACTIVE_TRANSPORTS = frozenset(
    {SourceTransport.CLI.value, SourceTransport.TUI.value}
)


def _is_interactive_transport(source_transport: str | None) -> bool:
    """Return True when a human can confirm approvals for this turn.

    Missing, empty, and unknown transports are fail-closed and therefore
    treated as unattended. A malicious inbound message must never gain the
    interactive shortcut merely because a caller omitted the security context.
    """
    value = getattr(source_transport, "value", source_transport)
    return str(value or "").strip().lower() in _INTERACTIVE_TRANSPORTS


def is_interactive_transport(source_transport: str | None) -> bool:
    """Public transport-classification helper for boundary adapters."""
    return _is_interactive_transport(source_transport)


def _transport_class(source_transport: str | None) -> str:
    """Return the fail-closed class for a transport value."""
    return (
        TransportClass.INTERACTIVE.value
        if _is_interactive_transport(source_transport)
        else TransportClass.UNATTENDED.value
    )


@dataclass
class PermissionRule:
    """Persistent permission rule."""

    id: int | None
    pattern: str
    permission_level: str
    approval: ApprovalMode
    mode: str
    granted_at: float = 0.0
    policy_digest: str = ""
    generation: int = 0
    # Scope fields are deliberately explicit.  A remembered approval from a
    # human-present transport must not silently become an unattended grant.
    # Empty means "choose the safe approval-dependent default" at the
    # persistence boundary: relaxing grants become project-interactive;
    # deny/ask rules become project-wide enforcement rules.
    transport_class: str = ""
    grant_lifetime: str = ""
    session_id: str = ""
    task_id: str = ""
    workspace_id: str = ""
    expires_at: float | None = None
    created_by: str = ""
    # P1-4: relaxing grants use a typed resource family and canonical JSON
    # spec. ``pattern`` remains for display and for non-relaxing legacy glob
    # rules; it is never the high-authority matcher once these fields exist.
    resource_type: str = ""
    resource_spec: dict[str, Any] | None = None


@dataclass
class PermissionDecision:
    """Result of checking a tool call against permission rules."""

    approved: ApprovalMode
    reason: str
    target: str
    matched_rule: PermissionRule | None = None
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
        commands_require_approval: frozenset[str] | None = None,
        principal_id: str = "legacy",
        project_id: str = "",
        policy_digest: str = "",
        runtime_id: str = "",
        exec_tool_names: frozenset[str] | None = None,
        audit_logger: AuditLogger | None = None,
    ):
        self.db = db
        # AuditLogger is the sole production audit repository.  Keeping the
        # writer on the engine prevents permission paths from bypassing the
        # independent chain anchor and the runtime attribution fields.
        self._audit_logger = audit_logger
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

        Every row is validated at the database trust boundary. Relaxing
        rules must carry a typed resource spec; unambiguous legacy path or
        command patterns are converted in memory, while ambiguous patterns
        are quarantined rather than becoming fnmatch authority.
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
        source_transport: str | None = None,
        session_id: str | None = None,
        task_id: str | None = None,
        workspace_id: str | None = None,
    ) -> PermissionDecision:
        """Check whether a tool call is approved, denied, or needs confirmation.

        Round-15 B-2 / review P1-2: ``source_transport`` gates the
        read-only-terminal auto-approve shortcut. An unattended, missing, or
        unknown transport must NOT auto-approve even read-only shell, because
        a malicious inbound message could otherwise drive
        ``cat ~/.ssh/id_rsa`` / ``grep AKIA .`` with no human approval and
        exfiltrate the output. Only explicit ``"cli"`` / ``"tui"`` values
        keep the convenience shortcut.
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
        current_transport_class = _transport_class(source_transport)
        for rule in self._rules:
            if rule.mode != "all" and rule.mode != mode:
                continue
            if rule.permission_level != permission_level:
                continue
            if not _rule_scope_matches(
                rule,
                transport_class=current_transport_class,
                session_id=session_id,
                task_id=task_id,
                workspace_id=workspace_id,
            ):
                continue
            matched = False
            if rule.resource_type:
                try:
                    matched = match_typed_rule(
                        rule.resource_type,
                        rule.resource_spec or {},
                        resource=resource,
                        tool_name=tool_name,
                        params=params,
                        target=target,
                        operation=permission_level,
                    )
                except (TypeError, ValueError, KeyError) as exc:
                    logger.warning(
                        "ignoring malformed typed permission rule id=%s: %s",
                        rule.id,
                        exc,
                    )
            elif not is_relaxing_approval(rule.approval):
                # Generic glob syntax is retained only for enforcement rules
                # that cannot widen authority. Relaxing rules are converted
                # to typed specs during grant/load and fail closed otherwise.
                matched = fnmatch.fnmatch(target, rule.pattern)
            if matched:
                match_label = (
                    f"{rule.resource_type} resource"
                    if rule.resource_type
                    else rule.pattern
                )
                return PermissionDecision(
                    approved=rule.approval,
                    reason=f"Matched rule: {match_label}",
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

        P1-4: ``AUTO_APPROVE``/``SUGGEST`` rules are materialized into a
        typed resource DSL before persistence. ``ASK_EVERY``/``DENY`` rules
        may retain the legacy glob grammar because they never widen
        authority. Ambiguous legacy relaxing patterns are rejected.
        """
        rule = _apply_default_rule_scope(rule)
        rule = _materialize_rule_resource(
            rule, source="PermissionEngine.grant_rule"
        )
        validate_rule_scope(rule, source="PermissionEngine.grant_rule")
        rule_id = await self.db.insert_permission_rule(
            rule.pattern or _typed_rule_display(rule),
            rule.permission_level,
            rule.approval.value,
            rule.mode,
            principal_id=self._principal_id,
            project_id=self._project_id,
            policy_digest=self._policy_digest,
            transport_class=rule.transport_class,
            grant_lifetime=rule.grant_lifetime,
            session_id=rule.session_id,
            task_id=rule.task_id,
            workspace_id=rule.workspace_id,
            expires_at=rule.expires_at,
            created_by=rule.created_by,
            resource_type=rule.resource_type,
            resource_spec=rule.resource_spec,
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
        """Build rules with fail-closed typed-resource validation.

        Rows restored or written directly to SQLite are untrusted. A legacy
        relaxing rule is loaded only when it can be translated into a typed
        resource; otherwise it is quarantined.
        """
        rules: list[PermissionRule] = []
        for row in rows:
            approval = ApprovalMode(str(row["approval"]))
            pattern = str(row["pattern"])
            resource_type = str(row.get("resource_type") or "")
            resource_spec: dict[str, Any] | None = None
            try:
                if resource_type:
                    raw_spec = row.get("resource_spec")
                    if isinstance(raw_spec, str):
                        resource_spec = json.loads(raw_spec)
                    elif isinstance(raw_spec, dict):
                        resource_spec = raw_spec
                    else:
                        raise ValueError("typed resource spec is missing")
                    resource_spec = validate_typed_rule(
                        resource_type,
                        resource_spec,
                        approval,
                        source="PermissionEngine.load",
                    )
                elif is_relaxing_approval(approval):
                    # Legacy high-authority rows are migrated in memory only
                    # when their syntax is unambiguous. Ambiguous rows are
                    # quarantined instead of remaining fnmatch authority.
                    validate_rule_pattern(
                        pattern, approval, source="PermissionEngine.load"
                    )
                    resource_type, resource_spec = legacy_pattern_to_typed(
                        pattern,
                        str(row["permission_level"]),
                        approval,
                        source="PermissionEngine.load",
                    )
                else:
                    validate_rule_pattern(
                        pattern, approval, source="PermissionEngine.load"
                    )
            except ValueError as exc:
                logger.warning(
                    "quarantining invalid %s permission rule id=%s "
                    "pattern=%r: %s", approval.value, row["id"], pattern, exc
                )
                continue
            rule = PermissionRule(
                id=int(row["id"]),
                pattern=pattern,
                permission_level=str(row["permission_level"]),
                approval=approval,
                mode=str(row["mode"]),
                granted_at=float(row["granted_at"] or 0),
                policy_digest=str(row["policy_digest"]),
                generation=int(row["generation"]),
                transport_class=str(
                    row.get("transport_class")
                    or TransportClass.INTERACTIVE.value
                ),
                grant_lifetime=str(
                    row.get("grant_lifetime")
                    or GrantLifetime.PROJECT_INTERACTIVE.value
                ),
                session_id=str(row.get("session_id") or ""),
                task_id=str(row.get("task_id") or ""),
                workspace_id=str(row.get("workspace_id") or ""),
                expires_at=(
                    float(row["expires_at"])
                    if row.get("expires_at") is not None
                    else None
                ),
                created_by=str(row.get("created_by") or ""),
                resource_type=resource_type,
                resource_spec=resource_spec,
            )
            try:
                validate_rule_scope(rule, source="PermissionEngine.load")
            except ValueError as exc:
                logger.warning(
                    "quarantining invalid permission rule scope id=%s: %s",
                    row["id"],
                    exc,
                )
                continue
            rules.append(rule)
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
    ) -> int:
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
        audit_logger = self._audit_logger
        if audit_logger is None:
            # Library/test callers may construct an engine directly.  Keep
            # that path usable, but still route it through the same writer
            # abstraction instead of reaching into Database directly.
            audit_logger = AuditLogger(
                self.db,
                principal_id=self._principal_id,
                runtime_id=self._runtime_id,
                policy_digest=self._policy_digest,
                project_id=self._project_id,
            )
            self._audit_logger = audit_logger
        row_id = await audit_logger.log(
            action=tool_name,
            target=target,
            result=result,
            detail=enriched,
            session_id=session_id,
            task_id=task_id,
            operation_id=operation_id,
            authority_generation=authority_generation,
            source_transport=source_transport,
        )
        if row_id < 0:
            raise RuntimeError("audit log write was rejected")
        return row_id

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

    A pattern is considered overbroad when it has fewer than the required
    leading fixed characters before the first glob meta character (``*``,
    ``?``, ``[``). Command selectors use the stricter
    :data:`MIN_COMMAND_RULE_SPECIFICITY` threshold; the typed migration also
    rejects a wildcard with an empty argv prefix. This catches blanket
    selectors and ``rm*``-style whole-executable grants.
    """
    if approval in (ApprovalMode.ASK_EVERY, ApprovalMode.DENY):
        return
    if pattern is None:
        raise ValueError(f"{source}: pattern must not be empty")
    text = str(pattern).strip()
    if not text:
        raise ValueError(f"{source}: pattern must not be empty")
    fixed_prefix = len(text)
    for index, char in enumerate(text):
        if char in ("*", "?", "["):
            fixed_prefix = index
            break
    required_specificity = MIN_RULE_SPECIFICITY
    command_pattern = _legacy_command_pattern_body(text)
    if command_pattern is not None:
        command_fixed_prefix = len(command_pattern)
        for index, char in enumerate(command_pattern):
            if char in ("*", "?", "["):
                command_fixed_prefix = index
                break
        # A command pattern is a higher-impact selector than a path prefix.
        # In particular, ``rm*`` becomes an argv-prefix rule with no argv
        # arguments and would therefore match every invocation of ``rm``.
        # Require one additional concrete character in the command selector;
        # the typed-resource conversion below still rejects ambiguous forms.
        required_specificity = max(
            required_specificity, MIN_COMMAND_RULE_SPECIFICITY
        )
        fixed_prefix = command_fixed_prefix
    if fixed_prefix < required_specificity:
        raise ValueError(
            f"{source}: auto-approve pattern {pattern!r} is too broad "
            f"(needs at least {required_specificity} non-glob leading "
            f"characters); a '*' / '**' style rule would silently "
            f"disable the approval gate for its permission level"
        )


def _legacy_command_pattern_body(pattern: str) -> str | None:
    """Return the command portion of a legacy pattern, when unambiguous.

    Path and URL patterns use different specificity semantics.  Bare command
    selectors and the historical ``terminal:``/``process:`` forms are
    treated as executable selectors so a short wildcard such as ``rm*``
    cannot be widened into an all-``rm`` auto-approve rule.
    """
    text = pattern.strip()
    if "://" in text or text.startswith(os.path.sep):
        return None
    for prefix in ("terminal:", "process:"):
        if text.startswith(prefix):
            return text[len(prefix):].strip()
    if "/" in text or "\\" in text:
        return None
    return text


def _typed_rule_display(rule: PermissionRule) -> str:
    """Return a stable display value for rules created without ``pattern``."""
    return json.dumps(
        {
            "resource_type": rule.resource_type,
            "resource_spec": rule.resource_spec or {},
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _materialize_rule_resource(
    rule: PermissionRule,
    *,
    source: str,
) -> PermissionRule:
    """Validate or safely upgrade a rule before it crosses the DB boundary."""
    if rule.resource_type:
        spec = validate_typed_rule(
            rule.resource_type,
            rule.resource_spec or {},
            rule.approval,
            source=source,
        )
        return replace(rule, resource_spec=spec)
    if is_relaxing_approval(rule.approval):
        validate_rule_pattern(rule.pattern, rule.approval, source=source)
        resource_type, resource_spec = legacy_pattern_to_typed(
            rule.pattern,
            rule.permission_level,
            rule.approval,
            source=source,
        )
        return replace(
            rule,
            resource_type=resource_type,
            resource_spec=resource_spec,
        )
    # DENY/ASK_EVERY remain allowed to use generic glob syntax. They can
    # still opt into the typed DSL by setting resource_type explicitly.
    validate_rule_pattern(rule.pattern, rule.approval, source=source)
    return rule


def _apply_default_rule_scope(rule: PermissionRule) -> PermissionRule:
    """Materialize a safe scope for legacy in-process grant callers."""
    if rule.transport_class or rule.grant_lifetime:
        return rule
    if rule.approval in {ApprovalMode.ASK_EVERY, ApprovalMode.DENY}:
        return replace(
            rule,
            transport_class=TransportClass.ALL.value,
            grant_lifetime=GrantLifetime.PROJECT_ALL_TRANSPORTS.value,
        )
    return replace(
        rule,
        transport_class=TransportClass.INTERACTIVE.value,
        grant_lifetime=GrantLifetime.PROJECT_INTERACTIVE.value,
    )


def validate_rule_scope(rule: PermissionRule, *, source: str = "permission") -> None:
    """Validate the authority scope attached to a persistent rule.

    Scope validation happens both before persistence and while loading rows
    from SQLite. The latter is required because a restored database or direct
    SQL writer is outside the Python grant API.
    """
    valid_classes = {item.value for item in TransportClass}
    valid_lifetimes = {item.value for item in GrantLifetime}
    if rule.transport_class not in valid_classes:
        raise ValueError(
            f"{source}: unknown transport class {rule.transport_class!r}"
        )
    if rule.grant_lifetime not in valid_lifetimes:
        raise ValueError(
            f"{source}: unknown grant lifetime {rule.grant_lifetime!r}"
        )
    if rule.grant_lifetime in {
        GrantLifetime.ONCE.value,
        GrantLifetime.TURN.value,
    }:
        raise ValueError(
            f"{source}: {rule.grant_lifetime} grants are ephemeral and must "
            "not be persisted"
        )
    if (
        rule.grant_lifetime == GrantLifetime.PROJECT_INTERACTIVE.value
        and rule.transport_class != TransportClass.INTERACTIVE.value
    ):
        raise ValueError(
            f"{source}: project_interactive grants require interactive scope"
        )
    if (
        rule.grant_lifetime == GrantLifetime.PROJECT_ALL_TRANSPORTS.value
        and rule.transport_class != TransportClass.ALL.value
    ):
        raise ValueError(
            f"{source}: project_all_transports grants require all scope"
        )
    if rule.grant_lifetime == GrantLifetime.SESSION.value and not rule.session_id:
        raise ValueError(f"{source}: session grants require session_id")
    if rule.grant_lifetime == GrantLifetime.TASK.value and not rule.task_id:
        raise ValueError(f"{source}: task grants require task_id")
    if rule.expires_at is not None and rule.expires_at <= 0:
        raise ValueError(f"{source}: expires_at must be positive")


def _rule_scope_matches(
    rule: PermissionRule,
    *,
    transport_class: str,
    session_id: str | None,
    task_id: str | None,
    workspace_id: str | None,
) -> bool:
    """Return whether a rule is valid for the current request context."""
    if rule.expires_at is not None and rule.expires_at <= time.time():
        return False
    if rule.transport_class not in {
        TransportClass.ALL.value,
        transport_class,
    }:
        return False
    if rule.workspace_id and rule.workspace_id != str(workspace_id or ""):
        return False
    if rule.grant_lifetime == GrantLifetime.PROJECT_INTERACTIVE.value:
        return transport_class == TransportClass.INTERACTIVE.value
    if rule.grant_lifetime == GrantLifetime.PROJECT_ALL_TRANSPORTS.value:
        return True
    if rule.grant_lifetime == GrantLifetime.SESSION.value:
        return bool(session_id) and rule.session_id == str(session_id)
    if rule.grant_lifetime == GrantLifetime.TASK.value:
        return bool(task_id) and rule.task_id == str(task_id)
    # Invalid/ephemeral values are quarantined on load and rejected before
    # persistence. Keep the matcher fail-closed if a caller bypasses either.
    return False


# Minimum number of leading non-glob characters an AUTO_APPROVE /
# SUGGEST rule pattern must carry before its first ``*`` / ``?`` / ``[``.
# Tuned to reject ``"*"``, ``"**"``, ``"/*"``, ``"?*"``, ``"[a-z]*"``
# while accepting concrete prefixes like ``"/home/u"`` or ``"terminal:"``.
MIN_RULE_SPECIFICITY = 2
MIN_COMMAND_RULE_SPECIFICITY = 3


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


def _matches_required_approval(command_text: str, approval_list: frozenset[str]) -> bool:
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
