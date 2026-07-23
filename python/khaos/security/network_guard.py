"""Network access control based on sandbox policy.

When the policy disables network access (the default), this guard inspects
tool calls that would touch the network — ``terminal`` running curl/wget,
``browser_navigate``, or any tool carrying a ``url`` — and blocks them unless
the destination domain is on the allowlist.

H1: ``network_enabled`` is a *total switch*, not a bypass for domain rules.
When enabled, ``allowed_domains`` and ``blocked_domains`` are STILL enforced:

* ``blocked_domains`` always wins (a blocked domain is rejected even when
  network is on and even when it appears in the allowlist);
* when ``allowed_domains`` is non-empty, only allowlisted domains pass
  (deny-by-default);
* when ``allowed_domains`` is empty and network is enabled, all domains
  pass (no allowlist configured = unrestricted, but still subject to the
  blocklist).

When network is disabled, all network access is blocked regardless of the
allowlist.

The guard is intentionally conservative: when in doubt about whether a
command reaches the network it blocks, matching Codex's "deny by default"
stance.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from khaos.security.host_network import (
    HostNetworkAuthority,
    HostNetworkDeniedError,
    ValidatedTarget,
)

logger = logging.getLogger(__name__)


# F-04 (third-round review): domain canonical form.  Pre-F-04 the
# NetworkGuard stored allow/block lists verbatim and compared domains
# case-sensitively, so a policy of ``blocked_domains: [example.com]``
# could be bypassed by ``https://EXAMPLE.COM/`` or
# ``https://example.com./``.  ``canonicalize_domain`` produces one
# authoritative representation applied BOTH at policy-compile time AND
# at every request/command parse time, so the blocklist can no longer
# be evaded by host representation tricks.
#
# Steps (per the review):
#   1. trim whitespace
#   2. strip one trailing dot (root label)
#   3. IDNA encode (Unicode → ASCII punycode)
#   4. lowercase
#   5. validate total length (<=253) and per-label length (<=63)
#   6. reject empty labels (``invalid..example``)
#   7. reject wildcard misuse (``*.example.com`` is not a valid host)
#
# Returns the canonical ASCII lowercase domain, or ``""`` when the input
# is empty.  Raises ``ValueError`` on malformed input so the policy
# compiler can fail closed.
_MAX_DOMAIN_LEN = 253
_MAX_LABEL_LEN = 63


def canonicalize_domain(domain: str) -> str:
    """Return the canonical ASCII lowercase form of ``domain``.

    Raises ``ValueError`` if the domain is malformed (empty labels,
    over-length, wildcard misuse, or un-encodable Unicode).
    """
    if domain is None:
        return ""
    cleaned = domain.strip()
    if not cleaned:
        return ""
    # Strip ONE trailing dot (the DNS root label).  Multiple trailing
    # dots are malformed.
    if cleaned.endswith("."):
        if cleaned.endswith(".."):
            raise ValueError(f"domain has multiple trailing dots: {domain!r}")
        cleaned = cleaned[:-1]
    if not cleaned:
        raise ValueError(f"domain is empty after stripping dot: {domain!r}")
    # Reject wildcards — the blocklist/allowlist matches hostnames, not
    # glob patterns.  ``*.example.com`` would silently never match a
    # real hostname and lull the operator into a false sense of security.
    if "*" in cleaned:
        raise ValueError(f"wildcard domains are not allowed: {domain!r}")
    # Validate labels BEFORE IDNA encoding.  We do this ourselves
    # (rather than relying on the idna codec's "label empty or too
    # long" error) so the error message is precise: ``invalid..example``
    # reports "empty label" instead of a generic "not IDNA-encodable".
    # Note: per-label length is checked on the Unicode form here; a
    # Unicode label may expand to a longer punycode form, so we also
    # re-check per-label length after IDNA below.
    raw_labels = cleaned.split(".")
    for label in raw_labels:
        if not label:
            raise ValueError(f"domain has empty label: {domain!r}")
        if len(label) > _MAX_LABEL_LEN:
            raise ValueError(
                f"domain label exceeds {_MAX_LABEL_LEN} chars: {label!r}"
            )
    # IDNA encode Unicode → ASCII punycode.  ``idna`` codecs raise
    # ``UnicodeError`` on invalid input (e.g. disallowed characters);
    # we re-raise as ``ValueError`` so callers get a single exception
    # type.  With empty/overlength labels already filtered above, the
    # codec's "label empty or too long" path is unreachable.
    try:
        encoded = cleaned.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"domain is not IDNA-encodable: {domain!r}") from exc
    # Lowercase AFTER IDNA so punycode prefix (``xn--``) is also lowercased.
    encoded = encoded.lower()
    # Validate total length.
    if len(encoded) > _MAX_DOMAIN_LEN:
        raise ValueError(
            f"domain exceeds {_MAX_DOMAIN_LEN} chars: {domain!r} "
            f"({len(encoded)} chars)"
        )
    # Re-validate per-label length on the punycode form — a short
    # Unicode label may expand past 63 chars once encoded.
    for label in encoded.split("."):
        if len(label) > _MAX_LABEL_LEN:
            raise ValueError(
                f"domain label exceeds {_MAX_LABEL_LEN} chars: {label!r}"
            )
    return encoded

# 命令中的网络相关关键词
NETWORK_COMMAND_KEYWORDS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "ncat",
        "telnet",
        "ssh",
        "scp",
        "rsync",
        "ping",
        "traceroute",
        "nslookup",
        "dig",
        "ftp",
        "python",
        "python3",
        "node",
        "npm",
        "pip",
        "cargo",
        "docker",
        "podman",
        "kubectl",
        "git",  # git push/pull/fetch/clone 涉及网络
    }
)

NETWORK_GIT_SUBCOMMANDS = frozenset({"push", "pull", "fetch", "clone", "remote", "ls-remote"})


@dataclass
class NetworkCheckResult:
    """网络访问检查结果。"""

    allowed: bool
    reason: str = ""
    domain: str = ""


class NetworkGuard:
    """根据策略检查工具调用是否涉及网络访问。"""

    def __init__(
        self,
        network_enabled: bool = False,
        allowed_domains: list[str] | None = None,
        blocked_domains: list[str] | None = None,
        *,
        host_authority: HostNetworkAuthority | None = None,
    ):
        self.network_enabled = network_enabled
        # H3: three-state — ``None`` means "no allowlist configured"
        # (unrestricted subject to blocklist when network is on); an empty
        # set means "explicitly deny all domains"; a non-empty set is the
        # whitelist.  The previous code did ``set(allowed_domains or [])``
        # which collapsed None and [] into the same empty set, then treated
        # both as "no allowlist" — so an explicit ``allowed_domains: []``
        # (deny all) silently became "unrestricted".
        #
        # F-04: every entry is canonicalized (lowercase + IDNA + trailing
        # dot strip) at compile time so the blocklist cannot be bypassed
        # by host representation tricks.  A malformed entry raises
        # ``ValueError`` so the policy compiler fails closed.
        if allowed_domains is None:
            self._allowed: set[str] | None = None
        else:
            self._allowed = {
                canonicalize_domain(d) for d in allowed_domains if d and d.strip()
            }
        self._blocked = {
            canonicalize_domain(d) for d in (blocked_domains or []) if d and d.strip()
        }
        # Dependency injection is intentionally explicit so integration tests
        # can use an isolated loopback HTTP server without weakening the
        # production authority's public-address-only policy.
        self._host_authority = host_authority or HostNetworkAuthority()

    async def check_resolved_url(self, url: str) -> NetworkCheckResult:
        """Apply domain policy and reject URLs resolving to special-use IPs."""
        try:
            await self.authorize_url(url)
        except HostNetworkDeniedError as exc:
            return NetworkCheckResult(
                allowed=False,
                reason=str(exc),
                domain=self._extract_domain(url),
            )
        return NetworkCheckResult(
            allowed=True,
            reason="network egress authorized",
            domain=self._extract_domain(url),
        )

    async def authorize_url(
        self,
        url: str,
        *,
        previous_scheme: str | None = None,
    ) -> ValidatedTarget:
        """Authorize one egress hop and freeze its approved DNS snapshot.

        Redirect transports must call this for every hop so the effective
        domain policy and DNS/IP policy cannot drift apart.
        """
        domain_result = self._check_url(url)
        if not domain_result.allowed:
            raise HostNetworkDeniedError(domain_result.reason)
        return await self._host_authority.validate_url(
            url,
            previous_scheme=previous_scheme,
            allowed_schemes=frozenset({"http", "https", "ws", "wss"}),
        )

    def check_tool(self, tool_name: str, arguments: dict) -> NetworkCheckResult:
        """检查工具调用是否涉及网络访问。

        H1: ``network_enabled`` is a total switch — when enabled, domain
        rules are still enforced; when disabled, all network access is
        blocked.  The previous ``if self.network_enabled: return allowed``
        early return was a fail-open that let an allowlist like
        ``allowed_domains: [pypi.org]`` silently grant unrestricted
        network access.
        """
        if tool_name.startswith("github_"):
            if not self.network_enabled:
                return NetworkCheckResult(
                    allowed=False,
                    reason="GitHub network access disabled by policy",
                    domain="github.com",
                )
            # H1: network enabled — still check github.com against the
            # allowlist/blocklist.
            return self._check_domain("github.com")

        if tool_name == "terminal":
            return self._check_terminal_command(arguments.get("command", ""))

        # H1: browser tools that can trigger network access (navigate,
        # click, type, evaluate, upload) are gated by the ``network.access``
        # capability at the broker layer.  For browser_navigate and any
        # tool with a ``url`` argument, we also check the target domain
        # here.  Browser click/type/evaluate/upload don't carry a URL, so
        # domain enforcement for them happens at the Playwright route
        # interception layer (future work) — the capability broker is the
        # primary gate today.
        if tool_name == "browser_navigate":
            return self._check_url(arguments.get("url", ""))

        if "url" in arguments:
            return self._check_url(str(arguments["url"]))

        return NetworkCheckResult(allowed=True, reason="not a network tool")

    def _check_terminal_command(self, command: str) -> NetworkCheckResult:
        """检查终端命令是否涉及网络。"""
        base = self._base_command(command)
        if base not in NETWORK_COMMAND_KEYWORDS:
            return NetworkCheckResult(allowed=True, reason="not a network command")

        # git 特殊处理：只在网络子命令时拦截
        if base == "git":
            parts = command.split()
            if len(parts) >= 2 and parts[1] in NETWORK_GIT_SUBCOMMANDS:
                if not self.network_enabled:
                    return NetworkCheckResult(
                        allowed=False,
                        reason=f"network git command: git {parts[1]}",
                    )
                # H1: network enabled — check the remote domain if extractable.
                domain = self._extract_domain(command)
                if domain:
                    return self._check_domain(domain)
                # Can't extract the remote URL (e.g. ``git push`` without an
                # explicit URL uses the configured remote).  When an
                # allowlist is configured (including empty = deny all) we
                # cannot verify the destination, so deny; when no allowlist
                # (None), allow (network is on, no domain restriction).
                if self._allowed is not None:
                    return NetworkCheckResult(
                        allowed=False,
                        reason=(
                            "git network command destination cannot be "
                            "verified against the configured allowlist"
                        ),
                    )
                return NetworkCheckResult(
                    allowed=True,
                    reason="network git command (no allowlist configured)",
                )
            # git add/commit/diff/log 等本地操作放行
            return NetworkCheckResult(allowed=True, reason="local git command")

        # curl/wget/ssh/etc: network commands
        if not self.network_enabled:
            # H1: network disabled — block all network commands.
            domain = self._extract_domain(command)
            if domain:
                return NetworkCheckResult(
                    allowed=False,
                    reason=f"network access blocked: {base} to {domain}",
                    domain=domain,
                )
            return NetworkCheckResult(
                allowed=False,
                reason=f"network command blocked: {base}",
            )

        # H1: network enabled — check domain against allowlist/blocklist.
        domain = self._extract_domain(command)
        if domain:
            return self._check_domain(domain)
        # No domain extractable (e.g. ``ssh user@host`` without a URL
        # scheme).  When an allowlist is configured (including empty = deny
        # all), deny (can't verify); when no allowlist (None), allow.
        if self._allowed is not None:
            return NetworkCheckResult(
                allowed=False,
                reason=(
                    f"network command {base} destination cannot be "
                    "verified against the configured allowlist"
                ),
            )
        return NetworkCheckResult(
            allowed=True,
            reason=f"network command {base} (no allowlist configured)",
        )

    def _check_url(self, url: str) -> NetworkCheckResult:
        """检查 URL 访问。"""
        if not url:
            return NetworkCheckResult(allowed=True, reason="empty url")

        domain = self._extract_domain(url)
        if domain:
            return self._check_domain(domain)

        return NetworkCheckResult(
            allowed=False,
            reason="network access blocked",
        )

    def _check_domain(self, domain: str) -> NetworkCheckResult:
        """Check a domain against the blocklist + allowlist (H1, H3).

        Priority: blocked > allowed > network_enabled.

        * ``blocked_domains`` always wins — a blocked domain is rejected
          even when network is on and even when it appears in the
          allowlist.
        * H3 three-state ``allowed_domains``:
          * ``None`` (no allowlist configured) — allow when network is on
            (subject to blocklist), block when off;
          * empty set (explicit deny-all) — block every domain regardless
            of network state;
          * non-empty — only allowlisted domains pass (deny-by-default).
        * When network is disabled, all domains are blocked (the allowlist
          can only TIGHTEN an enabled network, not RELAX a disabled one).

        F-04: the input domain is canonicalized (lowercase + IDNA +
        trailing dot strip) BEFORE comparison so the blocklist cannot be
        bypassed by ``EXAMPLE.COM`` / ``example.com.`` / Unicode forms.
        A malformed domain (empty labels, over-length, un-encodable) is
        rejected fail-closed — we never let an uncanonicalizable host
        slip through the policy.
        """
        if not domain:
            return NetworkCheckResult(allowed=True, reason="empty domain")
        # F-04: canonicalize the request-time domain.  If it can't be
        # canonicalized, fail closed.
        try:
            canonical = canonicalize_domain(domain)
        except ValueError as exc:
            return NetworkCheckResult(
                allowed=False,
                reason=f"domain {domain!r} rejected: {exc}",
                domain=domain,
            )
        if not canonical:
            return NetworkCheckResult(allowed=True, reason="empty domain")
        # Blocklist always wins.
        for blocked in self._blocked:
            if canonical == blocked or canonical.endswith(f".{blocked}"):
                return NetworkCheckResult(
                    allowed=False,
                    reason=f"domain {canonical} is blocked by policy",
                    domain=canonical,
                )
        # H3: three-state allowlist.
        if self._allowed is not None:
            # An explicit allowlist is configured (possibly empty = deny all).
            if not self._allowed:
                # Explicit deny-all.
                return NetworkCheckResult(
                    allowed=False,
                    reason=f"domain {canonical} blocked by empty allowlist (deny all)",
                    domain=canonical,
                )
            for allowed in self._allowed:
                if canonical == allowed or canonical.endswith(f".{allowed}"):
                    return NetworkCheckResult(
                        allowed=True,
                        reason=f"domain {canonical} in allowlist",
                        domain=canonical,
                    )
            return NetworkCheckResult(
                allowed=False,
                reason=f"domain {canonical} not in allowlist",
                domain=canonical,
            )
        # No allowlist configured (None) — allow when network is enabled,
        # block when disabled.
        if self.network_enabled:
            return NetworkCheckResult(
                allowed=True,
                reason=f"domain {canonical} allowed (network enabled, no allowlist)",
                domain=canonical,
            )
        return NetworkCheckResult(
            allowed=False,
            reason=f"network access blocked to {canonical}",
            domain=canonical,
        )

    # Backward-compatible alias — older callers may use _is_domain_allowed.
    def _is_domain_allowed(self, domain: str) -> bool:
        """检查域名是否在白名单中（支持子域名通配）。"""
        return self._check_domain(domain).allowed

    def _extract_domain(self, text: str) -> str:
        """从命令或 URL 中提取域名。

        F-04: prefer the standard URL parser (``urllib.parse``) over a
        regex so the host authority is not fooled by URL quirks.  The
        regex is kept as a fallback for ssh-style ``user@host`` and for
        commands that embed a URL without scheme (e.g. ``git clone
        github.com:user/repo``).
        """
        from urllib.parse import urlsplit

        # Try the standard URL parser first — it correctly handles
        # brackets (``[::1]``), ports (``host:8080``), userinfo
        # (``user:pw@host``), and edge cases the regex misses.
        try:
            parts = urlsplit(text)
            if parts.hostname:
                # parts.hostname is already lowercased and stripped of
                # brackets/ports by the parser; return as-is and let
                # ``canonicalize_domain`` do the IDNA + trailing-dot work.
                return parts.hostname
        except ValueError:
            # Malformed URL — fall through to the regex path.
            pass
        # Regex fallback for http(s)/ws(s) URLs that the parser rejected
        # (e.g. embedded in a longer command string).
        url_match = re.search(r"(?:https?|wss?)://([^\s/:\"'`]+)", text)
        if url_match:
            return url_match.group(1)
        # ssh-style: user@host
        ssh_match = re.search(r"@([a-zA-Z0-9.\-]+)", text)
        if ssh_match:
            return ssh_match.group(1)
        return ""

    def _base_command(self, command: str) -> str:
        parts = command.strip().split()
        return parts[0] if parts else ""
