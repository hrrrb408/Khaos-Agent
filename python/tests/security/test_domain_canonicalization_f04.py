"""F-04 (third-round review): domain policy normalization tests.

The third-round review (``review/Khaos-Agent 第三轮深度 Review.md`` §F-04)
found that ``NetworkGuard`` stored allow/block lists verbatim and compared
domains case-sensitively, so a policy of ``blocked_domains: [example.com]``
could be evaded with ``https://EXAMPLE.COM/`` or ``https://example.com./``.

These tests verify:

1. ``canonicalize_domain`` produces one authoritative representation
   (lowercase + IDNA punycode + trailing-dot strip + label validation).
2. The blocklist cannot be bypassed by host representation tricks.
3. The allowlist matches the same canonical form.
4. Malformed policy entries fail closed at compile time.
5. Malformed request-time domains are rejected fail-closed.

Review-specified cases (§F-04, lines ~818-828):

    EXAMPLE.COM
    example.com.
    bücher.example
    xn--bcher-kva.example
    sub.EXAMPLE.COM.
    invalid..example
    混合 Unicode/Punycode
"""

from __future__ import annotations

import pytest

from khaos.security.network_guard import (
    _MAX_DOMAIN_LEN,
    _MAX_LABEL_LEN,
    NetworkGuard,
    canonicalize_domain,
)


# ---------------------------------------------------------------------------
# canonicalize_domain unit tests
# ---------------------------------------------------------------------------


def test_f04_canonicalize_lowercase() -> None:
    """``EXAMPLE.COM`` collapses to ``example.com``."""
    assert canonicalize_domain("EXAMPLE.COM") == "example.com"


def test_f04_canonicalize_strips_one_trailing_dot() -> None:
    """``example.com.`` (DNS root label) collapses to ``example.com``."""
    assert canonicalize_domain("example.com.") == "example.com"


def test_f04_canonicalize_unicode_idna() -> None:
    """``bücher.example`` is encoded to its punycode form."""
    assert canonicalize_domain("bücher.example") == "xn--bcher-kva.example"


def test_f04_canonicalize_punycode_is_idempotent() -> None:
    """Already-canonical punycode is returned unchanged (lowercase)."""
    assert canonicalize_domain("xn--bcher-kva.example") == "xn--bcher-kva.example"


def test_f04_canonicalize_mixed_case_subdomain() -> None:
    """``sub.EXAMPLE.COM.`` → ``sub.example.com`` (case + trailing dot)."""
    assert canonicalize_domain("sub.EXAMPLE.COM.") == "sub.example.com"


def test_f04_canonicalize_mixed_unicode_and_ascii_labels() -> None:
    """A domain with one Unicode label and ASCII labels canonicalizes
    via IDNA across the whole name."""
    # ``bücher.example.com`` → ``xn--bcher-kva.example.com``
    assert (
        canonicalize_domain("bücher.example.com")
        == "xn--bcher-kva.example.com"
    )


def test_f04_canonicalize_strips_whitespace() -> None:
    """Surrounding whitespace is trimmed before normalization."""
    assert canonicalize_domain("  Example.COM  ") == "example.com"


def test_f04_canonicalize_none_returns_empty() -> None:
    """``None`` is treated as empty (no domain)."""
    assert canonicalize_domain(None) == ""  # type: ignore[arg-type]


def test_f04_canonicalize_empty_returns_empty() -> None:
    """Empty string is treated as no domain (not an error)."""
    assert canonicalize_domain("") == ""


def test_f04_reject_empty_label() -> None:
    """``invalid..example`` has an empty label and must raise."""
    with pytest.raises(ValueError, match="empty label"):
        canonicalize_domain("invalid..example")


def test_f04_reject_multiple_trailing_dots() -> None:
    """``example.com..`` has multiple trailing dots and must raise."""
    with pytest.raises(ValueError, match="multiple trailing dots"):
        canonicalize_domain("example.com..")


def test_f04_reject_only_dot() -> None:
    """``.`` is empty after stripping the trailing dot and must raise."""
    with pytest.raises(ValueError, match="empty after stripping dot"):
        canonicalize_domain(".")


def test_f04_reject_wildcard() -> None:
    """``*.example.com`` is a glob pattern, not a hostname, and must
    raise so operators don't get a false sense of security."""
    with pytest.raises(ValueError, match="wildcard"):
        canonicalize_domain("*.example.com")


def test_f04_reject_overlength_domain() -> None:
    """A domain exceeding 253 characters must raise."""
    # Build a 254-char domain: 4 labels of 63 chars + dots = 63+1+63+1+63+1+63 = 255
    label = "a" * 63
    domain = f"{label}.{label}.{label}.{label}"  # 255 chars
    assert len(domain) > _MAX_DOMAIN_LEN
    with pytest.raises(ValueError, match="exceeds"):
        canonicalize_domain(domain)


def test_f04_reject_overlength_label() -> None:
    """A single label exceeding 63 characters must raise."""
    overlength_label = "a" * (_MAX_LABEL_LEN + 1)
    domain = f"{overlength_label}.example.com"
    with pytest.raises(ValueError, match="label exceeds"):
        canonicalize_domain(domain)


def test_f04_max_length_domain_accepted() -> None:
    """A 253-character domain (the DNS max) is accepted."""
    # 63 + 1 + 63 + 1 + 63 + 1 + 60 = 252... need exactly 253.
    # 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
    label = "a" * 63
    last_label = "a" * 61
    domain = f"{label}.{label}.{label}.{last_label}"  # 253 chars
    assert len(domain) == _MAX_DOMAIN_LEN
    assert canonicalize_domain(domain) == domain


# ---------------------------------------------------------------------------
# Blocklist bypass tests (the core F-04 attack)
# ---------------------------------------------------------------------------


def test_f04_blocklist_blocks_uppercase_url() -> None:
    """Policy ``blocked_domains: [example.com]`` must block
    ``https://EXAMPLE.COM/`` — the pre-F-04 bypass."""
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["example.com"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://EXAMPLE.COM/"}
    )
    assert result.allowed is False
    assert result.domain == "example.com"


def test_f04_blocklist_blocks_trailing_dot_url() -> None:
    """Policy ``blocked_domains: [example.com]`` must block
    ``https://example.com./`` — the pre-F-04 bypass."""
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["example.com"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://example.com./"}
    )
    assert result.allowed is False
    assert result.domain == "example.com"


def test_f04_blocklist_blocks_mixed_case_subdomain_with_trailing_dot() -> None:
    """Policy ``blocked_domains: [example.com]`` must block
    ``https://SUB.Example.Com./`` via subdomain match."""
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["example.com"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://SUB.Example.Com./"}
    )
    assert result.allowed is False
    # Subdomain of a blocked domain is also blocked.
    assert result.domain == "sub.example.com"


def test_f04_blocklist_blocks_unicode_form() -> None:
    """Policy ``blocked_domains: [bücher.example]`` (or its punycode)
    must block both the Unicode form and the punycode form of the
    same domain.

    Operators may write either form in policy; both must work.
    """
    # Operator writes the Unicode form.
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["bücher.example"]
    )
    # Request uses the punycode form.
    result = guard.check_tool(
        "browser_navigate", {"url": "https://xn--bcher-kva.example/"}
    )
    assert result.allowed is False
    assert result.domain == "xn--bcher-kva.example"

    # Operator writes the punycode form, request uses Unicode.
    guard2 = NetworkGuard(
        network_enabled=True, blocked_domains=["xn--bcher-kva.example"]
    )
    result2 = guard2.check_tool(
        "browser_navigate", {"url": "https://Bücher.example/"}
    )
    assert result2.allowed is False


def test_f04_blocklist_blocks_curl_uppercase() -> None:
    """Blocklist bypass via ``curl https://EXAMPLE.COM`` is closed."""
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["example.com"]
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://EXAMPLE.com/path"}
    )
    assert result.allowed is False
    assert result.domain == "example.com"


def test_f04_blocklist_does_not_block_unrelated_domain() -> None:
    """Sanity: blocking ``example.com`` does NOT block ``example.org``."""
    guard = NetworkGuard(
        network_enabled=True, blocked_domains=["example.com"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://example.org/"}
    )
    assert result.allowed is True


def test_f04_blocklist_overrides_allowlist_with_case_trick() -> None:
    """If ``example.com`` is both allowed and blocked, and the request
    uses ``EXAMPLE.com``, the blocklist still wins (canonicalized)."""
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["example.com"],
        blocked_domains=["example.com"],
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://EXAMPLE.com/"}
    )
    assert result.allowed is False


# ---------------------------------------------------------------------------
# Allowlist canonicalization tests
# ---------------------------------------------------------------------------


def test_f04_allowlist_matches_uppercase_request() -> None:
    """Allowlist ``[pypi.org]`` matches a request to ``HTTPS://PYPI.ORG/``."""
    guard = NetworkGuard(
        network_enabled=True, allowed_domains=["pypi.org"]
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://PYPI.ORG/simple"}
    )
    assert result.allowed is True
    assert result.domain == "pypi.org"


def test_f04_allowlist_matches_trailing_dot_request() -> None:
    """Allowlist ``[pypi.org]`` matches ``https://pypi.org./``."""
    guard = NetworkGuard(
        network_enabled=True, allowed_domains=["pypi.org"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://pypi.org./simple"}
    )
    assert result.allowed is True
    assert result.domain == "pypi.org"


def test_f04_allowlist_unicode_form_matches_punycode_request() -> None:
    """Allowlist written in Unicode form matches a request in punycode."""
    guard = NetworkGuard(
        network_enabled=True, allowed_domains=["bücher.example"]
    )
    result = guard.check_tool(
        "browser_navigate", {"url": "https://xn--bcher-kva.example/"}
    )
    assert result.allowed is True
    assert result.domain == "xn--bcher-kva.example"


def test_f04_allowlist_subdomain_match_with_case() -> None:
    """Subdomain match (allowlisting ``github.com`` allows
    ``api.github.com``) must work even when the request uses uppercase."""
    guard = NetworkGuard(
        network_enabled=True, allowed_domains=["github.com"]
    )
    result = guard.check_tool(
        "terminal", {"command": "curl https://API.GITHUB.COM/"}
    )
    assert result.allowed is True
    assert result.domain == "api.github.com"


# ---------------------------------------------------------------------------
# Fail-closed behavior
# ---------------------------------------------------------------------------


def test_f04_malformed_policy_entry_fails_closed_at_compile() -> None:
    """A malformed entry in ``blocked_domains`` (e.g. ``*.example.com``)
    must raise at compile time so the operator cannot accidentally
    deploy a policy with a non-matching glob."""
    with pytest.raises(ValueError, match="wildcard"):
        NetworkGuard(
            network_enabled=True,
            blocked_domains=["*.example.com"],
        )


def test_f04_malformed_allowlist_entry_fails_closed_at_compile() -> None:
    """A malformed entry in ``allowed_domains`` (e.g. empty label)
    must raise at compile time."""
    with pytest.raises(ValueError, match="empty label"):
        NetworkGuard(
            network_enabled=True,
            allowed_domains=["invalid..example"],
        )


def test_f04_malformed_request_domain_rejected_fail_closed() -> None:
    """A request to a malformed domain (empty label) is rejected
    fail-closed at check time — it does NOT silently pass."""
    guard = NetworkGuard(network_enabled=True)
    # ``invalid..example`` is malformed; ``urlsplit`` will surface the
    # raw host, and ``_check_domain`` must reject via canonicalize_domain.
    result = guard.check_tool(
        "browser_navigate", {"url": "https://invalid..example/"}
    )
    assert result.allowed is False
    assert "rejected" in result.reason or "blocked" in result.reason


def test_f04_blank_entries_in_policy_are_skipped_not_raised() -> None:
    """Blank/whitespace entries in allow/block lists are skipped (not
    raised) so a YAML list with a trailing empty item is still valid."""
    # No exception expected.
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["pypi.org", "", "  "],
        blocked_domains=["", "evil.com"],
    )
    assert guard._allowed == {"pypi.org"}
    assert guard._blocked == {"evil.com"}


# ---------------------------------------------------------------------------
# Compiled canonical form is stored
# ---------------------------------------------------------------------------


def test_f04_compile_time_canonical_form_stored_lowercased() -> None:
    """The compiled allowlist stores the canonical (lowercase, IDNA,
    trailing-dot-stripped) form, not the raw operator input."""
    guard = NetworkGuard(
        network_enabled=True,
        allowed_domains=["EXAMPLE.COM."],
        blocked_domains=["BÜCHER.example."],
    )
    assert guard._allowed == {"example.com"}
    assert guard._blocked == {"xn--bcher-kva.example"}


def test_f04_extract_domain_prefers_urlsplit_for_uppercase() -> None:
    """``_extract_domain`` returns the lowercased hostname from
    ``urlsplit`` for an uppercase URL — the regex fallback is not
    needed for well-formed URLs."""
    guard = NetworkGuard()
    # ``urlsplit`` lowercases the hostname automatically.
    assert guard._extract_domain("https://EXAMPLE.com/path") == "example.com"
