"""Round-15 B-2: read-only terminal auto-approve must be gated on an
interactive transport.

An unattended transport (webhook / cron / rpc) must NOT auto-approve even
read-only shell — a malicious inbound message could otherwise drive
``cat ~/.ssh/id_rsa`` / ``grep AKIA .`` with no human in the loop and
exfiltrate the output.  Only interactive transports (cli / tui / unknown)
keep the convenience shortcut.
"""

import pytest

from khaos.db import Database
from khaos.permissions import ApprovalMode, PermissionEngine


@pytest.mark.parametrize("transport", ["webhook", "cron", "rpc"])
async def test_unattended_transport_does_not_auto_approve_read_only_shell(
    tmp_path, transport: str
) -> None:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    await engine.load_rules()
    decision = await engine.check(
        "terminal",
        {"command": "cat ~/.ssh/id_rsa"},
        "execute",
        "coding",
        source_transport=transport,
    )
    # Must require confirmation, not auto-approve — no human is present to
    # see the secret read happen, so the read must be gated.
    assert decision.approved is ApprovalMode.ASK_EVERY
    assert decision.requires_user_confirm is True
    await db.close()


@pytest.mark.parametrize("transport", ["cli", "tui", ""])
async def test_interactive_transport_keeps_read_only_auto_approve(
    tmp_path, transport: str
) -> None:
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    await engine.load_rules()
    decision = await engine.check(
        "terminal",
        {"command": "cat /etc/hosts"},
        "execute",
        "coding",
        source_transport=transport,
    )
    assert decision.approved is ApprovalMode.AUTO_APPROVE
    assert decision.requires_user_confirm is False
    await db.close()


async def test_webhook_transport_dangerous_command_still_ask_every(tmp_path) -> None:
    """A non-read-only command under an unattended transport still goes
    ask-every (the shortcut was never the only gate; this confirms B-2 did
    not accidentally over-loosen the dangerous-command path)."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    await engine.load_rules()
    decision = await engine.check(
        "terminal",
        {"command": "rm -rf /tmp/x"},
        "execute",
        "coding",
        source_transport="webhook",
    )
    assert decision.requires_user_confirm is True
    await db.close()


async def test_default_source_transport_is_interactive_for_backward_compat(
    tmp_path,
) -> None:
    """Callers that don't pass ``source_transport`` (legacy/default) are
    treated as interactive so existing behavior is preserved."""
    db = Database(tmp_path / "khaos.db")
    await db.connect()
    await db.run_migrations()
    engine = PermissionEngine(db)
    await engine.load_rules()
    decision = await engine.check(
        "terminal", {"command": "cat /etc/hosts"}, "execute", "coding"
    )
    assert decision.approved is ApprovalMode.AUTO_APPROVE
    await db.close()
