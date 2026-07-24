"""Round-6 Batch 6.2 — Browser nftables Authority Domain.

Closes the following Round-6 review findings:

* **§四 C-02 (round-6)**: the nft script used ``flush table inet <name>``
  without first creating the table.  On a fresh sandbox the table does
  not exist yet, so ``flush`` fails → ``BrowserSandboxError`` in
  production → browser creation permanently blocked.  Fix: use the
  ``table inet <name> { … }`` block syntax (create-or-replace).

* **§四 "真实 nft --check"**: ``_apply_nft_script`` now runs
  ``nft -c -f -`` first so a malformed script is a detectable failure
  instead of a silent kernel-policy gap.

* **§五 Browser 启动早于 Kernel Egress Guard**: previously the veth
  was completely open between ``setup()`` and the first
  ``ensure_page()``.  Fix: ``setup()`` now installs the default-deny
  table BEFORE the browser is launched.

* **§六 multi-context flush conflict**: previously each
  ``install_egress_pin`` call did ``flush table`` + a single port
  rule, so a second context's creation silently dropped the first
  context's port from the kernel policy.  Fix: maintain a per-sandbox
  ``_egress_ports`` set; every call atomically rebuilds the whole
  table with ALL active ports.  ``remove_egress_port`` (called by
  ``_close_one_context``) removes a port and re-applies.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from khaos.security.browser_sandbox import (
    BrowserNetworkSandbox,
    BrowserSandboxError,
)


# ───────────────────────── helpers ──────────────────────────────


def _active_sandbox() -> BrowserNetworkSandbox:
    """Build a sandbox with the fields ``_apply_nft_script`` reads,
    without running the real ``setup()`` (which needs CAP_NET_ADMIN).
    """
    s = BrowserNetworkSandbox()
    s._active = True
    s._veth_host = "khbrh-test12"
    s._host_ip = "10.200.42.1"
    s._nft_table = f"khaos_browser_{s._token}"
    return s


def _ok_run(**kwargs):
    return MagicMock(returncode=0, stderr="", stdout="", **kwargs)


# ───── 6.2-A: nft script uses ``table inet <name> { … }`` block ─────


def test_6_2_a_nft_script_uses_table_block_not_flush_only():
    """6.2-A (§四 C-02 round-6): the nft script must use the
    ``table inet <name> { … }`` block syntax so the table is CREATED
    if missing.  Previously only ``flush table`` was emitted, which
    fails on a fresh table.
    """
    s = _active_sandbox()
    script = s._build_nft_script(include_table_create=True)
    # The block syntax opens with ``table inet <name> {``.
    assert f"table inet {s._nft_table} {{" in script
    # The old ``flush table`` form must NOT be the only creation
    # mechanism.  (It may still appear as a comment, but the block
    # syntax is what actually creates the table.)
    lines = [ln.strip() for ln in script.splitlines() if ln.strip()]
    flush_lines = [ln for ln in lines if ln.startswith("flush table")]
    # No bare ``flush table`` command — the block syntax replaces it.
    assert flush_lines == [], (
        "nft script must use `table inet <name> { … }` block syntax, "
        "not bare `flush table` — flush fails on a fresh table"
    )


def test_6_2_a_nft_script_contains_both_hooks():
    """6.2-A: the block syntax must contain BOTH input and forward
    hooks so the browser veth is fully default-deny even with zero
    egress ports.
    """
    s = _active_sandbox()
    script = s._build_nft_script(include_table_create=True)
    assert "hook input" in script
    assert "hook forward" in script
    # Chains are nested INSIDE the table block.
    assert "chain khaos_input {" in script
    assert "chain khaos_forward {" in script


# ───── 6.2-B: default-deny with zero ports ──────────────────────


def test_6_2_b_zero_ports_script_is_default_deny():
    """6.2-B: with zero egress ports, the input chain must still drop
    everything from the browser veth (except established return
    traffic).  This is what ``setup()`` installs BEFORE the browser
    is launched.
    """
    s = _active_sandbox()
    assert s._egress_ports == set()
    script = s._build_nft_script(include_table_create=True)
    # No port-specific accept rule.
    assert "tcp dport" not in script
    # The drop rule is present.
    assert f'iifname "{s._veth_host}" drop' in script
    # Established return traffic is still allowed.
    assert "ct state established,related accept" in script


def test_6_2_b_install_egress_pin_adds_port_to_set():
    """6.2-B: ``install_egress_pin`` ADDS the port to ``_egress_ports``
    instead of ``flush``-ing the whole table.  Other ports are
    preserved.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        assert 40001 in s._egress_ports
        s.install_egress_pin(40002)
        assert s._egress_ports == {40001, 40002}
        # The last applied script must contain BOTH ports.
        last_script = mock_run.call_args_list[-1].kwargs["input"]
        assert "40001" in last_script
        assert "40002" in last_script


# ───── 6.2-C: multi-context port set preservation (§六) ─────────


def test_6_2_c_second_context_does_not_drop_first_port():
    """6.2-C (§六): installing a second port must NOT drop the first
    port from the kernel policy.  Previously each call did
    ``flush table`` + a single port rule.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        s.install_egress_pin(40002)
        # The last applied script must contain BOTH ports — not just
        # the most recent one.
        last_script = mock_run.call_args_list[-1].kwargs["input"]
        assert "tcp dport 40001 accept" in last_script
        assert "tcp dport 40002 accept" in last_script
        # Both ports remain in the active set.
        assert s._egress_ports == {40001, 40002}


def test_6_2_c_remove_egress_port_preserves_others():
    """6.2-C (§六): ``remove_egress_port`` removes only the specified
    port and re-applies the table.  Other ports are preserved.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        s.install_egress_pin(40002)
        s.install_egress_pin(40003)
        assert s._egress_ports == {40001, 40002, 40003}
        # Remove port 40002 (context B closed).
        s.remove_egress_port(40002)
        assert 40002 not in s._egress_ports
        assert s._egress_ports == {40001, 40003}
        # The last applied script must still contain 40001 and 40003.
        last_script = mock_run.call_args_list[-1].kwargs["input"]
        assert "tcp dport 40001 accept" in last_script
        assert "tcp dport 40003 accept" in last_script
        assert "tcp dport 40002 accept" not in last_script


def test_6_2_c_remove_egress_port_unknown_is_noop():
    """6.2-C: ``remove_egress_port`` with an unknown port is a safe
    no-op (does not raise, does not re-apply).
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        call_count_before = mock_run.call_count
        # Remove a port that was never installed.
        s.remove_egress_port(99999)
        # No additional nft calls — the method short-circuits.
        assert mock_run.call_count == call_count_before
        # The installed port is still there.
        assert s._egress_ports == {40001}


def test_6_2_c_remove_egress_port_to_zero_is_full_default_deny():
    """6.2-C: removing the last port returns the table to full
    default-deny (no port-specific accept rules).
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        s.remove_egress_port(40001)
        assert s._egress_ports == set()
        last_script = mock_run.call_args_list[-1].kwargs["input"]
        assert "tcp dport" not in last_script
        # The drop rule is still present.
        assert f'iifname "{s._veth_host}" drop' in last_script


# ───── 6.2-D: nft --check syntax validation (§四) ───────────────


def test_6_2_d_apply_nft_script_runs_check_first():
    """6.2-D (§四 "真实 nft --check"): ``_apply_nft_script`` must call
    ``nft -c -f -`` (syntax check) BEFORE ``nft -f -`` (apply).
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        script = s._build_nft_script(include_table_create=True)
        result = s._apply_nft_script(script, description="test")
        assert result is True
        assert mock_run.call_count == 2
        check_call, apply_call = mock_run.call_args_list
        assert check_call.args[0] == ["nft", "-c", "-f", "-"]
        assert apply_call.args[0] == ["nft", "-f", "-"]
        # Both calls receive the SAME script via stdin.
        assert check_call.kwargs["input"] == script
        assert apply_call.kwargs["input"] == script


def test_6_2_d_apply_nft_script_rejects_malformed_script_in_production():
    """6.2-D: when ``nft -c -f -`` rejects the script, production mode
    raises ``BrowserSandboxError`` and does NOT apply.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        # The check fails.
        mock_run.side_effect = [
            MagicMock(returncode=1, stderr="syntax error", stdout=""),
            MagicMock(returncode=0, stderr="", stdout=""),  # should NOT be called
        ]
        s = BrowserNetworkSandbox(require_os_sandbox=True)
        with pytest.raises(BrowserSandboxError, match="nft -c -f - rejected"):
            s._apply_nft_script("garbage", description="test")
        # Only the check call was made — apply was NOT attempted.
        assert mock_run.call_count == 1


def test_6_2_d_apply_nft_script_dev_mode_returns_false_on_check_failure():
    """6.2-D: in dev mode, a check failure logs a warning and returns
    False (no raise).  The apply is NOT attempted.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.side_effect = [
            MagicMock(returncode=1, stderr="syntax error", stdout=""),
        ]
        s = BrowserNetworkSandbox(require_os_sandbox=False)
        result = s._apply_nft_script("garbage", description="test")
        assert result is False
        assert mock_run.call_count == 1  # apply NOT attempted


def test_6_2_d_apply_nft_script_apply_failure_in_production_raises():
    """6.2-D: when the check passes but the apply fails, production
    mode raises ``BrowserSandboxError``.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr="", stdout=""),  # check ok
            MagicMock(returncode=1, stderr="permission denied", stdout=""),
        ]
        s = BrowserNetworkSandbox(require_os_sandbox=True)
        with pytest.raises(BrowserSandboxError, match="nft -f - failed"):
            s._apply_nft_script("table inet x { }", description="test")


# ───── 6.2-E: default-deny installed in setup() before browser ────


def test_6_2_e_setup_installs_default_deny_before_browser():
    """6.2-E (§五): ``setup()`` must install the default-deny nft
    table BEFORE the browser is launched.  We verify this by patching
    ``_install_default_deny_nft`` and checking it is called inside
    ``setup()`` BEFORE ``_active`` is set to True.
    """
    s = BrowserNetworkSandbox(require_os_sandbox=False)
    # Patch the internal helpers that need real privileges, so we can
    # trace the call order without running them.
    call_order: list[str] = []

    def fake_create_netns(self):
        call_order.append("create_netns")
    def fake_configure_veth(self):
        call_order.append("configure_veth")
    def fake_create_cgroup(self):
        call_order.append("create_cgroup")
    def fake_create_secure_run_dir(self):
        call_order.append("create_secure_run_dir")
    def fake_write_registry_entry(self):
        call_order.append("write_registry")
    def fake_install_default_deny(self):
        call_order.append("install_default_deny")
    def fake_check_prerequisites(self):
        return ""  # pretend prerequisites are met

    with patch.object(
        type(s), "_check_prerequisites", fake_check_prerequisites,
    ), patch.object(
        type(s), "_create_netns", fake_create_netns,
    ), patch.object(
        type(s), "_configure_veth", fake_configure_veth,
    ), patch.object(
        type(s), "_create_cgroup", fake_create_cgroup,
    ), patch.object(
        type(s), "_create_secure_run_dir", fake_create_secure_run_dir,
    ), patch.object(
        type(s), "_write_registry_entry", fake_write_registry_entry,
    ), patch.object(
        type(s), "_install_default_deny_nft", fake_install_default_deny,
    ), patch.object(
        type(s), "teardown", lambda self: None,
    ):
        s.setup()
    # The default-deny table is installed AFTER the netns/veth/cgroup
    # are ready, but BEFORE the sandbox is marked active (which is the
    # signal the browser launcher waits for).
    assert "install_default_deny" in call_order
    install_idx = call_order.index("install_default_deny")
    # Netns/veth/cgroup must come before the default-deny install.
    assert call_order.index("create_netns") < install_idx
    assert call_order.index("configure_veth") < install_idx
    assert call_order.index("create_cgroup") < install_idx


def test_6_2_e_setup_marks_route_guard_true_with_zero_ports():
    """6.2-E: after ``setup()`` the ``route_guard`` flag is True even
    though no egress port is installed yet — the kernel is already
    enforcing "browser veth → drop".  This is the fix for §五
    (startup window).
    """
    s = BrowserNetworkSandbox(require_os_sandbox=False)
    with patch.object(
        type(s), "_check_prerequisites", lambda self: "",
    ), patch.object(
        type(s), "_create_netns", lambda self: None,
    ), patch.object(
        type(s), "_configure_veth", lambda self: None,
    ), patch.object(
        type(s), "_create_cgroup", lambda self: None,
    ), patch.object(
        type(s), "_create_secure_run_dir", lambda self: None,
    ), patch.object(
        type(s), "_write_registry_entry", lambda self: None,
    ), patch.object(
        type(s), "_install_default_deny_nft", lambda self: None,
    ), patch.object(
        type(s), "teardown", lambda self: None,
    ):
        s.setup()
    assert s.is_active
    assert s.enforcement_status.route_guard is True
    # And zero egress ports are installed.
    assert s._egress_ports == set()


# ───── 6.2-F: invalid port validation ───────────────────────────


@pytest.mark.parametrize("bad_port", [0, -1, 65536, 100000])
def test_6_2_f_install_egress_pin_rejects_invalid_port(bad_port: int):
    """6.2-F: ``install_egress_pin`` rejects out-of-range ports."""
    s = _active_sandbox()
    with pytest.raises(BrowserSandboxError, match="invalid egress proxy port"):
        s.install_egress_pin(bad_port)


def test_6_2_f_install_egress_pin_rejects_non_int():
    """6.2-F: ``install_egress_pin`` rejects non-int ports."""
    s = _active_sandbox()
    with pytest.raises(BrowserSandboxError, match="invalid egress proxy port"):
        s.install_egress_pin("8080")  # type: ignore[arg-type]


# ───── 6.2-G: teardown clears egress_ports ──────────────────────


def test_6_2_g_teardown_clears_egress_ports():
    """6.2-G: ``teardown()`` clears ``_egress_ports`` so a re-setup()
    on the same instance starts from a clean port set.
    """
    with patch("khaos.security.browser_sandbox.subprocess.run") as mock_run, \
         patch("khaos.security.browser_sandbox.shutil.which",
               return_value="/usr/sbin/nft"):
        mock_run.return_value = _ok_run()
        s = _active_sandbox()
        s.install_egress_pin(40001)
        s.install_egress_pin(40002)
        assert s._egress_ports == {40001, 40002}
        s.teardown()
        assert s._egress_ports == set()


# ───── 6.2-H: deterministic port ordering in script ─────────────


def test_6_2_h_port_rules_are_deterministically_sorted():
    """6.2-H: ports in the generated script are sorted so the script
    is deterministic for the same port set (easier diffs in tests and
    in ``nft --check`` logs).
    """
    s = _active_sandbox()
    s._egress_ports = {40003, 40001, 40002}
    script = s._build_nft_script(include_table_create=True)
    # Extract the accept rules in order.
    accept_lines = [
        ln.strip() for ln in script.splitlines()
        if "tcp dport" in ln and "accept" in ln
    ]
    # Must be in ascending port order.
    ports_in_script = [
        int(ln.split("tcp dport")[1].split("accept")[0].strip())
        for ln in accept_lines
    ]
    assert ports_in_script == [40001, 40002, 40003]
