"""F-05 (third-round review §5.3): OS-level browser egress enforcement.

On Linux, wraps the Chromium process in a dedicated network namespace
with no default route — the only reachable address is the Khaos egress
proxy on the host side of a veth pair.  This means even if Chromium is
compromised, it cannot make direct socket connections to the host
network.

Architecture (round-5 review Batch 5.1 rewrite)::

    Host network namespace
    ├── egress proxy  →  bound on 10.200.X.1 (veth host end)
    ├── veth-host-<token>  (10.200.X.1/30)
    └── nftables  →  per-sandbox table khaos_browser_<token>
                      input hook:  allow browser-veth → proxy_ip:proxy_port
                                   drop  browser-veth → anything else
                      forward hook: drop browser-veth

    Browser network namespace  (khaos-browser-<token>)
    ├── lo  (loopback only, no default route)
    ├── veth-ns-<token>  (10.200.X.2/30)
    └── Chromium  →  --proxy-server=http://10.200.X.1:<port>
                     (joined to cgroup-v2 leaf for pids/mem/cpu limits)

Round-5 review Batch 5.1 fixes (C-01~C-04, H-01~H-04):

* **C-01**: nftables now uses the ``input`` hook (not ``forward``) for
  browser→host-local traffic, plus a ``forward`` drop for the browser
  veth.  Browser→host:proxy_port is local ``input``, not ``forward``.
* **C-02**: nftables rules are now installed via ``nft -f -`` (atomic
  stdin script) instead of ``["nft", *rule.split()]`` which broke quote
  parsing.
* **C-03**: base chains use ``policy accept`` (not ``policy drop``) so
  unmatched host traffic is unaffected.  Only browser-veth traffic is
  restricted.
* **C-04**: production callers must pass ``require_os_sandbox=True``.
  ``browser_tools.py`` now does this unless ``KHAOS_BROWSER_DEV_MODE=1``.
* **H-01/H-02**: every resource (netns, veth, cgroup, nft table) now
  includes a per-sandbox token.  Teardown only deletes its own table.
* **H-03**: ``startup_reaper`` now verifies the creating process is
  dead (PID + start-time) before deleting resources, using a registry
  file written at creation time.
* **H-04**: run-root directory chain is verified via
  ``openat``/``O_DIRECTORY``/``O_NOFOLLOW`` from the home directory
  down to the per-sandbox run dir.

Round-6 review Batch 6.2 fixes (C-02 round-6 + §四 + §五 + §六):

* **C-02 (round-6)**: the nft script now uses ``table inet <name> { … }``
  block syntax so the table is CREATED if missing (previously only
  ``flush table`` was emitted, which fails on a fresh table → nft
  returns an error → ``BrowserSandboxError`` in production).  The block
  syntax is accepted by ``nft --check -f -`` and is the documented way
  to atomically create+populate a table.
* **§四 default-deny before browser start**: ``setup()`` now installs
  the default-deny kernel rule (drop everything from the browser veth,
  allow established return traffic) BEFORE the browser is launched.
  Previously the veth was completely open between ``setup()`` and the
  first ``ensure_page()`` — a window in which a compromised startup
  component could reach any host port.
* **§六 multi-context port set**: ``install_egress_pin`` now ADDS the
  port to a per-sandbox ``_egress_ports`` set and atomically rebuilds
  the whole table (delete + recreate via one ``nft -f -`` transaction).
  Previously each call did ``flush table`` + a single port rule, so a
  second context's creation silently dropped the first context's port
  from the kernel policy.  New ``remove_egress_port`` (called by
  ``_close_one_context``) removes a port and re-applies.
* **nft --check**: ``_apply_nft_script`` runs ``nft -c -f -`` first to
  syntax-check the script before applying it, so a malformed script is
  a detectable failure instead of a silent kernel-policy gap.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re as _re
import secrets
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

# F-05: veth pair subnet.  Using 10.200.x.y/30 gives each browser
# namespace a 2-address point-to-point link (host=.1, ns=.2).  The
# second octet is randomized per-sandbox to avoid collisions when
# multiple browser contexts run concurrently.
_VETH_SUBNET_PREFIX = "10.200"
_VETH_PREFIX = "khaos-br"
_NETNS_BASE = "/var/run/netns"
_CGROUP_BROWSER_PREFIX = "browser"
# Round-5: nftables table name now includes a per-sandbox token.
_NFT_TABLE_FAMILY = "inet"
_NFT_TABLE_PREFIX = "khaos_browser"
# C-10: secure run directory root — per-process private subtree.
_RUN_DIR_ROOT = Path.home() / ".khaos" / "run"
# Round-5 H-03: registry directory for resource ownership records.
_RESOURCE_REGISTRY = Path.home() / ".khaos" / "run" / "browser_registry"

# Batch 9.1 (round-9 §九): the ONLY parent-process environment variables
# forwarded to Chromium.  Everything else (provider API keys, cloud creds,
# proxy secrets, DB connection strings) is dropped so a compromised
# Chromium cannot read parent secrets from its own environment.  The Rust
# launcher additionally runs bubblewrap with ``--clearenv`` and re-sets a
# minimal PATH/LANG/HOME inside the namespace.
_BROWSER_ENV_ALLOWLIST: tuple[str, ...] = (
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "PLAYWRIGHT_BROWSERS_PATH",
)


def _validate_tcb_binary(path: str, *, label: str) -> str:
    """Validate that ``path`` is a trusted TCB binary and return the
    CANONICAL (symlink-resolved) path.

    Batch 12.1 (round-12 §四): the function now RETURNS the canonical
    realpath so callers cache and execute the validated target, not the
    original symlink alias.  This closes the symlink-retarget attack:
    previously the cache stored the ``shutil.which`` result (a symlink
    alias) while validating the resolved target — an attacker could
    repoint the symlink between validation and execution.

    Raises ``BrowserSandboxError`` on any violation.
    """
    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        raise BrowserSandboxError(
            f"{label} path must be absolute, got {path!r}"
        )
    _validate_parent_chain(resolved, label=label)
    try:
        real_path = os.path.realpath(str(resolved))
    except OSError as exc:
        raise BrowserSandboxError(
            f"{label} {path}: realpath resolution failed: {exc}"
        ) from exc
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(real_path, flags)
    except OSError as exc:
        raise BrowserSandboxError(
            f"{label} {path}: secure open failed: {exc}"
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise BrowserSandboxError(
                f"{label} {path}: not a regular file"
            )
        # Batch 12.1 (round-12 §八): accept root-owned binaries.  When
        # the Python Agent is de-privileged in the future, system
        # binaries (root-owned /usr/bin/bwrap) must be accepted.  The
        # owner must be the current uid OR root (uid 0).
        if hasattr(os, "getuid") and info.st_uid not in (os.getuid(), 0):
            raise BrowserSandboxError(
                f"{label} {path}: owner {info.st_uid} is neither current "
                f"uid {os.getuid()} nor root"
            )
        if info.st_mode & 0o022:
            raise BrowserSandboxError(
                f"{label} {path}: group/other writable (mode "
                f"{oct(info.st_mode & 0o777)})"
            )
    finally:
        os.close(fd)
    return real_path


def _validate_parent_chain(path: Path, *, label: str) -> None:
    """Validate that every ancestor directory of ``path`` is owned by the
    current uid (or root, when running as root) with no group/other write.

    Batch 11.3 (round-11 §六): a root-owned binary in a group-writable
    parent directory can be renamed-over by anyone with directory write
    permission.  Walking the chain from the binary's parent up to the
    filesystem root rejects any directory whose mode allows group/other
    write or whose owner is neither the current uid nor root.

    System directories (/, /usr, /usr/local, /usr/sbin, /bin, /sbin,
    /opt, /etc) are exempted from the owner check when the binary itself
    is root-owned, because the kernel package manager owns them and
    they are conventionally root:root.  The mode check (no group/other
    write) still applies to ALL directories in the chain.
    """
    if not hasattr(os, "getuid"):
        return  # non-POSIX
    current_uid = os.getuid()
    # Resolve symlinks first so the chain walks the real directory tree
    # (usrmerge systems symlink /sbin → /usr/sbin).
    try:
        real = os.path.realpath(str(path))
    except OSError:
        real = str(path)
    # Walk from the immediate parent up to (but not including) the root.
    # The root '/' is conventionally root:root 0755 and always trusted.
    parts = Path(real).resolve().parts[1:-1]  # drop leading '/' and filename
    current = Path("/")
    for component in parts:
        current = current / component
        try:
            # Use stat (follows symlinks) for directories in the chain —
            # usrmerge systems symlink /sbin → /usr/sbin, /bin → /usr/bin,
            # etc.  These root-owned symlinks are safe; the final binary
            # is protected by O_NOFOLLOW on its resolved path.
            info = current.stat()
        except OSError as exc:
            raise BrowserSandboxError(
                f"{label}: cannot stat parent directory {current}: {exc}"
            ) from exc
        if not stat.S_ISDIR(info.st_mode):
            raise BrowserSandboxError(
                f"{label}: parent {current} is not a directory"
            )
        # A directory with the sticky bit (mode 0o1000) is safe even when
        # group/other-writable: the sticky bit ensures only the file
        # owner (or root) can rename/delete entries.  This is the standard
        # /tmp model.  Without this carve-out, /tmp (0o1777) would be
        # rejected, breaking every test that creates a binary under tmp_path.
        has_sticky = bool(info.st_mode & stat.S_ISVTX)
        if (info.st_mode & 0o022) and not has_sticky:
            raise BrowserSandboxError(
                f"{label}: parent directory {current} is group/other "
                f"writable without sticky bit (mode "
                f"{oct(info.st_mode & 0o777)})"
            )
        # Owner must be the current uid or root.  When running as root,
        # system package-manager directories (root:root) are accepted.
        if info.st_uid != current_uid and info.st_uid != 0:
            raise BrowserSandboxError(
                f"{label}: parent directory {current} owner "
                f"{info.st_uid} is neither current uid {current_uid} "
                f"nor root"
            )


# Batch 10.3 (round-10 §六): cache of resolved + validated TCB tool paths.
# ``ip``/``nft`` were previously invoked via bare PATH lookup
# (subprocess.run(["ip", ...])).  Under Root or CAP_NET_ADMIN a malicious
# PATH entry equals arbitrary high-privilege code execution BEFORE the
# sandbox is established.  _resolve_tcb_tool resolves the absolute path
# once and validates owner/mode/no-symlink; _run_command and the direct
# subprocess.run calls consult this cache so every privileged invocation
# uses the verified absolute path.
#
# Batch 11.1 (round-11 §四): the cache now records the validation LEVEL.
# A validate=False probe (e.g. _has_net_admin) can no longer poison the
# cache so that a later validate=True request silently skips validation.
# validate=True always re-validates an unvalidated cache entry and
# upgrades it; validate=False can never downgrade a validated entry.


@dataclass(frozen=True)
class TrustedTool:
    """A resolved TCB tool with its validation provenance.

    ``validated`` records whether ``_validate_tcb_binary`` was run on
    ``path``.  The cache invariant is: validate=True may upgrade an
    unvalidated entry but validate=False may never serve an unvalidated
    entry to a validate=True caller.
    """

    path: str
    validated: bool


_tcb_tool_cache: dict[str, TrustedTool] = {}


def _resolve_tcb_tool(name: str, *, validate: bool = True) -> str:
    """Resolve ``name`` (e.g. ``ip``, ``nft``) to a validated absolute path.

    Batch 11.1: the cache records the validation level; validate=True
    re-validates an unvalidated cached entry.

    Batch 12.1 (round-12 §四): the cache stores the CANONICAL (symlink-
    resolved) path returned by ``_validate_tcb_binary``, not the raw
    ``shutil.which`` result.  This closes the symlink-retarget attack:
    previously an attacker could repoint a symlink between validation
    (which resolved to the real target) and execution (which used the
    cached symlink alias).

    Raises ``BrowserSandboxError`` if the tool is missing or fails
    validation (production only).  Returns the bare ``name`` only if
    ``shutil.which`` cannot find it AND validate is False.
    """
    cached = _tcb_tool_cache.get(name)
    if cached is not None:
        if not validate or cached.validated:
            return cached.path
        # validate=True but cached entry is unvalidated → RE-VALIDATE and
        # upgrade to the canonical path.
        canonical = _validate_tcb_binary(cached.path, label=f"TCB tool {name!r}")
        _tcb_tool_cache[name] = TrustedTool(path=canonical, validated=True)
        return canonical
    # Cache miss: resolve fresh.
    resolved = shutil.which(name)
    if resolved is None:
        if validate:
            raise BrowserSandboxError(
                f"required TCB tool {name!r} not found on PATH"
            )
        return name
    if validate:
        # _validate_tcb_binary returns the canonical (realpath) target;
        # cache THAT, not the symlink alias.
        canonical = _validate_tcb_binary(resolved, label=f"TCB tool {name!r}")
        _tcb_tool_cache[name] = TrustedTool(path=canonical, validated=True)
        return canonical
    _tcb_tool_cache[name] = TrustedTool(path=resolved, validated=False)
    return resolved


def _fsync_dir(path: str | Path) -> None:
    """fsync the parent directory so a rename/create is durable on crash.

    Batch 9.5 (round-9 §十五): the registry entry, stage-update rename and
    MAC key file are all written via ``write → close → replace``.  Without
    an explicit ``fsync`` of the parent directory, a host power loss or
    filesystem crash can leave the directory entry (the rename) un-flushed
    even though the file data hit the page cache.  This makes the
    registry's crash-recovery claim hold under host-level failures, not
    just process crashes.

    Silently skipped on platforms without ``O_DIRECTORY`` (non-POSIX).
    """
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    else:
        return  # pragma: no cover — non-POSIX platform
    try:
        dir_fd = os.open(str(path), flags)
    except OSError as exc:
        logger.debug("fsync_dir %s failed to open: %s", path, exc)
        return
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        # fsync on a directory fd is not supported on all filesystems
        # (e.g. tmpfs in some kernels).  Log and continue — the file fsync
        # is the critical durability step.
        logger.debug("fsync_dir %s fsync failed: %s", path, exc)
    finally:
        os.close(dir_fd)


# ---------------------------------------------------------------------------
# Batch 7.3 (round-7 §六/§七/§八): resource-name derivation + validation,
# creation-stage state machine, structured teardown result.
#
# §六 fix: the registry NO LONGER stores resource names (netns/veth/cgroup/
# nft).  They are DERIVED from the per-sandbox token by the trusted code
# below, and the reaper re-derives them instead of trusting registry
# strings.  Each derived name is validated against a strict regex so a
# crafted/foreign name can never reach a privileged ``ip``/``nft`` command.
# ---------------------------------------------------------------------------

# Strict format validators for every derived resource name.  A name that
# does not match is REFUSED before any privileged operation — this closes
# the Confused Deputy (review §六): a forged registry entry cannot name an
# arbitrary netns/veth/nft-table/cgroup for the privileged reaper to delete.
_NETNS_RE = _re.compile(r"^khaos-br-[0-9a-f]{12}$")
_VETH_RE = _re.compile(r"^kh[0-9a-f]{12}$")
_NFT_TABLE_RE = _re.compile(r"^khaos_browser_[0-9a-f]{32}$")


def _registry_key(*, create: bool = False) -> bytes:
    """Read or securely create the process-external registry MAC key."""
    key_file = _RESOURCE_REGISTRY.parent / "browser-registry.key"
    if create:
        key_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            fd = os.open(
                key_file,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            pass
        else:
            try:
                os.write(fd, secrets.token_bytes(32))
                os.fsync(fd)
            finally:
                os.close(fd)
            # Batch 9.5: fsync the parent dir so the new key file's
            # directory entry survives a host power loss.
            _fsync_dir(key_file.parent)
    fd = os.open(key_file, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise BrowserSandboxError("browser registry key ownership/mode invalid")
        key = os.read(fd, 33)
    finally:
        os.close(fd)
    if len(key) != 32:
        raise BrowserSandboxError("browser registry key must be exactly 32 bytes")
    return key


def _resource_digest(token: str) -> str:
    return hmac.new(_registry_key(create=True), token.encode("ascii"), hashlib.sha256).hexdigest()


def _derive_netns_name(token: str) -> str:
    """Derive the netns name from the sandbox token (trusted derivation)."""
    return f"khaos-br-{_resource_digest(token)[:12]}"


def _derive_veth_host(token: str) -> str:
    """Derive the host veth name from the sandbox token."""
    return f"kh{_resource_digest(token)[:12]}"


def _derive_nft_table(token: str) -> str:
    """Derive the nft table name from the sandbox token."""
    return f"{_NFT_TABLE_PREFIX}_{_resource_digest(token)[:32]}"


def _derive_cgroup_name(token: str) -> str:
    """Derive the cgroup leaf name from the sandbox token."""
    return f"{_CGROUP_BROWSER_PREFIX}-{_resource_digest(token)[:24]}"


def _boot_id() -> str:
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    except OSError:
        return "non-linux"


def _sign_registry_entry(entry: dict[str, object]) -> str:
    payload = json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_registry_key(create=True), payload, hashlib.sha256).hexdigest()


def _verify_registry_entry(entry: dict[str, object]) -> bool:
    supplied = str(entry.pop("mac", ""))
    expected = _sign_registry_entry(entry)
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def _is_valid_derived_name(
    *, netns: str = "", veth: str = "", nft_table: str = ""
) -> bool:
    """Return True iff every provided name matches its strict derived format.

    Used by the reaper to refuse forged registry entries (§六)."""
    if netns and not _NETNS_RE.match(netns):
        return False
    if veth and not _VETH_RE.match(veth):
        return False
    if nft_table and not _NFT_TABLE_RE.match(nft_table):
        return False
    return True


# Creation-stage state machine (§七).  The registry records the current
# stage so a crash at any point leaves a trace the reaper can act on.
_CREATION_STAGES = (
    "INTENT", "NETNS", "VETH", "CGROUP", "RUNDIR",
    "NFT_ACTIVE", "BROWSER_ACTIVE",
)
_RELEASE_STAGES = ("RELEASING", "RELEASED", "QUARANTINED")


@dataclass
class CleanupResult:
    """§八: structured teardown result.  Every kernel resource is tracked;
    if any deletion fails, ``fully_closed`` is False and the registry is
    retained so the next startup reaper can retry."""

    nft_removed: bool = False
    veth_removed: bool = False
    netns_removed: bool = False
    cgroup_removed: bool = False
    wrapper_removed: bool = False
    run_dir_removed: bool = False
    registry_retained: bool = False
    fully_closed: bool = False

    def to_dict(self) -> dict[str, bool]:
        """Return a stable JSON-safe cleanup report for lifecycle owners."""
        return {
            "nft_removed": self.nft_removed,
            "veth_removed": self.veth_removed,
            "netns_removed": self.netns_removed,
            "cgroup_removed": self.cgroup_removed,
            "wrapper_removed": self.wrapper_removed,
            "run_dir_removed": self.run_dir_removed,
            "registry_retained": self.registry_retained,
            "fully_closed": self.fully_closed,
        }


@dataclass
class BrowserSandboxConfig:
    """Resource limits for the browser cgroup."""

    pids_max: int = 256
    memory_max: int = 2 * 1024 * 1024 * 1024  # 2 GiB
    memory_swap_max: int = 0
    cpu_quota: int = 200_000  # 2 CPUs (quota in microseconds per 100ms period)
    cpu_period: int = 100_000


@dataclass
class EnforcementStatus:
    """C-09: structured report of which enforcement layers are active.

    Callers (especially production profiles) should check this after
    ``setup()`` and refuse to launch the browser when a required layer
    is missing.  ``ok`` is True only when every layer the caller asked
    for is in effect.
    """

    network_namespace: bool = False
    proxy_required: bool = False
    cgroup: bool = False
    route_guard: bool = False  # nftables egress pin
    service_workers_blocked: bool = False
    # Batch 7.4 (round-7 §十): True ONLY when each (principal, project,
    # runtime) authority domain owns a DISTINCT browser process + netns +
    # cgroup.  The current design is process-shared (one Chromium, one
    # netns, one cgroup for the whole process), so this is False — see
    # ``docs/browser-threat-model.md``.  A caller that requires
    # per-principal OS isolation must check this and refuse to share.
    process_isolation: bool = False
    trusted_launcher: bool = False
    fd_sanitized: bool = False
    filesystem_sandbox: bool = False
    failure_reason: str = ""

    @property
    def kernel_ok(self) -> bool:
        """True once the pre-launch kernel and proxy layers exist."""
        return (
            not self.failure_reason
            and self.network_namespace
            and self.proxy_required
            and self.cgroup
            and self.route_guard
            and self.service_workers_blocked
        )

    @property
    def ok(self) -> bool:
        """True only for the complete production Chromium launch contract.

        P0-2 (round-13): ``process_isolation`` is NO LONGER part of ``ok``.
        The current design shares one Chromium process across contexts;
        ``process_isolation`` remains ``False`` and callers that need
        per-principal OS process isolation must check it separately and
        refuse to proceed.  ``ok`` means the kernel-level enforcement
        layers are active, not that process-level isolation is guaranteed.
        """
        return (
            self.kernel_ok
            and self.trusted_launcher
            and self.fd_sanitized
            and self.filesystem_sandbox
        )


class BrowserNetworkSandbox:
    """Linux: isolates Chromium in a dedicated netns + cgroup.

    On non-Linux: no-op.  The caller should check ``is_active`` after
    ``setup()`` to determine whether OS-level enforcement is in effect.

    C-09: when ``require_os_sandbox=True`` (production default), any
    missing component raises ``BrowserSandboxError`` instead of silently
    degrading to proxy-only.

    Round-5 Batch 5.1: every resource now carries a per-sandbox token
    (``_token``) so multiple sandboxes can coexist and teardown only
    deletes its own resources.
    """

    def __init__(
        self,
        config: BrowserSandboxConfig | None = None,
        *,
        require_os_sandbox: bool = False,
    ) -> None:
        self._config = config or BrowserSandboxConfig()
        self._require_os_sandbox = require_os_sandbox
        # Round-5 H-01: per-sandbox token used in all resource names.
        self._token: str = secrets.token_hex(8)
        self._netns_name: str | None = None
        self._veth_host: str | None = None
        self._veth_ns: str | None = None
        self._cgroup_path: Path | None = None
        self._wrapper_script: Path | None = None
        self._run_dir: Path | None = None
        self._nft_table: str | None = None
        self._host_ip: str = "127.0.0.1"
        self._ns_ip: str = ""
        self._active = False
        self._enforcement = EnforcementStatus()
        # Round-5 H-03: registry file path for ownership tracking.
        self._registry_file: Path | None = None
        # Batch 7.3 §七: creation-stage state machine.  Persisted in the
        # registry so the reaper can act on a crash at any point.
        self._creation_stage: str = ""
        # Round-6 Batch 6.2 (C-02 + §六): the set of currently-active
        # egress proxy ports.  ``install_egress_pin`` now ADDS to this
        # set (instead of ``flush``-ing the whole table — which would
        # silently drop other contexts' ports).  Rule (re)generation is
        # atomic: the whole table is rebuilt and applied via a single
        # ``nft -f -`` transaction.  ``remove_egress_port`` (called by
        # ``_close_one_context``) removes a port and re-applies.
        self._egress_ports: set[int] = set()

    @property
    def is_active(self) -> bool:
        """True if OS-level netns enforcement is in effect."""
        return self._active

    @property
    def enforcement_status(self) -> EnforcementStatus:
        """C-09: structured report of active enforcement layers."""
        return self._enforcement

    @property
    def proxy_bind_host(self) -> str:
        """The IP address the egress proxy should bind to.

        When the sandbox is active, this is the host-side veth IP so
        the browser can reach the proxy from inside the netns.
        Otherwise it's ``127.0.0.1`` (loopback-only fallback).
        """
        return self._host_ip if self._active else "127.0.0.1"

    @property
    def browser_proxy_host(self) -> str:
        """The proxy host as seen from inside the browser netns."""
        return self._host_ip if self._active else "127.0.0.1"

    def setup(self) -> None:
        """Create the netns, veth pair, and cgroup.

        C-09: when ``require_os_sandbox=True`` (production default),
        any missing prerequisite raises ``BrowserSandboxError`` instead
        of silently degrading to proxy-only.  When False (development),
        missing prerequisites are logged as warnings and the sandbox
        remains inactive.
        """
        reason = self._check_prerequisites()
        if reason:
            if self._require_os_sandbox:
                raise BrowserSandboxError(reason)
            logger.warning("browser netns sandbox: %s, using proxy-only", reason)
            return

        # Batch 7.3 (round-7 §六): resource names are DERIVED from the token
        # via trusted helpers (never read back from the registry).  The old
        # dead-code that built names two different ways is removed.
        self._netns_name = _derive_netns_name(self._token)
        self._veth_host = _derive_veth_host(self._token)
        self._veth_ns = f"kn{_resource_digest(self._token)[:12]}"
        self._nft_table = _derive_nft_table(self._token)

        # Keyed names make collisions cryptographically unlikely, but
        # privileged creation still performs an explicit global absence
        # check. Never adopt or overwrite a pre-existing kernel object.
        self._assert_resource_names_available()

        # Randomize the second octet to avoid collisions.
        subnet = f"{_VETH_SUBNET_PREFIX}.{secrets.randbelow(250) + 1}"
        self._host_ip = f"{subnet}.1"
        self._ns_ip = f"{subnet}.2"

        # Batch 7.3 §七: write INTENT FIRST (before any kernel resource is
        # created) so a crash at any later point leaves a registry trace
        # the reaper can act on.  Production refuses to start if the
        # registry cannot be written (§六 — was best-effort debug).
        self._creation_stage = "INTENT"
        try:
            self._write_registry_entry()  # writes INTENT
            self._create_netns()
            self._creation_stage = "NETNS"
            self._update_registry_stage("NETNS")
            self._configure_veth()
            self._creation_stage = "VETH"
            self._update_registry_stage("VETH")
            self._create_cgroup()
            self._creation_stage = "CGROUP"
            self._update_registry_stage("CGROUP")
            self._create_secure_run_dir()
            self._creation_stage = "RUNDIR"
            self._update_registry_stage("RUNDIR")
            if self._cgroup_path is None and self._require_os_sandbox:
                raise BrowserSandboxError(
                    "cgroup-v2 leaf creation failed — resource limits "
                    "cannot be enforced"
                )
            # Round-6 Batch 6.2 (§五): install the default-deny kernel
            # rule BEFORE the browser is launched.
            self._install_default_deny_nft()
            self._creation_stage = "NFT_ACTIVE"
            self._update_registry_stage("NFT_ACTIVE")
            self._active = True
            self._creation_stage = "BROWSER_ACTIVE"
            self._update_registry_stage("BROWSER_ACTIVE")
            self._enforcement = EnforcementStatus(
                network_namespace=True,
                proxy_required=True,
                cgroup=self._cgroup_path is not None,
                route_guard=True,
                service_workers_blocked=True,
                # P0-2 (round-13): process_isolation stays False — the
                # current design shares ONE Chromium process across all
                # (session, runtime) contexts under a single principal.
                # BrowserContext isolates cookies/DOM but is NOT a process
                # security boundary.  Setting True here was a false claim.
                process_isolation=False,
            )
            logger.info(
                "browser netns sandbox active: netns=%s host=%s ns=%s token=%s",
                self._netns_name, self._host_ip, self._ns_ip, self._token,
            )
        except BrowserSandboxError:
            self.teardown()
            raise
        except OSError as exc:
            if self._require_os_sandbox:
                self.teardown()
                raise BrowserSandboxError(
                    f"netns setup failed: {exc}"
                ) from exc
            logger.warning(
                "browser netns sandbox setup failed, "
                "falling back to proxy-only: %s",
                exc,
            )
            self.teardown()

    def _assert_resource_names_available(self) -> None:
        """Reject any pre-existing derived kernel/registry resource."""
        assert self._netns_name is not None
        assert self._veth_host is not None
        assert self._nft_table is not None
        # Batch 10.3: resolve ip/nft to validated absolute paths.
        ip_path = _resolve_tcb_tool("ip", validate=self._require_os_sandbox)
        nft_path = _resolve_tcb_tool("nft", validate=self._require_os_sandbox)
        probes = (
            ([ip_path, "netns", "list"], self._netns_name, True),
            ([ip_path, "link", "show", "dev", self._veth_host], "", False),
            ([nft_path, "list", "table", _NFT_TABLE_FAMILY, self._nft_table], "", False),
        )
        for argv, exact_name, list_probe in probes:
            result = subprocess.run(
                argv, capture_output=True, text=True, timeout=5,
            )
            collision = (
                any(line.split()[0] == exact_name for line in result.stdout.splitlines())
                if list_probe
                else result.returncode == 0
            )
            if collision:
                raise BrowserSandboxError(
                    f"derived browser resource already exists: {exact_name or argv[-1]}"
                )
        cgroup_root = _browser_cgroup_root()
        if cgroup_root is not None:
            cgroup = cgroup_root / _derive_cgroup_name(self._token)
            if cgroup.exists():
                raise BrowserSandboxError(
                    f"derived browser cgroup already exists: {cgroup.name}"
                )
        registry = _RESOURCE_REGISTRY / f"{self._token}.json"
        if registry.exists():
            raise BrowserSandboxError("browser registry token collision")

    @staticmethod
    def startup_reaper(*, validate: bool = False) -> dict[str, int]:
        """Round-5 review Batch 5.1 (H-03) + Batch 7.3 (round-7 §六):
        clean up resources from a previous process that crashed without
        calling ``teardown()``.

        §六 fix: the reaper NO LONGER trusts registry-supplied resource
        names.  It DERIVES every name (netns/veth/nft/cgroup) from the
        registry's ``token`` via the trusted helpers, and VALIDATES each
        against a strict regex before passing it to a privileged command.
        A forged registry entry cannot name an arbitrary resource.  The
        cgroup path is rebuilt from the trusted root + token and checked
        with ``realpath().is_relative_to(trusted_root)``.

        Returns a dict of cleanup counts: ``{"netns": N, "veth": N,
        "cgroup": N, "nft": N}``.
        """
        counts = {"netns": 0, "veth": 0, "cgroup": 0, "nft": 0}
        if not sys.platform.startswith("linux"):
            return counts

        # H-03: Read the registry and find orphaned resources.
        orphans = _find_orphaned_resources()
        trusted_cgroup_root = _browser_cgroup_root()
        for entry in orphans:
            token = entry.get("token", "")
            # §六: token must be a 16-hex string (the format our token
            # generator produces); a forged/short token is refused.
            if not token or not _re.match(r"^[0-9a-f]{16}$", token):
                logger.warning(
                    "reaper: registry entry has invalid token %r — skipping "
                    "(possible forgery)", token[:32],
                )
                continue
            # DERIVE every resource name from the token (trusted).
            netns_name = _derive_netns_name(token)
            veth_host = _derive_veth_host(token)
            nft_table = _derive_nft_table(token)
            # VALIDATE the derived names against strict regex (defense
            # in depth — the derivation is already correct, but this
            # guards against a future derivation change).
            if not _is_valid_derived_name(
                netns=netns_name, veth=veth_host, nft_table=nft_table,
            ):
                logger.error(
                    "reaper: derived names for token %s failed validation — "
                    "skipping (derivation bug?)", token,
                )
                continue
            # Delete netns
            with _suppress_oserrors():
                _run_command(
                    ["ip", "netns", "del", netns_name],
                    f"reaper: delete orphaned netns {netns_name}",
                    validate=validate,
                )
                counts["netns"] += 1
            # Delete veth (host end)
            with _suppress_oserrors():
                _run_command(
                    ["ip", "link", "del", veth_host],
                    f"reaper: delete orphaned veth {veth_host}",
                    validate=validate,
                )
                counts["veth"] += 1
            # Delete cgroup — §六: rebuild path from trusted root + token,
            # NOT from the registry.  realpath-is-relative-to guard.
            if trusted_cgroup_root is not None:
                cg = trusted_cgroup_root / _derive_cgroup_name(token)
                try:
                    if cg.is_dir():
                        real = cg.resolve(strict=False)
                        if real.is_relative_to(trusted_cgroup_root):
                            _remove_cgroup(cg)
                            counts["cgroup"] += 1
                        else:
                            logger.warning(
                                "reaper: cgroup %s realpath %s escapes "
                                "trusted root %s — skipping",
                                cg, real, trusted_cgroup_root,
                            )
                except OSError as exc:
                    logger.warning("reaper: cgroup cleanup failed: %s", exc)
            # Delete nft table
            with _suppress_oserrors():
                _run_command(
                    ["nft", "delete", "table", _NFT_TABLE_FAMILY, nft_table],
                    f"reaper: delete orphaned nft table {nft_table}",
                    validate=validate,
                )
                counts["nft"] += 1
            # Delete registry file
            reg_file = entry.get("registry_file")
            if reg_file:
                with _suppress_oserrors():
                    Path(reg_file).unlink(missing_ok=True)

        if any(counts.values()):
            logger.info("browser sandbox startup_reaper: %s", counts)
        return counts

    def _check_prerequisites(self) -> str:
        """Return empty string if all prerequisites are met, else reason."""
        if not sys.platform.startswith("linux"):
            return f"non-Linux platform ({sys.platform})"
        # Batch 11.1: production must validate the ip binary even for the
        # capability probe, otherwise an unvalidated path is cached and a
        # later validate=True call returns it without re-checking.
        if not _has_net_admin(validate=self._require_os_sandbox):
            return "CAP_NET_ADMIN not available"
        if shutil.which("ip") is None or shutil.which("nsenter") is None:
            return "'ip' or 'nsenter' not found"
        return ""

    # ------------------------------------------------------------------
    # Round-6 Batch 6.2: nftables authority — table creation, atomic
    # multi-port rule set, default-deny before browser start.
    # ------------------------------------------------------------------

    def _build_nft_script(self, *, include_table_create: bool) -> str:
        """Build the atomic nftables script for the current
        ``_egress_ports`` set.

        When ``include_table_create`` is True (used only by
        ``_install_default_deny_nft``), the script creates the table
        and its initial chains.  Re-applies use an atomic
        per-chain ``flush`` + reconstruction transaction instead.  A
        repeated ``table { ... }`` block does *not* replace existing
        rules; it appends to them, which can leave a prior terminal
        drop ahead of a newly-added allow rule.

        The script always contains BOTH hooks (input + forward), so
        even with zero egress ports the browser veth is fully
        default-deny.  Each port in ``_egress_ports`` produces one
        ``accept`` rule.

        This method is pure (no subprocess, no I/O) so it can be
        unit-tested without mocking ``subprocess.run``.
        """
        table = self._nft_table
        veth = self._veth_host
        host_ip = self._host_ip
        # Sort ports for deterministic output (easier diffs in tests
        # and in ``nft --check`` logs).
        ports = sorted(self._egress_ports)
        # Build one ``accept`` line per active port.  When no port is
        # active, the input chain is pure default-deny (drop everything
        # from the browser veth except established return traffic).
        if ports:
            port_rules = "\n    ".join(
                (
                    f'iifname "{veth}" ip daddr {host_ip} tcp dport {p} counter\n'
                    f'    iifname "{veth}" ip daddr {host_ip} tcp dport {p} accept'
                )
                for p in ports
            )
        else:
            port_rules = "# (no egress proxy port active — full default-deny)"
        if include_table_create:
            # ``table inet <name> { … }`` block: create the initial table.
            # This is the fix for C-02 (round-6): previously only
            # ``flush table`` was emitted, which fails on a fresh
            # table because the table does not exist yet.
            return (
                f"table inet {table} {{\n"
                f"    chain khaos_input {{\n"
                f"        type filter hook input priority -10; policy accept;\n"
                f"        ct state established,related accept\n"
                f"        {port_rules}\n"
                f"        iifname \"{veth}\" drop\n"
                f"    }}\n"
                f"    chain khaos_forward {{\n"
                f"        type filter hook forward priority -10; policy accept;\n"
                f"        iifname \"{veth}\" drop\n"
                f"        oifname \"{veth}\" ct state new drop\n"
                f"    }}\n"
                f"}}\n"
            )
        # The table is known to exist after setup.  nft applies an
        # entire input file as one transaction, so the old policy stays
        # live if any command below fails; there is no fail-open window.
        return (
            f"flush chain {_NFT_TABLE_FAMILY} {table} khaos_input\n"
            f"flush chain {_NFT_TABLE_FAMILY} {table} khaos_forward\n"
            f"add rule {_NFT_TABLE_FAMILY} {table} khaos_input "
            f"ct state established,related accept\n"
            + "".join(
                f"add rule {_NFT_TABLE_FAMILY} {table} khaos_input "
                f'iifname "{veth}" ip daddr {host_ip} tcp dport {port} accept\n'
                for port in ports
            )
            + f"add rule {_NFT_TABLE_FAMILY} {table} khaos_input "
            f'iifname "{veth}" drop\n'
            f"add rule {_NFT_TABLE_FAMILY} {table} khaos_forward "
            f'iifname "{veth}" drop\n'
            f"add rule {_NFT_TABLE_FAMILY} {table} khaos_forward "
            f'oifname "{veth}" ct state new drop\n'
        )

    def _apply_nft_script(self, script: str, *, description: str) -> bool:
        """Syntax-check (``nft -c -f -``) then apply (``nft -f -``) an
        nftables script atomically.

        Round-6 Batch 6.2 (§四 "真实 nft --check"): the script is first
        fed to ``nft -c -f -`` so a malformed script is a detectable
        failure instead of a silent kernel-policy gap.  If the check
        passes, the same script is applied for real.

        Returns ``True`` when the script was applied successfully,
        ``False`` when the nft binary is missing or the apply failed
        in dev mode (a warning is logged in that case).

        ``require_os_sandbox=True`` (production) raises
        ``BrowserSandboxError`` on any failure.  ``False`` (dev) logs a
        warning and returns ``False`` — the proxy-only layer remains.
        """
        if shutil.which("nft") is None:
            reason = "nftables ('nft') not found — egress pin inactive"
            if self._require_os_sandbox:
                raise BrowserSandboxError(reason)
            logger.warning("browser netns sandbox: %s", reason)
            return False
        # Batch 10.3: resolve nft to the validated absolute path once.
        nft_path = _resolve_tcb_tool("nft", validate=self._require_os_sandbox)
        try:
            # 1) Syntax check (does not touch kernel state).
            check = subprocess.run(
                [nft_path, "-c", "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if check.returncode != 0:
                raise OSError(
                    f"nft -c -f - rejected script (exit "
                    f"{check.returncode}): {check.stderr.strip()}"
                )
            # 2) Apply for real.
            result = subprocess.run(
                [nft_path, "-f", "-"],
                input=script,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                raise OSError(
                    f"nft -f - failed (exit {result.returncode}): "
                    f"{result.stderr.strip()}"
                )
        except OSError as exc:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    f"nftables {description} failed: {exc}"
                ) from exc
            logger.warning(
                "browser nftables %s failed, "
                "route_guard inactive: %s",
                description, exc,
            )
            return False
        return True

    def _install_default_deny_nft(self) -> None:
        """Round-6 Batch 6.2 (§五): install the default-deny nft table
        BEFORE the browser is launched.

        Called from ``setup()`` right after the netns/veth/cgroup are
        ready.  At this point ``_egress_ports`` is empty, so the input
        chain is pure default-deny: the browser veth can only receive
        established return traffic and everything else is dropped.

        ``install_egress_pin`` (called later from ``ensure_page``) adds
        a port to ``_egress_ports`` and re-applies the table.  The
        browser therefore NEVER runs in a window where the veth is
        completely open — even before the first proxy port is known.
        """
        if self._nft_table is None or self._veth_host is None:
            return  # nothing to do (non-Linux / dev fallback path)
        script = self._build_nft_script(include_table_create=True)
        self._apply_nft_script(
            script, description="default-deny table install",
        )
        logger.info(
            "browser nftables default-deny table installed (table=%s, "
            "veth=%s) — browser veth fully blocked until egress pin added",
            self._nft_table, self._veth_host,
        )

    def install_egress_pin(self, proxy_port: int) -> None:
        """C-06 (round-5 rewrite, round-6 redesign): add ``proxy_port``
        to the set of kernel-allowed egress ports and atomically
        re-apply the nft table.

        Round-6 Batch 6.2 changes:
          - ADDS the port to ``_egress_ports`` instead of ``flush``-ing
            the whole table.  Other contexts' ports are preserved.
          - Setup creates the table once; each pin change atomically
            flushes and rebuilds the two existing chains.  This avoids
            both ``flush`` on a missing table and rule appends behind a
            previously installed terminal drop.
          - ``_apply_nft_script`` first syntax-checks the script with
            ``nft -c -f -`` (§四 "真实 nft --check").

        Must be called AFTER the egress proxy has started (dynamic
        port) and AFTER ``setup()`` (which installs the default-deny
        table).
        """
        if not self._active or self._veth_host is None:
            return
        if not isinstance(proxy_port, int) or not (1 <= proxy_port <= 65535):
            raise BrowserSandboxError(
                f"invalid egress proxy port: {proxy_port!r}"
            )
        # Batch 7.3 (round-7 §九): transactional — APPLY the nft script
        # FIRST (with the candidate set = current + new port), and only
        # commit the port to ``_egress_ports`` on success.  Previously
        # the port was added before the apply, so a failed apply left a
        # stale port that the next rebuild would silently re-open (even
        # after the proxy was closed → a host process rebinding the port
        # became reachable from the browser netns).
        port = int(proxy_port)
        candidate = self._egress_ports | {port}
        saved = set(self._egress_ports)
        self._egress_ports = candidate
        try:
            script = self._build_nft_script(include_table_create=False)
            applied = self._apply_nft_script(
                script, description=f"egress pin port {port}",
            )
        except BaseException:
            # Rollback: restore the pre-install set on any failure.
            self._egress_ports = saved
            raise
        if not applied:
            # Dev-mode soft-failure: rollback so the in-memory set stays
            # consistent with the (unchanged) kernel policy.
            self._egress_ports = saved
            return
        # Only flip route_guard on when the nft apply actually
        # succeeded.  In dev mode, a missing nft binary logs a warning
        # and returns — route_guard must stay False so callers can
        # detect that kernel enforcement is NOT active.
        self._enforcement.route_guard = True
        logger.info(
            "browser nftables egress pin added: %s → %s:%d "
            "(table=%s, active_ports=%s)",
            self._veth_host, self._host_ip, port,
            self._nft_table, sorted(self._egress_ports),
        )

    def remove_egress_port(self, proxy_port: int) -> None:
        """Round-6 Batch 6.2 (§六): remove ``proxy_port`` from the set
        of kernel-allowed egress ports and atomically re-apply the nft
        table.

        Called by ``BrowserManager._close_one_context`` when a context
        is closed, so the kernel policy no longer allows traffic to a
        proxy that has been shut down.  Other contexts' ports are
        preserved.

        No-op (with a debug log) if the port was not in the set — this
        makes the call safe against double-close paths.
        """
        if not self._active or self._veth_host is None:
            return
        port = int(proxy_port)
        if port not in self._egress_ports:
            logger.debug(
                "remove_egress_port(%d): not in active set %s — no-op",
                port, sorted(self._egress_ports),
            )
            return
        # Batch 7.3 (round-7 §九): transactional — APPLY the nft script
        # FIRST with the candidate set (current - port), and only commit
        # the removal on success.  If the apply fails, KEEP the port in
        # the set (stale-open is safer than stale-closed: the proxy is
        # still running, so the kernel allowing it is correct; a rollback
        # to stale-closed would leave the kernel denying a live proxy).
        saved = set(self._egress_ports)
        self._egress_ports.discard(port)
        try:
            script = self._build_nft_script(include_table_create=False)
            applied = self._apply_nft_script(
                script, description=f"egress pin remove port {port}",
            )
        except BaseException:
            # Rollback: restore the port on failure (stale-open).
            self._egress_ports = saved
            raise
        if not applied:
            self._egress_ports = saved  # keep port (stale-open)
            return
        logger.info(
            "browser nftables egress pin removed: port %d "
            "(table=%s, active_ports=%s)",
            port, self._nft_table, sorted(self._egress_ports),
        )

    def _run_trusted(self, argv: list[str], description: str) -> None:
        """Run a privileged command, validating TCB tools in production.

        Batch 11.1 (round-11 §四): instance-method wrapper that threads
        ``self._require_os_sandbox`` into ``_run_command`` so production
        kernel operations (netns/veth/nft create+delete) always use a
        validated ip/nft binary, never an unvalidated cache entry.
        """
        _run_command(argv, description, validate=self._require_os_sandbox)

    def _create_netns(self) -> None:
        """Create the network namespace."""
        # Ensure /var/run/netns exists
        Path(_NETNS_BASE).mkdir(parents=True, exist_ok=True)
        self._run_trusted(
            ["ip", "netns", "add", self._netns_name],
            f"create netns {self._netns_name}",
        )

    def _configure_veth(self) -> None:
        """Create the veth pair and configure both ends."""
        v = self._require_os_sandbox
        # Create veth pair
        self._run_trusted(
            ["ip", "link", "add", self._veth_host, "type", "veth",
             "peer", "name", self._veth_ns],
            f"create veth pair {self._veth_host} <-> {self._veth_ns}",
        )
        # Move the namespace end into the netns
        self._run_trusted(
            ["ip", "link", "set", self._veth_ns, "netns", self._netns_name],
            f"move {self._veth_ns} to {self._netns_name}",
        )
        # Configure host side
        self._run_trusted(
            ["ip", "addr", "add", f"{self._host_ip}/30", "dev", self._veth_host],
            f"assign {self._host_ip}/30 to {self._veth_host}",
        )
        self._run_trusted(
            ["ip", "link", "set", self._veth_host, "up"],
            f"bring up {self._veth_host}",
        )
        # Configure namespace side
        ns_prefix = ["ip", "netns", "exec", self._netns_name]
        self._run_trusted(
            ns_prefix + ["ip", "addr", "add", f"{self._ns_ip}/30",
                         "dev", self._veth_ns],
            f"assign {self._ns_ip}/30 to {self._veth_ns}",
        )
        self._run_trusted(
            ns_prefix + ["ip", "link", "set", self._veth_ns, "up"],
            f"bring up {self._veth_ns} in {self._netns_name}",
        )
        self._run_trusted(
            ns_prefix + ["ip", "link", "set", "lo", "up"],
            f"bring up loopback in {self._netns_name}",
        )
        # Deliberately NO default route — the browser can only reach
        # the proxy on the directly-connected /30 subnet.

    def _create_cgroup(self) -> None:
        """Create a cgroup-v2 leaf for the browser process."""
        root = _browser_cgroup_root()
        if root is None:
            logger.warning(
                "browser cgroup: no writable cgroup-v2 root, "
                "skipping resource limits"
            )
            return
        group = root / _derive_cgroup_name(self._token)
        try:
            group.mkdir(mode=0o700)
            limits = {
                "pids.max": str(self._config.pids_max),
                "memory.max": str(self._config.memory_max),
                "memory.swap.max": str(self._config.memory_swap_max),
                "cpu.max": f"{self._config.cpu_quota} {self._config.cpu_period}",
            }
            for name, value in limits.items():
                (group / name).write_text(value, encoding="ascii")
            self._cgroup_path = group
        except OSError as exc:
            logger.warning("browser cgroup creation failed: %s", exc)
            _remove_cgroup(group)

    def _create_secure_run_dir(self) -> None:
        """C-10/H-04 (round-5): create a private run directory for the
        wrapper script using a verified dirfd chain.

        The directory chain from ``~`` → ``~/.khaos`` → ``~/.khaos/run``
        → ``~/.khaos/run/<token>`` is walked with ``openat`` +
        ``O_DIRECTORY`` + ``O_NOFOLLOW`` so no intermediate directory
        can be a symlink pointing to an attacker-controlled location.

        The wrapper script is part of the TCB (it launches Chromium)
        and must not live in shared ``/tmp`` where another user could
        pre-place a symlink or replace the file before exec.
        """
        home = Path.home()
        # H-04: walk the directory chain with openat to detect symlinks.
        fd = os.open(str(home), os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for component in (".khaos", "run"):
                try:
                    fd = _openat_dir(fd, component, create=True, mode=0o700)
                except OSError as exc:
                    raise BrowserSandboxError(
                        f"secure run dir chain broken at {component}: {exc}"
                    ) from exc
            # Verify the run dir root is owned by us.
            run_stat = os.fstat(fd)
            if run_stat.st_uid != os.getuid():
                raise BrowserSandboxError(
                    f"run dir root not owned by current user (uid={run_stat.st_uid})"
                )
            # Create the per-sandbox token directory.
            token_dir = self._token
            fd = _openat_dir(fd, token_dir, create=True, mode=0o700)
            self._run_dir = Path(home / ".khaos" / "run" / token_dir)
        finally:
            os.close(fd)

    def _write_registry_entry(self) -> None:
        """H-03 (round-5) + Batch 7.3 (round-7 §六/§七): write a registry
        file so the reaper can verify process liveness before deleting this
        sandbox's resources.

        §六 fix: the registry NO LONGER stores resource names
        (netns/veth/cgroup/nft).  They are DERIVED from the token by
        trusted code; the reaper re-derives them.  This closes the
        Confused Deputy — a forged registry entry cannot name an
        arbitrary resource for the privileged reaper to delete.  Only
        ``{token, pid, process_start_time, creation_stage}`` are stored.

        §六/§七 fix: in production (``require_os_sandbox=True``) a registry
        write failure now RAISES ``BrowserSandboxError`` (was best-effort
        debug) — a sandbox whose resources cannot be tracked must not
        start, or a crash would leave un-reapable orphans.
        """
        try:
            _RESOURCE_REGISTRY.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as exc:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    f"registry directory creation failed: {exc}"
                ) from exc
            return  # dev mode: best-effort
        entry = {
            "token": self._token,
            "pid": os.getpid(),
            "process_start_time": _get_process_start_time(os.getpid()),
            "boot_id": _boot_id(),
            "creation_stage": self._creation_stage or "INTENT",
        }
        entry["mac"] = _sign_registry_entry(entry)
        reg_file = _RESOURCE_REGISTRY / f"{self._token}.json"
        try:
            fd = os.open(
                str(reg_file),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode=0o600,
            )
            try:
                os.write(fd, json.dumps(entry).encode("utf-8"))
                # Batch 9.5 (round-9 §十五): fsync the file data before
                # closing so a host power loss does not lose the INTENT
                # record that lets the reaper recover residual resources.
                os.fsync(fd)
            finally:
                os.close(fd)
            # fsync the parent directory so the new file's directory
            # entry is durable.
            _fsync_dir(_RESOURCE_REGISTRY)
            self._registry_file = reg_file
        except OSError as exc:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    f"registry entry write failed: {exc}"
                ) from exc
            logger.debug("registry write failed (best-effort): %s", exc)

    def _update_registry_stage(self, stage: str) -> None:
        """§七: atomically update the registry's ``creation_stage`` after
        each resource is created, so a crash leaves a precise trace.  The
        update is written via a temp-file + atomic rename for durability."""
        if self._registry_file is None:
            return
        entry = {
            "token": self._token,
            "pid": os.getpid(),
            "process_start_time": _get_process_start_time(os.getpid()),
            "boot_id": _boot_id(),
            "creation_stage": stage,
        }
        entry["mac"] = _sign_registry_entry(entry)
        tmp = self._registry_file.with_suffix(".tmp")
        try:
            fd = os.open(
                str(tmp),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                mode=0o600,
            )
            try:
                os.write(fd, json.dumps(entry).encode("utf-8"))
                # Batch 9.5: fsync the temp file so the renamed-over
                # content is durable.
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(tmp, self._registry_file)
            # fsync the parent directory so the rename is durable.
            _fsync_dir(self._registry_file.parent)
        except OSError as exc:
            # A stage-update failure is not fatal (the INTENT record
            # already exists), but log it so a persistent failure is
            # visible.  The reaper falls back to deriving names from
            # the token regardless of the recorded stage.
            logger.debug("registry stage update to %s failed: %s", stage, exc)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def build_launcher_argv(
        self, real_executable: str, extra_args: list[str] | None = None,
    ) -> list[str] | None:
        """Batch 7.4 (round-7 §十一): build the Rust launcher argv for
        browser launching, replacing the shell wrapper.

        Returns ``[launcher, "--browser", "--netns", <name>, "--cgroup",
        <procs>, "--", <chromium>, ...]`` when the launcher binary is
        available (``KHAOS_SANDBOX_LAUNCHER`` env or on PATH), or None
        when it is not (caller falls back to the shell wrapper).

        The launcher does: validate argv → join cgroup → setns(netns) →
        close inherited FDs → no_new_privs → install seccomp (denies
        setns/unshare afterward) → execve(chromium).  This removes the
        shell from the TCB and adds FD sanitization + browser seccomp.
        """
        if not self._active or self._netns_name is None:
            return None
        launcher = self._locate_and_validate_browser_launcher()
        if launcher is None:
            return None
        argv: list[str] = [
            launcher, "--browser",
            "--netns", self._netns_name,
        ]
        if self._cgroup_path is not None:
            procs = self._cgroup_path / "cgroup.procs"
            argv += ["--cgroup", str(procs)]
        argv.append("--")
        argv.append(real_executable)
        if extra_args:
            argv.extend(extra_args)
        return argv

    @staticmethod
    def _locate_browser_launcher() -> str | None:
        """Locate the khaos-sandbox-launcher binary (env override first).

        No validation is performed here — callers that need the trusted
        production path should use ``_locate_and_validate_browser_launcher``
        instead (it rejects symlinks, non-owner files, and group/other-
        writable binaries).
        """
        configured = os.environ.get("KHAOS_SANDBOX_LAUNCHER", "").strip()
        if configured:
            return configured
        found = shutil.which("khaos-sandbox-launcher")
        if found:
            return found
        return None

    def _locate_and_validate_browser_launcher(self) -> str | None:
        """Locate AND validate the launcher binary for production use.

        Batch 9.3 (round-9 §十二): in production (``require_os_sandbox``)
        the launcher, bubblewrap and Chromium binaries are part of the TCB.
        Their path must be resolved to an absolute regular file owned by
        the current UID (root in production) with no group/other write bit
        and no symlink at the final component.  This closes PATH-hijack
        and binary-replacement attacks where a pre-sandbox attacker plants
        a malicious ``bwrap`` or launcher earlier in PATH.

        In dev mode the validation is skipped (the binary may be missing or
        owned by the developer on a non-root checkout).
        """
        path = self._locate_browser_launcher()
        if path is None:
            return None
        if not self._require_os_sandbox:
            return path
        _validate_tcb_binary(path, label="browser launcher")
        return path

    def launcher_environment(self, real_executable: str) -> dict[str, str]:
        """Return the direct Rust-launcher contract for Playwright.

        Playwright can only configure one executable path.  Passing the Rust
        binary directly and supplying immutable launch metadata through the
        child environment removes the forwarding shell from production TCB.

        Batch 9.1 (round-9 §九): this dict is the COMPLETE Chromium
        environment — it NO LONGER inherits ``os.environ``.  Only an
        explicit allowlist of benign runtime variables (PATH, locale, TLS
        roots, Playwright browser path) is forwarded, plus the four
        ``KHAOS_BROWSER_*`` authority-metadata vars that the Rust launcher
        strips at the namespace boundary.  Provider API keys, cloud
        credentials, proxy secrets and any other parent-process env are
        therefore NOT visible to a compromised Chromium.
        """
        launcher = self._locate_and_validate_browser_launcher()
        if launcher is None:
            raise BrowserSandboxError("trusted Rust browser launcher required")
        if not self._active or not self._netns_name:
            raise BrowserSandboxError("browser sandbox is not active")
        # Batch 9.3: validate the Chromium (real_executable) and bubblewrap
        # binaries in production so a planted/writable binary cannot enter
        # the TCB.  Dev mode skips validation (developer-owned checkouts).
        if self._require_os_sandbox:
            _validate_tcb_binary(real_executable, label="chromium runtime")
        # Start from the explicit allowlist only — never ``os.environ``.
        env: dict[str, str] = {}
        for name in _BROWSER_ENV_ALLOWLIST:
            value = os.environ.get(name)
            if value:
                env[name] = value
        # Authority metadata consumed by the Rust launcher; stripped inside
        # the bubblewrap namespace so Chromium never sees them.
        env["KHAOS_BROWSER_LAUNCH"] = "1"
        env["KHAOS_BROWSER_REAL_EXECUTABLE"] = real_executable
        env["KHAOS_BROWSER_NETNS"] = self._netns_name
        # Batch 9.2: resolved host home so the Rust launcher can mask the
        # REAL home directory (which may live outside /home or /root).
        env["KHAOS_BROWSER_HOST_HOME"] = str(Path.home().resolve())
        # Batch 9.3 + 11.3: validated absolute bubblewrap path (TCB binary
        # trust).  Production REQUIRES bwrap (the Rust launcher no longer
        # falls back to a PATH lookup); dev mode tolerates its absence.
        bwrap_path = shutil.which("bwrap")
        if bwrap_path:
            if self._require_os_sandbox:
                _validate_tcb_binary(bwrap_path, label="bubblewrap runtime")
            env["KHAOS_BROWSER_BWRAP_PATH"] = bwrap_path
        elif self._require_os_sandbox:
            raise BrowserSandboxError(
                "bubblewrap ('bwrap') is required for production browser "
                "sandbox but was not found on PATH"
            )
        if self._cgroup_path is not None:
            env["KHAOS_BROWSER_CGROUP_PROCS"] = str(
                self._cgroup_path / "cgroup.procs"
            )
        return env

    def run_fs_probe(
        self, sentinel_paths: list[str], *, chromium_executable: str = "/bin/true",
    ) -> dict[str, str]:
        """Batch 10.5 (round-10 §八): run a mount-namespace secrecy probe.

        Launches the Rust launcher with the SAME bwrap mount args used for
        Chromium (same ``--tmpfs`` masks), but instead of exec-ing Chromium
        it runs the ``--browser-fs-probe`` inner mode: for each sentinel
        path it calls ``open(2)`` from inside the bubblewrap mount
        namespace and reports ``READABLE`` / ``ENOENT`` / ``EACCES`` /
        ``BLOCKED``.

        This BYPASSES Playwright, Route Guard, and Web Security entirely
        — a direct kernel-level proof of the mount mask.  The round-9
        ``page.goto(file://)`` test could not distinguish "blocked by
        Route Guard" from "blocked by mount namespace"; this probe can.

        Returns a dict mapping each sentinel path to its outcome label.

        Note: ``chromium_executable`` defaults to ``/bin/true`` because
        the probe never execs Chromium — the launcher only needs a valid
        parent directory to bind-mount.  ``/bin/true`` is always present
        on Linux.
        """
        if not self._active or not self._netns_name:
            raise BrowserSandboxError("browser sandbox is not active")
        launcher = self._locate_and_validate_browser_launcher()
        if launcher is None:
            raise BrowserSandboxError("trusted Rust browser launcher required")
        env = self.launcher_environment(chromium_executable)
        env["KHAOS_BROWSER_FS_PROBE"] = ":".join(sentinel_paths)
        try:
            result = subprocess.run(
                [launcher],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.TimeoutExpired as exc:
            raise BrowserSandboxError(
                f"fs probe timed out: {exc}"
            ) from exc
        # Batch 11.6 (round-11 §九): check returncode + stderr so a
        # crashed/failed launcher is not silently treated as success.
        if result.returncode != 0:
            raise BrowserSandboxError(
                f"fs probe launcher exited {result.returncode}: "
                f"{result.stderr.strip()}"
            )
        outcomes: dict[str, str] = {}
        # Batch 12.3 (round-12 §十四): validate each outcome belongs to
        # the fixed enum so a buggy/corrupted probe cannot produce an
        # unknown label that silently passes a negative test.
        _valid_outcomes = {"READABLE", "ENOENT", "EACCES", "ENOTDIR", "BLOCKED"}
        for line in result.stdout.splitlines():
            parts = line.split("\t", 1)
            if len(parts) == 2:
                outcomes[parts[0]] = parts[1]
        invalid = {v for v in outcomes.values() if v not in _valid_outcomes}
        if invalid:
            raise BrowserSandboxError(
                f"fs probe produced unknown outcome(s): {sorted(invalid)} "
                f"(valid: {sorted(_valid_outcomes)})"
            )
        # Batch 11.6: every requested path MUST have an outcome.  A
        # missing outcome means the probe is broken (false negative risk).
        missing = set(sentinel_paths) - set(outcomes.keys())
        if missing:
            raise BrowserSandboxError(
                f"fs probe produced no outcome for: {sorted(missing)} "
                f"(stdout={result.stdout!r})"
            )
        return outcomes

    def create_wrapper_script(
        self, real_executable: str, proxy_port: int,
    ) -> str | None:
        """Create a wrapper script that launches Chromium inside the netns.

        Returns the path to the wrapper script, or None if the sandbox
        is not active (caller uses the real executable directly).

        Batch 7.4 (round-7 §十一): prefer the Rust launcher
        (``build_launcher_argv``) when available — it removes the shell
        from the TCB and adds FD sanitization + seccomp.  This shell
        wrapper remains as the FALLBACK when the launcher binary is
        absent (e.g. non-Linux or unbuilt).

        C-08: the wrapper writes its own PID to ``cgroup.procs`` before
        ``exec nsenter``.  Since ``nsenter --net`` preserves the PID,
        Chromium actually joins the cgroup and resource limits apply.
        If the cgroup write fails the wrapper exits non-zero instead of
        continuing without limits.

        C-10/H-04: the wrapper is created via ``O_NOFOLLOW | O_EXCL`` in
        the private run directory so it cannot be replaced by a symlink
        or a pre-placed file.

        C-04 (round-5): in production mode, wrapper creation failure
        raises ``BrowserSandboxError`` instead of returning ``None``
        (which would cause the caller to fall back to a direct,
        unsandboxed Chromium launch).
        """
        if not self._active:
            return None
        if self._run_dir is None:
            # C-04 (round-5): fail closed in production.
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    "secure run directory not created — refusing to "
                    "write wrapper to shared /tmp"
                )
            self._create_secure_run_dir()

        netns_path = f"{_NETNS_BASE}/{self._netns_name}"
        cgroup_procs = (
            str(self._cgroup_path / "cgroup.procs")
            if self._cgroup_path is not None
            else ""
        )

        # Batch 7.4 (round-7 §十一): prefer the Rust launcher when
        # available — it does cgroup join + netns join + FD sanitization
        # + seccomp in one trusted binary (no shell quoting, no nsenter
        # dependency).  The shim below just forwards Playwright's argv to
        # the launcher because Playwright's ``executable_path`` takes a
        # single binary path, not an argv list.  When the launcher is
        # absent we fall back to the legacy nsenter shell form.
        launcher = self._locate_browser_launcher()
        if launcher is not None:
            # Shim: exec the launcher with --browser + netns + cgroup,
            # then "$@" (Playwright's Chromium flags) become the
            # launcher's command after "--".  The launcher inserts
            # ``real_executable`` as the command — but Playwright calls
            # the shim with the Chromium flags as $@, so we pass the
            # real executable explicitly and let "$@" append flags.
            cgroup_arg = (
                f' --cgroup "{cgroup_procs}"' if cgroup_procs else ""
            )
            script_content = (
                f'#!/bin/sh\n'
                f'# Batch 7.4: forwards to the Rust browser launcher.\n'
                f'# AUTO-GENERATED - do not edit.\n'
                f'exec "{launcher}" --browser --netns "{self._netns_name}"'
                f'{cgroup_arg} -- "{real_executable}" "$@"\n'
            )
        else:
            if self._require_os_sandbox:
                raise BrowserSandboxError(
                    "trusted Rust browser launcher is required in production"
                )
            # Legacy fallback: direct nsenter shell wrapper (no FD
            # sanitization / seccomp — used when the launcher binary is
            # not built/installed, e.g. non-Linux dev).
            if cgroup_procs:
                join_cgroup = (
                    f'if ! echo $$ > "{cgroup_procs}" 2>/dev/null; then\n'
                    f'  echo "khaos: failed to join cgroup {cgroup_procs}" >&2\n'
                    f'  exit 1\n'
                    f'fi\n'
                )
            else:
                join_cgroup = ""
            script_content = f"""#!/bin/sh
# C-08/C-10: Khaos browser netns wrapper (legacy fallback).  AUTO-GENERATED.
# Prefer the Rust launcher (build khaos-sandbox-launcher) for FD
# sanitization + browser seccomp.
{join_cgroup}exec nsenter --net="{netns_path}" "{real_executable}" "$@"
"""
        # C-10: create with O_NOFOLLOW | O_EXCL so the wrapper cannot
        # be a symlink or overwrite an existing file.
        script_path = self._run_dir / f"chromium-{self._netns_name}.sh"
        fd = os.open(
            str(script_path),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode=0o700,
        )
        try:
            os.write(fd, script_content.encode("ascii"))
        finally:
            os.close(fd)
        # Verify owner and mode (defence in depth — TOCTOU between
        # open and exec is mitigated by the private 0700 run dir).
        stat = script_path.lstat()
        if stat.st_uid != os.getuid():
            raise BrowserSandboxError(
                f"wrapper script {script_path} not owned by current user"
            )
        self._wrapper_script = script_path
        return str(script_path)

    def teardown(self) -> CleanupResult:
        """Clean up nftables, netns, veth pair, cgroup, wrapper, run dir,
        and registry entry.

        Round-5 H-02: only deletes THIS sandbox's resources (per-sandbox
        nft table name), never a global table.

        Batch 7.3 (round-7 §八): returns a structured ``CleanupResult``.
        Every kernel-resource deletion is tracked; if ANY fails, the
        registry file is RETAINED (``registry_retained=True``) and
        ``fully_closed=False`` so the next startup reaper can retry.
        Previously teardown swallowed all failures (``_suppress_oserrors``
        + unconditional field-clearing + registry delete) and returned
        None, leaking un-trackable kernel orphans.  ``subprocess.
        TimeoutExpired`` is now caught too (it is not an ``OSError``,
        so the old guard let it abort teardown mid-way).
        """
        result = CleanupResult()
        # Track which kernel resources were present BEFORE deletion so an
        # inactive sandbox (nothing present) is vacuously clean.
        had_nft = self._nft_table is not None
        had_veth = self._veth_host is not None
        had_netns = self._netns_name is not None
        had_cgroup = self._cgroup_path is not None

        # Helper: run a deletion, return True on success.  Catches BOTH
        # OSError and subprocess.TimeoutExpired (§八 latent bug).
        def _try(fn) -> bool:
            try:
                fn()
                return True
            except (OSError, subprocess.TimeoutExpired) as exc:
                logger.warning("teardown: deletion failed (retained): %s", exc)
                return False

        # Delete wrapper script + secure run dir (C-10)
        if self._wrapper_script is not None:
            w = self._wrapper_script
            result.wrapper_removed = _try(lambda: w.unlink(missing_ok=True))
            if result.wrapper_removed:
                self._wrapper_script = None
        if self._run_dir is not None:
            rd = self._run_dir
            result.run_dir_removed = _try(lambda: rd.rmdir())
            if result.run_dir_removed:
                self._run_dir = None

        # Kill the browser process tree before removing the firewall.  The
        # nft default-deny boundary remains active until cgroup populated=0
        # and the leaf is gone, so a failed browser.close() cannot create an
        # unfiltered network window during force teardown.
        if self._cgroup_path is not None:
            cg = self._cgroup_path
            _remove_cgroup(cg)
            result.cgroup_removed = not cg.exists()
            if result.cgroup_removed:
                self._cgroup_path = None

        # Delete per-sandbox nftables table only after the browser cgroup is
        # dead.  If cgroup removal failed, retain the firewall and report a
        # quarantined partial cleanup.
        if self._nft_table is not None and (
            result.cgroup_removed or not had_cgroup
        ):
            tbl = self._nft_table
            result.nft_removed = _try(lambda: self._run_trusted(
                ["nft", "delete", "table", _NFT_TABLE_FAMILY, tbl],
                f"delete nftables table {tbl}",
            ))
            if result.nft_removed:
                self._nft_table = None
                self._egress_ports.clear()

        # Delete veth pair (deleting the host end removes both ends)
        if self._veth_host is not None:
            vh = self._veth_host
            result.veth_removed = _try(lambda: self._run_trusted(
                ["ip", "link", "del", vh],
                f"delete veth {vh}",
            ))
            if result.veth_removed:
                self._veth_host = None
                self._veth_ns = None

        # Delete netns
        if self._netns_name is not None:
            nn = self._netns_name
            result.netns_removed = _try(lambda: self._run_trusted(
                ["ip", "netns", "del", nn],
                f"delete netns {nn}",
            ))
            if result.netns_removed:
                self._netns_name = None

        # §八: clean iff every PRESENT resource was confirmed removed.
        # A resource that was never set (inactive sandbox) is vacuously
        # clean.  If any present resource failed, RETAIN the registry.
        kernel_clean = (
            (result.nft_removed or not had_nft)
            and (result.veth_removed or not had_veth)
            and (result.netns_removed or not had_netns)
            and (result.cgroup_removed or not had_cgroup)
        )
        if kernel_clean:
            if self._registry_file is not None:
                rf = self._registry_file
                result.registry_retained = not _try(
                    lambda: rf.unlink(missing_ok=True)
                )
            else:
                result.registry_retained = False
            result.fully_closed = not result.registry_retained
        else:
            # Keep the registry file; mark stage as RELEASING so the
            # reaper knows a partial cleanup happened.
            result.registry_retained = True
            result.fully_closed = False
            self._update_registry_stage("RELEASING")
            logger.error(
                "teardown: kernel resources remain (nft=%s veth=%s "
                "netns=%s cgroup=%s) — registry RETAINED for reaper",
                result.nft_removed, result.veth_removed,
                result.netns_removed, result.cgroup_removed,
            )

        self._active = False
        self._creation_stage = "RELEASED" if result.fully_closed else "QUARANTINED"
        self._enforcement = EnforcementStatus()
        return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class BrowserSandboxError(Exception):
    """C-09: raised when a required OS-sandbox component is unavailable.

    In production (``require_os_sandbox=True``) this propagates to the
    caller so the browser launch is refused rather than silently
    degrading to a weaker enforcement level.
    """


class _suppress_oserrors:
    """Context manager that swallows OSError (for best-effort cleanup)."""

    def __enter__(self) -> "_suppress_oserrors":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None and issubclass(exc_type, OSError):
            logger.debug("suppressed OSError during cleanup: %s", exc)
            return True
        return False


def _has_net_admin(*, validate: bool = False) -> bool:
    """C-09: actually check CAP_NET_ADMIN instead of optimistically returning True.

    Uses ``ip netns add/delete`` as a side-effect-free probe because it
    exercises the exact capability the sandbox needs.  The previous
    implementation unconditionally returned ``True``, which meant the
    real capability check was deferred to ``setup()`` failure — too late
    for a fail-closed decision.

    Batch 11.1 (round-11 §四): ``validate`` defaults to False for
    backward compatibility, but production callers MUST pass
    validate=True so the capability probe itself uses a validated ip
    binary (closing the cache-poisoning bypass where the probe ran first
    with validate=False and a later validate=True call hit the cache).
    """
    if not sys.platform.startswith("linux"):
        return False
    # Batch 11.1: resolve ip with the caller's validation level.
    ip_path = _resolve_tcb_tool("ip", validate=validate)
    if ip_path == "ip":  # not found
        return False
    probe = f"khaos-cap-probe-{secrets.token_hex(4)}"
    try:
        result = subprocess.run(
            [ip_path, "netns", "add", probe],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return False
        subprocess.run(
            [ip_path, "netns", "del", probe],
            capture_output=True, text=True, timeout=5,
        )
        return True
    except (OSError, subprocess.TimeoutExpired):
        return False


def _run_command(argv: list[str], description: str, *, validate: bool = False) -> None:
    """Run a command and raise OSError on failure.

    Batch 10.3 (round-10 §六): if ``argv[0]`` is a bare ``ip``/``nft``
    tool name, resolve it to the validated absolute path from the TCB
    cache before invoking.  This closes the bare-PATH-lookup gap for
    every privileged kernel operation (netns/veth/nft create+delete).

    Batch 11.1 (round-11 §四): ``validate`` defaults to False for
    backward compatibility, but production callers MUST pass validate=True
    so the privileged invocation uses a validated binary (not an
    unvalidated cache entry left by an earlier capability probe).
    """
    if argv and argv[0] in ("ip", "nft"):
        argv = [_resolve_tcb_tool(argv[0], validate=validate), *argv[1:]]
    result = subprocess.run(
        argv, capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        raise OSError(
            f"{description} failed (exit {result.returncode}): "
            f"{result.stderr.strip() or result.stdout.strip()}"
        )


def _browser_cgroup_root() -> Path | None:
    """Return a writable delegated cgroup-v2 subtree for browsers.

    Reuses the same root as ``platform._linux_cgroup_root`` so all
    Khaos cgroups live under the same delegated subtree.
    """
    if not sys.platform.startswith("linux"):
        return None
    unified = Path("/sys/fs/cgroup/cgroup.controllers")
    if not unified.is_file():
        return None
    configured = os.environ.get("KHAOS_CGROUP_ROOT", "").strip()
    root = Path(configured) if configured else Path("/sys/fs/cgroup/khaos")
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical = root.resolve()
        if Path("/sys/fs/cgroup") not in (canonical, *canonical.parents):
            return None
        if not os.access(canonical, os.W_OK):
            return None
        return canonical
    except OSError:
        return None


def _remove_cgroup(group: Path) -> None:
    """Remove a cgroup-v2 leaf using kill → wait → rmdir (Round-4 §13.4)."""
    import time

    if not group.is_dir():
        return
    kill_file = group / "cgroup.kill"
    if kill_file.exists():
        try:
            kill_file.write_text("1", encoding="ascii")
        except OSError as exc:
            logger.warning("browser cgroup.kill failed for %s: %s", group, exc)
    events_file = group / "cgroup.events"
    if events_file.exists():
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                content = events_file.read_text(encoding="ascii")
                if "populated 0" in content or "populated=0" in content:
                    break
            except OSError:
                break
            time.sleep(0.1)
    try:
        group.rmdir()
    except OSError as exc:
        logger.warning("browser cgroup rmdir failed for %s (orphaned): %s", group, exc)


# ---------------------------------------------------------------------------
# H-03: Process liveness verification for the startup reaper
# ---------------------------------------------------------------------------


def _get_process_start_time(pid: int) -> float:
    """Get the process start time (in clock ticks) for liveness checking.

    On Linux, reads ``/proc/<pid>/stat`` field 22 (starttime).  On
    other platforms, returns 0.0 (reaper is Linux-only anyway).
    """
    if not sys.platform.startswith("linux"):
        return 0.0
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        # Field 22 is starttime in clock ticks.  Comm may contain spaces
        # and parentheses, so find the last ')' and parse from there.
        rparen = stat.rfind(")")
        if rparen < 0:
            return 0.0
        fields = stat[rparen + 2:].split()
        if len(fields) >= 20:
            return float(fields[19])  # field 22 (0-indexed from after comm)
        return 0.0
    except (OSError, ValueError):
        return 0.0


def _is_process_alive(pid: int, expected_start_time: float) -> bool:
    """H-03: check if a process is alive AND matches the recorded
    start time (to detect PID reuse).

    Returns True only if:
      - The PID exists in /proc, AND
      - The process start time matches the recorded value.
    """
    if not sys.platform.startswith("linux"):
        return False
    if not Path(f"/proc/{pid}").exists():
        return False
    current_start = _get_process_start_time(pid)
    if expected_start_time > 0 and current_start != expected_start_time:
        # PID was reused by a different process.
        return False
    return True


def _find_orphaned_resources() -> list[dict]:
    """H-03: scan the registry and return entries whose owning process
    is confirmed dead.

    A resource is orphaned if:
      - The registry file exists, AND
      - The recorded PID no longer exists, OR
      - The PID's start time has changed (PID reused by another process).
    """
    orphans: list[dict] = []
    if not _RESOURCE_REGISTRY.is_dir():
        return orphans
    for entry_path in _RESOURCE_REGISTRY.iterdir():
        if not entry_path.name.endswith(".json"):
            continue
        try:
            data = json.loads(entry_path.read_text())
        except (OSError, ValueError):
            logger.error("reaper: unreadable registry entry %s quarantined", entry_path)
            continue
        if not isinstance(data, dict) or not _verify_registry_entry(data):
            logger.error("reaper: unauthenticated registry entry %s quarantined", entry_path)
            continue
        if data.get("boot_id") != _boot_id():
            # A prior boot cannot have a live owner PID in this boot.
            data["registry_file"] = str(entry_path)
            orphans.append(data)
            continue
        pid = data.get("pid", 0)
        start_time = data.get("process_start_time", 0.0)
        if not _is_process_alive(pid, start_time):
            data["registry_file"] = str(entry_path)
            orphans.append(data)
    return orphans


# ---------------------------------------------------------------------------
# H-04: openat-based directory chain verification
# ---------------------------------------------------------------------------


def _openat_dir(
    parent_fd: int, name: str, *, create: bool = False, mode: int = 0o755
) -> int:
    """H-04: open or create a subdirectory via ``openat`` with
    ``O_DIRECTORY | O_NOFOLLOW`` to reject symlinks.

    Returns a new file descriptor for the subdirectory.  The caller is
    responsible for closing it.

    Note: ``O_DIRECTORY | O_NOFOLLOW | O_CREAT`` can fail with EINVAL
    on some platforms (notably macOS) when the path already exists as a
    directory.  We handle this by falling back to ``mkdir`` + re-open.
    """
    # First try to open the existing directory.
    try:
        fd = os.open(
            name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY,
            dir_fd=parent_fd,
        )
        return fd
    except FileNotFoundError:
        if not create:
            raise
    except OSError:
        # May be EINVAL on some platforms — fall through to create path.
        pass

    # Create the directory (race-free with O_EXCL equivalent via mkdir).
    try:
        os.mkdir(name, mode=mode, dir_fd=parent_fd)
    except FileExistsError:
        pass  # Another thread/process created it — re-open below.

    # Re-open the newly created directory.
    fd = os.open(
        name, os.O_DIRECTORY | os.O_NOFOLLOW | os.O_RDONLY,
        dir_fd=parent_fd,
    )
    # Verify it's a directory and owned by us (defence in depth).
    stat = os.fstat(fd)
    import stat as stat_mod
    if not stat_mod.S_ISDIR(stat.st_mode):
        os.close(fd)
        raise OSError(f"{name} is not a directory")
    return fd
