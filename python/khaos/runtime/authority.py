"""Runtime authority seal — a factory-issued runtime binding assertion.

Review P1-1 (production Runtime injection): ``RuntimeConfig`` allowed
injecting every security-critical component (ToolScheduler, ExecutionService,
Sandbox, NetworkGuard, MemoryManager, ModeManager, AuditLogger) without
re-proving any of their security properties.  The seal is the typed binding
every production-built runtime carries, so the factory can detect mismatches
between a borrowed component's authority and the current runtime's authority.

**Scope limitation (round-12 review P1-3):** the seal is a *factory-issued
binding assertion*, NOT a cryptographic boundary against in-process malicious
code.  ``RuntimeAuthoritySeal.mint()`` is a public classmethod and the MAC key
is a module-level variable; arbitrary Python code running in the same
interpreter can mint a forged seal.  This is acceptable because the threat
model does not include same-process malicious code (the OS-user boundary is a
separate trust boundary — see ``docs/platform-security-guarantees.md``).  The
seal prevents *unintentional* misconfiguration, detects component-binding
drift, and strengthens factory invariants — it is not claimed to defend
against a hostile in-process caller.

Invariant A (single execution authority): every model command, git operation,
test, build, LSP, or browser subprocess runs only through a RuntimeFactory-
built ExecutionService whose authority matches this seal.  Invariant D (no
silent host fallback): the seal's policy_digest ties execution to exactly the
compiled EffectiveSecurityPolicy.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class RuntimeAuthoritySeal:
    """Factory-issued runtime binding assertion (NOT a crypto boundary).

    The four fields uniquely identify the security context every component of
    a runtime must be built from:

    * ``principal_id``  — the authenticated OS/API-key principal owning the run.
    * ``project_id``    — the state-root project identity (sha256(realpath)).
    * ``policy_digest`` — the compiled ``EffectiveSecurityPolicy`` digest.
    * ``runtime_id``    — the per-runtime UUID (isolates concurrent runtimes).

    ``mac`` is an HMAC over the four fields keyed by a process-random secret
    so a caller cannot fabricate a seal by constructing the dataclass with
    arbitrary field values — it must be minted by ``mint`` within this process.
    """

    principal_id: str
    project_id: str
    policy_digest: str
    runtime_id: str
    mac: str

    @classmethod
    def mint(
        cls,
        *,
        principal_id: str,
        project_id: str,
        policy_digest: str,
        runtime_id: str,
    ) -> RuntimeAuthoritySeal:
        """Mint a seal bound to the given authority tuple.

        The MAC key is fresh per process (read from ``urandom`` once and held
        in module state), so a seal is unforgeable outside the process that
        created it.  This is sufficient because the threat model is
        *in-process* injection of a second authority by a caller — not
        cross-process tampering (the OS-user boundary is a separate trust
        boundary, see ``docs/platform-security-guarantees.md``).
        """
        mac = _compute_mac(principal_id, project_id, policy_digest, runtime_id)
        return cls(
            principal_id=principal_id,
            project_id=project_id,
            policy_digest=policy_digest,
            runtime_id=runtime_id,
            mac=mac,
        )

    def verify(self) -> bool:
        """Return True iff this seal's MAC is valid for its fields."""
        expected = _compute_mac(
            self.principal_id, self.project_id, self.policy_digest, self.runtime_id
        )
        return hmac.compare_digest(self.mac, expected)

    def matches(
        self,
        *,
        principal_id: str,
        project_id: str,
        policy_digest: str,
        runtime_id: str,
    ) -> bool:
        """Return True iff this seal is valid AND binds the given tuple."""
        return self.verify() and (
            self.principal_id == principal_id
            and self.project_id == project_id
            and self.policy_digest == policy_digest
            and self.runtime_id == runtime_id
        )


# Process-random MAC key — fresh per process, never serialized.  A seal minted
# in one process cannot be replayed in another, which is fine: the injection
# threat is an in-process caller constructing a second authority, not a
# cross-process replay (the OS-user boundary handles the latter).
_MAC_KEY = os.urandom(32)


def _compute_mac(
    principal_id: str, project_id: str, policy_digest: str, runtime_id: str
) -> str:
    payload = f"{principal_id}|{project_id}|{policy_digest}|{runtime_id}".encode()
    return hmac.new(_MAC_KEY, payload, hashlib.sha256).hexdigest()


def is_production_mode() -> bool:
    """Return True when the runtime must enforce the sealed-injection gate.

    Production packaging (systemd unit, Compose) explicitly sets
    ``KHAOS_DEV_MODE=0``; the test suite and ad-hoc dev runs set it to ``1``.
    Only in production mode does ``build_runtime`` refuse injected
    security-critical components — the dev/test path injects mocks freely.
    """
    return os.environ.get("KHAOS_DEV_MODE") != "1"
