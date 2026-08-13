# Authority Control Plane and Execution Receipt Closure

This document is the authoritative boundary for the M4 control-plane work.
It deliberately separates code-enforced guarantees from deployment and
organization prerequisites.  A local SQLite database, JSONL trail, or Python
object is never described as an independent authority or WORM audit.

## Execution protocol

```text
agent intent
    -> khaos-authorityd policy + identity check
    -> remote/WORM append(execution.prepare)
    -> Ed25519 signed receipt
    -> native helper verifies receipt from already-open descriptors
    -> helper returns result digest
    -> remote/WORM append(execution.success|failed|unknown)
```

The receipt binds `principal_id`, `project_id`, `runtime_id`, `task_id`,
`workspace_id`, `operation`, `resource_digest`, `policy_digest`, `nonce`,
`authorization_epoch`, `expires_at`, and `audit_intent_digest`.  A missing
authority daemon or unavailable audit writer refuses `prepare`; a result that
cannot be committed is `unknown`/quarantined and must not be reported as
success.

Python callers use `AuthorityDaemonClient` through `AuthorityDaemonBroker` in
production.  `AuthorityBroker()` remains a test-only in-process broker; the
default production factory only permits it under the explicit development
profile.  The Rust execution launcher accepts the receipt and authorityd
public key through inherited file descriptors, verifies Ed25519, and rejects
raw Python objects, SQLite rows, pathname references, or caller-supplied key
paths.

For host execution, production deployment sets
`KHAOS_REQUIRE_AUTHORITY_RECEIPT=1` and
`KHAOS_AUTHORITYD_PUBLIC_KEY_PATH` to the separately provisioned trust anchor.
`ProcessSupervisor` derives an exact `exec.host` intent from the immutable
`ExecutionAuthority`, passes only the signed receipt and the already-open
public-key descriptors to the launcher, and commits a result digest after the
child is reaped.  `KHAOS_EFFECTIVE_POLICY_DIGEST` is loaded by authorityd from
its independently compiled policy; a client-supplied digest that does not
match is rejected before signing.  If that result commit is unavailable, the
returned outcome is `unknown`; it is never converted into `passed`.  A
production host spawn without the immutable execution authority, authorityd
receipt, public-key anchor, or native launcher is refused.

## OS identity contract

The daemon is a separate service, not merely another process in the Agent's
UID:

- Linux requires distinct Agent, authorityd, and job UIDs, a private `0600`
  Unix socket, and `SO_PEERCRED` validation.
- macOS production deployment must provide launchd/XPC service identity,
  signed daemon code, and Keychain/Secure Enclave access-group ACLs.
- Windows production deployment must provide a service SID, Named Pipe ACL,
  and CNG/DPAPI-protected key reference.

The Python admission module rejects missing platform handles.  It does not
pretend to implement launchd/XPC or Windows Named Pipes; those are installed
and owned by the platform service package.  The current repository deliberately
refuses to use a Unix-socket substitute on macOS or Windows; until those native
adapters are installed, production authority-backed execution is unavailable.

## Independent audit prerequisite

`RemoteWormAuditWriter` requires an HTTPS append-only endpoint and has no local
fallback.  The deployment must use object-lock compliance mode, a separate
append-only service, or an equivalent independently administered log.  The
local SQLite hash chain and JSONL file remain useful diagnostic evidence but
cannot defend against a same-UID actor that can rewrite both local stores.

## Governance prerequisite

The repository includes security-sensitive CODEOWNERS, exact-commit gate
evidence, release SBOM/provenance workflows, and signed-tag verification.
Independent approval, administrator-bypass prohibition, two-person
break-glass, and third-party penetration testing require GitHub organization
settings and people outside this repository.  Until a second maintainer and
external assessment exist, release material must label those controls
`not_proven`; code and CI must not claim Codex-equivalent organizational
assurance.
