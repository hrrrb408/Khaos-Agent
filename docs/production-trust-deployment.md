# Production trust material deployment runbook

This runbook describes the operator-owned inputs for a Khaos production
runtime. It is an integration contract, not proof that a host has completed
the native platform or protected-branch release gates.

## Provisioning

1. Compile the effective policy and typed catalog from the deployment
   configuration. Store the catalog at an absolute operator-controlled path
   with a bounded regular file, no symlinked ancestor, no group/other write,
   and a single hard link. Set `KHAOS_TYPED_RESOURCE_CATALOG_PATH` and
   `KHAOS_EFFECTIVE_POLICY_DIGEST` to those reviewed values.
2. Provision the authority signing key in the authorityd-owned key store. The
   Agent receives only the public verification key through
   `KHAOS_AUTHORITYD_PUBLIC_KEY_PATH`; it must not receive the private key,
   secret material, or a model-controlled path.
3. Configure the same explicit authority profile, issuer identity, transport,
   and identity contract for both services. If
   `KHAOS_AUTHORITYD_ENVIRONMENT_DIGEST` is supplied, it must be the same
   canonical digest on both sides.
4. Configure the independent audit writer. Native production requires the
   remote/WORM writer; a local JSONL file is only the explicit community
   profile diagnostic sink.

On Windows, also provision `KHAOS_WINDOWS_TRUST_ROOT`,
`KHAOS_WINDOWS_TRUSTED_OWNER_SIDS`, and the explicit
`KHAOS_WINDOWS_TRUSTED_ACL_SIDS` set in the authority-owned service
configuration. Apply an inheritance-disabled ACL to the root, catalog, key,
and public-key paths before starting the backend. The runtime and authorityd
use Win32 security-descriptor/handle checks; missing variables, an unknown
owner, an unparsed ACE, or an untrusted write ACE rejects startup. POSIX mode
bits are not used as a Windows substitute.

## Startup verification

The runtime and authorityd independently load and validate the catalog. The
runtime then loads the public key and performs the authority handshake. The
handshake must return `ready=READY` and matching values for:

```text
authority id, protocol version, policy digest, catalog semantic digest,
public-key fingerprint, and platform/profile/transport environment digest
```

It also returns a fresh channel nonce bound to the exact runtime identity
(`runtime_id`, `principal_id`, `project_id`, `principal_kind`). The client
attaches that identity, nonce, and deployment binding to every later request;
authorityd rejects substitutions.

Only after this result does the composition root construct the Workspace,
Network, and Execution effect consumers. A production `NetworkBroker` or
`WorkspaceManager` created without the runtime broker is a configuration
error, not an invitation to create a second authority path.

## Rotation and restart

Trust material is immutable for the lifetime of a runtime. For a key or
catalog rotation:

1. Stop admission and quiesce the current runtime.
2. Provision the complete new material and validate it independently.
3. Restart authorityd with the new key/catalog and publish the new public
   anchor through the service-owned path.
4. Restart the Agent runtime so it takes a new snapshot and handshake.
5. Verify the new binding and a bounded positive/negative effect probe before
   reopening RPC admission.

Do not edit a catalog in place under a READY runtime, retain a receipt across
an authority restart, or use a local broker while the new service is
unavailable. Any mismatch is a fail-closed restart/quarantine condition.

## Evidence boundary

The repository tests prove parsing, digest binding, no-follow path admission,
real Unix-socket handshake, effect rejection before/after mismatch, and
composition identity. Linux kernel identity, macOS XPC, Windows ACL/Service
SID, remote WORM, and protected-main exact-SHA checks still require their
respective CI or deployment evidence. They must be reported as blocked or
unknown until observed.
