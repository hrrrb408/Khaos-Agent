# ADR-023: Signed Challenge-Response Native Authority Proofs

Status: Accepted

## Context

M6.9 BATCH 1/2 made the native frontend/backend chain real and bound the
peer to a designated code requirement.  But the proof returned to the Agent
was still *static*: `challenge_digest` was
`SHA256(service_id | peer_identity | key_ref)` — a deployment digest that
never changed between requests.  A proof captured once could be replayed,
and the "protected key verified" flag only proved a Keychain item existed
(macOS) or `CryptUnprotectData` returned non-empty bytes (Windows).  The
protected key never actually signed anything the Agent verifies.

Additionally the Windows native client had no `--request` mode at all, so
the production Windows request path could not work end to end.

## Decision

Every native probe and request becomes a signed challenge-response:

1. The Agent-side client (Python adapter) generates a fresh 256-bit
   CSPRNG `challenge_nonce` for each probe/request and owns only the
   authority's **public** verification key.
2. The native client executable carries the nonce to the frontend.
3. The frontend (platform TCB) hex-encodes the raw request, computes
   `request_digest = SHA256(raw request bytes)`, and forwards one
   `attest` operation to the authority backend together with its
   transport identity fields (platform, transport, service id/pid,
   service/peer identity, Team ID, cdhash, designated requirement digest,
   service instance id, protected key ref).
4. The backend — the only holder of the Ed25519 signing key — validates
   the nonce/digest/proof shape, re-dispatches the inner request, and
   signs a canonical attestation payload covering
   `{schema_version, platform, transport, service_id, service_pid,
   service_identity, peer_identity, peer_team_id, peer_cdhash,
   designated_requirement_digest, service_instance_id, protected_key_ref,
   challenge_nonce, request_digest, issuer_id, issued_at}`.
5. The Agent verifies: returned nonce == sent nonce, returned
   request_digest == digest of the exact request it sent, signature valid
   under the public key, identity fields match the deployment contract,
   the service instance matches the one proven at probe time, and the
   attestation is fresh.

A replayed proof necessarily carries a different challenge nonce and
therefore fails verification.  The protected key is no longer proven by
existence: it must produce a valid signature over client-controlled
freshness input for every single request.

## Consequences

- `authorityd` gains the `attest` dispatch operation and a trivial `ping`
  operation used by probes.
- `NativeAuthorityProof` is derived from a verified signed attestation
  rather than trusted frontend JSON.
- The macOS XPC client accepts `--challenge <hex>` and the frontend
  wraps requests through the backend; the Windows service gains a real
  `--request` client mode with the same semantics.
- `KHAOS_AUTHORITYD_PUBLIC_KEY_PATH` becomes a required part of the
  native deployment contract for the Agent.
- The static `challenge_digest` field remains only as the
  frontend-instance binding echoed in responses; it is no longer the
  proof of freshness.
