# ADR-018: Typed Principal Delegation

**状态：** Implemented for M6.4 foundation

## Context

The previous identity contract carried a stable `principal_id`, but the
transport that authenticated it was not represented in the authority value.
That made it too easy for a Gateway, channel, cron task, subagent, or browser
helper to be treated as the same authority class as an interactive human.

## Decision

`python/khaos/security/principals.py` defines immutable principal kinds:
`HumanPrincipal`, `GatewayPrincipal`, `ChannelPrincipal`,
`AutomationPrincipal`, `SubagentPrincipal`, and `BrowserPrincipal`.
`RequestContext` derives the kind from the authenticated transport and rejects
a caller-supplied kind that does not match it.

`DelegationScope` binds the subject and parent principal to project, session,
runtime, task, workspace, operation family, resource set, policy digest,
expiry, and nonce. `DelegationAuthority` permits only subset delegation and
consumes a child scope once. Cross-principal, cross-context, expired, and
operation/resource widening attempts fail closed.

The typed layer does not replace the existing Ed25519 authority receipt,
`AuthorityGrant`, or exact-effect binding. Production authority integration
must carry the scope digest into the signed receipt before a platform-specific
adapter can claim the effect; local typed tests are not native authority
evidence.

## Consequences

Transport identity is no longer inferred from a single API-key-shaped string.
Channel, cron, subagent, and browser paths have an explicit narrower identity
class, and a replayed child scope cannot be consumed twice or by another
context. Development/test contexts retain their explicit `test` transport;
production structural runtime configuration rejects an untyped transport.

