# ADR-065: Memory V2 production closure boundary

## Status

Accepted — 2026-08-24

## Context

Memory V2 combines an append-only event stream, rebuildable provider projections,
remote provider adapters, verification promotion, runtime event attribution,
CodeGraph snapshots, transfer, and prompt-context injection.  Treating any one
provider table or legacy store as an authority would make scope, lifecycle and
privacy guarantees depend on an implementation detail.

## Decision

1. `MemoryHost` is the production composition owner.  It creates one Broker,
   one event ledger, one profile/provider selection authority, one verification
   verifier and one Trust-Kernel audit sink.  Agent, RPC, Subagent, TUI and CLI
   must borrow this host; the legacy `MemoryStore` adapter is not a fallback
   once a production Broker is bound.
2. The Broker is the only admission boundary.  Provider output is evidence, not
   authority.  Canonical local event provenance and the private verification
   issuer capability are required for elevated lifecycle states.
3. All lifecycle changes are canonical events.  Projection rebuilds consume a
   stable ledger cursor and commit atomically.  Provider switch publishes its
   pointer only after replay/rebuild/health/smoke and rolls back through the
   same Broker fence on failure.
4. Destructive operations carry `MemoryObjectIdentity`.  Remote forget requires
   an exact scoped ownership proof; unknown or foreign IDs are non-enumerating
   no-ops.  Revocation and privacy tombstones match provider, project,
   namespace, principal and session identity as applicable.
5. Transfer is node-closure based: visible nodes determine evidence, edges and
   entities, and lifecycle event targets are validated before import.  The
   current `compliance` mode is a content-free privacy-redaction boundary for
   Broker/ledger/export reads, not cryptographic erasure of plaintext at rest.
6. Context injection is observational and lower precedence than system,
   developer, project, permission and approval policy.  Retrieval relevance is
   primary; authority is only a bounded rerank signal after admission gates.
   CodeGraph queries require project/repository/commit snapshot binding.

## Consequences

* A provider cannot mint USER, TOOL, SYSTEM or VERIFIED authority by returning a
  string field.
* A rebuild can discard all derived rows and deterministically reconstruct them
  from the ledger without losing canonical evidence.
* Remote providers must return complete object identity; omission fails closed.
* Adding a new runtime event or provider requires an event schema, scope proof,
  audit path and conformance regression rather than a direct table write.

## Verification

The closure evidence is maintained by:

* `python/tests/memory/test_memory_v2.py`
* `python/tests/memory/test_memory_v2_production_surfaces.py`
* `python/tests/memory/test_memory_v2_closure_edges.py`
* `khaos.memory.conformance.ProviderConformanceSuite`
* migration source-integrity and full Python/Go/Rust test gates

Native kernel/browser/process tests remain host-capability gates. An unavailable
native environment is recorded as unavailable/skipped and cannot be reported as
green closure evidence. Deployment-profile interpretation is defined separately
by ADR-066: Community Local Profile can reach PASS without Apple signing, while
the optional macOS Signed Distribution Profile is
`OPTIONAL_PROFILE_NOT_ENABLED`/`NOT CERTIFIED` until explicitly enabled. The
final profile-scoped result is recorded in
`docs/memory-v2-production-closure-report.md`; this ADR does not make Memory
Core depend on an optional Apple identity.
