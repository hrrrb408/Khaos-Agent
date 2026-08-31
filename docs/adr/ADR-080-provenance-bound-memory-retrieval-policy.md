# ADR-080: Provenance-bound Memory V2 retrieval policy

Status: accepted for M7.7

## Decision

M7.7 adds a retrieval control plane over the existing Memory V2 event ledger,
`memory_nodes` projection, Native SQLite/FTS provider, and `MemoryBroker`. It
does not create a parallel database or make memory an authority source.

`MemoryRetrievalPolicy` is an immutable, canonically serialized, digest-bound
runtime object. `MemoryRetrievalRequest` is built from the host-bound runtime
identity; only the semantic query is low-trust input. `MemoryRetrievalService`
applies project/principal/session/task scope in addition to the provider's SQL
scope, filters the closed `MemorySourceKind` vocabulary, classifies
`CURRENT`/`STALE`/`HISTORICAL`/`UNBOUND`, ranks deterministically, applies
per-source and total byte/record limits, and returns an ephemeral typed
`MemoryBundle`.

Relevance is not trust. Similarity is not authority. A currentness label only
means that the stored binding matches the retrieval request. Current
repository truth remains M7.2 Context Intelligence; the published plan,
trusted verification, recovery, tool route, approval, permission, sandbox,
credential, and completion authorities remain their existing owners.

## Provenance and legacy records

New derived nodes persist `source_kind`, bounded `provenance_json`, and a
canonical `record_digest` in migration v24. Provenance includes only explicit
runtime and candidate identities: principal/project/task/session/workspace,
repository/base revision, generation, and optional GoalSpec/plan/verification/
recovery/tool references. No identity is fabricated. Existing nodes are
explicitly `UNBOUND` with empty provenance/digest and are excluded from
scope-sensitive M7.7 retrieval rather than relabelled current.

Repository-bound records from another repository are excluded. A matching
repository with a different base revision or generation is historical/stale.
Plan, verification, and recovery records remain historical references and
cannot publish a plan, satisfy verification/completion, or create recovery
authority.

## Prompt trust boundary

Retrieved memory is formatted as one bounded low-trust data envelope and is
projected by `AgentLoop` as a `user` observation after durable task facts and
before the authenticated current request. It is no longer concatenated into
the system prompt. Stored text, repository/tool output, and model summaries
remain data; summarization never elevates source trust. The envelope does not
contain approval receipts, dispatch tokens, capability handles, credentials,
or private reasoning. Known structured secret/authority fields are redacted
before event persistence, with bounded conservative text redaction as defense
in depth rather than a claim of perfect detection.

## Existing Memory V2 audit

Before this decision, the implementation inventory was:

* `MemoryManager` records user/assistant/tool messages and runtime events and
  orchestrates extraction/injection.
* `MemoryEventBridge` and `SqliteEventLedger` persist scoped append-only
  events; `MemoryBroker` admits candidates and is the provider boundary.
* `NativeMemoryProvider` stores derived nodes in `memory_nodes`, evidence in
  `memory_evidence`, and uses the rebuildable `memory_nodes_fts_search` index.
* Existing Broker ranking fused provider/codegraph rank and then used
  authority/confidence tie-breaks; v24 retrieval adds explicit currentness,
  policy weights, source quotas, and memory-id tie-breaking.
* Runtime composition in `runtime/factory.py` creates the Memory V2 host and
  now explicitly supplies the production retrieval policy.
* No separate vector database or semantic index is introduced.
* Session/project/principal identities already existed in the V2 ledger and
  provider predicates; M7.7 adds request-level exact task/session and
  provenance checks rather than trusting session IDs alone.

## Restart, failure, and non-goals

`MemoryBundle` is not persisted or replayed. Restart builds a new request and
recomputes scope/currentness from the current provider state. Retrieval
failure degrades cognition to no memory and cannot relax any control plane.
This ADR does not implement sub-agent v2, capability metrics, a vector store,
external SaaS memory, or memory-driven tools, approval, planning, verification,
recovery, or completion.

## Verification

The M7.7 matrix covers owner/project/task isolation, repository freshness,
plan/verification/recovery history, malformed digests, deterministic ranking,
10,000-candidate bounds, query/provider failure, secret exclusion, and the
AgentLoop low-trust role projection. Production reachability remains generated
and continues to forbid `khaos.coding.verification.pipeline`.
