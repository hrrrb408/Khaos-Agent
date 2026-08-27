# ADR-076: Context Intelligence and Cache Correctness

Status: accepted for M7.2

## Decision

Khaos coding context is an evidence projection, not an authority.  A typed
`ContextRequest` is bound to the authenticated principal, project, task,
immutable GoalSpec, TaskWorkspace, repository identity, and (when available)
the workspace base revision.  A `ContextBundle` carries only bounded,
generation-bound file, symbol, and evidence references.  It cannot grant
tools, workspace access, approval, sandbox capability, verification authority,
or lifecycle completion.

M7.2 adds one production composition seam, `ContextIntelligenceService`,
which reads source only through `SafeWorkspaceFS` and uses the existing
`LanguageRegistry` parser over safely captured bytes.  The older
`CodingContextBuilder` and path-oriented `RepositoryIndexer` remain
compatibility/development adapters; they are not silently promoted to the
production workspace reader.  Existing `coding.intelligence.query.CodeQueryService`
remains the persistent-index facade used by its established callers.  M7.2's
workspace-bound adapter is deliberately separate so the old direct-path API
cannot bypass the TaskWorkspace boundary.

## Cache and freshness invariants

The process-local bounded cache key includes the request semantic digest,
repository identity, workspace identity, base revision, repository content
generation, index schema, and parser version.  A task id or filesystem path
alone is never sufficient.  Repository content generation is a deterministic
digest of the safe workspace file manifest and content digests for bounded
files; a file whose identity changes during capture causes a bounded retry or
an explicit stale result.  Cache hits are additionally checked against the
current safe file digest.  TTL is not used as a correctness fence.

Mutating tool results invalidate the workspace cache as an optimization, but
correctness does not depend on that hook: the next request recaptures the
manifest and rejects a generation or content-digest mismatch.  Delete and
rename therefore remove the old path from the current structure and cannot
serve the old cached document.  Cache entries are workspace-scoped, so
uncommitted content cannot cross task workspaces.

All candidate ranking and output ordering use fixed integer scores and
canonical path/symbol tie-breakers.  File, symbol, excerpt, structure, and
byte limits are explicit in `ContextRequest`; truncation is recorded in the
bundle rather than represented as complete coverage.  A bundle never mixes
generations silently.  A query that races a mutation is returned as stale or
rebuilt from a fresh generation; an old result is never relabelled as current.

The service has no persisted semantic cache.  After restart it rebuilds from
the current workspace snapshot.  This is conservative and avoids treating
in-memory context as durable authority.  Any future persisted index must bind
repository/workspace/base/content generation and reject malformed or stale
records before use.

## Workspace and security boundary

`WorkspaceManager.require` remains the owner/runtime/root-identity gate and
`SafeWorkspaceFS` remains the handle-based path boundary.  Context retrieval
does not add a second workspace authority and has no Host filesystem fallback.
Absolute paths, parent traversal, protected metadata, symlink escapes, missing
workspace bindings, owner mismatches, malformed projections, and repository
identity mismatches fail closed or produce an explicit unavailable/stale
result.  Context facts never affect Approval, ToolScheduler capability,
Sandbox, execution leases, Memory visibility, or Trusted Verification.

## Existing intelligence inventory

* `LanguageRegistry` and its adapters are reusable after safe byte capture.
* `coding.intelligence.models` and `RepositoryIndexer` remain reusable for
  existing index/parser callers but contain path-oriented or mutable metadata
  surfaces unsuitable as the M7.2 canonical bundle contract.
* `coding.intelligence.query.CodeQueryService` already exposes definitions,
  references, callers/callees, imports/reverse imports, related tests, and
  optional LSP fusion for its existing persistent-index contract.  M7.2 does
  not duplicate or silently wire its unsafe reader into the AgentLoop; the new
  service provides the safe production retrieval seam and parser-derived
  relationships.
* `memory.codegraph` is a memory/index consumer, not a workspace authority,
  and is not used as the source of current context.
* LSP integration remains deferred until an owner-scoped, workspace-safe
  production adapter exists.

## AgentLoop composition

The production runtime constructs `ContextIntelligenceService` with the
runtime-owned `WorkspaceManager`; production configuration does not expose an
arbitrary replacement source reader.  AgentLoop loads the canonical GoalSpec
through its owner-scoped repository, constructs a bounded request for the
active TaskWorkspace, and injects only the bundle's bounded projection.  It
does not infer cognitive transitions, plans, completion, permissions, or
verification authority from context.  Compression/rebuild correctness is
preserved by rebuilding the typed bundle rather than relying on a historical
fingerprint-only “already shown” decision.

## Prompt privilege fence amendment

Repository/workspace context is emitted as a `Message(role="user")`
ephemeral observation.  The authenticated current user request is appended
after that observation by `AgentLoop`; the context message is never promoted
to `system` or `developer` role.  `metadata["trusted"] = False` remains
descriptive telemetry only: the OpenAI-compatible boundary is allowed to drop
Khaos metadata, so no security property relies on provider metadata support.

The trusted coding system prompt explicitly treats repository bytes as data
and rejects embedded instructions, policy/role/approval/permission claims, or
completion claims.  XML/Markdown delimiters are defense in depth and are not
considered a prompt-isolation or authority boundary.  Only trusted system
policy and the authenticated user request define the goal; Tool, Approval,
Sandbox, Workspace, Verification, and Completion authority remain enforced by
the runtime outside the model.

## Non-goals

M7.2 does not implement deterministic planning, PlanRevision persistence,
Recovery/Replan execution, Trusted Verification composition, legacy
`khaos.coding.verification.pipeline` integration, LLM ranking, or a new
database migration.
