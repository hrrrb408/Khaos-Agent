# ADR-087: Controlled MCP, Hooks, and Skills Extensibility

Status: Accepted

Date: 2026-09-06

## Context

M8.7 adds an extension plane for configured MCP servers, lifecycle hooks, and
declarative Skills.  The extension plane is model-visible and may cross trust
boundaries, but it must not become a second tool registry or a second control
plane.  Discovery, descriptive metadata, provider output, and Skill
instructions are therefore untrusted inputs unless the existing Khaos owners
independently admit an effect.

## Decision

Khaos uses one owner-scoped `ExtensionRegistry` and one
`CapabilityAdmissionService`.  The registry owns descriptor identity,
capability validation, collisions, and lifecycle projections.  Admission
re-reads the current registry state and binds task, principal, project,
workspace, policy generation, approval, credential, network, extension, and
capability digests into an immutable `InvocationBinding`.  A binding is a
proof of a current admission decision, not execution authority.

External capabilities are never registered in the canonical built-in
`ToolRegistry`.  MCP tool calls are dispatched only through the existing
execution/approval/sandbox/network owners after admission.  MCP resources and
prompts become bounded `ContextItem` projections with explicit extension trust
labels; they cannot create system/developer authority, completion, approval,
verification, or workspace facts.

## Trust classes and provenance

The descriptor records source, artifact/config identity, provenance, transport,
and lifecycle state.  Built-in and explicitly trusted local configuration are
distinct from project-declared and local-untrusted inputs.  Repository-local
configuration is data: it is validated and listed, but it does not auto-start
an MCP process, install a package, inject credentials, or enable an effect.

Skills are declarative packages.  Their manifest, body, examples, source root,
and package digest are validated and bound.  Skill text is injected through
the Context Engine as lower-trust extension context, with bounded size and
freshness; missing required tools yield a partial activation rather than a
new tool or an authority upgrade.

## MCP lifecycle and transport

Local stdio uses an injected process-owner seam.  The descriptor must provide
an absolute regular executable, an explicit artifact digest, bounded argv and
scrubbed environment; shell mode, package-manager launchers, model-writable
executables, and authority-shaped environment variables are rejected.

Remote HTTP is validated through the existing network authority.  Redirects
are disabled in the client and separately validated endpoints cannot change
host or downgrade HTTPS.  The approved DNS target is pinned for the HTTP hop;
malformed or missing `ValidatedTarget` results fail closed.  Private and
special addresses are denied by default.

Handshake, discovery pages, schemas, messages, results, concurrent calls,
notifications, per-task calls/bytes/wall time, and restarts are bounded.
Transport failure degrades the extension; uncertain cleanup quarantines it.
Cancellation shields cleanup and never reports a false terminal state.

## Hooks and supervision

Hooks receive immutable event projections and can observe, advise, or (only
when explicitly trusted) block.  They cannot mutate canonical events or write
control-plane state.  Hook tool requests return to the same admission service;
provider output cannot self-approve.  Depth, reentrancy, event storms, result
bytes, timeout, deterministic order, and failure isolation are bounded.
Extension lifecycle and hook/MCP outcomes are namespaced extension supervision
events, so provider-controlled fields cannot overwrite task status,
verification, approval, or completion projections.

## Durable state and child scope

Migration v31 adds owner-scoped descriptor, capability, runtime, invocation,
Hook registration, and Skill activation projections.  Identity and audit rows
are append-only; mutable runtime health remains separate.  Runtime process and
session identity cannot drift under one instance id.

Production runtime composition constructs the sole extension service from the
effective policy.  A delegated child is not given the parent's extension
registry or credentials; the current conservative composition exposes an
empty child subset until an explicit owner-scoped subset assignment is
provided.  This cannot escalate authority.

## Consequences

The feature has more explicit lifecycle and digest state, but all extension
effects remain inside existing authority owners.  Provider-specific integration
is intentionally an injected transport/process-owner seam, allowing deterministic
security tests without making a fake provider part of production authority.
Live third-party-provider behavior and coding-quality improvement remain
separate evidence questions; M8.7 does not claim either from scripted tests.

## Rejected alternatives

* Registering MCP tools directly in `ToolRegistry` would conflate discovery
  with execution and bypass extension provenance/lifecycle checks.
* Treating Skill or provider text as system instructions would allow prompt
  injection to widen policy and authority.
* Letting an extension return `approved`, `verified`, or `completed` fields
  would create a second authority chain.
* Starting repository-local commands through `PATH`, package launchers, or a
  shell would make executable identity and supply-chain provenance ambiguous.
