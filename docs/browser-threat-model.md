# Browser Threat Model (Batch 7.4, round-7 §十)

## Current isolation boundary

Khaos's browser subsystem is **process-shared**: a single `BrowserManager`
(process-wide singleton) owns ONE Chromium process, ONE network namespace,
ONE cgroup, and ONE nftables table.  Multiple callers are isolated only at
the Playwright `BrowserContext` layer:

| Layer | Scope | Isolation guarantee |
|-------|-------|---------------------|
| Chromium process tree | **process-wide (shared)** | none across principals |
| Network namespace | **process-wide (shared)** | none across principals |
| cgroup (pids/memory/cpu) | **process-wide (shared)** | budget shared across principals |
| nftables table | **process-wide (shared)** | port set shared (per-context pins coexist) |
| `BrowserContext` (cookies/DOM/localStorage) | per-`(principal, session, runtime)` | API-layer isolation only |
| Egress proxy port | per-context | per-context port, pinned into the shared table |

The `EnforcementStatus.process_isolation` flag is `False` to make this
explicit — callers that require per-principal OS-level isolation must
check it and refuse to share.

## What the current model defends against

- **Accidental cross-principal state leakage at the API layer** — cookies,
  DOM, localStorage, page state are scoped per `BrowserContext`.
- **Network egress to non-allowlisted hosts** — the nft default-deny +
  per-context egress pin + authenticated proxy enforce that the browser
  netns can only reach the pinned proxy port.
- **Resource exhaustion from a single context** — the shared cgroup bounds
  the whole browser tree (pids/memory/cpu).

## What the current model does NOT defend against

> **A full Chromium-process compromise is NOT contained per-principal.**

If an attacker achieves arbitrary code execution inside the Chromium
process (e.g. a browser exploit that escapes the renderer sandbox), they
share the OS-level authority of that single process with every other
principal's context.  Specifically:

- Memory of other principals' `BrowserContext` data is reachable.
- The netns/cgroup/nft authority is process-wide, not per-principal.
- The egress proxy credentials of other contexts are reachable.

For a **single-user local product** this is acceptable — there is only one
principal.  For a **multi-principal deployment** (e.g. a shared Khaos
instance serving several authenticated users) this is a known gap.

## Codex-aligned end state (future work)

Review §十 recommends, for multi-principal deployments, keying the
browser authority domain by `(project_id, principal_id, runtime_id)` so
each domain owns a DISTINCT:

```
Browser Process
Network Namespace
cgroup
Proxy
Registry
Kernel Policy (nft table)
```

This is a substantial refactor (per-domain browser launch, lifecycle, and
resource management) and is tracked as future work.  Until then, the
`process_isolation = False` flag and this document are the explicit,
audited statement of the boundary.

## Safe to claim

> Khaos isolates browser contexts at the API layer (cookies/DOM/storage)
> and enforces kernel-level network egress default-deny per process.

## Not yet safe to claim

> Khaos isolates browser authority per principal at the OS level (a
> compromise of one principal's browser context cannot reach another's).
