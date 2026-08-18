# ADR-019: Machine-Checked Production Reachability

**Status:** Accepted for M6 closure work

## Context

The production composition must not be able to reach the development
`HostExecutionBackend`, the legacy verification pipeline, or a compatibility
builder through a public package hook. A source review of individual call
sites is insufficient: import-time exports and lazy imports can preserve an
execution path after the obvious call is removed.

## Decision

`scripts/generate_production_reachability.py` is the repository authority for
the Python production composition graph. It starts at explicit production
roots, parses repository imports, resolves literal `_LAZY_EXPORTS` maps and
static dynamic-import strings, and fails closed when an internal module cannot
be resolved. Forbidden development/Host modules and symbols are explicit
denylisted targets.

The generated
`docs/generated/production-reachability.md` file is checked for freshness in
CI. It is evidence of repository-level composition reachability only; it is
not evidence that a native kernel, launchd/XPC service, Windows Service, or
remote governance control has run.

## Consequences

- A production compatibility hook must be removed or excluded from the graph;
  it cannot be justified by saying that callers do not currently use it.
- Adding a new production root or lazy export requires updating the generator,
  its tests, and this evidence boundary.
- Native and remote evidence remain separate M6 requirements and cannot be
  substituted by this static graph.
