# ADR-063: Give Python RPC services and composition explicit owners

## Status

Accepted — 2026-08-22

## Context

`python/khaos/grpc_server.py` had become a second application layer in
addition to its JSON-lines transport and process-lifecycle responsibilities.
It contained AgentService, TaskService, request value objects, router loading,
and optional subagent composition.  That made every transport change load the
full domain graph and allowed callers to import service types from a module
that was not their owner.  Compatibility imports also hid whether a migration
was complete.

## Decision

- `python/khaos/rpc/agent_service.py` is the sole owner of `AgentService`,
  including agent turns, webhook/channel handling, scheduled prompts, and
  process-scoped authority shutdown.
- `python/khaos/rpc/task_service.py` is the sole owner of `TaskService` and
  its per-principal/project manager cache.
- `python/khaos/rpc/models.py` owns the frozen request value objects
  `ChatRequest` and `ConfirmRequest`.
- `python/khaos/rpc/composition.py` owns router configuration and optional
  subagent composition.  It does not parse wire data or manage sockets.
- `python/khaos/grpc_server.py` owns JSON-lines framing, UDS peer/auth
  middleware, request dispatch, instance locking, and process startup/shutdown.
  It may hold private references to the named owners for dispatch, but it does
  not re-export application services or request models.
- The production import graph and `docs/security_facts.yaml` use
  `khaos.rpc.agent_service:AgentService` as the AgentService root.  Generated
  security fingerprints include every new owner module so a later edit cannot
  silently bypass the evidence artifact.

## Evidence and deletion record

- `python/tests/runtime/test_rpc_service_boundaries.py` asserts that the
  transport has no public service/model aliases and that each owner module is
  stable.
- The RPC, runtime, lifecycle, and integration suites were migrated to import
  the named owners directly; the targeted boundary run passed 89 tests with 4
  documented skips.
- The old AgentService, TaskService, request-model, router, and subagent
  composition definitions were deleted from `grpc_server.py`; no compatibility
  alias remains.  Future changes must target the named owner rather than adding
  another transport facade.
