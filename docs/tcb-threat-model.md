# M6 TCB Reduction Threat Model

## Boundary decomposition

| Boundary | Pure owner | I/O owner | Failure rule |
| --- | --- | --- | --- |
| Canonical bytes and digest | `protocol_boundary.py` | RPC/authority transport | malformed value rejected |
| Protocol negotiation/schema | `ProtocolNegotiation`, `validate_object_schema` | `grpc_server.py` | unknown fields/version rejected |
| Principal authentication | `RequestContext` and typed principal constructors | gateway/channel/cron adapters | transport mismatch rejected |
| Receipt state machine | `require_receipt_transition` | `authorityd.py` | illegal transition rejected |
| Exact effect | `EffectBinding` plus execution binding digest | launcher/supervisor | any mutation becomes mismatch/unknown |
| Resource lifecycle | `require_owner_transition` and `ResourceOwnerSnapshot` | runtime/process/browser owners | no proof means quarantine/unknown |
| Business orchestration | service/AgentLoop phases | database/model/tools | cannot issue native authority by itself |

## Adversarial assumptions

The model may control repository files, command strings, tool payloads,
untrusted channels, and cancellation timing. It may not be granted the
authority signing key, a native service identity, or an independent audit
writer. A local same-UID development broker remains test-only and is not
counted as production evidence.

## Closure rule

The pure boundary tests prove that malformed inputs and illegal transitions do
not produce a success state. They do not prove a process disappeared, a cgroup
was removed, or a native service ran. Those postconditions must be supplied by
the corresponding external resource oracle or real-platform CI job.
