# M2 Enforcement Closure Evidence

## Evidence status

| Control | Status | Evidence |
| --- | --- | --- |
| Task Worktree writes | enforced / verified | Runtime E2E creates a Git Worktree and proves the main tree remains unchanged before apply. |
| ChangeSet apply | enforced / verified | One-shot ApprovalBroker binding includes task, workspace, requester, ChangeSet content hash, operation, task HEAD and diff hash. |
| Verification | integrated / verified | `VerificationPipeline` accepts the runtime `ExecutionService` and executes under the active TaskWorkspace. |
| Managed LSP/process shutdown | enforced / verified | Managed processes use a POSIX process group; shutdown terminates parent, child, and grandchild, then removes temporary HOME. |
| Docker isolation | verified | Dedicated Docker security workflow runs real container isolation tests. |
| Linux bwrap isolation | integrated | Required GitHub Actions job runs actual bubblewrap execution; CI result is the release-gate evidence. |
| macOS sandbox-exec isolation | integrated | Required GitHub Actions job runs actual sandbox-exec execution. Local restricted runtimes may skip only when they cannot invoke the host sandbox. |

## Deliberate limits

- Linux/macOS platform controls remain **integrated** until their required CI jobs have produced a successful run; parameter construction is not counted as platform evidence.
- Domain-level network allowlisting is not implemented. The enforced policy here is network deny for local Coding execution.
- Public tool migration is outside this final verification sprint. Any direct compatibility implementation must remain unreachable through `ToolInvocationBroker`; final static audit must report such exceptions explicitly.
