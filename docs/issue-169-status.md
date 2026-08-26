# Issue #169 status matrix

> Status reference: 2026-08-26. This is a classification record, not a
> request to close Issue #169. The machine-readable source is the
> `issue_169` section of [`security_facts.yaml`](security_facts.yaml).

Issue #169 remains `PARTIALLY_COMPLETED`. The code-level authority work that
is already present is recorded as `COMPLETED`; deployment, governance, and
incremental decomposition boundaries remain explicit instead of being
rewritten as pending implementation or silently treated as closed.

| Work item | Classification | Current evidence | Remaining boundary |
|---|---|---|---|
| Typed resource narrowing | `COMPLETED` | `resource_scope.py` and its regression matrix | Protected exact-SHA CI is still release evidence, not a missing implementation. |
| Grant descendants | `COMPLETED` | Authority-owned descendant registry, reservation, revocation, and narrow tests | The native platform transport must remain fail-closed when unavailable. |
| Immutable scheduler states | `PARTIALLY_COMPLETED` | Typed admission/phase/effect objects and state-contract tests | The mutable compatibility projection and incremental physical split remain. |
| Native authority | `PARTIALLY_COMPLETED` | Native adapter contract, platform workflow, and negative tests | Exact-SHA macOS/Windows native CI and deployment identity are external evidence. |
| Delegation | `COMPLETED` | Authority-owned child issuance/one-shot consumption and delegation tests | A deployment without the authority transport is rejected, not upgraded to a caller-side capability. |

The following distinctions remain in force:

- `COMPLETED` means the repository implementation and regression contract
  are present. It does not manufacture a successful platform CI run.
- `PARTIALLY_COMPLETED` means a typed or fail-closed implementation exists,
  but a stated compatibility or external-evidence boundary remains.
- `RESIDUAL` covers an unresolved governance or deployment risk; it is not
  hidden by a green local subset.
- `DEFERRED` and `OUT_OF_PROFILE` are valid future classifications and must
  be used when a change would expand scope rather than silently changing the
  Community Local threat model.

The current Community Local profile explicitly keeps hostile same-UID
isolation and second-maintainer review as `NOT_CLAIMED`. A saved issue note,
closure JSON, or local test result cannot issue the live exact-SHA provenance
capability or close the issue.
