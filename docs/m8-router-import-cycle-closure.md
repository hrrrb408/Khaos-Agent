# Khaos — Router Import Cycle & Dependency Direction Closure

Date: 2026-09-12

This is an offline Harness/dependency-direction closure gate. It does not run
GLM, Coding, Browser, the real-provider qualification, the full corpus, or M9.

## Identity and scope

```text
Branch: codex/m8-coding-evaluation
Current HEAD: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14
Expected M8 baseline: 3c1095ff69b1a5d800d96eb61e8b88a47fceca14
Working-tree identity before repair (protected report excluded):
  3890ea3fd6ee9313d8ec7fe06e92d4547e3a334a71f7ff7ca684ac66733b5776
Working-tree identity after repair (protected report and this report excluded):
  293a78fcb1200f62a37bb1ca6f9133217d5992d603a3653a66f608076c904ce0
Provider network requests: 0
Credential material reads: 0
Credential unlocks: 0
Credential materializations/sessions in Router smoke: 0 / 0
Git commit/push/PR/merge: none
```

The worktree was already dirty. Existing changes were preserved. The
untracked `docs/local-security-closure-report.md` was not read or modified.

The prior fresh GLM-5.3 qualification attempt remains preserved as a separate
artifact. It stopped before P0 because of this import-cycle blocker and is not
reclassified as a model or provider result.

## Failure reproduced before repair

The security foundation imported `CanonicalWorkspaceId` from
`khaos.coding.planning.security_identities`. Importing that module first
executed the eager planning package initializer and pulled repository,
verification, and Agent control modules into a low-level security import.

The observed cold-import paths were:

```text
audit.logger
  -> security.secret_redaction
  -> security.__init__ / credential_broker / resource_scope
  -> coding.planning.security_identities
  -> coding.planning.__init__ / planning.repository / trusted_verification_service
  -> agent package / agent.error_handler
  -> partially initialized audit.logger
  -> ImportError

agent.error_handler
  -> agent package / agent.control.completion
  -> security.__init__ / credential_broker / resource_scope
  -> coding.planning.__init__ / trusted_verification_service
  -> partially initialized agent.control.completion
  -> ImportError
```

This was an availability and safe-startup blocker. No authority bypass or
credential exposure was observed.

## Dependency audit

| Edge | Kind | Classification | Closure state |
| --- | --- | --- | --- |
| `security/resource_scope.py -> coding/planning/security_identities.py` | runtime identity import | low-level security foundation -> planning implementation | removed |
| `security/resource_scope.py -> security/identities.py` | runtime identity import | security authority -> neutral security contract | canonical |
| `coding/planning/security_identities.py -> security/identities.py` | runtime compatibility import | planning -> lower-level contract | allowed; same object re-exported |
| `audit/logger.py -> security/secret_redaction.py` | runtime security utility import | audit -> security | retained |
| `agent/error_handler.py -> audit/logger.py` | runtime audit sink import | agent -> audit | retained; intentional high-level edge |
| `rpc/composition.py -> domain implementations` | composition import | composition root -> implementations | retained; allowed |

`python/khaos/security/identities.py` now owns the stable
`CanonicalWorkspaceId` contract and imports only `typing.NewType`. The planning
module re-exports the same object for compatibility; it does not define a
second nominal identity. No local-import, exception-swallowing, or cycle-hiding
workaround was added.

## Repair

Applied changes:

1. Added the neutral security identity module
   `python/khaos/security/identities.py`.
2. Moved the canonical `CanonicalWorkspaceId` definition there.
3. Changed `security/resource_scope.py` to depend on the neutral contract.
4. Kept `coding/planning/security_identities.py` as a compatibility re-export.
5. Added fresh-interpreter import-order, identity-reuse, Router, and
   qualification-bootstrap regressions in
   `python/tests/integration/test_router_import_boundaries.py`.
6. Documented the dependency invariant in `docs/maintainer-architecture.md`.
7. Regenerated and freshness-checked the security and production-reachability
   inventories after the new production module was added.

## Verification evidence

All commands used a clean, non-secret environment unless otherwise noted.

```text
Cold direct imports + import-order matrix + identity reuse + Router smoke
  18 passed

Production Router smoke
  ModelRouter
  provider: zhipu-coding
  model: glm-5.3
  endpoint profile: https://open.bigmodel.cn/api/coding/paas/v4
  credential sessions: 0
  provider materializations: 0

Qualification bootstrap through manifest/fixture/policy/trace/JSONL setup
  provider: zhipu-coding
  model: glm-5.3
  scenario: p4-readonly-authority v2
  fixture: resolved
  provider requests: 0
  credential materializations: 0
  credential sessions: 0

Security/resource/credential regressions: 57 passed, 2 skipped
Audit export: 5 passed
Subagent import boundary: 4 passed
Architecture/composition probes: 16 passed
Routing regressions: 50 passed
Agent completion/error regressions: 88 passed
AgentLoop regressions: 22 passed
Evaluation directory (Trace/JSONL/P4/oracle/contracts): 145 passed, 1 skipped
```

Static checks:

```text
Ruff: PASS
Pyright on changed modules/test: PASS (0 errors)
compileall on changed modules/test: PASS
privileged-spawn inventory: PASS
security inventory freshness: PASS
production reachability freshness: PASS
git diff --check: PASS
```

The broader Python-suite result from the preceding Harness gate remains
historical evidence, not a new full-suite claim for this repair: its initial
run was `5569 passed, 50 skipped, 11 failed`; after generated inventory
regeneration, eight known pre-existing failures remained outside this import
repair. No Go or Rust source was changed.

## Defect review

| Candidate | Severity | Affected subsystem | Generalizable | Security impact | Resolution |
| --- | --- | --- | --- | --- | --- |
| Security resource scope imported a planning implementation to obtain a shared identity | HIGH | security/planning import boundary | yes | startup availability only; no bypass observed | fixed with neutral identity owner and regression matrix |
| First version of the new test helper prefixed a raw Python contract probe with `import` | INFO | regression test only | no runtime impact | none | corrected before final evidence |
| Generated inventory became stale after adding a production module | INFO | generated evidence | yes as maintenance contract | none | regenerated; freshness checks pass |

No unresolved BLOCKER or HIGH Harness defect remains from this gate. The
first failed qualification result remains preserved and is not overwritten.

## Conservative capability status

```text
Provider Integration: NOT RUN in this gate
Real AgentLoop with GLM: NOT RUN
Real Coding Capability: NOT EVALUATED
Real Browser Capability: UNMEASURED
Full real-provider corpus: NOT RUN
M8 Engineering: COMPLETE (prior baseline)
Router import closure: PASS
Fresh GLM-5.3 P0–P4-v2 qualification: READY as the next separately authorized gate
Full Corpus Readiness: NOT READY
Production Readiness: NOT READY
M9: NOT STARTED
```

This report supplies readiness to start the next fresh qualification only. It
does not authorize that run and makes no capability or competitive claim.

## Repository state

```text
Protected docs/local-security-closure-report.md: unchanged / untracked / unstaged
Current code/docs/tests: uncommitted working-tree changes
Staged changes: none
Publication: not performed
```
