# M8 P4 Category / Ontology Contract Closure Gate

日期：2026-09-13
范围：离线 benchmark-contract closure；不执行 Provider、模型、Coding、Browser、Full Corpus 或 M9。

## 结论

- P4-v2 defect：**CONFIRMED**（历史证据保留，不重算）。
- P4-v3：**CLOSED**。
- P4-v3 engineering：**READY** for the next explicitly authorized fresh qualification run.
- Provider integration：**NOT RUN BY DESIGN**。
- Real coding capability：**UNMEASURED**。
- Real browser capability：**UNMEASURED**。
- Full corpus readiness：**NOT READY**。
- Production readiness：**NOT READY**。
- M9：**NOT STARTED**。

## 安全与边界

本 gate 全程保持离线：Provider requests = 0，credential reads = 0，credential unlocks = 0，runtime Keychain UI = 0。没有读取、打印、写入或持久化 Provider secret，也没有把 secret 放入 prompt、fixture、trace、JSONL 或报告。

本次没有修改 Provider、CredentialBroker、CredentialSession、AgentLoop 决策、CompletionGate、Context ranking、Repo Intelligence、ToolAdmission、Sandbox 或 Browser authority。P4-v3 只新增版本化的公开输出契约和对应的纯评估路径；能力发现仍不拥有执行或完成权限。

## 身份与工作树

| 项目 | 值 |
|---|---|
| Branch | `codex/m8-coding-evaluation` |
| HEAD / current base | `3c1095ff69b1a5d800d96eb61e8b88a47fceca14` |
| Initial working-tree identity | `57774c93636b64e734c1c7fcce73fdeb13f28e35e546af947cae0f11b8adeced` |
| Final working-tree identity | `767cba8a973c05c593752aa4db400a19fb8f48ab9c4383f765d532092227b2de` |
| Identity exclusions | `docs/local-security-closure-report.md` and this report |
| Delivery | no commit, no push, no PR update |

Working tree contains pre-existing and current uncommitted changes. No unrelated change was discarded, reset, staged, committed, or pushed.

## Canonical contract audit

The public v3 vocabulary is exactly:

| Canonical value | Public role definition |
|---|---|
| `authority_definition` | the code location that establishes or defines the authority represented by the finding |
| `consumer` | the code that consumes, depends on, or uses that authority |
| `enforcement_boundary` | the code location that checks, enforces, or guards use of that authority |

The public contract deliberately does not expose hidden repository targets, symbols, concepts, relationships, or finding identifiers.

| Layer | P4-v3 closure contract | Result |
|---|---|---|
| Prompt | Publishes the exact enum, role definitions, exact finding count, closed JSON-only shape, and rejects aliases | PASS |
| JSON Schema | Closed object; exactly three findings; category enum generated from `ReviewCategory` | PASS |
| Typed model | `ReviewCategory` is the canonical v3 category; legacy string form remains available only for compatibility | PASS |
| Parser | v3 performs exact enum conversion and rejects unknown/alias categories and non-canonical fenced output; v2 parser behavior remains unchanged | PASS |
| Evaluator | v3 matches typed enum identity plus semantic location/concept evidence; output-contract failure is distinct from semantic failure | PASS |
| Hidden Oracle | v3 uses the same enum contract while retaining the semantic mapping privately in the existing hidden oracle | PASS |
| Scenario identity | v2 remains version 2; v3 is `p4-readonly-authority-v3`, version 3, with a distinct contract and digest | PASS |
| JSONL identity | Typed qualification writer/reader preserves the v3 scenario identity and record digest | PASS |

Current contract digests:

- P4-v2 scenario: `314b8022fd0eb325bd8199379135d22f3673cf2e27f9ef0a9d1c3b171eb9fa58`
- P4-v3 scenario: `34c08b50bdb2454f1284f414fbf3c9fe866afde30f40f6161a820d886698091c`
- P4-v3 response schema: `989bb545a062b03b0fc42322fd8100eb5898f9e1874915a76d5357fc8a657765`

These digests are identity bindings only. P4-v2 and P4-v3 are not strict-score-comparable.

## Root-cause classification

Primary classification: **`MULTI_LAYER_ONTOLOGY_DRIFT`**
Severity: **HIGH**
Generalizable: **YES**
Security impact: **NONE IDENTIFIED**

The historical v2 path had a vocabulary mismatch across the public review instruction and the exact evaluator/Oracle comparison. The public role meaning was understandable, but the exact accepted category serialization was not a single model-visible contract. The preserved lineage-2 real run submitted three findings, matched zero, and was recorded as a mechanical failure with three extras. That evidence is retained; it is not silently converted into a v3 result.

The repair is versioned rather than a v2 rescore: one public `ReviewCategory` enum now drives the v3 schema, parser, typed finding, evaluator, and Oracle contract. No model-specific whitelist, task-ID special case, expected-file hint, hidden concept, or answer-following rule was added.

## Harness fixes applied

1. Added the canonical `ReviewCategory` enum and `p4-review-category-v3` contract identifier.
2. Added a closed model-visible v3 JSON Schema with an enum derived from that type and an exact three-finding bound.
3. Added public role definitions without hidden answer literals.
4. Added strict v3 parser and typed conversion; preserved the historical v2 parser path.
5. Added typed v3 semantic evaluation and separate `OUTPUT_CONTRACT_FAILURE` / `SEMANTIC_REVIEW_FAILURE` outcomes.
6. Added an independent v3 scenario identity and digest while leaving the v2 scenario identity intact.
7. Bound CLI qualification selection and typed JSONL records to the selected v3 identity without calling a provider.
8. Added regression coverage for canonical values, role/file/concept near-misses, aliases, format variants, hidden-only category rejection, v2 compatibility, Oracle/evaluator consistency, failure-layer observability, router bootstrap, and JSONL identity.

## Verification evidence

- Final focused P4/qualification/observability/CompletionGate/Context/Repo/route/evaluation set: **193 passed, 1 warning**.
- Ruff on all touched ontology/evaluation/CLI files: **PASS**.
- Pyright on the touched evaluation package and `eval_commands.py`: **0 errors, 0 warnings**.
- `compileall` on touched Python packages: **PASS**.
- `git diff --check` and staged diff check: **PASS**.
- Offline router/bootstrap probe: **PASS**; resolved `zhipu-coding / glm-5.3` as metadata only, with zero provider requests, zero credential materializations, and zero credential sessions.
- Hidden-oracle/evaluator consistency probe: **PASS**; no hidden mapping was emitted.
- Secret-pattern audit over 18 relevant prior/generated report artifacts: **0 matches** for bearer/key-shaped patterns.

The repository-wide Python suite was also run for diagnosis: **5655 passed, 50 skipped, 4 failed**. The four failures are outside this ontology gate and were not changed:

- `test_s17_manager_cache_lock_serializes_eviction` — existing `TaskService(db=None)` construction boundary.
- `test_generated_inventory_is_fresh_and_fail_closed` — pre-existing generated reachability inventory drift.
- `test_privileged_spawn_inventory_is_current` — pre-existing privileged-spawn inventory drift.
- `test_audit_projection_is_best_effort_and_preserves_error_boundary` — existing audit error-message expectation mismatch.

The aggregate CLI type-check command also reports legacy diagnostics in `cli/main.py`; the touched evaluation package and `eval_commands.py` are clean. These unrelated baseline conditions do not change the P4-v3 contract verdict.

## Historical artifact preservation

- `docs/local-security-closure-report.md`: **UNCHANGED**. It remains untracked and unstaged; pre/post metadata remained mode `0644`, size `851`, mtime `1787640581`.
- Historical GLM-5.3-Flash lineage-2 report: **UNCHANGED** and remains untracked. It was not rewritten or rescored.
- Existing P4-v2 manifest, fixture, hidden oracle, and historical result identity remain preserved. No historical result was overwritten.

## Next gate

The next permitted action is a separately authorized fresh GLM-5.3-Flash **P4-v3 qualification-only** run using the production-shaped path. This closure gate does not execute it. The full real-provider corpus, real coding capability claim, real browser capability claim, and production-readiness verdict remain pending.
