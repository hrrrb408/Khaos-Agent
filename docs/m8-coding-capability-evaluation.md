# M8.0 Coding Eval Closure Report

状态：实现完成；本地评测专用回归与 OS-enforced hidden-command smoke 已收口，远端 CI 尚未在本地代跑。

M8.0 建立了 Coding 能力评测基线。它回答“模型能否在受限仓库中完成指定编码任务”，不回答“控制平面是否正确执行权限、审批、验证、恢复或完成状态”。后者仍由 M7.9 observation-only control-capability evaluator 负责。

## 1. 实现边界

评测数据流如下：

```text
immutable manifest
        │
        ▼
private fixture copy ──► real AgentLoop/runtime ──► bounded trace
        │                         │                     │
        │                         ▼                     │
        └──────────────► external oracle ◄──────────────┘
                              │
                              ▼
                    immutable owner-scoped ledger
```

实现位于 `python/khaos/evaluation/coding/`，包含：

- `contracts.py`：Scenario v1、manifest digest、resource limits、typed oracle、run identity、verdict/failure taxonomy。
- `manifest.py`：重复键拒绝、closed fields、路径约束、manifest/fixture 解析。
- `fixtures.py`：独立私有运行目录、确定性 Git baseline、公共/隐藏 fixture digest、源不变性和精确清理。
- `oracle.py`：COMMAND、FILE_STATE、DIFF、COMPOSITE、REVIEW_FINDING；命令只经既有 `ExecutionService`，无 Host fallback。
- `runtime_invoker.py`：真实 Khaos `AgentLoop` 适配器；CODE_REVIEW 只注入只读工具白名单。
- `metrics.py`：bounded sanitized trace、模型/工具/编辑/验证/恢复/审批/时序/diff 指标；没有来源证据的 context 指标保持 `null`。
- `runner.py` / `results.py`：超时、Agent/Oracle/fixture 错误分类、最终 workspace 约束、结果 digest 和清理顺序。
- `repository.py` / `report.py` / `service.py`：owner-scoped append-only ledger、JSON/Markdown report、同 scenario id/version compare。
- `sandbox.py`：复用现有 OS-enforced backend；不可用时显式 `ORACLE_ERROR`/CLI unavailable，不降级到 host subprocess。

M8.0 的 `coding_evaluation_runs` 表由迁移 v27 创建，并带 UPDATE/DELETE 拒绝触发器。它没有被 Completion、Verification、Recovery、Permission、Approval、Router、Memory 或 TaskStatus 读取，因此不能改变 Khaos 的控制权威。

## 2. Scenario baseline

内置 pack 是 digest-bound、排序稳定的 12 个场景。每个公共 repo fixture 含 3--4 个源文件，隐藏 verifier 只在 oracle copy 中出现。

| Scenario | 类型 | 语言 | 难度 | Oracle | Fixture 文件 |
| --- | --- | --- | --- | --- | ---: |
| `bugfix-go-counter` | BUG_FIX | Go | medium | COMMAND + DIFF | 4 |
| `bugfix-python-cache` | BUG_FIX | Python | easy | COMMAND + DIFF | 4 |
| `bugfix-typescript-config` | BUG_FIX | TypeScript | medium | COMMAND + DIFF | 4 |
| `cross-language-python-go-contract` | CROSS_LANGUAGE | Python + Go | hard | COMMAND + DIFF | 4 |
| `cross-language-typescript-go-config` | CROSS_LANGUAGE | TypeScript + Go | hard | COMMAND + DIFF | 4 |
| `feature-python-index` | FEATURE | Python | medium | COMMAND + DIFF | 3 |
| `feature-rust-parser` | FEATURE | Rust | hard | COMMAND + DIFF | 3 |
| `multifile-go-pipeline` | MULTI_FILE | Go | hard | COMMAND + DIFF | 4 |
| `multifile-python-settings` | MULTI_FILE | Python | hard | COMMAND + DIFF | 4 |
| `refactor-python-repository` | REFACTOR | Python | medium | COMMAND + DIFF | 3 |
| `refactor-typescript-client` | REFACTOR | TypeScript | medium | COMMAND + DIFF | 3 |
| `review-python-cache-race` | CODE_REVIEW | Python | medium | REVIEW_FINDING + read-only DIFF | 3 |

分类计数为 BUG_FIX 3、FEATURE 2、REFACTOR 2、MULTI_FILE 2、CROSS_LANGUAGE 2、CODE_REVIEW 1；覆盖 Python、Go、Rust、TypeScript。

## 3. Oracle 与安全不变量

- COMMAND 使用 manifest-owned typed argv、固定 evaluated workspace cwd、有限 environment allowlist、timeout/output budget、expected exit code 和 `NetworkPolicy.NONE`。不接受 shell 字符串，不把模型命令或环境传给 verifier。
- hidden verifier 在 `private/oracle/run-*/.oracle-hidden` 中运行。Agent root 没有隐藏文件、隐藏路径或隐藏内容；结果只保留状态、退出码、字节数、digest 和耗时。
- FILE_STATE 只检查有限路径、存在性、文本片段、hash 或 JSON 状态；符号链接和特殊文件 fail closed。
- DIFF 基于前后 bounded snapshot，报告 changed/added/deleted/renamed、insertions/deletions、binary 和 digest；`.git` worktree pointer 与生成的 `__pycache__` 不算源变更。
- REVIEW_FINDING 只接受结构化 finding，匹配 file、line/range、category、severity 和 concepts，并分别统计 missed、duplicate、false-positive。CODE_REVIEW 的写工具不在 allowlist，未知的写调用被记录为拒绝结果，不终止整个只读回合。
- Fixture manager 先复制公共 bytes，再创建确定性 Git baseline；原始 pack 与隐藏 pack 每次都会复核。Agent 不能把 oracle workspace 伪装成 final output，也不能创建保留的 `.oracle-hidden` 目录。
- 既有 `BackendSelector`/`ExecutionService` 是唯一命令执行面。OS sandbox 不可用时保持明确的不可用/Oracle error 边界，绝不使用不受限 host 执行。

## 4. Identity、metrics 与 verdict

每次 run 绑定：run id、scenario id/version/digest、oracle digest、fixture digest、agent version、Khaos source SHA（无法取得时为 `unknown`）、model/provider、config/model-config digest、reasoning effort、runtime profile/id、OS、platform、Python version、fixture base revision、source/evaluated source digest。

Trace 不保存 prompt、模型原始回复、工具参数、仓库源码或 hidden verifier 输出。指标包含模型 calls/turns/tokens、按工具名和类别计数、读/搜索/符号/写/patch/terminal/test/git/browser/subagent、editing/verification/recovery、首次工具/读/编辑/测试/绿色时序、edit attempts/failed/reverted/unrelated、test pass/fail、approval/permission denial、completion/replan/no-progress/recovery，以及 diff 文件数/增删行数。上下文缓存、符号、压缩等字段没有可信来源时保持 `null`，不能用 0 冒充已观测。

终态仅有：`PASS`、`FAIL`、`TIMEOUT`、`AGENT_ERROR`、`ORACLE_ERROR`、`INVALID_FIXTURE`、`INSUFFICIENT_EVIDENCE`。失败 taxonomy 覆盖 localization/edit/build/test/regression/timeout/no-progress/wrong-files/excessive-diff/review missed/review false-positive，以及 agent/oracle/fixture/evidence 错误。

## 5. CLI 与持久化

```text
khaos eval coding list [--tag TAG] [--json]
khaos eval coding run SCENARIO_ID
khaos eval coding run --tag TAG
khaos eval coding run --all
khaos eval coding report [RUN_ID] [--scenario-id ID] [--format markdown|json]
khaos eval coding compare BASELINE_RUN_ID CANDIDATE_RUN_ID
```

`report` 与 `compare` 始终按 authenticated principal/project scope 查询；compare 只接受相同 scenario id/version。数据库表 `coding_evaluation_runs` 是 append-only，结果 JSON canonicalized 并与标量列交叉校验。

## 6. Validation boundary

本地 Fake Model 验证真实 AgentLoop adapter、外部 oracle、私有 fixture、只读 review、diff evidence、metrics limit、owner-scoped ledger、迁移 v27 和 CLI parser。PR CI 的四个独立 job 位于 `.github/workflows/coding-evaluation.yml`：unit、fixture integrity、oracles、fake-agent E2E。

真实 provider CLI 不在 PR CI 中运行；它需要用户明确选择的 provider、凭据、模型配置和对应 OS sandbox。没有该运行证据时，real-provider outcome/quality 保持 unknown，不从 Fake Model PASS 推断。

当前 pack 的 hidden checks 是结构化 baseline verifier，不是完整生产项目测试；review 是 bounded structured finding match；context/cached-token 指标尚无可信 runtime source。这些是已记录的评测限制，不会被报告为控制平面缺陷或成功证据。

### Known limitations

- 当前 12 个 fixture 是 synthetic-but-realistic baseline，不等价于大型真实仓库或 SWE-bench；它们用于稳定回归和能力趋势，不用于宣称生产级总体成功率。
- `context_*`、`cached_tokens` 以及 provider 不提供的 token 字段保持 `null`；没有通过估算填充。
- 本地执行的是 Fake Agent 与一个 hidden-command smoke；真实 provider/model quality、成本和跨平台表现尚未取得证据，保持 `unknown`。
- DIFF 使用 bounded source snapshot；超出文件、字节、事件或输出预算时 fail closed，不能当作完整未截断证据。

## 7. 实际 Fake Agent benchmark 样例

以下是 2026-09-01 在本机直接调用 `CodingEvaluationRunner` 得到的单场景结果。Fake Agent 修改私有 fixture 中的 `src/cache.py`，随后提交一次 `test_run`；评测使用真实 `FixtureManager`、真实 bounded diff、真实 `ExecutionService` OS-enforced read-only command oracle。该样例不使用真实 provider，也不把 Fake Agent 的成功外推为 provider 质量结论。

```json
{
  "changed_files": ["src/cache.py"],
  "deletions": 1,
  "editing_calls": 1,
  "failure_reason": null,
  "insertions": 3,
  "manifest_digest": "9ee1bf6fd10d3afc1ded11c689b1ae2ac251a641836aad1d1615a458358976d5",
  "model_calls": 2,
  "model_turns": 2,
  "oracle_checks": ["COMMAND", "DIFF"],
  "scenario_id": "bugfix-python-cache",
  "scenario_version": 1,
  "tests_passed": 1,
  "tests_run": 1,
  "tool_calls": 2,
  "tool_calls_by_name": {"test_run": 1, "write_file": 1},
  "verification_calls": 1,
  "verdict": "PASS"
}
```

## 8. 完整文件清单

### Evaluator implementation and integration

- `python/khaos/evaluation/coding/__init__.py`
- `python/khaos/evaluation/coding/contracts.py`
- `python/khaos/evaluation/coding/fixtures.py`
- `python/khaos/evaluation/coding/manifest.py`
- `python/khaos/evaluation/coding/metrics.py`
- `python/khaos/evaluation/coding/oracle.py`
- `python/khaos/evaluation/coding/repository.py`
- `python/khaos/evaluation/coding/report.py`
- `python/khaos/evaluation/coding/results.py`
- `python/khaos/evaluation/coding/runner.py`
- `python/khaos/evaluation/coding/runtime_invoker.py`
- `python/khaos/evaluation/coding/sandbox.py`
- `python/khaos/evaluation/coding/service.py`
- `python/khaos/cli/eval_commands.py`
- `python/khaos/cli/main.py`
- `python/khaos/db/migrations/0027_coding_evaluation_runs.sql`
- `python/khaos/db/migrations/_registry.py`
- `python/khaos/db/database.py`
- `python/khaos/tools/admission.py`
- `python/khaos/tools/scheduler.py`
- `pyproject.toml`

### Built-in pack: public fixture files and private oracle files

- `python/khaos/evaluation/coding/pack/manifest.yaml`
- `bugfix-go-counter`: `repo/README.md`, `repo/counter.go`, `repo/counter_snapshot.go`, `repo/counter_test.go`, `hidden/verify.py`
- `bugfix-python-cache`: `repo/README.md`, `repo/src/cache.py`, `repo/src/keys.py`, `repo/src/service.py`, `hidden/verify.py`
- `bugfix-typescript-config`: `repo/README.md`, `repo/src/config.ts`, `repo/src/index.ts`, `repo/src/types.ts`, `hidden/verify.py`
- `cross-language-python-go-contract`: `repo/README.md`, `repo/contract.json`, `repo/go/server.go`, `repo/python/client.py`, `hidden/verify.py`
- `cross-language-typescript-go-config`: `repo/README.md`, `repo/contract.json`, `repo/go/config.go`, `repo/ts/client.ts`, `hidden/verify.py`
- `feature-python-index`: `repo/src/index.py`, `repo/src/service.py`, `repo/tests.py`, `hidden/verify.py`
- `feature-rust-parser`: `repo/Cargo.toml`, `repo/src/lib.rs`, `repo/src/parser.rs`, `hidden/verify.py`
- `multifile-go-pipeline`: `repo/pipeline.go`, `repo/pipeline_test.go`, `repo/service.go`, `repo/validate.go`, `hidden/verify.py`
- `multifile-python-settings`: `repo/README.md`, `repo/service.py`, `repo/settings.py`, `repo/tests/test_settings.py`, `hidden/verify.py`
- `refactor-python-repository`: `repo/src/repository.py`, `repo/src/service.py`, `repo/tests.py`, `hidden/verify.py`
- `refactor-typescript-client`: `repo/src/client.ts`, `repo/src/index.ts`, `repo/src/transport.ts`, `hidden/verify.py`
- `review-python-cache-race`: `repo/src/cache.py`, `repo/src/service.py`, `repo/tests.py`, `hidden/README.md`

### Regression, CI, and documentation

- `python/tests/evaluation/test_coding_eval_cli.py`
- `python/tests/evaluation/test_coding_eval_contracts.py`
- `python/tests/evaluation/test_coding_eval_fixtures.py`
- `python/tests/evaluation/test_coding_eval_metrics.py`
- `python/tests/evaluation/test_coding_eval_oracle.py`
- `python/tests/evaluation/test_coding_eval_persistence.py`
- `python/tests/evaluation/test_coding_eval_report.py`
- `python/tests/evaluation/test_coding_eval_runner.py`
- `python/tests/evaluation/test_coding_eval_runtime.py`
- `python/tests/tools/test_scheduler_boundaries.py`
- `.github/workflows/coding-evaluation.yml`
- `docs/m8-coding-capability-evaluation.md`

## 9. Validation record

| Command | Passed | Failed | Skipped | Result |
| --- | ---: | ---: | ---: | --- |
| `PATH=/Library/Developer/CommandLineTools/usr/bin:$PATH DEVELOPER_DIR=/Library/Developer/CommandLineTools PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python .venv/bin/pytest -q --tb=short python/tests/evaluation/test_coding_eval_*.py python/tests/tools/test_scheduler_boundaries.py` | 43 | 0 | 0 | PASS |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python .venv/bin/pytest -q --tb=short python/tests/evaluation/test_capability_evaluation.py python/tests/evaluation/test_capability_benchmark_matrix.py python/tests/evaluation/test_capability_benchmark_real_paths.py` | 75 | 0 | 0 | PASS |
| `PATH=/Library/Developer/CommandLineTools/usr/bin:$PATH DEVELOPER_DIR=/Library/Developer/CommandLineTools PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python .venv/bin/pytest -q --tb=short python/tests/evaluation` | 111 | 0 | 0 | PASS |
| `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=python .venv/bin/pytest -q --tb=short python/tests/coding` | 1857 | 0 | 7 | PASS |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/pyright python/khaos/evaluation/coding python/khaos/cli/eval_commands.py python/khaos/db/migrations/_registry.py python/khaos/tools/admission.py python/khaos/tools/scheduler.py` | — | 0 | — | PASS: 0 errors, 0 warnings, 0 informations |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m compileall -q python/khaos/evaluation/coding python/khaos/cli/eval_commands.py python/khaos/db python/khaos/tools` | — | 0 | — | PASS |
| `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python` YAML parse of `.github/workflows/coding-evaluation.yml` | — | 0 | — | PASS: four jobs loaded |

The seven skips are pre-existing platform/backend skips in the broad Coding suite. Real-provider runs and remote GitHub CI were not executed in this local session; their outcome remains `unknown` until a provider, credentials, OS sandbox, and exact commit are selected.

## 10. Next step

下一里程碑仅为：**M8.1 Repo Intelligence Convergence**。M8.1 应以本报告中的 success、model turns、tool calls、time-to-first-green、repair/recovery、changed files 和 unrelated diff 指标作为 baseline。
