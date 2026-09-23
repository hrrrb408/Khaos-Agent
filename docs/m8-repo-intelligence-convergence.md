# M8.1 Repo Intelligence Convergence Closure Report

状态：M8.1 实现与本地回归已完成；提交与远端 ref 以本报告末尾的最终交付记录为准。本文只记录已验证的本地证据，不把 Fake Model 或单元测试当作真实 Coding Capability 提升证据。

## Architecture

改动前的生产形态是两条读取路径：

```text
workspace bytes → M3 RepositoryIndexer / IndexStore / ResolutionService
workspace bytes → M7 ContextIntelligenceService 的 snapshot/hash/parse/rank
```

现在的热路径是：

```text
TaskWorkspace
    → RepoIntelligenceService
       → IndexStore + RepositoryIndexer + ResolutionService + CodeQueryService
       → generation/freshness/query/cache
    → ContextIntelligenceService 的 task-aware ranking/assembly
    → ContextBundle
    → AgentLoop Coding Context
```

`ContextIntelligenceService` 保留 GoalSpec、TaskWorkspace、预算和 `ContextBundle` 合同，repository-wide 枚举、解析、索引、语义关系和安全 source capture 由统一门面负责。AgentLoop 通过同一门面向 `code_search` / `code_symbols` 注入共享实例。

## Reuse

实际复用的 M3 能力包括：

- `LanguageRegistry`、Tree-sitter adapter 和 `ParseState`：Python、Go、Rust、JavaScript/TypeScript 的解析与增量状态。
- `RepositoryIndexer`：bounded bootstrap、单文件 `refresh_paths()`、删除/重命名处理、parse-state cache 和 mutation fence 接口。
- `IndexStore`：既有 code index、symbols/imports/calls/references 与新增的 derived `repo_intelligence_state`。
- `ResolutionService`：受影响文件的 import/call/reference 重新解析和既有 generation CAS；Go module 读取也通过安全 source adapter。
- `CodeQueryService`：语义 graph 的 callers、callees、references、imports、reverse imports、依赖文件和 test association 查询。
- `SafeWorkspaceFS`：workspace containment、no-follow、regular-file/hardlink 检查；M8 facade 没有 host-path fallback。
- `LspEvidenceFusionService`：仍是可选证据，不是 Repo Intelligence 的正确性或可用性前置条件，M8.1 不自动安装或联网下载 LSP。

## Removed or downgraded duplication

- M7 context adapter 不再维护 repository-wide parser、semantic storage 或独立 snapshot/hash/parse universe；它只把 typed repository result 投影为旧 `ContextBundle`。
- M7 context 的 bounded LRU 只缓存 generation-bound 的 bundle projection，不再作为 repository semantic truth source。
- `code_search` 和 `code_symbols` 的 owner-bound 路径进入 `RepoIntelligenceService`；semantic search 无命中时才走 bounded lexical fallback，结果带 freshness/semantic/fallback 状态。
- 仅保留缺少完整 TaskWorkspace owner 字段的旧测试 fixture 的显式兼容 AST 路径；真实 Coding 工具路径必须经过 active TaskWorkspace，不能用它绕过生产边界。

## Generation, freshness and mutation

核心合同为：

```text
RepositoryGeneration(workspace_id, generation, manifest_digest, indexed_at, source_revision)
IntelligenceFreshness = CURRENT | STALE | PARTIAL | UNAVAILABLE
FreshnessPolicy = REQUIRE_CURRENT | PREFER_CURRENT | ALLOW_STALE
MutationType = CREATE | UPDATE | DELETE | RENAME | MOVE | COPY | RESTORE | ROLLBACK
```

- 首次有效 bootstrap 创建 generation 1；manifest 发生变化并成功刷新后递增。每个 typed query 和 context result 都携带 generation/freshness。
- `PREFER_CURRENT` 是 Coding Context 默认策略；`REQUIRE_CURRENT` 在无法取得 CURRENT 时 fail closed；`ALLOW_STALE` 显式返回 STALE，不伪装成 current。
- `write_file`、`patch`、`multi_edit`、`copy_file`、`move_file`、`delete_file` 的成功结果被转换为 typed mutation event。可安全解析的单文件变更进入 `refresh_paths()`；目录或无法安全恢复路径的变更请求 bounded full refresh。`copy_file` 刷新目标路径并保持源路径不变。
- rename/move 同时观察 old/new 路径：旧 symbol/relations 删除，新路径重新解析。受影响关系由 M3 `ResolutionService` 的 reverse-dependency closure 失效/重算。
- persistent `IndexStore` 只保存 derived index 和 generation projection；重启时先校验 workspace root identity、owner binding 和持久状态，不匹配则安全 rebuild。
- context capture 保留两次 bounded capture：stat/read/stat identity 校验；竞态会将路径重新置 dirty 并最多重试一次，仍变化则 STALE/UNAVAILABLE，不能静默混合 generation。

## Query capability

| Query | 实际支持 | 证据/边界 |
| --- | --- | --- |
| `symbols` | 是 | typed `RepoSymbol`，语言/path/qualified name/kind/range/id |
| `definitions` | 是 | 复用 indexed symbol/graph，未解析目标不猜测 |
| `references` | 是 | M3 persisted reference edges，保留 unresolved 状态 |
| `callers` | 是 | target stable symbol identity |
| `callees` | 是 | caller generation-specific symbol identity；已补回归 |
| `imports` / `importers` | 是 | resolved 与 reverse import graph |
| `related_files` | 是 | dependency/reverse-dependency graph |
| `related_tests` | 是 | semantic edges + path/module/subject 的 bounded heuristic |
| `search_text` | 是 | semantic symbol hit 优先；无命中时 bounded lexical fallback |
| `repository_overview` | 是 | languages、important roots、package/build/config、entry points、test roots、top symbols；不输出完整 tree |

所有结果使用 dataclass typed contract，limit、bytes、depth、symbols、relations 和 operation duration 均有资源上限。unsupported/binary/oversized 文件保留 bounded metadata-only record 并标记 `semantic_support=false`；它们不进入语义 context source。

## Context and tools

Context 选择顺序为 GoalSpec/task query、changed/target files、symbol evidence、relation evidence、path terms，再按文件/符号/字节预算组装。显式 target symbol 先按完整 symbol identity 解析，不用 substring 命中；semantic candidate 会提高 definition、caller/callee、reference、dependency、related-test 等相关文件的排序，最终 source bytes 仍由 `SafeWorkspaceFS` bounded capture 读取。排序遵循 definition 优先、强关系证据次之、lexical 最后，并受共享预算约束。

`AgentLoop._build_context()` 继续使用稳定的 GoalSpec-bound `ContextRequest`；在 Coding 模式下通过 `ContextIntelligenceService → RepoIntelligenceService.select_context()` 获取 bundle。authority、Permission、Approval、Sandbox、Workspace、Verification、Recovery、Router 和 Completion 都不读取 repo intelligence state，也不接受 freshness/confidence 作为授权依据。

## M8.0 metrics integration

`CodingTraceCollector.record_repository_metrics()` 将统一门面的有限数值快照映射到以下 canonical fields：

```text
repo_intelligence_queries
repo_intelligence_cache_hits
repo_intelligence_cache_misses
repo_index_full_refreshes
repo_index_incremental_refreshes
repo_files_parsed
repo_files_reparsed
semantic_queries
lexical_fallback_queries
stale_query_count
context_candidate_count
context_selected_file_count
context_selected_symbol_count
```

没有 facade snapshot 时这些字段保持 `null`；不会用 0 伪造观测。trace 只保留 bounded counters，不保留 repository source、query payload 或 hidden oracle 输出。

## Performance report

在本机对临时 250-file Python repository 连续运行 3 次，使用真实 `RepoIntelligenceService`、Tree-sitter、SQLite 和 `SafeWorkspaceFS`；表中是三次中位数，单位 ms：

| Operation | Median | 说明 |
| --- | ---: | --- |
| full index | 192.18 | 首次 bounded bootstrap，250 files |
| no-change refresh | 2.95 | 复用持久 index，不重新 walk/hash/parse 全仓库 |
| single-file refresh | 5.88 | 一个 UPDATE event 后的 parse + affected resolution |
| semantic query | 0.99 | indexed definition query |
| cached query | 0.08 | workspace + generation + request digest 命中 |

该测量是本地结构/性能证据，不是跨机器 benchmark，也不等价于大规模 monorepo 或 provider 端到端质量。运行时指标同时显示一次 full refresh、增量 refresh 和 cache hit/miss，便于后续 M8.0 compare。

## Coding Eval report

M8.0 pack 已验证为 12 个 scenario，manifest digest 为：

```text
9ee1bf6fd10d3afc1ded11c689b1ae2ac251a641836aad1d1615a458358976d5
```

本轮代码基线为 `a4dbaf77a87135036862dc83e81e649a924f0e0b`；M8.1 candidate 的提交 SHA 与远端 ref 在最终交付记录中核对。该派生报告不把自身生成后的 candidate SHA 写入内容，避免自引用漂移。provider/model、runtime、scenario-level success/model turns/tool calls/search/file reads/time-to-first-edit/time-to-green/repair cycles/changed files/unrelated diff 的同配置 baseline-vs-candidate compare 尚未运行。

真实 provider、凭据和对应 sandbox 未在本次环境中提供，所以 M8.1 对真实 Coding Capability 的改善结论是：**UNKNOWN**。Fake Model 的 deterministic PASS 或本地单测不能证明实际 provider 的 Coding Capability 提升；不得将本地架构/性能结果写成 capability gain。

评估运行能力已接到真实 `AgentLoop` adapter，并保留 M8.0 的 fixture/oracle/trace 边界。当前本机普通 PATH 下，evaluation fixture setup 被 Apple Git 的 Xcode license gate 阻塞，结果应记为 `INVALID_FIXTURE`；显式使用已安装 Command Line Tools git 的 harness 验证通过，但这仍是 Fake Model/runtime integration evidence，不是 real-provider evidence。

## Regression report

本轮 M8.1 相关 coding/evaluation/runtime 聚焦回归已执行并通过：

```text
155 passed, 1 skipped
evaluation: 112 passed
M7.9 observation-only: 75 passed
```

覆盖 M8 repo facade、M7 ContextIntelligence、M3 index/incremental/tree-sitter/real repository/call-reference/isolation/generation CAS/query authority、code tools、M8 evaluation metrics/report 和 runtime factory。

新增回归包含：

- binary rejection → metadata-only record；
- source capture race → bounded recapture and incremental refresh；
- shared database 的 workspace isolation/concurrent queries；
- restart reuse without full reindex；
- callers/callees/imports/importers/related-files typed graph queries；
- durable dirty-state、持久状态损坏、取消后重启恢复，以及 CREATE/UPDATE/DELETE/RENAME/MOVE/COPY/RESTORE/ROLLBACK mutation matrix；
- mutation fence、dependency mutation、exact symbol identity、关系排序、root/glob/language scope 与 fallback depth bounds；
- semantic backend unavailable 时的显式 bounded lexical fallback，以及非可恢复 generation failure 的 fail-closed 行为；
- canonical repository metrics emitted into M8.0 metrics。

另有 `compileall` 对相关 Python 包通过，且 `pyright-security.json` 为 `0 errors, 0 warnings, 0 informations`。完整 `python/tests/coding` 收集在本机得到 `1845 passed, 32 failed, 23 skipped`；32 个失败均在既有 TrustedGit/Workspace lifecycle 路径，根因是硬编码受 Apple Xcode license gate 阻塞的 `/usr/bin/git`，不是 Repo Intelligence 断言，不能记作全套 coding PASS。普通 PATH 的 M8 runtime fixture test 为 `INVALID_FIXTURE`（同一 Git 环境阻塞）；使用 `/Library/Developer/CommandLineTools/usr/bin` 优先的 harness 后，`test_coding_eval_runtime.py` 为 `2 passed`，完整 evaluation 为 `112 passed`。M7.9 control-capability evaluator（evaluation 下的 capability evaluation/matrix/real-path tests）只作 observation-only 回归，未被本轮 intelligence confidence 改写。

## Known limitations

- dynamic dispatch、复杂 type inference、宏和部分跨语言/外部依赖仍可能 unresolved；结果必须保留 unresolved/ambiguous，而非猜测。
- external dependency repositories 与 cross-repo graph 不在本轮范围。
- LSP 仍 optional/off by default；LSP 不可用不会阻塞 Tree-sitter/index/lexical 路径。
- bounded limits 触发时只能报告 PARTIAL/truncated；大型 monorepo 的完整覆盖需要显式后续 refresh，不能无界扩张本轮热路径。
- `code_search` 的 lexical fallback 为首个匹配行的 bounded preview，不能替代完整文本检索工具。
- 未取得真实 provider 同配置 baseline/candidate 数据，不能报告成功率或效率方向变化。

## Non-goals

本轮没有实现或重新打开：M8.2 Patch Transaction Engine、M8.3 Verification Planner、M8.4 Context Engine 2.0、M8.5 Parallel Coding、MCP、Hooks、checkpoint/rewind、IDE 或 desktop app。M7.9 仍保持 observation-only，不是本轮的 authority source。

## Definition of done evidence

- Architecture：M3/M7 已收敛到单一 workspace/generation-bound Repo Intelligence facade。
- Incremental：CREATE/UPDATE/DELETE/RENAME/MOVE/COPY/RESTORE/ROLLBACK contract 已定义；文件 mutation 使用 explicit dirty path；rename/delete/copy 有回归。
- Query/language：typed query facade 覆盖 Python、Go、Rust、TypeScript 及 bounded lexical/metadata fallback。
- Context/tools：AgentLoop、ContextIntelligence、`code_search`、`code_symbols` 均接入统一路径。
- Security：source reads 走 TaskWorkspace `SafeWorkspaceFS`；不同 workspace 使用 owner/project key 隔离；无 authority regression path。
- Performance：本地单文件增量显著低于初始 full index；不同 workspace 不共享 process-level global context lock。
- Evaluation：M8.0 adapter 可运行；真实 provider compare 因无 provider/凭据/可用 sandbox 为 UNKNOWN。

最终提交 SHA 与远端 `refs/heads/codex/m8-coding-evaluation` 的一致性在交付时单独核对并报告；本文不嵌入自身生成后的 SHA，避免派生报告产生自引用漂移。
