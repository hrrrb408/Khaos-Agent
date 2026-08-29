# Khaos 维护者架构手册

> 状态：active，随架构重构持续更新
>
> 本文回答一个问题：**一个不了解历史补丁的维护者，应该从哪里读、什么可以改、什么绝不能绕过，以及如何证明改动没有破坏边界。**

本文是维护地图，不替代安全事实或协议规范。发生冲突时按下面的优先级处理：

1. `AGENTS.md`、`KHAOS.md` 和 `docs/security_facts.yaml`；
2. 对应的 ADR、协议/威胁模型和生成的 inventory；
3. 当前源代码与回归测试；
4. 本文和其他历史性 gap analysis。

如果某项安全保证没有源代码、测试或当前 CI evidence 支撑，就只能称为“待证明”，不能写成已完成保证。

## 1. 先看什么

Khaos 是一个三层系统，但安全关键路径不是“Python 做完再交给 Go/Rust”这么简单。每层只拥有自己的职责，跨层调用必须经过显式协议或适配器。

| 层 | 入口 | 负责什么 | 不负责什么 |
| --- | --- | --- | --- |
| Python Agent | `python/khaos/agent/`、`python/khaos/runtime/` | turn、上下文、工具编排、任务领域逻辑、策略编译 | 不能把 Python 布尔值当作 OS 强制；不能绕过 authority 执行副作用 |
| Go Gateway | `go/cmd/gateway/`、`go/internal/` | HTTP/SSE/WebSocket、连接认证、限流、请求边界、Python RPC 适配 | 不拥有 Task/Approval/Verification 的业务真相；不自行执行 shell 或文件写入 |
| Rust TCB | `rust/khaos-core/` | native launcher/helper、受限执行、协议/receipt 校验、性能关键原语 | 不实现 Agent 业务；不读取模型上下文；不替 Python 决定产品流程 |

推荐的阅读顺序：

```text
KHAOS.md / AGENTS.md
  -> docs/security_facts.yaml
  -> 本文第 2、3 节
  -> 对应模块的 ADR 和测试
  -> 具体实现
```

不要从 `python/khaos/db/database.py` 或 `python/khaos/grpc_server.py` 的第一行开始“顺藤摸瓜”。它们是当前的过渡性组合体，不是新的模块设计模板。

## 2. 当前真实调用链

一次 Coding 请求的概念路径如下。箭头表示责任转移，不表示每一步都在同一个进程内。

```text
客户端/TUI
    -> Go Gateway（认证、大小/版本/所有权边界）
    -> Python RPC service（把 transport context 绑定到 principal/project/session）
    -> runtime/factory.py（composition root，只负责装配）
    -> AgentLoop / TurnCoordinator（turn 事件和终态）
    -> ToolScheduler（唯一工具调度入口）
       -> Permission/Approval（策略决定和一次性 capability）
       -> Tool handler（只表达领域意图）
       -> ExecutionService / SafeWorkspaceFS / TrustedGit（效果边界）
       -> platform backend / Rust launcher / Docker（OS 最终强制）
    -> durable DB/audit/ledger
    -> event adapter（SSE、WebSocket、TUI）
```

以下顺序是强约束：先建立身份和 scope，再做 admission/approval，再启动不可逆效果，最后提交可审计结果。任何“先跑起来，失败后再检查权限”的新路径都应视为设计缺陷。

## 3. 权威归属表

修改前先回答“谁是这个状态的唯一 writer”。如果答案是两个模块，先做收敛，不要继续加字段。

| 领域状态/效果 | 当前入口 | 权威 writer | 观察者/适配器 | 备注 |
| --- | --- | --- | --- | --- |
| Turn/event/terminal | `python/khaos/agent/events.py`、`agent/core.py` | `TurnCoordinator` + `Database` 事件事务 | Gateway/TUI/message adapter | `Message` 是兼容投影，不应成为新终态来源 |
| Tool invocation | `python/khaos/tools/registry.py`、`tools/scheduler.py` | `ToolScheduler`（调度）+ `tools/result_finalizer.py`（terminal/audit/result delivery）+ `tools/result_store.py`（runtime result replay）+ `db/repositories/tool_operations.py`（durable operation SQL） | tool handler、event renderer | handler 不接收 `approved=True` 作为权限证明；跨重启 replay 仍由 injected `ToolOperationRepository` 的 durable row 决定 |
| Effective policy | `python/khaos/security/effective_policy.py` | 启动期 immutable policy compiler | runtime、authorityd、execution selector | 原始 YAML 不是运行时权限对象 |
| Ordinary approval | `python/khaos/agent/approval.py`、permissions/、`tools/approval_callback.py`、`tools/authorization.py` | `ToolAuthorization` 拥有 policy decision hardening/remember projection；broker/durable consume path 拥有 one-shot capability；`ApprovalCallbackRunner` 只拥有 adapter 生命周期 | Gateway confirm、TUI dialog | one-shot、principal/context/args/expiry 绑定；回调线程未终止时不得报告 CLOSED |
| Plan/change approval | `coding/planning/approval/` | `approval/schema.py`（schema/migration）+ approval runtime/store + signed receipt | plan UI、verification | 不能与普通 tool approval 静默合并；schema owner 不执行业务状态转换 |
| Process effect | `coding/execution/service.py`、`supervisor.py` | `ExecutionService` + platform backend | terminal/test/LSP/browser | restricted backend 不可用时 fail closed，不回退 host |
| Workspace file effect | `coding/workspace/`、file tools | `SafeWorkspaceFS` / mutation authority | patch/ChangeSet/UI | 新代码不能直接用 `Path.write_*` 替代安全 API |
| Git effect | `coding/workspace/trusted_git.py`、`tools/git_tools.py` | `TrustedGitRunner` + authority receipt | diff/status renderers | read-only Git 也要经过受控执行上下文 |
| Verification proof | `coding/planning/verification_*` | trusted verification authority/ledger | plan gate、audit/export | 被测代码不能写 canonical input/result |
| Capability evaluation/metrics | `python/khaos/evaluation/` | `CapabilityEvidenceService`（coherent read snapshot）+ `CapabilityEvaluator`（纯计算）+ `CapabilityEvaluationRepository`（append-only ledger） | report/benchmark/export | 只读观察；不能写 TaskStatus、Gate、approval、verification、recovery、routing 或 prompt authority |
| Task/workspace identity | `coding/task_manager.py`、`coding/workspace/` | Task/Workspace stores | AgentLoop、TUI、RPC | 客户端只提交引用，不能自报 owner 或 generation |
| Durable audit | `audit/`、`db/`、authorityd/WORM adapters | 对应写入事务和 append-only ledger | export/query | Python 内存日志不是独立审计权威；authorityd canonical wire encoding 由 `security/protocol_boundary.py` 统一拥有 |
| Durable memory | `memory/`、`rpc/memory_service.py` | `MemoryStore`（领域门面）+ `MemoryRepository`（持久化端口）+ `MemoryOwner`（principal/project/namespace）+ `MemoryVisibility`（durable/session 视图） | `MemoryManager`、RPC/CLI/TUI | SQL、FTS、TTL、冲突、提取和检索策略不能重新堆回 store；durable list/search/touch/delete 默认排除 session-private；session 访问必须携带同一 session ID；所有 runtime 写入必须携带 owner 和审计 logger |
| Channel configuration/health | `channels/registry.py` | `ChannelRegistry`（唯一 writer；配置/健康锁） | channel tools、TUI、webhook service | `get`/`list_all` 只返回 immutable snapshot；配置必须经 `replace_config`/enable/disable，不能修改返回对象 |
| Function/model routing | `routing/table.py`、`routing/router.py` | `RoutingTable` + `ModelRouter.set_rule` | provider manager、AgentLoop、MoA | rules/fallback chain are immutable snapshots; provider availability is not routing-state mutation |
| Permission decision | `permissions/evaluator.py`、`permissions/engine.py` | `PermissionEvaluator`（纯策略）+ `PermissionEngine`（DB epoch/rule owner） | scheduler、approval UI、audit adapter | evaluator never opens DB or writes audit; engine publishes a captured rule snapshot and owns durable mutations |
| Gateway RPC connection | `go/internal/platform/rpc_transport.go`、`python_client.go` | `RPCTransport` + `RPCConnection`（拨号、deadline、取消、关闭） | `PythonClient`（认证 envelope、协议、service calls） | transport 不解释 JSON；新增平台 transport 只能实现接口，不能复制 client 生命周期 |
| Native receipt verification | `rust/khaos-core/src/authority_receipt.rs`、native launchers | `ReceiptVerifier`（绑定 operation/resource、验证与结果证明） | exec launcher、Python authority adapter | launcher 只能消费已绑定 receipt；不把 receipt 字段重新解释为业务状态 |

## 4. 目前的过渡性热点

这些文件不是“禁止修改”，而是明确的拆分目标。改动热点时必须先增加 characterization/contract test，再移动责任；不能在原文件末尾继续堆新分支。

| 文件 | 当前集中职责 | 拆分目标 |
| --- | --- | --- |
| `python/khaos/db/database.py` | 迁移、事务 owner、turn/event 与兼容 facade；session/message、scheduler/task、tool operation 和 memory 只做 lease/transaction 编排 | `python/khaos/db/connection.py` 拥有物理连接生命周期；各 domain repository 分别拥有 SQL 与 row conversion；Agent turn 通过 ADR-053 的 `TurnRepository` 端口隔离，后续继续按领域拆 repository 并保留一个薄 facade |
| `python/khaos/db/repositories/configuration.py` | user_config 与 principal_modes 的 JSON/owner-scoped SQL | `ConfigurationRepository` 唯一拥有配置与模式 SQL；`Database` 只保留公共 facade 和事务/连接端口 |
| `python/khaos/db/repositories/permissions.py` | permissions 与 authorization_contexts 的规则/epoch SQL | `PermissionRepository` 唯一拥有权限状态写入和 authorization lock；`PermissionEngine` 只消费 facade/端口 |
| `python/khaos/db/repositories/audit.py` | audit_log 写入、owner 查询、hash-chain replay | `AuditRepository` 唯一拥有 audit SQL 与 canonical hash recomputation；`AuditLogger` 不直接触碰连接 |
| `python/khaos/db/repositories/scheduler.py` | scheduled_tasks 的 owner scope、lease/CAS、recovery 与 scheduler-operation journal SQL | `SchedulerRepository` 唯一拥有 scheduler/task SQL；`Database` 只保留兼容 facade，`scheduler/repository.py` 只做 project scope adapter |
| `python/khaos/db/repositories/tool_operations.py` | durable tool_operations claim、terminal、effect identity、orphan quarantine 与 bounded prune SQL | `ToolOperationRepository` 唯一拥有 durable operation SQL；`Database.tool_operation_repository` 是只读注入边界，runtime `ToolOperationStore` 只拥有 in-process waiters/result projection；Database 同名 SQL facade 已删除 |
| `python/khaos/tools/scheduler.py` | admission 后的 approval、批次并发和结果事件编排 | `ToolAdmission`、`ToolResultFinalizer`（terminal phase/audit/result delivery）、`ToolResultStore`（runtime replay cache）、`ToolOperationStore`（claim/wait/terminal idempotency）、`ApprovalCallbackRunner`（adapter 生命周期）、`ToolAuthorization`（decision/remember/binding contract）、`ToolExecutionCoordinator`（authority-bound dispatch） |
| `python/khaos/tools/result_finalizer.py` | dispatched tool 的 terminal phase、best-effort audit、durable operation finish 和 idempotent result publish | `ToolResultFinalizer`；不做 admission、permission decision、handler dispatch 或 budget ownership |
| `python/khaos/tools/authorization.py` | permission decision hardening、remember rule projection、approval binding/request projection | `ToolAuthorization`、`build_approval_binding`、`build_permission_request`；不注册/消费 broker，不执行工具效果 |
| `python/khaos/tools/operation_store.py` | operation scope、durable claim、in-process waiter、effect-id update 和 terminal replay | `ToolOperationStore`；只消费 result cache 与已授权 DB operation ports，不做 admission/permission/handler dispatch |
| `python/khaos/tools/execution_coordinator.py` | 单步 authority context、handler timeout、broker dispatch 和 effect outcome normalization | `ToolExecutionCoordinator`；不做 permission、claim、budget、audit 或批次事件 |
| `python/khaos/tools/admission.py` | 工具调用规范化、raw phase、注册表解析和参数校验 | `ToolAdmission`；只返回 `AdmittedToolCall`/`RejectedToolCall`，不做权限、authority 或执行 |
| `python/khaos/tools/scheduler_models.py`、`tools/budget.py` | 调度结果协议、权限请求事件和原子预算 reservation/commit | 已完成首个 seam；后续只允许由调度器编排，不在 handler 中复制预算或结果状态机 |
| `python/khaos/grpc_server.py` | JSON-lines UDS transport、peer/auth middleware、dispatch、instance lifecycle、startup/shutdown | `rpc/agent_service.py` owns AgentService; `rpc/task_service.py` owns TaskService; `rpc/models.py` owns request value objects; `rpc/composition.py` owns router/subagent composition; `rpc/protocol.py` owns Python protocol constants and authenticator. Transport exports no application services or request models and only dispatches already-authenticated context |
| `python/khaos/coding/planning/approval/store.py` | approval CAS、receipt、lease、epoch、poison scope 等 mutation owner | schema/migration、approval ledger、receipt verifier；approval reads 由 `approval/read_model.py`、execution/proof reads 由 `approval/execution_read_model.py` 拥有，execution writers 不再经过 store |
| `python/khaos/coding/planning/approval/read_model.py` | approval request/decision/audit/authorization read SQL 与 row conversion | 只读连接查询；不打开/关闭连接、不 commit、不写入；生产 caller 必须显式注入 `PlanApprovalReadModel`，store 不保留读取委托 |
| `python/khaos/coding/planning/approval/execution_read_model.py` | execution run/journal/attestation read SQL、row conversion 和 proof digest 校验 | `PlanExecutionReadModel` 唯一拥有执行读取与 verified authority 前置检查；不拥有事务写入或 recovery transition，生产 caller 必须显式注入 |
| `python/khaos/coding/planning/approval/execution_writer.py` | execution run 状态转换、attestation、terminal seal 和 crash recovery 写入 | `PlanExecutionWriter` 唯一拥有执行写事务；不拥有 connection 生命周期、approval authority 或 edit-journal 的最终 facade 生命周期 |
| `python/khaos/coding/planning/approval/execution_journal_writer.py` | edit journal phase CAS、rollback identity 和 directory-sync proof 写入 | `PlanExecutionJournalWriter` 唯一拥有 journal 写事务；不拥有 connection 生命周期、approval/lease state 或 filesystem effect |
| `python/khaos/coding/planning/approval/schema.py` | plan approval、receipt、authorization、lease、execution journal 的 DDL 与旧库 column/index upgrade | schema/migration 唯一 owner；`PlanApprovalStore` 只消费 `APPROVAL_SCHEMA`/`upgrade_schema` 并拥有 CAS 事务 |
| `python/khaos/coding/workspace/boundary.py` | dirfd 文件读写、copy/move、snapshot/recovery 和 protected metadata 检查 | `workspace/policy.py` 统一 protected names/limits；`SafeWorkspaceFS` 只拥有 handle-based effect，`TrustedGitRunner` 只拥有 Git effect |
| `python/khaos/coding/workspace/artifacts.py` | ChangeSet artifact 的 bounded no-follow read/write/copy、digest/length 校验和 exclusive publish | artifact 文件效果唯一 owner；不决定 workspace ownership、quota registration 或 lifecycle transition |
| `python/khaos/coding/workspace/errors.py` | workspace-domain error type | `WorkspaceError` 唯一 owner；manager/application/artifact 共享同一错误边界 |
| `python/khaos/coding/workspace/git_process.py` | trusted Git subprocess spawn/adoption, bounded pipes, termination and quarantine | `TrustedGitProcessOwner` 唯一进程生命周期 owner；`TrustedGitRunner` 只消费它并拥有 Git effect/authority 语义 |
| `python/khaos/scheduler/engine.py` | lifecycle facade：任务创建/控制、start/stop、状态机和 owner composition | `scheduler/execution.py` 唯一拥有 executor admission、tick、lease、terminal publish；`scheduler/recovery.py` 唯一拥有 persistence reconcile、journal replay、lease recovery、drift quarantine 和 task loading；`scheduler/repository.py` 只拥有 project-scoped persistence port |
| `python/khaos/scheduler/repository.py` | scheduled-task CRUD、identity/CAS、lease、recovery 和 operation-journal 的 scheduler persistence port | `ScheduledTaskRepository` 绑定 project scope；不拥有 SQLite connection/schema 或 engine lifecycle |
| `python/khaos/scheduler/due_selector.py` | enabled/PENDING/next-run/pending-marker/in-flight 的纯候选筛选 | `DueTaskSelector` 唯一拥有 due selection；不修改任务、不访问 DB、不启动 executor |
| `python/khaos/memory/store.py` | 记忆领域 facade；历史上同时包含 SQL、owner mapping、TTL、冲突、FTS、访问频率和正则提取 | `memory/models.py`（值对象）、`ownership.py`（owner/namespace/visibility）、`repository.py`（SQLite adapter）、`conflict.py`、`decay.py`、`extraction.py`、`retrieval.py`；store 只编排这些端口并发出审计；所有读写都消费显式 `MemoryVisibility` |
| `python/khaos/memory/manager.py` | 记忆读取、三层注入、token budget、跨模式 intent 和主动提取编排 | `MemoryRetriever` 拥有 L0/L1/L2 分类与排序；`MemoryManager` 只负责 orchestration/格式化/预算，不读 SQLite、不实现 regex |
| `python/khaos/memory/core/`、`ledger/`、`providers/` | Memory V2 的 Trust Kernel、Broker、Canonical Event Ledger 和 Provider SPI | `MemoryBroker` 是唯一模型可见入口；`MemoryEvent` 只追加不覆盖；`NativeMemoryProvider` 只持有 SQLite 派生表/FTS，不能提升 authority、扩大 scope 或绕过 policy；`maintenance/` 负责显式 ledger replay/index rebuild/consistency check |
| `python/khaos/runtime/factory.py` | 依赖装配和兼容参数转换 | 保留为唯一 composition root；业务逻辑不得回流到 factory |
| `python/khaos/security/authority_transport.py`、`local_trust.py` | `community`/`native-production` profile 解析、平台矩阵、client transport construction 与 Community Local Trust Root | 唯一 transport/profile owner；Community authority state 固定在 owner-only `~/.khaos/authorityd/`；未知 profile、项目路径、symlink、非私有 socket fail closed；不按业务模块自行判断 `sys.platform` |
| `python/khaos/security/authorityd.py`、`authorityd_protocol.py` | authority daemon lifecycle、签名 receipt、审计事件、socket framing；历史上各自保留 canonical/digest 包装器 | `security/protocol_boundary.py` 统一 canonical JSON/digest；authorityd 只拥有 authority 状态机和被选中的 transport 适配 |
| `go/internal/platform/python_client.go` | Unix 拨号、deadline、context 取消、JSON framing、RPC auth 与 service calls | `rpc_transport.go` 拥有 connection lifecycle；`rpc_contract.go` 拥有版本/features；client 只拥有 auth/envelope 与 service adapter |
| `rust/khaos-core/src/bin/khaos-exec-launcher.rs`、`authority_receipt.rs` | 参数解析、FD 校验、receipt 验证、rlimit、session 与 exec | `authority_receipt.rs` 的 `ReceiptVerifier` 拥有 receipt binding/verification；launcher 只拥有 native launch sequencing |

拆分完成的判据不是“文件变小”，而是：每个状态只有一个 writer；依赖方向可画出来；单元测试不需要启动完整 runtime；旧 facade 可以删除而不是永久并行。

## 5. 依赖方向和禁止旁路

### 5.1 允许的方向

```text
transport adapter -> application service -> domain coordinator
domain coordinator -> policy/approval -> effect port
effect port -> platform backend / trusted helper
repository -> db connection
event/audit adapter <- domain events
```

`runtime/factory.py` 是装配根，可以依赖所有实现；其他模块不能反向 import factory 来取得“全局对象”。

### 5.2 新代码禁止的旁路

- 在 Agent、tool handler、TUI 中直接 `subprocess.run`/`Popen` 执行受控效果；统一走 `ExecutionService` 或明确的安全 helper owner。
- 在 workspace 工具中直接 `Path.write_text`、`Path.write_bytes` 或未经 authority 的 `open(..., "w")`；统一走 `SafeWorkspaceFS`/mutation authority。现有迁移中的兼容路径要标注 owner 和删除条件。
- 用原始 YAML、`access_mode`、字符串 mode 或工具名重新推导已编译的 `PermissionProfile`。
- 用 `approved`、`remember`、`is_admin` 等布尔值替代一次性、绑定 scope 的 capability。
- 在非数据库模块新建任意 SQLite 连接。专用的 intelligence/planning/verification store 属于现有 allowlist；新连接必须先说明生命周期、writer、锁和迁移归属。
- 把兼容逻辑散落到业务分支。旧协议、旧字段和旧表只能由显式 adapter/migration 转换，并且要有删除版本。
- 把 mock、skip、queued 或本机无法运行的测试写成平台安全已经闭环。报告必须区分 `verified`、`CI-only`、`skipped/unrun`、`blocked` 和 `unknown`。

这些规则是维护规则，不是建议。违反它们的 PR 需要在描述中给出边界证明和删除计划。

## 6. 必须保持的状态机

### 6.1 Turn

```text
NEW -> RUNNING -> (WAITING_APPROVAL | EXECUTING_TOOL)*
RUNNING/WAITING_APPROVAL/EXECUTING_TOOL -> COMPLETED | FAILED | INTERRUPTED
```

- 一个 turn 只能有一个 durable terminal event。
- `tool.call` 和 `tool.result` 必须配对；完成前不能有未解决的 tool call。
- 取消、进程重启和审批超时必须产生可解释的终态，不能靠消息内容猜测成功。
- terminal event 落盘成功前不能向外部 adapter 发送 `done`/`success`。

### 6.2 Tool effect

```text
DECLARED -> ADMITTED -> (APPROVAL_PENDING -> APPROVED)?
         -> PREPARED -> CLAIMED -> SUCCEEDED | FAILED | UNKNOWN
```

`PREPARED` 仍可被 grant/epoch/workspace-generation 撤销；`CLAIMED` 已跨过效果边界，之后必须完成终态记账。超时或清理无法证明时使用 `UNKNOWN`/quarantine，不能伪造成功或 CLOSED。

### 6.3 Workspace mutation

```text
PLANNED -> SNAPSHOTTED -> APPLIED -> VERIFIED
                   \-> RECOVERY_REQUIRED
```

目标路径、generation、base digest 和变更集身份必须来自 server-owned workspace state。失败进入 recovery，不回退到普通 pathlib 写入。

### 6.4 Verification

```text
REQUESTED -> SNAPSHOT_BOUND -> RUNNING -> PROOF_RECORDED
                                  \-> FAILED | UNKNOWN
```

验证输入和结果账本必须由受信任 writer 管理；旧 boot、不同 task/workspace/profile 的 proof 不能复用。

## 7. 重构工作法

每个重构切片遵循同一协议：

1. **先画边界**：写出 owner、输入/输出类型、错误分类和取消/关闭语义。
2. **先固化行为**：针对现有实现增加 characterization test；安全模块补负向测试，不能只测 happy path。
3. **引入 seam**：用 protocol/dataclass/adapter 把新组件接到旧 facade，保持一个写者。
4. **迁移调用者**：按调用图逐个切换；每次提交只改变一个 bounded context。
5. **删除旧路径**：旧实现保留一个迁移周期后删除；不能长期维护两套 authority。
6. **更新证据**：同步 ADR、测试矩阵、inventory 和运行手册；明确本机、CI-only、未运行和未知结果。

禁止以下“整理”方式：全仓库自动 `ruff --fix`、一次性移动数十个模块、把异常改成裸 `except`、把失败改成静默 fallback、为了让 CI 变绿而放宽安全断言、或在没有测试的情况下重写数据库访问。

## 8. 分阶段路线

### Phase 1：可读性和可见性（当前）

- 维护者架构手册和权威归属表。
- 生产代码 lint 清零，但不改变安全语义。
- 为四个热点建立公共接口/characterization test 清单。
- 将测试结果按本机/CI-only/skip/unknown 分类。

### Phase 2：数据库与 RPC 边界

- 从 `Database` 提取连接/迁移/repository，先迁移只读查询，再迁移写事务。连接生命周期已落在
  `python/khaos/db/connection.py`；session/message SQL 已落在
  `python/khaos/db/repositories/sessions.py`，facade 只提供 owner scope、reader lease
  和 transaction。
- 连接生命周期第一 seam 已落在 `python/khaos/db/connection.py`；`Database` 的 underscored
  connection views 只为迁移期兼容，后续 repository 迁移完成后删除这些 views。
- Configuration 的第一段迁移已完成：`ConfigurationRepository` 拥有
  `user_config` 与 `principal_modes` 的 SQL、JSON 解码和 project-scoped lookup；
  `Database` 只编排 facade 调用。后续按同一 port 继续迁移 permission、audit、task
  和 scheduler journal，不能把新的 SQL 放回 `Database`。
- Permission 与 audit 的 SQL owner 已迁移到 `db/repositories/permissions.py` 和
  `db/repositories/audit.py`；`Database` 仅保留公共 facade，hash-chain canonical
  实现也只有一个来源。不能再新增 `Database` 内联写事务。
- Scheduler/task 与 durable tool-operation 的 SQL owner 已迁移到
  `db/repositories/scheduler.py` 和 `db/repositories/tool_operations.py`；
  `Database` 的同名方法现在只负责兼容转发。scheduler engine 的 project-scoped
  adapter 与 tool runtime operation store 不得重新复制 SQL 或 connection lifecycle。
- 从 `grpc_server.py` 提取 protocol/auth/service；MemoryService、SessionService、AuditService 已完成首批 seam，协议边界已落在 `python/khaos/rpc/protocol.py`。本轮继续完成 AgentService、TaskService、请求模型和 composition root 的迁移：`grpc_server.py` 只保留 transport、peer/auth dispatch、instance lifecycle 和 startup/shutdown；它不再导出 application service 或 request model。新代码必须直接依赖其 named owner，不增加第二套 server authority。生产可达性根同步为 `khaos.rpc.agent_service:AgentService`，并由 generated inventory 绑定新模块指纹。
- authorityd 的 receipt、审计和 socket framing 已统一消费 `security/protocol_boundary.py` 的 canonical owner；删除 `_canonical`/`_digest` 私有包装器，后续不允许在 authority daemon 内重新实现摘要或序列化。
- Memory 的第一阶段 seam 已完成：`MemoryStore` 只接受 `MemoryRepository`，`MemoryOwner` 统一 principal/project/namespace 规则，`SqliteMemoryRepository` 统一 SQL 适配；冲突、TTL、提取和 L0/L1/L2 检索策略均为可独立测试的纯模块。RPC `MemoryService` 通过 ADR-051 的 context-bound audit sink 绑定请求身份，root logger 仍是唯一 durable writer。
- Memory 的第二阶段 visibility seam 已完成：`MemoryVisibility.durable()` 是 private/shared 且空 session 的默认视图；session-private 的 list/search/touch/delete-by-id 必须使用 `for_session(session_id)`，SQL repository 在同一 predicate 中绑定 principal、project、namespace 和 session。`MemoryManager` 明确只注入 durable view，避免把 session 行混入通用 prompt。
- Memory V2 的 canonical path 已完成：运行时消息先写入 `memory_events`，Broker 再按 Scope、Authority、Evidence、Applicability、Temporal 和 UsagePolicy 决定是否派生为 `memory_nodes`；模型上下文只能消费 Broker 返回的 `EvidenceResolution`，不能直接消费 Provider 或旧 `MemoryStore`。旧表仍是 RPC 兼容投影，不是 V2 的事实源。
- Memory V2 的长期维护边界已完成：`MemoryMaintenanceService` 可从 append-only Ledger 重放候选、重建 FTS，并验证 `memory_nodes`/FTS 一致性；soft/hard/compliance forget 分别对应撤销、清理派生内容/图/证据、内容无关 tombstone。检索次数只作为 telemetry，不得改变 authority 或 confidence。
- Memory V2 的 PR #216 (`ec02d5386f32cf3b06b3828149b6b587c4c9fa7a`) 是本轮冻结基线；本轮只完成 deployment-profile / Closure Z 语义。Community Local Profile 复用既有 Khaos Trust Kernel，不需要 Apple Team ID；macOS Signed Distribution Profile 是显式可选能力，未启用时不得把 `OPTIONAL_PROFILE_NOT_ENABLED` 误报为 Memory FAIL。
- Community Local Trust Root 的维护链是：local user/runtime identity -> owner-only `~/.khaos/authorityd/` -> protected local capability/AF_UNIX peer UID -> Runtime Authority -> Ed25519 key -> policy/catalog digest -> approval/verification/audit。相同 UID 的进程冒充风险是已记录的 profile residual，不是隐藏的多用户安全承诺。
- TUI 的 `/memory list|show|search|forget|rebuild|verify` 已绑定 `MemoryManager` 的 Broker/runtime context；旧 `memory_store` 只保留兼容测试与旧调用路径，不能成为默认生产上下文入口。
- Turn 的第一阶段 seam 已完成：`TurnCoordinator` 只接受 `TurnRepository`，`DatabaseTurnRepository` 是当前 SQLite 组合适配器；恢复、创建和 CAS 追加由同一 repository owner 提供，详见 ADR-053。后续把 turn SQL 从 `Database` 移出时保持该端口不变。
- Go RPC 的 connection seam 已完成：`PythonClient` 不再拥有 Unix 拨号、deadline 或 context watcher；`RPCTransport`/`RPCConnection` 统一连接建立与关闭语义，详见 ADR-057。协议版本/features 仍只由 `rpc_contract.go` 拥有，client 不得新增第二套 contract。
- Rust native receipt seam 已完成：`ReceiptBinding`/`ReceiptVerifier` 统一 operation/resource 绑定、FD 读取和签名验证结果；launcher 只编排验证通过后的 session、limits 和 exec，不重新解析 receipt 字段。

### Phase 3：工具和执行边界

- `ToolScheduler` 的调用 admission 已收敛到 `python/khaos/tools/admission.py`；结果/事件值对象已收敛到 `python/khaos/tools/scheduler_models.py`，结果归一化与 durable JSON 编解码已收敛到 `python/khaos/tools/result_codec.py`，runtime 幂等结果 replay cache 已收敛到 `python/khaos/tools/result_store.py`，terminal phase/audit/result delivery 已收敛到 `python/khaos/tools/result_finalizer.py`，原子预算已收敛到 `python/khaos/tools/budget.py`；`tools.scheduler` 仅保留一个迁移周期的兼容导出。
- approval callback 的 schema、deadline、容量和 worker 关闭语义已收敛到 `python/khaos/tools/approval_callback.py`；scheduler 不再直接拥有 callback executor。
- `ToolAuthorization` 已收敛 permission decision hardening、interactive remember projection，以及 `ApprovalBinding`/`PermissionRequest` 的 digest/字段投影；scheduler 只保留 broker 注册、确认事件和 capability consume 编排，后续由 `ToolExecutionCoordinator` 接管效果准备与 dispatch。
- `ToolOperationStore` 已收敛 durable operation claim/wait/finalize 与 runtime waiter map；它通过显式 `ToolOperationRepository` 注入消费 durable owner，缺失 owner 时在效果边界前 fail closed。`ToolScheduler` 不再保留幂等/terminal SQL 兼容委托。
- `ToolExecutionCoordinator` 已收敛单步 authority context 注入、broker invoke/timeout 和 effect outcome normalization；scheduler 不再直接调用 invocation broker，后续继续迁移 terminalization/result projection。
- ChangeSet artifact 的 descriptor/no-follow IO、digest 校验和 exclusive publish 已收敛到 `workspace/artifacts.py`；`WorkspaceManager` 只保留 lifecycle/quota 编排，workspace 错误类型由 `workspace/errors.py` 统一拥有。
- Trusted Git 的 process owner 已从 Git command/effect runner 独立到 `workspace/git_process.py`；Git runner 不再定义进程状态机，Windows/native 失败可分别归类为 argv/authority 或 process terminal evidence。
- Plan approval 的 DDL 与 post-schema migration 已收敛到 `coding/planning/approval/schema.py`；`PlanApprovalStore` 的 `APPROVAL_SCHEMA` 仅为兼容导出，后续删除。
- Plan approval request/decision/audit/authorization 的只读 SQL 与 row conversion 已收敛到 `coding/planning/approval/read_model.py`；execution run/journal/attestation 读取与 digest 校验已收敛到 `coding/planning/approval/execution_read_model.py`。生产 caller 现在显式依赖对应 owner，`PlanApprovalStore` 的读取兼容方法与 row-converter 已删除。
- Plan execution run/attestation/terminal recovery 写事务已收敛到 `coding/planning/approval/execution_writer.py`，edit journal/rollback proof 写事务已收敛到 `coding/planning/approval/execution_journal_writer.py`；生产 mutation/verification/recovery caller 已显式注入 writer，`PlanApprovalStore` 的 execution/journal 写兼容委托与动态 audit hook 已删除。
- `ToolScheduler` 已拆出 admission、execution、terminal/result delivery 四段；每段只能消费上述类型，不能重新定义平行的 `ToolResult`、预算或 effect 状态。durable operation SQL 已完成最终 port 迁移；后续只处理 capability consume 与跨模块 port，不再把终态逻辑塞回 scheduler。
- 将 file/Git/process 入口收敛为可注入 port，并为每个 port 提供 fail-closed contract tests。

### Phase 4：计划、验证和调度

- 拆分 approval store 与 CronEngine，显式区分 ledger、read model、recovery worker；纯 schedule
  计算已落在 `python/khaos/scheduler/calculator.py`，scheduler persistence port 与 due
  selector 已落位。CronEngine 现在只保留 lifecycle facade；execution owner 与 recovery
  owner 分别位于 `python/khaos/scheduler/execution.py` 和
  `python/khaos/scheduler/recovery.py`，不得把执行/恢复实现重新堆回 facade。
- 删除已经没有调用者的兼容分支，更新 schema/ADR 和迁移文档。

### Phase 4.5：Evidence-based capability evaluation

- M7.9 的 capability evaluation 只消费 owner-scoped immutable evidence snapshot；policy、
  request、metric vector、benchmark manifest 和报告均为 typed/canonical value objects。
- `CapabilityEvaluationRepository` 是唯一 evaluation ledger writer；评估结果不能作为
  Completion Gate、Verification authority、Recovery、Permission、Approval、Routing 或
  Memory ranking 的输入。关键证据缺失或安全完整性失败必须保留显式状态。
- 每次 schema/metric 变更都必须更新 ADR-082、versioned migration、确定性/对抗性测试和
  generated reachability/inventory；本机不能提供的 hosted/kernel/remote CI 证据只能标为
  blocked、skipped、unknown 或 not run。

### Phase 5：持续维护

- 新模块必须有 owner、状态机、错误分类、关闭语义、测试入口和删除/迁移说明。
- 每次平台 CI 失败先归类为代码、环境、凭据、平台缺失或 flaky，再决定修代码还是标注证据边界。

## 9. 验证入口

在本仓库根目录运行：

```bash
# Python：完整收集不执行外部平台测试
.venv/bin/python -m pytest --collect-only -q

# Python：只检查生产代码；测试代码有独立迁移计划
ruff check python/khaos

# Go：UDS/loopback 测试需要真实权限环境
cd go && GOCACHE=/tmp/khaos-go-build go test ./...

# Rust：不拉取新依赖
cd rust/khaos-core && cargo test --locked --no-default-features
```

当前基线（2026-08-21，分支 `codex/project-hardening-phase1`）：

- Python 收集 `4629` 个测试；
- Rust `cargo test --locked --no-default-features` 通过；
- Go 在真实权限环境通过，受限 sandbox 下的 Unix socket 测试会因 `bind: operation not permitted` 失败；
- 生产 Python lint 原有 6 项，属于导入整理、未使用导入和一个有明确隔离理由的 `preexec_fn` 告警；
- 以上不等同于所有平台 E2E 已通过。Docker、Linux kernel、Windows native、macOS launchd/XPC 仍按各自 CI gate 认定。

## 10. PR 自检清单

提交前必须能回答：

- 这次改动属于哪个 bounded context？谁是唯一 writer？
- 新代码是否引入了直接 subprocess、普通 pathlib 写、任意 SQLite connection 或隐式 fallback？
- 取消、超时、重启、重复请求和部分失败会落到哪个状态？
- 错误是可恢复、需重试、unknown 还是 fail closed？调用者能否区分？
- 新旧协议/表/接口的 adapter 何时删除？
- 测试是本机 verified、CI-only、skipped、blocked 还是 unknown？
- 相关 ADR、security facts、inventory 和运维文档是否仍然准确？

如果这些问题无法在 PR 描述和测试中回答，说明边界还没有整理完成，不应继续扩大改动范围。

## 11. 术语约定

- **authority**：拥有不可逆效果最终批准/提交权的组件，不是普通 Python 对象。
- **capability**：带 scope、主体、上下文、参数摘要、expiry 和 nonce 的一次性效果凭证，不是布尔 approval。
- **adapter**：只做版本/协议/数据形状转换，不拥有新的业务状态或安全权威。
- **proof/evidence**：可复核的输入、结果和账本记录；日志或测试输出本身不自动成为 proof。
- **unknown/quarantine**：系统无法证明成功或清理完成时的安全终态；它不是失败吞掉，也不是成功别名。
