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
| Tool invocation | `python/khaos/tools/registry.py`、`tools/scheduler.py` | `ToolScheduler` | tool handler、event renderer | handler 不接收 `approved=True` 作为权限证明 |
| Effective policy | `python/khaos/security/effective_policy.py` | 启动期 immutable policy compiler | runtime、authorityd、execution selector | 原始 YAML 不是运行时权限对象 |
| Ordinary approval | `python/khaos/agent/approval.py`、permissions/ | broker/ durable consume path | Gateway confirm、TUI dialog | one-shot、principal/context/args/expiry 绑定 |
| Plan/change approval | `coding/planning/approval/` | approval runtime/store + signed receipt | plan UI、verification | 不能与普通 tool approval 静默合并 |
| Process effect | `coding/execution/service.py`、`supervisor.py` | `ExecutionService` + platform backend | terminal/test/LSP/browser | restricted backend 不可用时 fail closed，不回退 host |
| Workspace file effect | `coding/workspace/`、file tools | `SafeWorkspaceFS` / mutation authority | patch/ChangeSet/UI | 新代码不能直接用 `Path.write_*` 替代安全 API |
| Git effect | `coding/workspace/trusted_git.py`、`tools/git_tools.py` | `TrustedGitRunner` + authority receipt | diff/status renderers | read-only Git 也要经过受控执行上下文 |
| Verification proof | `coding/planning/verification_*` | trusted verification authority/ledger | plan gate、audit/export | 被测代码不能写 canonical input/result |
| Task/workspace identity | `coding/task_manager.py`、`coding/workspace/` | Task/Workspace stores | AgentLoop、TUI、RPC | 客户端只提交引用，不能自报 owner 或 generation |
| Durable audit | `audit/`、`db/`、authorityd/WORM adapters | 对应写入事务和 append-only ledger | export/query | Python 内存日志不是独立审计权威 |

## 4. 目前的过渡性热点

这些文件不是“禁止修改”，而是明确的拆分目标。改动热点时必须先增加 characterization/contract test，再移动责任；不能在原文件末尾继续堆新分支。

| 文件 | 当前集中职责 | 拆分目标 |
| --- | --- | --- |
| `python/khaos/db/database.py` | 连接生命周期、迁移、session/message、turn/event、audit、memory、task、scheduler 等 | `DatabaseConnection`、migration runner、按领域的 repository/query service；保留一个薄 facade 兼容旧调用 |
| `python/khaos/tools/scheduler.py` | approval、authority、idempotency、并发和结果归一化 | `ToolAuthorization`、`ToolExecutionCoordinator`、`ToolResultStore` |
| `python/khaos/tools/admission.py` | 工具调用规范化、raw phase、注册表解析和参数校验 | `ToolAdmission`；只返回 `AdmittedToolCall`/`RejectedToolCall`，不做权限、authority 或执行 |
| `python/khaos/tools/scheduler_models.py`、`tools/budget.py` | 调度结果协议、权限请求事件和原子预算 reservation/commit | 已完成首个 seam；后续只允许由调度器编排，不在 handler 中复制预算或结果状态机 |
| `python/khaos/grpc_server.py` | transport/auth/startup、Agent service，以及兼容导出 | protocol/auth middleware、composition root、每个 service 独立模块；服务只消费已认证 context。MemoryService、SessionService、AuditService 已迁移到 `python/khaos/rpc/` |
| `python/khaos/coding/planning/approval/store.py` | schema、CAS transition、receipt、lease、plan execution event 和 read model | schema/migration、approval ledger、receipt verifier、execution-event repository、read model |
| `python/khaos/scheduler/engine.py` | cron 解析、持久化、调度、执行、恢复和审计 | schedule repository、due-item selector、execution coordinator、recovery worker |
| `python/khaos/runtime/factory.py` | 依赖装配和兼容参数转换 | 保留为唯一 composition root；业务逻辑不得回流到 factory |

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

- 从 `Database` 提取连接/迁移/repository，先迁移只读查询，再迁移写事务。
- 从 `grpc_server.py` 提取 protocol/auth/service；MemoryService、SessionService、AuditService 已完成首批 seam，保留兼容导出，不增加第二套 server authority。

### Phase 3：工具和执行边界

- `ToolScheduler` 的调用 admission 已收敛到 `python/khaos/tools/admission.py`；结果/事件值对象已收敛到 `python/khaos/tools/scheduler_models.py`，原子预算已收敛到 `python/khaos/tools/budget.py`；`tools.scheduler` 仅保留一个迁移周期的兼容导出。
- 下一步将 `ToolScheduler` 拆成 admission、capability consume、execution、result/audit 四段；每段只能消费上述类型，不能重新定义平行的 `ToolResult`、预算或 effect 状态。
- 将 file/Git/process 入口收敛为可注入 port，并为每个 port 提供 fail-closed contract tests。

### Phase 4：计划、验证和调度

- 拆分 approval store 与 CronEngine，显式区分 ledger、read model、recovery worker。
- 删除已经没有调用者的兼容分支，更新 schema/ADR 和迁移文档。

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
