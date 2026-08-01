# Khaos-Agent 第十四轮深度 Review — 本地安全机制对标 Codex

> **审查范围**：全栈安全审计（Python Agent / Go 网关 / Rust TCB），对标 OpenAI Codex 本地安全模型
> **审查基线**：Khaos `ea7fb9c`（main, 2026-07-30）
> **对标**：Codex 本地 sandbox（Seatbelt / Landlock / bwrap / seccomp / 命令审批）
> **审查日期**：2026-07-31
> **审查者**：ZCode（GLM-5.2）
> **审查方法**：源码直读 + 关键路径跟踪 + TOCTOU/重放/越权三类攻击面建模 + 与第 3–13 轮去重

---

## 0. 执行摘要

本轮在前 13 轮基础上，**重新走查了安全权威链从 YAML 到 syscall 的完整路径**，并对前轮覆盖较浅的几条路径做了深度攻击建模：coding 子进程执行 TOCTOU、审批/权限系统绕过面、Rust FFI 可达性、浏览器/Docker 边界。

### 整体评价

Khaos 的安全设计在**架构层面确实达到了 Codex 水准，在「策略权威链 + 平台执行沙箱 + 浏览器内核 TCB」这三块甚至更强**：

| 维度 | Khaos | Codex | 结论 |
|------|-------|-------|------|
| 策略权威链（policy → compile → bind → enforce） | `khaos_policy.yaml` → `EffectiveSecurityPolicy`（user ∩ project ∩ platform）→ digest 绑定每次审批 | 分散式 sandbox config，无跨层交集编译 | **Khaos 更强** |
| 命令执行沙箱（Linux） | empty-root bwrap + cgroup v2 + Rust launcher（no_new_privs + seccomp deny-list + close_range）+ capability 探针 | Landlock + seccomp | **持平** |
| 命令执行沙箱（macOS） | `sandbox-exec` deny-default + 写入/网络/IPC 探针证明 | Seatbelt deny-default | **持平** |
| 浏览器隔离 TCB | Rust helper：netns + nft default-deny + cgroup + SCM_RIGHTS fd 传递 + HMAC capability + journal 重放保护 + TCB 二进制 digest 校验 | （Codex 无浏览器） | **Khaos 独有，且极强** |
| 审批绑定（防重放/防伪造） | `arguments_digest` + `profile_digest`（含 `effective_policy_digest`）+ `authorization_resource_digest` + epoch 重校验 | approval profile | **Khaos 更细** |
| DNS 出口冻结（防 SSRF/rebinding） | `HostNetworkAuthority` 冻结全 A/AAAA 记录 → proxy 用 `_open_pinned` 直连冻结 IP，**绝不二次解析** | — | **设计正确，实现无误** |

**但实现层仍有几处 Codex 已解决而 Khaos 未解决的真实缺口**，以及前 13 轮**未充分跟踪到的新发现**。本轮最值得修的，按优先级：

| 排名 | 问题 | 类别 | 新/旧 |
|------|------|------|-------|
| 🔴 #1 | 子进程执行的 TOCTOU：`verify_git_identity` 与 `create_subprocess_exec` 之间无 inode 绑定，worktree 可被 swap | 越权执行 | **新（前轮未跟踪到完整攻击链）** |
| 🔴 #2 | `confirm_permission` 用 `request.principal_id`（payload）而非 `ctx.principal_id`（transport） | 审批伪造 | **新** |
| 🔴 #3 | `grant_permission` pattern 无特异性校验，`"*"` / `"**"` 自动审批规则可静默废掉整个审批闸门 | 权限绕过 | **新** |
| 🔴 #4 | 审计日志无 tamper protection（无 hash chain / append-only trigger） | 审计完整性 | **旧（第 13 轮 P0-1，仍未修）** |
| 🟠 #5 | `arguments_digest` 审批时计算、派发时**不重算对比**（与 schema/policy/resource digest 不对称） | 审批重放 | **新** |
| 🟠 #6 | Rust `executor.rs` 的 `exec`/`read_file`/`write_file` handler 无沙箱无路径授权（当前生产不可达，但是一颗上膛的枪） | 越权执行 | **旧（第 13 轮 P0-2/3，未修；本轮确认可达性）** |
| 🟡 #7 | `_commands_require_approval` 闸门硬编码工具名集合，新增 exec 类工具会绕过 | 权限绕过 | **新** |
| 🟡 #8 | 子进程存储配额是「写后检测 + 滚动回滚」，write→close→unlink 在 50ms 轮询间隙不可见 | 配额逃逸 | **新** |

下面逐条展开。**合规面（已正确实现）**见 §6，不在此处重复。

---

## 1. 🔴 P0 — 子进程执行的 TOCTOU（worktree swap）

**这是本轮最重要的新发现，也是与 Codex 本地安全差距最大的一处。**

### 攻击链

`ExecutionService.execute()`（`coding/execution/service.py`）的执行顺序：

1. `service.py:105` — `workspace_manager.require(...)` 校验 worktree 存在、`root_device`/`root_inode` 匹配（`manager.py:388-414`）。
2. `service.py:119` — `await verify_git_identity(workspace_id)` 用 `git_identity.py:69` 校验 `.git` 指针 / admin dir / repo `.git` 的 `(dev,ino,content)`。
3. `service.py:120` — `root = workspace.worktree_path.resolve()`（**词法解析，跟随符号链接**）。
4. `service.py:121-123` — cwd 包含检查。
5. 控制权交给 backend → `supervisor.run()` → `supervisor.py:88` `asyncio.create_subprocess_exec(*argv, cwd=str(cwd), ...)`。

**关键问题**：步骤 2 校验的 inode 与步骤 5 内核实际 `chdir` 落地的目录，**没有任何描述符级绑定**。中间隔着多个 `await` 和多次 `.resolve()`（`host.py:40`、`platform.py:349/586`、`docker.py:140` 每个都重新 `resolve()` 且跟随符号链接）。

### 可利用场景

一个拥有 worktree 写权限的并发进程（最现实来源：**上一条 git 命令触发的 hook**，因为 `_workspace_git` 会 `core.hooksPath=/dev/null`，但任意 `process` 子进程不受此约束；或一个被攻陷/恶意的子进程本身），可以在 `verify_git_identity` 通过之后、`create_subprocess_exec` 之前：

- `rename(2)` 把 worktree 目录换走，替换成符号链接指向攻击者树；
- 攻击者树的 `.git` 指向攻击者 object DB。

子进程随后 `chdir` 进攻击者树执行。Khaos **事后**才会发现：`service.py:216` `_verify_or_quarantine_git_identity` 在执行**完成后**重跑校验，此时子进程已经跑完。

### 对比：git 命令是安全的，exec 命令不安全

`_workspace_git`（`manager.py:275-298`）在**每次 git 调用前**重跑 `verify_git_worktree_identity`，并显式 `--git-dir=` + `core.hooksPath=/dev/null` + `core.fsmonitor=false`。所以 git 操作有 inode 级围栏。

但 `ProcessSupervisor.run`（`supervisor.py:88`）**没有对应的 pre-exec 重校验**，也没有把校验过的 inode 通过 `O_PATH` dirfd 传给子进程作为 cwd。

### Codex 对比

Codex 的 exec 路径在 sandbox 内执行，cwd 是 sandbox 挂载视图，不存在 host-side worktree swap 问题——因为 sandbox 本身就是不可变挂载。Khaos 的 host backend（`host.py`）和 platform backend 在 swap 后才 chdir，是真实差距。

### 修复方向

1. **最低修复**：在 `supervisor.run` 调用 `create_subprocess_exec` **之前**，立即重跑 `verify_git_worktree_identity`（与 `_workspace_git` 对称），并断言 `cwd` 的 `(dev,ino)` 与 `require()` 缓存的 `root_device/root_inode` 一致。这是「检测」，把事后 quarantine 提前到事前。
2. **根治**：用 `O_PATH | O_NOFOLLOW | O_CLOEXEC` 打开 worktree root 得到 dirfd，所有后续路径操作走 `openat(dirfd, ...)`；子进程通过 `fchdir` 或 `--cwd=/proc/self/fd/N` 落地到校验过的 inode，而不是字符串路径。这样从校验到落地全程描述符绑定，`rename`/符号链接 swap 无法生效。
3. 把 `core.hooksPath=/dev/null` 等 git 硬化也应用到 `_workspace_git` 之外的所有 worktree 内 exec（虽然不能影响第三方工具读 `.git`，但至少消除 Khaos 自己触发的 hook）。

### 证据
- `coding/execution/service.py:105,119-123,201,216`
- `coding/workspace/manager.py:275-298`（git 围栏）vs `coding/execution/supervisor.py:88-99`（exec 无围栏）
- `coding/workspace/git_identity.py:69-95`（verify 逻辑本身是强的，问题在调用时机）

---

## 2. 🔴 P0 — `confirm_permission` 用 payload principal 而非 transport principal

### 问题

`grpc_server.py:1461-1478`：

```python
async def confirm_permission(self, ctx: RequestContext, request: ConfirmRequest) -> dict:
    # M4 batch 3.1.16A-4-1: ctx is the authoritative principal.
    # ... A-4-2 will switch the ApprovalBroker call to use ctx.principal_id directly.
    if not request.principal_id or not request.binding_digest:
        return {"ok": False, "error": "approval principal/binding required"}
    return {"ok": await self.approval_broker.resolve(
        request.tool_call_id, request.approved, request.remember,
        principal_id=request.principal_id,   # ← PAYLOAD 值，不是 ctx.principal_id
        ...
    )}
```

代码注释自己声明了正确做法（`ctx.principal_id`），却留了一个「A-4-2 will switch」的 TODO，至今未做。

### 当前是否可利用

**当前不可直接利用**，因为 RPC dispatcher 在 `grpc_server.py:2484-2485` 对**所有**方法做了覆盖：

```python
if "principal_id" in payload:
    payload["principal_id"] = ctx.principal_id
```

所以走正常 dispatcher 时 `request.principal_id == ctx.principal_id`，`ApprovalBroker.resolve`（`approval.py:339` 比对 `record.binding.principal_id`）能匹配。

### 为什么仍是 P0

1. **违反了系统级不变量**。AGENTS.md / 整个 M4 批次的核心承诺是「principal 身份只来自 transport auth（ctx），payload 的 principal_id 不可信」。这条注释赤裸裸地承认违反了承诺。
2. **唯一防线是 dispatcher 那一行 `if "principal_id" in payload`**。注意它有条件：仅当 payload **包含** `principal_id` 时才覆盖。如果 payload 不带该字段（旧 Gateway、webhook 内部调用、测试构造、未来新 transport），`request.principal_id` 就是攻击者可控值，可直接伪造任意 principal 的审批。
3. 这是一颗**离被触发只差一次重构**的枪。任何把 `ConfirmRequest` 构造路径脱离 dispatcher 的事件，都会立刻变成审批伪造原语。

### 对比 `TaskService.approve/reject`

`grpc_server.py:2092, 2154` 用了 `if principal_id and principal_id != ctx.principal_id: return error`——至少显式拒绝。但同样是 `if principal_id` 守卫（空值跳过），依赖下游 `consume_task_decision_and_commit` 的 principal 比对兜底（fail-closed，但是脆弱链）。

### 修复

`confirm_permission` 直接用 `ctx.principal_id`，删掉对 `request.principal_id` 的依赖；`TaskService.approve/reject` 把 `if principal_id and ...` 改成无条件 `if principal_id != ctx.principal_id: return error`（空值直接当不匹配拒绝）。

---

## 3. 🔴 P0 — `grant_permission` 无 pattern 特异性校验

### 问题

`permission_tools.py:96-141` 的 `grant_permission` 接受任意 `pattern` 字符串，零校验。规则匹配在 `engine.py:216` 用 `fnmatch.fnmatch(target, rule.pattern)`。

后果：用户（或一个被社工的用户）执行 `grant_permission(pattern="*", approval="auto-approve", permission_level="write")` 后，**该 principal 的所有 write 工具调用永久免审批**。`"/**"`、`"*:*"`、`"{tool_name}:{*}"` 等同样有效。

### 为什么严重

- Khaos 的安全模型默认 `ask-every`（ADR-003），审批是核心闸门。一条 `"*"` 规则静默废掉整个闸门。
- `remember` 路径（`scheduler.py:655-662`）默认 pattern = `decision.target`（具体路径，安全），但**直接调 `grant_permission` 工具**没有任何等价保护。
- 与 `default_mode=AUTO_APPROVE` 配置叠加，单条 `"*"` 规则可让模型无确认执行任意写。

### Codex 对比

Codex 的 approval rule 也有类似风险，但其 `config.toml` 的 approval 规则通常更结构化（按 command/路径前缀），且 UI 会展示「记住的规则」让用户审计。Khaos 的 `list_permission_rules` 工具存在，但**授予时无特异性门槛**。

### 修复方向

在 `grant_permission` 入口加 pattern 校验：
- 拒绝纯 `"*"` / `"**"` / 全通配；
- 要求 pattern 至少包含一个非通配路径段（最小特异性）；
- 对危险 approval 级别（`auto-approve`）+ 宽 pattern 组合要求二次确认；
- `engine.check` 可选地拒绝匹配「过宽」的 AUTO_APPROVE 规则并降级为 ask。

### 证据
- `permissions/engine.py:216`（fnmatch，无特异性检查）
- `tools/permission_tools.py:96-141`（grant 无校验）

---

## 4. 🔴 P0 — 审计日志无 tamper protection（第 13 轮 P0-1，未修）

### 状态确认

```
grep -rniE "prev_hash|hash_chain|append.only|BEFORE DELETE.*audit|trigger.*audit" \
    python/khaos/audit/ python/khaos/db/
```

`audit_log` 表**无任何 `BEFORE DELETE`/`BEFORE UPDATE` 触发器**（schema.sql 里只有 `verification_*` 表有 append-only 触发器，audit_log 没有）。`audit/logger.py` 无 hash chain / HMAC。

### 风险（不变）

任何有 DB 写权限的进程（含被攻陷的 Agent）可 `DELETE FROM audit_log WHERE ...`，无任何 DB 层或应用层机制阻止或检测。审计作为「所有写操作可追溯」的安全承诺被打破。

注意：`verification_cleanup_proofs` / `verification_success_evidence` 表**有** append-only 触发器（schema.sql:867-891），证明团队知道怎么做，只是没应用到 audit_log。这是一个不对称的硬化缺口。

### Codex 对比
Codex 审计 = append-only 文件 + 每条记录含前一条 SHA-256 的 hash chain。

### 修复（第 13 轮已给详细方案）
1. DB 层：`audit_log` 加 `BEFORE DELETE / BEFORE UPDATE` 触发器 `RAISE(ABORT, 'audit_log is append-only')`。
2. 应用层：`AuditLogger` 每条记录追加 `prev_hash = SHA-256(action|target|result|detail|created_at|prev_hash)`，首条 `prev_hash = SHA-256("genesis")`。可选 HMAC（用独立于运行时的密钥）防应用层篡改。

---

## 5. 🟠 P1 — `arguments_digest` 派发时不重算

### 问题

审批阶段（`scheduler.py:536-538`）：

```python
arguments_digest=_canonical_digest(normalized["arguments"]),
```

覆盖**完整**参数 dict（好，不是子集）。

派发阶段（`scheduler.py:751-788`）重校验了：`tool.schema_digest`（:755）、`policy_digest`（:760）、`authorization_resource.digest()`（:781 重算）、`validate_dispatch_epoch`（:751,766）——**唯独 `arguments_digest` 不重算不对比**。

### 风险

`arguments_digest` 名义上绑定了「批准的具体参数」，但实际只是存在 `ApprovalBinding` 里自我消费（参与 `binding.digest()`），**没有作为独立防线在 dispatch 时复验**。

当前缓解：同一个 `normalized["arguments"]` 从审批流到派发是同步 generator 内的一次性传递，正常路径不可篡改。但：
- 任何能在审批与派发之间修改 `call["arguments"]` 的代码路径都不会被 arguments-digest mismatch 抓住；
- 与其它三个 digest 的不对称处理，是「看起来绑了其实没绑」的典型陷阱。

### 修复
dispatch 时重算 `_canonical_digest(call.get("arguments", {}))` 并与 `binding.arguments_digest` 比对，不一致 raise `PermissionDeniedError`。与 resource digest 处理对称。

### 证据
- `tools/scheduler.py:536-538`（审批计算）
- `tools/scheduler.py:751-788`（派发复验，缺 arguments_digest）

---

## 6. 🟠 P1 — Rust `executor.rs` 的 exec/read/write handler 无沙箱（第 13 轮 P0-2/3）

### 本轮新确认：生产可达性

`rust_bridge.py` 暴露了 `RustToolExecutor.read_file` / `write_file` / `exec_process` / `execute_parallel`，它们直接调用 `executor.rs` 的 `dispatch_read_file` / `dispatch_write_file` / `dispatch_exec`——这三个 handler：

- **无路径授权**：`dispatch_read_file`（executor.rs:135-159）`tokio::fs::read(&params.path)` 读任意路径；`dispatch_write_file`（:165-186）`tokio::fs::write` 写任意路径并 `create_dir_all`；`dispatch_exec`（:193-282）`tokio::process::Command::new` 执行任意命令，**无 seccomp、无 namespace、无 cwd 授权、无 env 清洗、无资源限制**。
- 超时处理还有资源泄漏 bug（:246-260）：超时时丢弃 `collect` future，子进程变孤儿「best-effort kill」实际没 kill。

**生产可达性核查**：

```
grep -rn "rust_read_file|rust_write_file|exec_process|execute_parallel|RustToolExecutor|use_rust_executor" \
    python/khaos/ --include="*.py" | grep -v __pycache__ | grep -v /tests/ | grep -v rust_bridge.py
```

→ 只剩 `scheduler.py:264,283` 的 `use_rust_executor: bool = False`（**默认 False**）。生产 factory（`runtime/factory.py`）未把它设 True，`grpc_server.py` 也只 `from khaos.rust_bridge import get_token_engine`（只用 token 引擎）。

**结论**：当前生产路径**不调用**这三个危险 handler（只 token counting 在用 Rust）。所以本轮**降级为 P1 而非 P0**——但这是一颗上膛的枪：

- PyO3 模块一旦被 import，`run_parallel_json` 就是导出符号；
- 任何未来「把 read_file offload 到 Rust 提速」的改动（`use_rust_executor=True`），会**瞬间**绕过整个 Python 安全栈（Sandbox / PathGuard / CommandGuard / PermissionEngine 全部失效），因为 Rust handler 直接 `fs::read`/`fs::write`/`Command::new`。
- 第 13 轮标 P0 是基于「Rust 是性能层，迟早会接执行」的预期；本轮确认它现在不可达，但接口已经存在且完全无防护。

### Codex 对比
Codex 的 Rust 层（如果有 I/O handler）会经过同一套 sandbox。Khaos 的 Rust executor 是「绕过 Python 安全栈的捷径」。

### 修复（两选一）
1. **推荐**：从 `executor.rs` 删除 `read_file`/`write_file`/`exec` 三个 handler 及对应 PyO3 导出。它们当前没人用，留着只增加攻击面。token/echo/sleep/sum 留着即可。
2. 若保留：每个 handler 必须接受 workspace root + capability 集合参数，内部做路径授权；`exec` 必须在 Rust launcher 沙箱内执行（复用 `khaos-sandbox-launcher`）。

### 证据
- `rust/khaos-core/src/executor.rs:124-282`（三个 handler 实现）
- `python/khaos/rust_bridge.py:142-186`（Python 包装，无任何授权）
- `python/khaos/tools/scheduler.py:264,283`（默认关闭）

---

## 7. 🟡 P2 — `_commands_require_approval` 闸门硬编码工具名集合

### 问题

`engine.py:190-192`：

```python
if self._commands_require_approval and tool_name in {
    "terminal", "terminal_argv", "terminal_shell", "process"
}:
```

这个前置闸门（policy 要求审批的命令优先于持久 auto-approve 规则）只对这 4 个硬编码工具名生效。任何**未来新增的 exec 类工具**（比如一个新的 `shell_exec`、`run_command`、或 Rust executor 接管后的某个工具名）都不会触发该闸门，从而：
- policy `commands_require_approval: [rm]` 对新工具失效；
- 一条针对 `terminal` 的 auto-approve 规则可能在新工具上被误用（取决于 target 归一化）。

### 为什么是 P2 而非更高
当前生产只有这 4 个工具能执行命令，闸门对它们都正确生效，且正确处理管道（`_matches_required_approval` 对每段都检查）。是「未来扩展时易踩坑」而非「现在可绕过」。

### 修复
从工具定义（`ToolCapability` 或 `Tool.permission_level == "execute"`）派生「exec 类工具集合」，而不是字符串字面量。或在 `Tool` 上加一个 `invokes_shell: bool` 标志，闸门检查该标志。

---

## 8. 🟡 P2 — 子进程存储配额「写后检测」+ 50ms 轮询间隙

### 问题

`WorkspaceStorageAuthority.mutate`（`storage.py:118-154`）的设计是：
1. 写前 `assess`（预检，已超则 fail-closed）；
2. 执行 `operation()`（**写发生，无人监控**）；
3. 写后 `assess`（检测）；
4. 违规则 `rollback`。

对于**子进程**（不是 file 工具），存储监控在 `supervisor.py:446-509` 的 watchdog，每 **50ms** 轮询一次（`supervisor.py:509`），并配合 `_deleted_open_file_usage`（:565-676）抓「已打开未链接」文件。

### 缝隙
- 进程内串行化只用 `threading.RLock`（按 workspace_id，`storage.py:161-165`）——**对子进程无效**。子进程可以写 >配额 字节然后 close+unlink，只要在下次 50ms 轮询前完成，delta 扫描（`workspace_storage_delta`）看不到。
- `write→close→unlink` 突发对 watchdog 不可见（只有「仍打开的已删文件」能被抓到）。
- 取消只 `SIGTERM` 进程组 + quarantine 整个 workspace（`manager.py:505-520`），**不回滚已写数据**。

### 现实风险等级
P2。因为：
- 子进程本身已经在 bwrap/seatbelt 沙箱内，写入只能落在 worktree（`/workspace` bind）和 tmpfs（`/tmp`/`/home/khaos`），无法逃逸到 host 敏感路径；
- 配额逃逸的后果是「worktree 里多写了一些字节然后删掉」或「tmpfs 膨胀」，属于资源滥用而非数据外泄；
- bwrap 的 `--size` tmpfs 上限（`platform.py:499-502`）是硬上限，tmpfs 写爆会被 ENOSPC 挡住。

### 修复方向（可选，提升健壮性）
- 把 watchdog 轮询间隔从 50ms 降到 ~10ms（增加开销）；
- 或对 worktree 用 `fsnotify`/inotify 监控 close-write 事件，事件驱动而非轮询；
- tmpfs `--size` 已经是硬墙，主要补 worktree 的 bytes 配额即时性。

---

## 9. 其他确认项（合规 / 已正确）

为避免与前 13 轮重复，以下只列本轮**重新验证为正确**的关键安全属性，作为合规清单：

### 9.1 策略编译链 ✅
- `effective_policy.py` 的 user ∩ project ∩ platform 交集编译正确；`default_user_policy()` 保证缺失 user 文件时 project 无法 elevate 到 yolo（`:325-340`）。
- 三态语义（None / 空 / 非空）在 `commands_allowed`、`network_allowed_domains`、`root_capabilities` 上一致，fail-closed（empty = deny all，不是 unrestricted）。
- `validate_policy_dict` 严格类型检查（`_check_bool` 拒绝 `"false"` 字符串，`:500-516`），未知字段 fail-closed。
- digest 覆盖所有策略字段（含 channel_admins），审批绑定有效。

### 9.2 审批重放防御 ✅（除 §5 的 arguments_digest 缺口）
- `ApprovalBinding.consume_for_dispatch` 一次性消费（`approval.py:354-392`，`used`/`dispatched` 标志）。
- `profile_digest` 含 `effective_policy_digest`（`scheduler.py:543-558`），policy 变更使 approval 失效。
- `authorization_resource_digest` 派发时**重算**（`scheduler.py:781`），path/shell script 漂移被抓。
- epoch 重校验（`engine.py:338-344`）+ `policy_digest` 比对（`engine.py:152`）。

### 9.3 跨 principal 隔离 ✅（除 §2）
- DB 层 `list/insert/delete_permission_rules` 全部 principal_id + project_id + policy_digest scoped（`database.py:2596-2606, 2629-2631, 2688-2692`）。
- `revoke_rule` fail-closed（0 rows → `PermissionDeniedError`，`engine.py:287-297`）。
- transport auth：HMAC 签名 envelope + nonce replay cache + `payload.principal_id` 与 `auth.principal_id` 比对（`grpc_server.py:739-782`）。

### 9.4 平台执行沙箱 ✅（除 §1 的 host-side swap）
- **Linux bwrap**：empty-root tmpfs + 最小 `/etc` 文件（非整树）+ allowlist ro-bind + `--unshare-net/pid/ipc/uts` + cgroup v2（pids/memory/cpu/io）+ Rust launcher（`PR_SET_NO_NEW_PRIVS` + seccomp deny 含 io_uring + `close_range`）。
- **macOS Seatbelt**：`(deny default)` + 正向 allowlist + `(deny network*)` + 写入/网络/IPC **实测探针**（`platform.py:146-221`，真正跑一遍证明写入拒绝、网络拒绝、pbpaste/security keychain 拒绝）。
- **capability 探针绑定 evidence**：boot_id + uid + namespace inode + binary digest + cgroup inode，TTL 60s 缓存，evidence 变化即重探（`capability.py`）。
- **bwrap/launcher 路径 TOCTOU 防护**：`_resolve_bwrap_path` / `_linux_sandbox_launcher` 在非 dev 模式走 `_validate_tcb_binary`（canonical path + owner/mode + parent chain + digest），生产无 PATH fallback（`platform.py:602-663`）。
- **fail-closed on unsupported**：bwrap 存在但无法 unshare-net（如 GitHub runner）→ writable 执行返回 `UnsupportedBackend`，**绝不降级到 host subprocess**（`platform.py:83-95`）。

### 9.5 浏览器 TCB ✅（本轮重点复核，极强）
- Rust helper（`khaos-browser-kernel-helper.rs`）：
  - 闭合 serde 协议（`deny_unknown_fields`）+ 长度前缀 + MAX_MESSAGE_BYTES。
  - HMAC capability 绑定 `(boot_id, principal, project, runtime, task, token, pid, start_time)`，`constant_time_equal` 比对（:1338-1346）。
  - `SO_PEERCRED` + PID start-time + `is_descendant` 三重验证 peer（:1037, 1281-1301）。
  - TCB 二进制（`/usr/sbin/ip`, `/usr/sbin/nft`）每次 exec 都重开 + 重校验 dev/ino/uid/mode/**digest**（:979-1003），`openat` /proc/self/fd/N 防 TOCTOU。
  - nft default-deny + journal HMAC + 重启 recovery 只采纳可重新验证的 active 记录（:1374-1528）。
- 出口冻结：`HostNetworkAuthority` 冻结全 A/AAAA → `_is_public_address` 逐个校验（拒绝 127.0.0.1/169.254/RFC1918/::1）→ proxy `_open_pinned` **直连冻结 IP，绝不二次解析**（`browser_egress_proxy.py:376-387`）。DNS rebinding 无效。

### 9.6 Docker 后端 ✅（本轮新审，意外地强）
- 镜像 digest pin（`python@sha256:...`）+ `--pull never` + 本地 inspect 闸门（`docker.py:29-34, 127-133, 144`），无 MITM/registry-swap 面。
- `--cap-drop ALL` + `--user 65534:65534` + `no-new-privileges` + `--network none` + `--ipc none` + `--read-only` + tmpfs noexec/nosuid/nodev（`docker.py:144-153`）。
- workspace bind 限定在 worktree + mount 语法注入防护（拒 `,` `\n` `\r` `\0`，`docker.py:282-283`）。
- 清理 owner-gated：随机 nonce 写 label，stop/kill/rm 前校验（`docker.py:313-339`）。
- **不可静默回退**：`BackendSelector` 永不选 Docker，只在显式 `backend_hint=="docker"`（即 `sandbox_exec` 工具）时触发。

### 9.7 网络权威 ✅
- `canonicalize_domain` 统一 lowercase + IDNA + trailing-dot（`network_guard.py:68-131`），policy 编译期与请求期双重 canonicalize，堵死 `EXAMPLE.COM`/`example.com.`/Unicode 绕过。
- `network_enabled` 是 total switch，开启时 allow/block list 仍生效（H1 修复了 fail-open）。

---

## 10. 优先级修复建议（给瑞邦）

### 立即修（P0，1–2 天内）
1. **§2** `confirm_permission` 改用 `ctx.principal_id`（1 行改动，消除审批伪造枪膛）。
2. **§3** `grant_permission` 加 pattern 特异性校验（拒 `"*"`/`"**"`，要求最小特异性）。
3. **§4** audit_log 加 append-only trigger + hash chain（schema 迁移 + logger 改造，与 verification_* 表对称）。

### 短期修（P0/P1，1 周内）
4. **§1** 子进程 exec 前重跑 `verify_git_worktree_identity` + cwd inode 断言（把事后 quarantine 提前到事前检测）；中期演进到 dirfd 绑定。
5. **§6** 从 `executor.rs` 删除未用的 `read_file`/`write_file`/`exec` handler（消除「Rust 绕过 Python 安全栈」的捷径）。

### 中期修（P1/P2，2–4 周）
6. **§5** dispatch 时重算 `arguments_digest` 与 binding 比对。
7. **§7** `_commands_require_approval` 闸门从工具定义派生而非硬编码。
8. **§8** 子进程存储配额改 inotify 事件驱动（可选）。

### 不需要修（确认安全）
- 浏览器 TCB、DNS 冻结、Docker 后端、bwrap/Seatbelt 沙箱、策略编译链、跨 principal DB scoped——均经验证为 Codex 水准或更强。

---

## 11. 与 Codex 的最终对标结论

| 安全控制 | Codex | Khaos | 差距 |
|---------|-------|-------|------|
| 策略权威链 | 分散 config | 三层交集编译 + digest 绑定 | **Khaos 更强** |
| Linux 沙箱 | Landlock+seccomp | bwrap+cgroup+seccomp+capability probe | 持平 |
| macOS 沙箱 | Seatbelt | Seatbelt + 实测探针 | 持平 |
| 浏览器隔离 | 无 | Rust helper TCB（netns+nft+cgroup+HMAC） | Khaos 独有 |
| 命令审批 | profile | digest 多重绑定 + epoch | 持平/更强 |
| **子进程 cwd 绑定** | sandbox 挂载（无 swap） | **host-side string path（有 swap 窗口）** | **Khaos 弱** |
| 审计完整性 | append-only + hash chain | **无 tamper protection** | **Khaos 弱** |
| DNS/SSRF | — | 冻结快照 + public-only | 正确 |
| 审批 principal 绑定 | transport-bound | **confirm_permission 漏洞（payload）** | **Khaos 弱（局部）** |

**总评**：Khaos 的安全架构是**严肃的、生产级的**，在策略链和浏览器 TCB 上明显超过了 Codex 的设计。**三个真实差距**（子进程 cwd TOCTOU、审计 tamper、confirm_permission principal）都是**实现层**而非设计层的问题，且都有清晰的修复路径。修完 §1–§4 后，Khaos 的本地安全机制可以达到「全面比肩 Codex，部分超越」的状态。

---

*审查结束。维护者：瑞邦 + Hermes/ZCode*
