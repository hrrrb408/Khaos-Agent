# Khaos-Agent 第十五轮深度 Review — 入站攻击面 + 第 14 轮修复对抗性复核

> **审查范围**：本轮分两条独立主线 ——(A) 对第 14 轮 7 个修复做**对抗性复核**（不信任修复者，找修复本身的漏洞）；(B) 审查 14 轮**完全没覆盖的入站攻击面**（webhook / Go 网关 / 通道适配器）——这是外部攻击者可控的部分，对一个本地安全优先的 agent 来说往往比本地沙箱更危险。
> **审查基线**：Khaos `ea7fb9c` + 第 14 轮未提交修复
> **对标**：Codex 本地安全模型
> **审查日期**：2026-07-31
> **审查者**：ZCode（GLM-5.2）
> **审查方法**：源码直读 + 攻击链建模 + 修复绕过验证

---

## 0. 执行摘要

### 整体结论

第 14 轮修复方向正确，但**对抗性复核发现其中 3 个修复存在真实绕过**（不是理论上的）：
- **§3 pattern 校验被 DB 直插完全绕过**（修复只守了 Python API，没守 DB 加载路径）；
- **§4 哈希链被一行 `INSERT ... prev_hash=''` 完全废掉**（没有 BEFORE INSERT 触发器 + 空 prev_hash 被当可信 reset）；
- **§1 TOCTOU 修复只对 Docker backend 真正生效**，macOS/Linux/LSP 路径窗口仍在。

更严重的是：**主线 B 发现了 14 轮全栈审计都漏掉的一个 P0 入站攻击链** —— 一个平台验证通过的 webhook（恶意 GitHub issue / Telegram / Slack 消息）能驱动完整 agent turn，且 `read-only terminal` 快捷自动批准对它**无差别生效**，可被用来无审批 `cat ~/.ssh/id_ed25519` / `cat ~/.aws/credentials` 后外传。这是 14 轮「本地安全」盲区里最锋利的一刀。

### 本轮发现总览（按优先级）

| 排名 | 问题 | 类别 | 主线 |
|------|------|------|------|
| 🔴 #1 | **WeChat webhook 签名不覆盖请求体** —— 截获一次有效签名即可注入任意消息，配合 #2 等于完全控制 agent prompt | 入站伪造 | B |
| 🔴 #2 | **验证通过的 webhook 驱动完整 agent turn，read-only terminal 快捷自动批准无差别生效** —— 外部攻击者无审批读密钥并外传 | 混淆代理 | B |
| 🔴 #3 | **§3 pattern 校验绕过** —— DB 直插的 `"*"` 规则在 `load_rules` 时不过校验，直接匹配 | 修复绕过 | A |
| 🔴 #4 | **§4 哈希链 INSERT-reset 绕过** —— 无 BEFORE INSERT 触发器 + `prev_hash=''` 被当可信 reset，一行 INSERT 隐藏全部篡改 | 修复绕过 | A |
| 🟠 #5 | **生产 webhook RPC 转发 `principal_id=""`，`for_rpc("")` 抛错** —— 经 Go 网关的 webhook 很可能根本进不到 handler（可靠性 + 安全路径未测） | 入站可靠性 | B |
| 🟠 #6 | **§1 TOCTOU 修复只对 Docker 生效** —— macOS/Linux backend 在 `verify_execution_root` 之后仍 `.resolve()` 重解析 cwd，窗口仍在；LSP/managed 路径完全跳过校验 | 修复绕过 | A |
| 🟡 #7 | **`/api/config` GET/PUT 无 admin 校验** —— 任何持有 API key 的 principal 可读写整个网关配置 | 越权 | B |
| 🟡 #8 | **§7 `_DEFAULT_EXEC_TOOLS` 漏了 `sandbox_exec`/`sandbox_build`** —— 非 factory 路径构造 PermissionEngine 时这两个 exec 工具绕过 `commands_require_approval` | 修复绕过 | A |
| 🟡 #9 | **webhook 限流只按源 IP** —— NAT 后共享、IP 轮换绕过、单 channel 可饿死其他 channel | DoS | B |
| 🟡 #10 | **§3 `MIN_RULE_SPECIFICITY=2` 对命令/URL 目标过低** —— `rm*`（2 字符）会自动批准整个 rm 家族 | 修复不足 | A |

合规面（已正确）：§5 `arguments_digest` 重算（SOLID）、§6 Rust handler 删除（SOLID，有回归测试钉死）、Slack/Discord/generic webhook 原始体 HMAC（正确）、Go API key 常量时间比较（正确）、SSE 流按 principal 隔离（正确）、Go→Python principal 由 transport 派生不可伪造（正确）。

---

## 主线 A：第 14 轮修复对抗性复核

### A-1 🔴 §3 BYPASS —— DB 加载路径完全不校验 pattern

**证据**：
```
validate_rule_pattern 调用点：
  engine.py:282  (grant_rule)         ✅ 有
  permission_tools.py:133 (grant_permission 工具)  ✅ 有
  engine.py:124-147  (load_rules)     ❌ 无
  engine.py:334-353  (_reload_current_rules)  ❌ 无
  engine.py:180-198  (check 内 epoch 重载)  ❌ 无
  database.py:2673  (insert_permission_rule DB 层)  ❌ 无
```

第 14 轮的 `validate_rule_pattern` 只守了 Python API 两个入口。**信任边界是 DB 行**，而 DB 行从未被校验。

**攻击**：一条 `"*"` AUTO_APPROVE 规则只要绕过 Python API 写进 `permissions` 表（途径：修复前版本残留、DB 备份恢复、迁移脚本、任何直接 SQL 访问），就会被 `load_rules` 加载进 `self._rules`，然后在 `engine.py:232` 被 `fnmatch.fnmatch(target, rule.pattern)` 匹配，**静默废掉整个 approval 闸门**。`check()` 的 epoch 重载路径同样绕过校验。

**为什么严重**：这正是第 14 轮 §3 想防的攻击，但攻击者只需换一条写路径。生产中 DB 备份恢复 / 主机迁移 / 旧版本升级是常见场景。

**修复**：在 `load_rules` / `_reload_current_rules` / `check()` 重载路径对每一行调用 `validate_rule_pattern`，校验失败的规则隔离（记日志 + 不加载，因为可能是合法但陈旧的）。

### A-2 🔴 §4 BYPASS —— 哈希链被 INSERT-reset 完全废掉

**证据**：
```
BEFORE INSERT ON audit_log 触发器：  ❌ 不存在（只有 BEFORE DELETE / BEFORE UPDATE）
verify_audit_chain 对 prev_hash='' 的处理（database.py:3019-3021）：
  if stored == "":
      expected_prev = ""
      continue   ← 当作可信 genesis reset
```

**攻击**：触发器只拦 DELETE/UPDATE，不拦 INSERT。攻击者（任何拿到写连接的进程，或 DB 直插）执行：
```sql
INSERT INTO audit_log (action, target, result, detail, session_id,
    principal_id, project_id, prev_hash)
VALUES ('forged', 'x', 'success', '{}', 's1', 'p1', '', '');
```
这一行 `prev_hash=''` 被 `verify_audit_chain` 当作 genesis reset，`expected_prev` 清空，**之后所有行重新基于攻击者伪造行验证**。此前所有行被排除在验证之外。配合 DELETE/UPDATE 触发器（攻击者用 INSERT 而非编辑来绕过），**完全废掉篡改可检测性**。

**为什么严重**：第 14 轮 §4 的核心承诺是「审计篡改可检测」。这个 INSERT-reset 让攻击者一行 SQL 隐藏全部历史篡改，承诺被打破。

**修复**（两选一或都做）：
1. 加 `BEFORE INSERT ON audit_log` 触发器：表非空时拒绝 `prev_hash=''` 的新行（genesis 只允许首行）。
2. `verify_audit_chain` 把「非首行的 `prev_hash=''`」当 break（而非 reset）——这样任何 INSERT-reset 反而被检测出来。

### A-3 🟠 §1 GAP —— TOCTOU 修复只对 Docker 真正生效

**证据**：
- `service.py:212` 路由：只有 `DockerBackend` 定义了 `execute_resolved`（`docker.py:124`）。`MacOSSandboxBackend` / `LinuxBubblewrapBackend` 只有 `execute(request)`，走 `service.py:220-221` 的 `else` 分支。
- 这两个 backend 在 `verify_execution_root` **之后**仍重新 `.resolve()` cwd（跟随符号链接）：
  - Linux bwrap：`platform.py:480` `canonical_worktree = worktree.expanduser().resolve()`；`platform.py:514` `metadata.resolve()`
  - macOS Seatbelt：`platform.py:233` `workspace = worktree.resolve()`
- `verify_execution_root`（`manager.py:445-471`）**只校验 inode，不校验 git identity**——而它自己的 docstring 声称是 `_verify_or_quarantine_git_identity` 的 pre-exec 兄弟（后者校验 git identity）。所以 `.git` 指针/admin-dir swap 不被 pre-exec 捕获。
- `start_managed_process`（LSP/managed 路径，`service.py:307-403`）**完全不调用** `verify_execution_root`，直接 `create_subprocess_exec`。

**结论**：第 14 轮声称「把窗口缩小到最后一次 await」只在 Docker 成立（docker 用 `relative_to` + bind，不重解析）。macOS/Linux 生产 sandbox backend 的窗口仍在；LSP 长进程可被 swap 进攻击者 worktree 零校验。

**修复**：
1. `verify_execution_root` 同时调 `verify_git_identity`（兑现 docstring 承诺）。
2. backend 在 `verify_execution_root` 之后不要再 `.resolve()` 字符串路径——改为传 `O_PATH` dirfd，子进程 `fchdir` 落地到校验过的 inode（根治）。
3. `start_managed_process` 也要调用 `verify_execution_root`。

### A-4 🟡 §7 GAP —— `_DEFAULT_EXEC_TOOLS` 漏了 sandbox_exec/sandbox_build

**证据**：
- `engine.py:25` `_DEFAULT_EXEC_TOOLS = {"terminal", "terminal_argv", "terminal_shell", "process"}`
- 线上 registry 实际注册了 **5 个** `permission_level="execute"` 工具（`registry.py:1127,1147,1165,1185,1208`）：`terminal_argv`、`terminal_shell`、`process`、**`sandbox_exec`**、**`sandbox_build`**。
- 默认集合漏了 `sandbox_exec`/`sandbox_build`，且多了一个可能已不存在的 `terminal`。

**影响**：production factory（`factory.py:578-586`）传了 registry 派生的完整集合，所以生产 OK。但任何**非 factory 路径**（CLI、admin adapter、库调用、未来新 runtime）构造 `PermissionEngine(db, ...)` 不传 `exec_tool_names` 时，`sandbox_exec`/`sandbox_build` 静默绕过 `commands_require_approval`——policy 要求审批 `rm` 会拦 `terminal_argv rm` 但不拦 `sandbox_exec rm`。

**修复**：要么 `_DEFAULT_EXEC_TOOLS` 跟踪完整 registry 集合，要么（更好）把 `exec_tool_names` 改成必填参数（无静默默认）。

### A-5 §5 / §6 —— 验证为 SOLID

- **§5 arguments_digest 重算**：dispatch 用同一个 `_canonical_digest` 作用于同一个对象，approval 与 dispatch 之间无 mutation。SOLID。
- **§6 Rust handler 删除**：`executor.rs` 已无 fs/process surface；token.rs 是纯计算；回归测试 `removed_file_and_exec_handlers_fail_closed` 钉死。`run_parallel_json` 仍导出但移除的 kind 现在 fail-closed。SOLID（残留面有文档、有测试）。

---

## 主线 B：入站攻击面（14 轮全栈审计的盲区）

这是本轮最严重的部分。一个「本地安全优先」的 agent 如果能被外部 webhook 驱动去读密钥，本地沙箱再强也没意义。

### B-1 🔴 WeChat webhook 签名不覆盖请求体

**位置**：`python/khaos/channels/webhook.py:296-314`

```python
if self.platform == ChannelType.WECHAT:
    timestamp = query.get("timestamp", ...)
    nonce = query.get("nonce", ...)
    signature = query.get("signature", ...)
    ...
    expected = hashlib.sha1(
        "".join(sorted((self.secret, timestamp, nonce))).encode("utf-8")
    ).hexdigest()
```

签名材料是 `(secret, timestamp, nonce)`——**请求体完全不参与签名**。

**攻击**：攻击者截获**一次**有效的 `(signature, timestamp, nonce)`（或拿到一次合法 webhook 的这三个值），在 300 秒窗口内（`WEBHOOK_SIGNATURE_WINDOW_SECONDS=300`）用同样的 `(timestamp, nonce)` 但**任意请求体**重放，签名校验通过。replay guard 按 `f"{timestamp}:{nonce}"` 去重，但攻击者不需要重放——构造新体即可。配合 B-2，攻击者完全控制 agent prompt。

**对比**：Telegram/Slack/Discord/generic 都签原始体（`webhook.py:257-343`），WeChat 是唯一例外。至少比较是常量时间（`hmac.compare_digest:308`）。

**修复**：WeChat 的签名材料必须包含请求体（按微信官方规范，签名 = sha1(sorted(token, timestamp, nonce, **body**))）。若旧客户端不兼容，至少加一个严格的时间窗 + nonce 一次性使用。

### B-2 🔴 验证通过的 webhook 驱动完整 agent turn，read-only terminal 快捷自动批准无差别生效（混淆代理）

**攻击链**：
1. 平台签名验证通过的 webhook（恶意 GitHub issue / Telegram / Slack 消息）→ `_on_webhook_message` → `self.chat(webhook_ctx, ChatRequest(...))`（`grpc_server.py:1545-1550`），**无 mode，默认 office**。
2. `webhook_ctx = RequestContext.for_webhook(...)`，`source_transport="webhook"`。
3. turn 跑正常 agent loop + 正常 `PermissionEngine`。**`PermissionEngine.check` 对 `source_transport` 完全无感知**（`engine.py:149-267`）。
4. 后果：
   - 操作者曾授予的任何 `AUTO_APPROVE` 规则对 webhook turn 生效；
   - **`read-only terminal` 快捷自动批准**（`engine.py:243-249`，集合含 `cat`/`head`/`tail`/`grep`/`ls`/`rg`/`wc`/...）对 webhook turn **无条件**生效，`requires_user_confirm=False`。

**具体利用**：恶意 GitHub issue 让 agent 跑 `cat ~/.ssh/id_ed25519` / `cat ~/.aws/credentials` / `head -200 .env` / `grep -r AKIA .` —— 全被分类为 read-only → `AUTO_APPROVE` → **无任何确认**，输出进入 agent context，再由后续网络工具外传回攻击者控制的 channel。

**为什么 14 轮没发现**：14 轮聚焦本地安全权威链，没有把 webhook 当作「能驱动特权工具的外部主体」。这是本地安全模型的外部边界漏洞。

**修复**：
1. `PermissionEngine.check`（或 agent loop）对 `source_transport in {"webhook","cron","rpc"}` 的 turn，强制对任何有副作用或数据访问的工具走 `ASK_EVERY`（或 DENY）。
2. read-only terminal 快捷自动批准（`engine.py:217-226, 243-249`）对非交互 transport 关闭。
3. `registry.py:380` 的 `source_transport not in {"cli","tui"}` 限制目前只用于 `host.notes.*`/`host.clipboard.*`，应扩展到 `process.execute`/`filesystem.*`/`vcs.*`。

### B-3 🟠 生产 webhook RPC 转发 `principal_id=""`，`for_rpc("")` 抛错

**证据**：
- `go/internal/platform/python_client.go:296-306` + `handler.go:474-479`：webhook 入站转发时 `principalID=""`。
- Python dispatcher 对**每个**方法无条件 `RequestContext.for_rpc(principal_id, ...)`（`grpc_server.py:2496-2500`），包括 `AgentService.HandleWebhook`。
- `for_rpc` 对空 principal 抛 `ValueError`（`runtime/context.py:81-82`），被 `grpc_server.py:2706-2718` 的宽 `except` 吞成通用错误。

**后果**：经 Go 网关的平台 webhook（Telegram/Discord/Slack/WeChat）很可能**根本到不了** `handle_webhook`——死在 context 构造。这既是可靠性 bug，也是安全覆盖缺口：webhook handler 里的签名校验/replay guard/限流只有直调 `_on_webhook_message` 的测试覆盖（`tests/test_grpc_server.py:216`），真实 RPC 路径未测。

**修复**：webhook 方法特殊处理，跳过 `for_rpc`（或加 `for_rpc_or_anonymous`），并加端到端测试：签一个 `principal_id=""` 的 webhook，断言它到 `handle_webhook`。

### B-4 🟡 `/api/config` GET/PUT 无 admin 校验

**证据**：`handler.go:1154-1166`：`handleConfigGet`/`handleConfigSet` 无任何 principal/admin 检查，任何持有 API key 的 caller（`secured` = `auth.Middleware`，`handler.go:180`）可读写整个网关 config map（`h.config.Set(cfg)`）。对比 channel enable/disable（`handler.go:515-541`）有 `channel_admins` 校验。

**后果**：config 可能含安全相关 key；任何已认证 principal 可覆盖网关配置。

**修复**：`/api/config` GET/PUT 加 admin 校验（与 channel 管理对称）。

### B-5 🟡 webhook 限流只按源 IP

**证据**：Go 边预认证 webhook 限流器 key = `r.RemoteAddr`（`handler.go:695-701`，`:174-176`）。后果：NAT/LB 后共享一个桶；攻击者 IP 轮换得新桶；单 channel 噪声饿死其他 channel（桶 `maxKeys=4096` LRU 驱逐）。

**修复**：Go webhook 限流器额外按 `(platform, channel_id)`（从 path/query）分桶。

### B-6 合规（已正确）

- Slack/Discord/generic webhook 签**原始体**（`webhook.py:271,283,323`），体在验签**后**解析。
- Go API key 比较常量时间（`auth.go:65-68`，`subtle.ConstantTimeCompare(sha256(provided), sha256(expected))`）。
- 浏览器 session cookie：HMAC 签名 + HttpOnly + SameSite=Strict + epoch 可撤销 + bootNonce 重启失效（`auth.go:84-156`）。
- SSE / task events 流按 principal 隔离（`grpc_server.py:1394-1417`，Python DB 层过滤）。
- Go→Python：principal 由 transport 派生（`auth.PrincipalFromContext` ← API key digest），不读 caller 断言的 header；Python 侧再校验 `payload.principal_id` 与 envelope 一致（`grpc_server.py:768-770`）。伪造 principal header 到不了 Python 方法。
- webhook replay guard 持久化（`grpc_server.py:911-913`，`db.consume_webhook_event`）。

---

## 1. 与第 14 轮的对比

第 14 轮修的 7 项里，**方向都对**，但有 3 项实现有真实绕过（A-1/A-2/A-3），1 项默认值不全（A-4），1 项阈值偏低（A-6）。更重要的是，第 14 轮**完全没有审查入站攻击面**，本轮 B-2 发现的「webhook 驱动读密钥」是一个比多数本地漏洞更锋利的 P0。

## 2. 优先级修复建议（给瑞邦）

### 立即修（P0）
1. **B-2** webhook turn 的工具审批按 `source_transport` 门控 + 关闭非交互 transport 的 read-only terminal 快捷自动批准。（外部攻击者无审批读密钥）
2. **B-1** WeChat 签名纳入请求体。（截获即注入）
3. **A-1** `load_rules`/重载路径对每行调 `validate_rule_pattern`，失败隔离。（DB 直插绕过）
4. **A-2** 加 `BEFORE INSERT` 触发器 或 `verify_audit_chain` 把非首行空 prev_hash 当 break。（INSERT-reset 绕过）

### 短期修（P0/P1）
5. **B-3** webhook RPC 的空 principal 特殊处理 + 端到端测试。
6. **A-3** `verify_execution_root` 补 git identity 校验 + 扩展到 managed/LSP 路径 + backend 不再 `.resolve()` 重解析。
7. **B-4** `/api/config` 加 admin 校验。

### 中期修（P1/P2）
8. **A-4** `exec_tool_names` 必填 或 `_DEFAULT_EXEC_TOOLS` 补 `sandbox_exec`/`sandbox_build`。
9. **A-6** `MIN_RULE_SPECIFICITY` 按 target 类型（路径/命令/URL）区分阈值。
10. **B-5** webhook 限流加 `(platform, channel_id)` 维度。

---

## 3. 与 Codex 的最终对标更新

第 14 轮结论「修完 §1–§4 即全面比肩」**需要修正**：本轮发现即便修完本地 4 项，**入站 webhook 混淆代理（B-2）仍是比 Codex 更大的差距**——Codex 没有 webhook/Bot 通道，而 Khaos 把一个外部消息源接进了带文件/shell 访问的 agent loop 且无 transport 门控。这是 Khaos 多通道架构引入的、Codex 不存在的新攻击面。

修完 B-1/B-2 + A-1/A-2 后，Khaos 才能在「本地安全 + 入站安全」两个维度都比肩/超越 Codex。

---

*审查结束。维护者：瑞邦 + ZCode*
