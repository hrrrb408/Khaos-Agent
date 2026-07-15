# ADR-010：Principal-bound 一次性 Approval Capability

## 状态

部分接受并实施（2026-07-15）。普通 tool approval 已迁移；Plan Approval 沿用已有的
signed durable receipt；destructive operation/ChangeSet 的统一持久化仍待完成。

## 决策

普通工具调用在展示确认 UI 前，必须由服务器创建不可变 `ApprovalBinding`。binding
包含 `principal_id`、`session_id`、`task_id`、`turn_id`、`tool_call_id`、tool name、
canonical arguments digest、`workspace_id`、permission profile digest、expiry 和随机
nonce。SHA-256 binding digest 是 UI 回调和 task approval API 的公开引用；nonce 不离开
broker。

同一 tool call ID 只能注册同一个 binding。principal、session、digest 或 expiry 任一
不匹配均拒绝；approve、reject、timeout、cancel 和成功 wait 都把 capability 标记为已
消费。回调早于 waiter 建立是合法 race：binding 已在 permission event 前注册，decision
可暂存，但仍只能消费一次。

Gateway 从通过校验的 API key 派生稳定 principal ID，并覆盖客户端 JSON 中的任何自报
principal。没有认证 principal 的 confirm、task approve 和 task reject 请求拒绝。Python
UDS 只接收 Gateway 传入的 principal；本地直连 runtime 使用 OS uid principal。

## 不变量

- approval 不能跨 principal、session、task、turn、call 或 workspace 重放；
- 修改工具参数或 permission profile 后旧 digest 失效；
- late approval、double approval 和 timeout 后 approval 均失败；
- Task 状态不能在 capability 校验失败后继续保持 running；
- Plan Approval 的 Ed25519 receipt、boot binding 和 durable outbox 不降级。

## 剩余工作

- destructive Git/GitHub/ChangeSet operation binding 仍由内存 broker 保存，需要统一成
  principal-bound durable consume ledger；
- Gateway principal 当前代表共享 API key，不等价于多租户用户身份；Batch D 必须加入
  session ownership 与独立 principal provider；
- pending ordinary tool approval 在 restart 后按设计失效，但失效事件尚未写入 durable
  audit ledger。

## 回滚

不可回滚到裸 `resolve(tool_call_id, approved)`。若 capability 协调失败，应拒绝新审批并
保留 blocked/failed 状态；不得恢复只按 tool call ID 的旧路径。
