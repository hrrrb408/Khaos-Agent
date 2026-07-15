# ADR-010：Principal-bound 一次性 Approval Capability

## 状态

接受并实施（2026-07-15）。普通 tool approval 已迁移；Plan Approval 沿用已有的
signed durable receipt；destructive operation/ChangeSet 使用事务化 durable ledger。

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

Scheduler 不把 UI callback 的布尔返回值直接当作执行权限。callback 返回后必须使用
server-held principal、session 和 binding digest 调用 Broker `consume_for_dispatch`。
远端 callback 可先通过 `resolve` + `wait` 等待 Gateway 决策，本地 callback 可直接返回
用户意图；两条路径最终都在同一 immutable binding 上一次性消费 dispatch 权限。scope
不匹配、过期、decision 不一致或 replay 均转为拒绝。

Gateway 从通过校验的 API key 派生稳定 principal ID，并覆盖客户端 JSON 中的任何自报
principal。没有认证 principal 的 confirm、task approve 和 task reject 请求拒绝。Python
UDS 只接收 Gateway 传入的 principal；本地直连 runtime 使用 OS uid principal。

破坏性 operation 的 canonical binding 与 authoritative expiry 持久化到 SQLite。注册、
批准、消费、拒绝与取消均在 `BEGIN IMMEDIATE` 事务内完成；消费时参数、principal 或
session 不匹配会烧毁 capability。Git、GitHub 与 ChangeSet 都绑定 task、workspace、
operation、arguments/profile digest，并在执行前重新计算可变仓库事实。进程重启和多个
数据库连接竞争时仍至多一个消费者成功。

## 不变量

- approval 不能跨 principal、session、task、turn、call 或 workspace 重放；
- 修改工具参数或 permission profile 后旧 digest 失效；
- late approval、double approval 和 timeout 后 approval 均失败；
- Task 状态不能在 capability 校验失败后继续保持 running；
- Plan Approval 的 Ed25519 receipt、boot binding 和 durable outbox 不降级。

## 剩余工作

- Gateway principal 当前代表 API key 派生身份；生产多租户部署仍需接入独立 identity
  provider，而不能让多个用户共享同一 key；
- pending ordinary tool approval 在 restart 后按设计失效，但失效事件尚未写入 durable
  audit ledger。

## 回滚

不可回滚到裸 `resolve(tool_call_id, approved)`。若 capability 协调失败，应拒绝新审批并
保留 blocked/failed 状态；不得恢复只按 tool call ID 的旧路径。
