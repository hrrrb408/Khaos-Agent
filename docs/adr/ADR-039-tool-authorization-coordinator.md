# ADR-039: Give ordinary tool authorization a decision owner

状态：accepted

日期：2026-08-22

## 背景

`ToolScheduler` 在 admission 之后同时调用 `PermissionEngine.check`、为进程工具补充
可信 executable 约束，并把 `remember` 回答投影成 transport-scoped `PermissionRule`。
这些规则与 approval binding/permission request 的构造混在调度循环中，容易让新的工具
入口绕过同一套 fail-closed 判定，或复制一份 remember 规则的 scope 语义。

## 决策

`python/khaos/tools/authorization.py` 的 `ToolAuthorization` 是普通工具授权决策与
remember-rule projection 的唯一 owner：

- `decide` 统一调用 `PermissionEngine`，并把 process capability 的不可信 executable
  从 auto-approve 收紧为显式确认；
- `project_remember_rule` 统一 interactive transport、typed resource 和 project scope；
- `build_approval_binding` / `build_permission_request` 继续由同一模块拥有 digest/字段
  投影；
- broker 注册、用户确认事件、receipt consume 和效果执行仍由 scheduler 编排，避免
  隐藏事件边界或产生第二个 capability writer。

## 证据与删除条件

- `python/tests/tools/test_authorization_contract.py` 覆盖不可信 executable 收紧、
  interactive/unattended remember 语义，以及 scheduler 不再直接调用 permission check。
- scheduler 回归继续通过；后续 `ToolExecutionCoordinator` 接管 authority preparation、
  dispatch 和 effect/result terminalization 后，scheduler 只保留批次编排和事件投影。
