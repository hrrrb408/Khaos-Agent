# ADR-043: Give trusted Git process lifecycle one owner

状态：accepted

日期：2026-08-22

## 背景

`TrustedGitRunner` 同时包含 Git allowlist/effect authority 和 subprocess spawn、pipe
drain、cancellation adoption、process-group termination 及 quarantine。平台失败时很难
区分“Git 语义拒绝”和“进程终态证据缺失”，也容易让新的 Git command path 直接使用普通
subprocess API。

## 决策

`python/khaos/coding/workspace/git_process.py` 的 `TrustedGitProcessOwner` 是 host Git
子进程生命周期的唯一 owner：

- 负责 spawn adoption、bounded stdout/stderr、whole process-domain termination 和
  quarantine/terminal proof；
- `TrustedGitRunner` 只拥有 Git executable identity、argv allowlist、typed effect/CAS
  authority 和 repository/tree semantics；
- `trusted_git.py` 保留一周期的显式兼容导出，其他模块继续从其公共入口导入，避免突然
  分叉异常类型。

## 证据与删除条件

- 现有 `test_trusted_git_process_owner.py` 回归继续通过，`test_git_process_boundary.py`
  固化 runner 不再定义 process owner。
- 所有直接 process-owner 调用迁移到新模块后删除 `trusted_git.py` 的兼容导入，不允许
  在 Git runner 中重新添加 subprocess 生命周期状态。
