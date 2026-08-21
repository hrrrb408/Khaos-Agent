# ADR-031: Make protected workspace metadata one shared policy

状态：accepted

日期：2026-08-21

## 背景

`SafeWorkspaceFS` 曾同时定义 protected names，而 WorkspaceManager、Docker、macOS
Seatbelt 和 authorization resource 通过不同 import/局部 casefold 集合消费它。任何
一个 backend 新增或遗漏名称都会造成写保护、mount 保护和权限解析不一致。

## 决策

`python/khaos/coding/workspace/policy.py` 是 protected workspace policy 的唯一 owner，
负责名称集合、默认 file/tree limits 和逐路径 component 检查。filesystem、workspace
manager、Docker/macOS backend 与 authorization resource 都从该模块读取；`boundary.py`
只保留显式兼容导出，不再定义第二份策略。

## 迁移和删除条件

新增 protected metadata 或调整默认边界只能修改 policy 模块并更新跨 backend contract
tests。完成所有调用者迁移后，删除 `boundary.py` 的兼容导出；任何 backend 不得在本地
重建 protected-name set。

## 证据

- `python/tests/coding/test_workspace_policy_boundary.py` 固化大小写无关和多级路径检查。
- 既有 SafeWorkspaceFS、workspace manager、Docker、platform、authorization resource
  回归测试继续证明具体效果边界。
