# ADR-042: Give ChangeSet artifacts a bounded storage owner

状态：accepted

日期：2026-08-22

## 背景

`WorkspaceManager` 同时管理 worktree 生命周期、Git snapshot 和 ChangeSet artifact 的
no-follow 文件读写、digest 校验与导出复制。artifact 的文件边界被埋在生命周期方法
之间，后来者很难判断哪些操作可以复用，也容易把普通 pathlib 写入带回安全路径。

## 决策

`python/khaos/coding/workspace/artifacts.py` 是 ChangeSet artifact 文件效果的唯一 owner：

- 只通过 bounded descriptor 读写、exclusive create、fsync 和 digest/length 校验；
- 不决定 workspace 是否拥有 artifact、不登记 quota、不执行 approval 或 lifecycle transition；
- `WorkspaceManager` 只负责生命周期/quota 注册并调用该 owner；旧私有 helper 不再在 manager
  中定义。

`workspace/errors.py` 统一 workspace-domain `WorkspaceError`，使 manager、artifact、
application 和测试共享同一个错误边界，而不是由 manager 私有定义。

## 证据与删除条件

- `python/tests/coding/test_workspace_artifact_boundary.py` 覆盖 digest-bound round trip、
  exclusive publish 和 manager 无 helper 重定义；workspace manager/storage/runtime 回归继续通过。
- 后续将 Changeset quota registration 独立为 lifecycle repository 后，删除 manager 的
  artifact 兼容别名和直接 helper 引用。
