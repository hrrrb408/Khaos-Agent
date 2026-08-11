# ADR-007：Coding Task 使用独立 Git Worktree

## 状态

已接受（Phase 0）。

## 决策

可写 Coding Task 默认创建独立 Worktree，并将其作为唯一 writable root。主工作树默认只读；回写必须生成 ChangeSet 并经过审批。

`git worktree add` 完成后立即固定 Worktree `.git` 指针的 dev/inode、完整内容摘要、
解析后的 admin dir 及 repository `.git` identity。Linux、macOS 与 Docker 沙箱都将
该指针作为只读例外；大小写不敏感文件系统上的 `.GIT` 等别名同样视为保护名称。
每次执行前后及 ChangeSet/commit 前必须重新验证 identity。宿主 Git 只能使用固定
`--git-dir` 与 `--work-tree`，并禁用 system/global config、hooks、fsmonitor 和 external
diff；不得再次通过 Worktree 内的指针动态选择 admin dir。identity 漂移时恢复固定指针
仅用于强制移除 disposable Worktree，不允许继续执行或提交。

bootstrap 先在 authority root 下的 pending worktree 中执行 `read-tree` 和 raw
tree/blob materialization；独立的 `WorkspaceBootstrapLimits` 限制总字节、单 blob、
条目、路径深度、symlink 数量、listing 大小和时长。对象格式由
`rev-parse --show-object-format` 决定，blob 内容必须重新计算并匹配 SHA-1/SHA-256
对象 ID。完整校验、保护名称检查和 stable storage baseline 通过后，才通过
`git worktree move` controlled publish 并登记 `TaskWorkspace`；失败、取消、磁盘错误
或 quota 触发会移除 pending worktree。mode `160000` 的 Git submodule/gitlink 当前
显式拒绝，Khaos 不自动执行 `git submodule update`。

Trusted Git 只允许审计过的 plumbing 操作。diff 强制关闭 external diff 与 textconv；
ChangeSet 提交使用 `hash-object --no-filters`、`update-index`、`write-tree`、
`commit-tree` 和 expected-old `update-ref`，不调用 `git add`、porcelain commit、
签名 helper 或仓库 clean/process filter。ChangeSet patch 以 authority-owned、带
长度和 SHA-256 digest 的 bounded artifact 保存，小变更才内联 preview，workspace
清理时一并删除 artifact。每个 workspace 最多登记 64 个 ChangeSet artifact，
并以 256 MiB 总字节上限做预留/核算；artifact 必须仍在 authority root 的登记集合中，
导出只能写入该私有 root，失败或取消会回收临时 artifact。

## 原因

物理隔离比路径约定更能降低误写主仓库、并发任务互相污染和审批后 Diff 漂移的风险。

## 替代方案

- 直接在主工作树修改：实现简单，但无法满足安全边界。
- 自动 stash 后复用主树：会改变用户状态且难以恢复，故不采用。

## 回滚与兼容

只读任务继续支持现有路径。Worktree 创建失败时返回结构化错误，不裸回退到主工作树。
