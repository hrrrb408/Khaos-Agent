# ADR-012：统一 SafeWorkspaceFS 文件能力

## 状态

接受并实施（2026-07-15）。

## 决策

Coding Agent 的文件读写不再以 `Path.resolve()` 的检查结果作为授权。所有通用文件与
代码搜索工具必须先取得 active TaskWorkspace，再通过 `SafeWorkspaceFS` 操作。该能力
复用 planned mutation 已验证的 `WorkspacePathHandle`：固定打开 workspace root dirfd，
父目录逐段 `O_DIRECTORY | O_NOFOLLOW` 打开，文件操作相对于 dirfd 执行，并在变更前后
复核 parent/object identity。

现有 regular file 必须 `st_nlink == 1`。symlink、hardlink、FIFO、socket、device 和
`.git/.agents/.codex/.khaos` protected metadata 全部拒绝。更新使用同目录临时文件，先
flush/fsync，再通过平台原子 exchange 替换；create/copy/rename 使用 no-replace 语义，
竞争者目标不得被覆盖。平台无法提供所需 dirfd/no-follow/atomic primitive 时 fail closed。

用户配置不属于 TaskWorkspace，但写协议同样改为 0600 同目录随机临时文件、file fsync、
dirfd rename、directory fsync；既有 config 若不是 single-link regular file 则拒绝。

## 不变量

- Agent 文件路径必须能词法归属 active workspace，绝对路径不扩大权限；
- 检查后 parent rename/symlink swap 不能把实际 syscall 引向 workspace 外；
- hardlink 不能把 workspace 写权限转换为 workspace 外 inode 写权限；
- protected metadata 对普通文件工具始终只读；
- patch/multi-edit 读取与写入使用同一固定 root capability；
- 失败时不保留未同步临时文件，也不静默回退到 `Path.write_text`。

## 平台边界

当前实现依赖 Python 平台提供 `dir_fd`、`O_NOFOLLOW`、目录 fsync，以及 macOS
`renameatx_np(RENAME_SWAP)` 或 Linux `renameat2(RENAME_EXCHANGE)`。Windows 尚无等价
实现，因此与 Execution backend 一致，应报告 unsupported，而不是使用普通路径 fallback。

## 回滚

不得回滚到 PathGuard 预检查后直接 open/write。出现兼容问题时可以将特定工具标记为
不可用，但不能为 Coding 模式恢复不受 dirfd 约束的实现。
