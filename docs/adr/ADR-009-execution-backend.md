# ADR-009：统一 ExecutionBackend 与安全拒绝

## 状态

已接受（Phase 0；Batch B1–B7 于 2026-07-15 完成首轮安全收敛）。

## 决策

终端、测试和沙箱工具统一通过 ExecutionBackend。Agent 发起的 `read-only` 和
`workspace-write` 请求都必须绑定 active TaskWorkspace，并携带 versioned、不可变
的 `PermissionProfile`。profile 是 filesystem、network、workspace roots、宿主
不可读 secret roots、environment allowlist 和 resource budget 的唯一执行权威；
旧 `ExecutionRequest` 字段仅作为兼容投影，不能覆盖显式 profile。

后端不可用或无法强制请求的网络策略时拒绝执行，不回退到裸 `subprocess` 或 Host
backend。默认网络策略为 `none`。默认环境不传递 `HOME`，并隐藏 `.ssh`、`.gnupg`、
`.aws`、`.kube`、gcloud credentials 和 macOS Keychains；需要临时 HOME 的固定工具
必须显式创建隔离目录并写入 profile。

所有 Agent-owned 前台进程、managed stdio 进程以及 Docker CLI 前台执行统一登记到
`ProcessSupervisor`。每个进程使用独立 process group/session；正常退出、外部取消、
task cancellation、timeout 和 service shutdown 都必须经过同一注册表。终止顺序固定为
process-group `SIGTERM`、有限 grace period、仍存活时 `SIGKILL`，禁止只杀父进程。

stdout/stderr 必须在进程运行期间并发 drain，各自取得总输出预算的一半，防止单一流
抢占全部内存或 pipe 回压死锁。超限字节只计数并丢弃，返回 dropped-byte diagnostics；
不得把未截断完整输出写入宿主 artifact 形成配额旁路。Docker backend 仅负责容器策略
和清理，不再拥有另一套 communicate/截断实现。
前台与 managed/LSP 进程共用 aggregate process-group PID/memory watchdog；
macOS 与 managed/LSP 的整个合成 HOME（包括 TMP）由同一 watchdog 统计 regular-file
bytes 与 filesystem entries，任一超过 `tmpfs_bytes` / `filesystem_entries` 即终止
整个 process group。Linux 的 HOME 与 TMP 均使用带 `--size` 的独立 tmpfs，并通过
`/proc/<pid>/root` 计入同一 entries/总字节 watchdog。

TaskWorkspace 另有固定创建时 baseline 的 aggregate storage authority。
`workspace_bytes` 按去重 inode 的 allocated blocks 计算相对增长，`workspace_entries`
按目录项净增长计算；rename 不增加预算，hardlink 只计算一次数据块但计算新增目录项。
`WorkspaceStorageAuthority` 是唯一核算实现，由 WorkspaceManager 持有并注入
ProcessSupervisor。write/patch/multi-edit/copy/move 与 journaled Planned Mutation 必须
使用同一 authority；文件工具在 authority 下串行执行，
修改后立即核算；超限时使用 identity-bound rollback，回滚对象被并发替换时不得覆盖，
而是 quarantine。进程无论运行多久，退出后都必须执行最终 snapshot，快速退出不能绕过。
snapshot 至少两次完整且 path/inode view 稳定；遍历错误、不可读目录、root identity 漂移
或持续 rename/delete churn 全部 fail closed。无法安全回滚的 violation 必须强制清理
disposable Worktree；清理失败时保持 FAILED。Docker bind mount 也必须使用该 authority。

目录 Snapshot 之外，ProcessSupervisor 还必须统计同 process group 中已经 unlink 但仍
持有 fd 的 regular file；Linux 通过 `/proc/<pid>/fd`，macOS 通过 `lsof +L1`。无法完整
观察时 fail closed。Docker payload 由固定、不可由调用方覆盖的容器内 supervisor 扫描
PID namespace 的 deleted fd，并同时设置 fsize/nofile ulimit；超过 Workspace budget
返回 `resource-exhausted`。这些检查覆盖目录扫描不可见的瞬时磁盘占用。

文件工具 mutation 在线程中执行时，调用方 timeout/cancel 不得释放 Workspace fence。
Runtime 使用 `shield` 等待 authority 完成 commit 或 rollback 后再传播取消，cleanup 和
下一次 mutation 在此之前均不可进入。普通文件读取、patch 和 snapshot 具有 16 MiB
硬上限，读取前检查 `fstat` 且流式读取过程中再次累计；copy 使用 bounded streaming。
rollback before-state 写入 Workspace 外权限 0700 的 authority recovery root，文件 0600，
不再把完整原文件保存在 Runtime heap，成功、失败或 rollback 后均删除 recovery artifact。

Linux backend 的 capability probe 与真实执行必须使用同一 bwrap mount/namespace
拓扑：宿主 `/` 只读、独立 `/dev`、新 `/proc`、受控 `/tmp`、唯一 workspace bind，
并隔离 network/PID/IPC/UTS，创建新 session 且启用 die-with-parent。sandbox cwd 由请求
cwd 相对 worktree 的路径确定，越界直接拒绝。probe 的 timeout、OS error 或内部异常均
转换为 unavailable；selector 对 read-only 和 workspace-write 一律 fail closed。

macOS selector 同样必须实际启动 `/usr/bin/sandbox-exec`，证明 workspace write 成功、
workspace 外 write、network、pasteboard 与 Keychain IPC 失败后才返回 backend。
Seatbelt 不得使用全局 `allow mach-lookup`，只允许显式的最小运行时 service
allowlist；只检查可执行文件存在不构成
capability。Windows 在没有受支持的 OS 强制 backend 前显式返回 unsupported，并在错误
中保留平台原因，未知平台同样拒绝。

Docker allowlist 只接受 `@sha256:` 固定镜像，运行使用 `--pull never`、只读 rootfs、
受限 tmpfs、非 root、drop-all capabilities、no-new-privileges、none network/IPC 和资源
配额。每个容器带随机 owner nonce label；stop/kill/rm 前必须 inspect 并精确匹配 nonce，
防止容器名冲突导致删除宿主现有容器。worktree mount 参数拒绝逗号/换行/NUL，所有
Docker CLI 进程也由 supervisor 管理。真实 Docker destructive lifecycle 测试只在干净
CI runner 执行。

`cpu_count` 只在具备 native quota controller 的 Docker backend 表示核心配额；POSIX
host backend 不伪装成核心数限制，改用独立 `cpu_time_seconds` 驱动 `RLIMIT_CPU`，并在
diagnostics 明确报告 `cpu_quota_enforced=false`。

## 原因

逻辑权限、Worktree 边界、OS/Docker 隔离、资源限制和审计必须形成纵深防御。

## 替代方案

- 每个工具自行启动进程：安全策略容易漂移。
- 后端不可用时裸执行：会把“无法隔离”错误地变成“允许写入”。

## 回滚与兼容

保留旧工具入口，通过适配器把旧字段规范化为 v1 profile。兼容只发生在数据入口，
不保留旧 executor：任何受限请求都必须选择可证明的 OS backend，否则得到结构化
拒绝。`full-access` 在 principal-bound approval capability 完成前不开放。
