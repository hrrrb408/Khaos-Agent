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
