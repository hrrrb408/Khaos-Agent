# Trusted Git 平台可移植性与测试边界

Trusted Git 是 Khaos workspace control plane 的宿主依赖。它不是模型可控的
工具，也不是普通的 `PATH` 命令查找：候选位置、文件信任策略、进程生命周期和
Git effect authority 是四个相互独立的责任。

## 运行时选择

`PlatformTrustedGitLocator` 只返回编译期审计过的静态候选，并按固定顺序返回：

| 平台 | 候选顺序 |
| --- | --- |
| macOS | `/usr/bin/git`，`/Library/Developer/CommandLineTools/usr/bin/git` |
| Linux | `/usr/bin/git` |
| Windows | `C:\Program Files\Git\cmd\git.exe` |

候选集合不读取调用者 `PATH`，不包含 Homebrew、当前用户目录或仓库目录中的
`git`。`TrustedGitExecutablePolicy` 对每个候选独立检查绝对规范路径、普通文件、
可信 owner、不可由 group/other 写入的 mode、父目录链，并通过 no-follow 二进制
descriptor 固定 device/inode/mode/owner 和 SHA-256。执行前会再次检查父链、身份和
摘要；身份或内容漂移一律 fail closed。

Windows 不把 POSIX `st_uid`/mode 当作 ACL 证据：仍只接受上表中的 Git 安装路径，
拒绝重解析点，并在固定的 `C:\Program Files\Git` 根及已打开的 Git descriptor 上
检查 Win32 owner/DACL。写权限 allowlist 仅包含 SYSTEM、BUILTIN Administrators
和 TrustedInstaller；ACL 缺失、解析失败或出现其他写入主体时同样 fail closed。

macOS 的 `/usr/bin/git` 可能只是依赖 Xcode 许可状态的系统入口。选中的候选必须
先通过由 `TrustedGitProcessOwner` 管理的、带 stdout/stderr/时间上限的绝对路径
`git --version` preflight。系统入口因 Xcode/Apple SDK 环境阻断时，诊断分类为
`ENVIRONMENT_BLOCKED`，然后才允许下一个静态候选独立通过同一 policy 和 preflight。
这不是对任意 Git 失败的自动 fallback，也不在运行时建议修改系统许可或使用
`sudo`。成功 preflight 按 path、file identity 和 digest 缓存；这些身份变化会使
缓存失效并重新验证。

所有实际 Git 子进程仍由 `TrustedGitProcessOwner` 从 spawn adoption 到 pipe drain、
进程域终止和 terminal proof 统一拥有。Locator 和 preflight 不得创建第二套
subprocess owner。Git runner 继续负责 argv allowlist、禁用 hooks/filters/textconv、
typed effect/CAS authority 和仓库/tree 语义。

## 诊断与测试

维护者可以运行：

```text
khaos doctor trusted-git
khaos doctor trusted-git --json
```

诊断只输出候选、规范路径、owner/mode、父链、身份、摘要和有界 preflight 结果，
不输出调用者环境或 credential。命令仅在至少一个候选完整通过 policy 与 preflight
时返回 0。

需要真实宿主 Git 的集成测试使用 `requires_trusted_git` marker 和 session-scoped
`trusted_git_environment` fixture。开发机遇到已分类的环境阻断时可以显式报告
`TEST_FIXTURE_ENVIRONMENT_BLOCKED` 并跳过；CI 中同一阻断必须失败，不能通过 skip
伪造 required check。locator、policy、PATH 注入、身份/摘要漂移、诊断分类、effect
绑定和进程 owner 的安全契约测试不依赖该集成 fixture，因此即使宿主 Git 不可运行
也必须继续执行。
