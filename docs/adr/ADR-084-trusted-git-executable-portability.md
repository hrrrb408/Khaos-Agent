# ADR-084: Separate Trusted Git location, trust policy, and operational preflight

状态：accepted

日期：2026-09-04

## 背景

WorkspaceManager 过去把宿主 Git 固定为单一 POSIX 路径。macOS 的 `/usr/bin/git`
可能因为 Xcode license gate 无法启动，而同一主机上已安装的 Command Line Tools
Git 可以正常工作。直接读取 caller `PATH` 或把任意用户安装的 Git 当作 fallback
会扩大 control-plane 的信任边界，也会让测试把“环境阻断”误报成产品失败。

## 决策

新增三个独立的、可审计的边界：

- `TrustedGitLocator` 只返回平台静态候选，不查 `PATH`；生产 macOS 候选是系统
  Git 后的 Command Line Tools Git，Linux 和 Windows 保持既有固定候选集合。
- `TrustedGitExecutablePolicy` 对每个候选执行 root-owner、mode、父链、no-follow
  descriptor、file identity 和 SHA-256 检查，并在 spawn 前重新验证。
- `TrustedGitProcessOwner` 管理一次性 `git --version` preflight。preflight 结果按
  path + identity + digest 缓存；macOS Xcode/Apple SDK 环境阻断单独分类为
  `ENVIRONMENT_BLOCKED`，只允许下一个静态候选重新通过完整 policy/preflight。

`TrustedGitRunner` 仍是唯一 Git effect/authority owner，继续消费 ADR-043 中唯一的
`TrustedGitProcessOwner`，并在每条异步及启动恢复 spawn 路径前确保 preflight。任何
候选都不能绕过 effect/CAS、argv allowlist、环境 scrub 或执行前身份复核。

## 后果

- macOS 开发机不需要把 Xcode license gate 错报为代码回归；可用的系统级 CLT Git
  能被明确选中。
- 可信候选集合不会因用户 `PATH`、Homebrew 或仓库内容而扩大。
- required Trusted Git 集成测试在本地环境阻断时有明确 skip 分类，但 CI 阻断会
  fail；安全契约测试继续独立运行。
- `khaos doctor trusted-git` 提供与运行时同源的有界诊断；不提供修改系统许可的
 自动化操作。
