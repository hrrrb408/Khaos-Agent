# 跨平台安全 CI 与真实 Sandbox 门禁

状态：已实现，等待远端 runner 生成首轮证据。日期：2026-07-15。

## 门禁分层

| Check | Runner | 证明内容 | 不证明的内容 |
| --- | --- | --- | --- |
| `Security Contract Matrix / contract` | Ubuntu 24.04、Windows 2025、macOS 14 | Approval、turn、permission profile、Gateway/RPC、TUI view model、Go/Rust；POSIX 额外验证 dirfd workspace boundary | 真实 OS 隔离 |
| `Platform Sandbox Security E2E / linux-bwrap-security` | Ubuntu hosted runner | bwrap workspace-write/read-only、禁网、secret root、PID/process tree、无 Host fallback | Windows sandbox |
| `Platform Sandbox Security E2E / macos-sandbox-security` | macOS hosted runner | sandbox-exec workspace-write、外部写拒绝、禁网、secret root | Linux namespace |
| `Platform Sandbox Security E2E / windows-fail-closed-security` | Windows hosted runner | 未实现 native backend 时明确 Unsupported，执行和 dirfd mutation 都拒绝 | Windows 可执行 sandbox；当前产品不宣称支持 |
| `Docker Security E2E / docker-isolation` | Ubuntu + Docker | digest-pinned image、network none、read-only root、非 root、资源限制、timeout/cancel/shutdown cleanup、Trusted Verification secret/output 边界 | 非容器宿主策略 |

Windows 当前的安全承诺是 **fail closed**，不是功能可用。没有 AppContainer/Job Object 等经
真实 runner 验证的 native backend 前，Coding command execution 和依赖 dirfd 的 mutation
必须拒绝，绝不切换到 Host subprocess。

## Supply-chain 规则

- workflow 只授予 `contents: read`，checkout 不持久化 credential；
- 所有外部 Action 固定 40 位 commit SHA，旁注版本仅用于人工阅读；
- Dependabot 每周提出 GitHub Actions、Python、Go、Rust 更新，升级 SHA 必须经过同一矩阵；
- 禁止 `continue-on-error`、能力缺失时的 Host fallback，以及把真实 Sandbox 测试替换成 mock；
- diagnostics 即使 job 失败也上传，但测试 step 本身保持失败状态。

## 仓库设置

在 GitHub branch protection 中把上述五类 check 设为 required。首次推送后，应保存每个
job 的 run URL、runner image/version、artifact digest 和结论到审计记录。runner image 会
随 GitHub 更新，因此 Actions 结果是“该次运行”的证据，不是永久的平台认证。

## 本地与远端边界

开发者本机只需运行 mock/host-local contract。Linux、Windows 与 macOS 的权威平台结论
来自 GitHub-hosted runner；Docker 结论来自 Ubuntu runner 的真实 daemon。生产发布仍需在
最终部署镜像/内核上再运行一次真实 Sandbox gate。
