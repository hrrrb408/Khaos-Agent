# 跨平台安全 CI 与真实 Sandbox 门禁

状态：Closure gate 已实现；本 PR 最新 head 的远端 runner 证据待完成。
旧提交的通过结果不得替代当前 head。

## 门禁分层

| Check | Runner | 证明内容 | 不证明的内容 |
| --- | --- | --- | --- |
| `Security Contract Matrix / contract` | Ubuntu 24.04、Windows 2025、macOS 14 | Approval、turn、permission profile、Office read/write Sandbox path、durable webhook replay/限流隔离、workspace mutation-wide storage authority、mutation cancel fence、deleted fd accounting、Git identity、快速退出最终核算、遍历错误/churn fail-closed、Gateway/RPC、managed resource、TUI、Go/Rust；POSIX 额外验证 Verification Authority、Office nested-object rejection 与 dirfd workspace boundary | 真实 OS 隔离 |
| `Platform Sandbox Security E2E / linux-bwrap-security` | Ubuntu hosted runner | bwrap workspace-write/read-only、`.git` pointer read-only、禁网、secret root、PID/process tree、HOME/TMP size 与 entry budget、TaskWorkspace 相对 entry budget、无 Host fallback | Windows sandbox |
| `Platform Sandbox Security E2E / macos-sandbox-security` | macOS hosted runner | sandbox-exec workspace-write、`.git`/case alias write denial、外部写拒绝、禁网、secret root、pasteboard/Keychain IPC、whole-HOME 与 TaskWorkspace 相对 byte budget 拒绝 | Linux namespace |
| `Platform Sandbox Security E2E / windows-fail-closed-security` | Windows hosted runner | 未实现 native backend 时明确 Unsupported，执行和 dirfd mutation 都拒绝 | Windows 可执行 sandbox；当前产品不宣称支持 |
| `Docker Security E2E / docker-isolation` | Ubuntu + Docker | digest-pinned image、network none、read-only root、非 root、`.git` readonly mount、deleted-open-file PID namespace watchdog、资源限制、timeout/cancel/shutdown cleanup、Trusted Verification secret/output 边界 | 非容器宿主策略 |
| `Security Closure Gate` | reusable workflow 聚合 | 上述真实平台矩阵、Python security、Go race、Rust test/clippy、供应链、schema fuzz、authorization drift、process lifecycle、event-loop starvation 全部成功，并生成 commit-bound Security Evidence Artifact | 绝对安全；未支持平台的功能可用性 |

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

在 GitHub branch protection 中把单一 `Security Closure Gate` job 设为 required；细分 job
仍保留用于定位失败，但不得代替聚合 gate。首次推送后，应保存每个 job 的 run URL、runner image/version、artifact digest 和结论到审计记录。runner image 会
随 GitHub 更新，因此 Actions 结果是“该次运行”的证据，不是永久的平台认证。

## 历史远端验证证据（仅作基线）

| Workflow run | 结论 | 覆盖 |
| --- | --- | --- |
| [Security Contract Matrix #29543446973](https://github.com/hrrrb408/Khaos-Agent/actions/runs/29543446973) | PASS | merge SHA 上 Ubuntu 24.04、macOS 14、Windows 2025 的 Python/Go/Rust 合同；POSIX 文件系统边界 |
| [Platform Sandbox Security E2E #29543447066](https://github.com/hrrrb408/Khaos-Agent/actions/runs/29543447066) | PASS | merge SHA 上 Linux bwrap、macOS sandbox-exec、Windows fail-closed |
| [Docker Security E2E #29543447054](https://github.com/hrrrb408/Khaos-Agent/actions/runs/29543447054) | PASS | merge SHA 上 Docker 与 Trusted Verification 真实隔离 |

以上结论只绑定历史提交；本 Closure 必须等待 PR 最新 head 的 `Security Closure Gate`
以及 `security-evidence-<sha>` artifact，不得沿用旧证据。

## 本地与远端边界

开发者本机只需运行 mock/host-local contract。Linux、Windows 与 macOS 的权威平台结论
来自 GitHub-hosted runner；Docker 结论来自 Ubuntu runner 的真实 daemon。生产发布仍需在
最终部署镜像/内核上再运行一次真实 Sandbox gate。
