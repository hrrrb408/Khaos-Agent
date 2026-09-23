# ADR-089: macOS Local-First Runtime

## 状态

已接受，第一阶段实施中。

## 背景

普通单用户 Coding 不应因为生产级 Linux 执行节点、authorityd、Go
Gateway 或浏览器内核尚未部署而无法启动。此前 CLI/TUI 直接使用
`ProductionRuntimeConfig`，把本地 Coding 与生产 authority/catalog handshake
绑定在了一起。

## 决策

新增显式 `RuntimeProfile.LOCAL`，作为 macOS 单用户 CLI/TUI 的默认组合。

Local 保留以下安全边界：

- Workspace / SafeWorkspaceFS 与 EditTransaction；
- Permission / Approval / CredentialBroker；
- ExecutionService 与 macOS Seatbelt 能力探针；
- Verification / Repair / CompletionGate；
- 本地 SQLite 状态与审计。

Local 不在启动时构造以下可选或服务端能力：

- 独立 production authorityd 与 typed resource catalog handshake；
- Go Gateway、远程审计、多用户 RPC 与多通道服务；
- Linux cgroup、bwrap、AppArmor 与浏览器内核 helper；
- Playwright / BrowserCodingService。

浏览器 Coding 不是 Local 的隐式 fallback。后续通过显式 Secure Runtime
连接 Linux VM 或远程执行节点；在 Secure Runtime 完成前，Local 浏览器能力应
返回不可用，而不是伪装成已隔离。

## 安全语义

Local 防护的是模型、Prompt、仓库内容导致的越权工具调用和工作区外写入。
它不宣称能够抵御同一操作系统用户下的恶意原生进程或已被攻陷的宿主机。
该信任模型必须在诊断与文档中明确显示。

`ProductionRuntimeConfig`、production RPC 和 `khaos start` 的生产路径保持
不变；Local 不是 `KHAOS_DEV_MODE=1` 的别名，也不是 production 的静默降级。

## 验收

在 macOS 上，未安装 Go/Cargo、未启动 systemd/authorityd、未配置 Linux
cgroup/bwrap、未安装 Playwright 时，以下路径应能完成普通 Coding：

```text
khaos setup  # 等价于 khaos config setup
 -> khaos chat --mode coding --unlock <provider>
 -> Workspace / EditTransaction / Permission / Execution / Verification
```
