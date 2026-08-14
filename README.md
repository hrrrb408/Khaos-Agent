# Khaos（混沌）

通用 AI Agent 平台 — 双模式（Office + Coding），多模型路由，子代理编排。

## 架构

- **Python**：Agent 核心循环、工具系统、记忆/技能/审计、安全中间件
- **Go**：API 网关（REST/SSE/Subagent API）
- **Rust**：token/并行执行，以及 Linux production 必需的 sandbox launcher 与
  browser kernel helper

## 功能

- 🔧 双模式切换：Office（通用）+ Coding（agentic coding）
- 🧠 三层记忆系统：TTL + 冲突解决 + 主动提取
- 🔐 安全中间件：命令注入检测、路径遍历防护、敏感信息扫描
- 🤖 子代理编排：任务拆分、DAG 调度、并行执行
- 🛠️ 40+ 工具：文件、终端、浏览器、搜索、笔记、剪贴板、Markdown
- 📊 可观测性：审计日志、请求指标、权限管理
- 🌐 API 网关：REST + SSE + 统一认证和速率限制

## 快速开始

```bash
# Docker（本机开发：只绑定 127.0.0.1，不提供跨主机 HTTP）
cp .env.example .env
mkdir -p .secrets
openssl rand -hex 32 > .secrets/python-capability
openssl rand -hex 32 > .secrets/browser-helper-secret
openssl rand -hex 32 > .secrets/gateway-api-key
chmod 0400 .secrets/*
docker compose -f compose.dev.yaml up --build --wait

# 查看本机健康状态（健康端点匿名，但仍使用 API key 验证认证链路）
curl -H "X-Khaos-Key: $(cat .secrets/gateway-api-key)" http://127.0.0.1:8080/api/health

# 生产安全组合验证（真实 authorityd + HTTPS WORM + bwrap + 收据结果）
# 该脚本只用于本机/CI 验证，会创建并销毁临时 WORM fixture
bash scripts/compose-security-e2e.sh

# 本地
pip install -e .
khaos start
```

`docker-compose.yml` 与 `compose.dev.yaml` 是等价的本机开发入口；默认只使用
loopback、仍强制 API key、project root 和 Python capability。生产入口必须使用
`compose.prod.yaml`，它绑定 `0.0.0.0:8443`、强制 TLS、API key、精确 Host allowlist
和 Docker secret 文件，并且必须由部署提供编译后的
`KHAOS_EFFECTIVE_POLICY_DIGEST`、HTTPS `KHAOS_AUDIT_WORM_ENDPOINT` 及其 CA 文件；不要
通过修改 Gateway 参数关闭这些检查。Docker 中 Python
固定为 UID 10001 且没有 kernel capability；Gateway 固定为 UID 10002、只读根文件系统、
只读 Agent runtime volume、无 capability 且不共享 Agent 的 PID namespace；Agent UDS
通过 root-group setgid 父目录与显式 Gateway UID/GID 校验提供最小 RPC 通道；root helper 是 netns/veth/nft/cgroup
的唯一 authority，并通过独立只读 socket volume 与 agent 通信。Compose 只把宿主上
预先委派的 cgroup v2 subtree（默认 `/sys/fs/cgroup/khaos-browser`，可用
`KHAOS_BROWSER_HELPER_CGROUP_SOURCE` 覆盖）挂到 helper 的
`/run/khaos-helper/cgroup`；helper 会拒绝普通目录、符号链接或越界 journal，不能把
整个 `/sys/fs/cgroup` 作为读写挂载。
生产 Docker 的 `khaos-agent` 还必须保留 `security_opt: ["seccomp:unconfined", "apparmor:unconfined", "systempaths:unconfined"]`，因为
Docker 默认的 seccomp、AppArmor 和 system-path 约束会阻止 bwrap 创建并固定非特权
namespace/mount 边界；这只是外层容器兼容性要求，不向 Python Agent 授予 `SYS_ADMIN`，
也不能用 Host 回退替代。等价的自定义 profile 必须先通过真实 production composition
probe，否则应 fail closed。Linux 原生部署先
审查并以 root 执行 `scripts/install-native-tcb.sh`，再启用 systemd 服务。不支持的
Windows Coding 执行使用 native helper：只有 helper probe、token/AppContainer、Job
Object、ACL 与 WFP 证据全部通过才执行；失败时拒绝，不回退 Host，也不报告
isolated。Windows 文件工具若缺少原生 no-follow handle backend 会直接 fail closed，
不会把 POSIX dirfd 假设伪装成 Windows 隔离。详细边界见
`docs/browser-threat-model.md`、`docs/platform-security-guarantees.md` 和
`docs/security-platform-support.md`。需要把 host execution 提升到独立
authorityd receipt 模式时，部署 `khaos-authorityd` 为独立 OS service，并设置
`KHAOS_REQUIRE_AUTHORITY_RECEIPT=1`、`KHAOS_AUTHORITYD_SOCKET`、
`KHAOS_AUTHORITYD_PUBLIC_KEY_PATH`、`KHAOS_EFFECTIVE_POLICY_DIGEST` 与远端审计
endpoint；authorityd 只签发与自身编译 policy digest 相同的收据，缺少任一生产证明时会
fail closed。完整协议见 `docs/authority-control-plane.md`。当前 API key 是单实例本地控制面认证，不是多租户隔离。
安全事实的机器可读来源是 `docs/security_facts.yaml`。

## 开发

```bash
# 运行测试
khaos test --all

# 单独运行
python -m pytest python/tests/ -x --ignore=python/tests/tui
cd go && go test ./...
```

## 项目结构

```text
khaos/
├── python/khaos/       # Agent 核心
├── go/                 # API 网关
├── rust/khaos-core/    # 安全关键 TCB launchers/helpers + 性能模块
├── prompts/            # System Prompts
├── docs/               # 设计文档
└── tests/              # 集成测试
```

## 协议

MIT
