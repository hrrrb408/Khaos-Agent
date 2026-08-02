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

# 局域网/生产 smoke：这里生成短期自签名证书；真实生产请换成受信任证书
bash scripts/generate-dev-cert.sh
docker compose -f compose.prod.yaml up --build --wait

# 本地
pip install -e .
khaos start
```

`docker-compose.yml` 与 `compose.dev.yaml` 是等价的本机开发入口；默认只使用
loopback、仍强制 API key、project root 和 Python capability。生产入口必须使用
`compose.prod.yaml`，它绑定 `0.0.0.0:8443`、强制 TLS、API key、精确 Host allowlist
和 Docker secret 文件；不要通过修改 Gateway 参数关闭这些检查。Docker 中 Python
固定为 UID 10001 且没有 kernel capability；Gateway 固定为 UID 10002、只读根文件系统、
只读 Agent runtime volume、无 capability 且不共享 Agent 的 PID namespace；Agent UDS
通过 root-group setgid 父目录与显式 Gateway UID/GID 校验提供最小 RPC 通道；root helper 是 netns/veth/nft/cgroup
的唯一 authority，并通过独立只读 socket volume 与 agent 通信。Linux 原生部署先
审查并以 root 执行 `scripts/install-native-tcb.sh`，再启用 systemd 服务。不支持的
Windows sandbox 路径明确拒绝执行，不回退 Host，也不报告 isolated。详细边界见
`docs/browser-threat-model.md`、`docs/platform-security-guarantees.md` 和
`docs/security-platform-support.md`。当前 API key 是单实例本地控制面认证，不是多租户隔离。

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
├── rust/khaos-core/    # 高性能模块（可选）
├── prompts/            # System Prompts
├── docs/               # 设计文档
└── tests/              # 集成测试
```

## 协议

MIT
