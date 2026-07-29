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
# Docker
export KHAOS_PYTHON_CAPABILITY="$(openssl rand -hex 32)"
export KHAOS_BROWSER_HELPER_SECRET="$(openssl rand -hex 32)"
docker compose up -d

# 本地
pip install -e .
khaos start
```

普通启动采用 secure production behavior；只有显式 `KHAOS_DEV_MODE=1` 才允许开发
fallback。Docker 中 Python 固定为 UID 10001 且没有 kernel capability；root helper
是 netns/veth/nft/cgroup 的唯一 authority，并通过独立只读 socket volume 与 agent
通信。Linux 原生部署先审查并以 root 执行 `scripts/install-native-tcb.sh`，再启用
`khaos-agent.service` 和 `khaos-browser-kernel-helper.service`。不支持的 Windows
sandbox 路径明确拒绝执行，不回退 Host，也不报告 isolated。详细边界见
`docs/browser-threat-model.md` 和 `docs/platform-security-guarantees.md`。

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
