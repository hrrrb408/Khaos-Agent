# Khaos（混沌）

通用 AI Agent 平台 — 双模式（Office + Coding），多模型路由，子代理编排。

## 架构

- **Python**：Agent 核心循环、工具系统、记忆/技能/审计、安全中间件
- **Go**：API 网关（REST/SSE/Subagent API）
- **Rust**：高性能 token 计数与并行执行（可选）

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
docker compose up -d

# 本地
pip install -e .
khaos start
```

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
