<div align="center">

# VulnHunter

**AI 驱动的自动化渗透测试平台**

中文 | [English](README.md)

[![GitHub release](https://img.shields.io/github/v/release/1nceSec/vulnhunter)](https://github.com/1nceSec/vulnhunter/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## 这是什么？

VulnHunter 是一个 AI 自主渗透测试系统。给它一个 URL，它会自动完成 JS 分析、接口发现、漏洞利用和报告生成。

五阶段「外科手术」模式：**威胁建模 → 精准打击 → 深度反思 → 绕过探索 → 深度验证**

> 本项目通过 AI Vibe Coding 构建，架构设计参考了 [LuaN1aoAgent](https://github.com/Viper373/LuaN1aoAgent)（Planner-Executor-Reflector 模式）。

## 核心特性

- **黑板架构** — 五分区持久化记忆（攻击面 / 已验证发现 / 待验证假设 / 利用原语 / 失败记录），避免重复探测
- **34 个漏洞知识库** — 覆盖 IDOR、SQLi、XSS、SSRF、RCE、JWT、GraphQL、WebSocket 等主流漏洞类型，特征匹配自动加载测试模块
- **模型分级** — 按阶段自动切换模型（强模型做建模和验证，快模型做打击），控制成本
- **验证铁律** — 所有漏洞发现必须有真实 curl 请求证据，模型自述「我认为」不算数
- **多视角轮转** — 6 个分析视角覆盖 4 个阶段，像一个专家团队系统化覆盖
- **自动收敛** — 连续 N 轮无新发现自动停止，不浪费 token
- **浏览器引导** — 首次启动在浏览器填写 API Key，无需手动编辑配置文件
- **多模型支持** — Anthropic Claude / OpenAI / DeepSeek / 通义千问 / 智谱 GLM 及任何 OpenAI 兼容 API
- **实时推送** — WebSocket 实时展示 AI 测试过程和工具执行结果
- **安全沙箱** — 内置危险命令拦截 + 文件写入路径限制
- **并发会话** — 同时测试多个目标
- **Docker 部署** — 一条命令启动

## 快速开始

### 方式一：克隆运行

```bash
git clone https://github.com/1nceSec/vulnhunter.git
cd vulnhunter
pip install -r requirements.txt
python app.py
```

浏览器打开 **http://127.0.0.1:8899**，首次访问会引导你填写 API Key。

### 方式二：Docker（推荐）

```bash
# 拉取并启动
docker run -d \
  --name vulnhunter \
  -p 8899:8899 \
  -v vulnhunter-data:/app/data \
  ox1dq/vulnhunter:latest

# 打开浏览器
# http://127.0.0.1:8899

# 查看日志
docker logs -f vulnhunter

# 停止 / 删除
docker stop vulnhunter
docker rm vulnhunter
```

**Docker Compose（可选）：**

```yaml
# docker-compose.yml
version: '3.8'
services:
  vulnhunter:
    image: ox1dq/vulnhunter:latest
    ports:
      - "8899:8899"
    volumes:
      - vulnhunter-data:/app/data
    restart: unless-stopped

volumes:
  vulnhunter-data:
```

```bash
docker compose up -d
```

### 方式三：Windows 双击启动

```
1. 从 Releases 下载 ZIP 并解压
2. 双击 start.bat
3. 浏览器打开 http://127.0.0.1:8899
```

## 配置说明

### 环境变量（.env）

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | API Key（首次启动通过浏览器配置） | - |
| `MODEL` | 默认模型 | claude-sonnet-4-20250514 |
| `MODEL_STRONG` | 强模型（建模/验证阶段） | claude-opus-4-20250514 |
| `MODEL_FAST` | 快模型（打击阶段） | claude-haiku-4-5-20251001 |
| `MAX_TOKENS` | 最大输出 token | 16384 |
| `BURP_PROXY` | Burp 代理地址（可选） | http://127.0.0.1:8080 |
| `MAX_CONCURRENT` | 最大并发会话数 | 3 |
| `MAX_TURNS` | 最大对话轮次 | 200 |
| `NO_FINDING_STOP` | 连续无发现自动停止轮次 | 8 |
| `HOST` | 监听地址 | 127.0.0.1 |
| `PORT` | 监听端口 | 8899 |

### Web 设置（运行时）

点击右上角 **Settings** 可以在运行时修改：提供商、模型、API Key、Base URL、Burp 代理、并发数。

### Skill 编辑器

点击 **Skill** 可在线编辑核心策略文件（SKILL.md），新会话将使用更新后的策略。

## 多模型支持

| 提供商 | Base URL | 模型 |
|--------|----------|------|
| Anthropic | *（默认）* | `claude-sonnet-4-20250514` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-max` |
| 智谱 GLM | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-plus` |
| Ollama | `http://127.0.0.1:11434/v1` | `llama3.1` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |

> 注意：非 Claude 模型的效果取决于模型自身的安全知识和推理能力。

## 工作流程

```
输入: https://target.com

阶段1: 威胁建模（强模型）
  视角: 攻击面侦察 → curl 抓页面、探测敏感路径、收集接口
  视角: JS 逆向分析 → 下载 JS、搜索硬编码密钥/凭证

阶段2: 精准打击（快模型）
  视角: 未授权探测  → 逐个接口测试无认证访问
  视角: 漏洞利用构造 → 对假设构造 PoC，用真实请求验证

阶段3: 绕过探索
  视角: 绕过 403   → 路径截断、参数污染、UA 欺骗...

阶段4: 深度验证（强模型）
  视角: 深度验证   → 评估真实影响、扩大攻击面

连续 N 轮无新发现自动停止
```

## 项目结构

```
vulnhunter/
├── app.py              # FastAPI 应用（REST API + WebSocket）
├── engine.py           # AI 引擎（会话循环 + 工具调用 + 模型分级）
├── llm.py              # LLM 抽象层（Anthropic Tool Use + OpenAI 兼容）
├── tools.py            # 工具沙箱（命令执行 / 文件读写 / 黑板 + 安全拦截）
├── db.py               # SQLite 数据库（含黑板五分区表）
├── events.py           # WebSocket 事件总线
├── prompt.py           # Prompt 构建器（黑板协议 + 验证铁律 + 知识库索引）
├── settings.py         # 运行时配置
├── config.py           # 环境配置
├── Dockerfile          # Docker 部署
├── knowledge/          # 34 个漏洞知识库模块（IDOR/SQLi/XSS/SSRF/RCE...）
├── templates/
│   ├── index.html      # 控制面板
│   └── setup.html      # 首次启动引导
└── data/               # 运行时数据（自动创建）
```

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 控制面板（首次访问显示引导页） |
| POST | `/api/setup` | 首次配置 API Key |
| POST | `/api/sessions` | 创建测试会话 |
| GET | `/api/sessions` | 列出所有会话 |
| GET | `/api/sessions/{id}` | 获取会话详情 |
| POST | `/api/sessions/{id}/stop` | 停止会话 |
| DELETE | `/api/sessions/{id}` | 删除会话 |
| POST | `/api/sessions/{id}/input` | 发送用户消息 |
| GET | `/api/sessions/{id}/findings` | 获取漏洞列表 |
| GET | `/api/sessions/{id}/blackboard` | 获取黑板内容 |
| GET | `/api/sessions/{id}/blackboard/summary` | 黑板五分区统计 |
| GET | `/api/sessions/{id}/logs` | 获取对话日志 |
| GET | `/api/sessions/{id}/report` | 导出 Markdown 报告 |
| GET | `/api/settings` | 获取设置 |
| PUT | `/api/settings` | 更新设置 |
| WS | `/ws/{id}` | WebSocket 实时推送 |

## 致谢

- [LuaN1aoAgent](https://github.com/Viper373/LuaN1aoAgent) — 架构灵感来源（Planner-Executor-Reflector 模式）

## 许可证

MIT
