# VulnHunter — AI漏洞挖掘系统

基于 AI 的自动化渗透测试平台。五阶段外科医生模式：**威胁建模 → 精准打击 → 深挖反思 → Bypass → 深度验证**。

## 特性

- **黑板架构** — 五分区持久化记忆（攻击面/已验证/待验证假设/利用原语/失败记录），避免重复探测
- **模型分级** — 按阶段自动切换模型（强模型做建模和验证，快模型做打击），控制成本
- **结果验证铁律** — FINDING 必须有真实 curl 请求证据，模型自述不算数
- **连续无发现自动收敛** — 连续 N 轮无新发现自动停止，不烧 Token
- **首次启动引导** — 浏览器内填 API Key 即可使用，无需编辑配置文件
- **AI工具执行** — AI 自主执行 curl/脚本/文件操作（Anthropic Tool Use API）
- **多模型支持** — Anthropic Claude / OpenAI / DeepSeek / Qwen / GLM 等 OpenAI 兼容 API
- **实时流式输出** — WebSocket 推送 AI 测试过程和工具执行结果
- **安全沙箱** — 命令执行内置危险操作拦截，文件写入限制在会话目录
- **并发会话** — 同时对多个目标进行测试
- **Docker 部署** — 一条命令启动

## 快速开始

### 方式一：克隆运行

```bash
git clone https://github.com/1nceSec/vulnhunter.git
cd vulnhunter
pip install -r requirements.txt
python app.py
```

浏览器打开 *http://127.0.0.1:8899*，首次打开会引导配置 API Key。

### 方式二：Docker

```bash
docker run -d -p 8899:8899 -v vulnhunter-data:/app/data ox1dq/vulnhunter
```

### 方式三：Windows 双击启动

```
1. 下载并解压
2. 双击 start.bat
3. 浏览器打开 http://127.0.0.1:8899
```

## 配置

### .env 文件

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `ANTHROPIC_API_KEY` | API Key（首次启动在浏览器中配置） | - |
| `MODEL` | 默认模型 | claude-sonnet-4-20250514 |
| `MODEL_STRONG` | 强模型（建模/验证阶段） | claude-opus-4-20250514 |
| `MODEL_FAST` | 快模型（打击阶段） | claude-haiku-4-5-20251001 |
| `MAX_TOKENS` | 最大输出 token | 16384 |
| `BURP_PROXY` | Burp 代理地址 | http://127.0.0.1:8080 |
| `MAX_CONCURRENT` | 最大并发会话数 | 3 |
| `INACTIVITY_TIMEOUT` | 无活动超时（秒） | 600 |
| `MAX_TURNS` | 最大对话轮次 | 200 |
| `NO_FINDING_STOP` | 连续无发现停止轮次 | 8 |
| `HOST` | 监听地址 | 127.0.0.1 |
| `PORT` | 监听端口 | 8899 |

### Web 界面设置（运行时可改）

点击右上角 **Settings** 按钮：

- **Provider** — 选择 Anthropic 或 OpenAI 兼容模式
- **Model** — 模型名称（如 `claude-sonnet-4-20250514`、`deepseek-chat`、`gpt-4o`）
- **API Key** — 运行时更换 Key
- **Base URL** — OpenAI 兼容 API 地址（如 `https://api.deepseek.com/v1`）
- **Burp 代理** — Burp Suite 代理地址
- **最大并发** — 同时运行的会话数

### Skill 编辑

点击右上角 **Skill** 按钮，在线编辑核心技能文件（SKILL.md）。修改后新建的测试会话会使用更新后的 Skill。

## 使用 OpenAI 兼容模型

在 Settings 中：
1. Provider 选择 `OpenAI / 兼容API`
2. 填入 Base URL 和 API Key
3. 填入模型名称

| 模型 | Base URL | Model |
|------|----------|-------|
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Qwen | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-max` |
| GLM | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-plus` |
| Ollama 本地 | `http://127.0.0.1:11434/v1` | `llama3.1` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |

> 注意：非 Claude 模型的测试效果取决于模型自身的安全知识和推理能力。

## 项目结构

```
vuln-hunter/
├── app.py              # FastAPI 主应用（REST API + WebSocket）
├── engine.py           # AI 工作引擎（会话循环 + 工具调用 + 模型分级）
├── llm.py              # LLM 抽象层（Anthropic Tool Use + OpenAI 兼容）
├── tools.py            # 工具沙箱（命令执行/文件读写/黑板读写 + 安全拦截）
├── db.py               # SQLite 数据库（含黑板五分区表）
├── events.py           # WebSocket 事件总线
├── prompt.py           # 提示词构建器（含黑板协议 + 验证铁律）
├── settings.py         # 运行时设置管理
├── config.py           # 环境变量配置
├── Dockerfile          # Docker 部署
├── requirements.txt    # Python 依赖
├── .env.example        # 配置模板
├── start.bat           # Windows 一键启动
├── start.sh            # Linux 一键启动
├── templates/
│   ├── index.html      # 前端仪表盘
│   └── setup.html      # 首次启动引导页
├── static/             # 静态资源
└── data/               # 运行时数据（自动创建）
```

## API

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/` | 前端仪表盘（首次进入为引导页） |
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
| GET | `/api/settings` | 获取设置 |
| PUT | `/api/settings` | 更新设置 |
| GET | `/api/skill` | 获取 Skill 内容 |
| PUT | `/api/skill` | 更新 Skill 内容 |
| WS | `/ws/{id}` | WebSocket 实时推送 |

## 与 CLI 模式的关系

| | CLI 交互模式 | VulnHunter Web |
|--|-------------|----------------|
| 工具 | Burp MCP + 文件操作 + 全套 | curl/脚本执行（Tool Use API）+ 文件读写 |
| 交互 | 手动对话 | AI 自动循环 + 工具自主调用 |
| 适合 | 单目标深度挖掘 | 多目标并发、挂机跑 |
| Skill | 共享同一个 SKILL.md | 共享同一个 SKILL.md（Web可在线编辑） |

两者可以并行使用，互不影响。
