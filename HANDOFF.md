# VulnHunter 交接文档

## 项目概况

AI 驱动的自动化渗透测试平台，给一个 URL 自动完成 JS 分析、接口发现、漏洞利用、报告生成。

- GitHub: https://github.com/1nceSec/vulnhunter
- GHCR: ghcr.io/1ncesec/vulnhunter
- 当前版本: v1.3.1
- 技术栈: Python + FastAPI + SQLite + WebSocket + Jinja2 单文件前端

## 版本历史

| 版本 | 核心内容 |
|------|---------|
| v1.0.0 | 基础框架：黑板架构、模型分级、Setup 引导页 |
| v1.1.0 | 伪多 Agent 视角轮转（6 视角 × 4 阶段） |
| v1.1.1 | PoC 提取、报告增强、黑板可视化、工具容错 |
| v1.2.0 | 34 个知识库模块、进站短表、打穿短表、交接文档 API |
| v1.3.0 | 暂停/恢复/终止、任务结束后对话、分组管理、漏洞摘要、搜索筛选 |
| v1.3.1 | 全新 UI（毛玻璃/暗色模式/行内重命名/侧滑面板） |

## 架构关键文件

```
vuln-hunter/
├── app.py          # FastAPI 路由（含 pause/resume/groups/handoff API）
├── engine.py       # AI 引擎（_ai_loop + _chat_session + 暂停 Event）
├── prompt.py       # Prompt 构建（FEATURE_KB_MAP 38条 + CHAIN_RULES 12条 + 6 LENSES）
├── db.py           # SQLite（sessions.group_name + severity_summary 查询）
├── tools.py        # 工具沙箱
├── llm.py          # LLM 抽象层
├── knowledge/      # 34 个漏洞知识库模块（按需加载）
├── templates/
│   ├── index.html  # Apple 风格单页应用（v1.3.1 全新）
│   └── setup.html  # 首次启动引导
└── data/           # 运行时 SQLite + 临时文件
```

## 核心机制

### 五阶段 + 六视角
威胁建模（surface_recon / js_reverse）→ 精准打击（unauth_probe / exploit_craft）→ Bypass（bypass_403）→ 深度验证（deep_verify）

### 黑板五分区
attack_surfaces / verified_findings / pending_hypotheses / exploits / failure_records

### 模型分级
- 强模型（opus）: threat_model / bypass / deep_verify
- 快模型（haiku）: strike
- 默认模型（sonnet）: 其余

### 知识库按需加载
prompt.py 的 FEATURE_KB_MAP（38 条特征→模块映射），AI 在 Phase 1 识别特征后 Phase 2 用 read_file 加载对应 knowledge/*.md

### 打穿短表
CHAIN_RULES 12 条"认 A 打 B"规则，注入 system prompt，AI 确认漏洞后自动联想升级路径

### 任务结束后对话
engine.py 的 `_chat_session()`，CHAT_ALLOWED 6 种状态（need_input/low_roi/stopped/vuln_found/error/paused）均可通过输入框对话

### 暂停/恢复
`_pause_events` 字典存 asyncio.Event，pause 时 clear() 阻塞 _ai_loop，resume 时 set() 恢复

## CLI Skill 状态

`E:\Claude\.claude\skills\pentest-ai-driven\SKILL.md` 已升级到 v5.0：
- 融合 clown-src-6k-skill 方法论（进站短表 + 打穿短表 + 价值矩阵）
- `知识库/` 目录 34 个模块
- 五阶段外科医生模式完整

## 待办 / 延期项

1. **会话恢复（resume）** — 用户想做类似 Claude Code resume 的功能，黑板数据已持久化，handoff API 已有，缺前端入口和恢复流程
2. **任务文件夹** — 按会话创建目录存放下载的 JS/脚本/文档，engine.py 已有 `_session_temp(sid)` 但未暴露给用户
3. **通知集成** — Server酱/企业微信，用户说"不急"
4. **EventBus 重连/回放** — 用户说"先别改，我想想"
5. **真多 Agent** — 用户了解了难点（token/协同），当前用伪多 Agent 视角轮转替代
6. **Docker 镜像更新** — 代码已推 GitHub，Docker Hub 镜像需要重新 build+push

## 账号信息

- GitHub: 1nceSec
- Docker Hub: ox1dq
- gh CLI: `E:\Environment\GitHub CLI\gh.exe`
- Python: `E:\Environment\Python312\python.exe`

## 用户偏好（从 memory 提取）

- 漏洞等级用中文（严重/高危/中危/低危），安全术语保留英文（Bypass/IDOR/XSS）
- Release notes 不写内部测试过程，只写用户可感知变更
- 每次 release 必须附带 ZIP 源码包
- 整合优化而非照搬，按需加载不全量塞 prompt
- CORS 一律低危
- 越权必须实际读到数据
- 报告必须含漏洞描述/模块说明/测试URL/修复建议
