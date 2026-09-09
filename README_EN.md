<div align="center">

# VulnHunter

**AI-Powered Autonomous Penetration Testing Platform**

[中文](README.md) | English

[![GitHub release](https://img.shields.io/github/v/release/1nceSec/vulnhunter)](https://github.com/1nceSec/vulnhunter/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

## What is VulnHunter?

VulnHunter is an autonomous penetration testing system powered by AI. Give it a URL, it does the rest — JS analysis, endpoint discovery, vulnerability exploitation, and report generation.

Five-phase "surgeon mode": **Threat Modeling → Precision Strike → Deep Reflection → Bypass → Deep Verification**

Built with AI Vibe Coding. Architecture inspired by [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) (Planner-Executor-Reflector pattern).

## Features

- **Blackboard Architecture** — Five-partition persistent memory (attack surfaces / verified findings / pending hypotheses / exploits / failure records) to avoid redundant probing
- **34 Vulnerability Knowledge Modules** — Covers IDOR, SQLi, XSS, SSRF, RCE, JWT, GraphQL, WebSocket and more; auto-loads matching modules based on target characteristics
- **Model Tiering** — Auto-switches models by phase (strong model for modeling & verification, fast model for striking), cost-efficient
- **Verification Iron Rule** — Every finding MUST have real curl request evidence; model self-assertion doesn't count
- **Multi-Lens Rotation** — 6 analysis perspectives across 4 phases, systematic coverage like a team of specialists
- **Auto-Convergence** — Stops after N consecutive rounds with no new findings
- **Browser Setup Wizard** — Configure API Key in browser on first launch, zero config file editing
- **Multi-Model Support** — Anthropic Claude / OpenAI / DeepSeek / Qwen / GLM and any OpenAI-compatible API
- **Real-time Streaming** — WebSocket push of AI testing process and tool execution results
- **Security Sandbox** — Built-in dangerous command blocking + file write path restriction
- **Concurrent Sessions** — Test multiple targets simultaneously
- **Handoff Document** — One-click session handoff doc (blackboard state + findings + attack surfaces + failure records) for session resume
- **Docker Ready** — One command to deploy

## Quick Start

### Option 1: Clone & Run

```bash
git clone https://github.com/1nceSec/vulnhunter.git
cd vulnhunter
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:8899** in your browser. First launch will guide you through API Key setup.

### Option 2: Docker

Pull and run:

```bash
docker run -d \
  --name vulnhunter \
  -p 8899:8899 \
  -v vulnhunter-data:/app/data \
  ox1dq/vulnhunter:latest
```

Open **http://127.0.0.1:8899** in your browser.

View logs:

```bash
docker logs -f vulnhunter
```

Stop and remove:

```bash
docker stop vulnhunter
docker rm vulnhunter
```

**Docker Compose (optional):** Create `docker-compose.yml`:

```yaml
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

Start:

```bash
docker compose up -d
```

### Option 3: Windows Double-Click

```
1. Download and extract the ZIP from Releases
2. Double-click start.bat
3. Open http://127.0.0.1:8899
```

## Upgrading

VulnHunter does not auto-update. After a new release, update manually based on your deployment method.

### Git Clone

```bash
cd vulnhunter
git pull
pip install -r requirements.txt
python app.py
```

### Docker

```bash
# Pull the latest image
docker pull ox1dq/vulnhunter:latest

# Stop and remove the old container (data volume is preserved)
docker stop vulnhunter
docker rm vulnhunter

# Start with the new image
docker run -d \
  --name vulnhunter \
  -p 8899:8899 \
  -v vulnhunter-data:/app/data \
  ox1dq/vulnhunter:latest
```

Docker Compose users:

```bash
docker compose pull
docker compose up -d
```

> The `vulnhunter-data` volume is independent of the container — updating won't lose your session data or configuration.

### Windows ZIP

```
1. Download the latest ZIP from Releases
2. Extract and overwrite the old directory (back up data/ first)
3. Double-click start.bat
```

## Configuration

### Environment Variables (.env)

| Variable | Description | Default |
|----------|-------------|---------|
| `ANTHROPIC_API_KEY` | API Key (configured via browser on first launch) | - |
| `MODEL` | Default model | claude-sonnet-4-20250514 |
| `MODEL_STRONG` | Strong model (modeling/verification phases) | claude-opus-4-20250514 |
| `MODEL_FAST` | Fast model (strike phase) | claude-haiku-4-5-20251001 |
| `MAX_TOKENS` | Max output tokens | 16384 |
| `BURP_PROXY` | Burp proxy address (optional) | http://127.0.0.1:8080 |
| `MAX_CONCURRENT` | Max concurrent sessions | 3 |
| `MAX_TURNS` | Max conversation turns | 200 |
| `NO_FINDING_STOP` | Auto-stop after N rounds without findings | 8 |
| `HOST` | Listen address | 127.0.0.1 |
| `PORT` | Listen port | 8899 |

### Web UI Settings (Runtime)

Click **Settings** in the top-right corner to change provider, model, API Key, Base URL, Burp proxy, and concurrency at runtime.

### Skill Editor

Click **Skill** to edit the core strategy file (SKILL.md) online. New sessions will use the updated Skill.

## Multi-Model Support

| Provider | Base URL | Model |
|----------|----------|-------|
| Anthropic | *(default)* | `claude-sonnet-4-20250514` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Qwen | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-max` |
| GLM | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-plus` |
| Ollama | `http://127.0.0.1:11434/v1` | `llama3.1` |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o` |

> Note: Non-Claude models' effectiveness depends on the model's own security knowledge and reasoning capabilities.

## How It Works

```
Input: https://target.com

Phase 1: Threat Modeling (strong model)
  Lens: Surface Recon → curl pages, probe sensitive paths, collect endpoints
  Lens: JS Reverse   → download JS, search for hardcoded keys/secrets

Phase 2: Precision Strike (fast model)
  Lens: Unauth Probe  → test each endpoint without authentication
  Lens: Exploit Craft  → build PoC for hypotheses, verify with real requests

Phase 3: Bypass
  Lens: Bypass 403    → path truncation, parameter pollution, UA spoofing...

Phase 4: Deep Verification (strong model)
  Lens: Deep Verify   → assess real impact, expand attack surface

Auto-stop after N rounds with no new findings
```

## Architecture

```
vulnhunter/
├── app.py              # FastAPI app (REST API + WebSocket)
├── engine.py           # AI engine (session loop + tool calls + model tiering)
├── llm.py              # LLM abstraction (Anthropic Tool Use + OpenAI compat)
├── tools.py            # Tool sandbox (cmd exec / file I/O / blackboard + safety)
├── db.py               # SQLite database (with blackboard 5-partition table)
├── events.py           # WebSocket event bus
├── prompt.py           # Prompt builder (blackboard protocol + verification rule + KB index)
├── settings.py         # Runtime settings
├── config.py           # Environment config
├── Dockerfile          # Docker deployment
├── knowledge/          # 34 vulnerability knowledge modules (IDOR/SQLi/XSS/SSRF/RCE...)
├── templates/
│   ├── index.html      # Dashboard
│   └── setup.html      # First-launch setup wizard
└── data/               # Runtime data (auto-created)
```

## Handoff Document

After a test session ends, you can generate a handoff document with one click, exporting the full test state:

- Blackboard data across all 5 partitions (attack surfaces, verified findings, pending hypotheses, exploits, failure records)
- Confirmed vulnerability list with PoCs
- AI conversation history summary

**How to use:**

- UI: Click the "Handoff" button on the session card
- API: `GET /api/sessions/{id}/handoff`

**Typical scenarios:**

- Resume after interruption: Export current progress, continue from where you left off in a new session
- Team collaboration: Hand off test results to other team members
- Archiving: Preserve the complete test process and findings

## API Reference

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Dashboard (setup wizard on first visit) |
| POST | `/api/setup` | First-time API Key configuration |
| POST | `/api/sessions` | Create test session |
| GET | `/api/sessions` | List all sessions |
| GET | `/api/sessions/{id}` | Get session details |
| POST | `/api/sessions/{id}/stop` | Stop session |
| DELETE | `/api/sessions/{id}` | Delete session |
| POST | `/api/sessions/{id}/input` | Send user message |
| GET | `/api/sessions/{id}/findings` | Get vulnerability list |
| GET | `/api/sessions/{id}/blackboard` | Get blackboard content |
| GET | `/api/sessions/{id}/blackboard/summary` | Blackboard 5-partition stats |
| GET | `/api/sessions/{id}/logs` | Get conversation logs |
| GET | `/api/sessions/{id}/report` | Export Markdown report |
| GET | `/api/sessions/{id}/handoff` | Generate handoff document (session resume) |
| GET | `/api/settings` | Get settings |
| PUT | `/api/settings` | Update settings |
| WS | `/ws/{id}` | WebSocket real-time push |

## Acknowledgements

- [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) — Architecture inspiration (Planner-Executor-Reflector pattern)

## Acknowledgments

- [LuaN1aoAgent](https://github.com/SanMuzZzZz/LuaN1aoAgent) — Architecture inspiration (Planner-Executor-Reflector pattern)

## License

MIT
