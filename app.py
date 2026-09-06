import asyncio
import json
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import db
import engine
import settings as cfg
from config import HOST, PORT
from events import bus


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    yield


app = FastAPI(title="VulnHunter", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    s = cfg.load()
    if not s.get("api_key"):
        return templates.TemplateResponse(request, "setup.html")
    return templates.TemplateResponse(request, "index.html")


@app.post("/api/setup")
async def setup(request: Request):
    body = await request.json()
    current = cfg.load()
    api_key = body.get("api_key", "").strip()
    if not api_key:
        raise HTTPException(status_code=400, detail="api_key is required")
    current["api_key"] = api_key
    if body.get("provider"):
        current["provider"] = body["provider"]
    if body.get("base_url"):
        current["base_url"] = body["base_url"]
    if body.get("model"):
        current["model"] = body["model"]
    if body.get("burp_proxy"):
        current["burp_proxy"] = body["burp_proxy"]
    cfg.save(current)
    return {"ok": True}


@app.post("/api/sessions")
async def create_session(request: Request):
    body = await request.json()
    target = body.get("target", "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="target is required")
    sid = await db.create_session(
        target,
        body.get("cookie", ""),
        body.get("cookie_b", ""),
        body.get("scope_notes", ""),
    )
    await engine.start_session(sid)
    return {"id": sid, "status": "queued"}


@app.get("/api/sessions")
async def list_sessions():
    return await db.list_sessions()


@app.get("/api/sessions/{sid}")
async def get_session(sid: int):
    s = await db.get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="not found")
    return s


@app.post("/api/sessions/{sid}/stop")
async def stop_session(sid: int):
    await engine.stop_session(sid)
    return {"status": "stopped"}


@app.delete("/api/sessions/{sid}")
async def delete_session(sid: int):
    s = await db.get_session(sid)
    if not s:
        raise HTTPException(status_code=404, detail="not found")
    if s["status"] == "running":
        await engine.stop_session(sid)
    await db.delete_session(sid)
    engine.cleanup_temp(sid)
    return {"ok": True}


@app.post("/api/sessions/{sid}/input")
async def send_input(sid: int, request: Request):
    body = await request.json()
    msg = body.get("message", "").strip()
    if not msg:
        raise HTTPException(status_code=400, detail="message is required")
    ok = await engine.send_input(sid, msg)
    return {"ok": ok}


@app.get("/api/sessions/{sid}/findings")
async def get_findings(sid: int):
    return await db.get_findings(sid)


@app.get("/api/sessions/{sid}/blackboard")
async def get_blackboard(sid: int, partition: str = "", status: str = ""):
    return await db.bb_read(sid, partition, status)


@app.get("/api/sessions/{sid}/blackboard/summary")
async def get_blackboard_summary(sid: int):
    return await db.bb_summary(sid)


@app.get("/api/sessions/{sid}/logs")
async def get_logs(sid: int, after: int = 0, limit: int = 100):
    return await db.get_logs(sid, after, limit)


@app.get("/api/sessions/{sid}/report")
async def export_report(sid: int):
    session = await db.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="not found")
    findings = await db.get_findings(sid)
    lines = [
        f"# 渗透测试报告 — {session['target']}",
        "",
        f"- 测试时间: {session['created_at']}",
        f"- 状态: {session['status']}",
        f"- 对话轮次: {session['turns']}",
        f"- 发现漏洞: {session['findings_count']}",
        "",
    ]
    if not findings:
        lines.append("未发现高价值漏洞。")
    for i, f in enumerate(findings, 1):
        lines.extend([
            f"## {i}. [{f['severity']}] {f['title']}",
            "",
            f"- 类型: {f['vuln_type']}",
            f"- 端点: {f['endpoint']}" if f.get('endpoint') else "",
            "",
            "### PoC",
            f.get('poc', '暂无'),
            "",
            "### 描述",
            f.get('description', '暂无'),
            "",
        ])
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{sid}.md"'},
    )


@app.get("/api/health")
async def health_check():
    s = cfg.load()
    return {
        "status": "ok",
        "api_key_set": bool(s.get("api_key")),
        "provider": s.get("provider"),
        "model": s.get("model"),
        "active_sessions": len(engine._tasks),
    }


@app.get("/api/settings")
async def get_settings():
    return cfg.get_masked()


@app.put("/api/settings")
async def update_settings(request: Request):
    body = await request.json()
    current = cfg.load()
    for k in ("provider", "model", "model_strong", "model_fast", "base_url", "max_tokens", "burp_proxy", "max_concurrent"):
        if k in body:
            current[k] = body[k]
    if "api_key" in body and body["api_key"] and not body["api_key"].startswith("****"):
        current["api_key"] = body["api_key"]
    cfg.save(current)
    return cfg.get_masked()


@app.get("/api/skill")
async def get_skill():
    from config import SKILL_FILE
    content = ""
    if SKILL_FILE.exists():
        content = SKILL_FILE.read_text(encoding="utf-8")
    return {"path": str(SKILL_FILE), "content": content}


@app.put("/api/skill")
async def update_skill(request: Request):
    from config import SKILL_FILE
    body = await request.json()
    content = body.get("content", "")
    if not content.strip():
        raise HTTPException(status_code=400, detail="content is required")
    SKILL_FILE.parent.mkdir(parents=True, exist_ok=True)
    SKILL_FILE.write_text(content, encoding="utf-8")
    return {"ok": True, "path": str(SKILL_FILE)}


@app.websocket("/ws/{sid}")
async def websocket_endpoint(websocket: WebSocket, sid: int):
    await websocket.accept()
    q = bus.subscribe(sid)
    try:
        while True:
            try:
                msg = await asyncio.wait_for(q.get(), timeout=15)
                await websocket.send_text(msg)
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        bus.unsubscribe(sid, q)
        try:
            await websocket.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT)
