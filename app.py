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
        body.get("group_name", ""),
    )
    await engine.start_session(sid)
    return {"id": sid, "status": "queued"}


@app.get("/api/sessions")
async def list_sessions(search: str = "", group: str = ""):
    return await db.list_sessions(search, group)


@app.get("/api/groups")
async def list_groups():
    return await db.list_groups()


@app.put("/api/sessions/{sid}/group")
async def update_session_group(sid: int, request: Request):
    body = await request.json()
    group_name = body.get("group_name", "")
    await db.update_session(sid, group_name=group_name)
    return {"ok": True}


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


@app.post("/api/sessions/{sid}/pause")
async def pause_session(sid: int):
    ok = await engine.pause_session(sid)
    if not ok:
        raise HTTPException(status_code=400, detail="只能暂停运行中的会话")
    return {"status": "paused"}


@app.post("/api/sessions/{sid}/resume")
async def resume_session(sid: int):
    ok = await engine.resume_session(sid)
    if not ok:
        raise HTTPException(status_code=400, detail="只能恢复已暂停的会话")
    return {"status": "running"}


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
    bb_summary = await db.bb_summary(sid)
    attack_surfaces = await db.bb_read(sid, "attack_surfaces")
    failure_records = await db.bb_read(sid, "failure_records")

    lines = [
        f"# 渗透测试报告 — {session['target']}",
        "",
        "## 渗透结果",
        "",
        f"- 测试时间: {session['created_at']}",
        f"- 结束状态: {session['status']}",
        f"- 对话轮次: {session['turns']}",
        f"- 发现漏洞: {session['findings_count']} 个",
        f"- 攻击面: {bb_summary.get('attack_surfaces', 0)} 个",
        f"- 失败尝试: {bb_summary.get('failure_records', 0)} 次",
        "",
    ]

    sev_count = {}
    for f in findings:
        sev_count[f['severity']] = sev_count.get(f['severity'], 0) + 1
    if sev_count:
        sev_str = "、".join(f"{s} {c}个" for s, c in sev_count.items())
        lines.append(f"漏洞分布：{sev_str}。")
    else:
        lines.append("未发现高价值漏洞。")
    lines.append("")

    if findings:
        lines.append("## 漏洞详情")
        lines.append("")
        for i, f in enumerate(findings, 1):
            lines.extend([
                f"### {i}. [{f['severity']}] {f['title']}",
                "",
                f"- 类型: {f['vuln_type']}",
            ])
            if f.get('endpoint'):
                lines.append(f"- 端点: {f['endpoint']}")
            if f.get('verified'):
                lines.append("- 验证状态: 已验证（有真实请求证据）")
            else:
                lines.append("- 验证状态: 待验证")
            lines.append("")
            lines.append("**PoC**")
            lines.append("```")
            lines.append(f.get('poc') or '暂无')
            lines.append("```")
            lines.append("")
            if f.get('description'):
                lines.append("**响应证据**")
                lines.append("```")
                lines.append(f['description'][:1000])
                lines.append("```")
                lines.append("")

    if attack_surfaces:
        lines.append("## 攻击面地图")
        lines.append("")
        lines.append("| 攻击面 | 详情 | 状态 |")
        lines.append("|--------|------|------|")
        for a in attack_surfaces[:50]:
            lines.append(f"| {a['key']} | {(a.get('value') or '')[:80]} | {a['status']} |")
        lines.append("")

    if failure_records:
        lines.append("## 失败记录")
        lines.append("")
        for fr in failure_records[:30]:
            lines.append(f"- **{fr['key']}**: {(fr.get('value') or '')[:100]}")
        lines.append("")

    lines.extend([
        "## 安全建议",
        "",
        "根据以上发现，建议：",
        "",
    ])
    for i, f in enumerate(findings, 1):
        lines.append(f"{i}. 修复 [{f['severity']}] {f['title']}（端点: {f.get('endpoint', 'N/A')}）")
    if not findings:
        lines.append("当前未发现高危漏洞，建议持续进行安全测试。")
    lines.append("")

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="report-{sid}.md"'},
    )


@app.get("/api/sessions/{sid}/handoff")
async def generate_handoff(sid: int):
    """Generate a handoff document for session resume — blackboard-powered structured memory."""
    session = await db.get_session(sid)
    if not session:
        raise HTTPException(status_code=404, detail="not found")
    findings = await db.get_findings(sid)
    bb_summary = await db.bb_summary(sid)
    attack_surfaces = await db.bb_read(sid, "attack_surfaces")
    pending = await db.bb_read(sid, "pending_hypotheses")
    verified = await db.bb_read(sid, "verified_findings")
    failures = await db.bb_read(sid, "failure_records")
    exploits = await db.bb_read(sid, "exploits")

    lines = [
        f"# 交接文档 — {session['target']}",
        f"会话ID: {sid} | 阶段: {session['phase']} | 状态: {session['status']} | 轮次: {session['turns']}",
        f"创建: {session['created_at']} | 更新: {session['updated_at']}",
        "",
        "## 1. 已确认漏洞",
        "",
    ]
    if findings:
        for f in findings:
            v = "已验证" if f.get("verified") else "待验证"
            lines.append(f"- [{f['severity']}] {f['title']} ({f['vuln_type']}) @ {f.get('endpoint', 'N/A')} [{v}]")
    else:
        lines.append("暂无确认漏洞。")

    lines.extend(["", "## 2. 攻击面地图", ""])
    if attack_surfaces:
        for a in attack_surfaces[:30]:
            lines.append(f"- {a['key']}: {(a.get('value') or '')[:100]} [{a['status']}]")
    else:
        lines.append("暂无攻击面记录。")

    lines.extend(["", "## 3. 待验证假设", ""])
    if pending:
        for p in pending[:20]:
            lines.append(f"- {p['key']}: {(p.get('value') or '')[:100]}")
    else:
        lines.append("无待验证假设。")

    lines.extend(["", "## 4. 已构造利用原语", ""])
    if exploits:
        for e in exploits[:10]:
            lines.append(f"- {e['key']}: {(e.get('value') or '')[:150]}")
    else:
        lines.append("无利用原语。")

    lines.extend(["", "## 5. 失败记录（避免重复踩坑）", ""])
    if failures:
        for f in failures[:20]:
            lines.append(f"- {f['key']}: {(f.get('value') or '')[:100]}")
    else:
        lines.append("无失败记录。")

    lines.extend([
        "",
        "## 6. 后续建议",
        "",
        f"- 黑板统计: 攻击面{bb_summary.get('attack_surfaces', 0)} / 已验证{bb_summary.get('verified_findings', 0)} / 待验证{bb_summary.get('pending_hypotheses', 0)} / 利用原语{bb_summary.get('exploits', 0)} / 失败{bb_summary.get('failure_records', 0)}",
        f"- 连续无发现: {session.get('no_finding_streak', 0)} 轮",
    ])

    if pending:
        lines.append("- 优先处理待验证假设中的高价值项")
    if session['status'] in ('low_roi', 'stopped'):
        lines.append("- 考虑换方向或使用不同的测试视角")

    lines.append("")

    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(
        "\n".join(lines),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="handoff-{sid}.md"'},
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
