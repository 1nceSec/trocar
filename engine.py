import asyncio
import json
import re
import time
import shutil
from pathlib import Path

import db
import settings as cfg
from config import TEMP_DIR, TEMP_LIMIT_MB, INACTIVITY_TIMEOUT, MAX_TURNS, NO_FINDING_STOP
from events import bus
from llm import stream_chat, build_tool_result_anthropic, build_tool_result_openai
from prompt import build_system_prompt, build_user_prompt, get_next_lens, get_lenses_for_phase, get_all_lenses_ordered
from tools import dispatch_tool

_semaphore: asyncio.Semaphore | None = None
_semaphore_limit: int = 0
_tasks: dict[int, asyncio.Task] = {}

RE_PHASE = re.compile(r"^PHASE:\s*(.+)$", re.MULTILINE)
RE_STATUS = re.compile(r"^STATUS:\s*(.+)$", re.MULTILINE)
RE_FINDING = re.compile(r"^FINDING:\s*(.+)$", re.MULTILINE)

MAX_WINDOW = 40
MAX_RETRIES = 2
MAX_TOOL_ROUNDS = 20

STRONG_PHASES = ("threat_model", "bypass", "deep_verify")
FAST_PHASES = ("strike",)


def _pick_model(s: dict, phase: str) -> str:
    if phase in STRONG_PHASES and s.get("model_strong"):
        return s["model_strong"]
    if phase in FAST_PHASES and s.get("model_fast"):
        return s["model_fast"]
    return s["model"]


def _get_semaphore() -> asyncio.Semaphore:
    global _semaphore, _semaphore_limit
    s = cfg.load()
    limit = s.get("max_concurrent", 3)
    if _semaphore is None or _semaphore_limit != limit:
        _semaphore = asyncio.Semaphore(limit)
        _semaphore_limit = limit
    return _semaphore


def _session_temp(sid: int) -> Path:
    p = TEMP_DIR / str(sid)
    p.mkdir(parents=True, exist_ok=True)
    return p


def _check_temp_size(sid: int) -> bool:
    p = _session_temp(sid)
    total = sum(f.stat().st_size for f in p.rglob("*") if f.is_file())
    return total < TEMP_LIMIT_MB * 1024 * 1024


def _parse_markers(text: str) -> dict:
    result = {}
    m = RE_PHASE.search(text)
    if m:
        result["phase"] = m.group(1).strip()
    m = RE_STATUS.search(text)
    if m:
        result["status"] = m.group(1).strip()
    findings = []
    for m in RE_FINDING.finditer(text):
        parts = m.group(1).strip().split("|", 3)
        if len(parts) >= 4:
            findings.append({
                "severity": parts[0].strip(),
                "vuln_type": parts[1].strip(),
                "endpoint": parts[2].strip(),
                "title": parts[3].strip(),
            })
    if findings:
        result["findings"] = findings
    return result


def _extract_poc_from_logs(tool_logs: list[dict]) -> tuple[str, str]:
    poc_parts = []
    desc_parts = []
    for log in reversed(tool_logs[-10:]):
        try:
            data = json.loads(log.get("content", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue
        name = data.get("name", "")
        if name == "execute_command":
            cmd = data.get("input", {}).get("command", "")
            output = data.get("output", "")
            if "curl" in cmd:
                poc_parts.append(cmd)
                try:
                    out_data = json.loads(output)
                    if out_data.get("success"):
                        stdout = out_data.get("stdout", "")
                        if stdout:
                            desc_parts.append(stdout[:500])
                except (json.JSONDecodeError, TypeError):
                    pass
    poc = "\n".join(poc_parts[:3]) if poc_parts else ""
    desc = "\n---\n".join(desc_parts[:2]) if desc_parts else ""
    return poc, desc


def _trim_messages(messages: list[dict]) -> list[dict]:
    if len(messages) <= MAX_WINDOW:
        return messages
    first = messages[0]
    old = messages[1:-MAX_WINDOW + 1]
    summary_parts = []
    for m in old:
        role = m.get("role", "")
        content = m.get("content", "")
        if isinstance(content, list):
            content = "[tool_result]"
        elif isinstance(content, str) and len(content) > 300:
            content = content[:200] + "\n...(truncated)...\n" + content[-100:]
        summary_parts.append(f"[{role}]: {content}")
    summary = "[历史摘要 - 早期对话精简版]\n" + "\n---\n".join(summary_parts)
    return [first, {"role": "user", "content": summary}, {"role": "assistant", "content": "收到历史摘要，继续测试。"}] + messages[-MAX_WINDOW + 3:]


async def _do_one_llm_call(sid: int, s: dict, system_prompt: str, messages: list[dict], model: str = ""):
    """Single LLM call with retry. Returns response dict."""
    if not model:
        model = s["model"]
    last_err = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            resp = await stream_chat(
                provider=s["provider"],
                api_key=s["api_key"],
                base_url=s.get("base_url", ""),
                model=model,
                max_tokens=s.get("max_tokens", 16384),
                system=system_prompt,
                messages=messages,
                tools=True,
            )
            return resp
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES:
                await bus.publish(sid, "stream", {"text": f"\n[重试 {attempt+1}/{MAX_RETRIES}...]\n"})
                await asyncio.sleep(2 ** attempt)
    raise last_err


async def _ai_loop(sid: int, messages: list[dict], system_prompt: str, start_turns: int = 0):
    s = cfg.load()
    if not s.get("api_key"):
        await db.update_session(sid, status="error")
        await bus.publish(sid, "error", {"message": "未配置 API Key，请在 Settings 中设置"})
        await bus.publish(sid, "done", {})
        _tasks.pop(sid, None)
        return

    provider = s["provider"]
    turns = start_turns
    last_activity = time.time()
    session_cwd = str(_session_temp(sid))
    current_phase = "threat_model"
    current_lens_id = ""
    no_finding_streak = 0
    lens_turns = 0
    LENS_MAX_TURNS = 6

    try:
        while turns < MAX_TURNS:
            if not _check_temp_size(sid):
                await db.update_session(sid, status="error")
                await bus.publish(sid, "error", {"message": "临时目录超限"})
                break

            if time.time() - last_activity > INACTIVITY_TIMEOUT:
                await db.update_session(sid, status="error")
                await bus.publish(sid, "error", {"message": "无活动超时"})
                break

            check = await db.get_session(sid)
            if check and check["status"] == "stopped":
                break

            model = _pick_model(s, current_phase)

            bb = await db.bb_summary(sid)
            bb_context = (
                f"\n[黑板状态] 攻击面:{bb['attack_surfaces']} 已验证:{bb['verified_findings']} "
                f"待验证:{bb['pending_hypotheses']} 利用原语:{bb['exploits']} 失败记录:{bb['failure_records']}"
            )

            trimmed = _trim_messages(messages)
            if trimmed and trimmed[-1]["role"] == "user":
                trimmed[-1] = {**trimmed[-1], "content": trimmed[-1]["content"] + bb_context}

            resp = await _do_one_llm_call(sid, s, system_prompt, trimmed, model)
            last_activity = time.time()

            text = resp.get("text", "")
            tool_calls = resp.get("tool_calls", [])

            if text:
                await bus.publish(sid, "stream", {"text": text})

            tool_round = 0
            has_real_request = False
            while tool_calls and tool_round < MAX_TOOL_ROUNDS:
                tool_round += 1

                if provider == "anthropic":
                    raw = resp.get("raw_content")
                    if raw:
                        messages.append({"role": "assistant", "content": raw})
                    else:
                        messages.append({"role": "assistant", "content": text})
                else:
                    messages.append({"role": "assistant", "content": text})

                results = []
                for tc in tool_calls:
                    tool_name = tc["name"]
                    tool_input = tc["input"]
                    await bus.publish(sid, "stream", {
                        "text": f"\n🔧 {tool_name}: {json.dumps(tool_input, ensure_ascii=False)[:200]}\n"
                    })

                    if tool_name == "execute_command" and "curl" in tool_input.get("command", ""):
                        has_real_request = True

                    try:
                        output = await dispatch_tool(tool_name, tool_input, session_cwd, session_id=sid)
                    except Exception as tool_err:
                        output = json.dumps({"success": False, "error": f"工具执行异常: {tool_err}"}, ensure_ascii=False)
                    last_activity = time.time()

                    output_preview = output[:500] + ("..." if len(output) > 500 else "")
                    await bus.publish(sid, "stream", {"text": f"📋 Result: {output_preview}\n"})

                    results.append({"id": tc["id"], "output": output})

                    await db.add_log(sid, "tool", json.dumps({
                        "name": tool_name, "input": tool_input, "output": output[:2000]
                    }, ensure_ascii=False), "")

                if provider == "anthropic":
                    messages.append(build_tool_result_anthropic(results))
                else:
                    messages.extend(build_tool_result_openai(results))

                check = await db.get_session(sid)
                if check and check["status"] == "stopped":
                    break

                trimmed = _trim_messages(messages)
                resp = await _do_one_llm_call(sid, s, system_prompt, trimmed, model)
                last_activity = time.time()

                text = resp.get("text", "")
                tool_calls = resp.get("tool_calls", [])

                if text:
                    await bus.publish(sid, "stream", {"text": text})

            turns += 1
            full_text = text
            await db.add_log(sid, "assistant", full_text, "")
            await db.update_session(sid, turns=turns)

            markers = _parse_markers(full_text)

            if "phase" in markers:
                current_phase = markers["phase"]
                await db.update_session(sid, phase=current_phase)
                await bus.publish(sid, "phase", {"phase": current_phase})

            found_this_turn = False
            if markers.get("findings"):
                recent_logs = await db.get_logs(sid, limit=0)
                tool_logs = [l for l in recent_logs if l["role"] == "tool"]
                poc, desc = _extract_poc_from_logs(tool_logs)

            for f in markers.get("findings", []):
                verified = 1 if has_real_request else 0
                fid = await db.add_finding(
                    sid, f["severity"], f["title"], f["vuln_type"], f["endpoint"],
                    poc=poc, description=desc or full_text[:500],
                )
                if not has_real_request:
                    await bus.publish(sid, "stream", {
                        "text": "\n⚠️ FINDING未经真实请求验证，标记为待验证\n"
                    })
                await bus.publish(sid, "finding", {**f, "id": fid, "verified": verified})
                found_this_turn = True

            if found_this_turn:
                no_finding_streak = 0
            else:
                no_finding_streak += 1

            await db.update_session(sid, no_finding_streak=no_finding_streak)

            status = markers.get("status", "running")

            if status in ("vuln_found", "low_roi", "error"):
                await db.update_session(sid, status=status)
                await bus.publish(sid, "status", {"status": status})
                break

            if status == "need_input":
                await db.update_session(sid, status="need_input")
                await bus.publish(sid, "status", {"status": "need_input"})
                break

            if no_finding_streak >= NO_FINDING_STOP and current_phase not in ("threat_model",):
                await bus.publish(sid, "stream", {
                    "text": f"\n⏹️ 连续{no_finding_streak}轮无新发现，自动收敛停止\n"
                })
                await db.update_session(sid, status="low_roi")
                await bus.publish(sid, "status", {"status": "low_roi", "reason": f"连续{no_finding_streak}轮无新发现"})
                break

            if not tool_calls and not resp.get("tool_calls"):
                messages.append({"role": "assistant", "content": full_text})

            lens_turns += 1
            next_msg = "继续。如果当前阶段完成，进入下一阶段。保持输出状态标记。"

            if lens_turns >= LENS_MAX_TURNS or no_finding_streak >= 3:
                next_lens = get_next_lens(current_lens_id, current_phase)
                if next_lens:
                    current_lens_id = next_lens["id"]
                    lens_turns = 0
                    next_msg = next_lens["prompt"]
                    await bus.publish(sid, "stream", {
                        "text": f"\n🔄 切换视角: {next_lens['name']}\n"
                    })
                else:
                    phases = ["threat_model", "strike", "bypass", "deep_verify"]
                    idx = phases.index(current_phase) if current_phase in phases else -1
                    if idx + 1 < len(phases):
                        new_phase = phases[idx + 1]
                        new_lenses = get_lenses_for_phase(new_phase)
                        if new_lenses:
                            current_phase = new_phase
                            current_lens_id = new_lenses[0]["id"]
                            lens_turns = 0
                            no_finding_streak = 0
                            next_msg = new_lenses[0]["prompt"]
                            await db.update_session(sid, phase=current_phase)
                            await bus.publish(sid, "stream", {
                                "text": f"\n⏭️ 进入阶段: {current_phase} / 视角: {new_lenses[0]['name']}\n"
                            })
                            await bus.publish(sid, "phase", {"phase": current_phase})

            messages.append({"role": "user", "content": next_msg})
            await db.add_log(sid, "user", messages[-1]["content"], "")

        else:
            await db.update_session(sid, status="low_roi")
            await bus.publish(sid, "status", {"status": "low_roi", "reason": "达到最大轮次"})

    except Exception as e:
        await db.update_session(sid, status="error")
        await bus.publish(sid, "error", {"message": str(e)})

    finally:
        await bus.publish(sid, "done", {})
        _tasks.pop(sid, None)


async def _run_session(sid: int):
    sem = _get_semaphore()
    async with sem:
        session = await db.get_session(sid)
        if not session:
            return

        await db.update_session(sid, status="running", phase="threat_model")
        await bus.publish(sid, "status", {"status": "running", "phase": "threat_model"})

        target = session["target"]
        system_prompt = build_system_prompt(
            target, session["cookie"], session["cookie_b"], session["scope_notes"]
        )

        has_cookie = bool(session["cookie"])
        messages = [{"role": "user", "content": build_user_prompt(target, has_cookie)}]
        await db.add_log(sid, "user", messages[0]["content"], "init")

        await _ai_loop(sid, messages, system_prompt)


async def _resume_session(sid: int, user_msg: str):
    sem = _get_semaphore()
    async with sem:
        session = await db.get_session(sid)
        if not session:
            return

        logs = await db.get_logs(sid)
        messages = [{"role": log["role"], "content": log["content"]} for log in logs if log["role"] in ("user", "assistant")]

        system_prompt = build_system_prompt(
            session["target"], session["cookie"], session["cookie_b"], session["scope_notes"]
        )

        await _ai_loop(sid, messages, system_prompt, session["turns"])


async def start_session(sid: int):
    if sid in _tasks:
        return
    task = asyncio.create_task(_run_session(sid))
    _tasks[sid] = task


async def stop_session(sid: int):
    await db.update_session(sid, status="stopped")
    task = _tasks.pop(sid, None)
    if task and not task.done():
        task.cancel()
    await bus.publish(sid, "status", {"status": "stopped"})


async def send_input(sid: int, user_msg: str):
    session = await db.get_session(sid)
    if not session or session["status"] != "need_input":
        return False
    await db.add_log(sid, "user", user_msg, "")
    await db.update_session(sid, status="running")
    task = asyncio.create_task(_resume_session(sid, user_msg))
    _tasks[sid] = task
    return True


def cleanup_temp(sid: int):
    p = TEMP_DIR / str(sid)
    if p.exists():
        shutil.rmtree(p, ignore_errors=True)
