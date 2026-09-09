import asyncio
import logging
import urllib.request
import urllib.parse
import json

import settings as cfg

log = logging.getLogger("notify")


def _send_serverchan(key: str, title: str, desp: str = ""):
    url = f"https://sctapi.ftqq.com/{key}.send"
    data = urllib.parse.urlencode({"title": title, "desp": desp}).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log.warning("Server酱推送失败: %s", e)
        return None


async def notify_finding(target: str, severity: str, title: str, endpoint: str = ""):
    s = cfg.load()
    key = s.get("serverchan_key", "")
    if not key:
        return
    msg_title = f"[{severity}] {title}"
    desp = f"**目标**: {target}\n\n**等级**: {severity}\n\n**漏洞**: {title}\n\n**接口**: {endpoint}"
    await asyncio.to_thread(_send_serverchan, key, msg_title, desp)
