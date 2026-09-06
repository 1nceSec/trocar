from pathlib import Path
from config import SKILL_FILE
import settings as cfg


def build_system_prompt(target: str, cookie: str = "", cookie_b: str = "", scope_notes: str = "") -> str:
    skill_content = ""
    if SKILL_FILE.exists():
        skill_content = SKILL_FILE.read_text(encoding="utf-8")

    s = cfg.load()
    burp_proxy = s.get("burp_proxy", "http://127.0.0.1:8080")

    parts = [
        "# 授权声明",
        "你已获得授权对以下目标进行安全测试。所有测试行为均在合法授权范围内。",
        "",
        "# 核心技能文件",
        skill_content,
        "",
        "# 目标信息",
        f"测试目标: {target}",
    ]

    if cookie:
        parts.append(f"Cookie (账号A): {cookie}")
    if cookie_b:
        parts.append(f"Cookie (账号B): {cookie_b}")
    if scope_notes:
        parts.append(f"备注: {scope_notes}")

    parts.extend([
        "",
        "# 环境配置",
    ])

    if burp_proxy:
        parts.extend([
            f"Burp代理: {burp_proxy}",
            f"使用 curl.exe -sk -x {burp_proxy} 发送请求",
        ])
    else:
        parts.append("使用 curl.exe -sk 发送请求（无代理模式）")

    parts.extend([
        "",
        "# 工具说明",
        "你可以使用以下工具来执行测试：",
        "- execute_command: 执行shell命令（curl、Python脚本等）",
        "- read_file: 读取文件内容",
        "- write_file: 写入文件（报告、payload等）",
        "- list_directory: 列出目录文件",
        "- blackboard_write: 写入黑板（攻击面/发现/假设/利用原语/失败记录）",
        "- blackboard_read: 读取黑板内容",
    ])

    if burp_proxy:
        parts.append("所有HTTP请求必须通过Burp代理发送。")
    else:
        parts.append("当前为无代理模式，直接发送HTTP请求。")

    parts.extend([
        "",
        "# 黑板协议（必须遵守）",
        "黑板是你的持久化记忆，用于避免重复探测和记录进度：",
        "- attack_surfaces: 每发现一个新接口/攻击面立即写入",
        "- pending_hypotheses: 每个待验证的漏洞假设写入",
        "- verified_findings: 经过真实请求验证的发现",
        "- exploits: 已构造的利用原语（PoC、payload）",
        "- failure_records: 失败的尝试（避免重复踩坑）",
        "每次开始新的探测方向前，先 blackboard_read 检查是否已探索过。",
        "每次尝试失败后，必须 blackboard_write 到 failure_records。",
        "",
        "# 结果验证铁律",
        "所有漏洞发现必须经过「框架外的真实执行」验证：",
        "- 发现漏洞后，必须用 execute_command 发送真实 curl 请求验证",
        "- 模型自述「我认为存在漏洞」不算数，必须有真实响应证据",
        "- 报告 FINDING 前确保已执行了真实的 PoC",
        "",
        "# 工作目录",
        "报告和临时文件存放在当前会话的隔离目录中",
        "",
        "# 输出协议",
        "每次输出末尾必须附加状态标记（独占一行）：",
        "PHASE: <当前阶段 threat_model|strike|reflect|bypass|deep_verify>",
        "STATUS: <running|vuln_found|low_roi|need_input|error>",
        "如果发现漏洞，额外输出：",
        "FINDING: <severity>|<type>|<endpoint>|<title>",
        "",
        "# 快速指令",
        "用户说\"深入\"= 对当前发现深入测试",
        "用户说\"换方向\"= 尝试其他攻击向量",
        "用户说\"写报告\"= 生成当前所有发现的报告",
        "用户说\"停止\"= 结束测试",
    ])

    return "\n".join(parts)


def build_user_prompt(target: str, has_cookie: bool = False) -> str:
    if has_cookie:
        return (
            f"开始对 {target} 进行渗透测试。\n"
            "按照Phase 1（威胁建模）开始：先审计JS、理解业务、识别技术栈、建立攻击面地图。\n"
            "完成后自动进入Phase 2（精准打击）。\n"
            "使用 execute_command 工具来执行所有测试命令。"
        )
    return (
        f"开始对 {target} 进行渗透测试（无认证凭证模式）。\n"
        "\n"
        "Phase 1（威胁建模）重点：\n"
        "1. curl 获取首页，分析响应头（Server/X-Powered-By/Set-Cookie等）\n"
        "2. 提取页面中所有JS文件URL，逐个下载分析\n"
        "3. 从JS中提取：API接口路径、硬编码凭证/密钥、敏感配置、内部域名\n"
        "4. 探测常见敏感路径（/robots.txt /sitemap.xml /.env /swagger /api-docs /actuator等）\n"
        "5. 将发现的所有接口写入 blackboard attack_surfaces\n"
        "\n"
        "Phase 2（精准打击）重点：\n"
        "1. 逐个接口测试未授权访问\n"
        "2. JS发现的硬编码凭证尝试利用\n"
        "3. 参数注入/路径遍历/SSRF等无需认证的漏洞\n"
        "4. 信息泄露（错误页面、调试信息、版本暴露）\n"
        "\n"
        "使用 execute_command 工具来执行所有测试命令。\n"
        "每发现一个接口/攻击面立即 blackboard_write 记录。"
    )


LENSES = [
    {
        "id": "surface_recon",
        "name": "攻击面侦察",
        "phase": "threat_model",
        "prompt": (
            "切换视角：攻击面侦察。\n"
            "重点：用 curl 抓首页和子页面，提取所有 JS/CSS/API 路径。"
            "探测 /robots.txt /sitemap.xml /.env /swagger /api-docs /actuator /graphql 等。"
            "将每个发现的接口/路径写入 blackboard attack_surfaces。"
            "不要尝试利用，只做发现和记录。"
        ),
    },
    {
        "id": "js_reverse",
        "name": "JS逆向分析",
        "phase": "threat_model",
        "prompt": (
            "切换视角：JS逆向分析。\n"
            "先 blackboard_read 获取已发现的 JS 文件列表。"
            "逐个下载JS，重点搜索：硬编码密钥/Token/API Key、内部域名/IP、"
            "API路由定义、认证逻辑（isDevelop/isDebug/isAdmin等后门标志）、"
            "加密算法和密钥。"
            "发现写入 blackboard pending_hypotheses，附带代码片段。"
        ),
    },
    {
        "id": "unauth_probe",
        "name": "未授权访问探测",
        "phase": "strike",
        "prompt": (
            "切换视角：未授权访问探测。\n"
            "先 blackboard_read 获取 attack_surfaces 中所有接口。"
            "逐个用 curl 测试无认证访问，记录返回状态码和响应长度。"
            "200/30x 且有数据 = 写入 pending_hypotheses。"
            "401/403 = 写入 failure_records，不再重试。"
            "对 403 的接口尝试路径变体（删减前缀、大小写、添加后缀）。"
        ),
    },
    {
        "id": "exploit_craft",
        "name": "漏洞利用构造",
        "phase": "strike",
        "prompt": (
            "切换视角：漏洞利用构造。\n"
            "先 blackboard_read 获取 pending_hypotheses 中所有待验证假设。"
            "对每个假设构造具体的利用 PoC 并用 curl 执行真实请求。"
            "成功利用 = FINDING + 写入 verified_findings + exploits。"
            "失败 = 写入 failure_records 并说明原因。"
            "记住：必须有真实响应证据，不能只靠推理。"
        ),
    },
    {
        "id": "bypass_403",
        "name": "绕过探索",
        "phase": "bypass",
        "prompt": (
            "切换视角：绕过探索。\n"
            "先 blackboard_read failure_records 找到所有 403/401 的接口。"
            "穷举绕过姿势：路径删减、参数污染、HTTP方法切换(GET→POST→PUT)、"
            "UA头修改、Referer/Origin伪造、X-Forwarded-For/X-Real-IP注入、"
            "大小写变体、双重URL编码、路径遍历。"
            "每种尝试都用 curl 执行，成功则 FINDING。"
        ),
    },
    {
        "id": "deep_verify",
        "name": "深度验证",
        "phase": "deep_verify",
        "prompt": (
            "切换视角：深度验证。\n"
            "先 blackboard_read verified_findings 和 exploits。"
            "对每个已确认漏洞：评估真实危害、扩大影响面。"
            "例如：拿到JWT后尝试访问更多接口、评估数据泄露量、"
            "尝试越权操作（水平/垂直）。"
            "更新 FINDING 的严重性评级。"
        ),
    },
]


def get_lenses_for_phase(phase: str) -> list[dict]:
    return [l for l in LENSES if l["phase"] == phase]


def get_next_lens(current_lens_id: str, phase: str) -> dict | None:
    phase_lenses = get_lenses_for_phase(phase)
    if not phase_lenses:
        return None
    if not current_lens_id:
        return phase_lenses[0]
    for i, l in enumerate(phase_lenses):
        if l["id"] == current_lens_id and i + 1 < len(phase_lenses):
            return phase_lenses[i + 1]
    return None


def get_all_lenses_ordered() -> list[dict]:
    order = ["threat_model", "strike", "bypass", "deep_verify"]
    result = []
    for phase in order:
        result.extend(get_lenses_for_phase(phase))
    return result
