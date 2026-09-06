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
        f"Burp代理: {burp_proxy}",
        "所有HTTP请求必须走Burp代理",
        f"使用 curl.exe -sk -x {burp_proxy} 发送请求",
        "",
        "# 工具说明",
        "你可以使用以下工具来执行测试：",
        "- execute_command: 执行shell命令（curl、Python脚本等）",
        "- read_file: 读取文件内容",
        "- write_file: 写入文件（报告、payload等）",
        "- list_directory: 列出目录文件",
        "- blackboard_write: 写入黑板（攻击面/发现/假设/利用原语/失败记录）",
        "- blackboard_read: 读取黑板内容",
        "所有HTTP请求必须通过Burp代理发送。",
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


def build_user_prompt(target: str) -> str:
    return (
        f"开始对 {target} 进行渗透测试。\n"
        "按照Phase 1（威胁建模）开始：先审计JS、理解业务、识别技术栈、建立攻击面地图。\n"
        "完成后自动进入Phase 2（精准打击）。\n"
        "使用 execute_command 工具来执行所有测试命令。"
    )
