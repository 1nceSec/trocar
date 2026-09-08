from pathlib import Path
from config import SKILL_FILE, BASE_DIR
import settings as cfg

KNOWLEDGE_DIR = BASE_DIR / "knowledge"

# 进站短表：特征关键词 → 知识库模块映射
# Phase 1 威胁建模识别到特征后，Phase 2 按需加载对应模块
FEATURE_KB_MAP = {
    # 业务特征
    "用户体系": ["idor-test.md", "authbypass-test.md"],
    "搜索筛选": ["injection-test.md"],
    "文件上传": ["file-upload-test.md"],
    "URL预览": ["ssrf-test.md"],
    "评论留言": ["xss-test.md"],
    "支付积分": ["logic-test.md", "race-condition-test.md"],
    "订单": ["logic-test.md", "idor-test.md", "race-condition-test.md"],
    "优惠券": ["logic-test.md", "race-condition-test.md"],
    "短信验证": ["race-condition-test.md", "authbypass-test.md"],
    "注册登录": ["authbypass-test.md", "logic-test.md"],
    "密码重置": ["authbypass-test.md", "http-host-header-test.md"],
    "写操作": ["csrf-test.md"],
    # 协议/接口特征
    "GraphQL": ["graphql-test.md"],
    "OAuth/JWT": ["oauth-jwt-test.md"],
    "WebSocket": ["websocket-test.md"],
    "API网关": ["api-gateway-test.md"],
    "REST API": ["idor-test.md", "api-gateway-test.md"],
    "XML解析": ["xxe-test.md"],
    "SOAP": ["xxe-test.md"],
    # 技术栈
    "Java中间件": ["deserialization-test.md", "jndi-injection-test.md", "el-injection-test.md"],
    "Spring": ["el-injection-test.md", "jndi-injection-test.md"],
    "Fastjson": ["deserialization-test.md", "jndi-injection-test.md"],
    "Node.js": ["prototype-pollution-test.md"],
    "PHP弱类型": ["type-juggling-test.md"],
    "Python/Flask": ["ssrf-test.md"],
    "React/Vue": ["xss-test.md", "prototype-pollution-test.md"],
    # 基础设施
    "缓存CDN": ["cache-poisoning-test.md"],
    "WAF拦截": ["waf-bypass.md"],
    "反代/Nginx": ["http-smuggling-test.md", "http-host-header-test.md"],
    "前后端分离": ["http-smuggling-test.md"],
    "子域名": ["subdomain-takeover-test.md"],
    "源码泄露": ["insecure-scm-test.md"],
    "路径下载": ["path-traversal-lfi-test.md"],
    "重定向": ["open-redirect-test.md"],
    "Host头": ["http-host-header-test.md"],
    # 新兴攻击面
    "AI/LLM": ["agent-tool-exec-test.md"],
    "云IDE": ["cloud-ide-codex-rce-chain.md"],
    "EL表达式": ["el-injection-test.md"],
}

# 打穿短表：认A打B — 发现一个特征时，联想测试另一个
CHAIN_RULES = [
    ("SSRF", "→ 云元数据(169.254.169.254) → AK/SK → S3列桶 → 内网横向"),
    ("IDOR", "→ 批量枚举评估规模 → 垂直越权尝试管理员操作"),
    ("SQLi", "→ 库名/表名证明深度 → 尝试堆叠/写文件/UDF"),
    ("JWT弱密钥", "→ 伪造admin token → 访问所有管理接口"),
    ("任意文件读", "→ /etc/passwd → 配置文件 → 数据库凭证 → 连接DB"),
    ("未授权接口", "→ 枚举同前缀全部接口 → 寻找写操作(POST/PUT/DELETE)"),
    ("XSS存储", "→ Cookie窃取PoC → 管理员后台 → 接管"),
    ("硬编码密钥", "→ 搜索同类密钥(AWS/OSS/Redis) → 验证每个密钥的权限范围"),
    ("信息泄露", "→ Actuator→heapdump→密码 | Swagger→全接口→逐个测 | .env→凭证"),
    ("竞态条件", "→ 短信轰炸 → 优惠券叠加 → 0元购 → 余额溢出"),
    ("403绕过", "→ 路径变体穷举 → Header覆盖 → HTTP方法切换 → 编码填充"),
    ("上传成功", "→ 可访问？ → 可执行？ → 能getshell？ → 链式RCE"),
]


def load_kb_module(name: str) -> str:
    p = KNOWLEDGE_DIR / name
    if p.exists():
        return p.read_text(encoding="utf-8")
    return ""


def get_kb_index() -> str:
    if not KNOWLEDGE_DIR.exists():
        return ""
    files = sorted(f.name for f in KNOWLEDGE_DIR.iterdir() if f.suffix == ".md")
    if not files:
        return ""
    lines = ["可用知识库模块（用 read_file 按需加载 knowledge/<name>）："]
    for f in files:
        lines.append(f"  - {f}")
    return "\n".join(lines)


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
        "- read_file: 读取文件内容（包括 knowledge/ 下的知识库模块）",
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
        "# 打穿短表（认A打B — 发现一个立刻联想下一个）",
    ])
    for vuln_type, chain in CHAIN_RULES:
        parts.append(f"- {vuln_type} {chain}")
    parts.extend([
        "",
        "# SRC价值矩阵（力气先砸哪）",
        "没号：未授权→换id→认证口→JS钥匙→四件套",
        "有号：带会话换id→加字段/跳步/钱→四件套打在出数的业务参上",
        "类型矩阵每轮至少过一遍：未授权/越权/注入/XSS/SSRF/上传/逻辑/认证/凭证",
        "",
        "# 进站短表精华（认什么→打哪）",
        "- 密文id+JS有公钥 → 加密相邻数字替换 → 出别人数据",
        "- 列表按tenantId过滤 → 租户字段试0/-1/空 → 出他租户数据",
        "- 前端写死appId+appKey → 不登录带钥打业务表 → 出他人数据",
        "- STS签名Policy吃filename → 凭证填*/空 → 覆盖他人文件",
        "- 云开发/SSRF到元数据 → 不登录打元数据 → AK/SK泄露",
        "- 列表公开详情不校验 → 加可见性参/换id → 未公开内容",
        "- 管理后台SSO壳+账密API → POST默认admin/123456 → 管理员",
        "- Node __proto__+EJS/Pug → 污染outputFunctionName → RCE",
        "",
        "# 知识库（按需加载，节省 token）",
        "knowledge/ 目录下有34个漏洞类型测试模块。不要一次全部加载！",
        "Phase 1 威胁建模时识别目标特征，Phase 2 按需用 read_file 加载对应模块：",
        "- 有用户体系 → knowledge/idor-test.md + knowledge/authbypass-test.md",
        "- 有搜索/查询参数 → knowledge/injection-test.md",
        "- 有文件上传 → knowledge/file-upload-test.md",
        "- 有URL预览/请求 → knowledge/ssrf-test.md",
        "- 有支付/积分/优惠券 → knowledge/logic-test.md + knowledge/race-condition-test.md",
        "- GraphQL → knowledge/graphql-test.md",
        "- JWT/OAuth → knowledge/oauth-jwt-test.md",
        "- WebSocket → knowledge/websocket-test.md",
        "- WAF拦截 → knowledge/waf-bypass.md",
        "- Java中间件 → knowledge/deserialization-test.md + knowledge/jndi-injection-test.md",
        "- 更多模块用 list_directory knowledge/ 查看",
        "每个模块包含：检测方法、payload、curl示例、WAF绕过、判定标准。",
        "威胁建模阶段识别到特征后，在精准打击阶段加载对应模块获取攻击指导。",
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
            "识别技术栈特征（Java/Spring/Node/PHP/Python）写入 blackboard。"
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
            "加密算法和密钥、webpack里的accessKeyId/secretAccessKey。"
            "发现写入 blackboard pending_hypotheses，附带代码片段。"
            "识别到业务特征后，用 read_file 加载对应 knowledge/ 模块获取攻击指导。"
        ),
    },
    {
        "id": "unauth_probe",
        "name": "未授权访问探测",
        "phase": "strike",
        "prompt": (
            "切换视角：未授权访问探测。\n"
            "先 blackboard_read 获取 attack_surfaces 中所有接口。"
            "根据识别的特征，用 read_file 加载 knowledge/ 下对应模块（如有用户体系加载idor-test.md）。"
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
            "对每个假设，先用 read_file 加载 knowledge/ 下对应漏洞类型模块获取具体payload。"
            "构造具体的利用 PoC 并用 curl 执行真实请求。"
            "成功利用 = FINDING + 写入 verified_findings + exploits。"
            "失败 = 写入 failure_records 并说明原因。"
            "记住：必须有真实响应证据，不能只靠推理。"
            "打穿短表：每确认一个漏洞，立刻查打穿短表联想下一步升级路径。"
        ),
    },
    {
        "id": "bypass_403",
        "name": "绕过探索",
        "phase": "bypass",
        "prompt": (
            "切换视角：绕过探索。\n"
            "先 blackboard_read failure_records 找到所有 403/401 的接口。"
            "用 read_file 加载 knowledge/waf-bypass.md 获取绕过技巧。"
            "穷举绕过姿势：路径删减(/admin;/ /.;/ %2e)、参数污染、"
            "HTTP方法切换(GET→POST→PUT)、UA头修改、Referer/Origin伪造、"
            "X-Forwarded-For/X-Original-URL注入、大小写变体、双重URL编码。"
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
            "对每个已确认漏洞，按打穿短表升级：\n"
            "- SSRF → 云元数据 → AK/SK → S3列桶\n"
            "- IDOR → 批量枚举规模 → 垂直越权\n"
            "- JWT弱密钥 → 伪造admin → 全管理接口\n"
            "- 未授权 → 枚举同前缀接口 → 写操作\n"
            "- 硬编码密钥 → 搜同类密钥 → 验证权限\n"
            "- 信息泄露 → heapdump/Swagger → 连锁利用\n"
            "每个洞至少升级一层，更新 FINDING 严重性评级。"
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
