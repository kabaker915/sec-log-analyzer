"""规则层：载荷归一化 + 特征规则集。

设计要点（面试必问，先想清楚再写代码）

1. 为什么先归一化再匹配？
   攻击者在 URL 里不可能直接放空格和引号，一定是 %20 / %27。
   你如果拿原始日志去匹配 "union select"，永远匹配不到。
   更狠的是二次编码：%2527 解码一次是 %27，解码两次才是 '。
   所以 normalize() 做两轮解码，并且把 URL 里的 "+" 还原成空格——
   原项目 `union\\s+select` 抓不到 "UnIoN+SeLeCt" 就是栽在这里。

2. 为什么不做"一条正则命中即告警"？
   因为单引号、双连字符在日常业务里太常见（O'Brien、item--detail）。
   只要有正常参数带撇号，误报率就失控。
   正确做法是分级：强特征独立定罪，弱特征只能加权。
   本质是把布尔判断换成加权求和，让规则之间互相"背书"。

3. 为什么规则要写成数据而不是一堆 if？
   规则是数据，引擎是逻辑。加一条新规则只改列表不改代码，
   以后要做成 YAML 配置下发、或者热更新规则库，都不用重构。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote_plus


def normalize(text: str) -> str:
    """把攻击载荷还原成"人看得懂"的形式，供规则匹配。

    只用于匹配，不用于展示——原始日志要原样保留在报告里作为证据。
    """
    s = text
    # 两轮解码：对抗 %2527 这类二次编码。循环里比较前后值，稳定就提前退出，
    # 避免对已经干净的字符串做无谓计算。
    for _ in range(2):
        nxt = unquote_plus(s)
        if nxt == s:
            break
        s = nxt
    # 折叠空白，让 `union    select`、`union%09select` 都归一成 `union select`
    return re.sub(r"\s+", " ", s).strip()


@dataclass(frozen=True, slots=True)
class Rule:
    name: str
    category: str
    weight: int
    pattern: re.Pattern[str]
    note: str


# 权重语义：10 = 强特征（单独即可定罪），3 = 弱特征（需同分类累计达标）
STRONG = 10
WEAK = 3

RULES: tuple[Rule, ...] = (
    # ---------------------------- SQL 注入 ----------------------------
    Rule(
        "sqli_union", "SQL注入", STRONG,
        re.compile(r"\bunion\b\s*(?:all\b\s*)?\bselect\b", re.I),
        "联合查询注入，攻击者用来跨表读数据",
    ),
    Rule(
        "sqli_tautology", "SQL注入", STRONG,
        re.compile(
            r"(?:'|\"|\)|\d)\s*(?:or|and)\s+"
            # 注意结尾的 '? ：真实 payload 的最后一个引号往往是不闭合的，
            # 因为闭合它的那个引号来自应用自己的 SQL 语句。
            # 写成 '...' 要求成对，会把 "1' OR '1'='1" 这种最经典的 payload 漏掉。
            r"(?:'[^']*'?|\"[^\"]*\"?|\d+)\s*=\s*(?:'[^']*'?|\"[^\"]*\"?|\d+)",
            re.I,
        ),
        "恒真条件，绕过登录或扩大查询结果集",
    ),
    Rule(
        "sqli_timebased", "SQL注入", STRONG,
        re.compile(r"\b(?:sleep|benchmark|pg_sleep)\s*\(", re.I),
        "时间盲注，靠延时判断条件真假，不依赖回显",
    ),
    Rule(
        "sqli_meta", "SQL注入", STRONG,
        re.compile(
            r"\b(?:information_schema|sysobjects|load_file|xp_cmdshell)\b"
            r"|\binto\s+(?:out|dump)file\b",
            re.I,
        ),
        "读元数据/写文件，属于注入后的深度利用",
    ),
    Rule(
        "sqli_errorbased", "SQL注入", STRONG,
        re.compile(r"\b(?:extractvalue|updatexml)\s*\(|\bfloor\s*\(\s*rand\s*\(", re.I),
        "报错注入，把数据拼进数据库报错信息带出来",
    ),
    Rule(
        "sqli_stacked", "SQL注入", STRONG,
        re.compile(r";\s*(?:select|insert|update|delete|drop|create|alter)\b", re.I),
        "堆叠查询，一次请求执行多条语句",
    ),
    Rule(
        "sqli_quote", "SQL注入", WEAK,
        re.compile(r"['\"]"),
        "引号只是弱特征：O'Brien 这类正常姓名同样带引号",
    ),
    Rule(
        "sqli_comment", "SQL注入", WEAK,
        # 结尾的 (?:\s|$) 不能省：`1'--` 这种 payload 的注释符在字符串末尾，
        # 后面没有空格。只写 --\s 会漏掉它。
        re.compile(r"--(?:\s|$)|/\*"),
        "注释符用于截断后半句 SQL，但单独出现也可能只是业务字符",
    ),

    # ------------------------------ XSS ------------------------------
    Rule(
        "xss_script", "XSS", STRONG,
        re.compile(r"<\s*script", re.I),
        "直接注入 script 标签",
    ),
    Rule(
        "xss_handler", "XSS", STRONG,
        re.compile(r"\bon(?:error|load|mouseover|focus|click|submit|toggle)\s*=", re.I),
        "事件处理器注入，常用于绕过 script 关键字过滤",
    ),
    Rule(
        "xss_proto", "XSS", STRONG,
        re.compile(r"(?:javascript|vbscript)\s*:|data:text/html", re.I),
        "伪协议触发脚本，href/src 里最常见",
    ),
    Rule(
        "xss_func", "XSS", WEAK,
        re.compile(r"\b(?:alert|prompt|confirm)\s*\(", re.I),
        "弹窗函数是教科书 payload，但正常前端代码里也会有",
    ),
    Rule(
        "xss_tag", "XSS", WEAK,
        re.compile(r"<\s*(?:img|svg|iframe|body|input|video|audio|details)\b", re.I),
        "可承载事件的标签，单看只是可疑",
    ),

    # ---------------------------- 路径穿越 ----------------------------
    Rule(
        "traversal_dotdot", "路径穿越", STRONG,
        re.compile(r"(?:\.\./|\.\.\\)"),
        "向上跳目录，正常业务请求几乎不会出现",
    ),
    Rule(
        "traversal_direct", "路径穿越", STRONG,
        re.compile(r"^(?:/etc/(?:passwd|shadow|hosts|group)|/proc/self/|/windows/win\.ini)", re.I),
        "请求本身就以系统文件开头，直接读本地文件",
    ),
    Rule(
        "traversal_target", "路径穿越", WEAK,
        # 降为弱特征：/etc/passwd 也可能出现在命令注入的参数里，
        # 那种情况应该归到命令注入，不该重复报一条路径穿越。
        re.compile(
            r"/etc/(?:passwd|shadow|hosts|group)|/proc/self/|win\.ini|boot\.ini"
            r"|\\windows\\system32",
            re.I,
        ),
        "穿越目标文件名，单独出现需结合上下文判断",
    ),

    # ---------------------------- 命令注入 ----------------------------
    Rule(
        "cmdi_sep", "命令注入", STRONG,
        re.compile(
            r"[;|`&]\s*(?:cat|ls|whoami|id|uname|wget|curl|nc|ncat|bash|sh|python|"
            r"powershell|ping|chmod|rm|net)\b",
            re.I,
        ),
        "命令分隔符后接系统命令，典型 RCE 探测",
    ),
    Rule(
        "cmdi_subshell", "命令注入", STRONG,
        re.compile(r"\$\(|\|\||`[^`]{1,200}`"),
        "子命令替换，用来拼接执行结果",
    ),

    # -------------------------- 敏感文件探测 --------------------------
    Rule(
        "sens_vcs", "敏感文件探测", STRONG,
        re.compile(r"/\.(?:git|svn|hg)(?:/|$)", re.I),
        "版本库目录可被还原出全部源码",
    ),
    Rule(
        "sens_env", "敏感文件探测", STRONG,
        re.compile(r"/\.(?:env|ds_store|htaccess|htpasswd|gitignore|npmrc)\b", re.I),
        "配置/凭据文件，命中即高价值",
    ),
    Rule(
        "sens_conf", "敏感文件探测", STRONG,
        re.compile(
            r"/(?:wp-config|web\.config|configuration\.php"
            r"|config\.(?:php|json|ya?ml)|application\.properties)",
            re.I,
        ),
        "应用主配置文件，通常含数据库口令",
    ),
    Rule(
        "sens_backup", "敏感文件探测", STRONG,
        re.compile(
            r"/(?:backup|db|database|dump|www|site|web)[\w\-.]*\.(?:zip|tar\.gz|tgz|sql|bak|7z|rar)$",
            re.I,
        ),
        "备份包泄露，是实战中拿源码最省事的路子",
    ),
    Rule(
        "sens_admin", "敏感文件探测", WEAK,
        re.compile(r"/(?:phpmyadmin|pma|adminer|myadmin|manager/html)(?:/|$)", re.I),
        "管理后台入口，正常站点也可能存在，只能算可疑",
    ),
    Rule(
        "sens_ext", "敏感文件探测", WEAK,
        re.compile(r"\.(?:sql|bak|swp|old|orig|save)$", re.I),
        "备份后缀，也可能只是正常静态资源",
    ),

    # ---------------------------- WebShell ----------------------------
    Rule(
        "webshell_func", "WebShell", STRONG,
        re.compile(
            r"\b(?:eval|assert|system|passthru|shell_exec|exec|popen|proc_open)\s*\(", re.I
        ),
        "危险函数出现在参数里，通常是 webshell 回连或一句话木马",
    ),

    # ---------------------------- Log4j ------------------------------
    Rule(
        "log4j_jndi", "Log4j注入", STRONG,
        re.compile(r"\$\{jndi:(?:ldap|rmi|dns|http|iiop)", re.I),
        "CVE-2021-44228，JNDI 注入触发远程类加载",
    ),

    # ------------------------------ SSRF ------------------------------
    Rule(
        "ssrf_internal", "SSRF", STRONG,
        re.compile(
            r"[?&][\w\[\]]*(?:url|uri|target|dest|redirect|callback|image|file)=\s*"
            r"(?:https?://)?(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254"
            r"|10\.\d|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)",
            re.I,
        ),
        "参数指向内网/元数据地址，典型 SSRF 打内网",
    ),
)

# UA 指纹：扫描器通常懒得改 UA，这是成本最低的一层识别
SCANNER_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb|wfuzz|ffuf|nuclei"
    r"|acunetix|awvs|appscan|netsparker|wpscan|xray|burpsuite|hydra|medusa|patator)",
    re.I,
)

# 爬虫白名单：只用于"降噪"，不作为安全放行依据（UA 可伪造）
CRAWLER_UA = re.compile(
    r"(baiduspider|googlebot|bingbot|yandexbot|sogou|360spider|bytespider"
    r"|ahrefsbot|semrushbot|applebot)",
    re.I,
)

# 分类 → 基础等级。命中规则越多、分数越高，会在检测层里上调等级。
CATEGORY_SEVERITY: dict[str, str] = {
    "SQL注入": "high",
    "XSS": "high",
    "命令注入": "critical",
    "WebShell": "critical",
    "Log4j注入": "critical",
    "路径穿越": "high",
    "敏感文件探测": "medium",
    "SSRF": "high",
    "扫描器指纹": "medium",
    "目录扫描": "medium",
    "SSH爆破": "high",
}
