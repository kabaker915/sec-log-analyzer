"""Web 界面层的安全原语：密码、会话、CSRF、限流、输入校验。

为什么把安全逻辑单独抽一个文件，而不是散在各个路由里

    散着写的结果是"哪里想起来哪里加"，最后一定漏。
    集中成原语之后，每条路由只要调用，不需要重新思考一遍安全。
    安全问题的本质不是"写不出对的代码"，是"漏掉了某一处"。

这里刻意不用 Flask-Login / Flask-WTF 这些库

    第一，这个项目的核心引擎坚持零第三方依赖，界面层只加 Flask 本身。
    第二，登录、CSRF、限流这三件事逻辑很小，自己写反而能讲清楚每一个决定。
    第三，面试时"我用了 Flask-Login"和"我自己实现了会话与 CSRF 防护"
    是两种完全不同的回答。
    但也要诚实：真实生产环境应该用成熟库，自己写的价值在于理解，不在于更安全。
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
import threading
import time
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# 密码
# ---------------------------------------------------------------------------
# PBKDF2-HMAC-SHA256，60 万次迭代（OWASP 2023 对 PBKDF2-SHA256 的建议值）。
#
# 为什么不用 md5/sha256 直接哈希：它们太快了。一张消费级显卡每秒能算
# 上百亿次 sha256，8 位密码的字典几分钟就撞完。
# PBKDF2 的设计目标就是"慢"，把每次尝试的成本抬到攻击者算不起的量级。
#
# 为什么不自己实现加盐：salt 的作用是让相同密码产生不同哈希，
# 防止彩虹表和"撞库一个就破一片"。os.urandom 是密码学安全的随机源，
# random 模块是可预测的，绝不能拿来做 salt。
PBKDF2_ITERATIONS = 600_000
PBKDF2_ALGO = "sha256"


def hash_password(password: str, *, iterations: int = PBKDF2_ITERATIONS) -> str:
    """返回 `算法$迭代次数$salt$hash` 的自描述格式。

    把参数写进结果里，是为了将来提高迭代次数时，老密码还能验证通过。
    只存 hash 不存参数的话，改一次参数所有用户都得重置密码。
    """
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac(PBKDF2_ALGO, password.encode(), salt, iterations)
    return f"pbkdf2_{PBKDF2_ALGO}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """校验密码。用 hmac.compare_digest 而不是 ==。

    为什么：`==` 比较字符串时遇到第一个不同字符就返回，耗时随匹配前缀长度变化。
    攻击者可以通过反复请求测出时间差，一位一位地把哈希猜出来。
    这叫时序攻击，虽然在这个场景下很难利用，但成本几乎为零为什么不做。
    """
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if not algo.startswith("pbkdf2_"):
            return False
        dk = hashlib.pbkdf2_hmac(
            PBKDF2_ALGO, password.encode(), bytes.fromhex(salt_hex), int(iterations)
        )
        return hmac.compare_digest(dk.hex(), hash_hex)
    except (ValueError, AttributeError):
        # 格式不对一律判失败，不向上抛异常。
        # 抛异常会把"这个账号的密码字段是坏的"这个信息泄露出去。
        return False


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------
def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def csrf_ok(expected: str, provided: str) -> bool:
    """常数时间比较。CSRF token 泄露不了什么，但比较方式统一处理更省心。"""
    if not expected or not provided:
        return False
    return hmac.compare_digest(expected, provided)


# ---------------------------------------------------------------------------
# 登录限流
# ---------------------------------------------------------------------------
@dataclass
class _Bucket:
    failures: list[float] = field(default_factory=list)
    locked_until: float = 0.0


class LoginThrottle:
    """按 (IP, 用户名) 分别限流，防止爆破和撞库。

    为什么两个维度都要：
      只按 IP —— 攻击者换 IP 就能绕过（用代理池成本极低）
      只按用户名 —— 攻击者可以对一个用户名从一万个 IP 各试一次
      两个都记，任一超限即拦，才需要同时绕过两重限制。

    为什么用滑动窗口而不是固定窗口：
      固定窗口在边界处可以打双倍次数（第 59 秒一次、第 61 秒一次）。
      这个漏洞在真实系统里被利用过很多次。

    锁定时长取指数退避：连续被锁得越频繁，下次锁得越久。
    目的是让慢速撞库变得不划算，而不是彻底堵死（那会误伤忘记密码的正常用户）。
    """

    def __init__(self, max_failures: int = 5, window: int = 300,
                 base_lock: int = 300, max_entries: int = 10_000) -> None:
        self.max_failures = max_failures
        self.window = window
        self.base_lock = base_lock
        # 上限存在的理由：这个字典的键来自用户输入，
        # 不设上限就是一个内存放大攻击面（换着 IP 打，字典无限增长）。
        self.max_entries = max_entries
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def _key(self, ip: str, username: str) -> tuple[str, str]:
        return (ip, username.lower()[:64])

    def check(self, ip: str, username: str) -> tuple[bool, int]:
        """返回 (是否允许尝试, 还要等多少秒)。"""
        now = time.monotonic()
        with self._lock:
            b = self._buckets.get(self._key(ip, username))
            if b is None:
                return True, 0
            if b.locked_until > now:
                return False, int(b.locked_until - now)
            return True, 0

    def record_failure(self, ip: str, username: str) -> None:
        now = time.monotonic()
        with self._lock:
            if len(self._buckets) >= self.max_entries:
                self._evict(now)
            key = self._key(ip, username)
            b = self._buckets.setdefault(key, _Bucket())
            # 只保留窗口内的失败记录，旧的丢掉
            b.failures = [t for t in b.failures if now - t < self.window]
            b.failures.append(now)
            if len(b.failures) >= self.max_failures:
                # 失败次数越多，锁得越久：5 次 5 分钟，10 次 25 分钟……
                over = len(b.failures) - self.max_failures
                b.locked_until = now + self.base_lock * (over + 1)

    def record_success(self, ip: str, username: str) -> None:
        """登录成功就清空记录。

        不清的话，一个正常用户白天输错几次、晚上再输错几次，
        会被累积到锁定——而他从没连续输错过。
        """
        with self._lock:
            self._buckets.pop(self._key(ip, username), None)

    def _evict(self, now: float) -> None:
        """清掉既没在锁定期、又没有近期失败的条目。"""
        dead = [
            k for k, b in self._buckets.items()
            if b.locked_until < now and all(now - t >= self.window for t in b.failures)
        ]
        for k in dead[: self.max_entries // 4]:
            self._buckets.pop(k, None)


# ---------------------------------------------------------------------------
# 输入校验
# ---------------------------------------------------------------------------
def parse_ip(value: str) -> str | None:
    """严格校验 IP 字面量，返回规范化后的字符串；不合法返回 None。

    ⚠️ 这个函数是整个封禁链路的安全闸门，作用有三：

    1. 阻止命令注入。封禁最终要写进 nginx 配置或 iptables 规则，
       如果直接拼字符串，`1.2.3.4; rm -rf /` 就是一次远程命令执行。
       用 ipaddress 解析之后，输出只可能是规范 IP，注入字符根本活不下来。

    2. 阻止配置注入。nginx 配置里换行是有语义的，
       传 `1.2.3.4;\n}` 能闭合块、注入任意指令。
       规范化后不含换行和分号。

    3. 阻止误封。拒绝 0.0.0.0、广播地址、以及自己。
       "把自己封了"是自动化响应里最常见的事故。

    正确做法是白名单解析（只接受能解析成 IP 的），不是黑名单过滤
    （把 `;` `|` `$` 这些字符过滤掉）。黑名单永远漏。
    """
    if not value or len(value) > 45:  # 45 = IPv6 最大长度，先挡超长输入
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if ip.is_unspecified or ip.is_multicast or ip.is_reserved:
        return None
    return str(ip)


def is_loopback(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# 安全响应头
# ---------------------------------------------------------------------------
def security_headers(csp_nonce: str) -> dict[str, str]:
    """一套响应头，每一条都对应一类具体攻击。

    没有 CSP 的站点，一个 XSS 就等于攻击者拿到了整个后台。
    有 CSP 且禁止内联脚本时，注入的 <script> 根本不会执行。
    这是纵深防御里性价比最高的一层。
    """
    return {
        # 默认只允许同源资源；object-src 'none' 关掉 Flash/插件类载体；
        # base-uri 'none' 防止攻击者用 <base> 劫持所有相对链接；
        # frame-ancestors 'none' 等价于 X-Frame-Options，防点击劫持。
        "Content-Security-Policy": (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{csp_nonce}'; "
            "style-src 'self'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "object-src 'none'; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ),
        # 禁止浏览器猜 MIME 类型。不设的话，上传一个内容是 HTML 的 .txt
        # 可能被当页面执行。
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        # 不要把完整 URL 带给第三方（URL 里可能含 token）
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
        # 只允许 HTTPS 访问（部署到 HTTPS 后生效；localhost 上是空操作）
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        # 这些页面不该被缓存：里面有攻击者 IP 和日志内容
        "Cache-Control": "no-store, max-age=0",
    }
