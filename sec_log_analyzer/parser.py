"""解析层：把一行文本变成结构化数据。

这一层最容易被人低估。面试时如果你只会说"我用正则匹配日志"，对方会追一句
"你的量词会不会回溯爆炸""畸形行怎么办""编码不是 UTF-8 怎么办"。
所以这里每一步都写清楚了为什么这么做。
"""

from __future__ import annotations

import re
from datetime import datetime

from .models import LogEntry

# ---------------------------------------------------------------------------
# nginx 访问日志
# ---------------------------------------------------------------------------
# 标准 combined 格式：
#   $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
#   "$http_referer" "$http_user_agent"
#
# 注意几个坑：
# 1. 空字段是 "-" 而不是空字符串，所以 status 之类要允许 "-"；
# 2. $request 可能是 "-"（畸形请求），此时整段没有空格可切；
# 3. UA 里可能含有转义引号 \"，所以用 [^"]* 而不是 .*?，避免贪婪回溯。
NGINX_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<size>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# 有些日志关掉了 referer/ua（common 格式），用降级正则兜一下，别整行丢掉。
NGINX_COMMON = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}|-) (?P<size>\d+|-)'
)

NGINX_TIME_FORMATS = ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S")

# 请求行三要素：方法 目标 协议。用 maxsplit=2 是因为目标里可能含空格（畸形注入）。
REQUEST_LINE = re.compile(r"^(?P<method>[A-Z]+) (?P<target>\S+)(?: (?P<proto>HTTP/[\d.]+))?$")

# ---------------------------------------------------------------------------
# Linux 认证日志（ssh 爆破检测用）
# ---------------------------------------------------------------------------
SYSLOG_LINE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) (?P<proc>[\w\-.]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

SSH_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
SSH_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# 连接被断开/关闭：不是攻击证据，但属于正常会话的收尾。
# 早期版本把它当解析失败丢掉，导致 auth.log 的解析成功率莫名其妙只有 88%。
SSH_DISCONNECT = re.compile(
    r"(?:Connection closed by|Disconnected from) (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
# 兜底提取 IP。必须同时认 from 和 by 两个介词：
#   Failed password for root from 10.0.0.5 ...   -> from
#   Connection closed by 10.0.0.5 port 4321      -> by
#   Disconnected from 172.16.0.8 port 5612       -> from
# 原版只写了 from，导致 "Connection closed by" 这类行整行被判为解析失败。
# 真实服务器上这类行数量极大，漏掉它们会让"解析成功率"这个指标失去意义。
IP_ANY = re.compile(
    r"(?:from|by) (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def decode_bytes(data: bytes, candidates: tuple[str, ...]) -> tuple[str, str]:
    """按候选顺序尝试解码，返回 (文本, 实际使用的编码)。

    security 类工具经常要处理别人导出的日志，GBK/GB18030 很常见。
    直接 open(encoding='utf-8') 遇到一个非法字节就整个文件崩掉，这是原项目的隐患之一。
    latin-1 能解码任意字节，所以作为最后兜底，保证永远不抛异常。
    """
    for enc in candidates:
        try:
            return data.decode(enc), enc
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("latin-1", errors="replace"), "latin-1(replace)"


def infer_year(ts_text: str, now: datetime | None = None) -> datetime:
    """给不带年份的 syslog 时间补年份。

    这是原项目最直观的 bug：report.txt 里写着 "1900-01-15 03:22:01"。
    原因：datetime.strptime("Jan 15 03:22:01", "%b %d %H:%M:%S") 的年份默认是 1900。
    正确做法是先假设是今年，如果补出来的时间比"现在"晚了一年以上，
    说明这是去年 12 月的日志（跨年场景），年份要减一。
    """
    now = now or datetime.now()
    current = datetime.strptime(f"{now.year} {ts_text}", "%Y %b %d %H:%M:%S")
    # 容差 1 天，避免日志服务器和本机时钟有几小时偏差时误判
    if (current - now).total_seconds() > 86_400:
        current = current.replace(year=current.year - 1)
    return current


def _parse_time(raw: str) -> datetime | None:
    for fmt in NGINX_TIME_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        # 关键：把带时区的时间统一转成本地时间再去掉 tzinfo。
        # 否则同一个列表里既有 aware 又有 naive 的 datetime，
        # 后面排序或做减法时会抛 "can't compare offset-naive and offset-aware datetimes"。
        # 这是实战里非常常见的坑：日志混了多个来源就开始崩。
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    return None


def parse_access_line(line: str) -> LogEntry | None:
    """解析一行 nginx 日志。无法识别时返回 None，由调用方计入错误统计。"""
    m = NGINX_COMBINED.match(line) or NGINX_COMMON.match(line)
    if not m:
        return None

    gd = m.groupdict()
    request = gd.get("request") or ""
    method = path = query = proto = ""
    if request and request != "-":
        rm = REQUEST_LINE.match(request)
        if rm:
            method = rm.group("method")
            target = rm.group("target")
            proto = rm.group("proto") or ""
        else:
            # 畸形请求，比如 "GET /a b" 或纯二进制探测。整段当成 target，
            # 因为攻击载荷往往就藏在这种不合规的请求行里，不能丢弃。
            target = request
        path, _, query = target.partition("?")

    status_raw = gd.get("status") or "-"
    size_raw = gd.get("size") or "-"

    return LogEntry(
        ip=gd.get("ip", ""),
        raw=line,
        source="access",
        ts=_parse_time(gd.get("time", "")),
        method=method,
        path=path,
        query=query,
        protocol=proto,
        status=int(status_raw) if status_raw.isdigit() else None,
        size=int(size_raw) if size_raw.isdigit() else None,
        referer=gd.get("referer") or "",
        user_agent=gd.get("ua") or "",
    )


def parse_auth_line(line: str, now: datetime | None = None) -> LogEntry | None:
    """解析一行 sshd 认证日志。只关心"谁从哪来、成功还是失败"。"""
    m = SYSLOG_LINE.match(line)
    if not m:
        return None

    msg = m.group("msg")
    username = ""
    ip = ""
    event = "other"

    if fm := SSH_FAILED.search(msg):
        username, ip, event = fm.group("user"), fm.group("ip"), "failed"
    elif am := SSH_ACCEPTED.search(msg):
        username, ip, event = am.group("user"), am.group("ip"), "accepted"
    elif im := SSH_INVALID_USER.search(msg):
        username, ip, event = im.group("user"), im.group("ip"), "invalid_user"
    elif dm := SSH_DISCONNECT.search(msg):
        ip, event = dm.group("ip"), "disconnect"
    elif pm := IP_ANY.search(msg):
        ip = pm.group("ip")

    if not ip:
        return None

    try:
        ts = infer_year(m.group("ts"), now)
    except ValueError:
        ts = None

    # 把事件类型拼回 message，检测层靠它区分失败/成功，不用再跑一遍正则
    return LogEntry(
        ip=ip,
        raw=line,
        source="auth",
        ts=ts,
        username=username,
        message=f"{event}: {msg}",
    )


class LogParser:
    """统一的入口：喂行，吐结构化条目。

    用类而不是一堆裸函数，是为了让"现在读的是哪一年"这种状态有地方放，
    也方便以后换成流式解析（大文件不需要一次读进内存）。
    """

    def __init__(self, config, now: datetime | None = None) -> None:
        self.config = config
        self.now = now

    def parse_line(self, line: str) -> LogEntry | None:
        line = line.strip()
        if not line:
            return None
        entry = parse_access_line(line)
        if entry is not None:
            return entry
        return parse_auth_line(line, now=self.now)

    def parse_text(self, text: str) -> tuple[list[LogEntry], list[str]]:
        """返回 (条目列表, 解析失败的行)。失败行要留着给用户看，不能静默吞掉。"""
        entries: list[LogEntry] = []
        errors: list[str] = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(entries) >= self.config.max_lines:
                errors.append(f"已达行数上限 {self.config.max_lines}，剩余内容被截断")
                break
            stripped = line.strip()
            if not stripped:
                continue
            entry = self.parse_line(stripped)
            if entry is None:
                errors.append(f"第 {lineno} 行无法识别: {stripped[:120]}")
            else:
                entries.append(entry)
        return entries, errors
