"""攻击流量统计：把 nginx 日志和凭据日志汇总成人能看懂的东西。

为什么单独写这个而不是直接用 sec_log_analyzer：
    分析器是"逐条判定是不是攻击"，输出的是告警列表；
    这个脚本是"统计一段时间内谁来了、来了多少次、试了什么"，
    输出的是态势。两者视角不同，不能互相替代。

用法（在服务器上）：
    python3 stats.py                    # 概览
    python3 stats.py --top 20           # 看前 20 名扫描源
    python3 stats.py --hours 24         # 只看最近 24 小时
    python3 stats.py --creds            # 看登录爆破的账号密码
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
ACCESS_LOG = APP_DIR / "logs" / "nginx" / "access.log"
CRED_LOG = APP_DIR / "logs" / "login" / "credential.log"

# 已知扫描器的 UA 指纹，用于快速分层（不是全部，只是最常见的那批）
KNOWN_SCANNERS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|dirb|wfuzz|ffuf|nuclei"
    r"|acunetix|awvs|appscan|netsparker|wpscan|xray|burpsuite|hydra|zgrab"
    r"|censys|shodan|palo alto|expanse|internet-measurement|binaryedge"
    r"|netsparker|acunetix|nuclei)",
    re.I,
)

# 被扫最多的路径，按攻击意图归类
PATH_INTENT = [
    ("版本库泄露探测", re.compile(r"/\.(git|svn|hg)(/|$)")),
    ("凭据文件探测",   re.compile(r"/\.(env|aws|npmrc|htpasswd|htaccess)")),
    ("应用配置探测",   re.compile(r"/(wp-config|web\.config|config\.(php|json|ya?ml))")),
    ("备份文件探测",   re.compile(r"\.(zip|tar\.gz|tgz|sql|bak|7z|rar|old|swp)$", re.I)),
    ("管理后台探测",   re.compile(r"/(phpmyadmin|pma|adminer|wp-login|wp-admin|admin|manager/html)")),
    ("Spring 端点探测", re.compile(r"/actuator/")),
    ("常见组件探测",   re.compile(r"/(solr|elasticsearch|console|jenkins|druid|nacos|swagger)")),
    ("Shell 上传探测", re.compile(r"\.(php|jsp|asp|aspx)$", re.I)),
]


def load_access(hours: int | None) -> list[dict]:
    """读 nginx JSON 日志。日志格式是 escape=json，可以直接 json.loads。"""
    if not ACCESS_LOG.exists():
        return []

    cutoff = datetime.now().astimezone() - timedelta(hours=hours) if hours else None
    out: list[dict] = []

    with ACCESS_LOG.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue

            if cutoff:
                try:
                    # nginx 的 $time_local 形如 10/Nov/2026:21:30:00 +0800
                    ts = datetime.strptime(rec["time"], "%d/%b/%Y:%H:%M:%S %z")
                except (KeyError, ValueError):
                    pass
                else:
                    if ts < cutoff:
                        continue
            out.append(rec)
    return out


def load_creds() -> list[dict]:
    if not CRED_LOG.exists():
        return []
    rows = []
    with CRED_LOG.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def is_public(ip: str) -> bool:
    """区分公网 IP 和内网 IP。内网来源一般是扫描平台自己的探测。"""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not (a.is_private or a.is_loopback or a.is_reserved or a.is_multicast)


def classify_path(uri: str) -> str:
    for name, pat in PATH_INTENT:
        if pat.search(uri):
            return name
    return "普通业务请求"


def bar(n: int, total: int, width: int = 24) -> str:
    if total == 0:
        return ""
    fill = int(n / total * width)
    return "█" * max(fill, 1 if n else 0)


def main() -> int:
    ap = argparse.ArgumentParser(description="攻击流量态势统计")
    ap.add_argument("--hours", type=int, default=None, help="只看最近 N 小时")
    ap.add_argument("--top", type=int, default=10, help="展示前 N 名")
    ap.add_argument("--creds", action="store_true", help="显示登录爆破的账号密码统计")
    args = ap.parse_args()

    recs = load_access(args.hours)
    creds = load_creds()

    if not recs and not creds:
        print("没有数据。确认容器已启动，且日志路径正确：")
        print(f"  {ACCESS_LOG}")
        print(f"  {CRED_LOG}")
        return 1

    span = f"最近 {args.hours} 小时" if args.hours else "全部"
    print("=" * 62)
    print(f"攻击流量态势  （{span}）")
    print("=" * 62)

    # ---------------- 总览 ----------------
    total = len(recs)
    pub = [r for r in recs if is_public(r.get("ip", ""))]
    uniq_ip = {r.get("ip") for r in pub}
    scanner_hits = [r for r in recs if KNOWN_SCANNERS.search(r.get("ua", ""))]

    print(f"\n总览")
    print(f"  请求总数      {total:>8,}")
    print(f"  独立公网 IP   {len(uniq_ip):>8,}")
    print(f"  扫描器请求    {len(scanner_hits):>8,}  ({len(scanner_hits)/max(total,1)*100:.1f}%)")
    if creds:
        print(f"  登录尝试      {len(creds):>8,}")

    if not recs:
        return 0

    # ---------------- 状态码 ----------------
    codes = Counter(r.get("status") for r in recs)
    print(f"\n状态码分布")
    for code, n in codes.most_common(6):
        print(f"  {code}  {n:>7,}  {bar(n, total)}")

    # ---------------- Top 来源 ----------------
    print(f"\nTop {args.top} 来源 IP")
    ip_counter = Counter(r.get("ip") for r in pub)
    for ip, n in ip_counter.most_common(args.top):
        # 找一个代表性 UA，方便判断是扫描器还是真人
        ua = next((r.get("ua", "") for r in recs if r.get("ip") == ip), "")
        ua_short = (ua[:44] + "…") if len(ua) > 45 else (ua or "-")
        tag = "扫描器" if KNOWN_SCANNERS.search(ua) else "其他  "
        print(f"  {ip:<16} {n:>6}  [{tag}] {ua_short}")

    # ---------------- 攻击意图 ----------------
    print(f"\n扫描意图分布")
    intent = Counter(classify_path(r.get("uri", "")) for r in recs)
    for name, n in intent.most_common():
        print(f"  {name:<14} {n:>7,}  {bar(n, total)}")

    # ---------------- 被扫最多的路径 ----------------
    print(f"\n被请求最多的路径")
    paths = Counter(r.get("path") for r in recs)
    for path, n in paths.most_common(10):
        print(f"  {n:>6}  {path[:70]}")

    # ---------------- 付费区 ----------------
    if creds:
        print(f"\n登录爆破分析")
        users = Counter(c.get("user", "") for c in creds)
        print(f"  被尝试的账号 Top 10")
        for u, n in users.most_common(10):
            print(f"    {n:>5}  {u[:40]}")

        # 口令指纹反查：常见弱口令的 sha256 前 16 位是固定的，
        # 建一张小表就能把高频弱口令识别出来，同时不需要保存明文。
        WEAK = ["123456", "password", "12345678", "qwerty", "123456789",
                "12345", "1234", "111111", "1234567", "admin", "admin123",
                "root", "toor", "pass", "test", "letmein", "welcome"]
        fp_map = {hashlib.sha256(p.encode()).hexdigest()[:16]: p for p in WEAK}

        fps = Counter(c.get("pass_fp", "") for c in creds)
        print(f"  口令特征 Top 10")
        for fp, n in fps.most_common(10):
            hint = fp_map.get(fp, "（已哈希，需比对）")
            print(f"    {n:>5}  {fp[:16]}  {hint}")

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
