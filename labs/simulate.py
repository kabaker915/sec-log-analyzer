"""攻击模拟：对着靶场打一轮，让检测规则一条条触发。

设计原则：**每条请求都是真实的网络请求**，走完整的 socket -> 靶场 -> 日志 ->
解析 -> 检测链路。只有「谁在打」是假的（源 IP 都是本机回环）。

为什么不直接把告警记录塞进控制台

    那样演示的只是界面的渲染能力，不是检测能力。
    真正的验证必须让请求走完整链路：如果解析层把畸形请求吃掉了，
    或者规则写错了，只有真跑一遍才能发现。
    这也是我在这个项目里踩过的坑 —— 手写测试串「恰好」通过，
    真实日志却漏报。

各场景对应的规则

    normal       -> 应该 0 告警（用来验证不会误报）
    xss          -> xss_handler / xss_tag / xss_proto
    sqli         -> sqli_union / sqli_tautology
    traversal    -> traversal_dotdot
    sensitive    -> sens_vcs / sens_env / sens_backup
    scanner-ua   -> 扫描器指纹
    dirscan      -> 目录扫描（behav_404_burst）
    distributed  -> 分布式扫描（behav_distributed_scan）
    malformed    -> 协议误用探测（behav_http_400_burst）

用法
    python labs/simulate.py                    # 跑全部场景
    python labs/simulate.py --only xss sqli    # 只跑指定场景
    python labs/simulate.py --list             # 看有哪些场景
"""

from __future__ import annotations

import argparse
import random
import socket
import string
import sys
import time
from datetime import datetime
from pathlib import Path

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081


def send(host: str, port: int, request_line: bytes, *,
         ua: str | None = None, src: str | None = None,
         extra: str = "") -> str:
    """发一条原始请求，返回状态码字符串（如 "200"），失败返回 "ERR"。

    用裸 socket 而不是 requests/urllib，是因为要三件它们做不到的事：
      1. 发完全不合法的请求行（TLS 握手包）
      2. 指定源 IP（模拟分布式扫描）
      3. 控制每一段字节

    src 参数对应「分布式扫描」场景：绑 127.0.0.x 作为源地址。
    127.0.0.0/8 整段都是回环，Windows 和 Linux 都允许绑定不同地址，
    这样就能在本机造出「多个不同 IP」的效果，而且不需要伪造 IP头。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        if src:
            sock.bind((src, 0))
        sock.connect((host, port))

        head = request_line + b"\r\n"
        head += b"Host: " + f"{host}:{port}".encode() + b"\r\n"
        if ua:
            head += b"User-Agent: " + ua.encode() + b"\r\n"
        if extra:
            head += extra.encode() + b"\r\n"
        head += b"Connection: close\r\n\r\n"
        sock.sendall(head)

        data = sock.recv(64)
        # 响应第一行形如 "HTTP/1.1 200 OK"
        parts = data.split(b" ", 2)
        return parts[1].decode() if len(parts) >= 2 else "ERR"
    except OSError as exc:
        return f"ERR({exc.__class__.__name__})"
    finally:
        sock.close()


def req(path: str, method: str = "GET", **kw) -> str:
    return send(kw.pop("host", DEFAULT_HOST), kw.pop("port", DEFAULT_PORT),
                f"{method} {path} HTTP/1.1".encode(), **kw)


# ---------------------------------------------------------------------------
# 场景
# ---------------------------------------------------------------------------
def scene_normal(host, port):
    """正常用户。这一条很重要：如果它也报警，说明规则有误报。"""
    out = []
    for p in ("/", "/about", "/", "/about"):
        out.append(req(p, host=host, port=port,
                       ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"))
        time.sleep(0.15)
    return f"4 次正常访问 -> {','.join(out)}（期望 0 告警）"


def scene_xss(host, port):
    payloads = [
        "/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
        "/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
        "/?next=javascript:alert(1)",
    ]
    out = [req(p, host=host, port=port, ua="Mozilla/5.0") for p in payloads]
    return f"3 条 XSS -> {','.join(out)}（期望 XSS 告警）"


def scene_sqli(host, port):
    payloads = [
        "/product?id=1%27%20OR%20%271%27%3D%271",
        "/product?id=1%20UNION%20SELECT%201,2,3",
        "/product?id=1%27%20AND%20SLEEP(5)--",
    ]
    out = [req(p, host=host, port=port, ua="Mozilla/5.0") for p in payloads]
    return f"3 条 SQL 注入 -> {','.join(out)}（期望 SQL注入 告警）"


def scene_traversal(host, port):
    payloads = [
        "/../../../../etc/passwd",
        "/static/..%2f..%2f..%2fetc%2fpasswd",
        "/download?file=../../../../etc/shadow",
    ]
    out = [req(p, host=host, port=port, ua="Mozilla/5.0") for p in payloads]
    return f"3 条路径穿越 -> {','.join(out)}（期望 路径穿越 告警）"


def scene_sensitive(host, port):
    paths = ["/.git/config", "/.env", "/backup.zip", "/wp-config.php"]
    out = [req(p, host=host, port=port, ua="Mozilla/5.0") for p in paths]
    return f"4 条敏感文件探测 -> {','.join(out)}（期望 敏感文件探测 告警）"


def scene_scanner(host, port):
    pairs = [
        ("sqlmap/1.7.2#stable (https://sqlmap.org)", "/item?id=1"),
        ("Nikto/2.5.0 (Evasions:None) (Test:Port Check)", "/"),
        ("zgrab/0.x", "/"),
    ]
    out = [req(p, host=host, port=port, ua=u) for u, p in pairs]
    return f"3 个扫描器 UA -> {','.join(out)}（期望 扫描器指纹 告警）"


def scene_dirscan(host, port):
    """12 个不存在的路径，快速连发 -> 触发 404 突发。

    随机路径而不是固定字典，是为了同时满足「次数多」和「路径分散」两个条件。
    目录扫描规则要求两条都满足，因为页面真的挂掉也会有大量 404，
    但路径是同一个。
    """
    out = []
    for _ in range(12):
        name = "".join(random.choices(string.ascii_lowercase, k=8))
        out.append(req(f"/{name}.php", host=host, port=port, ua="Mozilla/5.0"))
    return f"12 个随机路径 -> {','.join(out)}（期望 目录扫描 告警）"


def scene_distributed(host, port):
    """多个源 IP 各发一次同一路径，UA 一致 -> 触发分布式扫描。

    用 127.0.0.2 ~ 127.0.0.7 当源地址。
    这不是伪造 IP——是真的用不同的本地地址建立连接，
    所以服务端看到的 remote_addr 确实不同。
    """
    out = []
    for i in range(2, 8):
        src = f"127.0.0.{i}"
        code = req("/.git/config", host=host, port=port, src=src,
                   ua="Mozilla/5.0 (compatible; Scanner/1.0)")
        out.append(f"{src}:{code}")
    return f"6 个源 IP -> {' '.join(out)}（期望 分布式扫描 告警）"


def scene_malformed(host, port):
    """把 TLS 握手包怼到 HTTP 端口 -> nginx/靶场回 400。

    这是 11-10 在公网服务器上真实抓到的那类探测：
    攻击者用 curl https://ip:80 之类的命令，把 TLS 记录层字节直接发到明文端口。
    载荷里没有任何 SQL 注入或 XSS 特征，内容规则一条都命中不了，
    只能靠协议层的 400 统计发现。
    """
    tls = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
    out = []
    for _ in range(4):
        out.append(send(host, port, tls))
        time.sleep(0.2)
    return f"4 个 TLS 握手包 -> {','.join(out)}（期望 协议误用探测 告警）"


def scene_ssh(auth_log: Path | None, ip: str = "127.0.0.1"):
    """生成 sshd 失败登录日志。

    ⚠️ 这一条是**唯一纯合成**的场景：不产生真实连接，
    只往 auth.log 追加符合 syslog 格式的行。
    原因是本机没有 sshd 可以被爆破，而 SSH 爆破检测值得演示一次。

    格式必须严格对齐 Ubuntu 的 sshd：
        Nov 11 12:00:00 host sshd[1234]: Failed password for root from 1.2.3.4 port 5 ssh2
    少了任何一段，解析层都取不到 IP，规则就不会触发。
    """
    if auth_log is None:
        return "跳过（未指定 --auth-log）"

    host = socket.gethostname()
    lines = []
    for i in range(8):
        ts = datetime.now().strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} {host} sshd[{3000 + i}]: Failed password for invalid user admin "
            f"from {ip} port {40000 + i} ssh2"
        )
        time.sleep(0.1)

    auth_log.parent.mkdir(parents=True, exist_ok=True)
    with auth_log.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return f"8 条 SSH 失败登录 -> {auth_log}（合成数据，期望 SSH爆破 告警）"


SCENES = {
    "normal": scene_normal,
    "xss": scene_xss,
    "sqli": scene_sqli,
    "traversal": scene_traversal,
    "sensitive": scene_sensitive,
    "scanner-ua": scene_scanner,
    "dirscan": scene_dirscan,
    "distributed": scene_distributed,
    "malformed": scene_malformed,
}

ORDER = ["normal", "xss", "sqli", "traversal", "sensitive",
         "scanner-ua", "dirscan", "distributed", "malformed"]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="靶场攻击模拟")
    ap.add_argument("--host", default=DEFAULT_HOST)
    ap.add_argument("--port", type=int, default=DEFAULT_PORT)
    ap.add_argument("--only", nargs="+", default=None, help="只跑指定场景")
    ap.add_argument("--list", action="store_true", help="列出所有场景")
    ap.add_argument("--auth-log", default=None,
                    help="可选：往这个 auth.log 追加合成的 SSH 失败日志")
    ap.add_argument("--delay", type=float, default=0.3,
                    help="场景之间的间隔秒数")
    args = ap.parse_args(argv)

    if args.list:
        for name in ORDER:
            doc = (SCENES[name].__doc__ or "").strip().split("\n")[0]
            print(f"  {name:14} {doc}")
        print(f"  {'ssh':14} 合成 sshd 失败登录（需 --auth-log）")
        return 0

    names = args.only or ORDER
    unknown = [n for n in names if n not in SCENES]
    if unknown:
        print(f"未知场景：{unknown}", file=sys.stderr)
        return 2

    # 先探活，避免每个场景都报 ERR 让人以为规则坏了
    try:
        if req("/", host=args.host, port=args.port) == "ERR":
            raise OSError
    except OSError:
        print(f"连不上靶场 {args.host}:{args.port}\n"
              f"先启动：python labs/fake_site.py --port {args.port}", file=sys.stderr)
        return 1

    print(f"目标 {args.host}:{args.port}\n")
    for name in names:
        result = SCENES[name](args.host, args.port)
        print(f"[{name}] {result}")
        time.sleep(args.delay)

    if args.auth_log:
        print(f"[ssh] {scene_ssh(Path(args.auth_log))}")

    print("\n完成。切到控制台看告警是否出现。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
