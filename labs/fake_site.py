"""靶场网站：几个页面 + 严格按 nginx combined 格式写日志。

为什么不用 Flask / http.server 的 BaseHTTPRequestHandler

    这里要演示的核心场景之一是「畸形请求」——把 TLS 握手包怼到 HTTP 端口，
    nginx 回 400。BaseHTTPRequestHandler 内部自己读请求行、自己判 400，
    想在外层拿到「原始那一行长什么样」要重写 handle_one_request，
    而那个方法的实现随 Python 版本变，重写它等于把一个私有实现复制进项目。

    直接用 socket 读写，总共几十行，每个字节在哪儿都清楚。
    靶场的价值在于「行为可控」，不在于用没用框架。

日志格式严格按 nginx combined

    `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent
     "$http_referer" "$http_user_agent"`

    一个字段都不能少。少一个，解析层就会整体错位——
    那种问题在靶场里可能看不出来（因为我们的解析器和生成器是同一套假设），
    但接到真 nginx 日志时会立刻暴露。所以宁可多写代码，也不要图省事。

用法
    python labs/fake_site.py --port 8081 --log labs/access.log
"""

from __future__ import annotations

import argparse
import socket
import socketserver
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 站点只有两个真页面。其余一律 404——
# 这样「正常访问」和「路径探测」在日志里能区分开：
# 正常用户只访问 / 和 /about，扫描器会去试 /.git/config、/admin.php。
ROUTES = {
    "/": (200, b"<h1>Demo Shop</h1><p>a tiny site for log analysis practice</p>"),
    "/about": (200, b"<h1>About</h1><p>nothing here</p>"),
}

_log_path: Path | None = None
_log_lock = threading.Lock()

# 固定时区偏移。生成日志时用 +0800，和真实服务器一致。
TZ = timezone(timedelta(hours=8))

VALID_METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"}


def nginx_time() -> str:
    """nginx 的 $time_local：11/Nov/2026:11:00:01 +0800

    注意 %d/%b/%Y —— 日期不补零，月份是英文缩写。
    写成 %Y-%m-%d 的话解析层认不出来，会被记成解析失败。
    """
    return datetime.now(TZ).strftime("%d/%b/%Y:%H:%M:%S %z")


def escape_nonprintable(data: bytes) -> str:
    """模拟 nginx 的转义：不可打印字节写成字面量 \\xNN。

    这一步是靶场能不能测出真 bug 的关键。
    nginx 把 TLS 握手包的首字节 0x16 写成四个字符「反斜杠 x 1 6」，
    而不是那一个字节。检测层如果没有同时判这两种形态，
    在靶场里可能「恰好」通过（因为靶场也写二进制），上线就失效。
    """
    out = []
    for b in data:
        if 0x20 <= b < 0x7F:
            out.append(chr(b))
        else:
            out.append(f"\\x{b:02x}")
    return "".join(out)


def write_log(ip: str, request_line: str, status: int, size: int,
              referer: str, ua: str) -> None:
    """追加一行日志。

    加锁不可省：每个连接一个线程，两个线程同时 write 会让两行交错，
    产生一条谁都解析不了的行。这是并发写文件最经典的错误。
    """
    assert _log_path is not None
    line = (
        f'{ip} - - [{nginx_time()}] "{request_line}" {status} {size} '
        f'"{referer or "-"}" "{ua or "-"}"\n'
    )
    with _log_lock:
        with _log_path.open("a", encoding="utf-8") as fh:
            fh.write(line)


class Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        client_ip = self.client_address[0]
        try:
            raw = self._read_head()
        except OSError:
            return
        if not raw:
            return

        head = raw.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
        text = escape_nonprintable(head)

        # 请求行必须是「方法 目标 协议」三段，且方法在白名单里。
        # 不满足就是畸形请求 —— nginx 在这里同样返回 400。
        parts = text.split(" ")
        if len(parts) < 3 or parts[0] not in VALID_METHODS or not parts[2].startswith("HTTP/"):
            self._respond(400, b"<h1>400 Bad Request</h1>", text, client_ip, raw)
            return

        method, target, version = parts[0], parts[1], parts[2]
        path = target.split("?", 1)[0]
        status, body = ROUTES.get(path, (404, b"404 Not Found"))
        if method == "HEAD":
            body_out = b""
        else:
            body_out = body

        self._respond(status, body_out, f"{method} {target} {version}", client_ip, raw)

    def _read_head(self, limit: int = 8192) -> bytes:
        """读到空行为止。读不到就返回已读到的部分。

        限制 8KB 是为了防止有人发超长请求头把内存吃满——
        这类「用超长头部撑爆缓冲区」的手法在网络设备上导致过不少 CVE。
        """
        buf = b""
        self.request.settimeout(5.0)
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf and len(buf) < limit:
            chunk = self.request.recv(1024)
            if not chunk:
                break
            buf += chunk
        return buf

    def _respond(self, status: int, body: bytes, request_line: str,
                 client_ip: str, raw: bytes) -> None:
        reason = {200: "OK", 400: "Bad Request", 404: "Not Found"}.get(status, "OK")
        resp = (
            f"HTTP/1.1 {status} {reason}\r\n"
            f"Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode() + body
        try:
            self.request.sendall(resp)
        except OSError:
            pass

        # UA / Referer 从原始头部里取。取不到就记 "-"，和 nginx 行为一致。
        ua = referer = "-"
        for line in raw.split(b"\r\n")[1:]:
            low = line.lower()
            if low.startswith(b"user-agent:"):
                ua = line.split(b":", 1)[1].strip().decode("latin-1")
            elif low.startswith(b"referer:"):
                referer = line.split(b":", 1)[1].strip().decode("latin-1")

        write_log(client_ip, request_line, status, len(body), referer, ua)


class Server(socketserver.ThreadingTCPServer):
    # 端口复用：频繁重启靶场时不用等 TIME_WAIT 结束（默认要 60 秒）。
    allow_reuse_address = True
    daemon_threads = True

    def server_bind(self):
        # 关掉反向 DNS 查询。不关的话每个连接都要查一次，
        # 在内网环境会卡几秒，看着像"站点很慢"，其实是 DNS 超时。
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        socketserver.ThreadingTCPServer.server_bind(self)


def main(argv: list[str] | None = None) -> int:
    global _log_path
    ap = argparse.ArgumentParser(description="靶场网站")
    ap.add_argument("--port", type=int, default=8081)
    ap.add_argument("--log", default="labs/access.log")
    ap.add_argument("--host", default="127.0.0.1",
                    help="默认仅本机。靶场不需要暴露到公网")
    args = ap.parse_args(argv)

    _log_path = Path(args.log)
    _log_path.parent.mkdir(parents=True, exist_ok=True)
    _log_path.touch(exist_ok=True)

    srv = Server((args.host, args.port), Handler)
    print(f"靶场站点: http://{args.host}:{args.port}")
    print(f"日志写入: {_log_path.resolve()}")
    print("Ctrl-C 停止")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
