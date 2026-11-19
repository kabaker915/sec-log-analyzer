"""统一启动入口：检测引擎 + 控制台，可分别开关。

    python run.py --log "/var/log/nginx/access.log*"                  # 控制台 + 检测
    python run.py --log "/var/log/nginx/access.log*" --console off    # 只检测，不开端口
    python run.py --log samples/xxx.log --console on --port 8090      # 只起控制台

为什么要这个开关
----------------
控制台会监听一个端口，企业内部有些机器不允许开监听，或者由反向代理统一接管。
这时仍然需要检测能力（告警打到 journald 或 stdout），只是不需要 Web 界面。

所以模型分成两个模块：

    检测引擎（LogWatcher）—— 始终运行
    控制台（Flask）      —— 可选，--console on/off

优先级：命令行 > 环境变量 CONSOLE_ENABLED > 默认 on。
systemd 里改一行 Environment=CONSOLE_ENABLED=0 就能关掉，不用改 ExecStart。
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time

FALSY = {"0", "off", "false", "no", "disable", "disabled"}
TRUTHY = {"1", "on", "true", "yes", "enable", "enabled"}


def _env_console() -> bool | None:
    """从环境变量读控制台开关。读不出来返回 None，交给默认值。

    不用 bool() 直接转换：bool("0") 是 True，这是个经典陷阱。
    """
    raw = (os.getenv("CONSOLE_ENABLED") or "").strip().lower()
    if raw in TRUTHY:
        return True
    if raw in FALSY:
        return False
    if raw:
        print(f"[警告] CONSOLE_ENABLED={raw!r} 无法识别，按默认值处理", file=sys.stderr)
    return None


def _fmt(f) -> str:
    ts = f.ts.strftime("%H:%M:%S") if getattr(f, "ts", None) else "--:--:--"
    sev = {"low": "低危", "medium": "中危", "high": "高危", "critical": "严重"}.get(
        f.severity.value if hasattr(f.severity, "value") else str(f.severity), "?")
    reason = (getattr(f, "reason", "") or "").replace("\n", " ")
    if len(reason) > 80:
        reason = reason[:80] + "…"
    return f"[{ts}] [{sev}] {f.category:<8} {f.ip:<16} {reason}"


def run_engine(log_paths: list[str], from_start: bool, dry_run: bool) -> int:
    """无控制台模式：只跑检测，告警打到 stdout（systemd 下进 journald）。

    这个模式下进程不监听任何端口，适合不允许对外提供 Web 服务的环境。
    """
    from sec_log_analyzer.config import Config
    from sec_log_analyzer.paths import expand_log_paths
    from sec_log_analyzer.watcher import LogWatcher

    # 通配符必须自己展开：命令行不会替我们展开
    resolved = expand_log_paths(log_paths)
    print(f"[引擎] 启动，监控 {len(resolved)} 个日志，关闭控制台", flush=True)
    for p in resolved:
        print(f"[引擎]   {p}", flush=True)

    watcher = LogWatcher(resolved, Config.from_env(), from_start=from_start)
    stop = threading.Event()

    def _stop(signum, _frame):
        # systemctl stop 发的是 SIGTERM。收到后要让 run() 正常退出，
        # 否则 systemd 等到超时会 SIGKILL，日志写入可能被截断。
        print(f"[引擎] 收到信号 {signum}，准备退出", flush=True)
        stop.set()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    def on_finding(f):
        print(_fmt(f), flush=True)

    try:
        watcher.run(on_finding=on_finding, stop_event=stop)
    finally:
        watcher.close()
        s = watcher.snapshot()
        print(f"[引擎] 退出。已解析 {s.get('entries_parsed', 0)} 行，"
              f"告警 {s.get('findings', 0)} 条", flush=True)
    return 0


def run_console(args) -> int:
    """控制台模式：起 Flask，检测作为后台线程跑在里面。"""
    from webapp import create_app

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "⚠️  正在监听非本机地址。这个后台能看到全部攻击日志、能封禁 IP，\n"
            "    暴露到公网前请确认：已启用 HTTPS、已设置强密码、\n"
            "    并且前面有反向代理做限流。\n",
            file=sys.stderr,
        )

    # 关掉 Werkzeug 访问日志，否则每 2 秒的轮询会把真正的告警淹掉
    if not args.access_log:
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app = create_app(
        args.log,
        dry_run=not args.live,
        start_watcher=not args.no_watch,
        from_start=args.from_start,
    )

    # 抹掉 Server 头。它在应用之外由 WSGI 服务器添加，只能在服务器类上改。
    from werkzeug.serving import WSGIRequestHandler
    WSGIRequestHandler.server_version = "web"
    WSGIRequestHandler.sys_version = ""

    mode = "生效模式（会真正封禁）" if args.live else "演练模式（只记录不生效）"
    print(f"控制台启动：http://{args.host}:{args.port}    {mode}", flush=True)

    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="统一入口：检测引擎 + 可选控制台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--log", action="append", default=[], required=True,
                    help="要监控的日志，可重复。支持通配符，如 '/var/log/nginx/access.log*'")
    ap.add_argument("--console", choices=["on", "off"], default=None,
                    help="是否启动 Web 控制台。默认读环境变量 CONSOLE_ENABLED，再默认 on")
    ap.add_argument("--host", default="127.0.0.1", help="控制台监听地址，默认仅本机")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--live", action="store_true",
                    help="生效模式：真正写 nginx deny 并重载。不加为演练模式")
    ap.add_argument("--no-watch", action="store_true",
                    help="不起日志跟随（只看已有数据，调试界面用）")
    ap.add_argument("--from-start", action="store_true",
                    help="从文件开头读。演示时必须加，否则面板是空的")
    ap.add_argument("--access-log", action="store_true",
                    help="显示每条 HTTP 访问日志（默认关闭）")
    args = ap.parse_args(argv)

    if args.console is None:
        env = _env_console()
        console_on = True if env is None else env
    else:
        console_on = args.console == "on"

    # 无控制台时 --no-watch 没意义：那等于什么都不做
    if not console_on and args.no_watch:
        print("[警告] --console off 时 --no-watch 无意义，已忽略", file=sys.stderr)

    if console_on:
        return run_console(args)
    return run_engine(args.log, args.from_start, dry_run=not args.live)


if __name__ == "__main__":
    raise SystemExit(main())
