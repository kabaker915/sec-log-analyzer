"""启动 Web 控制台。

    python run_web.py --log /var/log/nginx/access.log --log /var/log/auth.log

默认只监听 127.0.0.1。要对外网开放必须显式加 --host 0.0.0.0，
并且启动时会打印警告 —— 不要让别人帮你决定要不要暴露一个
能封 IP 的后台，这种事必须是有意识的选择。

    --live  真正写入 nginx deny 配置。不加就是演练模式：只记录、不生效。
"""

from __future__ import annotations

import argparse
import sys

from webapp import create_app


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="日志安全控制台")
    ap.add_argument("--log", action="append", default=[], required=True,
                    help="要监控的日志文件，可重复传")
    ap.add_argument("--host", default="127.0.0.1",
                    help="监听地址，默认仅本机")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--live", action="store_true",
                    help="生效模式：真正写 nginx deny 并重载。不加为演练模式")
    ap.add_argument("--no-watch", action="store_true",
                    help="不启动日志跟随（只看已有数据，调试界面用）")
    ap.add_argument("--from-start", action="store_true",
                    help="从文件开头读。演示时必须加，否则面板会是空的")
    ap.add_argument("--access-log", action="store_true",
                    help="显示每条 HTTP 访问日志（默认关闭，否则刷屏看不到告警）")
    args = ap.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "⚠️  正在监听非本机地址。这个后台能看到全部攻击日志、能封禁 IP，\n"
            "    暴露到公网前请确认：已启用 HTTPS、已设置强密码、\n"
            "    并且前面有反向代理做限流。\n",
            file=sys.stderr,
        )

    # 关掉 Werkzeug 的访问日志。
    #
    # 不关的话会是这样：页面每 2 秒轮询一次统计、每 5 秒轮询一次封禁列表、
    # SSE 还在持续连接，终端每秒刷好几行 HTTP 访问记录，
    # 真正的告警被完全淹没 —— 这跟"告警疲劳"是同一类问题，只是发生在终端里。
    #
    # 需要看访问日志时加 --access-log。
    if not args.access_log:
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)

    app = create_app(
        args.log,
        dry_run=not args.live,
        start_watcher=not args.no_watch,
        from_start=args.from_start,
    )

    # 抹掉 Werkzeug 开发服务器自己加的 Server 头。
    #
    # 应用层的 after_request 删不掉它：那个头是 WSGI 服务器在应用**之外**
    # 加的，响应出应用时已经定稿。所以必须直接改服务器的类属性。
    #
    # 为什么在意这个：`Werkzeug/3.1.9 Python/3.13.14` 直接告诉攻击者
    # 用什么框架、什么版本，拿去查 CVE 就行。信息泄露不是"高危漏洞"，
    # 但它让攻击者的第一步从"试探"变成"查表"，成本差一个数量级。
    #
    # 这个改动只在开发服务器上有效。生产部署换成 gunicorn / waitress 时，
    # 同样要关掉它们各自的 Server 头（gunicorn: --no-server-header）。
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "web"
    WSGIRequestHandler.sys_version = ""

    mode = "生效模式（会真正封禁）" if args.live else "演练模式（只记录不生效）"
    print(f"控制台启动：http://{args.host}:{args.port}    {mode}")

    # debug 永远是 False。Werkzeug 调试器会给访问者一个可执行 Python 的界面，
    # 这是历史上被利用过很多次的真实漏洞，不能靠"只在开发时开"来规避。
    app.run(host=args.host, port=args.port, debug=False, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
