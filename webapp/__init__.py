"""Flask 应用工厂。

为什么用工厂函数而不是模块级 app = Flask(__name__)

    测试要能造多个互不干扰的实例（不同配置、不同状态）。
    模块级单例做不到这件事，测试之间会串状态。

安全基线都在 create_app 里统一施加，路由里不再单独操心：
    * 响应头（CSP / nosniff / frame-ancestors …）
    * 会话 Cookie 属性
    * 登录态校验
    * 请求体大小上限
漏一处就等于没设，所以收口在一个地方。
"""

from __future__ import annotations

import os
import secrets
import threading
import time
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from sec_log_analyzer.config import Config
from sec_log_analyzer.watcher import LogWatcher

from .security import (
    LoginThrottle,
    csrf_ok,
    hash_password,
    new_csrf_token,
    parse_ip,
    security_headers,
    verify_password,
)
from .state import AppState, apply_deny_file, audit

# 会话闲置超时。安全工具的后台不该"打开一次管一天"：
# 分析师离开工位忘关浏览器是很常见的，8 小时是个折中。
SESSION_IDLE_SECONDS = 8 * 3600


def _load_credentials() -> tuple[str, str]:
    """读取用户名与密码哈希。

    密码只以哈希形式存在环境变量里，绝不明文写进代码或配置文件。
    首次部署可以用 `python -m webapp.hashpw` 生成哈希。

    没有配置时给一个随机密码并打印出来，而不是给默认密码 admin/admin ——
    默认密码是物联网设备被大规模入侵的头号原因，不能自己踩同一个坑。
    """
    user = os.getenv("CONSOLE_USER", "admin")
    stored = os.getenv("CONSOLE_PASSWORD_HASH", "")
    if stored:
        return user, stored

    password = secrets.token_urlsafe(12)
    print("=" * 60)
    print("未设置 CONSOLE_PASSWORD_HASH，已生成临时密码（重启后失效）：")
    print(f"    用户名: {user}")
    print(f"    密  码: {password}")
    print("生产部署请用 python -m webapp.hashpw 生成哈希并写入环境变量。")
    print("=" * 60)
    return user, hash_password(password)


def create_app(log_paths: list[str] | None = None, *,
               dry_run: bool = True, start_watcher: bool = True,
               from_start: bool = False, emit_findings: bool = True) -> Flask:
    # 模板和静态资源放在项目根目录的 templates/ static/，
    # 不放进 webapp/ 里面：这样 engine（sec_log_analyzer）和界面完全分离，
    # 前者零依赖、能被命令行和测试直接复用，不会被迫牵扯 webapp 的包结构。
    root = Path(__file__).resolve().parent.parent
    app = Flask(
        __name__,
        template_folder=str(root / "templates"),
        static_folder=str(root / "static"),
    )

    # secret_key 决定 session 能否被伪造。
    # 写死一个默认值等于把所有人的会话签名密钥公开——攻击者可以自己签一个
    # 管理员会话。没给环境变量就随机生成，代价是重启后要重新登录。
    app.secret_key = os.getenv("CONSOLE_SECRET_KEY") or secrets.token_hex(32)

    app.config.update(
        # 会话 Cookie：HttpOnly 让 JS 读不到（XSS 也偷不走 token）；
        # SameSite=Lax 挡住跨站 POST（CSRF 的主要形态）；
        # Secure 在 HTTPS 下必须开，localhost 调试时关掉。
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.getenv("CONSOLE_HTTPS", "0") == "1",
        PERMANENT_SESSION_LIFETIME=SESSION_IDLE_SECONDS,
        # 请求体上限：这个应用只收 JSON 小对象，1MB 都嫌多。
        # 不设上限时，一个超大 POST 就能把内存吃满。
        MAX_CONTENT_LENGTH=256 * 1024,
        # 关闭 Flask 的调试器。开着 Werkzeug 调试器等于给攻击者一个
        # 可交互的 Python 控制台 —— 这在真实事故里出现过很多次。
        DEBUG=False,
    )

    username, password_hash = _load_credentials()
    state = AppState(dry_run=dry_run)
    throttle = LoginThrottle()
    app.extensions["state"] = state

    # ------------------------------------------------------------ 响应头
    @app.before_request
    def _attach_nonce():
        # 每个请求一个 nonce，供内联 <script> 使用（CSP 白名单）。
        # 用随机值而不是固定串，是为了让攻击者无法提前构造能通过 CSP 的标签。
        request.nonce = secrets.token_urlsafe(16)

    @app.after_request
    def _harden(resp: Response) -> Response:
        for k, v in security_headers(getattr(request, "nonce", "")).items():
            resp.headers[k] = v
        # 不设自己的 Server 头，只删。
        #
        # 设一个 "Server: web" 看着更干净，但 Werkzeug 在 WSGI 层还会再加一个，
        # 结果是响应里出现两个 Server 头 —— 重复头在有些扫描器里会被判成异常，
        # 也可能被中间设备用第一个覆盖第二个，反而不可控。
        # 版本信息的真正来源是 WSGI 服务器，那里改才有效（见 run_web.py）。
        resp.headers.pop("Server", None)
        return resp

    # ------------------------------------------------------------ 鉴权
    def current_user() -> str | None:
        user = session.get("user")
        if not user:
            return None
        last = session.get("last_seen", 0)
        if time.time() - last > SESSION_IDLE_SECONDS:
            session.clear()
            return None
        session["last_seen"] = time.time()
        return user

    def require_login():
        """未登录就跳转，API 则返回 401。

        注意 API 不能重定向 —— 前端 fetch 收到 302 后会跟着跳到 HTML，
        然后把整页 HTML 当 JSON 解析，报一个莫名其妙的错。
        """
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login"))
        return None

    # ------------------------------------------------------------ 页面
    @app.get("/login")
    def login_page():
        if current_user():
            return redirect(url_for("dashboard"))
        token = new_csrf_token()
        session["csrf"] = token
        return render_template("login.html", csrf_token=token, error=None,
                               nonce=request.nonce)

    @app.post("/login")
    def login():
        token = session.get("csrf", "")
        provided = request.form.get("csrf_token", "")
        if not csrf_ok(token, provided):
            return render_template("login.html", csrf_token=token,
                                   error="会话已过期，请重试", nonce=request.nonce), 400

        ip = request.remote_addr or ""
        user_in = (request.form.get("username") or "").strip()[:64]
        pwd_in = request.form.get("password") or ""

        allowed, wait = throttle.check(ip, user_in)
        if not allowed:
            audit("login_blocked", ip=ip, username=user_in, wait=wait)
            return render_template(
                "login.html", csrf_token=token,
                error=f"尝试过于频繁，请 {wait} 秒后再试", nonce=request.nonce,
            ), 429

        # 用户名也做常数时间比较：否则"用户名对不对"可以通过响应时间差判断出来
        user_ok = secrets.compare_digest(user_in, username)
        pass_ok = verify_password(pwd_in, password_hash)

        if not (user_ok and pass_ok):
            throttle.record_failure(ip, user_in)
            audit("login_failed", ip=ip, username=user_in)
            # 对外只说"用户名或密码错误"，不区分是哪一项错了。
            # 区分开等于送出"这个用户名存在"的情报，是枚举账号的入口。
            return render_template("login.html", csrf_token=token,
                                   error="用户名或密码错误", nonce=request.nonce), 401

        throttle.record_success(ip, user_in)
        # 登录成功后清空 session 再写 —— 防会话固定攻击。
        # 不清的话，攻击者可以先给受害者种一个自己知道的 session id，
        # 受害者登录后这个 id 就变成了已认证状态，攻击者直接拿去用。
        session.clear()
        session["user"] = user_in
        session["csrf"] = new_csrf_token()
        session["last_seen"] = time.time()
        session.permanent = True
        audit("login_ok", ip=ip, username=user_in)
        return redirect(url_for("dashboard"))

    @app.post("/logout")
    def logout():
        token = session.get("csrf", "")
        if not csrf_ok(token, request.form.get("csrf_token", "")):
            return jsonify({"error": "csrf"}), 400
        user = session.get("user")
        session.clear()
        audit("logout", username=user)
        return redirect(url_for("login"))

    @app.get("/")
    def dashboard():
        gate = require_login()
        if gate:
            return gate
        return render_template(
            "dashboard.html",
            csrf_token=session.get("csrf", ""),
            user=session.get("user", ""),
            dry_run=state.dry_run,
            nonce=request.nonce,
        )

    # ------------------------------------------------------------ API
    def api_gate():
        if current_user() is None:
            return jsonify({"error": "unauthorized"}), 401
        return None

    def api_write_gate():
        """所有写操作必须同时过登录态和 CSRF。

        为什么 JSON 接口也要 CSRF：很多人以为"我只收 JSON 就没有 CSRF"，
        错。跨站请求只要有办法让浏览器带上 Cookie 就行，
        form 表单能发 application/x-www-form-urlencoded，
        攻击者也可以先做一次跨域请求探测。用自定义头 + token 才稳。
        """
        gate = api_gate()
        if gate:
            return gate
        token = session.get("csrf", "")
        if not csrf_ok(token, request.headers.get("X-CSRF-Token", "")):
            return jsonify({"error": "csrf"}), 403
        return None

    @app.get("/api/stats")
    def api_stats():
        gate = api_gate()
        if gate:
            return gate
        w = state.watcher
        snap = w.snapshot() if w else {}
        return jsonify({
            "watcher": snap,
            "buffer": len(w.buffer) if w else 0,
            "bans": len(state.active_bans()),
            "dry_run": state.dry_run,
            "seq": state.seq,
        })

    @app.get("/api/findings")
    def api_findings():
        gate = api_gate()
        if gate:
            return gate
        limit = min(int(request.args.get("limit", 100)), 500)
        sev = request.args.get("severity")
        return jsonify({"items": state.recent(limit, sev)})

    @app.get("/api/stream")
    def api_stream():
        """SSE 增量推送。

        用 SSE 而不是 WebSocket：这个场景只需要服务端单向推，
        SSE 走普通 HTTP、自动重连、不需要额外协议升级，
        在 nginx 后面也更好配。

        安全上要注意：每条数据先 json.dumps 再放进 data 字段。
        不转义的话，日志里的换行会把一条消息拆成两条，
        攻击者可以用这个伪造事件流。
        """
        gate = api_gate()
        if gate:
            return gate

        try:
            since = int(request.args.get("since", 0))
        except ValueError:
            since = 0

        def gen():
            import json as _json
            cursor = since
            idle = 0
            # 上限 20 分钟：SSE 连接会一直占着一个工作线程，
            # 不设上限时多个标签页开着就能把线程池耗光。
            while idle < 1200:
                rows = state.since(cursor)
                if rows:
                    for r in rows:
                        cursor = max(cursor, r["seq"])
                        yield f"data: {_json.dumps(r, ensure_ascii=False)}\n\n"
                    idle = 0
                else:
                    idle += 1
                    # 注释行作为心跳，顺便防止中间代理把空闲连接掐掉
                    yield ": ping\n\n"
                time.sleep(1.0)

        return Response(gen(), mimetype="text/event-stream",
                        headers={"X-Accel-Buffering": "no"})

    @app.post("/api/ban")
    def api_ban():
        gate = api_write_gate()
        if gate:
            return gate

        payload = request.get_json(silent=True) or {}
        ip = parse_ip(str(payload.get("ip", "")))
        if not ip:
            # 校验失败要明确拒绝，不猜用户想填什么。
            # 尤其是这里 —— ip 后面会被写进 nginx 配置。
            return jsonify({"error": "IP 格式不合法"}), 400

        # TTL 必须有上限和下限：0 等于永不封禁（危险），
        # 太大等于永久封禁（事故）。默认 1 小时。
        try:
            ttl = int(payload.get("ttl", 3600))
        except (TypeError, ValueError):
            ttl = 3600
        ttl = max(60, min(ttl, 7 * 86400))

        reason = str(payload.get("reason", "手工封禁"))[:200]
        rec = state.ban(ip, reason, ttl, session.get("user", "?"),
                        finding_uid=str(payload.get("uid", ""))[:120])

        result = None
        if not state.dry_run:
            result = apply_deny_file([r["ip"] for r in state.active_bans()])

        return jsonify({
            "ok": True,
            "record": rec.to_row(),
            "dry_run": state.dry_run,
            "apply": result,
        })

    @app.post("/api/unban")
    def api_unban():
        gate = api_write_gate()
        if gate:
            return gate
        ip = parse_ip(str((request.get_json(silent=True) or {}).get("ip", "")))
        if not ip:
            return jsonify({"error": "IP 格式不合法"}), 400
        ok = state.revoke(ip, session.get("user", "?"))
        if ok and not state.dry_run:
            apply_deny_file([r["ip"] for r in state.active_bans()])
        return jsonify({"ok": ok})

    @app.get("/api/bans")
    def api_bans():
        gate = api_gate()
        if gate:
            return gate
        return jsonify({"items": state.active_bans(), "dry_run": state.dry_run})

    # ------------------------------------------------------------ 后台线程
    if start_watcher and log_paths:
        # from_start=True 是为了演示：默认从文件末尾开始读（生产环境重启后
        # 不该把历史告警重放一遍），但演示时要立刻看到已有内容，
        # 否则打开页面一片空白，看着像坏了。
        watcher = LogWatcher(log_paths, Config.from_env(), from_start=from_start)
        state.watcher = watcher

        def _emit(f) -> None:
            """告警同时写进内存（给页面）和终端（给人看）。

            只在页面上显示是不够的：把控制台挂在服务器上跑的时候，
            人往往是先看 journalctl 的输出，发现异常了才去翻页面。
            终端里一行一条、带等级标记，比在浏览器里滚动更快。
            """
            state.add_finding(f)
            if not emit_findings:
                return
            ts = f.ts.strftime("%H:%M:%S") if f.ts else "--:--:--"
            tag = {
                "critical": "[严重]", "high": "[高危]",
                "medium": "[中危]", "low": "[低危]",
            }.get(f.severity.value, "[?]")
            reason = f.reason if len(f.reason) <= 80 else f.reason[:80] + "…"
            print(f"[{ts}] {tag} {f.category:<8} {f.ip:<15} {reason}", flush=True)

        def _run():
            watcher.run(on_finding=_emit, interval=0.5)

        threading.Thread(target=_run, name="watcher", daemon=True).start()

        def _expire():
            while True:
                time.sleep(30)
                if state.expire_bans():
                    # 过期解封后也要重写配置，否则文件里还留着已过期的 deny
                    if not state.dry_run:
                        apply_deny_file([r["ip"] for r in state.active_bans()])

        threading.Thread(target=_expire, name="ban-expire", daemon=True).start()

    return app
