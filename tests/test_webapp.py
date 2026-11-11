"""控制台的安全回归测试。

这些用例不是在测"功能对不对"，是在测"防护还在不在"。
安全代码有个特点：加功能时最容易顺手把它拆掉 ——
比如为了显示方便改成 innerHTML，一个 XSS 防护就没了，而且功能看起来完全正常。
所以每一条防护都要有一条测试盯着。

跑法：
    ./.venv/Scripts/python.exe tests/test_webapp.py
或
    ./.venv/Scripts/python.exe -m pytest tests/test_webapp.py -q
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 必须在 import webapp 之前设置：create_app 在构造时读取这些环境变量
TEST_PASSWORD = "TestPass!2026"
os.environ["CONSOLE_USER"] = "admin"
os.environ["CONSOLE_SECRET_KEY"] = "test-secret-key-not-for-production"

from webapp.security import hash_password  # noqa: E402

os.environ["CONSOLE_PASSWORD_HASH"] = hash_password(TEST_PASSWORD, iterations=1000)

from webapp import create_app  # noqa: E402
from webapp.security import parse_ip  # noqa: E402

PASSED: list[str] = []
FAILED: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        PASSED.append(name)
        print(f"  ✓ {name}")
    else:
        FAILED.append(f"{name} {detail}")
        print(f"  ✗ {name}  {detail}")


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    return m.group(1) if m else ""


def run() -> int:
    app = create_app(["samples/access_2026-11-11.sample.log"],
                     dry_run=True, start_watcher=False)
    app.config["TESTING"] = True
    c = app.test_client()

    print("\n[1] 未登录访问")
    r = c.get("/")
    check("根路径重定向到登录页", r.status_code == 302 and "/login" in r.headers["Location"])
    r = c.get("/api/findings")
    check("未登录调 API 返回 401（不是重定向）", r.status_code == 401)

    print("\n[2] 响应头")
    r = c.get("/login")
    csp = r.headers.get("Content-Security-Policy", "")
    check("存在 CSP", bool(csp))
    check("CSP 禁内联脚本", "script-src 'self'" in csp and "'unsafe-inline'" not in csp)
    check("CSP frame-ancestors 为 none", "frame-ancestors 'none'" in csp)
    check("nosniff", r.headers.get("X-Content-Type-Options") == "nosniff")
    check("X-Frame-Options DENY", r.headers.get("X-Frame-Options") == "DENY")
    check("不泄露 Server 版本", "Werkzeug" not in (r.headers.get("Server") or ""))

    print("\n[3] 登录防护")
    html = r.get_data(as_text=True)
    token = csrf_from(html)

    r = c.post("/login", data={"username": "admin", "password": TEST_PASSWORD,
                               "csrf_token": "wrong-token"})
    check("CSRF 错误被拒", r.status_code == 400)

    r = c.post("/login", data={"username": "admin", "password": "wrong",
                               "csrf_token": token})
    check("密码错误返回 401", r.status_code == 401)
    body = r.get_data(as_text=True)
    check("错误提示不区分用户名/密码", "用户名或密码错误" in body)

    r = c.post("/login", data={"username": "admin", "password": TEST_PASSWORD,
                               "csrf_token": token})
    check("正确密码登录成功", r.status_code == 302)

    print("\n[4] 登录后访问")
    r = c.get("/")
    check("控制台可访问", r.status_code == 200)
    page = r.get_data(as_text=True)
    check("页面无内联 style 属性", "style=" not in page)
    check("CSRF token 通过 data 属性传出", 'data-csrf="' in page)

    print("\n[5] 越权与 CSRF")
    r = c.post("/api/ban", json={"ip": "203.0.113.9"})
    check("无 CSRF 头的写操作被拒", r.status_code == 403)

    r = c.post("/api/ban", json={"ip": "203.0.113.9"},
               headers={"X-CSRF-Token": "bogus"})
    check("伪造 CSRF token 被拒", r.status_code == 403)

    print("\n[6] IP 校验（封禁链路的注入闸门）")
    bad_inputs = [
        "1.2.3.4; rm -rf /",
        "1.2.3.4\n}",
        "1.2.3.4 && reboot",
        "../../etc/passwd",
        "1.2.3",
        "999.1.1.1",
        "",
    ]
    for bad in bad_inputs:
        check(f"拒绝 {bad!r}", parse_ip(bad) is None)

    check("接受合法 IPv4", parse_ip("8.8.8.8") == "8.8.8.8")
    check("接受合法 IPv6", parse_ip("2001:db8::1") == "2001:db8::1")
    check("拒绝未指定地址", parse_ip("0.0.0.0") is None)

    # 通过接口再验一遍。这里必须带**正确的** CSRF token，
    # 否则请求会先被 CSRF 拦掉，返回 403 —— 测试看起来是"过了"，
    # 其实根本没走到 IP 校验那一步。这种"因为错误的原因而通过"的用例
    # 比没有测试更危险，它会让人以为防护措施生效了。
    with c.session_transaction() as sess:
        real_token = sess.get("csrf")
    r = c.post("/api/ban", json={"ip": "1.2.3.4; rm -rf /"},
               headers={"X-CSRF-Token": real_token})
    check("接口层面拒绝注入型 IP（且是被 IP 校验拒的）", r.status_code == 400,
          f"实际 {r.status_code}")

    print("\n[7] 封禁动作")
    with c.session_transaction() as sess:
        token = sess.get("csrf")
    r = c.post("/api/ban", json={"ip": "203.0.113.9", "ttl": 999999999, "reason": "测试"},
               headers={"X-CSRF-Token": token})
    d = r.get_json()
    check("合法 IP 封禁成功", r.status_code == 200 and d.get("ok"))
    rec = d.get("record") or {}
    from datetime import datetime
    expires = datetime.strptime(rec["expires"], "%m-%d %H:%M:%S")
    created = datetime.strptime(rec["created"], "%m-%d %H:%M:%S")
    check("TTL 被强制收敛到 7 天内", (expires - created).days <= 7)
    check("演练模式下不改系统文件", d.get("dry_run") is True)

    r = c.post("/api/unban", json={"ip": "203.0.113.9"},
               headers={"X-CSRF-Token": token})
    check("解封成功", r.status_code == 200 and r.get_json().get("ok"))

    print("\n[8] XSS 静态检查（这个项目最关键的防护）")
    js = (ROOT / "static" / "app.js").read_text(encoding="utf-8")
    # 去掉注释再检查，避免注释里写"不用 innerHTML"反而被判为命中
    code = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    code = re.sub(r"^\s*//.*$", "", code, flags=re.M)
    check("app.js 不使用 innerHTML", "innerHTML" not in code)
    check("app.js 不使用 outerHTML", "outerHTML" not in code)
    check("app.js 不使用 document.write", "document.write" not in code)
    check("app.js 不使用 eval", re.search(r"\beval\s*\(", code) is None)

    dash = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    # 注意这里必须写 `not in`。
    # 写成 `"|safe" in dash is False` 会变成链式比较：
    #   等价于 ("|safe" in dash) and (dash is False)
    # 第二个条件永远为假，于是整个表达式恒假 —— 测试永远失败，
    # 但失败原因是写错了，不是代码有问题。链式比较在 Python 里是个常见陷阱。
    check("模板不使用 |safe 过滤器", "|safe" not in dash)
    check("模板不使用 autoescape false", "autoescape" not in dash)
    check("模板不使用内联 style 属性", "style=" not in dash)

    print("\n[9] 密码哈希")
    from webapp.security import verify_password
    h = hash_password("correct horse battery", iterations=1000)
    check("正确密码验证通过", verify_password("correct horse battery", h))
    check("错误密码验证失败", not verify_password("wrong", h))
    check("哈希不含明文", "correct horse" not in h)
    check("两次哈希不同（salt 生效）", h != hash_password("correct horse battery", iterations=1000))
    check("脏数据不抛异常", verify_password("x", "garbage") is False)

    print("\n" + "=" * 56)
    print(f"通过 {len(PASSED)} 项，失败 {len(FAILED)} 项")
    for f in FAILED:
        print(f"  ✗ {f}")
    return 0 if not FAILED else 1


if __name__ == "__main__":
    raise SystemExit(run())
