"""把两份分析报告合成一份可直接发给 HR / 面试官的交付版 HTML。

用法：
    python reports/build_deliverable.py
输出：
    reports/日志分析工具_演示报告.html

单独成一份而不是发两个原始 HTML，原因有两点：
1. 交付物要有封面和导读，否则对方打开看到满屏日志不知道在说什么；
2. 一个文件传起来不容易漏。
"""

from __future__ import annotations

import html
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

ACCESS_HTML = HERE / "demo_access.html"
AUTH_HTML = HERE / "demo_auth.html"
OUT = HERE / "日志分析工具_演示报告.html"

AUTHOR = "苏昊岩"
TITLE = "日志安全分析工具 · 演示报告"
SUBTITLE = "2027 届 · 网络工程技术（本科）· 求职作品"


def extract_body(path: Path) -> str:
    """从单份报告里抽出 <body> 内部内容，并去掉它自己的一级标题。"""
    text = path.read_text(encoding="utf-8")
    m = re.search(r"<body>(.*)</body>", text, re.S)
    if not m:
        raise SystemExit(f"无法解析 {path}")
    body = m.group(1)
    # 干掉原报告自带的 h1 和源文件说明，合并版统一由外层提供
    body = re.sub(r"<h1>.*?</h1>", "", body, flags=re.S)
    body = re.sub(r'<p style="color:#888780[^>]*>.*?</p>', "", body, flags=re.S)
    return body.strip()


def main() -> None:
    access_body = extract_body(ACCESS_HTML)
    auth_body = extract_body(AUTH_HTML)

    out = f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{TITLE}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:900px;margin:0 auto;padding:0 24px 60px;color:#2C2C2A;line-height:1.75;background:#fff}}
.cover{{padding:64px 0 40px;border-bottom:2px solid #2C2C2A;margin-bottom:8px}}
.cover .kicker{{font-size:12px;letter-spacing:.18em;color:#888780;text-transform:uppercase}}
.cover h1{{font-size:32px;font-weight:500;margin:14px 0 6px;line-height:1.3}}
.cover .sub{{font-size:14px;color:#5F5E5A}}
.cover .meta{{margin-top:28px;font-size:13px;color:#5F5E5A;display:grid;grid-template-columns:88px 1fr;row-gap:6px}}
.cover .meta b{{font-weight:500;color:#888780}}
section.part{{margin-top:48px;padding-top:8px}}
section.part > h2{{font-size:20px;font-weight:500;border-bottom:1px solid #D3D1C7;padding-bottom:12px}}
.lead{{background:#F7F6F2;border-left:3px solid #2C2C2A;padding:14px 18px;font-size:13.5px;color:#3A3A38;border-radius:0 6px 6px 0;margin:18px 0}}
.lead ul{{margin:8px 0 0;padding-left:20px}}
.lead li{{margin:4px 0}}
h3{{font-size:15px;font-weight:500;margin-top:26px;color:#2C2C2A}}
table{{border-collapse:collapse;width:100%;font-size:13px;margin:10px 0}}
td,th{{border:1px solid #D3D1C7;padding:8px 12px;text-align:left}}
th{{background:#F1EFE8;font-weight:500}}
.item{{border:1px solid #D3D1C7;border-radius:8px;padding:14px;margin:12px 0}}
.head{{display:flex;gap:10px;align-items:center;font-size:13px;flex-wrap:wrap}}
.cat{{font-weight:500}}
.sev{{color:#fff;border-radius:4px;padding:1px 8px;font-size:12px}}
.ip{{font-family:ui-monospace,Consolas,monospace}}
.time{{color:#888780;font-size:12px;margin-left:auto}}
.reason{{font-size:13px;color:#5F5E5A;margin:8px 0}}
pre.raw{{background:#F1EFE8;padding:10px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;margin:0}}
.ai{{background:#E6F1FB;border-left:3px solid #378ADD;padding:10px;font-size:13px;white-space:pre-wrap;border-radius:0 6px 6px 0}}
.footer{{margin-top:56px;padding-top:18px;border-top:1px solid #D3D1C7;font-size:12px;color:#888780}}
.pagebreak{{break-before:page;page-break-before:always;height:0}}
@media print{{
  @page{{margin:16mm 14mm}}
  body{{max-width:none;padding:0}}
  .cover{{padding-top:0}}
  .item,.ai,pre.raw,.lead,table{{break-inside:avoid;page-break-inside:avoid}}
  h2,h3{{break-after:avoid;page-break-after:avoid}}
}}
</style></head><body>

<div class="cover">
  <div class="kicker">Security Log Analyzer</div>
  <h1>{TITLE}</h1>
  <div class="sub">{SUBTITLE}</div>
  <div class="meta">
    <b>作者</b><span>{AUTHOR}</span>
    <b>工具</b><span>Python 自研，命令行调用，无第三方安全组件</span>
    <b>输入</b><span>nginx combined 访问日志 + Linux auth.log</span>
    <b>输出</b><span>控制台、Markdown、自包含 HTML、CSV 四种形式</span>
  </div>
</div>

<section class="part">
  <h2>这份报告是什么</h2>
  <div class="lead">
    我写了一个日志分析工具，输入 nginx 访问日志和 Linux 认证日志，输出带评分和判定依据的告警报告。下面是它在两份样例日志上的真实运行结果，未经人工修改。
    <ul>
      <li><b>检测手段</b>：内容特征（正则匹配攻击载荷）+ 行为特征（时间窗口内的次数与离散度）两层，单条命中不够阈值不报警，降低误报。</li>
      <li><b>每条告警都带判定依据</b>：写清楚命中了哪条规则、为什么这样判断、归一化后的载荷长什么样，方便人工复核。</li>
      <li><b>解析失败的行不会被静默丢弃</b>：单独列出并统计失败率，避免"看起来分析完了其实漏了一半"。</li>
    </ul>
  </div>
</section>

<section class="part">
  <h2>样例一　Web 访问日志</h2>
  <p style="font-size:13px;color:#5F5E5A">12 行 combined 格式日志，其中混入 SQL 注入、XSS、敏感文件探测与目录扫描流量，来源为 sqlmap 和 gobuster 两个自动化工具。</p>
  {access_body}
</section>

<div class="pagebreak"></div>

<section class="part">
  <h2>样例二　Linux 认证日志</h2>
  <p style="font-size:13px;color:#5F5E5A">9 行 sshd 日志，包含两个来源 IP 的慢速 SSH 爆破。检测逻辑看的是"同一时间窗口内的失败次数与尝试用户名数量"，而不是简单的失败次数累加。</p>
  {auth_body}
</section>

<div class="footer">
  {AUTHOR} · 本报告由自研工具自动生成，如需源码或扩展说明可随时提供。
</div>

</body></html>"""

    OUT.write_text(out, encoding="utf-8")
    print(f"已生成：{OUT}")
    print(f"大小：{OUT.stat().st_size / 1024:.1f} KB")


if __name__ == "__main__":
    main()
