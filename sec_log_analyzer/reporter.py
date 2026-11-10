"""报告层：把结构化结果渲染成可交付物。

为什么同时出 Markdown / HTML / CSV：
  * Markdown -> 贴进周报、工单、GitHub issue，人是直接读的；
  * HTML     -> 单文件自包含，双击就能看，可以直接交给领导/客户；
  * CSV      -> 喂给 Excel 做二次统计，或者灌进 SIEM 做关联。

原项目的 "报告" 是 f-string 拼的一堆行，只能看不能算。这里的区别是：
先有结构化数据，再有多种呈现。呈现是视图，数据才是事实。
"""

from __future__ import annotations

import csv
import html
import io
from collections import Counter
from datetime import datetime

from .models import SEVERITY_LABEL, AnalysisResult, Severity

_TIME_FMT = "%Y-%m-%d %H:%M:%S"


def _fmt_ts(ts) -> str:
    return ts.strftime(_TIME_FMT) if ts else "时间未知"


def summary_rows(result: AnalysisResult) -> list[tuple[str, str]]:
    by_cat = result.count_by(lambda f: f.category)
    by_sev = Counter(SEVERITY_LABEL[f.severity] for f in result.findings)
    top_ip = Counter(f.ip for f in result.findings).most_common(1)
    return [
        ("日志文件", result.filename),
        ("解析成功行数", str(len(result.entries))),
        ("解析失败行数", f"{len(result.parse_errors)}（{result.parse_error_rate:.2%}）"),
        ("告警总数", str(len(result.findings))),
        ("涉及攻击类型", "、".join(by_cat.keys()) if by_cat else "无"),
        ("严重 / 高危", f"{by_sev.get('严重', 0)} / {by_sev.get('高', 0)}"),
        ("告警最多来源 IP", f"{top_ip[0][0]}（{top_ip[0][1]} 次）" if top_ip else "无"),
        ("分析耗时", f"{result.elapsed_ms} ms"),
    ]


def to_markdown(result: AnalysisResult, max_detail: int = 50) -> str:
    lines: list[str] = []
    lines.append(f"# Web 日志安全分析报告\n")
    lines.append(f"> 源文件：`{result.filename}`　生成时间：{_fmt_ts(datetime.now())}\n")

    lines.append("## 一、概览\n")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | --- |")
    for k, v in summary_rows(result):
        lines.append(f"| {k} | {v} |")

    by_cat = result.count_by(lambda f: f.category)
    lines.append("\n## 二、攻击类型分布\n")
    if by_cat:
        lines.append("| 攻击类型 | 告警数 |")
        lines.append("| --- | --- |")
        for cat, n in by_cat.items():
            lines.append(f"| {cat} | {n} |")
    else:
        lines.append("未检测到攻击特征。")

    lines.append("\n## 三、来源 IP 排名\n")
    ip_counter = Counter(f.ip for f in result.findings)
    if ip_counter:
        lines.append("| 排名 | 源 IP | 告警数 |")
        lines.append("| --- | --- | --- |")
        for i, (ip, n) in enumerate(ip_counter.most_common(10), start=1):
            lines.append(f"| {i} | {ip} | {n} |")
    else:
        lines.append("无。")

    lines.append(f"\n## 四、告警明细（前 {max_detail} 条）\n")
    for i, f in enumerate(result.findings[:max_detail], start=1):
        lines.append(f"### {i}. {f.category} · {SEVERITY_LABEL[f.severity]} · {f.ip}")
        lines.append(f"- 时间：{_fmt_ts(f.ts)}")
        lines.append(f"- 命中规则：`{', '.join(f.rule_names)}`（评分 {f.score}）")
        lines.append(f"- 判定依据：{f.reason}")
        lines.append(f"- 原始日志：`{f.entry.raw[:300]}`")
        if f.ai_comment:
            lines.append("- AI 研判：")
            for inline in f.ai_comment.splitlines():
                lines.append(f"  - {inline}")
        lines.append("")
    if len(result.findings) > max_detail:
        lines.append(f"\n_另有 {len(result.findings) - max_detail} 条告警未展开，完整数据见 CSV。_\n")

    if result.parse_errors:
        lines.append("\n## 五、解析异常\n")
        lines.append(f"共 {len(result.parse_errors)} 行无法解析，前 10 条：\n")
        for e in result.parse_errors[:10]:
            lines.append(f"- {e}")

    if result.notes:
        lines.append("\n## 六、备注\n")
        for n in result.notes:
            lines.append(f"- {n}")
    return "\n".join(lines)


def to_csv(result: AnalysisResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["时间", "源IP", "攻击类型", "等级", "评分", "命中规则", "判定依据", "原始日志", "AI研判"])
    for f in result.findings:
        writer.writerow(
            [
                _fmt_ts(f.ts),
                f.ip,
                f.category,
                SEVERITY_LABEL[f.severity],
                f.score,
                "|".join(f.rule_names),
                f.reason,
                f.entry.raw,
                f.ai_comment.replace("\n", " "),
            ]
        )
    return buf.getvalue()


_SEV_COLOR = {
    "严重": "#A32D2D",
    "高": "#D85A30",
    "中": "#BA7517",
    "低": "#5F5E5A",
}


def to_html(result: AnalysisResult, max_detail: int = 200) -> str:
    """自包含单文件 HTML。不引外部 CSS，方便直接发给别人。"""
    esc = html.escape
    rows = "\n".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>" for k, v in summary_rows(result)
    )

    cat_counter = result.count_by(lambda f: f.category)
    cat_rows = "\n".join(
        f"<tr><td>{esc(c)}</td><td>{n}</td></tr>" for c, n in cat_counter.items()
    ) or '<tr><td colspan="2">未检测到攻击特征</td></tr>'

    detail: list[str] = []
    for f in result.findings[:max_detail]:
        color = _SEV_COLOR.get(SEVERITY_LABEL[f.severity], "#5F5E5A")
        ai = (
            f'<div class="ai">{esc(f.ai_comment)}</div>' if f.ai_comment else ""
        )
        detail.append(
            f"""<div class="item">
  <div class="head">
    <span class="cat">{esc(f.category)}</span>
    <span class="sev" style="background:{color}">{SEVERITY_LABEL[f.severity]}</span>
    <span class="ip">{esc(f.ip)}</span>
    <span class="time">{_fmt_ts(f.ts)}</span>
  </div>
  <div class="reason">{esc(f.reason)}</div>
  <pre class="raw">{esc(f.entry.raw)}</pre>
  {ai}
</div>"""
        )

    notes = "".join(f"<li>{esc(n)}</li>" for n in result.notes)
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>Web 日志安全分析报告 - {esc(result.filename)}</title>
<style>
body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;max-width:960px;margin:40px auto;padding:0 20px;color:#2C2C2A;line-height:1.7;background:#fff}}
h1{{font-size:22px;font-weight:500;border-bottom:2px solid #E24B4A;padding-bottom:10px}}
h2{{font-size:16px;font-weight:500;margin-top:32px}}
table{{border-collapse:collapse;width:100%;font-size:13px}}
td,th{{border:1px solid #D3D1C7;padding:8px 12px;text-align:left}}
th{{background:#F1EFE8;font-weight:500}}
.item{{border:1px solid #D3D1C7;border-radius:8px;padding:14px;margin:12px 0}}
.head{{display:flex;gap:10px;align-items:center;font-size:13px;flex-wrap:wrap}}
.cat{{font-weight:500}}
.sev{{color:#fff;border-radius:4px;padding:1px 8px;font-size:12px}}
.ip{{font-family:ui-monospace,Consolas,monospace}}
.time{{color:#888780;font-size:12px;margin-left:auto}}
.reason{{font-size:13px;color:#5F5E5A;margin:8px 0}}
pre.raw{{background:#F1EFE8;padding:10px;border-radius:6px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all}}
.ai{{background:#E6F1FB;border-left:3px solid #378ADD;padding:10px;font-size:13px;white-space:pre-wrap;border-radius:0 6px 6px 0}}
ul{{font-size:13px;color:#5F5E5A}}
/* 打印/导出 PDF：去掉外边距，条目不要从中间断开 */
@media print{{
  @page{{margin:16mm 14mm}}
  body{{max-width:none;margin:0;padding:0}}
  .item,.ai,pre.raw{{break-inside:avoid;page-break-inside:avoid}}
  h2{{break-after:avoid;page-break-after:avoid}}
  tr{{break-inside:avoid}}
}}
</style></head><body>
<h1>Web 日志安全分析报告</h1>
<p style="color:#888780;font-size:13px">源文件：{esc(result.filename)}</p>
<h2>一、概览</h2>
<table><tbody>{rows}</tbody></table>
<h2>二、攻击类型分布</h2>
<table><thead><tr><th>攻击类型</th><th>告警数</th></tr></thead><tbody>{cat_rows}</tbody></table>
<h2>三、告警明细</h2>
{"".join(detail) or "<p>未检测到攻击特征。</p>"}
{ f"<h2>四、备注</h2><ul>{notes}</ul>" if notes else "" }
</body></html>"""
