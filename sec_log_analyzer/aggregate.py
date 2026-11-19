"""告警聚合：把「同一来源 + 同一类型」的多条告警合并成一条。

为什么必须做
------------
实测 8.4 天的日志：924 条告警里，敏感文件探测占 658 条（71%）。
而其中约 150 条来自同一个 IP —— 一个扫描器把整本 .env 字典跑了一遍，
每一行 404 都变成一条告警。

这不是"检测太灵敏"，是**报告不可读**：
分析师打开报告看到 658 条几乎一样的记录，第一反应是关掉它。
告警疲劳不是"告警太多"的问题，是"同样的信息重复出现太多次"的问题。

聚合后：658 条 → 约 50 条，而且信息量反而变大——
原来的 150 条告诉你"有人在扫"，聚合后的 1 条告诉你
"这个 IP 试了 37 个不同的 .env 变体，从 09:12 持续到 09:14"。

放在哪一层
----------
引擎层，pipeline 调用。不放在 Detector 里，因为：
  * Detector 的输出是"逐条命中"，这个语义是干净的，不该被聚合污染
  * 实时链路（watcher）有自己的节流机制，聚合会打乱它的推送节奏
  * 离线报告需要聚合，这两个场景的诉求不一样

什么时候不该聚合
----------------
跨时间跨度很大的场景。如果同一个 IP 周一扫了一次、周五又扫了一次，
合并成一条会丢失"来了两次"这个信息。所以保留首次/最近时间，
跨度写在 reason 里。
"""

from __future__ import annotations

from datetime import datetime

from .models import Finding, Severity

_SEV_RANK = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

MAX_SAMPLE_PATHS = 4       # reason 里最多列几个路径样本
MAX_REASON_CHARS = 110     # 基础描述截断，给"共 N 次"留位置


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    """按 (类型, 来源 IP) 合并。

    只合并两条及以上的组：单条的告警原样返回，
    避免给本来就唯一的告警加上"共 1 次"这种废话。
    """
    groups: dict[tuple[str, str], list[Finding]] = {}
    for f in findings:
        groups.setdefault((f.category, f.ip), []).append(f)

    merged: list[Finding] = []
    for (_cat, _ip), items in groups.items():
        if len(items) == 1:
            merged.append(items[0])
            continue
        merged.append(_merge(items))

    # 重新排序：等级高的在前，同等级按次数多的在前
    merged.sort(
        key=lambda f: (_SEV_RANK.get(f.severity, 0), f.count, f.ts or datetime.min),
        reverse=True,
    )
    return merged


def _merge(items: list[Finding]) -> Finding:
    items.sort(key=lambda f: f.ts or datetime.min)
    first, last = items[0], items[-1]

    # 代表条目取最后一条：报告里显示的时间和载荷应该是"最新一次"的
    rep = last

    rules = sorted({r for f in items for r in f.rule_names})

    paths: list[str] = []
    for f in items:
        p = f.entry.path or ""
        if p and p not in paths:
            paths.append(p)

    t0 = first.ts.strftime("%m-%d %H:%M:%S") if first.ts else "-"
    t1 = last.ts.strftime("%m-%d %H:%M:%S") if last.ts else "-"

    base = (first.reason or "").split("\n")[0]
    if len(base) > MAX_REASON_CHARS:
        base = base[:MAX_REASON_CHARS] + "…"

    sample = "、".join(paths[:MAX_SAMPLE_PATHS])
    more = f" 等 {len(paths)} 个" if len(paths) > MAX_SAMPLE_PATHS else ""
    reason = (
        f"{base}（同类共 {len(items)} 次，涉及 {len(paths)} 个路径："
        f"{sample}{more}；{t0} ~ {t1}）"
    )

    return Finding(
        category=rep.category,
        severity=max((f.severity for f in items), key=lambda s: _SEV_RANK.get(s, 0)),
        ip=rep.ip,
        entry=rep.entry,
        rule_names=rules,
        score=max(f.score for f in items),
        reason=reason,
        count=len(items),
        span=f"{t0} ~ {t1}",
    )


__all__ = ["aggregate_findings"]
