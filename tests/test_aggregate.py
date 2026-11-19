"""告警聚合的单元测试。

测的是"合并规则"本身，不依赖真实日志——
真实日志会变，规则不该跟着变。

运行：python tests/test_aggregate.py
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sec_log_analyzer.aggregate import aggregate_findings   # noqa: E402
from sec_log_analyzer.models import Finding, LogEntry, Severity  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ✓ {name}")
    else:
        FAIL += 1
        print(f"  ✗ {name}  {detail}")


def mk(ip: str, category: str, path: str, minute: int,
       severity: Severity = Severity.MEDIUM, rules: list[str] | None = None,
       reason: str = "测试用告警") -> Finding:
    entry = LogEntry(
        source="access",
        ip=ip,
        ts=datetime(2026, 11, 13, 9, 0, 0) + timedelta(minutes=minute),
        method="GET",
        path=path,
        status=404,
        user_agent="-",
        raw="",
    )
    return Finding(
        category=category,
        severity=severity,
        ip=ip,
        entry=entry,
        rule_names=rules or ["sens_env"],
        score=10,
        reason=reason,
    )


def main() -> int:
    print("[1] 同 IP 同类型合并")
    fs = [mk("1.1.1.1", "敏感文件探测", "/.env", 0),
          mk("1.1.1.1", "敏感文件探测", "/.env.bak", 1),
          mk("1.1.1.1", "敏感文件探测", "/.env.local", 2)]
    out = aggregate_findings(fs)
    check("3 条合成 1 条", len(out) == 1, f"实际 {len(out)}")
    f = out[0]
    check("count = 3", f.count == 3, str(f.count))
    check("reason 含次数", "共 3 次" in f.reason, f.reason)
    check("reason 含路径样本", "/.env" in f.reason and "/.env.local" in f.reason, f.reason)
    check("代表条目取最新的", f.entry.path == "/.env.local", f.entry.path)
    check("span 记录起止",
          "09:00:00" in f.span and "09:02:00" in f.span, f.span)

    print("\n[2] 不该合并的情况")
    out2 = aggregate_findings([mk("1.1.1.1", "敏感文件探测", "/.env", 0),
                               mk("2.2.2.2", "敏感文件探测", "/.env", 1)])
    check("不同 IP 不合并", len(out2) == 2, f"实际 {len(out2)}")

    out3 = aggregate_findings([mk("1.1.1.1", "敏感文件探测", "/.env", 0),
                               mk("1.1.1.1", "命令注入", "/x;id", 1)])
    check("同 IP 不同类型不合并", len(out3) == 2, f"实际 {len(out3)}")

    print("\n[3] 单条告警不加废话")
    out4 = aggregate_findings([mk("3.3.3.3", "命令注入", "/x;id", 0)])
    check("单条保持 1 条", len(out4) == 1)
    check("单条 count = 1", out4[0].count == 1)
    check("单条 reason 不含『共 1 次』", "共 1 次" not in out4[0].reason, out4[0].reason)

    print("\n[4] 等级取最高的")
    out5 = aggregate_findings([
        mk("4.4.4.4", "敏感文件探测", "/.env", 0, Severity.LOW),
        mk("4.4.4.4", "敏感文件探测", "/.env.bak", 1, Severity.CRITICAL),
        mk("4.4.4.4", "敏感文件探测", "/.env.old", 2, Severity.MEDIUM),
    ])
    check("合并后等级为 critical",
          out5[0].severity == Severity.CRITICAL, str(out5[0].severity))
    check("score 取最大值", out5[0].score == 10)

    print("\n[5] 规则名取并集")
    out6 = aggregate_findings([
        mk("5.5.5.5", "敏感文件探测", "/.env", 0, rules=["sens_env"]),
        mk("5.5.5.5", "敏感文件探测", "/.git/config", 1, rules=["sens_vcs"]),
    ])
    check("规则合并", set(out6[0].rule_names) == {"sens_env", "sens_vcs"},
          str(out6[0].rule_names))

    print("\n[6] 排序与边界")
    fs7 = [mk("6.6.6.6", "敏感文件探测", f"/.env{i}", i) for i in range(5)]
    fs7 += [mk("7.7.7.7", "命令注入", "/x;id", 9, Severity.CRITICAL)]
    out7 = aggregate_findings(fs7)
    check("严重级排在最前", out7[0].severity == Severity.CRITICAL, str(out7[0].severity))
    check("空输入不崩", aggregate_findings([]) == [])

    print(f"\n{'=' * 40}\n通过 {PASS} 项，失败 {FAIL} 项")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
