"""Agent 的命令行入口。

    python -m agents.app chat  --index 0          # 交互式追问
    python -m agents.app batch --limit 10         # 批量研判
    python -m agents.app chat --index 0 --llm     # 用真实模型

不加 --llm 时走规则替身，不联网、不花钱，结论可复现。
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from sec_log_analyzer.config import Config
from sec_log_analyzer.pipeline import analyze_file
from webapp.state import finding_row

from .chat import TriageAssistant


def _load(path: str):
    p = Path(path)
    if not p.exists():
        print(f"找不到日志：{p}", file=sys.stderr)
        print("先跑 CLI 生成样本，或用 --log 指定", file=sys.stderr)
        raise SystemExit(1)
    print(f"加载 {p} ...")
    r = analyze_file(str(p), Config(ai_enabled=False))
    findings = [finding_row(f) for f in r.findings]
    print(f"共 {len(findings)} 条告警，{len(r.entries)} 条日志\n")
    return findings, r.entries


VERDICT_TEXT = {
    "true_positive": "真阳性",
    "false_positive": "假阳性",
    "needs_investigation": "需调查",
}


def cmd_chat(args) -> int:
    findings, entries = _load(args.log)
    if not findings:
        print("没有告警可研判")
        return 0

    alert = findings[args.index]
    a = TriageAssistant(alert, findings, entries,
                        use_llm=args.llm, verbose=True)

    print("=" * 66)
    print(f"告警：{alert['category']} / {alert['severity']} / {alert['ip']}")
    print("=" * 66)
    r = a.triage()
    v = r.verdict or {}
    print(f"\n研判：{VERDICT_TEXT.get(v.get('verdict'), v.get('verdict'))}"
          f"（置信度 {v.get('confidence')}）")
    print(f"依据：{v.get('reason')}")
    print(f"处置：{v.get('action')}")

    if not args.llm:
        print("\n[提示] 当前使用规则替身，不是真实模型。加 --llm 走 DeepSeek。")

    print("\n可以追问：为什么 / 处置步骤 / 误判风险 / 加白名单会怎样。q 退出\n")
    while True:
        try:
            q = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not q or q.lower() in ("q", "quit", "exit"):
            break
        out = a.ask(q)
        if out["tool_calls"]:
            print(f"  [查询] {'; '.join(out['tool_calls'])}")
        print(f"  {out['answer']}\n")
    return 0


def _is_ban(action: str) -> bool:
    """判断处置建议是不是「封禁」。

    不能用 `"封禁" in action`：模型会说「暂不封禁」「不建议封禁」，
    这些句子里都含「封禁」二字，会被误判成要封。
    **否定词和肯定词在字符串里长得一样，这是文本分类的经典坑。**

    先排除否定表述，再判肯定。顺序不能反。
    """
    if not action:
        return False
    negations = ("暂不封禁", "不封禁", "不建议封禁", "无需封禁", "避免封禁")
    if any(n in action for n in negations):
        return False
    return "封禁" in action


def cmd_batch(args) -> int:
    findings, entries = _load(args.log)
    if not findings:
        print("没有告警可研判")
        return 0

    # 按 IP 聚合，一个 IP 只研判一次。
    #
    # 为什么不逐条告警研判：一次扫描会产生几十条告警（实测一个 IP 贡献了 52 条），
    # 逐条跑等于拿同一个 IP 问模型几十遍，结论几乎一样，纯浪费。
    # 分析师关心的也是「这个 IP 有没有威胁」，不是「第 37 条告警对不对」。
    order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(f["ip"], []).append(f)

    # 每个 IP 取最严重的那条作为代表
    targets = []
    for ip, items in groups.items():
        rep = max(items, key=lambda x: order.get(x.get("severity", "low"), 0))
        targets.append((ip, rep, len(items)))

    targets.sort(key=lambda t: (-t[2], -order.get(t[1].get("severity", "low"), 0)))
    targets = targets[:args.limit]

    print(f"{len(findings)} 条告警来自 {len(groups)} 个 IP，"
          f"按 IP 聚合后研判前 {len(targets)} 个（不加 --llm 时走规则替身）\n")

    rows = []
    for i, (ip, alert, n_alerts) in enumerate(targets):
        a = TriageAssistant(alert, findings, entries, use_llm=args.llm)
        r = a.triage()
        v = r.verdict or {}
        rows.append({
            "ip": ip,
            "alerts": n_alerts,
            "category": alert["category"],
            "verdict": v.get("verdict"),
            "confidence": v.get("confidence"),
            "reason": v.get("reason", "")[:80],
            "action": v.get("action", "")[:60],
            "steps": len(r.steps),
        })
        print(f"  [{i + 1}/{len(targets)}] {ip:<16} {n_alerts:>2} 条告警  "
              f"-> {VERDICT_TEXT.get(v.get('verdict'), '?'):<4} {v.get('confidence')}")

    print("\n" + "=" * 66)
    print("汇总")
    print("=" * 66)
    for verdict, n in Counter(x["verdict"] for x in rows).most_common():
        print(f"  {VERDICT_TEXT.get(verdict, verdict):<6} {n} 个 IP")

    banned = [x for x in rows if _is_ban(x.get("action") or "")]
    watched = [x for x in rows if x not in banned]
    print(f"\n  建议封禁 {len(banned)} 个，仅记录观察 {len(watched)} 个")

    if banned:
        print("\n  封禁名单：")
        for x in banned:
            print(f"    {x['ip']:<16} {x['category']}（{x['alerts']} 条告警）")

    out = Path("reports") / "triage_batch.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n明细已写入 {out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="告警研判 Agent")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log", default="archive/access-2026-11-13.log")
    common.add_argument("--llm", action="store_true", help="使用真实模型")

    p_chat = sub.add_parser("chat", parents=[common], help="交互式研判与追问")
    p_chat.add_argument("--index", type=int, default=0, help="选第几条告警")
    p_chat.set_defaults(func=cmd_chat)

    p_batch = sub.add_parser("batch", parents=[common], help="批量研判")
    p_batch.add_argument("--limit", type=int, default=10)
    p_batch.set_defaults(func=cmd_batch)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
