"""规则调试工具：输入一条 URL，看它命中哪些规则、得多少分、会不会告警。

这是我写规则时真正会用的东西——改完一条正则，先拿它验一遍，不用跑整个分析。

用法：
    .venv\\Scripts\\python.exe tools\\score.py "/p?id=1' OR '1'='1"
    .venv\\Scripts\\python.exe tools\\score.py --threshold 11 "/p?id=1 union select 1"
    .venv\\Scripts\\python.exe tools\\score.py "/.env" "/../../etc/passwd"

退出码：告警返回 0，不告警返回 1（方便写进 shell 判断）。
"""

import argparse
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sec_log_analyzer.config import Config
from sec_log_analyzer.rules import RULES, normalize


def score_one(payload: str, threshold: int) -> bool:
    target = normalize(payload)
    hits = [r for r in RULES if r.pattern.search(target)]

    print(f"\n载荷    {payload}")
    if target != payload:
        print(f"归一化  {target}")

    if not hits:
        print("命中    无 → 不告警")
        return False

    print("命中")
    scores = defaultdict(int)
    for r in hits:
        scores[r.category] += r.weight
        print(f"  {r.name:<16} {r.category:<6} +{r.weight:<3} {r.note}")

    alerted = False
    for category, total in scores.items():
        verdict = "告警" if total >= threshold else "不告警"
        alerted = alerted or total >= threshold
        print(f"\n{category} 合计 {total} 分 / 阈值 {threshold} → {verdict}")
    return alerted


def main() -> int:
    ap = argparse.ArgumentParser(description="检查一条 URL 会不会被判定为攻击")
    ap.add_argument("payloads", nargs="+", help="要检查的 URL 或查询串，可传多个")
    ap.add_argument("--threshold", type=int, default=None,
                    help="覆盖默认阈值（默认取 Config.alert_score_threshold）")
    args = ap.parse_args()

    threshold = args.threshold if args.threshold is not None else Config().alert_score_threshold

    any_alert = False
    for payload in args.payloads:
        any_alert = score_one(payload, threshold) or any_alert

    return 0 if any_alert else 1


if __name__ == "__main__":
    raise SystemExit(main())
