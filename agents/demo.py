"""演示：拿真实日志跑一次告警研判。

运行：
    python -m agents.demo                       # mock 模型，不联网
    python -m agents.demo --llm                 # 真调 DeepSeek（需 DEEPSEEK_API_KEY）
    python -m agents.demo --log archive/access-2026-11-13.log --llm
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sec_log_analyzer.config import Config
from sec_log_analyzer.pipeline import analyze_file
from webapp.state import finding_row

from . import run_triage


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="告警研判 Agent 演示")
    ap.add_argument("--log", default="archive/access-2026-11-13.log",
                    help="access.log 路径")
    ap.add_argument("--llm", action="store_true", help="使用真实模型")
    ap.add_argument("--index", type=int, default=-1,
                    help="选第几条告警，默认最后一条")
    args = ap.parse_args(argv)

    path = Path(args.log)
    if not path.exists():
        print(f"找不到日志：{path}", file=sys.stderr)
        print("先跑一次 CLI 生成，或指定 --log", file=sys.stderr)
        return 1

    print(f"加载 {path} ...")
    result = analyze_file(str(path), Config(ai_enabled=False))
    findings = [finding_row(f) for f in result.findings]
    print(f"共 {len(findings)} 条告警，{len(result.entries)} 条日志\n")

    if not findings:
        print("没有告警可研判")
        return 0

    alert = findings[args.index]
    print("=" * 64)
    print(f"待研判告警：{alert['category']} / {alert['severity']} / {alert['ip']}")
    print(f"依据：{alert['reason'][:100]}")
    print("=" * 64)

    run = run_triage(alert, findings, result.entries,
                     use_llm=args.llm, verbose=True)

    print("\n" + "=" * 64)
    print(f"研判结果（{run.total_ms} ms，{len(run.steps)} 步）")
    print("=" * 64)
    v = run.verdict or {}
    print(f"  结论    : {v.get('verdict')}")
    print(f"  置信度  : {v.get('confidence')}")
    print(f"  依据    : {v.get('reason')}")
    print(f"  建议处置: {v.get('action')}")
    if run.stopped_reason:
        print(f"  终止原因: {run.stopped_reason}")

    out = Path("reports") / "triage_demo.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(run.to_dict(), ensure_ascii=False, indent=2),
                   encoding="utf-8")
    print(f"\n完整 trace 已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
