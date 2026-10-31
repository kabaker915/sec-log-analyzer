"""命令行入口：不启动界面也能出报告。

面试时"能不能在没有 GUI 的环境跑"是常被问的点（服务器上通常没有浏览器）。
用法：
    python -m sec_log_analyzer.cli access.log --out report
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import Config
from .pipeline import analyze_file
from .reporter import to_csv, to_html, to_markdown


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Web 日志安全分析")
    ap.add_argument("files", nargs="+", help="日志文件路径，可传多个")
    ap.add_argument("--out", default="report", help="输出文件名前缀（不含扩展名）")
    ap.add_argument("--no-ai", action="store_true", help="只做规则检测，不调大模型")
    ap.add_argument("--window", type=int, default=None, help="404 扫描检测窗口（秒）")
    ap.add_argument("--threshold", type=int, default=None, help="404 触发阈值（次）")
    args = ap.parse_args(argv)

    config = Config.from_env()
    if args.window:
        config.scan_window_seconds = args.window
    if args.threshold:
        config.scan_404_threshold = args.threshold
    if args.no_ai:
        config.ai_enabled = False

    exit_code = 0
    for path in args.files:
        p = Path(path)
        if not p.exists():
            print(f"[跳过] 文件不存在：{p}", file=sys.stderr)
            exit_code = 2
            continue

        result = analyze_file(p, config)
        stem = Path(f"{args.out}_{p.stem}")
        # 输出目录可能不存在（比如 --out reports/demo），先建出来再写
        stem.parent.mkdir(parents=True, exist_ok=True)
        Path(f"{stem}.md").write_text(to_markdown(result), encoding="utf-8")
        Path(f"{stem}.html").write_text(to_html(result), encoding="utf-8")
        Path(f"{stem}.csv").write_text(to_csv(result), encoding="utf-8-sig")

        print(f"\n=== {p.name} ===")
        print(f"解析 {len(result.entries)} 行，告警 {len(result.findings)} 条，"
              f"耗时 {result.elapsed_ms}ms")
        for cat, n in result.count_by(lambda f: f.category).items():
            print(f"  - {cat}: {n}")
        print(f"报告已写入 {stem}.md / .html / .csv")

        if any(f.severity.value == "critical" for f in result.findings):
            exit_code = max(exit_code, 1)  # 有严重告警时返回非 0，方便接 CI/监控

    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
