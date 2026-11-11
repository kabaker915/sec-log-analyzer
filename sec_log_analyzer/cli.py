"""命令行入口：不启动界面也能出报告。

面试时"能不能在没有 GUI 的环境跑"是常被问的点（服务器上通常没有浏览器）。
用法：
    python -m sec_log_analyzer.cli access.log --out report
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from .config import Config
from .ocsf import to_jsonl
from .pipeline import analyze_file
from .reporter import to_csv, to_html, to_markdown


def _severity_tag(f) -> str:
    """终端里不靠颜色分级。

    颜色在日志文件、管道、CI 输出里全部丢失，而文本标记永远在。
    这也是把告警接到告警平台时唯一可靠的传输形式。
    """
    return {
        "critical": "[严重]",
        "high": "[高危]",
        "medium": "[中危]",
        "low": "[低危]",
    }.get(f.severity.value, "[?]")


def _run_tail(files: list[str], config: Config, *, from_start: bool) -> int:
    """实时模式主循环。

    刻意不写日志文件、不落库：这一层只负责"让新事件出现在屏幕上"。
    持久化交给存储层，避免一个进程同时管三件事导致状态混乱。
    """
    from .watcher import LogWatcher

    paths = []
    for f in files:
        p = Path(f)
        if not p.exists():
            print(f"[跳过] 文件不存在：{p}", file=sys.stderr)
            continue
        paths.append(p)
    if not paths:
        print("没有可跟随的文件。", file=sys.stderr)
        return 2

    watcher = LogWatcher(paths, config, from_start=from_start)
    started = datetime.now().strftime("%H:%M:%S")
    print(f"[{started}] 开始监控 {len(paths)} 个文件，Ctrl-C 退出")

    shown = 0

    def on_finding(f) -> None:
        nonlocal shown
        shown += 1
        ts = f.ts.strftime("%H:%M:%S") if f.ts else "--:--:--"
        # 判定依据截断：终端宽度有限，完整内容在报告/控制台里看
        reason = f.reason if len(f.reason) <= 100 else f.reason[:100] + "…"
        print(f"[{ts}] {_severity_tag(f)} {f.category:<8} {f.ip:<15} {reason}", flush=True)

    try:
        watcher.run(on_finding=on_finding)
    except KeyboardInterrupt:
        snap = watcher.snapshot()
        print(
            f"\n已停止。共读 {snap['lines_read']} 行，"
            f"推送告警 {snap['findings_total']} 条，"
            f"抑制 {snap['suppressed_total']} 条。"
        )
    finally:
        watcher.close()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Web 日志安全分析")
    ap.add_argument("files", nargs="+", help="日志文件路径，可传多个")
    ap.add_argument("--out", default="report", help="输出文件名前缀（不含扩展名）")
    ap.add_argument("--no-ai", action="store_true", help="只做规则检测，不调大模型")
    ap.add_argument("--window", type=int, default=None, help="404 扫描检测窗口（秒）")
    ap.add_argument("--threshold", type=int, default=None, help="404 触发阈值（次）")
    ap.add_argument("--ocsf", action="store_true",
                    help="额外导出一份 OCSF JSONL（可被其他 SIEM 直接消费）")
    ap.add_argument("--tail", action="store_true",
                    help="实时模式：持续跟随文件，边读边出告警（Ctrl-C 退出）")
    ap.add_argument("--from-start", action="store_true",
                    help="配合 --tail：从文件开头读，而不是从末尾")
    args = ap.parse_args(argv)

    config = Config.from_env()
    if args.window:
        config.scan_window_seconds = args.window
    if args.threshold:
        config.scan_404_threshold = args.threshold
    if args.no_ai:
        config.ai_enabled = False

    if args.tail:
        return _run_tail(args.files, config, from_start=args.from_start)

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
        if args.ocsf:
            # 事件在前、告警在后，不是随便排的：
            # 下游按行流式消费时，通常先建事件索引再关联告警，
            # 顺序反了会出现"告警引用了尚未入库的事件"。
            Path(f"{stem}.jsonl").write_text(
                to_jsonl(result.entries, result.findings), encoding="utf-8"
            )

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
