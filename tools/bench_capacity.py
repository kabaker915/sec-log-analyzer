"""容量测算：这个监控在 2 核 4G 的机器上到底跑不跑得动。

为什么要写这个脚本，而不是拍脑袋说"应该没问题"

    安全工具的性能问题有个特点：**平时看不出来，出事的时候才发现**。
    平常一天几百条日志，占 CPU 接近 0；一旦被 CC 打或者被全网扫，
    日志量暴涨，检测跟不上，此时恰恰是最需要监控工作的时候，它却瘫了。
    所以容量必须按"最坏情况"算，不是按"平常情况"算。

    这个脚本量的就是最坏情况：缓冲区打满、窗口内条目数到上限时的单轮耗时。

用法：
    python tools/bench_capacity.py
    python tools/bench_capacity.py --entries 8000 20000

判读标准

    单轮耗时必须明显小于检测周期（默认 5 秒）。
    如果接近或超过周期，说明每轮都在追上一轮的尾巴，
    延迟会一直累积——表现出来的现象是"告警越来越晚"，
    而不是"系统报错"，所以特别容易被忽略。
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sec_log_analyzer.config import Config            # noqa: E402
from sec_log_analyzer.detector import Detector        # noqa: E402
from sec_log_analyzer.parser import LogParser         # noqa: E402
from sec_log_analyzer.watcher import LogWatcher       # noqa: E402

SAMPLE = Path(__file__).resolve().parent.parent / "samples" / "access_2026-11-11.sample.log"


def rss_mb() -> float:
    """读当前进程的常驻内存。

    不引入 psutil 是有意的：这个项目核心零依赖，
    为了一个测算脚本装一个第三方库不值得。
    系统自带工具足够，只是 Windows 和 Linux 的命令不同。
    """
    if os.name == "nt":
        out = subprocess.run(
            ["tasklist", "/FI", f"PID eq {os.getpid()}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True,
        ).stdout
        m = re.search(r'"([\d,]+) K"', out)
        return int(m.group(1).replace(",", "")) / 1024 if m else -1.0
    # Linux/macOS：/proc 里的 VmRSS 单位是 kB
    try:
        for line in Path("/proc/self/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    except OSError:
        pass
    return -1.0


def build_entries(n: int) -> list:
    """用真实样本循环拼出 n 条，时间戳按 0.3 秒递减间隔铺开。

    n 条 0.3 秒间隔 ≈ 覆盖 n*0.3 秒的时间跨度，用来模拟
    "缓冲区里塞满了最近一小时的数据"这种最坏情况。
    """
    lines = [ln for ln in SAMPLE.read_text(encoding="utf-8").splitlines() if ln]
    parser = LogParser(Config())
    out = []
    for i in range(n):
        e = parser.parse_line(lines[i % len(lines)])
        if e is None:
            continue
        e.ts = datetime(2026, 11, 11, 10, 0, 0) + timedelta(seconds=i * 0.3)
        out.append(e)
    return out


def timeit(fn, repeat: int = 3) -> float:
    """取多次运行的最小值。

    不用平均值：第一次调用包含解释器预热、正则编译缓存填充，
    平均值会被这一次拖高，而稳态性能才是我们要看的。
    """
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best * 1000


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="实时监控容量测算")
    ap.add_argument("--entries", type=int, nargs="+", default=[2000, 8000, 20000],
                    help="要测的缓冲区条目数")
    args = ap.parse_args(argv)

    if not SAMPLE.exists():
        print(f"缺少样本文件：{SAMPLE}", file=sys.stderr)
        return 2

    config = Config(ai_enabled=False)
    detector = Detector(config)

    print(f"样本：{SAMPLE.name}")
    print(f"行为检测窗口上限：{config.behavior_max_window_entries} 条")
    print(f"行为检测周期：5.0 秒（watcher 默认值）\n")
    print(f"{'条目数':>8}  {'内存':>8}  {'完整 detect':>12}  {'仅行为':>10}  {'占单核':>8}")
    print("-" * 56)

    for n in args.entries:
        entries = build_entries(n)
        full = timeit(lambda: detector.detect(entries))
        beh = timeit(lambda: detector.detect_behavior_only(entries))
        mem = rss_mb()

        # 「占单核」按 5 秒周期折算：每 5 秒只做一次行为检测。
        # 这是理想估算，不含读文件、解析、抑制的开销（那部分实测 < 5ms）。
        cpu_pct = beh / 5000 * 100
        print(f"{n:>8}  {mem:>7.1f}M  {full:>10.0f} ms  {beh:>8.0f} ms  {cpu_pct:>7.1f}%")

    print("\n判读：『仅行为』一列才是实时模式的真实开销。")
    print("完整 detect 只在离线批量分析时用。")
    print("占单核超过 50% 属于危险，说明窗口上限该调小或检测周期该放宽。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
