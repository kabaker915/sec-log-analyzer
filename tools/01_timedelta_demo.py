"""演示 timedelta.seconds 和 total_seconds() 的区别。

运行：.venv\\Scripts\\python.exe tools\\01_timedelta_demo.py
"""

from datetime import datetime, timedelta

base = datetime(2026, 1, 1, 0, 0, 0)

cases = [
    ("相隔 90 秒", base + timedelta(seconds=90)),
    ("相隔 25 小时", base + timedelta(hours=25)),
    ("负数：后一条比前一条早 30 秒", base - timedelta(seconds=30)),
]

for label, other in cases:
    d = other - base
    print(f"\n{label}")
    print(f"  days          = {d.days}")
    print(f"  seconds       = {d.seconds}")
    print(f"  total_seconds = {d.total_seconds()}")
