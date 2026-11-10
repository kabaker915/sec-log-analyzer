"""我的第一个检测器 —— 从零写，约 40 行。

目标：读 access.log，找出含攻击特征的请求，打分，打印告警。
这是 sec_log_analyzer 的"最小内核"，剩下 1500 行都是它的工程化包装。

运行：
    python simple/04_my_analyzer.py

分两步填，每步都能跑。**不要一次写完，填一步跑一次。**
"""

import re
from pathlib import Path

# 用 __file__ 定位项目根目录，这样不管在哪个目录运行都能找到 access.log
BASE = Path(__file__).resolve().parent.parent

# 规则表：(正则, 权重, 类别) —— 只留 3 条，方便看清结构
RULES = [
    (r"union\s+select", 10, "SQL注入"),
    (r"<\s*script", 10, "XSS"),
    (r"\.\./", 10, "路径穿越"),
]

THRESHOLD = 6


def analyze(path):
    total = 0
    alerts = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            total += 1

            # ================= 第 1 步：取出请求路径 =================
            # 日志长这样：
            #   10.0.0.8 - - [31/Oct/2026:13:00:00 +0800] "GET /?id=1 HTTP/1.1" 200 512 "-" "curl"
            # 我们要的是引号里的 "GET /?id=1 HTTP/1.1"
            #
            # 提示：line.split('"') 会把字符串按双引号切开，试试打印看看是几段
            # toString = line.split('"')
            # payload = toString[1]        # ← 把这两行的注释去掉，改成你自己写的
            parts = line.split('"')

            payload = parts[1]

            if payload is None:
                continue  # 第 1 步没填完时，先跳过，保证程序能跑

            # ================= 第 2 步：拿规则去匹配 =================
            # 要求：遍历 RULES，命中就累加权重；分数够 THRESHOLD 就记录告警
            #
            # 提示：
            #   for pattern, weight, category in RULES:
            #       if re.search(pattern, payload, re.I):
            #           ...
            score = 0
            category = ""
            for pattern, weight, rule_category in RULES:
                if re.search(pattern, payload, re.I):
                    score += weight
                    category = rule_category



            if score >= THRESHOLD:
                alerts.append(f"[{category}] {payload}")

    print(f"共 {total} 行，告警 {len(alerts)} 条")
    for a in alerts:
        print(" ", a)


    if __name__ == "__main__":
        analyze(BASE / "access.log")
