"""最简版 Web 日志分析器 —— 单文件，约 90 行，能完整读懂的那种。

只做三件事：
    1. 读日志
    2. 用规则给每条请求打分
    3. 打印报告

没有类、没有 dataclass、没有 AI、没有配置文件、没有命令行参数解析。
把这一百行读透，再去看 sec_log_analyzer/ 那个 1500 行的版本，就有参照物了。

用法：
    .venv\\Scripts\\python.exe simple\\analyzer.py access.log
"""

import re
import sys
from collections import Counter
from urllib.parse import unquote_plus

# ---------------------------------------------------------------- 1. 规则表
# 每条：(正则, 权重, 类别)
# 权重 10 = 单独命中就告警；权重 3 = 必须叠加才够
RULES = [
    # SQL 注入
    (r"\bunion\b\s*(?:all\b\s*)?\bselect\b", 10, "SQL注入"),
    (r"\b(?:sleep|benchmark|pg_sleep)\s*\(", 10, "SQL注入"),
    (r"(?:'|\"|\)|\d)\s*(?:or|and)\s+(?:'[^']*'?|\d+)\s*=\s*(?:'[^']*'?|\d+)", 10, "SQL注入"),
    (r"['\"]", 3, "SQL注入"),
    # XSS
    (r"<\s*script", 10, "XSS"),
    (r"\bon(?:error|load|click)\s*=", 10, "XSS"),
    (r"\b(?:alert|prompt|confirm)\s*\(", 3, "XSS"),
    # 路径穿越 / 命令注入
    (r"(?:\.\./|\.\.\\)", 10, "路径穿越"),
    (r"[;|`&]\s*(?:cat|ls|whoami|id|wget|curl|bash|sh)\b", 10, "命令注入"),
    # 敏感文件
    (r"/\.(?:git|env|svn)(?:/|\b)", 10, "敏感文件探测"),
    (r"/(?:backup|db|dump)[\w\-.]*\.(?:zip|sql|bak|tar\.gz)$", 10, "敏感文件探测"),
]
RULES = [(re.compile(pattern, re.I), weight, category) for pattern, weight, category in RULES]

THRESHOLD = 6

# ---------------------------------------------------------------- 2. 解析一行
# 注意：整个请求行用 ([^"]*) 抓，不能用 (\S+) (\S+)
# 因为攻击请求里可能有空格，比如 "GET /p?id=1' OR '1'='1 HTTP/1.1"
LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"]*)" (\d{3})')


def parse(line):
    """一行文本 -> 字典。解析不了就返回 None。"""
    m = LINE.match(line)
    if not m:
        return None
    ip, time, request, status = m.groups()

    parts = request.split()
    if len(parts) < 2:
        return None
    method = parts[0]
    # 末尾是 HTTP/1.1 就去掉它，剩下的全是 target（可能含空格）
    if parts[-1].startswith("HTTP/"):
        target = " ".join(parts[1:-1])
    else:
        target = " ".join(parts[1:])

    return {"ip": ip, "time": time, "method": method, "target": target, "status": int(status)}


# ---------------------------------------------------------------- 3. 归一化
def normalize(text):
    """%27 变回 '，+ 变回空格。不做这一步，编码过的攻击全部漏掉。"""
    for _ in range(2):  # 两轮，防 %2527 二次编码
        new = unquote_plus(text)
        if new == text:
            break
        text = new
    return re.sub(r"\s+", " ", text)


# ---------------------------------------------------------------- 4. 打分
def score(target):
    """返回 (类别, 总分)；不够阈值就返回 None。"""
    payload = normalize(target)

    per_category = {}
    for pattern, weight, category in RULES:
        if pattern.search(payload):
            per_category[category] = per_category.get(category, 0) + weight

    if not per_category:
        return None

    category, total = max(per_category.items(), key=lambda item: item[1])
    if total < THRESHOLD:
        return None
    return category, total


# ---------------------------------------------------------------- 5. 主流程
def main(path):
    total = 0
    alerts = []

    with open(path, encoding="utf-8") as f:
        for line in f:
            entry = parse(line.strip())
            if entry is None:
                continue
            total += 1

            result = score(entry["target"])
            if result is None:
                continue

            entry["category"], entry["score"] = result
            alerts.append(entry)

    print(f"共解析 {total} 条请求，告警 {len(alerts)} 条\n")
    for a in alerts:
        print(f"[{a['category']}] {a['ip']}  {a['target']}  (score={a['score']})")

    print("\n按类别统计：")
    for category, n in Counter(a["category"] for a in alerts).most_common():
        print(f"  {category}: {n}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "access.log")
