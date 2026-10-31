"""新旧版本对比：复现博客里那组数字。

用法：
    cd "E:\\python files"
    .venv\\Scripts\\python.exe tools\\compare_old_new.py

它做两件事：
1. 用同一批 12 条样本跑"旧版正则"和"新版引擎"，算精确率/召回率；
2. 用你真实的 access.log / auth.log 跑一遍新版，看实际告警长什么样。

保留这个脚本的意义：博客里写的 50%/14% -> 100%/100% 不是编的，
任何人都能跑一遍验证。这是"结论可复现"的最低要求。
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sec_log_analyzer import Config  # noqa: E402
from sec_log_analyzer.pipeline import analyze_bytes, analyze_file  # noqa: E402

# ---------------- 旧版正则（原封不动抄自 Web_log_analyzer_V2.py）----------------
OLD_SQLI = re.compile(r"(union\s+select|or\s+['\"]?1['\"]?=1|--|')", re.IGNORECASE)
OLD_XSS = re.compile(r"(<script>|alert\(|onerror=)", re.IGNORECASE)

UA = "Mozilla/5.0"
T = "[15/Oct/2026:10:00:{:02d}]"

# (说明, 是否真实攻击, 请求目标, 状态码)
SAMPLES = [
    ("正常-姓名带撇号(编码)", False, "/user/profile?name=O%27Brien", 200),
    ("正常-路径含双连字符", False, "/api/v2/item--detail", 200),
    ("正常-字体文件", False, "/fonts/fa-solid-900.woff2", 200),
    ("正常-搜索词含 select", False, "/search?q=select+the+best+product", 200),
    ("正常-文章页", False, "/article/2026/10/how-to-use-git", 200),
    ("攻击-URL编码 SQLi", True, "/p?id=1%27%20OR%20%271%27%3D%271", 500),
    ("攻击-大小写混淆 UNION", True, "/p?id=1+UnIoN+SeLeCt+1,2,3", 500),
    ("攻击-时间盲注", True, "/p?id=1%20AND%20SLEEP(5)", 500),
    ("攻击-路径穿越", True, "/../../etc/passwd", 400),
    ("攻击-命令注入", True, "/ping?host=127.0.0.1;cat+/etc/passwd", 200),
    ("攻击-编码 XSS", True, "/s?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E", 200),
    ("攻击-敏感文件探测", True, "/.env", 404),
]

lines = [
    f'10.9.9.{i} - - {T.format(i)} "GET {target} HTTP/1.1" {status} 512 "-" "{UA}"'
    for i, (_, _, target, status) in enumerate(SAMPLES)
]
text = "\n".join(lines)


def score(hits):
    tp = sum(1 for h, (_, atk, _, _) in zip(hits, SAMPLES) if h and atk)
    fp = sum(1 for h, (_, atk, _, _) in zip(hits, SAMPLES) if h and not atk)
    fn = sum(1 for h, (_, atk, _, _) in zip(hits, SAMPLES) if not h and atk)
    tn = sum(1 for h, (_, atk, _, _) in zip(hits, SAMPLES) if not h and not atk)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return tp, fp, fn, tn, precision, recall


old_hits = [bool(OLD_SQLI.search(line) or OLD_XSS.search(line)) for line in lines]

config = Config()
config.ai_enabled = False  # 对比检测能力，不掺 AI
result = analyze_bytes(text.encode("utf-8"), "samples.log", config)
alerted = {f.entry.raw for f in result.findings}
new_hits = [line in alerted for line in lines]

print("=" * 74)
print(f"{'样本':<24}{'实际':<8}{'旧版':<10}{'新版':<10}")
print("-" * 74)
for (desc, is_attack, _, _), o, n in zip(SAMPLES, old_hits, new_hits):
    print(f"{desc:<24}{'攻击' if is_attack else '正常':<8}"
          f"{'告警' if o else '放过':<10}{'告警' if n else '放过':<10}")

print()
for name, hits in (("旧版正则", old_hits), ("新版引擎", new_hits)):
    tp, fp, fn, tn, p, r = score(hits)
    print(f"{name}：TP={tp} FP={fp} FN={fn} TN={tn}  "
          f"精确率={p:.0%}  召回率={r:.0%}")

print("\n" + "=" * 74)
print("真实日志")
print("-" * 74)
for path in (ROOT / "access.log", ROOT / "auth.log"):
    if not path.exists():
        continue
    res = analyze_file(path, config)
    print(f"\n{path.name}：解析 {len(res.entries)} 行，告警 {len(res.findings)} 条")
    for f in res.findings:
        ts = f.ts.strftime("%Y-%m-%d %H:%M:%S") if f.ts else "时间未知"
        print(f"  [{f.severity.value:<8}] {f.category:<10} {f.ip:<14} {ts}")
