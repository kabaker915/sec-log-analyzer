"""评估检出质量：真阳 / 误报 / 漏检，按攻击类型分组。

为什么需要这个脚本：
    "检出 6998 条告警"这个数字本身没有意义，安全工具要证明的是三件事——
    1. 召回率：造了多少攻击，抓到了多少（漏报会出事故）
    2. 精确率：报出来的是不是真的（误报会让人关掉告警）
    3. 性能：多大体积、多快跑完（能不能上线）

    语料是 gen_corpus.py 造的，每条攻击样本都能在原始日志里按特征反查，
    所以这里的口径是可复现的，不是随口报的数字。

用法：
    python bench/evaluate.py
"""

from __future__ import annotations

import csv
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

from sec_log_analyzer.config import Config
from sec_log_analyzer.pipeline import analyze_file
from sec_log_analyzer.rules import normalize

CORPUS = Path("bench/corpus")
OUT = Path("bench/out")

# 判定某行原始日志属于哪类攻击（用于计算召回率）
# 用路径/参数里的决定性特征反查，与生成器的载荷一一对应
SIGNATURES: dict[str, re.Pattern[str]] = {
    "SQL注入": re.compile(r"union\b|\bor\s+'|sleep\(|extractvalue|drop\s+table|sysobjects", re.I),
    "XSS": re.compile(r"<script|<img|onerror=|onload=|javascript:alert", re.I),
    "路径穿越": re.compile(r"\.\./|\.\.\\|win\.ini|/etc/(passwd|shadow)", re.I),
    "命令注入": re.compile(r"[;|]\s*cat\b|[;|]\s*whoami|\|nc\b|\$\(|;\s*ls\b|\|\s*id\b", re.I),
    "敏感文件探测": re.compile(r"/\.(git|svn|env)(/|$)|backup/|\.bak|actuator/(env|heapdump)"),
    "WebShell": re.compile(r"system\('id'|eval\(\$|/shell\.php"),
    "Log4j注入": re.compile(r"jndi:(ldap|rmi)"),
    "SSRF": re.compile(r"url=http://127\.0\.0\.1|target=http://169\.254|src=http://192\.168"),
}

# 干净的正常请求，出现在告警里即为误报
CLEAN_NORMAL = re.compile(r"O'Brien|item--detail|1\+1=2|select-guide|report_2026\.sql\.pdf|alert-notice")


def classify(raw: str) -> str | None:
    """先 URL 解码再匹配。原始日志里的载荷都是编码过的。"""
    text = normalize(raw)
    for cat, pat in SIGNATURES.items():
        if pat.search(text):
            return cat
    return None


def main() -> None:
    cfg = Config.from_env()
    cfg.ai_enabled = False

    reports = {}
    for name in ("access_large.log", "auth_large.log"):
        p = CORPUS / name
        t0 = time.perf_counter()
        result = analyze_file(p, cfg)
        wall = (time.perf_counter() - t0) * 1000
        reports[name] = (result, wall, p.stat().st_size)

    rows = list(csv.DictReader(open(OUT / "large_access_large.csv", encoding="utf-8-sig")))

    # --- 召回率：把告警里的原始日志归类，和语料里的真实攻击数对比 ---
    detected = Counter()
    for r in rows:
        cat = classify(r["原始日志"])
        if cat:
            detected[cat] += 1

    truth = Counter()
    for line in (CORPUS / "access_large.log").read_text(encoding="utf-8").splitlines():
        cat = classify(line)
        if cat:
            truth[cat] += 1

    # --- 误报：告警中不含任何攻击特征的行 ---
    fp = 0
    fp_samples = []
    for r in rows:
        if classify(r["原始日志"]) is None:
            fp += 1
            if len(fp_samples) < 5:
                fp_samples.append((r["攻击类型"], r["原始日志"][:110]))

    total_alert = len(rows)
    total_truth = sum(truth.values())

    print("=" * 66)
    print("检出质量评估  (10 万行 access.log / 5 千行 auth.log)")
    print("=" * 66)

    res_a, wall_a, size_a = reports["access_large.log"]
    res_h, wall_h, size_h = reports["auth_large.log"]
    print(f"\n性能")
    print(f"  access.log  {size_a/1024/1024:>6.2f} MB  {res_a.entries.__len__():>7} 行  "
          f"{res_a.elapsed_ms:>5} ms  ({res_a.entries.__len__()/(res_a.elapsed_ms/1000):>8.0f} 行/秒)")
    print(f"  auth.log    {size_h/1024/1024:>6.2f} MB  {res_h.entries.__len__():>7} 行  "
          f"{res_h.elapsed_ms:>5} ms")

    print(f"\n召回率（按攻击类型）")
    print(f"  {'类型':<12}{'注入':>6}{'检出':>6}{'漏':>5}{'召回':>8}")
    for cat in SIGNATURES:
        t, d = truth.get(cat, 0), detected.get(cat, 0)
        if t == 0:
            continue
        rec = d / t * 100
        print(f"  {cat:<12}{t:>6}{d:>6}{t-d:>5}{rec:>7.1f}%")
    print(f"  {'合计':<12}{total_truth:>6}{sum(detected.values()):>6}"
          f"{total_truth-sum(detected.values()):>5}{sum(detected.values())/total_truth*100:>7.1f}%")

    print(f"\n精确率")
    print(f"  告警总数 {total_alert}")
    print(f"  含攻击特征 {total_alert - fp}")
    print(f"  疑似误报 {fp}  ({fp/total_alert*100:.1f}%)")
    if fp_samples:
        print("  误报样例：")
        for cat, raw in fp_samples:
            print(f"    [{cat}] {raw}")

    print(f"\nSSH 爆破")
    print(f"  auth.log 告警 {len(res_h.findings)} 条，"
          f"识别出爆破源 {len({f.ip for f in res_h.findings})} 个 IP")


if __name__ == "__main__":
    main()
