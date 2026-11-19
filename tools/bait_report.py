"""蜜罐诱饵访问报告。

为什么单独一个脚本，不直接塞进引擎
----------------------------------
引擎的规则是"通配特征"——一条规则命中所有站点的所有 .env 请求。
但诱饵的判断逻辑不同：**只有我自己放的那几个路径算诱饵**。

混进通用规则有两个坏处：
  1. 规则里会出现本机路径，换台机器就不成立
  2. 未来接地图时要区分"泛扫"和"定向"，这个区分是蜜罐层的概念，
     不该污染内容检测层

所以独立一层：读 access.log，只挑出命中诱饵路径的请求。

核心价值
--------
   扫 /.env 的           → 泛扫工具，人人都扫，噪音
   扫 /admin/backup.zip  → 看过你的站，知道有备份，这才是信号

前者每天几百次，后者可能一个月一次。**报告只该让人看后者。**
"""

from __future__ import annotations

import argparse
import gzip
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# 和 nginx 里放行的三条一一对应。
# 改动这里必须同步改 nginx，否则统计口径和实际暴露面不一致。
BAIT_PATHS = {
    "/.env": "假数据库凭据",
    "/.aws/credentials": "假云密钥",
    "/admin/backup.zip": "假数据库备份",
}

# nginx combined 格式
LINE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<ref>[^"]*)" "(?P<ua>[^"]*)"'
)


def read_lines(path: Path):
    """支持 .gz，直接读文本。"""
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
            yield from fh
    else:
        with open(path, encoding="utf-8", errors="replace") as fh:
            yield from fh


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="蜜罐诱饵访问报告")
    ap.add_argument("logs", nargs="+", help="access.log 路径，支持通配符和 .gz")
    ap.add_argument("--all", action="store_true",
                    help="连 /.env 这种泛扫目标也显示（默认只显示强信号）")
    ap.add_argument("--exclude", action="append", default=[],
                    help="排除的 IP（自己的测试出口），可重复。"
                         "不排除的话报告全被自己的 curl 淹掉")
    args = ap.parse_args(argv)

    # 展开通配符
    files: list[Path] = []
    for pattern in args.logs:
        p = Path(pattern)
        if any(c in pattern for c in "*?["):
            files.extend(sorted(Path().glob(pattern)))
        elif p.exists():
            files.append(p)

    if not files:
        print("没有找到日志文件", file=sys.stderr)
        return 1

    hits: list[dict] = []
    total = 0

    for f in files:
        for line in read_lines(f):
            total += 1
            m = LINE.match(line)
            if not m:
                continue
            path = m.group("path")
            if path not in BAIT_PATHS:
                continue
            if m.group("ip") in args.exclude:
                continue
            hits.append({
                "ip": m.group("ip"),
                "ts": m.group("ts"),
                "path": path,
                "status": m.group("status"),
                "ua": m.group("ua") or "-",
                "ref": m.group("ref") or "-",
            })

    print(f"扫描 {len(files)} 个文件，{total} 行日志")
    if args.exclude:
        print(f"已排除自己的 IP：{', '.join(args.exclude)}")
    print(f"诱饵命中：{len(hits)} 次\n")

    if not hits:
        print("还没有人碰过诱饵。")
        print("这是正常的——诱饵刚上线，扫描器会按自己的节奏来。")
        print("过 24 小时再看。")
        return 0

    # 按路径分组：/.env 是泛扫重灾区，其余两个信号更强
    by_path: dict[str, list[dict]] = defaultdict(list)
    for h in hits:
        by_path[h["path"]].append(h)

    for path, desc in BAIT_PATHS.items():
        items = by_path.get(path, [])
        if not items:
            print(f"【{path}】{desc}：无人访问")
            continue
        strong = path != "/.env"
        mark = "★ 强信号" if strong else "  泛扫"
        print(f"【{path}】{desc}：{len(items)} 次  {mark}")
        for h in items[:8]:
            print(f"    {h['ts']}  {h['ip']:<16} {h['status']}  {h['ua'][:44]}")
        if len(items) > 8:
            print(f"    ... 还有 {len(items) - 8} 条")

    # 来源去重
    ips = Counter(h["ip"] for h in hits)
    print(f"\n涉及 {len(ips)} 个不同 IP")
    multi = [(ip, n) for ip, n in ips.items() if n > 1]
    if multi:
        print("重复访问（更可能是人工/定向）：")
        for ip, n in sorted(multi, key=lambda x: -x[1])[:10]:
            print(f"    {ip:<16} {n} 次")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
