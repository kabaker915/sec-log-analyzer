"""根据分析结果生成封禁建议 —— 只打印命令，绝不执行。

这是"自动化封禁"最安全的第一步：先做成建议，人工确认后再执行。
直接把封禁写成自动执行的脚本，是新手最容易翻车的地方（后面有说明）。

用法：
    .venv\\Scripts\\python.exe tools\\ban_suggest.py real_access.log
    .venv\\Scripts\\python.exe tools\\ban_suggest.py real_access.log --min-score 10
"""

import argparse
import ipaddress
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sec_log_analyzer import Config
from sec_log_analyzer.pipeline import analyze_file

# 永远不封的地址：本机、以及自己人
ALWAYS_ALLOW = {"127.0.0.1", "::1"}

# 额外白名单，用逗号分隔，从环境变量读
# 例：set BAN_WHITELIST=10.119.72.163,10.119.72.8
EXTRA_ALLOW = {ip.strip() for ip in os.getenv("BAN_WHITELIST", "").split(",") if ip.strip()}


def main() -> int:
    ap = argparse.ArgumentParser(description="生成封禁建议（只输出，不执行）")
    ap.add_argument("logfile")
    ap.add_argument("--min-score", type=int, default=10, help="只处理评分不低于该值的告警")
    ap.add_argument("--ttl", type=int, default=3600, help="建议封禁秒数（默认 1 小时）")
    args = ap.parse_args()

    cfg = Config()
    cfg.ai_enabled = False
    result = analyze_file(args.logfile, cfg)

    # 按 IP 汇总
    candidates: dict[str, list] = {}
    for f in result.findings:
        if f.score < args.min_score:
            continue
        candidates.setdefault(f.ip, []).append(f)

    print(f"分析 {len(result.entries)} 行，告警 {len(result.findings)} 条，"
          f"候选封禁 IP {len(candidates)} 个\n")

    if not candidates:
        print("没有需要封禁的 IP。")
        return 0

    commands = []
    for ip, items in sorted(candidates.items(), key=lambda kv: -len(kv[1])):
        reasons = ", ".join(sorted({i.category for i in items}))

        if ip in ALWAYS_ALLOW or ip in EXTRA_ALLOW:
            print(f"⏭  {ip:<16} 命中白名单，跳过（{reasons}）")
            continue

        # 内网地址要特别提醒：很可能封到你自己
        try:
            if ipaddress.ip_address(ip).is_private:
                print(f"⚠️  {ip:<16} 是内网地址，确认不是你自己人再封（{reasons}）")
        except ValueError:
            pass

        commands.append(f"ipset add banned {ip} timeout {args.ttl}")
        print(f"🚫 {ip:<16} {len(items)} 条告警，涉及 {reasons}")

    if commands:
        print("\n--- 确认无误后，在服务器上执行 ---")
        print("# 先建集合（只需一次）：")
        print("ipset create banned hash:ip timeout 3600")
        print("# 让 iptables 引用它（只需一次）：")
        print("iptables -I INPUT -m set --match-set banned src -j DROP")
        print()
        for c in commands:
            print(c)
        print("\n# 查看当前封禁：")
        print("ipset list banned")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
