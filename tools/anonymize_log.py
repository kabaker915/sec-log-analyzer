"""日志脱敏工具：把真实日志里的 IP 替换掉，再用于公开仓库/文档。

为什么需要这一步：
  公网日志里既有我自己的服务器 IP，也有攻击者的 IP。
    服务器 IP 暴露 = 直接告诉别人"这台机器在哪儿"，会招来更多扫描；
    攻击者 IP 暴露 = 可能牵连第三方（很多肉鸡的主人是无辜的），也可能泄露情报来源。
  所以公开前必须脱敏。

脱敏策略（这几条是「有用」和「安全」的平衡点）：
  * 每一个不同的 IP 映射成一个稳定假名，同一 IP 在整份文件里始终是同一个假名
    → 保留"IP 与 IP 之间的关系"，但看不出它真实是谁
  * 只替换 IPv4，连 URL 里嵌的 IP 一起替换（日志里 http://1.2.3.4/ 也要处理）
  * 时间戳、端口、URL、UA 全部保留
    → 攻击特征完全不丢失，检测结果可复现，只是身份被抹掉了

用法：
    python tools/anonymize_log.py 原始日志.log -o 脱敏日志.log
    python tools/anonymize_log.py *.log -o out_dir/     # 批量
"""

from __future__ import annotations

import argparse
import hashlib
import re
import sys
from pathlib import Path

# 匹配 IPv4。每段限制在 0-255 之间。
#
# 这里踩过两个坑，都值得记下来：
#
# 坑 1：最初只用 \b 边界，结果 UA 里的版本号 "Chrome/157.0.0.0" 被当成 IP 替换掉，
#       脱敏后变成 "Chrome/198.51.100.138"——攻击特征里最重要的 UA 信息直接废了。
#       根因：版本号和 IPv4 长得一模一样，光靠正则是分不出来的。
#
# 坑 2：为了修坑 1，我加了 (?<![/v]) 排除「前面是斜杠」的情况。结果
#       URL 里的 "http://203.0.113.1/" 也匹配不上了——真实服务器 IP 漏脱敏。
#       根因：斜杠既出现在 "Chrome/157..." 里，也出现在 "http://1.2.3.4" 里，
#       光看前一个字符分不出这两种场景。
#
# 最终做法：正则只做「形状约束」（防止切进长版本号中间），
# 语义判断（是不是版本号）交给 VERSION_CONTEXT 去做。
# 这也是一条通用经验：正则适合描述形状，不适合表达语义。
IPV4 = re.compile(
    r"(?<![\d.])"
    r"(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)"
    r"(?!\.\d)"
)

# 版本号上下文：出现在这些词后面的四段数字，一律不当作 IP。
# 这是第二道防线——正则看着对，但它不可能理解语义。
VERSION_CONTEXT = re.compile(
    r"(?:Chrome|Chromium|Firefox|Safari|Edg|OPR|Version|rv|MSIE|Trident|"
    r"AppleWebKit|Gecko|python|curl|Wget|sqlmap|nmap|gobuster|nikto)"
    r"/?\s*$"
)

# 这些地址是「结构性」的，替换掉反而让人看不懂示例，所以保留原样。
# 文档网段（RFC 5737）本来就专供示例使用，出现在里面也无害。
KEEP_AS_IS = {
    "0.0.0.0",
    "127.0.0.1",
    "255.255.255.255",
}

# 私有网段保留，因为「内网还是外网」是判断攻击路径的重要信息。
# 内网 IP 本身不敏感，公开也没风险。
PRIVATE_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "172.18.",
                    "172.19.", "172.2", "172.30.", "172.31.")


def _is_private(ip: str) -> bool:
    return ip.startswith(PRIVATE_PREFIXES)


def fake_ip(ip: str, style: str = "testnet", salt: str = "") -> str:
    """把一个真实 IP 映射成稳定的假名。

    用 sha256 而不是随机数，是为了「稳定」：同一份日志里同一个 IP
    每次都要映射成同一个结果，否则时间序列分析就废了。
    salt 可以用来区分不同的日志批次，避免不同批次之间的假名撞车。
    """
    if style == "testnet":
        # RFC 5737 定义了三个专供文档示例的网段：
        #   192.0.2.0/24 (TEST-NET-1)、198.51.100.0/24 (TEST-NET-2)、203.0.113.0/24 (TEST-NET-3)
        # 用它们做假名，任何人一眼就知道这是脱敏过的样例，不会被误认成真实地址。
        pools = ("192.0.2", "198.51.100", "203.0.113")
        h = hashlib.sha256((salt + ip).encode()).digest()
        net = pools[h[0] % len(pools)]
        return f"{net}.{(h[1] % 254) + 1}"

    # 备选：统一压到 10.x 段，适合不想暴露「国家/运营商」线索的场合
    h = hashlib.sha256((salt + ip).encode()).digest()
    return f"10.{h[0]}.{h[1]}.{(h[2] % 254) + 1}"


def anonymize_text(text: str, mapping: dict[str, str] | None = None,
                   style: str = "testnet", salt: str = "") -> tuple[str, dict[str, str]]:
    """返回 (脱敏后的文本, IP 映射表)。映射表可以留下来做追溯（不公开）。"""
    mapping = {} if mapping is None else mapping
    skipped: list[str] = []

    def _sub(m: re.Match) -> str:
        ip = m.group(0)
        # 版本号识别：前面紧挨着 Chrome/、Version/ 这类词，就不是 IP
        if VERSION_CONTEXT.search(text[max(0, m.start() - 24): m.start()]):
            skipped.append(ip)
            return ip
        if ip in KEEP_AS_IS or _is_private(ip):
            return ip
        if ip not in mapping:
            mapping[ip] = fake_ip(ip, style=style, salt=salt)
        return mapping[ip]

    out = IPV4.sub(_sub, text)
    if skipped:
        # 不静默跳过：让人知道有哪些「看起来像 IP 的版本号」被保护了
        print(f"[提示] 识别为版本号、保持原样 {len(skipped)} 处："
              f"{', '.join(sorted(set(skipped)))}", file=sys.stderr)
    return out, mapping


def anonymize_file(src: Path, dst: Path, mapping: dict[str, str] | None = None,
                   style: str = "testnet", salt: str = "") -> dict[str, str]:
    text = src.read_text(encoding="utf-8", errors="replace")
    out, mapping = anonymize_text(text, mapping, style=style, salt=salt)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(out, encoding="utf-8")
    return mapping


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="日志 IP 脱敏")
    ap.add_argument("files", nargs="+", help="要脱敏的日志文件")
    ap.add_argument("-o", "--out", required=True,
                    help="输出文件；传目录则按原文件名写入")
    ap.add_argument("--style", default="testnet", choices=["testnet", "10net"],
                    help="假名风格：testnet 用文档保留网段，10net 用 10.x")
    ap.add_argument("--salt", default="", help="区分批次的盐，避免跨文件假名撞车")
    ap.add_argument("--map-out", default=None,
                    help="把 IP 映射表另存为文件（不要提交到公开仓库）")
    args = ap.parse_args(argv)

    out_path = Path(args.out)
    is_dir_out = out_path.suffix == "" and (out_path.is_dir() or len(args.files) > 1)
    if is_dir_out:
        out_path.mkdir(parents=True, exist_ok=True)

    mapping: dict[str, str] = {}
    for f in args.files:
        src = Path(f)
        if not src.exists():
            print(f"[跳过] 不存在：{src}", file=sys.stderr)
            continue
        dst = out_path / src.name if is_dir_out else out_path
        anonymize_file(src, dst, mapping, style=args.style, salt=args.salt)
        print(f"[完成] {src} -> {dst}")

    print(f"\n共替换 {len(mapping)} 个 IP")
    for real, fake in list(mapping.items())[:20]:
        print(f"  {real:>16}  ->  {fake}")
    if len(mapping) > 20:
        print(f"  ... 另有 {len(mapping) - 20} 个")

    if args.map_out:
        mp = Path(args.map_out)
        mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(
            "\n".join(f"{k}\t{v}" for k, v in mapping.items()),
            encoding="utf-8",
        )
        print(f"\n映射表已写入 {mp}（不要提交到公开仓库）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
