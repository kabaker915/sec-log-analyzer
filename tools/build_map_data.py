"""把日志聚合成地图数据。

输出一份 JSON，前端只负责画点，不做任何解析——
这样"数据怎么算"和"怎么显示"分开，换个前端不用重写统计逻辑。

聚合维度是 IP 而不是请求：
一台服务器 8 天收到 3086 个请求、645 个 IP，画 3086 个点会糊成一团，
画 645 个点才看得出地域分布。点的半径用请求数表示。
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sec_log_analyzer.config import Config
from sec_log_analyzer.geo import ATTRIBUTION, GeoLookup
from sec_log_analyzer.parser import LogParser, decode_bytes

# 诱饵分三级。这个分级是**实测出来的**，不是拍脑袋定的：
#
#   /.env                泛扫字典标配，8 天里几十个 IP 都试过
#   /.aws/credentials    我原本以为是强信号，实测发现也在泛扫字典里
#                        （45.148.10.5 在 11-13 就试过它，那时诱饵还没部署）
#   /admin/backup.zip    必须先知道"这站有后台、有备份"才会去试
#                        → 目前唯一真正站点特定的路径
#
# 教训：什么算"强信号"要拿真实日志验证，不能凭直觉。
# 一开始把 aws/credentials 算进强信号，地图上会有 4 个红点全是误报。
SITE_BAIT = {"/admin/backup.zip"}          # 站点特定
CLOUD_BAIT = {"/.aws/credentials"}         # 云凭据字典
ENV_BAIT = {"/.env"}                       # 泛扫标配

# 有这些告警说明不只是扫，而是在尝试利用
EXPLOIT_CATEGORIES = {"命令注入", "SQL注入", "路径穿越", "XSS", "命令执行"}


def iter_files(patterns: list[str]) -> list[Path]:
    files: list[Path] = []
    for pat in patterns:
        p = Path(pat)
        if p.is_dir():
            files.extend(sorted(p.glob("*.log*")))
        elif any(c in pat for c in "*?["):
            files.extend(sorted(Path().glob(pat)))
        elif p.exists():
            files.append(p)
    return files


def read_bytes(p: Path) -> bytes:
    """读文件，.gz 自动解压。

    地图是离线批处理，不像实时跟随需要"接着上次读"，
    所以 .gz 完全可以读——而且必须读，否则历史部分全丢了：
    nginx 只保留 8 个轮转包，最早那几天的数据只存在于 .gz 里。
    """
    if p.name.endswith(".gz"):
        with gzip.open(p, "rb") as fh:
            return fh.read()
    return p.read_bytes()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="生成地图数据")
    ap.add_argument("logs", nargs="*", default=["archive/*.log"],
                    help="日志路径，支持通配符，默认 archive/*.log")
    ap.add_argument("--out", default="data/map_points.json")
    ap.add_argument("--exclude", action="append", default=[],
                    help="排除的 IP（自己的测试出口）")
    args = ap.parse_args(argv)

    files = iter_files(args.logs or ["archive/*.log"])
    if not files:
        print("没找到日志文件", file=sys.stderr)
        return 1

    parser = LogParser(Config(ai_enabled=False))
    geo = GeoLookup()

    per_ip: dict[str, dict] = defaultdict(lambda: {
        "n": 0, "first": None, "last": None,
        "ua": Counter(), "paths": Counter(),
        "bait": False, "bait_cloud": False, "bait_weak": False,
        "exploit": False, "h": Counter(),
    })
    total_lines = 0
    # 去重键。archive/ 里是多份重叠的拉取结果——
    # 每次 pull 都会把当前 access.log 整份拉下来，同一行会出现很多次。
    # 不去重的话"诱饵命中 7 次"实际可能只有 3 次，
    # 而这张地图的说服力全靠数字准不准。
    seen: set[tuple] = set()
    dup = 0

    for f in files:
        text, _enc = decode_bytes(read_bytes(f), ["utf-8", "gbk", "latin-1"])
        entries, _errors = parser.parse_text(text)
        total_lines += len(entries)

        for e in entries:
            if e.source != "access" or not e.ip:
                continue
            if e.ip in args.exclude:
                continue
            key = (e.ip, e.ts, e.method, e.path, e.status,
                   (e.user_agent or "")[:40])
            if key in seen:
                dup += 1
                continue
            seen.add(key)
            rec = per_ip[e.ip]
            rec["n"] += 1
            if e.ts:
                rec["first"] = e.ts if rec["first"] is None or e.ts < rec["first"] else rec["first"]
                rec["last"] = e.ts if rec["last"] is None or e.ts > rec["last"] else rec["last"]
            if e.ts:
                # 按小时分桶：时间轴要能"拖到某一小时看谁在打"，
                # 只有首末时间点做不出连续回放，只能跳变。
                rec["h"][e.ts.strftime("%Y-%m-%dT%H")] += 1
            if e.user_agent:
                rec["ua"][e.user_agent[:80]] += 1
            if e.path:
                # 去掉查询串，只保留路径骨架，否则同一路径会分裂成几百个
                path = e.path.split("?")[0][:60]
                rec["paths"][path] += 1
            if e.path in SITE_BAIT:
                rec["bait"] = True
            elif e.path in CLOUD_BAIT:
                rec["bait_cloud"] = True
            elif e.path in ENV_BAIT:
                rec["bait_weak"] = True

    # 需要检测结果才能知道"是否尝试利用"，单独跑一次
    from sec_log_analyzer.detector import Detector

    detector = Detector(Config(ai_enabled=False))
    for f in files:
        text, _ = decode_bytes(read_bytes(f), ["utf-8", "gbk", "latin-1"])
        entries, _ = parser.parse_text(text)
        for finding in detector.detect(entries):
            if finding.category in EXPLOIT_CATEGORIES and finding.ip in per_ip:
                per_ip[finding.ip]["exploit"] = True

    # 全局小时轴：从最早到最晚，补齐中间没有事件的空小时。
    # 不补的话时间轴刻度会跳（比如 13 号到 17 号之间是空的，
    # 滑块会"瞬间跳过去"，看起来像数据丢了）。
    all_hours: list[str] = []
    if per_ip:
        stamps = sorted({h for rec in per_ip.values() for h in rec["h"]})
        if stamps:
            from datetime import datetime as _dt
            cur = _dt.strptime(stamps[0], "%Y-%m-%dT%H")
            end = _dt.strptime(stamps[-1], "%Y-%m-%dT%H")
            while cur <= end:
                all_hours.append(cur.strftime("%Y-%m-%dT%H"))
                cur = cur + __import__("datetime").timedelta(hours=1)
    hour_index = {h: i for i, h in enumerate(all_hours)}

    points = []
    no_geo = 0
    for ip, rec in per_ip.items():
        loc = geo.lookup(ip)
        if not loc.get("ok"):
            no_geo += 1
            continue
        points.append({
            "ip": ip,
            "lat": loc["lat"],
            "lon": loc["lon"],
            "country": loc["country"],
            "cc": loc["country_code"],
            "city": loc["city"],
            "n": rec["n"],
            "first": rec["first"].isoformat() if rec["first"] else "",
            "last": rec["last"].isoformat() if rec["last"] else "",
            "ua": rec["ua"].most_common(1)[0][0] if rec["ua"] else "-",
            "paths": [p for p, _ in rec["paths"].most_common(4)],
            "h": {str(hour_index[h]): n for h, n in rec["h"].items() if h in hour_index},
            "cat": ("bait" if rec["bait"]
                    else ("exploit" if rec["exploit"]
                          else ("cloud" if rec["bait_cloud"]
                                else "scan"))),
        })

    countries = Counter(p["country"] for p in points if p["country"])
    payload = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attribution": ATTRIBUTION,
        "stats": {
            "files": len(files),
            "entries": total_lines,
            "ips": len(per_ip),
            "mapped": len(points),
            "no_geo": no_geo,
            "countries": len(countries),
            "bait": sum(1 for p in points if p["cat"] == "bait"),
            "cloud": sum(1 for p in points if p["cat"] == "cloud"),
            "env": sum(1 for p in points if p["cat"] == "scan" and "/.env" in p["paths"]),
            "exploit": sum(1 for p in points if p["cat"] == "exploit"),
            "top_countries": countries.most_common(8),
        },
        "hours": all_hours,
        "points": points,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")

    s = payload["stats"]
    print(f"日志 {s['files']} 个，{s['entries']} 条（去重跳过 {dup} 条重复）")
    print(f"IP {s['ips']} 个，成功定位 {s['mapped']} 个（{s['no_geo']} 个无坐标）")
    print(f"国家/地区 {s['countries']} 个")
    print(f"站点特定诱饵 {s['bait']} 个 / 云凭据探测 {s['cloud']} 个 / "
          f"尝试利用 {s['exploit']} 个")
    print(f"\n已写入 {out}（{out.stat().st_size / 1024:.0f} KB）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
