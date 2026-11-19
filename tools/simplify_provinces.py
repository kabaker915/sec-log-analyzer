"""把国标省级边界精简成适合 3D 渲染的版本。

为什么需要
----------
原始数据 25240 个顶点、339 个环。three-globe 的 polygons 会把每个环
挤出成"带侧壁的立体块"，339 个立体块 + 25000 顶点，帧率直接掉。

而这张图上的中国只占球面很小一块，80 个点的省界弧线和 1400 个点的
看起来几乎没有差别——多出来的顶点全在浪费。

做的事
------
1. 抽稀：每个环最多保留 MAX_POINTS 个点（等间隔取样，保留首尾闭合）
2. 降精度：坐标保留 3 位小数（约 100 米），球面尺度上不可见
3. 丢弃极小的环：< 4 个点的碎片（几个像素大的礁石）保留也看不见

**不改变边界走向**，只是把密集的采样点变稀疏。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

SRC = Path("static/vendor/geo/china-provinces.json")
DST = Path("static/vendor/geo/china-provinces-lite.json")

MAX_POINTS = 90        # 每个环的顶点上限
MIN_RING = 4           # 少于这个点数的环直接丢


def decimate(ring: list[list[float]]) -> list[list[float]]:
    """等间隔抽稀，并保留首尾。"""
    if len(ring) <= MAX_POINTS:
        return [[round(x, 3), round(y, 3)] for x, y in ring]

    step = len(ring) / MAX_POINTS
    out = [ring[int(i * step)] for i in range(MAX_POINTS)]
    # 多边形必须闭合：首点补到末尾
    if out[0] != out[-1]:
        out.append(out[0])
    return [[round(x, 3), round(y, 3)] for x, y in out]


def process(geom: dict) -> dict | None:
    t = geom["type"]
    if t == "MultiPolygon":
        polys = []
        for poly in geom["coordinates"]:
            rings = [decimate(r) for r in poly if len(r) >= MIN_RING]
            if rings:
                polys.append(rings)
        return {"type": "MultiPolygon", "coordinates": polys} if polys else None

    if t == "Polygon":
        rings = [decimate(r) for r in geom["coordinates"] if len(r) >= MIN_RING]
        return {"type": "Polygon", "coordinates": rings} if rings else None

    # LineString / MultiLineString 之类的要素不属于面，
    # 交给 polygons 渲染会变成一整片色块（地球被染蓝的元凶之一）
    return None


def main() -> int:
    if not SRC.exists():
        print("缺少原始省界数据", file=sys.stderr)
        return 1

    src = json.loads(SRC.read_text(encoding="utf-8"))
    out_features = []
    dropped = 0

    for f in src["features"]:
        geom = process(f["geometry"])
        if geom is None:
            dropped += 1
            continue
        out_features.append({
            "type": "Feature",
            "properties": {"name": f["properties"].get("name", ""),
                           "adcode": f["properties"].get("adcode")},
            "geometry": geom,
        })

    out = {"type": "FeatureCollection", "features": out_features}
    DST.write_text(json.dumps(out, ensure_ascii=False, separators=(",", ":")),
                   encoding="utf-8")

    def count(d):
        n = r = 0
        for f in d["features"]:
            g = f["geometry"]
            polys = g["coordinates"] if g["type"] == "MultiPolygon" else [g["coordinates"]]
            for p in polys:
                for ring in p:
                    r += 1
                    n += len(ring)
        return n, r

    n0, r0 = count(src)
    n1, r1 = count(out)
    print(f"顶点 {n0} → {n1}（-{100 - n1 * 100 // n0}%）")
    print(f"环   {r0} → {r1}")
    print(f"要素 {len(src['features'])} → {len(out_features)}（丢弃非面要素 {dropped} 个）")
    print(f"文件 {SRC.stat().st_size // 1024}KB → {DST.stat().st_size // 1024}KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
