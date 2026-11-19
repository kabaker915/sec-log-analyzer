"""把地图页打成单文件 HTML 快照。

为什么需要
----------
控制台的页面要登录，口令是启动时随机生成打在终端里的。
面试演示、发给人看、或者截图存档时，不该为了看一眼图去翻终端找口令。

这个脚本把 CSS/JS/数据全部内联成一个 HTML 文件，双击就能打开。
它和线上页面用的是同一份 map.js、同一份数据，所以看到的就是真实效果，
不是另画一张图。

瓦片仍然走 CDN（浏览器要联网），但即使瓦片加载不出来，
点也会画在深色底上——数据部分不依赖网络。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>攻击者地图 · 快照</title>
<style>
{leaflet_css}
</style>
<style>
{map_css}
</style>
</head>
<body class="map-body">

<header class="topbar">
  <div class="brand"><strong>攻击者地图</strong>
    <span class="badge badge-warn">离线快照</span>
  </div>
  <div class="topbar-right"><span class="muted">{generated}</span></div>
</header>

<div id="mapwrap">
  <div id="map"></div>

  <aside id="panel">
    <h1>观测概览</h1>
    <p class="sub" id="generated">加载中…</p>
    <div class="stats">
      <div class="stat"><b id="s-ips">–</b><span>来源 IP</span></div>
      <div class="stat"><b id="s-countries">–</b><span>国家/地区</span></div>
      <div class="stat"><b id="s-entries">–</b><span>日志条数</span></div>
    </div>
    <div class="legend">
      <div class="lg"><i class="dot bait"></i>站点特定诱饵 <b id="s-bait">0</b></div>
      <div class="lg"><i class="dot exploit"></i>尝试利用 <b id="s-exploit">0</b></div>
      <div class="lg"><i class="dot cloud"></i>云凭据探测 <b id="s-cloud">0</b></div>
      <div class="lg"><i class="dot scan"></i>扫描 / 探测 <b id="s-scan">0</b></div>
    </div>
    <h2>来源国家 / 地区</h2>
    <ol id="countries" class="countries"></ol>
    <p class="attr" id="attribution"></p>
  </aside>

  <aside id="detail" hidden>
    <button id="close-detail" aria-label="关闭">×</button>
    <h2 id="d-ip">–</h2>
    <p class="sub" id="d-loc">–</p>
    <dl>
      <dt>请求数</dt><dd id="d-n">–</dd>
      <dt>首次</dt><dd id="d-first">–</dd>
      <dt>最近</dt><dd id="d-last">–</dd>
      <dt>UA</dt><dd id="d-ua" class="mono">–</dd>
    </dl>
    <h3>访问过的路径</h3>
    <ul id="d-paths" class="paths"></ul>
  </aside>
</div>

<script>
{leaflet_js}
</script>
<script>
window.__MAP_DATA__ = {data};
</script>
<script>
{map_js}
</script>
</body>
</html>
"""


def read(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"缺少文件：{path}")
    return path.read_text(encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    data_path = ROOT / "data" / "map_points.json"
    out_path = ROOT / "reports" / "攻击者地图_快照.html"

    if not data_path.exists():
        print("缺少 data/map_points.json，先跑 tools/build_map_data.py", file=sys.stderr)
        return 1

    payload = json.loads(data_path.read_text(encoding="utf-8"))

    html = TEMPLATE.format(
        leaflet_css=read(ROOT / "static/vendor/leaflet/leaflet.css"),
        map_css=read(ROOT / "static/map.css"),
        leaflet_js=read(ROOT / "static/vendor/leaflet/leaflet.js"),
        map_js=read(ROOT / "static/map.js"),
        data=json.dumps(payload, ensure_ascii=False),
        generated=payload.get("generated_at", ""),
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    size_kb = out_path.stat().st_size / 1024
    print(f"已生成 {out_path}（{size_kb:.0f} KB）")
    print(f"数据：{payload['stats']['mapped']} 个点，"
          f"{payload['stats']['countries']} 个国家/地区")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
