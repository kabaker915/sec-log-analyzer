"""把 3D 地球页打成单文件快照（资源走 CDN）。

为什么快照用 CDN 而不是内联：
  globe.gl 1.1MB + 贴图 1.4MB，base64 内联后 HTML 接近 4MB，
  预览面板打开会很慢。生产环境仍然用本地 static/ 里的文件，
  快照只是给人看一眼效果。
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CDN = "https://unpkg.com/three-globe/example/img"

TEMPLATE = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>攻击者地球 · 快照</title>
<style>{app_css}</style>
<style>{globe_css}</style>
</head>
<body class="globe-body">

<header class="topbar">
  <div class="brand"><strong>攻击者地球</strong>
    <span class="badge badge-warn">离线快照</span></div>
  <div class="topbar-right"><span class="muted">{generated}</span></div>
</header>

<div id="stage">
  <div id="globe"></div>

  <aside id="panel">
    <h1>观测概览</h1>
    <p class="sub" id="generated">加载中…</p>
    <div class="stats">
      <div class="stat"><b id="s-ips">–</b><span>来源 IP</span></div>
      <div class="stat"><b id="s-countries">–</b><span>国家/地区</span></div>
      <div class="stat"><b id="s-window">–</b><span>窗口内来源</span></div>
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

  <div id="controls">
    <label class="ctl"><span>日期</span><input type="date" id="dt-date"></label>
    <label class="ctl"><span>窗口</span>
      <select id="dt-window">
        <option value="1">1 小时</option>
        <option value="6">6 小时</option>
        <option value="24" selected>24 小时</option>
        <option value="72">3 天</option>
        <option value="168">7 天</option>
      </select>
    </label>
    <button id="dt-play" type="button">播放</button>
    <label class="ctl ctl-check"><input type="checkbox" id="dt-spin" checked><span>自转</span></label>
    <label class="ctl ctl-check"><input type="checkbox" id="dt-arcs" checked><span>攻击线</span></label>
    <span id="dt-label" class="ctl-label">–</span>
  </div>

  <aside id="detail" hidden>
    <button id="close-detail" aria-label="关闭">×</button>
    <h2 id="d-title">–</h2>
    <p class="sub" id="d-loc">–</p>
    <dl>
      <dt>请求数</dt><dd id="d-n">–</dd>
      <dt>首次</dt><dd id="d-first">–</dd>
      <dt>最近</dt><dd id="d-last">–</dd>
    </dl>
    <h3>来源</h3>
    <ul id="d-list" class="src-list"></ul>
  </aside>
</div>

<script>window.__ASSET_BASE__ = "{cdn}";</script>
<script src="https://unpkg.com/globe.gl@2.32.3/dist/globe.gl.min.js"></script>
<script>window.__MAP_DATA__ = {data};</script>
<script>window.__PROVINCES__ = {provinces};</script>
<script>{globe_js}</script>
</body>
</html>
"""


def read(path: Path) -> str:
    if not path.exists():
        raise SystemExit(f"缺少文件：{path}")
    return path.read_text(encoding="utf-8")


def main() -> int:
    data_path = ROOT / "data" / "map_points.json"
    if not data_path.exists():
        print("缺少 data/map_points.json，先跑 tools/build_map_data.py", file=sys.stderr)
        return 1

    payload = json.loads(data_path.read_text(encoding="utf-8"))

    # 省界数据内联进快照：快照是本地打开的，取不到 /static 下的文件
    # 优先用精简版：完整版 568KB、25240 个顶点，快照里既大又卡
    geo_path = ROOT / "static" / "vendor" / "geo" / "china-provinces-lite.json"
    if not geo_path.exists():
        geo_path = ROOT / "static" / "vendor" / "geo" / "china-provinces.json"
    provinces = json.loads(geo_path.read_text(encoding="utf-8")) if geo_path.exists() else {"features": []}
    html = TEMPLATE.format(
        app_css=read(ROOT / "static/app.css"),
        globe_css=read(ROOT / "static/globe.css"),
        globe_js=read(ROOT / "static/globe.js"),
        data=json.dumps(payload, ensure_ascii=False),
        provinces=json.dumps(provinces, ensure_ascii=False),
        generated=payload.get("generated_at", ""),
        cdn=CDN,
    )

    out = ROOT / "reports" / "攻击者地球_快照.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    print(f"已生成 {out}（{out.stat().st_size / 1024:.0f} KB）")
    print(f"数据：{payload['stats']['mapped']} 个点")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
