/* 攻击者地球 —— 3D 可旋转，弧线表示攻击流向。
 *
 * 为什么从 2D 换 3D：
 *   2D 平面地图上，"攻击从哪来"只能靠连线长度判断，跨半球时线会穿过整个屏幕。
 *   3D 地球上弧线走大圆航线，方向和距离一眼能看出来。
 *
 * 用 globe.gl（three.js 封装）：
 *   - 内置 arcsData 的流动虚线动画，正好是攻击流向
 *   - ringsData 做目标点的心跳扩散
 *   - 自带 OrbitControls，拖拽旋转/滚轮缩放都是现成的
 *
 * 清晰度：
 *   贴图 4096×2048（earth-night），比 2D 反色瓦片清楚得多。
 *   再叠一张 topology 做凹凸，让山脉有立体感。
 */
(function () {
  "use strict";

  var ASSET = window.__ASSET_BASE__ || "/static/vendor/globe";
  var GEO = window.__GEO_BASE__ || "/static/vendor/geo";

  var COLORS = {
    bait: "#ff453a",
    exploit: "#ff9f0a",
    cloud: "#ffd60a",
    scan: "#5ab0ff"
  };

  // 被攻击的目标：服务器（广州）。地理库给 WGS-84，地球贴图也是 WGS-84，
  // 所以这里**不需要** GCJ-02 纠偏 —— 那是高德瓦片才有的问题。
  var TARGET = { lat: 23.1291, lng: 113.264 };

  var MAX_ARCS = 40;   // 60 条弧线 + 省界 + 点，中低端显卡会掉帧

  var el = function (id) { return document.getElementById(id); };

  var globe = Globe()(el("globe"))
    .globeImageUrl(ASSET + "/earth-night.jpg")
    .bumpImageUrl(ASSET + "/earth-topology.png")
    .backgroundColor("rgba(0,0,0,0)")
    // 大气层原本是 #3a86ff / 0.18，配夜色贴图时整颗球泛蓝，
    // 看起来像"地球全蓝"。压到 0.08 并调暗，只留边缘一圈冷光。
    .atmosphereColor("#1d4f7a")
    .atmosphereAltitude(0.08)
    .showGraticules(false);

  // 清晰度：默认 renderer 用 devicePixelRatio，但在高分屏上会被浏览器
  // 限制到 1；手动设到 2，贴图 4096×2048 的细节才真正显现出来。
  // 上限压 2 是因为 3x 屏上 4 倍像素量对 GPU 太重，收益却看不出来。
  (function sharpen() {
    var r = globe.renderer();
    // 2 在 4K 屏上像素量是 1 的 4 倍，配 339 个省界网格直接掉帧。
    // 1.5 是清晰度和帧率的折中，肉眼几乎看不出差别。
    r.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5));
    // bumpScale 默认 10，山脉起伏很平；调到 25 才有"球体"的立体感
    var m = globe.globeMaterial();
    if (m) {
      m.bumpScale = 25;
      m.shininess = 6;
    }
  })();

  // 中国省级边界。
  //
  // 数据来源：阿里云 DataV 的国标行政区划（geo.datav.aliyun.com），
  // 35 个要素 = 34 个省级行政区 + adcode 100000_JD（南海诸岛/九段线）。
  // 明确包含"台湾省"，符合国家标准的表述。
  //
  // 为什么不画其它国家的国界：世界国界涉及政治边界，
  // 用境外数据集（Natural Earth 之类）很容易在阿克赛钦、藏南、
  // 南海等问题上画错。宁可只画中国省级边界 + 全球海岸线，
  // 也不画一张边界有争议的世界地图。
  var provincesLayer = function (features) {
    globe
      .polygonsData(features)
      .polygonAltitude(0.005)
      // 不填色。只画描边有两个原因：
      //   1. 填色会盖住贴图上的城市灯光，"清晰度"反而下降
      //   2. 九段线那种极细的多边形一旦三角化，容易生成一大片面，
      //      把整个球面染成蓝色（这就是"地球全蓝"的一个来源）
      .polygonCapColor(function () { return "rgba(0,0,0,0)"; })
      .polygonSideColor(function () { return "rgba(0,0,0,0)"; })
      .polygonStrokeColor(function () { return "rgba(122,203,255,0.6)"; })
      .polygonsTransitionDuration(0);
  };

  // 离线快照会把省界数据直接内联到 __PROVINCES__，
  // 因为快照是从本地文件打开的，相对路径取不到 static/ 下的数据。
  if (window.__PROVINCES__ && window.__PROVINCES__.features) {
    provincesLayer(window.__PROVINCES__.features);
  } else {
    fetch(GEO + "/china-provinces-lite.json")
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (gj) {
        if (gj && gj.features) provincesLayer(gj.features);
      })
      .catch(function () { /* 边界加载失败不影响主图 */ });
  }

  // 点：柱状，高度代表请求数
  globe
    .pointLat("lat")
    .pointLng("lng")
    .pointColor("color")
    .pointAltitude("alt")
    .pointRadius("radius")
    .pointLabel("label")
    .pointsMerge(false)
    .onPointClick(function (p) { showDetail(p.src); });

  // 攻击弧线：从来源到目标，红色流动虚线
  globe
    .arcStartLat("sLat").arcStartLng("sLng")
    .arcEndLat("eLat").arcEndLng("eLng")
    .arcColor(function () { return ["rgba(255,69,58,0.05)", "rgba(255,69,58,0.85)"]; })
    .arcStroke(0.42)
    .arcAltitudeAutoScale(0.35)
    .arcDashLength(0.32)
    .arcDashGap(0.22)
    .arcDashInitialGap(function () { return Math.random(); })
    .arcDashAnimateTime(2200);

  // 目标点心跳
  globe
    .ringsData([{ lat: TARGET.lat, lng: TARGET.lng }])
    .ringColor(function () { return function (t) { return "rgba(255,69,58," + (1 - t) + ")"; }; })
    .ringMaxRadius(4)
    .ringPropagationSpeed(2.2)
    .ringRepeatPeriod(1100);

  // 控制
  var controls = globe.controls();
  controls.autoRotate = true;
  controls.autoRotateSpeed = 0.35;
  controls.enableDamping = true;
  controls.dampingFactor = 0.12;
  controls.minDistance = 160;
  controls.maxDistance = 620;

  // 高度跟着容器走，窗口变了要重设，否则地球会被裁掉
  function resize() {
    var stage = el("stage");
    globe.width(stage.clientWidth).height(stage.clientHeight);
  }
  window.addEventListener("resize", resize);

  // ------------------------------------------------------------ 状态
  var points = [];
  var hours = [];
  var hourIndex = {};
  var windowStart = 0;
  var windowSize = 24;
  var playing = false;
  var playTimer = null;
  var showArcs = true;

  function countInWindow(h, start, size) {
    var end = start + size;
    var sum = 0;
    for (var k in h) {
      if (!h.hasOwnProperty(k)) continue;
      var i = +k;
      if (i >= start && i < end) sum += h[k];
    }
    return sum;
  }

  function fmtHour(iso) {
    if (!iso) return "–";
    return iso.replace("T", " ") + ":00";
  }

  /** 同一坐标聚成一个点：地理库只有城市级精度，不合并会重叠成一坨。 */
  function buildClusters(pts) {
    var buckets = {}, order = [];
    pts.forEach(function (p) {
      var key = p.lat.toFixed(3) + "," + p.lon.toFixed(3);
      var c = buckets[key];
      if (!c) {
        c = buckets[key] = {
          lat: p.lat, lng: p.lon, n: 0, h: {},
          members: [], cat: "scan",
          country: p.country, city: p.city,
          first: p.first, last: p.last
        };
        order.push(c);
      }
      c.n += p.n;
      c.members.push(p);
      for (var k in p.h) {
        if (p.h.hasOwnProperty(k)) c.h[k] = (c.h[k] || 0) + p.h[k];
      }
      if (p.cat === "bait") c.cat = "bait";
      else if (p.cat === "exploit" && c.cat !== "bait") c.cat = "exploit";
      else if (p.cat === "cloud" && c.cat === "scan") c.cat = "cloud";
      if (p.first && (!c.first || p.first < c.first)) c.first = p.first;
      if (p.last && (!c.last || p.last > c.last)) c.last = p.last;
    });
    return order;
  }

  var clusters = [];

  // ------------------------------------------------------------ 渲染
  function render() {
    var visible = [], arcs = [];
    var byCat = { bait: 0, exploit: 0, cloud: 0, scan: 0 };
    var sum = 0;

    clusters.forEach(function (c) {
      var n = countInWindow(c.h, windowStart, windowSize);
      if (n <= 0) return;
      visible.push(c);
      sum += n;
      byCat[c.cat] = (byCat[c.cat] || 0) + 1;

      if (visible.length <= MAX_ARCS) {
        arcs.push({
          sLat: c.lat, sLng: c.lng,
          eLat: TARGET.lat, eLng: TARGET.lng
        });
      }
    });

    // 按窗口内请求数降序，点的大小和高低才有意义
    visible.sort(function (a, b) {
      return countInWindow(b.h, windowStart, windowSize) -
             countInWindow(a.h, windowStart, windowSize);
    });

    var maxN = 1;
    visible.forEach(function (c) {
      var n = countInWindow(c.h, windowStart, windowSize);
      if (n > maxN) maxN = n;
    });

    var pts = visible.map(function (c) {
      var n = countInWindow(c.h, windowStart, windowSize);
      var ratio = Math.log2(n + 1) / Math.log2(maxN + 1);
      var isCluster = c.members.length > 1;
      return {
        lat: c.lat, lng: c.lng,
        color: COLORS[c.cat] || COLORS.scan,
        // 高度 0.01–0.28：太高会挡住地球，太矮看不出差别
        alt: 0.012 + ratio * 0.27,
        radius: 0.18 + ratio * 0.42,
        label: isCluster
          ? (c.city || c.country || "?") + " · " + c.members.length + " 个来源 · " + n + " 次"
          : c.members[0].ip + " · " + n + " 次",
        src: c
      };
    });

    globe.pointsData(pts);
    globe.arcsData(showArcs ? arcs : []);

    el("s-window").textContent = visible.length;
    el("s-bait").textContent = byCat.bait;
    el("s-exploit").textContent = byCat.exploit;
    el("s-cloud").textContent = byCat.cloud;
    el("s-scan").textContent = byCat.scan;

    var a = hours[windowStart] || "";
    var bIdx = Math.min(hours.length - 1, windowStart + windowSize - 1);
    el("dt-label").textContent = fmtHour(a) +
      (windowSize > 1 ? "  →  " + fmtHour(hours[bIdx] || "") : "");

    // 日期框跟着窗口起点走，避免"选了日期但显示的是别的天"
    var dateInput = el("dt-date");
    if (dateInput && a) dateInput.value = a.slice(0, 10);
  }

  // ------------------------------------------------------------ 交互
  function moveTo(idx, animate) {
    var maxStart = Math.max(0, hours.length - windowSize);
    windowStart = Math.max(0, Math.min(idx, maxStart));
    render();
  }

  function dayStartIndex(day) {
    // 当天第一个小时；如果那天空白，就取之后最近的有数据的小时
    for (var i = 0; i < hours.length; i++) {
      if (hours[i].slice(0, 10) >= day) return i;
    }
    return Math.max(0, hours.length - windowSize);
  }

  function showDetail(c) {
    var members = c.members || [];
    el("d-title").textContent = members.length === 1
      ? members[0].ip
      : members.length + " 个来源";
    el("d-loc").textContent =
      ([c.country, c.city].filter(Boolean).join(" · ") || "未知") + "（城市级定位）";
    el("d-n").textContent =
      countInWindow(c.h, windowStart, windowSize) + " 次（窗口内）/ 共 " + c.n + " 次";
    el("d-first").textContent = (c.first || "").replace("T", " ").slice(0, 16);
    el("d-last").textContent = (c.last || "").replace("T", " ").slice(0, 16);

    var ul = el("d-list");
    ul.textContent = "";
    members.slice().sort(function (a, b) { return b.n - a.n; }).slice(0, 8)
      .forEach(function (m) {
        var li = document.createElement("li");
        li.textContent = m.ip + "  ·  " + m.n + " 次";
        ul.appendChild(li);
      });
    el("detail").hidden = false;
  }

  function startPlay() {
    if (playing) return;
    playing = true;
    el("dt-play").textContent = "暂停";
    el("dt-play").classList.add("on");
    playTimer = setInterval(function () {
      var maxStart = Math.max(0, hours.length - windowSize);
      if (windowStart >= maxStart) { stopPlay(); return; }
      moveTo(windowStart + 1, true);
    }, 620);
  }

  function stopPlay() {
    playing = false;
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
    el("dt-play").textContent = "播放";
    el("dt-play").classList.remove("on");
  }

  el("dt-play").addEventListener("click", function () {
    if (playing) stopPlay(); else startPlay();
  });

  el("dt-window").addEventListener("change", function (e) {
    windowSize = parseInt(e.target.value, 10) || 24;
    moveTo(windowStart, true);
  });

  el("dt-date").addEventListener("change", function (e) {
    stopPlay();
    var day = e.target.value;
    if (!day) return;
    moveTo(dayStartIndex(day), true);
  });

  el("dt-spin").addEventListener("change", function (e) {
    controls.autoRotate = e.target.checked;
  });

  el("dt-arcs").addEventListener("change", function (e) {
    showArcs = e.target.checked;
    render();
  });

  el("close-detail").addEventListener("click", function () {
    el("detail").hidden = true;
  });

  // ------------------------------------------------------------ 启动
  function boot(data) {
    points = data.points || [];
    hours = data.hours || [];
    windowSize = Math.min(24, Math.max(1, hours.length));
    windowStart = Math.max(0, hours.length - windowSize);

    // 日期框的上下限
    var di = el("dt-date");
    if (di && hours.length) {
      di.min = hours[0].slice(0, 10);
      di.max = hours[hours.length - 1].slice(0, 10);
    }

    clusters = buildClusters(points);
    resize();
    render();

    var s = data.stats || {};
    el("s-ips").textContent = s.ips || 0;
    el("s-countries").textContent = s.countries || 0;
    el("generated").textContent =
      "生成于 " + (data.generated_at || "–") + " · " + (s.files || 0) + " 个日志文件";
    el("attribution").textContent = (data.attribution || "") +
      " · 地球贴图 NASA Blue Marble / Earth at Night";

    var ol = el("countries");
    ol.textContent = "";
    (s.top_countries || []).forEach(function (row) {
      var li = document.createElement("li");
      li.textContent = row[0] || "未知";
      var span = document.createElement("span");
      span.textContent = row[1];
      li.appendChild(span);
      ol.appendChild(li);
    });

    // 缓缓转到目标位置，作为开场
    globe.pointOfView({ lat: TARGET.lat, lng: TARGET.lng, altitude: 2.6 }, 1600);
  }

  var ready = window.__MAP_DATA__
    ? Promise.resolve(window.__MAP_DATA__)
    : fetch("/api/map/points", { credentials: "same-origin" })
        .then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        });

  ready.then(boot).catch(function (err) {
    el("generated").textContent = "加载失败：" + err.message;
  });
})();
