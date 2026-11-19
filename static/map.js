/* 攻击者地图：时间轴回放 + 流式显示。
 *
 * 底图换成了高德。
 * 原因：CartoDB 和 OSM 在国内基本连不上（实测 8 秒超时），
 * 表现就是"地图一片黑，只有点"——所以之前看起来像坏了。
 * 高德 webrd 瓦片 0.3 秒响应，配一层 CSS 反色滤镜做成深色。
 *
 * 注意坐标系：高德是 GCJ-02，我们的点是 WGS-84，
 * 理论上差几百米。这张图看的是国家/城市级分布（zoom 2–9），
 * 几百米在这个尺度上不到一个像素，可以忽略。
 * 如果以后要做到街道级，必须做坐标纠偏。
 *
 * 流畅度的三个前提：
 *   1. 标记只创建一次（不 clearLayers 重建）
 *   2. canvas 渲染（679 个 SVG 改样式要重排）
 *   3. rAF 手写补间（canvas 没有 DOM 节点，CSS transition 无效）
 */
(function () {
  "use strict";

  var COLORS = {
    bait: "#ff453a",
    exploit: "#ff9f0a",
    cloud: "#ffd60a",
    scan: "#5ab0ff"
  };

  var TWEEN_MS = 240;
  var FLASH_MS = 700;

  // 连线总数上限：绝大多数攻击者只扫一次，全画出来会盖住那几个高频来源
  var MAX_LINES = 120;
  // 画流光拖尾的条数上限。每条要 8 次 stroke，全画每帧 960 次描边会掉帧。
  // 底弧仍然全画，所以"有 120 条线"这个信息不丢。
  var MAX_STREAKS = 48;

  /* ---------------------------------------------------------------- 坐标系纠偏
   *
   * 我们的日志 IP 地理库给的是 WGS-84（国际标准）。
   * 高德瓦片用的是 GCJ-02（国测局加密坐标），两者在国内差 300–800 米。
   *
   * 之前我判断"看国家/城市级分布，几百米不到一个像素，可以忽略"——
   * 这个判断在 zoom 3 成立，但用户一放大就露馅了：点会整体偏到隔壁街区，
   * 缩放越大偏得越明显。**缩放不精准就是这个问题，不是渲染 bug。**
   *
   * 所以必须把点转到 GCJ-02 再投影，让点和底图用同一套坐标。
   * 这是标准的 eviltransform 算法，纯数学，无依赖。
   */
  var PI = 3.1415926535897932384626;
  var AXIS = 6378245.0;
  var EE = 0.00669342162296594323;

  function outOfChina(lat, lon) {
    return lon < 72.004 || lon > 137.8347 || lat < 0.8293 || lat > 55.8271;
  }

  function transformLat(x, y) {
    var ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * Math.sqrt(Math.abs(x));
    ret += (20.0 * Math.sin(6.0 * x * PI) + 20.0 * Math.sin(2.0 * x * PI)) * 2.0 / 3.0;
    ret += (20.0 * Math.sin(y * PI) + 40.0 * Math.sin(y / 3.0 * PI)) * 2.0 / 3.0;
    ret += (160.0 * Math.sin(y / 12.0 * PI) + 320 * Math.sin(y * PI / 30.0)) * 2.0 / 3.0;
    return ret;
  }

  function transformLon(x, y) {
    var ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * Math.sqrt(Math.abs(x));
    ret += (20.0 * Math.sin(6.0 * x * PI) + 20.0 * Math.sin(2.0 * x * PI)) * 2.0 / 3.0;
    ret += (20.0 * Math.sin(x * PI) + 40.0 * Math.sin(x / 3.0 * PI)) * 2.0 / 3.0;
    ret += (150.0 * Math.sin(x / 12.0 * PI) + 300.0 * Math.sin(x / 30.0 * PI)) * 2.0 / 3.0;
    return ret;
  }

  /** WGS-84 → GCJ-02。国外坐标原样返回（高德在境外也用 WGS-84）。 */
  function toGcj02(lat, lon) {
    if (outOfChina(lat, lon)) return [lat, lon];
    var dLat = transformLat(lon - 105.0, lat - 35.0);
    var dLon = transformLon(lon - 105.0, lat - 35.0);
    var radLat = lat / 180.0 * PI;
    var magic = Math.sin(radLat);
    magic = 1 - EE * magic * magic;
    var sqrtMagic = Math.sqrt(magic);
    dLat = (dLat * 180.0) / ((AXIS * (1 - EE)) / (magic * sqrtMagic) * PI);
    dLon = (dLon * 180.0) / (AXIS / sqrtMagic * Math.cos(radLat) * PI);
    return [lat + dLat, lon + dLon];
  }

  var map = L.map("map", {
    worldCopyJump: true,
    minZoom: 2,
    maxZoom: 9,
    zoomControl: false,
    preferCanvas: true,
    attributionControl: true
  }).setView([24, 60], 3);

  L.control.zoom({ position: "bottomright" }).addTo(map);

  L.tileLayer(
    "https://webrd0{s}.is.autonavi.com/appmaptile?lang=zh_cn&size=1&scale=1&style=8&x={x}&y={y}&z={z}",
    {
      subdomains: ["1", "2", "3", "4"],
      maxZoom: 18,
      attribution: "&copy; 高德地图"
    }
  ).addTo(map);

  var canvas = L.canvas({ padding: 0.4 });
  var layer = L.layerGroup().addTo(map);

  // 被攻击的目标：服务器所在位置（广州）
  var TARGET_RAW = [23.1291, 113.264];            // 广州，WGS-84
  var TARGET_GCJ = toGcj02(TARGET_RAW[0], TARGET_RAW[1]);
  var TARGET = { lat: TARGET_GCJ[0], lon: TARGET_GCJ[1] };

  map.createPane("attackPane");
  map.getPane("attackPane").style.zIndex = 450;
  map.getPane("attackPane").style.pointerEvents = "none";

  /**
   * 攻击连线层。
   *
   * 为什么自己画 canvas，不用 L.polyline：
   *   100 多条曲线 + 每条一个流动光点，用 polyline 就是 100+ 个 Leaflet 图层，
   *   每帧改属性会触发大量重排。自己在一个 canvas 上画，一帧就是一次 clearRect
   *   加 N 条贝塞尔曲线，稳定 60fps。
   *
   * 曲线而不是直线：直线会在地图上形成一团从中心散开的"刺"，
   * 视觉上分不清哪条对哪条。二次贝塞尔带一点弧度，线之间不会重叠。
   */
  var AttackLayer = L.Layer.extend({
    initialize: function () {
      this._attacks = [];
      this._t0 = performance.now();
      this._raf = null;
    },

    onAdd: function (m) {
      this._map = m;
      var c = this._canvas = L.DomUtil.create("canvas", "attack-canvas");
      c.style.position = "absolute";
      c.style.left = "0";
      c.style.top = "0";
      m.getPane("attackPane").appendChild(c);
      m.on("move zoom resize viewreset", this._reset, this);
      this._reset();
      this._loop();
    },

    onRemove: function (m) {
      if (this._raf) cancelAnimationFrame(this._raf);
      m.off("move zoom resize viewreset", this._reset, this);
      L.DomUtil.remove(this._canvas);
    },

    _reset: function () {
      var size = this._map.getSize();
      var dpr = window.devicePixelRatio || 1;
      this._canvas.width = Math.round(size.x * dpr);
      this._canvas.height = Math.round(size.y * dpr);
      this._canvas.style.width = size.x + "px";
      this._canvas.style.height = size.y + "px";
      this._ctx = this._canvas.getContext("2d");
      this._ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      this._w = size.x;
      this._h = size.y;
    },

    setAttacks: function (list) {
      this._attacks = list;
    },

    setVisible: function (on) {
      this._visible = on;
      if (!on && this._ctx) this._ctx.clearRect(0, 0, this._w, this._h);
    },

    _loop: function () {
      var self = this;
      function frame(ts) {
        self._draw(ts);
        self._raf = requestAnimationFrame(frame);
      }
      this._raf = requestAnimationFrame(frame);
    },

    _draw: function (ts) {
      var ctx = this._ctx;
      if (!ctx) return;
      ctx.clearRect(0, 0, this._w, this._h);
      if (this._visible === false) return;

      var mp = this._map;
      var T = mp.latLngToContainerPoint([TARGET.lat, TARGET.lon]);
      var self = this;

      // 目标位置的脉冲环：三圈错开相位，看起来像"心跳"
      var beat = ((ts - this._t0) % 2600) / 2600;
      for (var r = 0; r < 3; r++) {
        var ph = (beat + r / 3) % 1;
        var rad = 6 + ph * 34;
        ctx.beginPath();
        ctx.arc(T.x, T.y, rad, 0, Math.PI * 2);
        ctx.strokeStyle = "rgba(255,69,58," + (0.34 * (1 - ph)) + ")";
        ctx.lineWidth = 1.6;
        ctx.stroke();
      }
      ctx.beginPath();
      ctx.arc(T.x, T.y, 4.5, 0, Math.PI * 2);
      ctx.fillStyle = "#ff453a";
      ctx.fill();
      ctx.beginPath();
      ctx.arc(T.x, T.y, 9, 0, Math.PI * 2);
      ctx.strokeStyle = "rgba(255,69,58,.55)";
      ctx.lineWidth = 1;
      ctx.stroke();

      var n = this._attacks.length;
      for (var i = 0; i < n; i++) {
        var a = this._attacks[i];
        var P = mp.latLngToContainerPoint([a.lat, a.lon]);

        // 控制点：中点朝垂直方向偏移，偏移量随距离增大，
        // 让长线和短线都有弧度但都不夸张
        var mx = (P.x + T.x) / 2;
        var my = (P.y + T.y) / 2;
        var dx = T.x - P.x;
        var dy = T.y - P.y;
        var len = Math.sqrt(dx * dx + dy * dy) || 1;
        var bend = Math.min(90, len * 0.22);
        var cx = mx - (dy / len) * bend;
        var cy = my + (dx / len) * bend;

        // 轨迹统一红色：颜色已经用点区分了种类，
        // 线再分色只会让图变成调色板。红色 = 攻击流。
        var RED = "255,69,58";

        // 底弧：很淡，只用来交代"这条线存在"
        ctx.beginPath();
        ctx.moveTo(P.x, P.y);
        ctx.quadraticCurveTo(cx, cy, T.x, T.y);
        ctx.strokeStyle = "rgba(" + RED + ",0.10)";
        ctx.lineWidth = 1;
        ctx.stroke();

        // 流光：只给前 MAX_STREAKS 条画，否则每帧上千次 stroke
        if (i >= MAX_STREAKS) continue;

        var period = 2600;
        var phase = ((ts - this._t0) / period + a.seed) % 1;

        // 进出两头淡入淡出，避免光带在起点"凭空出现"
        var fade = Math.min(1, Math.min(phase, 1 - phase) * 6);

        var SEG = 8;
        var TAIL = 0.17;          // 拖尾长度占曲线比例
        var step = TAIL / SEG;

        for (var s2 = 0; s2 < SEG; s2++) {
          var t1 = phase - s2 * step;
          var t2 = phase - (s2 + 1) * step;
          if (t2 < 0 || t1 > 1) continue;
          if (t1 > 1) t1 = 1;
          if (t2 < 0) t2 = 0;

          var i1 = 1 - t1, i2 = 1 - t2;
          var x1 = i1 * i1 * P.x + 2 * i1 * t1 * cx + t1 * t1 * T.x;
          var y1 = i1 * i1 * P.y + 2 * i1 * t1 * cy + t1 * t1 * T.y;
          var x2 = i2 * i2 * P.x + 2 * i2 * t2 * cx + t2 * t2 * T.x;
          var y2 = i2 * i2 * P.y + 2 * i2 * t2 * cy + t2 * t2 * T.y;

          // 头亮尾暗、头粗尾细 —— 这就是"流光"和"一条线"的区别
          var k = 1 - s2 / SEG;
          ctx.beginPath();
          ctx.moveTo(x1, y1);
          ctx.lineTo(x2, y2);
          ctx.strokeStyle = "rgba(" + RED + "," + (0.85 * k * k * fade) + ")";
          ctx.lineWidth = 0.6 + 2.6 * k;
          ctx.lineCap = "round";
          ctx.stroke();
        }

        // 光点头部：一团红色辉光，不用实心圆
        var ih = 1 - phase;
        var hx = ih * ih * P.x + 2 * ih * phase * cx + phase * phase * T.x;
        var hy = ih * ih * P.y + 2 * ih * phase * cy + phase * phase * T.y;
        var hg = ctx.createRadialGradient(hx, hy, 0, hx, hy, 9);
        hg.addColorStop(0, "rgba(255,120,110," + (0.95 * fade) + ")");
        hg.addColorStop(0.35, "rgba(" + RED + "," + (0.55 * fade) + ")");
        hg.addColorStop(1, "rgba(" + RED + ",0)");
        ctx.beginPath();
        ctx.fillStyle = hg;
        ctx.arc(hx, hy, 9, 0, Math.PI * 2);
        ctx.fill();

      }
    },

    /** 把 #rrggbb 转成带透明度的 rgba，避免每帧拼字符串出错。 */
    _rgb: function (hex, alpha) {
      var h = hex.replace("#", "");
      var r = parseInt(h.substring(0, 2), 16);
      var g = parseInt(h.substring(2, 4), 16);
      var b = parseInt(h.substring(4, 6), 16);
      return "rgba(" + r + "," + g + "," + b + "," + alpha + ")";
    }
  });

  var attackLayer = new AttackLayer();

  var points = [];
  var hours = [];
  var markers = [];
  var windowStart = 0;
  var windowSize = 24;
  var playing = false;
  var playTimer = null;
  var streamMode = false;      // 流式：窗口 1 小时 + 新点闪烁

  // ------------------------------------------------------------ 工具
  function radiusFor(n) {
    return n <= 0 ? 0 : 3.2 + Math.log2(n + 1) * 2.1;
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;")
      .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
  }

  function fmtHour(iso) {
    if (!iso) return "–";
    return iso.replace("T", " ") + ":00";
  }

  function fmtDay(iso) {
    if (!iso) return "–";
    return iso.slice(5, 10);   // MM-DD
  }

  function countInWindow(p, start, size) {
    var end = start + size;
    var sum = 0;
    for (var k in p.h) {
      if (!Object.prototype.hasOwnProperty.call(p.h, k)) continue;
      var i = +k;
      if (i >= start && i < end) sum += p.h[k];
    }
    return sum;
  }

  // ------------------------------------------------------------ 建点（只做一次）
  function buildMarkers() {
    layer.clearLayers();
    markers = [];

    points.forEach(function (p) {
      var color = COLORS[p.cat] || COLORS.scan;
      // 纠偏后再投影，否则放大后点会整体偏几百米
      var g = toGcj02(p.lat, p.lon);
      p.glat = g[0];
      p.glon = g[1];
      var m = L.circleMarker([p.glat, p.glon], {
        renderer: canvas,
        radius: 0,
        color: color,
        weight: p.cat === "bait" ? 2 : 1.4,
        opacity: 0,
        fillColor: color,
        fillOpacity: 0
      });

      m.bindTooltip(function () {
        var n = countInWindow(p, windowStart, windowSize);
        return "<b>" + escapeHtml(p.ip) + "</b><br>" +
               escapeHtml((p.country || "?") + (p.city ? " · " + p.city : "")) +
               "<br>窗口内 " + n + " 次 / 共 " + p.n + " 次";
      }, { className: "ip-tip", direction: "top", offset: [0, -2] });

      m.on("click", function () { showDetail(p); });
      m.addTo(layer);

      markers.push({
        marker: m, p: p,
        curR: 0, curO: 0, tgtR: 0, tgtO: 0,
        flash: 0          // 1 → 0 衰减，流式模式下让新出现的点"亮一下"
      });
    });
  }

  // ------------------------------------------------------------ 动画循环
  var rafId = null;
  var tweenFrom = 0;
  var tweening = false;

  function kick() {
    if (rafId === null) {
      tweenFrom = performance.now();
      rafId = requestAnimationFrame(tick);
    }
  }

  function tick(now) {
    var t = Math.min(1, (now - tweenFrom) / TWEEN_MS);
    var e = 1 - Math.pow(1 - t, 3);      // easeOutCubic
    var anyFlash = false;
    var i, it;

    for (i = 0; i < markers.length; i++) {
      it = markers[i];

      var r = it.curR + (it.tgtR - it.curR) * e;
      var o = it.curO + (it.tgtO - it.curO) * e;

      if (it.flash > 0) {
        // 闪烁：额外撑大一圈再收回，视觉上像"刚打过来"
        r += it.flash * 9;
        o = Math.min(1, o + it.flash * 0.5);
        anyFlash = true;
      }

      it.marker.setRadius(r);
      it.marker.setStyle({
        opacity: o > 0 ? Math.min(1, o * 1.25) : 0,
        fillOpacity: o
      });
    }

    if (t < 1) {
      rafId = requestAnimationFrame(tick);
      return;
    }

    // 补间收尾：对齐目标值，避免累积误差让点慢慢漂
    for (i = 0; i < markers.length; i++) {
      it = markers[i];
      it.curR = it.tgtR;
      it.curO = it.tgtO;
      it.marker.setRadius(it.tgtR + it.flash * 9);
      it.marker.setStyle({
        opacity: it.tgtO > 0 ? Math.min(1, it.tgtO * 1.25 + it.flash * 0.5) : it.flash * 0.5,
        fillOpacity: it.tgtO + it.flash * 0.5
      });
    }

    if (anyFlash) {
      // 闪烁还没走完，继续下一帧
      rafId = requestAnimationFrame(flashTick);
    } else {
      rafId = null;
      tweening = false;
    }
  }

  function flashTick() {
    var alive = false;
    for (var i = 0; i < markers.length; i++) {
      var it = markers[i];
      if (it.flash <= 0) continue;
      it.flash -= 16 / FLASH_MS;        // 约 60fps 下的衰减步长
      if (it.flash < 0) it.flash = 0;
      alive = true;

      it.marker.setRadius(it.tgtR + it.flash * 9);
      it.marker.setStyle({
        opacity: it.tgtO > 0 ? Math.min(1, it.tgtO * 1.25 + it.flash * 0.5) : it.flash * 0.5,
        fillOpacity: Math.min(1, it.tgtO + it.flash * 0.5)
      });
    }
    if (alive) {
      rafId = requestAnimationFrame(flashTick);
    } else {
      rafId = null;
    }
  }

  // ------------------------------------------------------------ 应用窗口
  function applyWindow(animate, flashNew) {
    var visible = 0, sum = 0;
    var byCat = { bait: 0, exploit: 0, cloud: 0, scan: 0 };

    for (var i = 0; i < markers.length; i++) {
      var it = markers[i];
      var n = countInWindow(it.p, windowStart, windowSize);
      var wasVisible = it.tgtR > 0;

      if (n > 0) {
        visible += 1;
        sum += n;
        byCat[it.p.cat] = (byCat[it.p.cat] || 0) + 1;
        it.tgtR = radiusFor(n);
        // 提亮了：之前 0.38 在深色底图上几乎看不见，这就是"显示有问题"的一半
        it.tgtO = it.p.cat === "bait" ? 0.85 : 0.62;
        if (flashNew && !wasVisible) it.flash = 1;
      } else {
        it.tgtR = 0;
        it.tgtO = 0;
      }
    }

    if (animate) {
      kick();
    } else {
      for (var j = 0; j < markers.length; j++) {
        var m = markers[j];
        m.curR = m.tgtR;
        m.curO = m.tgtO;
        m.marker.setRadius(m.tgtR);
        m.marker.setStyle({
          opacity: m.tgtO > 0 ? Math.min(1, m.tgtO * 1.25) : 0,
          fillOpacity: m.tgtO
        });
      }
    }

    updateLabels(visible, sum, byCat);
    highlightDate();
    updateAttacks();
  }

  /**
   * 给连线层喂数据。
   *
   * 上限 120 条：线多了会糊成一团，而且攻击者里绝大多数是单次扫描，
   * 把它们全画出来只会掩盖那几个真正高频的来源。
   * 按窗口内请求数排序，只画最猛的那些。
   */

  function updateAttacks() {
    if (!attackLayer) return;
    var list = [];
    for (var i = 0; i < markers.length; i++) {
      var it = markers[i];
      if (it.tgtR > 0) {
        list.push({ lat: it.p.glat, lon: it.p.glon, cat: it.p.cat, n: it.p.n });
      }
    }
    list.sort(function (a, b) { return b.n - a.n; });
    var top = list.slice(0, MAX_LINES);
    // 每条线一个固定的随机相位，否则所有光点齐步走
    for (var k = 0; k < top.length; k++) {
      top[k].seed = (k * 0.1373) % 1;
    }
    attackLayer.setAttacks(top);
  }

  function updateLabels(visible, sum, byCat) {
    var label = document.getElementById("tl-label");
    if (label && hours.length) {
      var a = hours[windowStart] || "";
      var bIdx = Math.min(hours.length - 1, windowStart + windowSize - 1);
      label.textContent = fmtHour(a) + (windowSize > 1 ? "  →  " + fmtHour(hours[bIdx] || "") : "");
    }
    var wc = document.getElementById("tl-window-count");
    if (wc) wc.textContent = visible + " 个来源 · " + sum + " 次请求";

    var ids = { "s-bait": "bait", "s-exploit": "exploit", "s-cloud": "cloud", "s-scan": "scan" };
    for (var id in ids) {
      if (!ids.hasOwnProperty(id)) continue;
      var el = document.getElementById(id);
      if (el) el.textContent = byCat[ids[id]] || 0;
    }
  }

  // ------------------------------------------------------------ 日期快捷
  function buildDateChips() {
    var box = document.getElementById("tl-dates");
    if (!box || !hours.length) return;

    // 每天取第一个小时的序号，点一下直接跳过去
    var firstOfDay = {};
    hours.forEach(function (h, i) {
      var d = h.slice(0, 10);
      if (firstOfDay[d] === undefined) firstOfDay[d] = i;
    });

    var frag = document.createDocumentFragment();
    Object.keys(firstOfDay).sort().forEach(function (d) {
      var b = document.createElement("button");
      b.type = "button";
      b.textContent = fmtDay(d);
      b.dataset.day = d;
      b.addEventListener("click", function () {
        stopPlay();
        windowStart = firstOfDay[d];
        var maxStart = Math.max(0, hours.length - windowSize);
        if (windowStart > maxStart) windowStart = maxStart;
        var slider = document.getElementById("tl-slider");
        if (slider) slider.value = String(windowStart);
        applyWindow(true, false);
      });
      frag.appendChild(b);
    });
    box.appendChild(frag);
  }

  function highlightDate() {
    var box = document.getElementById("tl-dates");
    if (!box || !hours.length) return;
    var cur = (hours[windowStart] || "").slice(0, 10);
    var btns = box.querySelectorAll("button");
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle("on", btns[i].dataset.day === cur);
    }
  }

  // ------------------------------------------------------------ 时间轴
  function buildTimeline() {
    var slider = document.getElementById("tl-slider");
    if (!slider) return;

    slider.max = String(Math.max(0, hours.length - 1));
    slider.value = String(windowStart);
    slider.addEventListener("input", function () {
      windowStart = parseInt(slider.value, 10) || 0;
      applyWindow(true, streamMode);
    });

    // 直方图：每小时请求总量。没有它，滑块拖到哪都是盲猜
    var hist = document.getElementById("tl-hist");
    var totals = new Array(hours.length);
    var i;
    for (i = 0; i < hours.length; i++) totals[i] = 0;
    points.forEach(function (p) {
      for (var k in p.h) {
        if (p.h.hasOwnProperty(k)) totals[+k] += p.h[k];
      }
    });

    var peak = 1;
    for (i = 0; i < totals.length; i++) if (totals[i] > peak) peak = totals[i];

    var frag = document.createDocumentFragment();
    totals.forEach(function (v) {
      var bar = document.createElement("i");
      bar.style.height = Math.max(4, Math.round((v / peak) * 100)) + "%";
      bar.title = v + " 次";
      frag.appendChild(bar);
    });
    hist.appendChild(frag);

    var winSel = document.getElementById("tl-win");
    if (winSel) {
      winSel.addEventListener("change", function () {
        windowSize = parseInt(winSel.value, 10) || 24;
        streamMode = false;
        var maxStart = Math.max(0, hours.length - windowSize);
        if (windowStart > maxStart) {
          windowStart = maxStart;
          slider.value = String(maxStart);
        }
        applyWindow(true, false);
      });
    }

    var modeSel = document.getElementById("tl-mode");
    if (modeSel) {
      modeSel.addEventListener("change", function () {
        streamMode = modeSel.value === "stream";
        if (streamMode) {
          windowSize = 1;
          if (winSel) winSel.value = "6";
          winSel.disabled = true;
        } else {
          windowSize = parseInt(winSel.value, 10) || 24;
          winSel.disabled = false;
        }
        var maxStart = Math.max(0, hours.length - windowSize);
        if (windowStart > maxStart) {
          windowStart = maxStart;
          slider.value = String(maxStart);
        }
        applyWindow(true, streamMode);
      });
    }

    var lineToggle = document.getElementById("tl-lines");
    if (lineToggle) {
      lineToggle.addEventListener("change", function () {
        attackLayer.setVisible(lineToggle.checked);
      });
    }

    var playBtn = document.getElementById("tl-play");
    if (playBtn) {
      playBtn.addEventListener("click", function () {
        if (playing) stopPlay(); else startPlay();
      });
    }
  }

  function startPlay() {
    if (playing) return;
    playing = true;
    var lineToggle = document.getElementById("tl-lines");
    if (lineToggle) {
      lineToggle.addEventListener("change", function () {
        attackLayer.setVisible(lineToggle.checked);
      });
    }

    var playBtn = document.getElementById("tl-play");
    if (playBtn) { playBtn.textContent = "暂停"; playBtn.classList.add("on"); }

    var slider = document.getElementById("tl-slider");
    // 流式模式推进快一点，一小时的量 0.55 秒走完，看起来像事件在涌入
    var step = streamMode ? 520 : 700;

    playTimer = setInterval(function () {
      var maxStart = Math.max(0, hours.length - windowSize);
      if (windowStart >= maxStart) { stopPlay(); return; }
      windowStart = Math.min(maxStart, windowStart + 1);
      if (slider) slider.value = String(windowStart);
      applyWindow(true, streamMode);
    }, step);
  }

  function stopPlay() {
    playing = false;
    if (playTimer) { clearInterval(playTimer); playTimer = null; }
    var lineToggle = document.getElementById("tl-lines");
    if (lineToggle) {
      lineToggle.addEventListener("change", function () {
        attackLayer.setVisible(lineToggle.checked);
      });
    }

    var playBtn = document.getElementById("tl-play");
    if (playBtn) { playBtn.textContent = "播放"; playBtn.classList.remove("on"); }
  }

  // ------------------------------------------------------------ 详情
  function showDetail(p) {
    document.getElementById("d-ip").textContent = p.ip;
    document.getElementById("d-loc").textContent =
      [p.country, p.city].filter(Boolean).join(" · ") || "未知位置";
    document.getElementById("d-n").textContent =
      countInWindow(p, windowStart, windowSize) + " 次（窗口内）/ 共 " + p.n + " 次";
    document.getElementById("d-first").textContent =
      (p.first || "").replace("T", " ").slice(0, 16);
    document.getElementById("d-last").textContent =
      (p.last || "").replace("T", " ").slice(0, 16);
    document.getElementById("d-ua").textContent = p.ua || "-";

    var ul = document.getElementById("d-paths");
    ul.textContent = "";
    (p.paths || []).forEach(function (path) {
      var li = document.createElement("li");
      li.textContent = path;   // 路径是攻击者写的，只能 textContent
      ul.appendChild(li);
    });

    document.getElementById("detail").hidden = false;
  }

  // ------------------------------------------------------------ 启动
  function boot(data) {
    points = data.points || [];
    hours = data.hours || [];
    windowSize = Math.min(24, Math.max(1, hours.length));
    windowStart = Math.max(0, hours.length - windowSize);

    buildMarkers();
    attackLayer.addTo(map);
    buildTimeline();
    buildDateChips();
    applyWindow(false, false);

    var s = data.stats || {};
    document.getElementById("s-ips").textContent = s.ips || 0;
    document.getElementById("s-countries").textContent = s.countries || 0;
    document.getElementById("s-entries").textContent = (s.entries || 0).toLocaleString();
    document.getElementById("generated").textContent =
      "生成于 " + (data.generated_at || "–") + " · " + (s.files || 0) + " 个日志文件";
    document.getElementById("attribution").textContent = data.attribution || "";

    var ol = document.getElementById("countries");
    ol.textContent = "";
    (s.top_countries || []).forEach(function (row) {
      var li = document.createElement("li");
      li.textContent = row[0] || "未知";
      var span = document.createElement("span");
      span.textContent = row[1];
      li.appendChild(span);
      ol.appendChild(li);
    });
  }

  document.getElementById("close-detail").addEventListener("click", function () {
    document.getElementById("detail").hidden = true;
  });

  var ready = window.__MAP_DATA__
    ? Promise.resolve(window.__MAP_DATA__)
    : fetch("/api/map/points", { credentials: "same-origin" })
        .then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        });

  ready.then(function (data) {
    boot(data);
    watchForUpdate(data.generated_at);
  }).catch(function (err) {
    document.getElementById("generated").textContent = "加载失败：" + err.message;
  });

  /**
   * 数据有新版本时给一个提示，不自动刷新。
   *
   * 为什么不 location.reload()：地图可能正被人拖到某个城市在看细节，
   * 突然刷新会把他刚看的位置丢掉。让人自己点一下更合适。
   */
  function watchForUpdate(initialStamp) {
    if (!initialStamp) return;

    setInterval(function () {
      fetch("/api/map/points", { credentials: "same-origin" })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (d) {
          if (!d || d.generated_at === initialStamp) return;
          var el = document.getElementById("generated");
          if (!el) return;
          el.textContent = "有新数据（" + d.generated_at + "）· 点击刷新";
          el.classList.add("has-update");
          el.onclick = function () { location.reload(); };
        })
        .catch(function () { /* 轮询失败不打扰用户 */ });
    }, 90000);
  }
})();
