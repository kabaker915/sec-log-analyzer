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
      var m = L.circleMarker([p.lat, p.lon], {
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

  ready.then(boot).catch(function (err) {
    document.getElementById("generated").textContent = "加载失败：" + err.message;
  });
})();
