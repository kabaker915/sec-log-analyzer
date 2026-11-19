/* 攻击者地图 + 时间轴。
 *
 * 流畅度的三个前提（不是"加点 CSS 过渡"就能解决的）：
 *
 * 1. **标记只创建一次**
 *    早期版本每次切换时间都 clearLayers 再重建 679 个 marker，
 *    拖动滑块时明显卡顿。现在一次建好，之后只改半径和透明度。
 *
 * 2. **用 canvas 渲染**
 *    679 个 SVG 元素每次改样式都要重排。Leaflet 的 canvas 渲染器
 *    把所有点画在一张画布上，改样式只是重绘一次。
 *
 * 3. **补间由 rAF 驱动，不用 CSS transition**
 *    canvas 上没有 DOM 元素，CSS 过渡对它无效。
 *    必须自己插值：记录起止值，每帧算中间值。
 */
(function () {
  "use strict";

  var COLORS = {
    bait: "#ff3b30",
    exploit: "#ff9f0a",
    cloud: "#ffd60a",
    scan: "#4a9eff"
  };

  var TWEEN_MS = 260;

  var map = L.map("map", {
    worldCopyJump: true,
    minZoom: 2,
    maxZoom: 9,
    zoomControl: false,
    preferCanvas: true
  }).setView([22, 40], 2);

  L.control.zoom({ position: "bottomright" }).addTo(map);

  L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {
      subdomains: "abcd",
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap &copy; CARTO'
    }
  ).addTo(map);

  var canvas = L.canvas({ padding: 0.3 });
  var layer = L.layerGroup().addTo(map);

  var points = [];
  var hours = [];
  var markers = [];
  var windowStart = 0;
  var windowSize = 24;
  var playing = false;
  var playTimer = null;

  // ------------------------------------------------------------ 工具
  function radiusFor(n) {
    // 对数：174 次的点和 1 次的点线性差 174 倍，小的会看不见
    return n <= 0 ? 0 : 3 + Math.log2(n + 1) * 1.9;
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

  /** 某个点在当前窗口内的请求数。 */
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
        weight: p.cat === "bait" ? 2 : 1,
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

      markers.push({ marker: m, p: p, curR: 0, curO: 0, tgtR: 0, tgtO: 0 });
    });
  }

  // ------------------------------------------------------------ 补间
  var rafId = null;
  var animFrom = 0;

  function startTween() {
    if (rafId !== null) return;
    animFrom = performance.now();
    rafId = requestAnimationFrame(stepTween);
  }

  function stepTween(now) {
    var t = Math.min(1, (now - animFrom) / TWEEN_MS);
    // easeOutCubic：起步快收尾稳，比线性"有质感"
    var e = 1 - Math.pow(1 - t, 3);

    for (var i = 0; i < markers.length; i++) {
      var it = markers[i];
      var r = it.curR + (it.tgtR - it.curR) * e;
      var o = it.curO + (it.tgtO - it.curO) * e;
      it.marker.setRadius(r);
      it.marker.setStyle({
        opacity: o > 0 ? Math.min(1, o * 1.3) : 0,
        fillOpacity: o
      });
    }

    if (t < 1) {
      rafId = requestAnimationFrame(stepTween);
    } else {
      // 收尾对齐目标值，避免累积误差让点慢慢"漂"
      for (var j = 0; j < markers.length; j++) {
        var m2 = markers[j];
        m2.curR = m2.tgtR;
        m2.curO = m2.tgtO;
        m2.marker.setRadius(m2.tgtR);
        m2.marker.setStyle({
          opacity: m2.tgtO > 0 ? Math.min(1, m2.tgtO * 1.3) : 0,
          fillOpacity: m2.tgtO
        });
      }
      rafId = null;
    }
  }

  function applyImmediate() {
    for (var j = 0; j < markers.length; j++) {
      var m = markers[j];
      m.curR = m.tgtR;
      m.curO = m.tgtO;
      m.marker.setRadius(m.tgtR);
      m.marker.setStyle({
        opacity: m.tgtO > 0 ? Math.min(1, m.tgtO * 1.3) : 0,
        fillOpacity: m.tgtO
      });
    }
  }

  // ------------------------------------------------------------ 应用窗口
  function applyWindow(animate) {
    var visible = 0;
    var sum = 0;
    var byCat = { bait: 0, exploit: 0, cloud: 0, scan: 0 };

    for (var i = 0; i < markers.length; i++) {
      var it = markers[i];
      var n = countInWindow(it.p, windowStart, windowSize);
      if (n > 0) {
        visible += 1;
        sum += n;
        byCat[it.p.cat] = (byCat[it.p.cat] || 0) + 1;
        it.tgtR = radiusFor(n);
        it.tgtO = it.p.cat === "bait" ? 0.62 : 0.38;
      } else {
        it.tgtR = 0;
        it.tgtO = 0;
      }
    }

    if (animate) { startTween(); } else { applyImmediate(); }

    // 面板数字跟着窗口变——拖时间轴时数字在跳，才让人相信图是真的
    var label = document.getElementById("tl-label");
    if (label && hours.length) {
      var a = hours[windowStart] || "";
      var bIdx = Math.min(hours.length - 1, windowStart + windowSize - 1);
      label.textContent = fmtHour(a) +
        (windowSize > 1 ? "  →  " + fmtHour(hours[bIdx] || "") : "");
    }

    var wc = document.getElementById("tl-window-count");
    if (wc) wc.textContent = visible + " 个来源 · " + sum + " 次请求";

    var sb = document.getElementById("s-bait");
    var se = document.getElementById("s-exploit");
    var sc = document.getElementById("s-cloud");
    var ss = document.getElementById("s-scan");
    if (sb) sb.textContent = byCat.bait;
    if (se) se.textContent = byCat.exploit;
    if (sc) sc.textContent = byCat.cloud;
    if (ss) ss.textContent = byCat.scan;
  }

  // ------------------------------------------------------------ 时间轴
  function buildTimeline() {
    var slider = document.getElementById("tl-slider");
    if (!slider) return;

    slider.max = String(Math.max(0, hours.length - 1));
    slider.value = String(windowStart);
    slider.addEventListener("input", function () {
      windowStart = parseInt(slider.value, 10) || 0;
      applyWindow(true);
    });

    // 频率直方图：每小时的请求总量。
    // 没有它，滑块拖到哪都是盲猜；有了它，能直接看到"11-17 晚上有一波"。
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
        var maxStart = Math.max(0, hours.length - windowSize);
        if (windowStart > maxStart) {
          windowStart = maxStart;
          slider.value = String(maxStart);
        }
        applyWindow(true);
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
    playTimer = setInterval(function () {
      var maxStart = Math.max(0, hours.length - windowSize);
      if (windowStart >= maxStart) { stopPlay(); return; }
      windowStart = Math.min(maxStart, windowStart + 1);
      if (slider) slider.value = String(windowStart);
      applyWindow(true);
    }, 420);
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

    // 默认停在最后 24 小时：那是"现在"，也是最有意义的视角
    windowStart = Math.max(0, hours.length - windowSize);

    buildMarkers();
    buildTimeline();
    applyWindow(false);   // 首屏不做动画，避免一打开就"从无到有"闪一下

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

  // 生产环境走接口；离线快照把数据直接塞进 window.__MAP_DATA__
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
