/* 攻击者地图前端。
 *
 * 三条原则：
 *   1. 不解析日志 —— 后端已经把每个 IP 聚合成一个点，这里只画
 *   2. 不做假动画 —— 点的大小和颜色都是真实数据，不做"随机闪烁"骗观感
 *   3. 只看能看懂的 —— 图上只留四种颜色，多一种就分不清了
 */
(function () {
  "use strict";

  var COLORS = {
    bait: "#ff3b30",     // 站点特定诱饵：知道这站有备份的人才会试
    exploit: "#ff9f0a",  // 尝试利用
    cloud: "#ffd60a",    // 云凭据探测
    scan: "#4a9eff"      // 扫描 / 探测
  };

  var LABEL = {
    bait: "站点特定诱饵",
    exploit: "尝试利用",
    cloud: "云凭据探测",
    scan: "扫描 / 探测"
  };

  var map = L.map("map", {
    worldCopyJump: true,
    minZoom: 2,
    maxZoom: 9,
    zoomControl: false,
    attributionControl: true
  }).setView([22, 40], 2);

  L.control.zoom({ position: "bottomright" }).addTo(map);

  // CartoDB 深色底图：免费、无需 token、深色背景上的点最清楚。
  // 用亮色底图会让几百个点糊成一片，什么都看不出来。
  L.tileLayer(
    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    {
      subdomains: "abcd",
      maxZoom: 19,
      attribution: '&copy; OpenStreetMap &copy; CARTO'
    }
  ).addTo(map);

  var layer = L.layerGroup().addTo(map);
  var points = [];

  function radius(n) {
    // 用对数：一个打了 174 次的 IP 和一个打 1 次的 IP 半径差不能是 174 倍，
    // 那样小的会看不见。log 之后视觉比例才和人眼的感知接近。
    return 3 + Math.log2(n + 1) * 1.9;
  }

  function fmtTime(iso) {
    if (!iso) return "–";
    // 后端给的是 ISO，前端只取到分钟，够用了
    return iso.replace("T", " ").slice(0, 16);
  }

  function escapeHtml(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function showDetail(p) {
    document.getElementById("d-ip").textContent = p.ip;
    document.getElementById("d-loc").textContent =
      [p.country, p.city].filter(Boolean).join(" · ") || "未知位置";
    document.getElementById("d-n").textContent = p.n + " 次";
    document.getElementById("d-first").textContent = fmtTime(p.first);
    document.getElementById("d-last").textContent = fmtTime(p.last);
    document.getElementById("d-ua").textContent = p.ua || "-";
    document.getElementById("d-loc").dataset.cat = p.cat;

    var ul = document.getElementById("d-paths");
    ul.textContent = "";
    (p.paths || []).forEach(function (path) {
      var li = document.createElement("li");
      // 路径是攻击者写的，必须用 textContent，绝不能拼 HTML
      li.textContent = path;
      ul.appendChild(li);
    });

    document.getElementById("detail").hidden = false;
  }

  function draw(data) {
    layer.clearLayers();
    points = data.points || [];

    points.forEach(function (p) {
      var color = COLORS[p.cat] || COLORS.scan;
      var isBait = p.cat === "bait";

      var marker = L.circleMarker([p.lat, p.lon], {
        radius: radius(p.n),
        color: color,
        weight: isBait ? 2 : 1,
        opacity: isBait ? 1 : 0.75,
        fillColor: color,
        fillOpacity: isBait ? 0.55 : 0.32
      });

      marker.bindTooltip(
        "<b>" + escapeHtml(p.ip) + "</b><br>" +
        escapeHtml((p.country || "?") + (p.city ? " · " + p.city : "")) +
        "<br>" + p.n + " 次请求",
        { className: "ip-tip", direction: "top", offset: [0, -2] }
      );

      marker.on("click", function () { showDetail(p); });
      marker.addTo(layer);
    });

    // 统计
    var s = data.stats || {};
    document.getElementById("s-ips").textContent = s.ips || 0;
    document.getElementById("s-countries").textContent = s.countries || 0;
    document.getElementById("s-entries").textContent = (s.entries || 0).toLocaleString();
    document.getElementById("s-bait").textContent = s.bait || 0;
    document.getElementById("s-exploit").textContent = s.exploit || 0;
    document.getElementById("s-cloud").textContent = s.cloud || 0;
    document.getElementById("s-scan").textContent =
      Math.max(0, (s.mapped || 0) - (s.bait || 0) - (s.exploit || 0) - (s.cloud || 0));

    document.getElementById("generated").textContent =
      "生成于 " + (data.generated_at || "–") + " · 共 " + (s.files || 0) + " 个日志文件";
    document.getElementById("attribution").textContent = data.attribution || "";

    // 国家排行
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

  // 生产环境走接口；离线快照（tools/build_map_preview.py）会把数据
  // 直接塞进 window.__MAP_DATA__，这样预览不需要登录态。
  var ready = window.__MAP_DATA__
    ? Promise.resolve(window.__MAP_DATA__)
    : fetch("/api/map/points", { credentials: "same-origin" })
        .then(function (r) {
          if (!r.ok) throw new Error("HTTP " + r.status);
          return r.json();
        });

  ready
    .then(draw)
    .catch(function (err) {
      document.getElementById("generated").textContent = "加载失败：" + err.message;
    });
})();
