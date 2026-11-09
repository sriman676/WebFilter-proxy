// WebFilter admin dashboard (SPEC_EXT_OPS O4, A-30). Vanilla JS; every dynamic value goes through
// textContent/createElement (D-57). The token lives in this closure only: never stored or sent in URLs.
"use strict";
(function () {
  let token = "";
  let current = "overview";
  const history = []; // {t, req, blocked} per refresh, for the rate chart
  const $ = (id) => document.getElementById(id);

  function el(tag, text, cls) {
    const e = document.createElement(tag);
    if (text !== undefined && text !== null) e.textContent = String(text);
    if (cls) e.className = cls;
    return e;
  }
  function row(cells) {
    const tr = document.createElement("tr");
    for (const c of cells) {
      const td = document.createElement("td");
      if (c instanceof Node) td.appendChild(c); else td.textContent = c === null || c === undefined ? "" : String(c);
      tr.appendChild(td);
    }
    return tr;
  }
  function fill(tableId, rows) {
    const body = $(tableId).querySelector("tbody");
    body.replaceChildren(...rows);
  }
  function pill(text) { return el("span", text, "pill " + String(text)); }
  function status(text, bad) { const s = $("status"); s.textContent = text; s.className = bad ? "status err" : "status"; }
  function time(ts) { return typeof ts === "string" ? ts.replace("T", " ").replace("Z", "") : ""; }

  async function api(method, path, body) {
    if (!token) throw new Error("not connected");
    const opts = { method, headers: { "Authorization": "Bearer " + token } };
    if (method !== "GET") {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body || {});
    }
    const r = await fetch("/api/v1/" + path, opts);
    if (r.status === 401) { token = ""; status("Token rejected; enter it again", true); throw new Error("unauthorized"); }
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || ("HTTP " + r.status));
    return data;
  }

  // ---------------------------------------------------------------- tabs
  for (const b of $("tabs").querySelectorAll("button")) {
    b.addEventListener("click", () => {
      current = b.dataset.tab;
      for (const x of $("tabs").querySelectorAll("button")) x.classList.toggle("active", x === b);
      for (const p of document.querySelectorAll(".panel")) p.classList.toggle("active", p.id === current);
      refresh(true);
    });
  }
  $("login").addEventListener("submit", (e) => {
    e.preventDefault();
    token = $("token").value.trim();
    $("token").value = "";
    refresh(true);
  });

  // ---------------------------------------------------------------- charts (canvas, no libraries)
  function css(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
  function rateChart() {
    const c = $("chart-rate"), g = c.getContext("2d");
    g.clearRect(0, 0, c.width, c.height);
    const pts = history.slice(-60);
    if (pts.length < 2) return;
    const rates = [];
    for (let i = 1; i < pts.length; i++) {
      const dt = Math.max(0.001, (pts[i].t - pts[i - 1].t) / 1000);
      rates.push({ r: Math.max(0, pts[i].req - pts[i - 1].req) / dt, b: Math.max(0, pts[i].blocked - pts[i - 1].blocked) / dt });
    }
    const max = Math.max(1, ...rates.map((x) => x.r));
    const pad = 28, w = c.width - pad - 8, h = c.height - 2 * pad;
    g.strokeStyle = css("--line"); g.fillStyle = css("--muted"); g.font = "12px system-ui";
    g.beginPath(); g.moveTo(pad, pad); g.lineTo(pad, pad + h); g.lineTo(pad + w, pad + h); g.stroke();
    g.fillText(max.toFixed(1) + "/s", 2, pad - 6);
    const line = (key, color) => {
      g.strokeStyle = color; g.lineWidth = 2; g.beginPath();
      rates.forEach((p, i) => {
        const x = pad + (i / Math.max(1, rates.length - 1)) * w, y = pad + h - (p[key] / max) * h;
        if (i === 0) g.moveTo(x, y); else g.lineTo(x, y);
      });
      g.stroke();
    };
    line("r", css("--accent")); line("b", css("--bad"));
  }
  function topChart(items) {
    const c = $("chart-top"), g = c.getContext("2d");
    g.clearRect(0, 0, c.width, c.height);
    const top = items.slice(0, 8);
    const max = Math.max(1, ...top.map((x) => x.count));
    const bh = Math.floor((c.height - 10) / Math.max(1, top.length));
    g.font = "12px system-ui";
    top.forEach((x, i) => {
      const y = 5 + i * bh, w = ((c.width - 230) * x.count) / max; // room for the count label
      g.fillStyle = css("--bad"); g.fillRect(160, y + 3, Math.max(2, w), bh - 8);
      g.fillStyle = css("--text"); g.fillText(String(x.host).slice(0, 24), 4, y + bh / 2 + 3);
      g.fillText(String(x.count), 164 + w, y + bh / 2 + 3);
    });
  }

  // ---------------------------------------------------------------- views
  async function overview() {
    const s = await api("GET", "stats");
    const badge = $("mode-badge"); badge.textContent = s.mode; badge.className = "badge " + s.mode;
    const tiles = [["Requests", s.requests], ["Blocked", s.blocked], ["Active connections", s.active_connections],
      ["Domains listed", s.lists.domains], ["URL patterns", s.lists.url_patterns], ["IP ranges", s.lists.ip_blocklist],
      ["Interception", s.intercept ? "on" : "off"], ["Scanning", s.scan ? "on" : "off"], ["Log drops", s.log_dropped]];
    $("tiles").replaceChildren(...tiles.map(([k, v]) => { const t = el("div", null, "tile"); t.append(el("div", k, "k"), el("div", v, "v")); return t; }));
    history.push({ t: Date.now(), req: s.requests, blocked: s.blocked });
    if (history.length > 120) history.shift();
    rateChart();
    topChart(await api("GET", "top/blocked?n=8"));
  }
  async function events() {
    if ($("ev-pause").checked) return;
    const action = $("ev-action").value;
    const evs = await api("GET", "events/recent?limit=300" + (action ? "&action=" + encodeURIComponent(action) : ""));
    const f = $("ev-search").value.toLowerCase();
    const rows = evs.filter((e) => !f || [e.dest_host, e.uri_path, e.client_id, e.reason, e.rule_id].some((v) => String(v || "").toLowerCase().includes(f)))
      .map((e) => row([time(e.timestamp), e.client_id, e.http_method, e.url, e.status, pill(e.action), e.reason, e.rule_id]));
    fill("ev-table", rows);
  }
  async function blocked() {
    fill("top-table", (await api("GET", "top/blocked?n=100")).map((x) => row([x.host, x.count])));
  }
  async function clients() {
    fill("clients-table", (await api("GET", "clients")).map((c) => row([c.client_id, c.requests, c.blocked, time(c.last_seen)])));
  }
  let listsLoaded = false;
  async function lists(force) {
    const sel = $("list-select");
    if (!listsLoaded || force === "reload") {
      const l = await api("GET", "lists");
      const keep = sel.value;
      sel.replaceChildren(...l.lists.map((x) => { const o = el("option", x.name); o.value = x.name; return o; }));
      if (keep) sel.value = keep;
      listsLoaded = true;
      await loadList();
    }
  }
  async function loadList() {
    const name = $("list-select").value;
    if (!name) return;
    const l = await api("GET", "lists/" + name);
    $("list-text").value = l.content;
    $("list-info").textContent = l.kind + " - " + l.versions.length + " earlier version(s)";
  }
  $("list-select").addEventListener("change", () => loadList().catch((e) => status(e.message, true)));
  $("list-save").addEventListener("click", async () => {
    try {
      const r = await api("PUT", "lists/" + $("list-select").value, { content: $("list-text").value });
      $("list-info").textContent = "Saved: " + r.entries + " entries";
      await loadList();
    } catch (e) { $("list-info").textContent = "Not saved: " + e.message; }
  });
  $("list-rollback").addEventListener("click", async () => {
    try { await api("POST", "lists/" + $("list-select").value + "/rollback", {}); await loadList(); }
    catch (e) { $("list-info").textContent = "Rollback failed: " + e.message; }
  });

  let settingsLoaded = false;
  async function settings(force) {
    if (settingsLoaded && !force) return;
    const [st, l] = await Promise.all([api("GET", "settings"), api("GET", "lists")]);
    $("cfg-mode").textContent = st.config_mode;
    for (const r of document.querySelectorAll("input[name=mode]")) r.checked = (r.value || null) === (st.settings.mode || null);
    $("allow-text").value = (st.settings.allow_domains || []).join("\n");
    const ov = st.settings.categories || {};
    fill("cat-table", l.categories.map((c) => {
      const on = el("input"); on.type = "checkbox"; on.checked = ov[c.name] && ov[c.name].enabled !== null && ov[c.name].enabled !== undefined ? ov[c.name].enabled : c.enabled; on.dataset.cat = c.name;
      const sched = el("input"); sched.value = (c.active || []).join("; "); sched.dataset.cat = c.name; sched.className = "sched";
      return row([c.name, on, sched, c.active_now ? el("span", "active", "ok") : el("span", "idle", "muted")]);
    }));
    $("settings-info").textContent = st.versions + " earlier version(s)";
    settingsLoaded = true;
  }
  $("settings-save").addEventListener("click", async () => {
    const mode = [...document.querySelectorAll("input[name=mode]")].find((r) => r.checked);
    const categories = {};
    for (const cb of document.querySelectorAll("#cat-table input[type=checkbox]")) {
      const sched = document.querySelector("#cat-table input.sched[data-cat='" + CSS.escape(cb.dataset.cat) + "']");
      const active = sched.value.split(";").map((x) => x.trim()).filter((x) => x);
      categories[cb.dataset.cat] = { enabled: cb.checked, active };
    }
    const body = { mode: mode && mode.value ? mode.value : null, allow_domains: $("allow-text").value.split("\n").map((x) => x.trim()).filter((x) => x), categories };
    try { await api("POST", "settings", body); $("settings-info").textContent = "Applied"; await settings(true); }
    catch (e) { $("settings-info").textContent = "Not applied: " + e.message; }
  });
  $("settings-rollback").addEventListener("click", async () => {
    try { await api("POST", "settings/rollback", {}); await settings(true); }
    catch (e) { $("settings-info").textContent = "Rollback failed: " + e.message; }
  });

  async function feeds() {
    fill("feeds-table", (await api("GET", "feeds")).map((f) => {
      const b = el("button", "Update now");
      b.addEventListener("click", async () => {
        b.disabled = true;
        try { await api("POST", "feeds/update", { name: f.name }); } catch (e) { status(e.message, true); }
        b.disabled = false; refresh(true);
      });
      return row([f.name, f.enabled ? "yes" : "no", f.entries, f.active || "-", f.last_success ? new Date(f.last_success * 1000).toISOString() : "never", b]);
    }));
  }
  async function scans() {
    const evs = (await api("GET", "events/recent?limit=500")).filter((e) => e.scan_status);
    fill("scans-table", evs.map((e) => row([time(e.timestamp), e.client_id, e.download_name, pill(e.scan_status), e.scan_engine, e.scan_signature, e.body_sha256])));
  }
  async function requests() {
    const ttl = () => Math.min(24, Math.max(1, Number($("req-ttl").value) || 4)) * 3600;
    fill("req-table", (await api("GET", "access-requests")).map((r) => {
      const box = el("span");
      if (r.status === "pending") {
        for (const [label, decision] of [["Approve", "approve"], ["Deny", "deny"]]) {
          const b = el("button", label, decision === "deny" ? "danger" : "primary");
          b.addEventListener("click", async () => {
            try { await api("POST", "access-requests/" + encodeURIComponent(r.id) + "/decide", { decision, ttl_secs: ttl() }); } catch (e) { status(e.message, true); }
            refresh(true);
          });
          box.appendChild(b);
        }
      }
      return row([new Date(r.created * 1000).toISOString(), r.client_id, r.host, r.reason, r.justification, pill(r.status), box]);
    }));
  }
  async function allows() {
    fill("ta-table", (await api("GET", "temp-allows")).map((a) => {
      const b = el("button", "Remove", "danger");
      b.addEventListener("click", async () => {
        try { await api("DELETE", "temp-allows/" + encodeURIComponent(a.id), {}); } catch (e) { status(e.message, true); }
        refresh(true);
      });
      return row([a.host + (a.include_subdomains ? " (+subdomains)" : ""), a.scope.kind + ": " + a.scope.value, new Date(a.expires * 1000).toISOString(), a.created_by, b]);
    }));
  }
  $("allow-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const body = { host: $("ta-host").value.trim(), scope: $("ta-scope").value, target: $("ta-target").value.trim(),
      ttl_secs: Math.min(24, Math.max(1, Number($("ta-ttl").value) || 4)) * 3600 };
    try { await api("POST", "temp-allows", body); $("ta-host").value = ""; } catch (err) { status(err.message, true); }
    refresh(true);
  });
  async function audit() {
    fill("audit-table", (await api("GET", "audit?limit=200")).map((a) => row([time(a.timestamp), a.remote_addr, a.action, a.target, pill(a.result)])));
  }

  const views = { overview, events, blocked, clients, lists, settings, feeds, scans, requests, allows, audit };
  async function refresh(force) {
    if (!token) { status("Not connected", false); return; }
    try {
      if (current !== "overview") await overview().catch(() => {}); // keep the badge and chart current
      await views[current](force);
      status("Connected - updated " + new Date().toLocaleTimeString(), false);
    } catch (e) {
      if (e.message !== "unauthorized") status(e.message, true);
    }
  }
  setInterval(() => refresh(false), 5000);
})();
