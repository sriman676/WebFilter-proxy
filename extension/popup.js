// Popup (SPEC_EXT_OPS O9). Every value from the API is untrusted and rendered with textContent only.
"use strict";

const $ = (id) => document.getElementById(id);

const ERRORS = {
  not_configured: "Not configured. Set the admin URL and read-only token in the options.",
  unreachable: "Admin API unreachable. Is the proxy running with [admin] enabled?",
  auth: "Token refused by the admin API. Check the read-only token in the options.",
  http: "The admin API returned an error.",
  bad_response: "The admin API sent an unexpected response.",
  internal: "Internal extension error.",
};

async function send(msg) {
  try {
    return (await api.runtime.sendMessage(msg)) ?? { ok: false, error: "internal" };
  } catch {
    return { ok: false, error: "internal" };
  }
}

function text(tag, cls, value) {
  const el = document.createElement(tag);
  if (cls) el.className = cls;
  el.textContent = String(value ?? "");
  return el;
}

function showError(kind) {
  $("status").hidden = true;
  $("error").hidden = false;
  $("error-text").textContent = ERRORS[kind] ?? ERRORS.internal;
}

function showStatus(s) {
  $("error").hidden = true;
  $("status").hidden = false;
  $("s-mode").textContent = s.mode;
  $("s-requests").textContent = String(s.requests);
  $("s-blocked").textContent = String(s.blocked);
  $("s-since").textContent = String(s.blockedSinceStart);
  $("s-active").textContent = String(s.activeConnections);
}

function fmtTime(ts) {
  if (typeof ts !== "string") return "";
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? ts.slice(0, 40) : d.toLocaleTimeString();
}

function renderBlocks(events) {
  const list = $("blocks");
  list.replaceChildren();
  const items = Array.isArray(events) ? events.slice(0, 10) : [];
  $("no-blocks").hidden = items.length > 0;
  for (const ev of items) {
    if (typeof ev !== "object" || ev === null) continue;
    const li = document.createElement("li");
    li.append(text("div", "host", ev.dest_host));
    li.append(text("div", "url", ev.url));
    const meta = document.createElement("div");
    meta.className = "meta";
    meta.append(text("span", "reason", ev.reason), text("span", "muted", fmtTime(ev.timestamp)));
    const target = safeHttpUrl(ev.url);
    if (target) {
      const btn = text("button", "", "Request access");
      btn.type = "button";
      btn.title = "Open the blocked page; the proxy's block page has the request form";
      btn.addEventListener("click", () => {
        api.tabs.create({ url: target });
      });
      meta.append(btn);
    }
    li.append(meta);
    list.append(li);
  }
}

async function load() {
  const s = await send({ type: "refresh" });
  $("proxy-toggle").checked = s.proxyOn === true;
  if (!s.ok) {
    showError(s.error);
    return;
  }
  showStatus(s);
  try {
    renderBlocks(await apiGet("events/recent?action=blocked&limit=10"));
  } catch (e) {
    showError(e instanceof ApiError ? e.kind : "internal");
  }
}

$("proxy-toggle").addEventListener("change", async (e) => {
  const on = e.target.checked;
  const msg = $("proxy-msg");
  const r = await send({ type: "setProxy", on });
  if (r.error === "proxy") {
    e.target.checked = !on;
    msg.hidden = false;
    msg.className = "msg error";
    msg.textContent = `Proxy setting refused: ${r.detail ?? "unknown error"}. In Firefox, allow this extension to run in private windows.`;
    return;
  }
  msg.hidden = false;
  msg.className = "msg muted";
  msg.textContent = on ? "Browser traffic now goes through the proxy." : "System proxy settings restored.";
  if (r.ok) showStatus(r);
  else showError(r.error);
});

$("open-options").addEventListener("click", () => {
  api.runtime.openOptionsPage();
});

load();
