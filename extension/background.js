// Background worker (Chrome service worker / Firefox MV3 background script), SPEC_EXT_OPS O9.
// Badge = blocked requests since the extension started; proxy toggle via the proxy settings API.
"use strict";

// Chrome loads only this file as the service worker; Firefox lists common.js before it in `scripts`.
if (typeof importScripts === "function" && typeof validateAdminUrl === "undefined") {
  importScripts("common.js");
}

const ALARM = "wf-poll";
const COLOR_ON = "#1e8e3e";
const COLOR_OFF = "#80868b";
const COLOR_ERR = "#d93025";
let memBaseline = null; // fallback when storage.session is unavailable

function isFirefox() {
  return typeof browser !== "undefined" && typeof browser.runtime.getBrowserInfo === "function";
}

async function getBaseline() {
  const s = sessionArea();
  if (s) {
    const v = await s.get("baseline");
    return Number.isSafeInteger(v?.baseline) ? v.baseline : null;
  }
  return memBaseline;
}

async function setBaseline(n) {
  const s = sessionArea();
  if (s) await s.set({ baseline: n });
  else memBaseline = n;
}

function badgeText(n) {
  if (n <= 0) return "";
  return n > 999 ? "999+" : String(n);
}

async function setBadge(text, color) {
  await api.action.setBadgeText({ text });
  await api.action.setBadgeBackgroundColor({ color });
}

/** Poll `stats`, update the badge and return a status object for the popup. */
async function refresh() {
  const { proxyOn = false } = await storageGet(["proxyOn"]);
  try {
    const stats = await apiGet("stats");
    const blocked = toCount(stats?.blocked);
    let base = await getBaseline();
    // First poll since the extension started, or the proxy restarted and its counters reset.
    if (base === null || blocked < base) {
      base = base === null ? blocked : 0;
      await setBaseline(base);
    }
    const since = blocked - base;
    await setBadge(badgeText(since), proxyOn ? COLOR_ON : COLOR_OFF);
    return {
      ok: true,
      proxyOn,
      blockedSinceStart: since,
      mode: stats?.mode === "monitor" ? "monitor" : stats?.mode === "enforce" ? "enforce" : "unknown",
      requests: toCount(stats?.requests),
      blocked,
      activeConnections: toCount(stats?.active_connections),
    };
  } catch (e) {
    const kind = e instanceof ApiError ? e.kind : "unreachable";
    if (kind === "not_configured") await setBadge("", COLOR_OFF);
    else await setBadge("!", COLOR_ERR);
    return { ok: false, proxyOn, error: kind };
  }
}

async function applyProxy(on) {
  const { proxyHost } = await storageGet(["proxyHost"]);
  const p = validateProxy(proxyHost);
  if (isFirefox()) {
    // Firefox needs "Run in private windows" allowed for this extension to change proxy settings.
    const value = on
      ? { proxyType: "manual", http: p.text, httpProxyAll: true, passthrough: "localhost, 127.0.0.1" }
      : { proxyType: "system" };
    await browser.proxy.settings.set({ value });
  } else {
    const value = on
      ? {
          mode: "fixed_servers",
          rules: { singleProxy: { scheme: "http", host: p.host, port: p.port }, bypassList: ["<local>"] },
        }
      : { mode: "system" };
    await api.proxy.settings.set({ value, scope: "regular" });
  }
  await storageSet({ proxyOn: on });
}

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!sender || sender.id !== api.runtime.id || typeof msg !== "object" || msg === null) return false;
  if (msg.type === "refresh") {
    refresh().then(sendResponse, () => sendResponse({ ok: false, error: "internal" }));
    return true;
  }
  if (msg.type === "setProxy" && typeof msg.on === "boolean") {
    applyProxy(msg.on)
      .then(() => refresh())
      .then(sendResponse, (e) =>
        sendResponse({ ok: false, error: "proxy", detail: e instanceof Error ? e.message : "proxy settings refused" }),
      );
    return true;
  }
  return false;
});

api.alarms.onAlarm.addListener((a) => {
  if (a.name === ALARM) refresh();
});

async function ensureAlarm() {
  const existing = await api.alarms.get(ALARM);
  if (!existing) await api.alarms.create(ALARM, { periodInMinutes: 1, delayInMinutes: 1 });
}

api.runtime.onInstalled.addListener(() => {
  ensureAlarm();
  refresh();
});
api.runtime.onStartup.addListener(() => {
  ensureAlarm();
  refresh();
});
ensureAlarm();
