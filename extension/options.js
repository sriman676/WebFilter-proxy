// Options page (SPEC_EXT_OPS O9). The token is stored in storage.local and never shown again.
"use strict";

const $ = (id) => document.getElementById(id);

function report(msg, isError) {
  const r = $("result");
  r.textContent = msg;
  r.className = isError ? "error" : "muted";
}

async function load() {
  const cfg = await storageGet(["adminUrl", "token", "proxyHost"]);
  $("admin-url").value = typeof cfg.adminUrl === "string" ? cfg.adminUrl : "";
  $("proxy").value = typeof cfg.proxyHost === "string" ? cfg.proxyHost : "127.0.0.1:8080";
  $("token").value = "";
  $("token-state").textContent = cfg.token ? "Token saved. Leave empty to keep it." : "No token saved.";
}

$("form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const items = {};
  try {
    items.adminUrl = validateAdminUrl($("admin-url").value);
    items.proxyHost = validateProxy($("proxy").value).text;
    const tokenInput = $("token").value;
    if (tokenInput.trim() !== "") {
      items.token = validateToken(tokenInput);
    } else {
      const { token } = await storageGet(["token"]);
      if (!token) throw new Error("A read-only token is required.");
    }
  } catch (err) {
    report(err instanceof Error ? err.message : "Invalid input.", true);
    return;
  }
  await storageSet(items);
  $("token").value = "";
  await load();
  let note = "";
  const { proxyOn } = await storageGet(["proxyOn"]);
  if (proxyOn === true) {
    // Re-apply the proxy toggle so a changed host:port takes effect.
    try {
      const r = await api.runtime.sendMessage({ type: "setProxy", on: true });
      if (r?.error === "proxy") note = " Proxy setting could not be re-applied.";
    } catch {
      note = " Proxy setting could not be re-applied.";
    }
  }
  report((items.token ? "Settings saved; token saved." : "Settings saved.") + note, Boolean(note));
});

load();
