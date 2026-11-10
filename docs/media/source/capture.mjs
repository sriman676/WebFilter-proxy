// Frame capture over the Chrome DevTools Protocol (Node >= 22 built-in WebSocket; no packages).
// Usage: node capture.mjs frames <outDir> [fps=30] [secs=20]   |   node capture.mjs stills <outDir> t1 t2 ...
import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const CHROME = "C:/Program Files/Google/Chrome/Application/chrome.exe";
const [mode, outDir, ...rest] = process.argv.slice(2);
mkdirSync(outDir, { recursive: true });
const page = pathToFileURL(resolve(import.meta.dirname, "video.html")).href;
const port = 9333;
const chrome = spawn(CHROME, [
  "--headless=new", `--remote-debugging-port=${port}`, "--no-first-run", "--disable-extensions",
  "--hide-scrollbars", "--force-color-profile=srgb", "--disable-gpu",
  `--user-data-dir=${resolve(import.meta.dirname, "chrome-profile")}`, "about:blank",
], { stdio: "ignore" });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let version;
for (let i = 0; i < 50 && !version; i++) {
  try { version = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(); } catch { await sleep(200); }
}
const target = version.find((t) => t.type === "page");
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((r) => ws.addEventListener("open", r, { once: true }));
let seq = 0;
const pending = new Map();
ws.addEventListener("message", (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
});
const send = (method, params = {}) => new Promise((res, rej) => {
  const id = ++seq;
  pending.set(id, (m) => (m.error ? rej(new Error(`${method}: ${m.error.message}`)) : res(m.result)));
  ws.send(JSON.stringify({ id, method, params }));
});

await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride", { width: 1920, height: 1080, deviceScaleFactor: 1, mobile: false });
await send("Page.navigate", { url: page });
for (let i = 0; i < 100; i++) {
  const r = await send("Runtime.evaluate", { expression: "document.readyState === 'complete' && typeof render === 'function'", returnByValue: true });
  if (r.result.value) break;
  await sleep(100);
}
await send("Runtime.evaluate", { expression: "document.fonts.ready.then(() => true)", awaitPromise: true });

async function shot(t, file) {
  await send("Runtime.evaluate", { expression: `render(${t}); new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))`, awaitPromise: true });
  const { data } = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: false });
  writeFileSync(file, Buffer.from(data, "base64"));
}

if (mode === "frames") {
  const fps = Number(rest[0] ?? 30), secs = Number(rest[1] ?? 20), total = Math.round(fps * secs);
  for (let f = 0; f < total; f++) {
    await shot(f / fps, resolve(outDir, `f${String(f).padStart(4, "0")}.png`));
    if (f % 60 === 0) console.log(`frame ${f}/${total}`);
  }
} else {
  for (const t of rest) await shot(Number(t), resolve(outDir, `still-${t}.png`));
}
ws.close();
chrome.kill();
console.log("done");
