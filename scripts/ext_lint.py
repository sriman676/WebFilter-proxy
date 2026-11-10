#!/usr/bin/env python3
"""Lint the browser extension (`just ext-lint`, E-88; SPEC_EXT_OPS O9). Python >= 3.10, stdlib only.

Checks the manifest (MV3, minimal permissions, loopback-only hosts, no content scripts / CSP override / external
connectivity), every JS file (no HTML injection, eval, string timers, non-loopback URLs, non-GET methods), every
HTML file (no inline script, inline handlers or external resources) and that the URL validation in common.js is
an exact loopback allowlist. If `node` is on PATH, the real validators are also run against a case table."""
import json, pathlib, re, shutil, subprocess, sys

root = pathlib.Path(__file__).resolve().parent.parent
ext = root / "extension"
errs: list[str] = []

LOOPBACK = ["127.0.0.1", "localhost", "[::1]"]
ALLOWED_PERMS = {"storage", "proxy", "alarms"}
ALLOWED_HOST_PERMS = {f"http://{h}/*" for h in LOOPBACK}


def err(where: str, msg: str) -> None:
    errs.append(f"{where}: {msg}")


def line_of(text: str, pos: int) -> int:
    return text[:pos].count("\n") + 1


if not ext.exists():
    print("EXT-LINT FAIL\n - extension/ does not exist"); sys.exit(1)

# ---- manifest ----
try:
    man = json.loads((ext / "manifest.json").read_text(encoding="utf-8"))
except (OSError, ValueError) as e:
    print(f"EXT-LINT FAIL\n - manifest.json unreadable: {e}"); sys.exit(1)
if man.get("manifest_version") != 3:
    err("manifest.json", "manifest_version must be 3")
perms = man.get("permissions", [])
if not isinstance(perms, list) or not set(perms) <= ALLOWED_PERMS:
    err("manifest.json", f"permissions must be a subset of {sorted(ALLOWED_PERMS)}, got {perms}")
hp = man.get("host_permissions", [])
if not isinstance(hp, list) or not set(hp) <= ALLOWED_HOST_PERMS:
    err("manifest.json", f"host_permissions must be loopback http only, got {hp}")
for key in ("content_scripts", "content_security_policy", "externally_connectable", "web_accessible_resources",
            "optional_permissions", "optional_host_permissions", "update_url"):
    if key in man:
        err("manifest.json", f"forbidden key {key!r}")
raw_manifest = json.dumps(man)
if "<all_urls>" in raw_manifest:
    err("manifest.json", "<all_urls> is forbidden")
bg = man.get("background", {})
if bg.get("service_worker") != "background.js" or "background.js" not in bg.get("scripts", []):
    err("manifest.json", "background needs service_worker and scripts (Firefox) with background.js")
gecko = man.get("browser_specific_settings", {}).get("gecko", {})
if gecko.get("id") != "webfilter-proxy@localhost":
    err("manifest.json", "browser_specific_settings.gecko.id must be webfilter-proxy@localhost")
for f in [*bg.get("scripts", []), bg.get("service_worker"), man.get("action", {}).get("default_popup"),
          man.get("options_ui", {}).get("page")]:
    if f and not (ext / f).is_file():
        err("manifest.json", f"referenced file missing: {f}")

# ---- JS ----
URL_RX = re.compile(r"https?://([^\s\"'`/]*)")
JS_BAD = [
    (r"\binnerHTML\b", "innerHTML"), (r"\bouterHTML\b", "outerHTML"), (r"insertAdjacentHTML", "insertAdjacentHTML"),
    (r"document\.write", "document.write"), (r"\beval\s*\(", "eval("), (r"new\s+Function", "new Function"),
    (r"set(Timeout|Interval)\s*\(\s*[\"'`]", "string setTimeout/setInterval"), (r"javascript:", "javascript: URL"),
    (r"\bXMLHttpRequest\b", "XMLHttpRequest (use apiGet)"), (r"\bWebSocket\b", "WebSocket"),
    (r"\bsendBeacon\b", "sendBeacon"), (r"\bimport\s*\(", "dynamic import"),
]
js_files = sorted(ext.rglob("*.js"))
fetch_count = 0
for f in js_files:
    rel = f.relative_to(root).as_posix()
    text = f.read_text(encoding="utf-8", errors="replace")
    for rx, name in JS_BAD:
        for m in re.finditer(rx, text):
            err(f"{rel}:{line_of(text, m.start())}", name)
    for m in URL_RX.finditer(text):
        host = m.group(1).split(":")[0] if not m.group(1).startswith("[") else m.group(1).split("]")[0] + "]"
        if host not in LOOPBACK:
            err(f"{rel}:{line_of(text, m.start())}", f"non-loopback URL literal {m.group(0)!r}")
    for m in re.finditer(r"\bmethod\s*:\s*([^,}\n]+)", text):
        if m.group(1).strip() not in ('"GET"', "'GET'"):
            err(f"{rel}:{line_of(text, m.start())}", f"non-GET request method {m.group(1).strip()}")
    for m in re.finditer(r"\bfetch\s*\(", text):
        fetch_count += 1
        if f.name != "common.js":
            err(f"{rel}:{line_of(text, m.start())}", "fetch outside common.js apiGet")
if fetch_count > 1:
    err("extension", f"exactly one fetch call (apiGet) allowed, found {fetch_count}")

# ---- HTML ----
for f in sorted(ext.rglob("*.html")):
    rel = f.relative_to(root).as_posix()
    text = f.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"<script\b([^>]*)>(.*?)</script\s*>", text, re.S | re.I):
        if "src=" not in m.group(1).lower() or m.group(2).strip():
            err(f"{rel}:{line_of(text, m.start())}", "inline <script>")
    for m in re.finditer(r"<[^>]*\son[a-z]+\s*=", text, re.I):
        err(f"{rel}:{line_of(text, m.start())}", "inline event handler attribute")
    for m in re.finditer(r"\b(src|href|action)\s*=\s*[\"']?\s*(https?:|//|javascript:|data:)", text, re.I):
        err(f"{rel}:{line_of(text, m.start())}", "external/script resource reference")
    for m in re.finditer(r"<(iframe|object|embed|base|meta\s+http-equiv)\b", text, re.I):
        err(f"{rel}:{line_of(text, m.start())}", f"forbidden element <{m.group(1)}>")
    for m in re.finditer(r"@import|url\(\s*[\"']?https?:", text, re.I):
        err(f"{rel}:{line_of(text, m.start())}", "external style reference")
for f in sorted(ext.rglob("*.css")):
    rel = f.relative_to(root).as_posix()
    text = f.read_text(encoding="utf-8", errors="replace")
    for m in re.finditer(r"@import|url\(", text, re.I):
        err(f"{rel}:{line_of(text, m.start())}", "external/url() style reference")

# ---- validation allowlist in common.js ----
common = (ext / "common.js").read_text(encoding="utf-8", errors="replace") if (ext / "common.js").is_file() else ""
m = re.search(r"const\s+LOOPBACK_HOSTS\s*=\s*Object\.freeze\(\s*\[([^\]]*(?:\[::1\][^\]]*)?)\]\s*\)", common)
allow = re.findall(r"[\"']([^\"']+)[\"']", m.group(1)) if m else []
if sorted(allow) != sorted(LOOPBACK):
    err("extension/common.js", f"LOOPBACK_HOSTS must be exactly {LOOPBACK}, got {allow}")
for fn in ("validateAdminUrl", "validateProxy"):
    body = re.search(rf"function\s+{fn}\s*\([^)]*\)\s*\{{(.*?)\n\}}", common, re.S)
    if not body:
        err("extension/common.js", f"{fn} not found")
    elif "!LOOPBACK_HOSTS.includes(" not in body.group(1) or "throw" not in body.group(1):
        err("extension/common.js", f"{fn} must reject hosts not in LOOPBACK_HOSTS")
if "credentials: \"omit\"" not in common or "redirect: \"error\"" not in common or "AbortController" not in common:
    err("extension/common.js", "apiGet must use credentials omit, redirect error and a timeout")

# (input, expected accepted) - checked against the allowlist, and against the real code when node exists.
ADMIN_CASES = [
    ("http://127.0.0.1:9090", True), ("http://localhost:9090/", True), ("http://[::1]:9090", True),
    ("http://127.0.0.1:80", True),
    ("https://127.0.0.1:9090", False), ("http://127.0.0.1", False), ("http://127.0.0.1:0", False),
    ("http://127.0.0.1:65536", False), ("http://evil.example:9090", False), ("http://127.0.0.2:9090", False),
    ("http://localhost.evil.example:9090", False), ("http://0.0.0.0:9090", False), ("http://u:p@127.0.0.1:9090", False),
    ("http://127.0.0.1:9090/api", False), ("http://127.0.0.1:9090/?a=1", False), ("http://127.0.0.1:9090/#x", False),
    ("http://127.0.0.1@evil.example:9090", False), ("file:///etc/passwd", False), ("", False),
]
PROXY_CASES = [
    ("127.0.0.1:8080", True), ("localhost:3128", True), ("[::1]:8080", True), ("", True),
    ("10.0.0.1:8080", False), ("evil.example:8080", False), ("127.0.0.1", False), ("127.0.0.1:99999", False),
    ("http://127.0.0.1:8080", False),
]
for url, ok in ADMIN_CASES:
    hm = re.match(r"^http://([^/?#@\s]+):(\d{1,5})/?$", url)
    accepted = bool(hm) and hm.group(1) in allow and 1 <= int(hm.group(2)) <= 65535
    if ok != accepted:
        err("allowlist-table", f"admin URL case {url!r} expected {'accept' if ok else 'reject'}")

node = shutil.which("node")
if node and common:
    harness = (
        "const vm=require('vm'),fs=require('fs');"
        "const src=fs.readFileSync(process.argv[1],'utf8');"
        "const ctx={URL,AbortController,setTimeout,clearTimeout,globalThis:{}};"
        "const f=vm.runInNewContext(src+'\\n;({validateAdminUrl,validateProxy})',ctx);"
        "const cases=JSON.parse(process.argv[2]);const out=[];"
        "for(const [fn,s,ok] of cases){let got;try{f[fn](s);got=true}catch{got=false}"
        "if(got!==ok)out.push(fn+' '+JSON.stringify(s)+' expected '+(ok?'accept':'reject'))}"
        "console.log(JSON.stringify(out));"
    )
    cases = [["validateAdminUrl", s, ok] for s, ok in ADMIN_CASES] + [["validateProxy", s, ok] for s, ok in PROXY_CASES]
    try:
        r = subprocess.run([node, "-e", harness, str(ext / "common.js"), json.dumps(cases)],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0:
            err("node-validators", f"harness failed: {r.stderr.strip()[:300]}")
        else:
            for e in json.loads(r.stdout or "[]"):
                err("node-validators", e)
    except (OSError, ValueError, subprocess.TimeoutExpired) as e:
        err("node-validators", f"could not run: {e}")
else:
    print("note: node not found; validator behaviour checked against the allowlist table only")

if errs:
    print("EXT-LINT FAIL"); [print(" -", e) for e in errs]; sys.exit(1)
print("EXT-LINT PASS")
