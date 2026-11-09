#!/usr/bin/env python3
"""`just ui-e2e`: E-80 (snapshot opened offline in a headless browser).

Builds a snapshot with the real proxy and client from a local origin whose page has a stylesheet (green
background), an image (blue) and a script that would paint the page red. The saved snapshot is opened in
headless Chromium with every host name unresolvable and a screenshot is decoded: green proves the local
CSS loaded under the snapshot CSP, blue proves the local image loaded, no red proves no script ran.
Firefox runs the same check when installed. Exit 2 (SKIP) when no browser is available.
Stdlib only (D-29); loopback only.
"""
import http.server
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "release"
WIN_CHROME = Path("/mnt/c/Program Files/Google/Chrome/Application/chrome.exe")


def png(rgb, w=8, h=8):
    raw = b"".join(b"\0" + bytes(rgb) * w for _ in range(h))
    chunk = lambda t, d: struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)) + \
        chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def decode_png(data):
    """Return (width, height, pixel(x, y) -> (r, g, b)) for 8-bit RGB/RGBA PNGs."""
    pos, idat, w, h, bpp = 8, b"", 0, 0, 3
    while pos < len(data):
        n, t = struct.unpack(">I4s", data[pos:pos + 8])
        body = data[pos + 8:pos + 8 + n]
        if t == b"IHDR":
            w, h, depth, ctype = struct.unpack(">IIBB", body[:10])
            assert depth == 8 and ctype in (2, 6), (depth, ctype)
            bpp = 3 if ctype == 2 else 4
        elif t == b"IDAT":
            idat += body
        pos += 12 + n
    raw, stride, rows, prev = zlib.decompress(idat), w * bpp, [], bytearray(w * bpp)
    for y in range(h):
        f, line = raw[y * (stride + 1)], bytearray(raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)])
        for i in range(stride):
            a = line[i - bpp] if i >= bpp else 0
            b, c = prev[i], prev[i - bpp] if i >= bpp else 0
            if f == 1:
                line[i] = (line[i] + a) & 255
            elif f == 2:
                line[i] = (line[i] + b) & 255
            elif f == 3:
                line[i] = (line[i] + (a + b) // 2) & 255
            elif f == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                line[i] = (line[i] + (a if pa <= pb and pa <= pc else b if pb <= pc else c)) & 255
        rows.append(line)
        prev = line
    return w, h, lambda x, y: tuple(rows[y][x * bpp:x * bpp + 3])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port):
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.1)
    raise SystemExit(f"port {port} never opened")


def browsers():
    found = []
    for name in ("chromium", "chromium-browser", "google-chrome"):
        if shutil.which(name):
            found.append(("chromium", [shutil.which(name)], False))
            break
    else:
        if WIN_CHROME.exists():
            found.append(("chromium", [str(WIN_CHROME)], True))
    if shutil.which("firefox"):
        found.append(("firefox", [shutil.which("firefox")], False))
    return found


def winpath(p):
    return subprocess.run(["wslpath", "-w", str(p)], capture_output=True, text=True, check=True).stdout.strip()


def main():
    found = browsers()
    if not found:
        print("no headless browser (chromium/chrome/firefox)")
        return 2
    subprocess.run(["cargo", "build", "--quiet", "--release", "--locked", "--bin", "webfilter-proxy",
                    "--bin", "webfilter-client"], cwd=ROOT, check=True)
    work = Path(tempfile.mkdtemp())
    site = work / "site"
    site.mkdir()
    (site / "index.html").write_text(
        '<!doctype html><html><head><link rel="stylesheet" href="style.css"></head><body>'
        '<img src="blue.png" width="300" height="300" style="position:absolute;left:400px;top:50px">'
        "<script>document.documentElement.style.background='#ff0000';"
        "document.body.style.background='#ff0000'</script></body></html>")
    (site / "style.css").write_text("html,body{margin:0;background:#00ff00;height:100%}")
    (site / "blue.png").write_bytes(png((0, 0, 255)))
    origin_port, proxy_port = free_port(), free_port()
    handler = lambda *a: http.server.SimpleHTTPRequestHandler(*a, directory=str(site))
    http.server.SimpleHTTPRequestHandler.log_message = lambda *a: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", origin_port), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    lab = work / "lab"
    (lab / "blocklists").mkdir(parents=True)
    for f in ("domains", "url_patterns", "ip_blocklist"):
        (lab / "blocklists" / f"{f}.txt").write_text("")
    (lab / "config.toml").write_text(
        f'listen = "127.0.0.1:{proxy_port}"\n[ports]\nhttp_allowed = "any"\nconnect_allowed = "any"\n'
        f'[destination]\ndeny_private_ranges = false\n[logging]\ndir = "{lab}/logs"\n')
    proxy = subprocess.Popen([TARGET / "webfilter-proxy", "--config", lab / "config.toml", "run"],
                             stderr=subprocess.DEVNULL)
    fail = 0
    try:
        wait_port(proxy_port)
        out = work / "out"
        url = f"http://127.0.0.1:{origin_port}/index.html"
        r = subprocess.run([TARGET / "webfilter-client", "--proxy", f"http://127.0.0.1:{proxy_port}",
                            "--out-dir", out, "--snapshot", "--json", url], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr
        res = json.loads(r.stdout)
        page = Path(res["saved_path"])
        html = page.read_text()
        assert "<script" not in html and "http://" not in html and "Content-Security-Policy" in html, html
        for name, cmd, windows in found:
            view = page
            if windows:  # a Windows browser needs the snapshot on a Windows path
                dst = Path(f"/mnt/c/Users/{os.environ.get('WIN_USER', 'SRLAB-611')}/AppData/Local/Temp/wf-e80")
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(page.parent, dst)
                view = dst / page.name
            shot = view.parent / f"shot-{name}.png"
            p = lambda x: winpath(x) if windows else str(x)
            if name == "chromium":
                args = cmd + ["--headless=new", "--disable-gpu", "--no-first-run", "--disable-extensions",
                              "--disable-background-networking", "--host-resolver-rules=MAP * ~NOTFOUND",
                              f"--user-data-dir={p(view.parent / 'profile')}", "--window-size=800,600",
                              f"--screenshot={p(shot)}", "file:///" + p(view).replace("\\", "/")]
            else:
                args = cmd + ["--headless", "--screenshot", str(shot), "--window-size=800,600", view.as_uri()]
            subprocess.run(args, capture_output=True, timeout=90)
            w, h, px = decode_png(shot.read_bytes())
            bg, img = px(50, 300), px(550, 200)
            ok = bg[1] > 200 and bg[0] < 60 and img[2] > 200 and img[0] < 60
            red = any(px(x, y)[0] > 200 and px(x, y)[1] < 60 for x in range(0, w, 40) for y in range(0, h, 40))
            print(f"{'PASS' if ok and not red else 'FAIL'}  E-80 {name}: background {bg} (green = CSS), "
                  f"image {img} (blue = image), script ran: {red}")
            fail |= not ok or red
    finally:
        proxy.terminate()
        srv.shutdown()
        shutil.rmtree(work, ignore_errors=True)
        win = Path(f"/mnt/c/Users/{os.environ.get('WIN_USER', 'SRLAB-611')}/AppData/Local/Temp/wf-e80")
        shutil.rmtree(win, ignore_errors=True)
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
