#!/usr/bin/env python3
"""Stress-test helpers for scripts/stress.sh (A-40). Stdlib only, Python >= 3.10. Loopback lab use only.

Every client subcommand prints one JSON line on stdout.

  origin     HTTP/1.1 origin on a fixed port: GET / (small page), GET /big?mb=N (deterministic body),
             POST /upload (answers the body's sha256). Prints the port, serves until killed.
  churn      many short connections (Connection: close) through the proxy
  slowloris  N sockets trickling a request head byte by byte; reports when the proxy closes them
  bigbody    N MiB download and upload through the proxy, sha256 compared on both sides
  ratelimit  a burst from one client id, then one request from each of many client ids
             (distinct 127.x.y.z source addresses = distinct client ids)
  h2         intercepted HTTP/2 through the proxy (CONNECT + TLS + ALPN h2): healthy traffic or a flood
             (rapid_reset, control, continuation). Exit 3 when h2 cannot be negotiated.
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures
import errno
import hashlib
import json
import selectors
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MIB = 1 << 20
_BLOCK = bytes((i * 31 + 7) & 0xFF for i in range(MIB))
SMALL = b"<html><body>stress origin</body></html>"


def chunk(i: int) -> bytes:
    """MiB number `i` of a deterministic body (each MiB differs, so reordering is detected)."""
    return i.to_bytes(8, "big") + _BLOCK[8:]


def expected_sha256(mb: int) -> str:
    h = hashlib.sha256()
    for i in range(mb):
        h.update(chunk(i))
    return h.hexdigest()


def emit(obj: dict) -> None:
    print(json.dumps(obj), flush=True)


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    return round(s[min(int(len(s) * p), len(s) - 1)] * 1000, 3)


def hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


# ---------------------------------------------------------------- origin


class _Origin(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:  # quiet
        pass

    def do_GET(self) -> None:
        u = urllib.parse.urlsplit(self.path)
        if u.path == "/big":
            q = urllib.parse.parse_qs(u.query)
            try:
                mb = max(1, min(4096, int(q.get("mb", ["1"])[0])))
            except ValueError:
                mb = 1
            self.send_response(200)
            self.send_header("content-type", "application/octet-stream")
            self.send_header("content-length", str(mb * MIB))
            self.end_headers()
            for i in range(mb):
                self.wfile.write(chunk(i))
            return
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.send_header("content-length", str(len(SMALL)))
        self.end_headers()
        self.wfile.write(SMALL)

    def do_POST(self) -> None:
        try:
            left = int(self.headers.get("content-length", "0"))
        except ValueError:
            left = -1
        if left < 0:
            self.send_error(400)
            return
        h = hashlib.sha256()
        while left > 0:
            data = self.rfile.read(min(left, MIB))
            if not data:
                return
            h.update(data)
            left -= len(data)
        body = h.hexdigest().encode()
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def cmd_origin(a: argparse.Namespace) -> None:
    ThreadingHTTPServer.allow_reuse_address = True
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), _Origin)
    srv.daemon_threads = True
    print(srv.server_address[1], flush=True)
    srv.serve_forever()


# ---------------------------------------------------------------- HTTP/1 via the proxy


def connect(proxy: tuple[str, int], source: str | None, timeout: float) -> socket.socket:
    src = (source, 0) if source else None
    s = socket.create_connection(proxy, timeout=timeout, source_address=src)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def send_get(s: socket.socket, url: str, close: bool) -> None:
    host = urllib.parse.urlsplit(url).netloc
    conn = "Connection: close\r\n" if close else ""
    s.sendall(f"GET {url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: stress\r\n{conn}\r\n".encode())


class Reader:
    """Buffered response reader (Content-Length, chunked, or close-delimited bodies)."""

    def __init__(self, s: socket.socket):
        self.s, self.buf = s, b""

    def _fill(self) -> bool:
        data = self.s.recv(MIB)
        if not data:
            return False
        self.buf += data
        return True

    def _line(self) -> bytes:
        while b"\r\n" not in self.buf:
            if not self._fill():
                raise EOFError("eof in line")
        line, _, self.buf = self.buf.partition(b"\r\n")
        return line

    def _take(self, n: int, sink) -> None:
        while n > 0:
            if not self.buf and not self._fill():
                raise EOFError("eof in body")
            part, self.buf = self.buf[:n], self.buf[n:]
            n -= len(part)
            if sink:
                sink(part)

    def response(self, sink=None) -> tuple[int, dict[str, str]]:
        while b"\r\n\r\n" not in self.buf:
            if len(self.buf) > 65536 or not self._fill():
                raise EOFError("eof in head")
        head, _, self.buf = self.buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        status = int(lines[0].split(" ", 2)[1])
        hdrs: dict[str, str] = {}
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            hdrs[k.strip().lower()] = v.strip()
        if "chunked" in hdrs.get("transfer-encoding", "").lower():
            while True:
                size = int(self._line().split(b";")[0], 16)
                if size == 0:
                    while self._line():
                        pass
                    break
                self._take(size, sink)
                self._line()
        elif "content-length" in hdrs:
            self._take(int(hdrs["content-length"]), sink)
        elif status not in (204, 304):
            while True:
                if self.buf and sink:
                    sink(self.buf)
                self.buf = b""
                if not self._fill():
                    break
        return status, hdrs


def one_get(proxy, url, source, timeout) -> tuple[int, dict[str, str]]:
    s = connect(proxy, source, timeout)
    try:
        send_get(s, url, close=True)
        return Reader(s).response()
    finally:
        s.close()


CLIENT_ERRNOS = {errno.EADDRNOTAVAIL, errno.EADDRINUSE, errno.EMFILE, errno.ENFILE}


def cmd_churn(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    sources = [f"127.0.{a.source_net}.{i}" for i in range(1, a.sources + 1)] if a.sources else [None]
    end = time.monotonic() + a.secs
    lock = threading.Lock()
    tot = {"ok": 0, "errors": 0, "client_errors": 0}
    statuses: collections.Counter = collections.Counter()
    lats: list[float] = []

    def worker(i: int) -> None:
        ok = err = cerr = 0
        st: collections.Counter = collections.Counter()
        lat: list[float] = []
        interval = a.threads / a.rate if a.rate else 0.0
        nxt = time.monotonic() + interval * i / a.threads
        k = i
        while time.monotonic() < end:
            if interval:
                d = nxt - time.monotonic()
                if d > 0:
                    time.sleep(d)
                nxt += interval
            src = sources[k % len(sources)]
            k += a.threads
            t0 = time.monotonic()
            try:
                status, _ = one_get(proxy, a.url, src, a.timeout)
            except OSError as e:
                if e.errno in CLIENT_ERRNOS:
                    cerr += 1
                    time.sleep(0.01)
                else:
                    err += 1
                continue
            except (EOFError, ValueError, IndexError):
                err += 1
                continue
            st[status] += 1
            if status == a.expect:
                ok += 1
                lat.append(time.monotonic() - t0)
            else:
                err += 1
        with lock:
            tot["ok"] += ok
            tot["errors"] += err
            tot["client_errors"] += cerr
            statuses.update(st)
            lats.extend(lat)

    t0 = time.monotonic()
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(a.threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    el = time.monotonic() - t0
    emit({**tot, "conns_per_sec": round(tot["ok"] / el, 1), "p50_ms": pct(lats, 0.5),
          "p99_ms": pct(lats, 0.99), "statuses": {str(k): v for k, v in statuses.items()}})


# ---------------------------------------------------------------- slowloris


def cmd_slowloris(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    host = urllib.parse.urlsplit(a.url).netloc
    head = f"GET {a.url} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: slowloris\r\n".encode()
    filler = b"X-Slow: aaaaaaaaaaaaaaaa\r\n"  # the head is never terminated
    sel = selectors.DefaultSelector()
    state: dict[socket.socket, list] = {}  # sock -> [opened_at, bytes_sent]
    counts = {"opened": 0, "refused": 0}
    end = time.monotonic() + a.secs

    def open_one() -> None:
        try:
            s = connect(proxy, a.source, 5)
        except OSError:
            counts["refused"] += 1
            return
        s.setblocking(False)
        sel.register(s, selectors.EVENT_READ)
        state[s] = [time.monotonic(), 0]
        counts["opened"] += 1

    for _ in range(a.n):
        open_one()
    closed_after: list[float] = []
    answered: collections.Counter = collections.Counter()

    def close(s: socket.socket, how: str) -> None:
        closed_after.append(time.monotonic() - state[s][0])
        answered[how] += 1
        sel.unregister(s)
        s.close()
        del state[s]
        if a.reopen and time.monotonic() < end - 1:
            open_one()  # keep the slow-socket pressure at N for the whole run

    next_send = time.monotonic()
    while state and time.monotonic() < end:
        now = time.monotonic()
        if now >= next_send:
            for s in list(state):
                n = state[s][1]
                b = head[n:n + 1] if n < len(head) else filler[(n - len(head)) % len(filler):][:1]
                try:
                    s.send(b)
                    state[s][1] += 1
                except BlockingIOError:
                    pass
                except OSError:
                    close(s, "send_error")
            next_send = now + a.interval
        for key, _ in sel.select(timeout=max(0.0, min(next_send, end) - time.monotonic())):
            s = key.fileobj
            if s not in state:
                continue
            try:
                data = s.recv(4096)
            except BlockingIOError:
                continue
            except OSError:
                close(s, "reset")
                continue
            if not data:
                close(s, "eof")
            else:
                line = data.split(b"\r\n", 1)[0].decode("latin-1", "replace")
                close(s, line[:32] or "data")
    still_open = len(state)
    for s in list(state):
        s.close()
    emit({"initial": a.n, **counts, "closed_by_proxy": len(closed_after),
          "still_open": still_open, "median_close_s": round(sorted(closed_after)[len(closed_after) // 2], 2)
          if closed_after else None, "max_close_s": round(max(closed_after), 2) if closed_after else None,
          "how": dict(answered)})


# ---------------------------------------------------------------- big bodies


def cmd_bigbody(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    base = a.url.rstrip("/")
    host = urllib.parse.urlsplit(base).netloc
    want = expected_sha256(a.mb)
    res: dict = {"mb": a.mb, "expected_sha256": want}

    s = connect(proxy, None, a.timeout)
    t0 = time.monotonic()
    h = hashlib.sha256()
    n = [0]

    def sink(b: bytes) -> None:
        h.update(b)
        n[0] += len(b)

    try:
        send_get(s, f"{base}/big?mb={a.mb}", close=True)
        status, _ = Reader(s).response(sink)
        res.update(download_status=status, download_bytes=n[0], download_sha256=h.hexdigest())
    except (OSError, EOFError, ValueError, IndexError) as e:
        res.update(download_status=None, download_error=repr(e)[:200])
    finally:
        s.close()
    dt = time.monotonic() - t0
    res["download_s"] = round(dt, 2)
    res["download_ok"] = res.get("download_sha256") == want and n[0] == a.mb * MIB

    s = connect(proxy, None, a.timeout)
    t0 = time.monotonic()
    try:
        s.sendall(f"POST {base}/upload HTTP/1.1\r\nHost: {host}\r\nUser-Agent: stress\r\n"
                  f"Content-Type: application/octet-stream\r\nContent-Length: {a.mb * MIB}\r\n"
                  "Connection: close\r\n\r\n".encode())
        for i in range(a.mb):
            s.sendall(chunk(i))
        got = bytearray()
        status, _ = Reader(s).response(got.extend)
        res.update(upload_status=status, upload_sha256=got.decode("ascii", "replace").strip())
    except (OSError, EOFError, ValueError, IndexError) as e:
        res.update(upload_status=None, upload_error=repr(e)[:200])
    finally:
        s.close()
    res["upload_s"] = round(time.monotonic() - t0, 2)
    res["upload_ok"] = res.get("upload_sha256") == want
    emit(res)


# ---------------------------------------------------------------- rate limits


def cmd_ratelimit(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    burst: collections.Counter = collections.Counter()
    retry_ok = retry_bad = burst_err = 0
    s = None
    rd = None
    for _ in range(a.burst):
        try:
            if s is None:
                s = connect(proxy, a.burst_source, a.timeout)
                rd = Reader(s)
            send_get(s, a.url, close=False)
            status, hdrs = rd.response()
        except (OSError, EOFError, ValueError, IndexError):
            burst_err += 1
            if s:
                s.close()
            s = None
            continue
        burst[status] += 1
        if status == 429:
            if hdrs.get("retry-after", "").isdigit():
                retry_ok += 1
            else:
                retry_bad += 1
        if hdrs.get("connection", "").lower() == "close":
            s.close()
            s = None
    if s:
        s.close()

    ids: collections.Counter = collections.Counter()
    id_err = [0]
    lock = threading.Lock()
    t0 = time.monotonic()

    def one(k: int) -> None:
        src = f"127.{a.id_net + k // 62500}.{(k // 250) % 250}.{k % 250 + 1}"
        try:
            status, _ = one_get(proxy, a.url, src, a.timeout)
        except (OSError, EOFError, ValueError, IndexError):
            with lock:
                id_err[0] += 1
            return
        with lock:
            ids[status] += 1

    with concurrent.futures.ThreadPoolExecutor(a.threads) as ex:
        list(ex.map(one, range(a.ids)))
    emit({"burst": {str(k): v for k, v in burst.items()}, "burst_errors": burst_err,
          "retry_after_ok": retry_ok, "retry_after_bad": retry_bad, "ids": a.ids,
          "id_statuses": {str(k): v for k, v in ids.items()}, "id_errors": id_err[0],
          "id_phase_s": round(time.monotonic() - t0, 2)})


# ---------------------------------------------------------------- HTTP/2 (intercepted)

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
DATA, HEADERS, RST, SETTINGS, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = 0, 1, 3, 4, 6, 7, 8, 9
END_STREAM, ACK, END_HEADERS, PADDED, PRIORITY_F = 0x1, 0x1, 0x4, 0x8, 0x20
STATUS_BY_INDEX = {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}


class NoH2(Exception):
    pass


def frame(kind: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", sid) + payload


def hp_int(v: int, bits: int, first: int = 0) -> bytes:
    lim = (1 << bits) - 1
    if v < lim:
        return bytes([first | v])
    out = bytearray([first | lim])
    v -= lim
    while v >= 128:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def hp_lit(name: str, value: str) -> bytes:
    """Literal header field without indexing, new name, no Huffman (RFC 7541 6.2.2)."""
    n, v = name.encode(), value.encode()
    return b"\x00" + hp_int(len(n), 7) + n + hp_int(len(v), 7) + v


def request_block(authority: str, path: str = "/") -> bytes:
    return (hp_lit(":method", "GET") + hp_lit(":scheme", "https") + hp_lit(":authority", authority)
            + hp_lit(":path", path) + hp_lit("user-agent", "stress-h2"))


def first_status(block: bytes) -> int | None:
    """`:status` from the first field when it is a static-table entry (enough for 200)."""
    i = 0
    while i < len(block) and block[i] & 0xE0 == 0x20:  # dynamic table size update
        i += 1
        if block[i - 1] & 0x1F == 0x1F:
            while i < len(block) and block[i] & 0x80:
                i += 1
            i += 1
    if i < len(block) and block[i] & 0x80:
        return STATUS_BY_INDEX.get(block[i] & 0x7F)
    return None


class H2:
    def __init__(self, proxy, authority: str, ca: str, timeout: float):
        host = authority.rpartition(":")[0]
        s = connect(proxy, None, timeout)
        s.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode())
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = s.recv(4096)
            if not d:
                raise EOFError("CONNECT eof")
            buf += d
        if not buf.startswith(b"HTTP/1.1 200"):
            raise EOFError("CONNECT refused: " + buf.split(b"\r\n")[0].decode("latin-1"))
        ctx = ssl.create_default_context(cafile=ca)
        ctx.set_alpn_protocols(["h2"])
        self.s = ctx.wrap_socket(s, server_hostname=host)
        if self.s.selected_alpn_protocol() != "h2":
            self.s.close()
            raise NoH2(f"ALPN {self.s.selected_alpn_protocol()!r}")
        self.buf = b""
        self.s.sendall(PREFACE + frame(SETTINGS, 0, 0))

    def send(self, data: bytes) -> None:
        self.s.sendall(data)

    def recv_frame(self, timeout: float):
        """One frame, None on timeout; EOFError when the peer closed."""
        deadline = time.monotonic() + timeout
        while True:
            if len(self.buf) >= 9:
                ln = int.from_bytes(self.buf[:3], "big")
                if len(self.buf) >= 9 + ln:
                    kind, flags = self.buf[3], self.buf[4]
                    sid = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
                    payload, self.buf = self.buf[9:9 + ln], self.buf[9 + ln:]
                    return kind, flags, sid, payload
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            self.s.settimeout(left)
            try:
                d = self.s.recv(65536)
            except (socket.timeout, ssl.SSLWantReadError):
                return None
            except OSError as e:
                raise EOFError(repr(e)) from e
            if not d:
                raise EOFError("eof")
            self.buf += d

    def housekeeping(self, kind: int, flags: int, sid: int, payload: bytes) -> None:
        if kind == SETTINGS and not flags & ACK:
            self.send(frame(SETTINGS, ACK, 0))
        elif kind == PING and not flags & ACK:
            self.send(frame(PING, ACK, 0, payload))
        elif kind == DATA and payload:
            self.send(frame(WINDOW_UPDATE, 0, 0, struct.pack(">I", len(payload))))

    def close(self) -> None:
        try:
            self.s.close()
        except OSError:
            pass


def header_payload(flags: int, payload: bytes) -> bytes:
    if flags & PADDED and payload:
        pad = payload[0]
        payload = payload[1:len(payload) - pad]
    if flags & PRIORITY_F:
        payload = payload[5:]
    return payload


def h2_healthy(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    end = time.monotonic() + a.secs
    lock = threading.Lock()
    tot = collections.Counter()
    lats: list[float] = []

    def worker() -> None:
        c = None
        sid = 1
        lat: list[float] = []
        cnt = collections.Counter()
        while time.monotonic() < end:
            if c is None:
                try:
                    c = H2(proxy, a.authority, a.ca, a.timeout)
                except NoH2:
                    cnt["no_h2"] += 1
                    break
                except (OSError, EOFError, ssl.SSLError):
                    cnt["errors"] += 1
                    time.sleep(0.05)
                    continue
                sid = 1
            t0 = time.monotonic()
            outcome = None
            retire = False
            try:
                c.send(frame(HEADERS, END_STREAM | END_HEADERS, sid, request_block(a.authority)))
                status = None
                while outcome is None:
                    f = c.recv_frame(a.timeout)
                    if f is None:
                        outcome = "error"
                        break
                    kind, flags, fsid, payload = f
                    c.housekeeping(kind, flags, fsid, payload)
                    if kind == GOAWAY:
                        last = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                        code = int.from_bytes(payload[4:8], "big")
                        if code != 0:
                            outcome = "error"
                        elif last < sid:
                            outcome = "retry"  # graceful: this stream was not processed
                        else:
                            retire = True  # graceful: finish this stream, then reconnect
                        continue
                    if fsid != sid:
                        continue
                    if kind == HEADERS:
                        status = status or first_status(header_payload(flags, payload))
                    elif kind == RST:
                        outcome = "error"
                    if outcome is None and kind in (HEADERS, DATA) and flags & END_STREAM:
                        outcome = "ok" if status == 200 else "error"
            except (OSError, EOFError, ssl.SSLError):
                outcome = "error"
            if outcome == "ok":
                cnt["ok"] += 1
                lat.append(time.monotonic() - t0)
            elif outcome == "error":
                cnt["errors"] += 1
            if outcome != "ok" or retire or sid >= a.max_streams:
                c.close()
                c = None
            sid += 2
        if c:
            c.close()
        with lock:
            tot.update(cnt)
            lats.extend(lat)

    t0 = time.monotonic()
    ts = [threading.Thread(target=worker) for _ in range(a.conns)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if tot["no_h2"]:
        emit({"mode": "healthy", "error": "h2 not negotiated"})
        sys.exit(3)
    el = time.monotonic() - t0
    emit({"mode": "healthy", "ok": tot["ok"], "errors": tot["errors"], "rps": round(tot["ok"] / el, 1),
          "p50_ms": pct(lats, 0.5), "p99_ms": pct(lats, 0.99)})


def h2_flood(a: argparse.Namespace) -> None:
    proxy = hostport(a.proxy)
    try:
        c = H2(proxy, a.authority, a.ca, a.timeout)
    except NoH2 as e:
        emit({"mode": a.mode, "error": f"h2 not negotiated: {e}"})
        sys.exit(3)
    except (OSError, EOFError, ssl.SSLError) as e:
        emit({"mode": a.mode, "error": repr(e)[:200], "goaway": False, "closed": False})
        return
    res = {"mode": a.mode, "sent_frames": 0, "goaway": False, "goaway_code": None, "closed": False}
    t0 = time.monotonic()

    def drain(timeout: float) -> bool:
        """Read what is there; True once the proxy sent GOAWAY or closed."""
        while True:
            try:
                f = c.recv_frame(timeout)
            except EOFError:
                res["closed"] = True
                return True
            if f is None:
                return False
            kind, flags, sid, payload = f
            if kind == GOAWAY:
                res["goaway"] = True
                res["goaway_code"] = int.from_bytes(payload[4:8], "big")
                return True
            try:
                c.housekeeping(kind, flags, sid, payload)
            except OSError:
                res["closed"] = True
                return True
            timeout = 0.0

    if a.mode == "continuation":
        frames = [frame(HEADERS, 0, 1, request_block(a.authority))]
        frames += [frame(CONTINUATION, 0, 1, hp_lit(f"x-c{i}", "1")) for i in range(a.count)]
    elif a.mode == "control":
        frames = [frame(PING, 0, 0, struct.pack(">Q", i)) for i in range(a.count)]
    else:  # rapid_reset
        frames = []
        for i in range(a.count):
            sid = 2 * i + 1
            frames.append(frame(HEADERS, END_HEADERS, sid, request_block(a.authority))
                          + frame(RST, 0, sid, struct.pack(">I", 8)))  # CANCEL
    done = False
    for i in range(0, len(frames), 20):
        try:
            c.send(b"".join(frames[i:i + 20]))
            res["sent_frames"] += len(frames[i:i + 20])
        except OSError:
            res["closed"] = True
            done = True
            break
        if drain(0.0):
            done = True
            break
    if not done:
        end = time.monotonic() + a.wait
        while time.monotonic() < end and not drain(0.5):
            pass
    res["secs"] = round(time.monotonic() - t0, 2)
    c.close()
    emit(res)


def cmd_h2(a: argparse.Namespace) -> None:
    (h2_healthy if a.mode == "healthy" else h2_flood)(a)


# ---------------------------------------------------------------- RSS/fd samples


def cmd_samples(a: argparse.Namespace) -> None:
    """Judge `<unix> <rss_kb> <fds>` samples: peak RSS, growth after warm-up, fd spread. Exit 1 when out of bounds."""
    rows = []
    with open(a.file, encoding="ascii") as f:
        for line in f:
            parts = line.split()
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                rows.append(tuple(int(p) for p in parts))
    if not rows:
        emit({"samples": 0, "ok": False})
        sys.exit(1)
    base = a.base_kb if a.base_kb is not None else rows[0][1]
    peak = max(r[1] for r in rows)
    steady = rows[a.skip:] if len(rows) > a.skip + 1 else rows
    rss_first, rss_last = steady[0][1], steady[-1][1]
    fd_spread = max(r[2] for r in steady) - min(r[2] for r in steady)
    ok = peak <= a.max_mb * 1024
    if a.growth_mb is not None:
        ok = ok and peak - base <= a.growth_mb * 1024
    if a.stable:
        ok = ok and rss_last <= rss_first * 1.2 + 10240 and fd_spread <= a.fd_tol
    emit({"samples": len(rows), "base_rss_mb": round(base / 1024, 1), "peak_rss_mb": round(peak / 1024, 1),
          "steady_first_mb": round(rss_first / 1024, 1), "steady_last_mb": round(rss_last / 1024, 1),
          "fd_min": min(r[2] for r in steady), "fd_max": max(r[2] for r in steady), "fd_spread": fd_spread,
          "ok": ok})
    sys.exit(0 if ok else 1)


# ---------------------------------------------------------------- CLI


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("origin")
    o.add_argument("--port", type=int, default=0)
    o.set_defaults(fn=cmd_origin)

    c = sub.add_parser("churn")
    c.add_argument("--proxy", required=True)
    c.add_argument("--url", required=True)
    c.add_argument("--threads", type=int, default=32)
    c.add_argument("--secs", type=float, default=30)
    c.add_argument("--rate", type=float, default=0, help="total connections/s (0 = as fast as possible)")
    c.add_argument("--expect", type=int, default=200)
    c.add_argument("--sources", type=int, default=0, help="spread over 127.0.NET.1..N source addresses")
    c.add_argument("--source-net", type=int, default=2)
    c.add_argument("--timeout", type=float, default=10)
    c.set_defaults(fn=cmd_churn)

    s = sub.add_parser("slowloris")
    s.add_argument("--proxy", required=True)
    s.add_argument("--url", required=True)
    s.add_argument("--n", type=int, default=500)
    s.add_argument("--secs", type=float, default=40)
    s.add_argument("--interval", type=float, default=1.0)
    s.add_argument("--source", default=None)
    s.add_argument("--reopen", action="store_true", help="replace every closed socket (constant pressure)")
    s.set_defaults(fn=cmd_slowloris)

    b = sub.add_parser("bigbody")
    b.add_argument("--proxy", required=True)
    b.add_argument("--url", required=True, help="origin base URL, e.g. http://127.0.0.1:18190")
    b.add_argument("--mb", type=int, default=200)
    b.add_argument("--timeout", type=float, default=120)
    b.set_defaults(fn=cmd_bigbody)

    r = sub.add_parser("ratelimit")
    r.add_argument("--proxy", required=True)
    r.add_argument("--url", required=True)
    r.add_argument("--burst", type=int, default=300)
    r.add_argument("--burst-source", default="127.0.3.1")
    r.add_argument("--ids", type=int, default=10000)
    r.add_argument("--id-net", type=int, default=20)
    r.add_argument("--threads", type=int, default=64)
    r.add_argument("--timeout", type=float, default=10)
    r.set_defaults(fn=cmd_ratelimit)

    h = sub.add_parser("h2")
    h.add_argument("--proxy", required=True)
    h.add_argument("--authority", required=True, help="origin host:port as named in CONNECT")
    h.add_argument("--ca", required=True, help="proxy CA PEM")
    h.add_argument("--mode", choices=["healthy", "rapid_reset", "control", "continuation"], default="healthy")
    h.add_argument("--conns", type=int, default=4)
    h.add_argument("--secs", type=float, default=20)
    h.add_argument("--count", type=int, default=1000, help="flood size (streams / frames)")
    h.add_argument("--wait", type=float, default=15, help="seconds to wait for GOAWAY after a flood")
    h.add_argument("--max-streams", type=int, default=2001, help="healthy: reconnect after this stream id")
    h.add_argument("--timeout", type=float, default=10)
    h.set_defaults(fn=cmd_h2)

    m = sub.add_parser("samples")
    m.add_argument("file")
    m.add_argument("--max-mb", type=int, default=300, help="peak RSS bound")
    m.add_argument("--growth-mb", type=int, default=None, help="peak minus base bound")
    m.add_argument("--base-kb", type=int, default=None, help="base RSS (default: first sample)")
    m.add_argument("--stable", action="store_true", help="also require flat RSS and fds after warm-up")
    m.add_argument("--skip", type=int, default=2, help="warm-up samples ignored by --stable")
    m.add_argument("--fd-tol", type=int, default=64)
    m.set_defaults(fn=cmd_samples)

    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
