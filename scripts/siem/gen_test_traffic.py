#!/usr/bin/env python3
"""Deterministic labelled dataset for detection tests (S-02, S-03, PT-5.5).

Writes LOG_SCHEMA-complete events to OUT/webfilter*.jsonl plus OUT/expected.json (the alerts every
non-report detection must raise, and nothing else). Scenarios: benign baseline, beaconing,
DGA-like hostnames, high block rate, smuggling/SSRF/auth bursts, TLS anomalies, encoding evasion,
pipeline health and the v1.1 feature events.

  gen_test_traffic.py OUT [--seed N] [--end 2026-10-31T12:00:00.000Z]
"""
import argparse
import json
import random
import string
import uuid
from datetime import timedelta
from pathlib import Path

from common import fmt_ts, parse_ts, request_fields

POPULAR = [f"site{i}.example" for i in range(30)]


class Gen:
    def __init__(self, seed, end):
        self.rng, self.end = random.Random(seed), end
        self.fields = request_fields()
        self.files = {"webfilter.jsonl": [], "webfilter_system.jsonl": [],
                      "webfilter_access.jsonl": [], "webfilter_admin.jsonl": []}
        self.expected = []

    def at(self, mins_ago):
        return fmt_ts(self.end - timedelta(minutes=mins_ago))

    def request(self, when, src, host, **kw):
        e = dict.fromkeys(self.fields)
        path = kw.pop("path", "/")
        e.update(timestamp=when, event_id=str(uuid.UUID(int=self.rng.getrandbits(128))), event_type="request",
                 src_ip=src, src_port=self.rng.randint(1024, 65535), http_method="GET",
                 url=f"https://{host}{path}", url_scheme="https", dest_host=host, dest_ip="203.0.113.10",
                 dest_port=443, uri_path=path, uri_query_keys=[], status=200, action="allowed",
                 would_block=False, reason="none", http_version="1.1", bytes_in=1200, bytes_out=300,
                 duration_ms=40, tls_intercepted=True, tls_sni=host, ech_present=False, alpn="http/1.1",
                 transparent=False, suspicious_encoding=False, throttled=False, proxy_mode="enforce")
        if kw.get("action") == "blocked":
            e.update(status=403, bytes_in=0)
        e.update(kw)
        self.files["webfilter.jsonl"].append(e)

    def system(self, when, kind, **detail):
        self.files["webfilter_system.jsonl"].append(
            {"timestamp": when, "event_type": "system", "kind": kind, "detail": detail})

    def expect(self, det_id, **group):
        self.expected.append({"id": det_id, "group": group})

    def baseline(self):
        for i in range(2000):
            src = f"10.1.0.{self.rng.randint(1, 40)}"
            blocked = self.rng.random() < 0.02
            self.request(self.at(self.rng.uniform(0, 230)), src, self.rng.choice(POPULAR),
                         path=f"/p{self.rng.randint(1, 50)}",
                         **({"action": "blocked", "reason": "domain_blocklist", "rule_id": "domain:ads.example",
                             "rule_list": "domains.txt"} if blocked else {}))

    def attacks(self):
        r = self.request
        for i in range(40):  # beacon: 30 s +/- 1 s
            r(self.at(25 - i * 0.5 + self.rng.uniform(-1, 1) / 60), "10.9.0.1", "c2-beacon.test")
        self.expect("WF-03", src_ip="10.9.0.1", dest_host="c2-beacon.test")
        for _ in range(5):
            host = "".join(self.rng.choices(string.ascii_lowercase + string.digits, k=45)) + ".test"
            r(self.at(self.rng.uniform(0, 600)), "10.9.0.2", host)
            self.expect("WF-04", dest_host=host)
        for i in range(60):
            blocked = i < 50
            r(self.at(10 + i / 60), "10.9.0.3", "casino.test" if blocked else "site1.example",
              **({"action": "blocked", "reason": "domain_blocklist", "rule_id": "domain:casino.test"} if blocked else {}))
        self.expect("WF-02", src_ip="10.9.0.3")
        bursts = [("10.9.0.4", ["invalid_request"] * 8 + ["parser_differential"] * 2, 400, "WF-05"),
                  ("10.9.0.5", ["private_range"] * 5 + ["port_not_allowed"] * 2, 403, "WF-06")]
        for src, reasons, status, det in bursts:
            for i, reason in enumerate(reasons):
                r(self.at(20 + i / 10), src, "internal.test", action="blocked", reason=reason, status=status)
            self.expect(det, src_ip=src)
        self.expect("WF-02", src_ip="10.9.0.4")  # 10 blocked of 10; the SSRF burst (7) stays below min_hits
        for i in range(10):
            r(self.at(15 + i / 10), "10.9.0.6", "site2.example", action="blocked", reason="auth_failed",
              status=407, proxy_user="alice")
        self.expect("WF-07", src_ip="10.9.0.6", proxy_user="alice")
        self.expect("WF-02", src_ip="10.9.0.6")
        for reason, host in [("sni_mismatch", "bank.test"), ("upstream_cert_invalid", "selfsigned.test")]:
            r(self.at(30), "10.9.0.7", host, action="blocked", reason=reason)
            self.expect("WF-08", src_ip="10.9.0.7", dest_host=host, reason=reason)
        r(self.at(40), "10.9.0.8", "site3.example", path="/%252e%252e/admin", suspicious_encoding=True)
        self.expect("WF-09", src_ip="10.9.0.8", dest_host="site3.example")
        self.system(self.at(50), "log_dropped", count=12)
        self.system(self.at(55), "insecure_permissions", files=["/srv/wf/blocklists/domains.txt"])
        self.system(self.at(60), "proxy_start", listen="127.0.0.1:8080", mode="enforce")
        self.expect("WF-10", kind="log_dropped")
        self.expect("WF-10", kind="insecure_permissions")

    def v11(self):
        r = self.request
        for i in range(12):
            r(self.at(5 + i / 10), "10.2.0.9", "video.example", action="blocked", reason="quota_exceeded",
              status=429, client_id="kid-tablet", profile="kids")
        self.expect("WF-11", client_id="kid-tablet", reason="quota_exceeded")
        self.expect("WF-02", src_ip="10.2.0.9")
        r(self.at(70), "10.2.0.10", "files.test", path="/setup.exe", client_id="laptop", scan_status="infected",
          scan_engine="clamav", scan_signature="Eicar-Test-Signature", action="blocked", reason="malware_detected",
          download_name="setup.exe")
        self.expect("WF-12", client_id="laptop", dest_host="files.test", scan_status="infected")
        r(self.at(80), "10.2.0.11", "phish.test", client_id="desktop", action="blocked", reason="feed_domain",
          rule_list="feed:urlhaus")
        self.expect("WF-13", client_id="desktop", dest_host="phish.test")
        self.system(self.at(90), "feed_failed", name="urlhaus", error="timeout")
        self.expect("WF-14", kind="feed_failed")
        self.files["webfilter_access.jsonl"].append({
            "timestamp": self.at(95), "event_type": "access_request", "request_id": "ar-1", "event_id": None,
            "client_id": "kid-tablet", "host": "school.example", "reason": "domain_blocklist", "status": "pending",
            "decided_by": None, "ttl_secs": None, "justification_len": 24})
        for i in range(3):
            self.files["webfilter_admin.jsonl"].append({
                "timestamp": self.at(100 - i), "event_type": "admin", "actor": None, "remote_addr": "127.0.0.1",
                "action": "login", "target": None, "result": "auth_failed"})
        self.expect("WF-16", remote_addr="127.0.0.1", action="login")

    def write(self, out):
        out.mkdir(parents=True, exist_ok=True)
        for name, events in self.files.items():
            events.sort(key=lambda e: e["timestamp"])
            with (out / name).open("w", encoding="utf-8", newline="\n") as f:
                f.writelines(json.dumps(e, separators=(",", ":")) + "\n" for e in events)
        (out / "expected.json").write_text(json.dumps(self.expected, indent=1), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", type=Path)
    ap.add_argument("--seed", type=int, default=5)
    ap.add_argument("--end", default="2026-10-31T12:00:00.000Z")
    args = ap.parse_args()
    g = Gen(args.seed, parse_ts(args.end))
    g.baseline()
    g.attacks()
    g.v11()
    g.write(args.out)
    print(f"wrote {sum(map(len, g.files.values()))} events and {len(g.expected)} expected alerts to {args.out}")


if __name__ == "__main__":
    main()
