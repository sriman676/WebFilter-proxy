#!/usr/bin/env python3
"""Evaluate siem/opensearch/detections.json over JSONL logs or an OpenSearch index (A-35).

  detect.py --jsonl logs/                       offline, same logic as the SIEM run
  detect.py --opensearch https://localhost:9200 --ca siem/opensearch/certs/root-ca.pem
            (user admin, password from $OPENSEARCH_PASSWORD; TLS always verified)

Field values are compared as data only; nothing from the logs is ever evaluated (PT-5.1).
"""
import argparse
import base64
import json
import os
import ssl
import statistics
import sys
import urllib.request
from datetime import timedelta

from common import fmt_ts, load_detections, load_jsonl, parse_ts


def matches(event, det):
    for field, want in det["match"].items():
        value = event.get(field)
        if isinstance(want, list):
            if value not in want:
                return False
        elif value != want:
            return False
    for field, n in det.get("min_len", {}).items():
        if len(event.get(field) or "") < n:
            return False
    return True


def evaluate(det, events, now):
    """Alerts for one detection: [{"id", "group": {...}, "count", ...}]."""
    start = now - timedelta(minutes=det["window_mins"])
    groups = {}
    for e in events:
        ts = parse_ts(e["timestamp"])
        if start <= ts <= now and matches(e, det):
            key = tuple(e.get(f) for f in det["group_by"])
            groups.setdefault(key, []).append((ts, e))
    alerts = []
    for key, rows in sorted(groups.items(), key=lambda kv: str(kv[0])):
        alert = {"id": det["id"], "group": dict(zip(det["group_by"], key)), "count": len(rows)}
        kind = det["kind"]
        if kind in ("threshold", "report"):
            fired = len(rows) >= det["min_count"]
        elif kind == "ratio":
            r = det["ratio"]
            hits = sum(1 for _, e in rows if e.get(r["field"]) == r["value"])
            alert["hits"], alert["pct"] = hits, round(100 * hits / len(rows), 1)
            fired = hits >= r["min_hits"] and alert["pct"] >= r["min_pct"]
        elif kind == "beacon":
            b = det["beacon"]
            times = sorted(t for t, _ in rows)
            deltas = [(y - x).total_seconds() for x, y in zip(times, times[1:])]
            fired = False
            if len(times) >= b["min_count"] and len(deltas) >= 2:
                mean, sd = statistics.mean(deltas), statistics.pstdev(deltas)
                alert["mean_secs"], alert["stdev_secs"] = round(mean, 2), round(sd, 2)
                fired = mean >= b["min_interval_secs"] and sd < b["max_jitter"] * mean
        else:
            raise ValueError(f"{det['id']}: unknown kind {kind}")
        if fired:
            alerts.append(alert)
    return alerts


class OpenSearch:
    """Minimal verified-TLS client: fetch matching documents per detection with the scroll API."""

    def __init__(self, url, ca, index, user, password):
        self.url, self.index = url.rstrip("/"), index
        self.ctx = ssl.create_default_context(cafile=ca)
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}

    def call(self, method, path, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.url + path, data, self.headers, method=method)
        with urllib.request.urlopen(req, context=self.ctx, timeout=30) as r:
            return json.load(r)

    def events(self, det, now):
        start = now - timedelta(minutes=det["window_mins"])
        filters = [{"range": {"timestamp": {"gte": fmt_ts(start), "lte": fmt_ts(now)}}}]
        for field, want in det["match"].items():
            filters.append({"terms": {field: want if isinstance(want, list) else [want]}})
        body = {"size": 5000, "query": {"bool": {"filter": filters}}, "sort": ["_doc"]}
        page = self.call("POST", f"/{self.index}/_search?scroll=1m", body)
        out = []
        while page["hits"]["hits"]:
            out += [h["_source"] for h in page["hits"]["hits"]]
            page = self.call("POST", "/_search/scroll", {"scroll": "1m", "scroll_id": page["_scroll_id"]})
        self.call("DELETE", "/_search/scroll", {"scroll_id": page["_scroll_id"]})
        return out

    def latest(self):
        body = {"size": 1, "sort": [{"timestamp": "desc"}], "_source": ["timestamp"]}
        hits = self.call("POST", f"/{self.index}/_search", body)["hits"]["hits"]
        return parse_ts(hits[0]["_source"]["timestamp"]) if hits else None


def run(events_for, now):
    return [a for det in load_detections() for a in evaluate(det, events_for(det), now)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--jsonl", help="directory with webfilter*.jsonl files")
    src.add_argument("--opensearch", help="OpenSearch base URL (https)")
    ap.add_argument("--ca", help="CA file that signs the OpenSearch certificate")
    ap.add_argument("--index", default="webfilter-*")
    ap.add_argument("--now", help="evaluation time (ISO, UTC); default: newest event")
    args = ap.parse_args()
    if args.jsonl:
        events = load_jsonl(args.jsonl)
        latest = max((parse_ts(e["timestamp"]) for e in events), default=None)
        events_for = lambda det: events  # noqa: E731
    else:
        password = os.environ.get("OPENSEARCH_PASSWORD")
        if not password or not args.ca:
            sys.exit("error: --ca and $OPENSEARCH_PASSWORD are required for --opensearch")
        client = OpenSearch(args.opensearch, args.ca, args.index, "admin", password)
        latest = client.latest()
        events_for = lambda det: client.events(det, now)  # noqa: E731
    now = parse_ts(args.now) if args.now else latest
    if now is None:
        sys.exit("error: no events")
    for alert in run(events_for, now):
        print(json.dumps(alert, sort_keys=True))


if __name__ == "__main__":
    main()
