#!/usr/bin/env python3
"""Offline SIEM checks (D-29; TEST_PLAN section 8 Docker-less fallback, run by `just siem-test`).

S-01  the index template maps every LOG_SCHEMA request field with the right type; generated
      events carry exactly the schema keys and parse as UTC timestamps.
S-02/S-03/S-05  every detection raises exactly the expected alerts on the labelled dataset
      (attack replays fire; the benign baseline raises nothing; reports return rows).
PT-5.1  injection-looking values are compared as data and never change detection logic.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import detect  # noqa: E402
import gen_test_traffic  # noqa: E402
from common import ROOT, load_detections, load_jsonl, parse_ts, request_fields  # noqa: E402

TYPES = {"int": "long", "bool": "boolean", "array[str]": "keyword", "string": "keyword"}
failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def s01(events):
    props = json.loads((ROOT / "siem/opensearch/index-template.json").read_text())["template"]["mappings"]["properties"]
    for field in request_fields():
        check(field in props, f"S-01: index template misses {field}")
    check(props.get("timestamp", {}).get("type") == "date", "S-01: timestamp must be a date")
    for field, typ in [("status", "long"), ("bytes_in", "long"), ("tls_intercepted", "boolean"), ("src_ip", "ip")]:
        check(props.get(field, {}).get("type") == typ, f"S-01: {field} should be {typ}")
    want = set(request_fields())
    for e in events:
        parse_ts(e["timestamp"])
        if e["event_type"] == "request":
            check(set(e) == want, f"S-01: request keys differ: {set(e) ^ want}")


def detections(events, expected, now):
    alerts = detect.run(lambda det: events, now)
    reports = {d["id"] for d in load_detections() if d["kind"] == "report"}
    got = sorted(json.dumps({"id": a["id"], "group": a["group"]}, sort_keys=True)
                 for a in alerts if a["id"] not in reports)
    exp = sorted(json.dumps(x, sort_keys=True) for x in expected)
    for missing in sorted(set(exp) - set(got)):
        check(False, f"S-03: expected alert missing: {missing}")
    for extra in sorted(set(got) - set(exp)):
        check(False, f"S-02: false positive: {extra}")
    for rid in reports:
        check(any(a["id"] == rid for a in alerts), f"S-02: report {rid} returned no rows")
    fired = {a["id"] for a in alerts}
    for det in load_detections():
        check(det["id"] in fired, f"S-03: detection {det['id']} never fired on the dataset")


def pt51(events, now):
    hostile = dict(events[0], src_ip='10.9.9.9" OR 1=1', reason="invalid_request | delete index=*",
                   dest_host="x\" } { \"match_all\": {} }")
    alerts = detect.run(lambda det: events + [hostile] * 6, now)
    check(not any(a["group"].get("src_ip") == hostile["src_ip"] for a in alerts if a["id"] == "WF-05"),
          "PT-5.1: a crafted reason string matched a detection")


def main():
    with tempfile.TemporaryDirectory() as tmp:
        g = gen_test_traffic.Gen(5, parse_ts("2026-10-31T12:00:00.000Z"))
        g.baseline(), g.attacks(), g.v11()
        g.write(Path(tmp))
        events = load_jsonl(tmp)
        now = max(parse_ts(e["timestamp"]) for e in events)
        s01(events)
        detections(events, g.expected, now)
        pt51(events, now)
    for f in failures:
        print("FAIL", f)
    print("SIEM-TEST", "FAIL" if failures else "PASS", f"({len(load_detections())} detections)")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
