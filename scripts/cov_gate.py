#!/usr/bin/env python3
"""Per-module coverage gate (TEST_PLAN 1): >= 85% lines for the core modules, >= 70% overall.
Usage: cargo llvm-cov ... --json --summary-only | python3 scripts/cov_gate.py   (stdlib only)"""
import json, sys

CORE = ("blocklist.rs", "normalize.rs", "policy.rs", "filter.rs", "logger.rs", "naming.rs")
data = json.load(sys.stdin)["data"][0]
errs = []
for f in data["files"]:
    name = f["filename"].replace("\\", "/").rsplit("/", 1)[-1]
    pct = f["summary"]["lines"]["percent"]
    if name in CORE:
        print(f"{name:14} {pct:6.2f}%")
        if pct < 85:
            errs.append(f"{name} {pct:.2f}% < 85%")
total = data["totals"]["lines"]["percent"]
print(f"{'TOTAL':14} {total:6.2f}%")
if total < 70:
    errs.append(f"total {total:.2f}% < 70%")
if errs:
    print("COV-GATE FAIL: " + "; ".join(errs))
    sys.exit(1)
print("COV-GATE PASS")
