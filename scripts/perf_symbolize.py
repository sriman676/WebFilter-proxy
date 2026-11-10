#!/usr/bin/env python3
"""Aggregate a perf profile by function when perf itself cannot symbolize the binary (WSL perf builds
without libelf). Reads `perf report --stdio --no-children --sort dso,symbol -g none` from stdin,
resolves the binary's unresolved offsets with `addr2line -f -C` and prints the top functions.
Usage: perf report ... | perf_symbolize.py BINARY [TOP]. Stdlib only."""
import re
import subprocess
import sys
from collections import defaultdict


def main():
    binary, top = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 40
    name = binary.rsplit("/", 1)[-1]
    rows = []  # (percent, dso, symbol-or-offset)
    for line in sys.stdin:
        m = re.match(r"\s*([\d.]+)%\s+(\S+)\s+\[[.k]\]\s+(\S+)", line)
        if m:
            rows.append((float(m.group(1)), m.group(2), m.group(3)))
    offsets = sorted({s for _, d, s in rows if d == name and s.startswith("0x")})
    # perf prints file offsets; addr2line wants virtual addresses (PIE: vaddr - offset of the
    # executable LOAD segment, e.g. 0x1000).
    delta = 0
    segs = subprocess.run(["readelf", "-lW", binary], capture_output=True, text=True).stdout
    for line in segs.splitlines():
        f = line.split()
        if f[:1] == ["LOAD"] and len(f) >= 7 and "E" in f[6:-1]:
            delta = int(f[2], 16) - int(f[1], 16)
    names = {}
    if offsets:
        addrs = [hex(int(o, 16) + delta) for o in offsets]
        out = subprocess.run(["addr2line", "-f", "-C", "-e", binary, *addrs], capture_output=True, text=True).stdout
        lines = out.splitlines()
        for i, off in enumerate(offsets):
            fn = lines[2 * i] if 2 * i < len(lines) else "??"
            # Strip generic noise so instantiations of the same function aggregate.
            fn = re.sub(r"::h[0-9a-f]{16}$", "", fn)
            names[off] = fn
    agg = defaultdict(float)
    for pct, dso, sym in rows:
        key = f"{dso}: {names.get(sym, sym)}" if dso == name else f"{dso}: {sym if not sym.startswith('0x') else '(unresolved)'}"
        agg[key] += pct
    for key, pct in sorted(agg.items(), key=lambda kv: -kv[1])[:top]:
        print(f"{pct:6.2f}%  {key[:150]}")


if __name__ == "__main__":
    main()
