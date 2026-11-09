#!/usr/bin/env bash
# `just load-features`: TEST_PLAN L-06 / PT-13.4. Two proxies side by side on loopback (release build):
# plain v1.0 settings vs profiles + client CIDR mapping + (generous) rate limits + admin/metrics on.
# Overhead must stay within 10 percent of the plain proxy. Results: docs/pentest/phase-13/raw/load/.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/docs/pentest/phase-13/raw/load"; mkdir -p "$OUT"
SECS=${L06_SECS:-20}
WORK=$(mktemp -d); PIDS=(); fail=0
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$ROOT"
cargo build --quiet --release --locked --bin webfilter-proxy --example loadgen || exit 1
T="${CARGO_TARGET_DIR:-$ROOT/target}/release"; LG="$T/examples/loadgen"
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
rss_kb() { awk '/VmRSS/ {print $2}' "/proc/$1/status"; }

"$LG" origin > "$WORK/origin.port" & PIDS+=($!)
sleep 1; OP=$(cat "$WORK/origin.port"); URL="http://127.0.0.1:$OP/"
HASH=$(printf 'load-test-admin-token-0123456789' | "$T/webfilter-proxy" hash-password)

lab() { # name port extra
    mkdir -p "$WORK/$1/blocklists"; for f in domains url_patterns ip_blocklist; do : > "$WORK/$1/blocklists/$f.txt"; done
    cat > "$WORK/$1/config.toml" <<CFG
listen = "127.0.0.1:$2"
[ports]
http_allowed = "any"
connect_allowed = "any"
[destination]
deny_private_ranges = false
[limits]
max_connections = 4096
max_connections_per_ip = 4096
[logging]
dir = "$WORK/$1/logs"
$3
CFG
    "$T/webfilter-proxy" --config "$WORK/$1/config.toml" run 2>"$WORK/$1.err" & PIDS+=($!)
}
lab plain 18091 ""
PLAIN=${PIDS[-1]}
lab features 18092 "
[admin]
enabled = true
listen = \"127.0.0.1:18093\"
token_hash = \"$HASH\"
[[profiles]]
name = \"default\"
extra_blocked_domains = [\"blocked.example\"]
[profiles.rate]
requests_per_sec = 100000
burst = 100000
max_concurrent_connections = 4096
max_inflight_requests = 4096
[[profiles]]
name = \"lab\"
[[clients]]
cidr = \"10.0.0.0/8\"
profile = \"lab\""
FEAT=${PIDS[-1]}
sleep 1

run() { "$LG" run --url "$URL" --proxy "127.0.0.1:$1" "${@:2}"; }
DIRECT=$("$LG" run --url "$URL" --conns 32 --secs "$SECS" --rate 2000)
for name in plain features; do
    port=18091; [[ $name == features ]] && port=18092
    run $port --conns 32 --secs "$SECS" --rate 2000 > "$OUT/L-06-$name-2000.json"
    run $port --conns 64 --secs 10 > "$OUT/L-06-$name-max.json"
done
"$LG" hold --proxy 127.0.0.1:18092 --url "$URL" --conns 1000 --secs 8 > "$WORK/hold.json" & HOLD=$!
sleep 6; RSS=$(rss_kb $FEAT); RSS_PLAIN=$(rss_kb $PLAIN); wait $HOLD
METRICS=$(curl -s -H "Host: 127.0.0.1:18093" -H "Authorization: Bearer load-test-admin-token-0123456789" http://127.0.0.1:18093/metrics | grep -c '^webfilter_')
echo "$DIRECT" > "$OUT/L-06-direct.json"
python3 - "$OUT" "$RSS" "$METRICS" <<'PY' | tee "$OUT/L-06-summary.txt"
import json, sys
out, rss, metrics = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
d = lambda n: json.load(open(f"{out}/L-06-{n}.json"))
direct = d("direct")
for n in ("plain", "features"):
    r, m = d(f"{n}-2000"), d(f"{n}-max")
    print(f"{n:9s} 2000rps: rps={r['rps']:.0f} errors={r['errors']} p99_added={r['p99_ms']-direct['p99_ms']:.2f}ms | max rps={m['rps']:.0f}")
print(f"features: rss_kb at 1000 conns={rss}, metric series={metrics}")
PY
P=$(cat "$OUT/L-06-plain-max.json"); F=$(cat "$OUT/L-06-features-max.json"); F2=$(cat "$OUT/L-06-features-2000.json")
check "L-06 features: 2000 req/s, 0 errors" "python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d[\"errors\"]==0 and d[\"rps\"]>=1980 else 1)' '$F2'"
check "L-06 features p99 added latency < 15 ms" "python3 -c 'import json,sys; a,b=json.loads(sys.argv[1]),json.loads(sys.argv[2]); sys.exit(0 if b[\"p99_ms\"]-a[\"p99_ms\"]<15 else 1)' '$DIRECT' '$F2'"
check "L-06 max throughput overhead <= 10%" "python3 -c 'import json,sys; p,f=json.loads(sys.argv[1]),json.loads(sys.argv[2]); sys.exit(0 if f[\"rps\"]>=0.9*p[\"rps\"] else 1)' '$P' '$F'"
check "L-06 RSS < 200 MB at 1000 connections" "[[ $RSS -lt 204800 ]]"
check "L-06 metrics served" "[[ $METRICS -gt 0 ]]"
[[ $fail -eq 0 ]] && echo "LOAD-FEATURES PASS" || { echo "LOAD-FEATURES FAIL"; exit 1; }
