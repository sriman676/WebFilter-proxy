#!/usr/bin/env bash
# `just load`: TEST_PLAN L-01..L-05 against the D-34 targets (loopback; release build). Results go to
# docs/pentest/phase-8/raw/load/. SOAK_SECS (default 60) sets the L-05 duration (3600 for the full soak).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/docs/pentest/phase-8/raw/load"; mkdir -p "$OUT"
SOAK_SECS=${SOAK_SECS:-60}; L01_SECS=${L01_SECS:-30}
WORK=$(mktemp -d); PIDS=(); fail=0
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$ROOT"
cargo build --quiet --release --locked --bin webfilter-proxy --example loadgen || exit 1
T="${CARGO_TARGET_DIR:-$ROOT/target}/release"; LG="$T/examples/loadgen"
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
field() { python3 -c "import json,sys; print(json.loads(sys.argv[1])[sys.argv[2]])" "$1" "$2"; }
rss_kb() { awk '/VmRSS/ {print $2}' "/proc/$1/status"; }
fds() { ls "/proc/$1/fd" | wc -l; }

"$LG" origin > "$WORK/origin.port" & PIDS+=($!)
"$LG" origin --tls "$WORK/origin-ca.pem" > "$WORK/tls.port" & PIDS+=($!)
sleep 1; OP=$(cat "$WORK/origin.port"); TP=$(cat "$WORK/tls.port")
mkdir -p "$WORK/lab/blocklists"; for f in domains url_patterns ip_blocklist; do : > "$WORK/lab/blocklists/$f.txt"; done
cat > "$WORK/lab/config.toml" <<CFG
listen = "127.0.0.1:18090"
[ports]
http_allowed = "any"
connect_allowed = "any"
[destination]
deny_private_ranges = false
[limits]
max_connections = 4096
max_connections_per_ip = 4096
[logging]
dir = "$WORK/logs"
[tls]
intercept = true
ca_dir = "$WORK/ca"
upstream_ca_bundle = "$WORK/origin-ca.pem"
CFG
"$T/webfilter-proxy" --config "$WORK/lab/config.toml" run 2>"$WORK/proxy.err" & PROXY=$!; PIDS+=($PROXY)
sleep 1
URL="http://127.0.0.1:$OP/"; P=127.0.0.1:18090

# L-01: 2,000 req/s for L01_SECS, 0 errors, p99 added latency < 15 ms vs direct; plus max throughput.
DIRECT=$("$LG" run --url "$URL" --conns 32 --secs "$L01_SECS" --rate 2000); echo "$DIRECT" > "$OUT/L-01-direct.json"
PROXIED=$("$LG" run --url "$URL" --proxy $P --conns 32 --secs "$L01_SECS" --rate 2000); echo "$PROXIED" > "$OUT/L-01-proxied.json"
MAX=$("$LG" run --url "$URL" --proxy $P --conns 64 --secs 10); echo "$MAX" > "$OUT/L-01-max.json"
echo "L-01 direct $DIRECT"; echo "L-01 proxy  $PROXIED"; echo "L-01 max    $MAX"
check "L-01 >= 2000 req/s, 0 errors" "python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d[\"errors\"]==0 and d[\"rps\"]>=1980 else 1)' '$PROXIED'"
check "L-01 p99 added latency < 15 ms" "python3 -c 'import json,sys; a,b=json.loads(sys.argv[1]),json.loads(sys.argv[2]); sys.exit(0 if b[\"p99_ms\"]-a[\"p99_ms\"]<15 else 1)' '$DIRECT' '$PROXIED'"

# L-02: 1,000 concurrent keep-alive connections, RSS < 200 MB.
"$LG" hold --proxy $P --url "$URL" --conns 1000 --secs 8 > "$WORK/hold.json" & HOLD=$!
sleep 6; RSS=$(rss_kb $PROXY); wait $HOLD
echo "L-02 $(cat "$WORK/hold.json") rss_kb=$RSS" | tee "$OUT/L-02.txt"
check "L-02 1000 connections held" "[[ \$(field \"\$(cat $WORK/hold.json)\" held) -ge 1000 ]]"
check "L-02 RSS < 200 MB" "[[ $RSS -lt 204800 ]]"

# L-03: slow clients (slowloris) do not hurt healthy ones.
if command -v slowhttptest >/dev/null; then
  slowhttptest -c 500 -H -i 10 -r 200 -l 30 -u "$URL" -d $P -p 3 >/dev/null 2>&1 & SLOW=$!
  sleep 5
  HEALTHY=$("$LG" run --url "$URL" --proxy $P --conns 16 --secs 15 --rate 500); echo "$HEALTHY" > "$OUT/L-03.json"
  kill $SLOW 2>/dev/null; wait $SLOW 2>/dev/null
  echo "L-03 healthy under slowloris $HEALTHY"
  check "L-03 healthy clients unaffected" "[[ \$(field '$HEALTHY' errors) -eq 0 ]]"
else
  echo "SKIP  L-03 (slowhttptest missing)"
fi

# L-04: intercepted HTTPS at 500 req/s.
TLS=$("$LG" run --url "https://localhost:$TP/" --proxy $P --ca "$WORK/ca/ca.pem" --conns 16 --secs 15 --rate 500)
echo "$TLS" > "$OUT/L-04.json"; echo "L-04 intercepted $TLS"
check "L-04 intercepted 500 req/s, 0 errors" "python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if d[\"errors\"]==0 and d[\"rps\"]>=490 else 1)' '$TLS'"

# L-05: soak at 500 req/s; RSS and fd count sampled every 10 s must stay flat.
"$LG" run --url "$URL" --proxy $P --conns 16 --secs "$SOAK_SECS" --rate 500 > "$OUT/L-05.json" & SOAK=$!
: > "$OUT/L-05-samples.txt"
sleep 5
while kill -0 $SOAK 2>/dev/null; do echo "$(rss_kb $PROXY) $(fds $PROXY)" >> "$OUT/L-05-samples.txt"; sleep 10; done
echo "L-05 soak $(cat "$OUT/L-05.json") samples(rss_kb fds): $(tr '\n' ';' < "$OUT/L-05-samples.txt")"
check "L-05 RSS and fds stable" "python3 - '$OUT/L-05-samples.txt' <<'PY'
import sys
s=[tuple(map(int,l.split())) for l in open(sys.argv[1]) if l.strip()]
if len(s)<2: sys.exit(0)
rss_ok = s[-1][0] <= s[1 if len(s)>2 else 0][0]*1.2 + 5120
fd_ok = max(f for _,f in s) - min(f for _,f in s) <= 40
sys.exit(0 if rss_ok and fd_ok else 1)
PY"
check "L-05 0 errors" "[[ \$(field \"\$(cat $OUT/L-05.json)\" errors) -eq 0 ]]"
[[ $fail -eq 0 ]] && echo "LOAD PASS" || { echo "LOAD FAIL"; exit 1; }
