#!/usr/bin/env bash
# `just stress` (A-40): full stress test beyond `just load` - sustained concurrency, churn, slow clients, large
# bodies, h2 floods, limits on, chaos, mixed workload. Loopback only (D-30), release build, Linux (/proc).
# Results: docs/pentest/stress/raw/ (one file per scenario + checks.txt). Helpers: scripts/stress/stress.py.
# Env: STRESS_SECS (S1 sustained, 120), STRESS_CONNS (S1 active conns, 512), STRESS_IDLE (S1 idle keep-alive
# conns, 1500), STRESS_CHURN_SECS (30), STRESS_SLOW (S3 slow sockets, 500), STRESS_BODY_MB (200),
# STRESS_IDS (S6 client ids, 10000), STRESS_MIXED_SECS (60), STRESS_RSS_MAX_MB (300), STRESS_PY_PORT (18190),
# STRESS_ONLY (run a subset, e.g. "S1 S4"), STRESS_H2_NEXTEST=1 (also run the h2 flood integration tests).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/docs/pentest/stress/raw"; mkdir -p "$OUT"
STRESS_SECS=${STRESS_SECS:-120}; STRESS_CONNS=${STRESS_CONNS:-512}; STRESS_IDLE=${STRESS_IDLE:-1500}
STRESS_CHURN_SECS=${STRESS_CHURN_SECS:-30}; STRESS_SLOW=${STRESS_SLOW:-500}; STRESS_BODY_MB=${STRESS_BODY_MB:-200}
STRESS_IDS=${STRESS_IDS:-10000}; STRESS_MIXED_SECS=${STRESS_MIXED_SECS:-60}; RSS_MAX=${STRESS_RSS_MAX_MB:-300}
PYP=${STRESS_PY_PORT:-18190}; HEAD_READ=10
WORK=$(mktemp -d); PIDS=(); fail=0
trap 'kill "${PIDS[@]}" 2>/dev/null; chmod -R u+w "$WORK" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$ROOT"
ulimit -n 65536 2>/dev/null || ulimit -n "$(ulimit -Hn)" 2>/dev/null || true
echo "stress: nofile=$(ulimit -n) secs=$STRESS_SECS conns=$STRESS_CONNS idle=$STRESS_IDLE" | tee "$OUT/env.txt"
command -v python3 >/dev/null || { echo "STRESS FAIL (python3 missing)"; exit 1; }
cargo build --quiet --release --locked --bin webfilter-proxy --example loadgen || exit 1
T="${CARGO_TARGET_DIR:-$ROOT/target}/release"; LG="$T/examples/loadgen"; SP="$ROOT/scripts/stress/stress.py"
: > "$OUT/checks.txt"
check() { if "${@:2}"; then echo "PASS  $1" | tee -a "$OUT/checks.txt"; else echo "FAIL  $1" | tee -a "$OUT/checks.txt"; fail=1; fi; }
skip() { echo "SKIP  $1" | tee -a "$OUT/checks.txt"; }
# jt JSON EXPR: EXPR is a Python expression over `d` (the parsed JSON); empty/invalid JSON fails.
jt() { python3 -c 'import json,sys; d=json.loads(sys.argv[1]); sys.exit(0 if eval(sys.argv[2], {}, {"d": d}) else 1)' "$1" "$2" 2>/dev/null; }
jf() { python3 -c 'import json,sys; print(json.loads(sys.argv[1]).get(sys.argv[2]))' "$1" "$2" 2>/dev/null; }
wants() { [[ -z "${STRESS_ONLY:-}" || " $STRESS_ONLY " == *" $1 "* ]]; }
rss_kb() { awk '/VmRSS/ {print $2}' "/proc/$1/status" 2>/dev/null || echo 0; }
fds() { ls "/proc/$1/fd" 2>/dev/null | wc -l; }
alive() { [[ -d "/proc/$1" ]] && kill -0 "$1" 2>/dev/null; }
sampler() { : > "$2"; while alive "$1"; do echo "$(date +%s) $(rss_kb "$1") $(fds "$1")" >> "$2"; sleep "$3"; done; }
wait_file() { for _ in $(seq 100); do [[ -s "$1" ]] && return 0; sleep 0.1; done; return 1; }
wait_port() { for _ in $(seq 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; return 1; }
py() { python3 "$SP" "$@"; }

# ---- origins: loadgen plain, loadgen TLS h1, loadgen TLS h2, python (fixed port: big bodies, chaos restarts)
"$LG" origin > "$WORK/origin.port" & PIDS+=($!)
"$LG" origin --tls "$WORK/tls-ca.pem" > "$WORK/tls.port" & PIDS+=($!)
"$LG" origin --tls "$WORK/h2-ca.pem" --h2 > "$WORK/h2.port" & PIDS+=($!)
start_pyorigin() { py origin --port "$PYP" > "$WORK/py.port" 2>>"$WORK/py.err" & PYO=$!; PIDS+=($PYO); wait_port "$PYP"; }
start_pyorigin || { echo "STRESS FAIL (python origin did not start on $PYP)"; exit 1; }
for f in origin tls h2; do wait_file "$WORK/$f.port" || { echo "STRESS FAIL (loadgen origin $f)"; exit 1; }; done
OP=$(cat "$WORK/origin.port"); TP=$(cat "$WORK/tls.port"); HP=$(cat "$WORK/h2.port")
wait_file "$WORK/tls-ca.pem" && wait_file "$WORK/h2-ca.pem"
cat "$WORK/tls-ca.pem" "$WORK/h2-ca.pem" > "$WORK/upstream-bundle.pem"

# ---- proxies: main (no rate limits; interception on) and rate-limited (S6)
lab() { # name port extra-toml
  mkdir -p "$WORK/$1/blocklists"; for f in domains url_patterns ip_blocklist; do : > "$WORK/$1/blocklists/$f.txt"; done
  echo "blocked.stress.test" > "$WORK/$1/blocklists/domains.txt"
  cat > "$WORK/$1/config.toml" <<CFG
listen = "127.0.0.1:$2"
[ports]
http_allowed = "any"
connect_allowed = "any"
[destination]
deny_private_ranges = false
[limits]
max_connections = 16384
max_connections_per_ip = 16384
[timeouts]
client_head_read = $HEAD_READ
[logging]
dir = "$WORK/$1/logs"
max_bytes = 4194304
backup_count = 3
[tls]
intercept = true
ca_dir = "$WORK/$1/ca"
upstream_ca_bundle = "$WORK/upstream-bundle.pem"
$3
CFG
  "$T/webfilter-proxy" --config "$WORK/$1/config.toml" run 2>"$WORK/$1.err" & PIDS+=($!)
}
lab main 18095 ""; PROXY=${PIDS[-1]}
lab rate 18096 "
[[profiles]]
name = \"default\"
[profiles.rate]
requests_per_sec = 5
burst = 10"
RPROXY=${PIDS[-1]}
wait_port 18095 && wait_port 18096 || { echo "STRESS FAIL (proxy did not start)"; cat "$WORK"/*.err; exit 1; }
wait_file "$WORK/main/ca/ca.pem"
P=127.0.0.1:18095; CA="$WORK/main/ca/ca.pem"; LOGS="$WORK/main/logs"
URL="http://127.0.0.1:$OP/"; PYURL="http://127.0.0.1:$PYP/"
H2OK=1

# ---- S1: sustained high concurrency (max rate, STRESS_CONNS active + STRESS_IDLE idle keep-alive connections)
if wants S1; then
  "$LG" hold --proxy $P --url "$URL" --conns "$STRESS_IDLE" --secs $((STRESS_SECS + 15)) > "$WORK/S1-hold.json" & HOLD=$!; PIDS+=($HOLD)
  sleep 3
  "$LG" run --url "$URL" --proxy $P --conns "$STRESS_CONNS" --secs "$STRESS_SECS" > "$OUT/S1.json" & RUN=$!
  sleep 5; sampler $PROXY "$OUT/S1-samples.txt" 5 & SMP=$!; PIDS+=($SMP)
  wait $RUN; kill $SMP 2>/dev/null; wait $HOLD 2>/dev/null
  S1=$(cat "$OUT/S1.json"); HELD=$(cat "$WORK/S1-hold.json")
  MEM=$(py samples "$OUT/S1-samples.txt" --max-mb "$RSS_MAX" --stable --fd-tol 64); MEMOK=$?
  echo "$MEM" > "$OUT/S1-mem.json"
  echo "S1 sustained $S1 hold=$HELD mem=$MEM"
  # No limits are configured on this proxy, so every non-200 counts (loadgen cannot tell 429/503 apart).
  check "S1 sustained: 0 errors over ${STRESS_SECS}s" jt "$S1" 'd["errors"] == 0 and d["requests"] > 0'
  check "S1 idle connections held ($STRESS_IDLE)" jt "$HELD" "d['held'] >= $STRESS_IDLE"
  check "S1 RSS/fds stable, peak < ${RSS_MAX} MB" test $MEMOK -eq 0
  check "S1 proxy alive" alive $PROXY
fi

# ---- S2: connection churn (one request per connection, spread over 16 source addresses)
if wants S2; then
  sleep 2; FD0=$(fds $PROXY)
  S2=$(py churn --proxy $P --url "$URL" --threads 64 --secs "$STRESS_CHURN_SECS" --sources 16 --source-net 2)
  sleep 3; FD1=$(fds $PROXY)
  echo "$S2" > "$OUT/S2.json"; echo "fds_before=$FD0 fds_after=$FD1" >> "$OUT/S2.json"
  echo "S2 churn $S2 fds $FD0 -> $FD1"
  check "S2 churn: 0 proxy errors" jt "$S2" 'd["errors"] == 0 and d["ok"] > 0'
  check "S2 no fd leak after churn" test "$FD1" -le $((FD0 + 32))
  check "S2 proxy alive" alive $PROXY
fi

# ---- S3: slowloris (STRESS_SLOW sockets trickling heads) while healthy traffic is measured
if wants S3; then
  BASE=$("$LG" run --url "$URL" --proxy $P --conns 16 --secs 10 --rate 500)
  py slowloris --proxy $P --url "$URL" --n "$STRESS_SLOW" --secs $((HEAD_READ * 3 + 5)) --reopen --source 127.0.0.5 > "$OUT/S3-slow.json" & SLOW=$!; PIDS+=($SLOW)
  sleep 3
  HEALTHY=$("$LG" run --url "$URL" --proxy $P --conns 16 --secs 20 --rate 500)
  wait $SLOW; SL=$(cat "$OUT/S3-slow.json")
  printf '{"baseline":%s,"healthy":%s,"slowloris":%s}\n' "$BASE" "$HEALTHY" "$SL" > "$OUT/S3.json"
  echo "S3 slowloris healthy=$HEALTHY baseline_p99_ms=$(jf "$BASE" p99_ms) slow=$SL"
  check "S3 healthy: 0 errors, >= 490 req/s" jt "$HEALTHY" 'd["errors"] == 0 and d["rps"] >= 490'
  check "S3 healthy p99 within baseline + 50 ms" python3 -c 'import json,sys; a,b=json.loads(sys.argv[1]),json.loads(sys.argv[2]); sys.exit(0 if b["p99_ms"] <= a["p99_ms"] + 50 else 1)' "$BASE" "$HEALTHY"
  check "S3 proxy timed out slow sockets (<= ${HEAD_READ}s + 6)" jt "$SL" "d['closed_by_proxy'] >= 0.95 * d['initial'] and d['max_close_s'] is not None and d['max_close_s'] <= $HEAD_READ + 6"
  check "S3 proxy alive" alive $PROXY
fi

# ---- S4: large bodies (download + upload of STRESS_BODY_MB MiB, sha256 both ways, bounded RSS)
if wants S4; then
  sleep 2; B0=$(rss_kb $PROXY)
  sampler $PROXY "$OUT/S4-samples.txt" 1 & SMP=$!; PIDS+=($SMP)
  S4=$(py bigbody --proxy $P --url "http://127.0.0.1:$PYP" --mb "$STRESS_BODY_MB" --timeout 300)
  kill $SMP 2>/dev/null
  MEM=$(py samples "$OUT/S4-samples.txt" --max-mb "$RSS_MAX" --base-kb "$B0" --growth-mb 64); MEMOK=$?
  echo "$S4" > "$OUT/S4.json"; echo "$MEM" > "$OUT/S4-mem.json"
  echo "S4 large bodies mb=$(jf "$S4" mb) download_ok=$(jf "$S4" download_ok) ($(jf "$S4" download_s)s) upload_ok=$(jf "$S4" upload_ok) ($(jf "$S4" upload_s)s) mem=$MEM"
  check "S4 ${STRESS_BODY_MB} MiB download sha256 equal" jt "$S4" 'd["download_ok"] and d["download_status"] == 200'
  check "S4 ${STRESS_BODY_MB} MiB upload sha256 equal" jt "$S4" 'd["upload_ok"] and d["upload_status"] == 200'
  check "S4 proxy RSS growth <= 64 MB while streaming" test $MEMOK -eq 0
  check "S4 proxy alive" alive $PROXY
fi

# ---- S5: h2 floods (rapid reset, control frames, CONTINUATION) against the intercepted h2 origin, while
# healthy h2 traffic continues on other connections. Fallback: the h2_tests flood tests.
if wants S5; then
  H2A="localhost:$HP"
  PROBE=$(py h2 --proxy $P --authority "$H2A" --ca "$CA" --mode healthy --conns 1 --secs 2); PRC=$?
  if [[ $PRC -eq 3 ]]; then
    H2OK=0; echo "S5 python client could not negotiate h2 ($PROBE); falling back to the h2_tests flood tests"
    if cargo nextest --version >/dev/null 2>&1; then
      check "S5 h2 flood tests (fallback)" cargo nextest run --release --locked --features insecure-test --test h2_tests \
        e42_rapid_reset pt_6_2_continuation pt_6_3_control pt_6_3_slow_reader
    else
      skip "S5 (no h2 via python ssl and cargo-nextest missing)"
    fi
  else
    FL0=$(grep -c 'h2_flood' "$LOGS/webfilter_system.jsonl" 2>/dev/null); FL0=${FL0:-0}
    py h2 --proxy $P --authority "$H2A" --ca "$CA" --mode healthy --conns 4 --secs 50 > "$OUT/S5-healthy.json" & HH=$!; PIDS+=($HH)
    sleep 2
    for m in rapid_reset:1000 control:2000 continuation:64; do
      py h2 --proxy $P --authority "$H2A" --ca "$CA" --mode "${m%%:*}" --count "${m##*:}" --wait 15 > "$OUT/S5-${m%%:*}.json"
      R=$(cat "$OUT/S5-${m%%:*}.json"); echo "S5 flood $R"
      check "S5 ${m%%:*} flood cut (GOAWAY or close)" jt "$R" 'd.get("goaway") or d.get("closed")'
      sleep 1
    done
    wait $HH; HR=$(cat "$OUT/S5-healthy.json"); sleep 2
    FL1=$(grep -c 'h2_flood' "$LOGS/webfilter_system.jsonl" 2>/dev/null); FL1=${FL1:-0}
    echo "S5 h2 healthy during floods $HR; h2_flood events $FL0 -> $FL1" | tee "$OUT/S5.txt"
    check "S5 healthy h2 traffic unaffected (0 errors)" jt "$HR" 'd["errors"] == 0 and d["ok"] > 0'
    check "S5 h2_flood events logged (>= 3)" test $((FL1 - FL0)) -ge 3
    if [[ "${STRESS_H2_NEXTEST:-0}" == 1 ]] && cargo nextest --version >/dev/null 2>&1; then
      check "S5 h2 flood integration tests" cargo nextest run --release --locked --features insecure-test --test h2_tests \
        e42_rapid_reset pt_6_2_continuation pt_6_3_control pt_6_3_slow_reader
    fi
  fi
  check "S5 proxy alive" alive $PROXY
fi

# ---- S6: limits on (5 req/s, burst 10 per client id): 429 + Retry-After, then STRESS_IDS distinct client ids
# (source addresses 127.20.x.y; Linux routes all of 127/8 to lo) with bounded memory, then responsiveness.
if wants S6; then
  sleep 1; R0=$(rss_kb $RPROXY)
  sampler $RPROXY "$OUT/S6-samples.txt" 1 & SMP=$!; PIDS+=($SMP)
  S6=$(py ratelimit --proxy 127.0.0.1:18096 --url "$URL" --burst 300 --ids "$STRESS_IDS" --threads 64)
  kill $SMP 2>/dev/null
  RESP=$(py churn --proxy 127.0.0.1:18096 --url "$URL" --threads 1 --rate 4 --secs 5 --sources 1 --source-net 4)
  MEM=$(py samples "$OUT/S6-samples.txt" --max-mb "$RSS_MAX" --base-kb "$R0" --growth-mb 64); MEMOK=$?
  printf '{"ratelimit":%s,"after":%s,"mem":%s}\n' "$S6" "$RESP" "$MEM" > "$OUT/S6.json"
  echo "S6 limits $S6 after=$RESP mem=$MEM"
  check "S6 burst gets 429s" jt "$S6" 'd["burst"].get("429", 0) > 0 and d["burst"].get("200", 0) > 0'
  check "S6 every 429 carries Retry-After" jt "$S6" 'd["retry_after_bad"] == 0 and d["retry_after_ok"] == d["burst"].get("429", 0)'
  check "S6 $STRESS_IDS client ids served (no errors, >= 99% 200)" jt "$S6" 'd["id_errors"] == 0 and set(d["id_statuses"]) <= {"200", "429"} and d["id_statuses"].get("200", 0) >= 0.99 * d["ids"]'
  check "S6 RSS growth <= 64 MB with $STRESS_IDS ids" test $MEMOK -eq 0
  check "S6 responsive afterwards (fresh id, 0 errors)" jt "$RESP" 'd["errors"] == 0 and d["ok"] >= 15'
  check "S6 proxy alive" alive $RPROXY
fi

# ---- S7: chaos - SIGHUP reload storm under load, origin killed and restarted mid-run, log dir read-only
if wants S7; then
  "$LG" run --url "$PYURL" --proxy $P --conns 8 --secs 15 --rate 300 > "$OUT/S7-hup.json" & RUN=$!
  for i in $(seq 25); do echo "hup$i.stress.test" >> "$WORK/main/blocklists/domains.txt"; kill -HUP $PROXY 2>/dev/null; sleep 0.5; done
  wait $RUN; HUP=$(cat "$OUT/S7-hup.json"); echo "S7a SIGHUP storm $HUP"
  check "S7a 25 SIGHUP reloads under load: 0 errors" jt "$HUP" 'd["errors"] == 0 and d["requests"] > 0'
  check "S7a proxy alive" alive $PROXY

  "$LG" run --url "$PYURL" --proxy $P --conns 8 --secs 20 --rate 300 > "$OUT/S7-outage.json" & RUN=$!
  sleep 5; kill $PYO 2>/dev/null; wait $PYO 2>/dev/null; sleep 5
  start_pyorigin; ORC=$?
  wait $RUN; OUTAGE=$(cat "$OUT/S7-outage.json")
  REC=$("$LG" run --url "$PYURL" --proxy $P --conns 8 --secs 5 --rate 300); echo "$REC" > "$OUT/S7-recovery.json"
  echo "S7b origin restart outage=$OUTAGE (errors expected) recovery=$REC"
  check "S7b origin restarted" test $ORC -eq 0
  check "S7b proxy recovered after origin restart (0 errors)" jt "$REC" 'd["errors"] == 0 and d["requests"] > 0'
  check "S7b proxy alive" alive $PROXY

  if [[ $(id -u) -eq 0 ]]; then
    skip "S7c read-only log dir (running as root: permissions do not restrict root)"
  else
    chmod -R a-w "$LOGS"; kill -USR1 $PROXY 2>/dev/null
    RO=$("$LG" run --url "$URL" --proxy $P --conns 8 --secs 10 --rate 1000); echo "$RO" > "$OUT/S7-readonly.json"
    chmod -R u+w "$LOGS"; kill -USR1 $PROXY 2>/dev/null
    MARK=$(date +%s); sleep 1
    RW=$("$LG" run --url "$URL" --proxy $P --conns 8 --secs 5 --rate 500); echo "$RW" > "$OUT/S7-restored.json"
    sleep 3; MT=$(stat -c %Y "$LOGS/webfilter.jsonl" 2>/dev/null || echo 0)
    echo "S7c read-only logs $RO restored=$RW log_mtime=$MT mark=$MARK"
    check "S7c log dir read-only: requests still served (0 errors)" jt "$RO" 'd["errors"] == 0 and d["requests"] > 0'
    check "S7c logging resumed after restore" test "$MT" -ge "$MARK"
    check "S7c restored: 0 errors" jt "$RW" 'd["errors"] == 0'
  fi
  check "S7 /proc/<pid> still exists" test -d "/proc/$PROXY"
  { echo "hup=$HUP"; echo "outage=$OUTAGE"; echo "recovery=$REC"; } > "$OUT/S7.txt"
fi

# ---- S8: mixed workload at fixed rates: intercepted HTTPS 500/s + plain HTTP 1000/s + h2 + blocked requests
if wants S8; then
  M=$STRESS_MIXED_SECS
  "$LG" run --url "https://localhost:$TP/" --proxy $P --ca "$CA" --conns 16 --secs "$M" --rate 500 > "$OUT/S8-https.json" & A=$!
  "$LG" run --url "$URL" --proxy $P --conns 16 --secs "$M" --rate 1000 > "$OUT/S8-http.json" & B=$!
  py churn --proxy $P --url "http://blocked.stress.test/" --expect 403 --threads 4 --rate 50 --secs "$M" > "$OUT/S8-blocked.json" & C=$!
  if [[ $H2OK -eq 1 ]]; then py h2 --proxy $P --authority "localhost:$HP" --ca "$CA" --mode healthy --conns 2 --secs "$M" > "$OUT/S8-h2.json" & D=$!; fi
  sleep 5; sampler $PROXY "$OUT/S8-samples.txt" 5 & SMP=$!; PIDS+=($SMP)
  wait $A $B $C; [[ $H2OK -eq 1 ]] && wait $D; kill $SMP 2>/dev/null
  MEM=$(py samples "$OUT/S8-samples.txt" --max-mb "$RSS_MAX" --stable --fd-tol 64); MEMOK=$?; echo "$MEM" > "$OUT/S8-mem.json"
  HS=$(cat "$OUT/S8-https.json"); HT=$(cat "$OUT/S8-http.json"); BL=$(cat "$OUT/S8-blocked.json")
  echo "S8 mixed https=$HS http=$HT blocked=$BL h2=$(cat "$OUT/S8-h2.json" 2>/dev/null) mem=$MEM"
  check "S8 intercepted HTTPS 500/s, 0 errors" jt "$HS" 'd["errors"] == 0 and d["rps"] >= 490'
  check "S8 plain HTTP 1000/s, 0 errors" jt "$HT" 'd["errors"] == 0 and d["rps"] >= 980'
  check "S8 blocked requests answered 403" jt "$BL" 'd["errors"] == 0 and d["ok"] > 0'
  if [[ $H2OK -eq 1 ]]; then check "S8 h2 streams, 0 errors" jt "$(cat "$OUT/S8-h2.json")" 'd["errors"] == 0 and d["ok"] > 0'
  else skip "S8 h2 part (python ssl could not negotiate h2)"; fi
  check "S8 RSS/fds stable" test $MEMOK -eq 0
  check "S8 proxy alive" alive $PROXY
fi

cp "$WORK/main.err" "$OUT/proxy-main.stderr.txt" 2>/dev/null; cp "$WORK/rate.err" "$OUT/proxy-rate.stderr.txt" 2>/dev/null
[[ $fail -eq 0 ]] && echo "STRESS PASS" | tee -a "$OUT/checks.txt" || { echo "STRESS FAIL" | tee -a "$OUT/checks.txt"; exit 1; }
