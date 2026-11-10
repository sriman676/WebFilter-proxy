#!/usr/bin/env bash
# `just profile`: speed pass (A-31). Profiles the release proxy under max-rate load with perf (user space
# only; perf_event_paranoid <= 2 is enough) and writes flamegraphs plus top-function reports to
# docs/pentest/speed/. Workloads: W1 plain HTTP, W2 intercepted HTTPS, W3 plain HTTP with profiles,
# limits and metrics on. Needs `perf` and `inferno` (cargo install inferno). PROFILE_SECS (default 15).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/docs/pentest/speed"; mkdir -p "$OUT"
SECS=${PROFILE_SECS:-15}
command -v perf >/dev/null || { echo "SKIP: perf not installed"; exit 2; }
command -v inferno-flamegraph >/dev/null || { echo "SKIP: inferno not installed (cargo install inferno)"; exit 2; }
WORK=$(mktemp -d); PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
cd "$ROOT"
# Frame pointers and line tables, in a separate target dir so normal builds are untouched.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}-profile"
RUSTFLAGS="-C force-frame-pointers=yes" CARGO_PROFILE_RELEASE_DEBUG=line-tables-only CARGO_PROFILE_RELEASE_STRIP=none \
    cargo build --quiet --release --locked --bin webfilter-proxy --example loadgen || exit 1
T="$CARGO_TARGET_DIR/release"; LG="$T/examples/loadgen"

"$LG" origin > "$WORK/origin.port" & PIDS+=($!)
"$LG" origin --tls "$WORK/origin-ca.pem" > "$WORK/tls.port" & PIDS+=($!)
sleep 1; OP=$(cat "$WORK/origin.port"); TP=$(cat "$WORK/tls.port")

lab() { # name port extra-toml
    mkdir -p "$WORK/$1/blocklists"
    printf 'ads.example\ntracker.example\n' > "$WORK/$1/blocklists/domains.txt"
    printf '^https?://[^/]+/ads/\n' > "$WORK/$1/blocklists/url_patterns.txt"
    : > "$WORK/$1/blocklists/ip_blocklist.txt"
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
}

profile() { # name port url extra-loadgen-args
    local name=$1 port=$2 url=$3; shift 3
    # Start the proxy under perf (attaching with -p loses the binary's mappings on WSL kernels).
    perf record -F 499 -g -o "$WORK/$name.data" -- \
        "$T/webfilter-proxy" --config "$WORK/$name/config.toml" run 2>"$WORK/$name.err" &
    local rec=$!; PIDS+=($rec)
    sleep 2
    "$LG" run --url "$url" --proxy "127.0.0.1:$port" --conns 64 --secs "$SECS" "$@" > "$OUT/$name-load.json"
    pkill -INT -P "$rec" 2>/dev/null
    wait $rec 2>/dev/null
    perf script -i "$WORK/$name.data" 2>/dev/null | inferno-collapse-perf > "$WORK/$name.folded"
    inferno-flamegraph --title "webfilter-proxy $name" < "$WORK/$name.folded" > "$OUT/flame-$name.svg"
    # WSL perf cannot symbolize the binary itself: resolve offsets with addr2line and aggregate.
    perf report -i "$WORK/$name.data" --stdio --no-children --sort dso,symbol -g none 2>/dev/null \
        | python3 "$ROOT/scripts/perf_symbolize.py" "$T/webfilter-proxy" 40 > "$OUT/top-$name.txt"
    perf report -i "$WORK/$name.data" --stdio --no-children --sort dso -g none 2>/dev/null \
        | grep -v '^#' | grep -v '^$' | head -8 > "$OUT/dso-$name.txt"
    echo "$name: $(cat "$OUT/$name-load.json")"
}

lab w1 18101 ""
profile w1 18101 "http://127.0.0.1:$OP/"
lab w2 18102 "[tls]
intercept = true
ca_dir = \"$WORK/w2/ca\"
upstream_ca_bundle = \"$WORK/origin-ca.pem\""
profile w2 18102 "https://localhost:$TP/" --ca "$WORK/w2/ca/ca.pem"
lab w3 18103 "[admin]
enabled = true
listen = \"127.0.0.1:18104\"
token_hash = \"$(printf 'profile-token-0123456789abcdef' | "$T/webfilter-proxy" hash-password)\"
[[profiles]]
name = \"default\"
extra_blocked_domains = [\"blocked.example\"]
[profiles.rate]
requests_per_sec = 1000000
burst = 1000000
max_concurrent_connections = 4096
max_inflight_requests = 4096"
profile w3 18103 "http://127.0.0.1:$OP/"
echo "PROFILE DONE: $OUT/flame-*.svg, $OUT/top-*.txt"
