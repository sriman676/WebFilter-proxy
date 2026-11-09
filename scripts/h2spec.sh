#!/usr/bin/env bash
# E-41 / PT-6.7: h2spec against the interception path. A socat PROXY forwarder does the CONNECT,
# so h2spec talks TLS+h2 to the proxy's minted leaf; the origin is `loadgen origin --tls --h2`.
# Needs h2spec and socat; exits 2 (skip) when either is missing. Loopback only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
for tool in h2spec socat; do
  command -v "$tool" >/dev/null || { echo "H2SPEC SKIP: $tool not installed"; exit 2; }
done
WORK=$(mktemp -d); PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
cd "$ROOT"
cargo build --quiet --release --locked --bin webfilter-proxy --example loadgen
T="${CARGO_TARGET_DIR:-$ROOT/target}/release"
"$T/examples/loadgen" origin --tls "$WORK/origin-ca.pem" --h2 > "$WORK/origin.port" & PIDS+=($!)
sleep 1; OP=$(cat "$WORK/origin.port")
mkdir -p "$WORK/lab/blocklists"; for f in domains url_patterns ip_blocklist; do : > "$WORK/lab/blocklists/$f.txt"; done
cat > "$WORK/lab/config.toml" <<CFG
listen = "127.0.0.1:18080"
[ports]
connect_allowed = "any"
[destination]
deny_private_ranges = false
[logging]
dir = "$WORK/logs"
[tls]
intercept = true
ca_dir = "$WORK/proxy-ca"
upstream_ca_bundle = "$WORK/origin-ca.pem"
CFG
"$T/webfilter-proxy" --config "$WORK/lab/config.toml" run 2>/dev/null & PIDS+=($!)
socat TCP-LISTEN:19443,bind=127.0.0.1,reuseaddr,fork "PROXY:127.0.0.1:localhost:$OP,proxyport=18080" & PIDS+=($!)
sleep 2
# -k: h2spec does not trust the proxy CA; the tool is the test client here, not the proxy.
h2spec --strict -t -k -h 127.0.0.1 -p 19443 -o 5 | tee "$WORK/out.txt" || true
mkdir -p docs/pentest/phase-6/raw && cp "$WORK/out.txt" docs/pentest/phase-6/raw/h2spec.txt
if grep -Eq "[0-9]+ tests, [0-9]+ passed, [0-9]+ skipped, 0 failed" "$WORK/out.txt"; then echo "H2SPEC PASS"; else echo "H2SPEC FAIL"; exit 1; fi
