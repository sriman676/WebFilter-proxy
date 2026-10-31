#!/usr/bin/env bash
# E-41 / PT-6.7: h2spec against the interception path. A socat PROXY forwarder does the CONNECT,
# so h2spec talks TLS+h2 to the proxy's minted leaf; the origin is nghttpd with a throwaway PKI.
# Needs h2spec, socat, nghttpd and openssl; exits 2 (skip) when any is missing. Loopback only.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
for tool in h2spec socat nghttpd openssl; do
  command -v "$tool" >/dev/null || { echo "H2SPEC SKIP: $tool not installed"; exit 2; }
done
WORK=$(mktemp -d); PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true; rm -rf "$WORK"' EXIT
"$ROOT/scripts/gen_test_pki.sh" "$WORK/pki" localhost >/dev/null
nghttpd -q 18443 "$WORK/pki/leaf.key" "$WORK/pki/leaf.pem" & PIDS+=($!)
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
upstream_ca_bundle = "$WORK/pki/ca.pem"
CFG
cargo build --quiet --release --locked --bin webfilter-proxy --manifest-path "$ROOT/Cargo.toml"
"${CARGO_TARGET_DIR:-$ROOT/target}/release/webfilter-proxy" --config "$WORK/lab/config.toml" run 2>/dev/null & PIDS+=($!)
socat TCP-LISTEN:19443,bind=127.0.0.1,reuseaddr,fork PROXY:127.0.0.1:localhost:18443,proxyport=18080 & PIDS+=($!)
sleep 2
# -k: h2spec does not trust the proxy CA; the tool is the test client here, not the proxy.
h2spec --strict -t -k -h 127.0.0.1 -p 19443 -o 5 --junit-report "$WORK/h2spec.xml" | tee "$WORK/out.txt"
grep -q " 0 failed" "$WORK/out.txt" && echo "H2SPEC PASS" || { echo "H2SPEC FAIL"; exit 1; }
