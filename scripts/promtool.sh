#!/usr/bin/env bash
# `just promtool`: start the proxy with the admin listener, send a little traffic, fetch /metrics and
# validate it with `promtool check metrics` (local binary, or the pinned prom/prometheus image).
# Exit 2 = skipped (neither promtool nor Docker available).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"
IMAGE=prom/prometheus:v2.55.1
if command -v promtool >/dev/null; then CHECK=(promtool check metrics)
elif docker info >/dev/null 2>&1; then CHECK=(docker run --rm -i --entrypoint promtool "$IMAGE" check metrics)
else echo "PROMTOOL SKIP: neither promtool nor Docker"; exit 2; fi
WORK=$(mktemp -d); PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null; rm -rf "$WORK"' EXIT
cargo build --quiet --locked --bin webfilter-proxy || exit 1
BIN="${CARGO_TARGET_DIR:-$ROOT/target}/debug/webfilter-proxy"
TOKEN=promtool-check-token-0123456789
HASH=$(printf '%s' "$TOKEN" | "$BIN" hash-password)
mkdir -p "$WORK/blocklists"; printf 'blocked.test\n' > "$WORK/blocklists/domains.txt"
: > "$WORK/blocklists/url_patterns.txt"; : > "$WORK/blocklists/ip_blocklist.txt"
cat > "$WORK/config.toml" <<CFG
listen = "127.0.0.1:18111"
[logging]
dir = "$WORK/logs"
[admin]
enabled = true
listen = "127.0.0.1:18112"
token_hash = "$HASH"
[state]
dir = "$WORK/state"
CFG
"$BIN" --config "$WORK/config.toml" run 2>/dev/null & PIDS+=($!)
sleep 1
curl -s -o /dev/null -x http://127.0.0.1:18111 http://blocked.test/ || true
curl -s -H "Authorization: Bearer $TOKEN" -H "Host: 127.0.0.1:18112" http://127.0.0.1:18112/metrics > "$WORK/metrics.txt"
grep -q '^webfilter_up 1' "$WORK/metrics.txt" || { echo "PROMTOOL FAIL: no metrics"; exit 1; }
if "${CHECK[@]}" < "$WORK/metrics.txt"; then echo "PROMTOOL PASS"; else echo "PROMTOOL FAIL"; exit 1; fi
