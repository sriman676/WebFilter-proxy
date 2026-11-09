#!/usr/bin/env bash
# `just scan-e2e`: E-63..E-65 against a real clamd (Docker) instead of the fake used by `just test`.
# Exit 2 = skipped (no Docker access).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"
docker info >/dev/null 2>&1 || { echo "SCAN-E2E SKIP: no Docker access"; exit 2; }
docker rm -f webfilter-clamd >/dev/null 2>&1 || true
docker compose -f scan/docker-compose.yml up -d >/dev/null || { echo "SCAN-E2E FAIL: compose"; exit 1; }
trap 'docker compose -f scan/docker-compose.yml down >/dev/null 2>&1' EXIT
for _ in $(seq 180); do
  if printf 'zPING\0' | timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/3310; cat >&3; head -c 5 <&3' 2>/dev/null | grep -q PONG; then break; fi
  sleep 2
done
WEBFILTER_REAL_CLAMD=127.0.0.1:3310 cargo test --locked --features insecure-test --test feeds_scan_tests real_clamd -- --ignored --test-threads=1
rc=$?
[[ $rc -eq 0 ]] && echo "SCAN-E2E PASS" || { echo "SCAN-E2E FAIL"; exit 1; }
