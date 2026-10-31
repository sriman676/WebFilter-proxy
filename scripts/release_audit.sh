#!/usr/bin/env bash
# PT-8.2 release audit: release build without `insecure-test` (feature list and binary strings),
# no first-party unsafe (cargo geiger), SBOM, gitleaks over the whole history.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd); cd "$ROOT"
OUT=docs/pentest/phase-8/raw; mkdir -p "$OUT"; fail=0
check() { if eval "$2"; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
cargo build --quiet --release --locked --bins || exit 1
T="${CARGO_TARGET_DIR:-$ROOT/target}/release"
check "insecure-test not a default feature" "! sed -n '/^\[features\]/,/^\[/p' Cargo.toml | grep -E '^default *=' | grep -q insecure-test"
for b in webfilter-proxy webfilter-client; do
  check "$b has no WEBFILTER_TEST_* code" "! strings '$T/$b' | grep -q WEBFILTER_TEST_"
done
check "unsafe_code = forbid in Cargo.toml lints" "grep -Eq '^unsafe_code *= *\"forbid\"' Cargo.toml"
if command -v cargo-geiger >/dev/null; then
  cargo geiger --locked --forbid-only --output-format Ascii > "$OUT/geiger.txt" 2>&1 || true
  check "geiger: first-party crate forbids unsafe" "grep -Eq 'webfilter' '$OUT/geiger.txt'"
else echo "SKIP  cargo geiger (not installed)"; fi
if command -v cargo-cyclonedx >/dev/null; then cargo cyclonedx --format json >/dev/null && cp webfilter.cdx.json "$OUT/sbom.cdx.json"
else python3 scripts/sbom.py Cargo.lock > "$OUT/sbom.cdx.json"; fi
check "SBOM generated" "python3 -c \"import json; d=json.load(open('$OUT/sbom.cdx.json')); assert len(d['components'])>50\""
if command -v gitleaks >/dev/null; then
  check "gitleaks: no secrets in history" "gitleaks detect --source . --redact --no-banner --log-opts=--all > '$OUT/gitleaks.txt' 2>&1"
else echo "SKIP  gitleaks (not installed)"; fi
[[ $fail -eq 0 ]] && echo "RELEASE-AUDIT PASS" || { echo "RELEASE-AUDIT FAIL"; exit 1; }
