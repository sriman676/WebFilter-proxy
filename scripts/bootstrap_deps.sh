#!/usr/bin/env bash
# Phase 0: add the approved v1 core crates (D-27, D-66, addendum A-03) with `cargo add`, so cargo
# resolves current versions. Phase-specific crates are added at their phase (addendum A-05):
# h2 (6), nix (7), ratatui/crossterm/lol_html/hmac/yara-x (9-12).
# Afterwards: record resolved versions with `scripts/bootstrap_deps.sh --report` into
# docs/ENVIRONMENT.md "Resolved versions", and commit Cargo.lock.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--report" ]]; then
    meta=$(mktemp)
    cargo metadata --format-version 1 --locked >"$meta"
    python3 - "$meta" "$(date -u +%F)" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
root = next(p for p in m["packages"] if p["name"] == "webfilter")
direct = {d["name"] for d in root["dependencies"]}
for p in sorted(m["packages"], key=lambda p: p["name"]):
    if p["name"] in direct:
        print(f"| {p['name']} | {p['version']} | {sys.argv[2]} |")
PY
    rm -f "$meta"
    exit 0
fi

# Runtime / proxy core
cargo add tokio --features rt-multi-thread,net,io-util,time,sync,macros,signal,fs
cargo add httparse bytes tokio-util arc-swap regex url idna ipnet thiserror anyhow base64 subtle sha2 zeroize
cargo add http                                   # A-03: D-09 second parser (http::Uri)
cargo add uuid --features v7
cargo add serde --features derive
cargo add serde_json toml
cargo add clap --features derive
cargo add tracing
cargo add tracing-subscriber --features json,env-filter
cargo add time --features formatting,macros
cargo add argon2
cargo add moka --features sync
# TLS: rustls with the ring provider only (D-19)
cargo add rustls --no-default-features --features ring,std,tls12,logging
cargo add tokio-rustls --no-default-features --features ring,tls12,logging
cargo add rcgen rustls-pki-types webpki-roots
# Client (D-25) - hyper is never used inside the proxy (D-05)
cargo add hyper --features client,http1,http2
cargo add hyper-util --features tokio
cargo add http-body-util
# D-66
cargo add getrandom socket2 httpdate futures-util serde_urlencoded hex
# Dev
cargo add --dev proptest tempfile
# Fuzz package
(cd fuzz && cargo add libfuzzer-sys)

cargo generate-lockfile
cargo check --all-targets --features insecure-test
echo "Done. Now run: $0 --report  and paste into docs/ENVIRONMENT.md"
