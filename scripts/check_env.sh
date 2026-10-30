#!/usr/bin/env bash
# `just check-env`: verify required tools and print versions (docs/ENVIRONMENT.md).
# Exit 1 if a tool required for the current milestone (M1) is missing or the Rust pin differs.
# Tools for later phases are reported as WARN only.
set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
pin=$(sed -n 's/^RUST_PIN=//p' docs/ENVIRONMENT.md)

ver() { "$@" 2>&1 | head -n1; }
need() { # need <name> <cmd...>
    local name=$1; shift
    if command -v "$1" >/dev/null 2>&1; then printf 'OK    %-16s %s\n' "$name" "$(ver "$@")"
    else printf 'MISS  %-16s (required)\n' "$name"; fail=1; fi
}
want() {
    local name=$1; shift
    if command -v "$1" >/dev/null 2>&1; then printf 'OK    %-16s %s\n' "$name" "$(ver "$@")"
    else printf 'WARN  %-16s (needed in a later phase)\n' "$name"; fi
}
need_cargo() { # cargo subcommands
    local sub=$1
    if cargo "$sub" --version >/dev/null 2>&1; then printf 'OK    cargo-%-10s %s\n' "$sub" "$(ver cargo "$sub" --version)"
    else printf 'MISS  cargo-%-10s (required)\n' "$sub"; fail=1; fi
}
want_cargo() {
    local sub=$1
    if cargo "$sub" --version >/dev/null 2>&1; then printf 'OK    cargo-%-10s %s\n' "$sub" "$(ver cargo "$sub" --version)"
    else printf 'WARN  cargo-%-10s (needed in a later phase)\n' "$sub"; fi
}

echo "== Platform: $(uname -sr) (supported: Linux, macOS - D-01)"
case "$(uname -s)" in Linux|Darwin) ;; *) echo "FAIL  unsupported OS"; fail=1;; esac

echo "== Rust (pin $pin)"
need rustup rustup --version
need rustc rustc --version
need cargo cargo --version
if command -v rustc >/dev/null 2>&1; then
    have=$(rustc --version | awk '{print $2}')
    if [[ "$have" != "$pin" ]]; then echo "FAIL  rustc $have != RUST_PIN $pin"; fail=1; fi
fi
need cc cc --version
need clippy cargo clippy --version
need rustfmt rustfmt --version
need_cargo nextest
need_cargo llvm-cov
need_cargo deny
need_cargo audit
want_cargo fuzz
want_cargo geiger
want_cargo cyclonedx
nightly=$(sed -n 's/.*`\(nightly-[0-9-]*\)`.*/\1/p' docs/ENVIRONMENT.md | head -n1)
if [[ -n "$nightly" ]] && rustup toolchain list 2>/dev/null | grep -q "^$nightly"; then
    echo "OK    fuzz nightly     $nightly"
else echo "WARN  fuzz nightly     ${nightly:-<not recorded>} not installed"; fi

echo "== General"
need just just --version
need git git --version
need python3 python3 --version
if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
    echo "FAIL  python3 < 3.10"; fail=1
fi
need openssl openssl version
need curl curl --version
need jq jq --version
need gitleaks gitleaks version
if command -v nc >/dev/null 2>&1; then echo "OK    nc"; elif command -v ncat >/dev/null 2>&1; then echo "OK    ncat"; else echo "MISS  nc/ncat (required)"; fail=1; fi

echo "== Later phases"
want oha oha --version
want slowhttptest slowhttptest -h
want testssl.sh testssl.sh --version
want sslyze sslyze --help
want docker docker --version
want nmap nmap --version
want h2spec h2spec --version
want nghttp nghttp --version
want h2load h2load --version
want socat socat -V
want nft nft --version
want ip ip -V
want promtool promtool --version

if [[ $fail -ne 0 ]]; then echo "check-env: FAIL"; exit 1; fi
echo "check-env: PASS"
