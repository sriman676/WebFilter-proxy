# Task runner (SPEC 10). Unimplemented targets print a TODO naming their phase and exit 1.
set shell := ["bash", "-euo", "pipefail", "-c"]

# Dated nightly used ONLY for cargo-fuzz (docs/ENVIRONMENT.md, addendum A-09).
fuzz_nightly := "nightly-2026-10-28"
target_dir := env_var_or_default("CARGO_TARGET_DIR", "target")
config := "config/config.toml"

default:
    @just --list

# --- environment / hygiene ---------------------------------------------------------------
check-env:
    scripts/check_env.sh

install-hooks:
    git config core.hooksPath scripts/hooks
    @echo "pre-commit hook installed (fmt + clippy + gitleaks)"

bootstrap-deps:
    scripts/bootstrap_deps.sh

# Check formatting (CI mode). Use `just fmt-fix` to rewrite.
fmt:
    cargo fmt --all -- --check

fmt-fix:
    cargo fmt --all

lint:
    cargo clippy --locked --all-targets -- -D warnings
    cargo clippy --locked --all-targets --all-features -- -D warnings

test:
    cargo nextest run --locked --features insecure-test --no-tests=pass
    cargo nextest run --locked --features insecure-test,plugins --test plugin_tests
    cargo test --locked --features insecure-test --doc
    python3 scripts/siem/siem_test.py

cov:
    cargo llvm-cov nextest --locked --features insecure-test --json --summary-only | python3 scripts/cov_gate.py

demo:
    scripts/demo.sh

docs-check:
    python3 scripts/docs_check.py

check-config cfg=config:
    cargo run --locked --bin webfilter-proxy -- --config {{cfg}} check-config

# Release build WITHOUT insecure-test; fail if test-only hooks leaked into the binaries (D-20, D-44).
release:
    cargo build --release --locked
    for b in webfilter-proxy webfilter-client; do \
        if grep -a -q -e WEBFILTER_TEST_HOSTS -e WEBFILTER_TEST_ORIG_DST "{{target_dir}}/release/$b"; then \
            echo "FAIL: $b contains test-only hooks"; exit 1; fi; \
    done
    @echo "release OK: insecure-test hooks absent"

# --- supply chain -----------------------------------------------------------------------
audit:
    cargo deny check
    cargo deny --all-features check
    cargo audit
    cargo geiger --all-features

sbom:
    if command -v cargo-cyclonedx >/dev/null; then cargo cyclonedx --format json; else python3 scripts/sbom.py Cargo.lock > webfilter.cdx.json; fi
release-audit:
    scripts/release_audit.sh
compat:
    scripts/compat.sh

# --- fuzzing ----------------------------------------------------------------------------
fuzz-smoke secs="60":
    targets=$(cargo +{{fuzz_nightly}} fuzz list); \
    [[ -n "$targets" ]] || { echo "no fuzz targets found"; exit 1; }; \
    for t in $targets; do \
        cargo +{{fuzz_nightly}} fuzz run "$t" -- -max_total_time={{secs}} || exit 1; \
    done

# --- pentest ----------------------------------------------------------------------------
pentest-p0:
    scripts/pentest_p0.sh

pentest-p1:
    scripts/pentest_p1.sh
pentest-p2:
    scripts/pentest_p2.sh
pentest-p3:
    scripts/pentest_p3.sh
pentest-p4:
    scripts/pentest_p4.sh
pentest-p5:
    scripts/pentest_p5.sh
pentest-p6:
    scripts/pentest_p6.sh
pentest-p7:
    scripts/pentest_p7.sh
pentest-p8:
    scripts/pentest_p8.sh
pentest-p9:
    scripts/pentest_p9.sh
pentest-p10:
    scripts/pentest_p10.sh
pentest-p11:
    scripts/pentest_p11.sh
pentest-p12:
    scripts/pentest_p12.sh
pentest-p13:
    scripts/pentest_p13.sh
pentest-p14:
    scripts/pentest_p14.sh
# Whole-codebase pentest in one run (A-50).
pentest-full:
    scripts/pentest_full.sh

# --- end-to-end and external suites (later phases) --------------------------------------
# Offline end-to-end suites that drive the real proxy/client (E-xx; E-28/E-41/E-44..50 have own recipes).
e2e:
    cargo nextest run --locked --features insecure-test --test client_e2e --test cli_check_config --test proxy_integration --test proxy_security --test tls_tests --test h2_tests --test transparent_tests --test observability_tests --test policy_profile_tests --test feeds_scan_tests --test admin_tests --test client_ext_tests --test interaction_tests
load:
    scripts/load.sh
# L-06 / PT-13.4: overhead with profiles, limits and metrics on vs plain.
load-features:
    scripts/load_features.sh
# Speed pass (A-31): perf flamegraphs under max-rate load.
profile:
    scripts/profile.sh
# Stress test (A-40).
stress:
    scripts/stress.sh
# Offline detection/template checks (TEST_PLAN section 8 fallback) and the live OpenSearch run (A-14).
siem-test:
    python3 scripts/siem/siem_test.py
siem-e2e:
    scripts/siem/siem_e2e.sh
h2spec:
    scripts/h2spec.sh
# Linux + root: sudo -E just e2e-netns (D-43).
e2e-netns:
    scripts/e2e_netns.sh
feeds-test:
    cargo nextest run --locked --features insecure-test --test feeds_scan_tests
scan-e2e:
    scripts/scan_e2e.sh
promtool:
    scripts/promtool.sh
ui-lint:
    python3 scripts/ui_lint.py
# E-88: browser extension lint (permissions, CSP, text-only rendering, loopback-only URLs).
ext-lint:
    python3 scripts/ext_lint.py
# E-84..E-86: WASM rule plugins (optional `plugins` feature).
plugins-test:
    cargo nextest run --locked --features insecure-test,plugins --test plugin_tests
ui-e2e:
    python3 scripts/ui_e2e.py
acceptance:
    scripts/acceptance.sh
