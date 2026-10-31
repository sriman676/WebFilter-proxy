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
    cargo test --locked --features insecure-test --doc

cov:
    cargo llvm-cov nextest --locked --features insecure-test --json --summary-only | python3 scripts/cov_gate.py

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
    cargo audit
    cargo geiger --all-features

sbom:
    cargo cyclonedx --format json

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
    @echo "TODO: pentest-p3 lands in Phase 3 (PENTEST_PLAN PT-3.x)" >&2; exit 1
pentest-p4:
    @echo "TODO: pentest-p4 lands in Phase 4 (PENTEST_PLAN PT-4.x)" >&2; exit 1
pentest-p5:
    @echo "TODO: pentest-p5 lands in Phase 5 (PENTEST_PLAN PT-5.x)" >&2; exit 1
pentest-p6:
    @echo "TODO: pentest-p6 lands in Phase 6 (PENTEST_PLAN PT-6.x)" >&2; exit 1
pentest-p7:
    @echo "TODO: pentest-p7 lands in Phase 7 (PENTEST_PLAN PT-7.x)" >&2; exit 1
pentest-p8:
    @echo "TODO: pentest-p8 lands in Phase 8 (PENTEST_PLAN PT-8.x)" >&2; exit 1
pentest-p9:
    @echo "TODO: pentest-p9 lands in Phase 9 (PENTEST_PLAN_EXT PT-9.x)" >&2; exit 1
pentest-p10:
    @echo "TODO: pentest-p10 lands in Phase 10 (PENTEST_PLAN_EXT PT-10.x)" >&2; exit 1
pentest-p11:
    @echo "TODO: pentest-p11 lands in Phase 11 (PENTEST_PLAN_EXT PT-11.x)" >&2; exit 1
pentest-p12:
    @echo "TODO: pentest-p12 lands in Phase 12 (PENTEST_PLAN_EXT PT-12.x)" >&2; exit 1
pentest-p13:
    @echo "TODO: pentest-p13 lands in Phase 13 (PENTEST_PLAN_EXT PT-13.x)" >&2; exit 1

# --- end-to-end and external suites (later phases) --------------------------------------
e2e:
    @echo "TODO: e2e lands in Phase 1 (offline end-to-end tests, TEST_PLAN E-xx)" >&2; exit 1
load:
    @echo "TODO: load lands in Phase 8 (TEST_PLAN L-xx, D-34)" >&2; exit 1
splunk-e2e:
    @echo "TODO: splunk-e2e lands in Phase 5 (TEST_PLAN S-xx)" >&2; exit 1
h2spec:
    @echo "TODO: h2spec lands in Phase 6 (SPEC 4.16)" >&2; exit 1
e2e-netns:
    @echo "TODO: e2e-netns lands in Phase 7 (Linux, sudo; D-43)" >&2; exit 1
feeds-test:
    @echo "TODO: feeds-test lands in Phase 10 (SPEC_EXT_POLICY P3)" >&2; exit 1
scan-e2e:
    @echo "TODO: scan-e2e lands in Phase 10 (Docker clamd, E-63..E-67)" >&2; exit 1
promtool:
    @echo "TODO: promtool lands in Phase 11 (metrics format, D-56)" >&2; exit 1
ui-lint:
    python3 scripts/ui_lint.py
ui-e2e:
    @echo "TODO: ui-e2e lands in Phase 11 (headless browser, E-72, E-80)" >&2; exit 1
acceptance:
    @echo "TODO: acceptance lands in Phase 8 (docs/ACCEPTANCE.md runs everything)" >&2; exit 1
