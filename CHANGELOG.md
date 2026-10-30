# Changelog

All notable changes per phase. Keep a Changelog format.

## [phase-0-complete] - 2026-10-30 - Phase 0: environment & scaffold
### Added
- `src/lib.rs`, `src/config.rs` (SPEC 6 schema + validation, `check-config`), binary stubs `webfilter-proxy` / `webfilter-client`.
- U-cfg tests (`tests/config_tests.rs`), `check-config` CLI tests, harness skeleton `tests/common`.
- `fuzz/` cargo-fuzz package with `config_toml` target.
- `justfile` (all SPEC 10 targets; later-phase targets print TODO and exit 1), `scripts/check_env.sh`,
  `scripts/pentest_p0.sh`, `scripts/check_gitignore.py`, `scripts/bootstrap_deps.sh`, `scripts/hooks/pre-commit`.
- `.github/workflows/ci.yml` (actions pinned by SHA, `--locked`, release `insecure-test` assertion, fuzz smoke).
### Changed
- Simplification pass (A-13): limit checks are merged into one range table, a single `Redacted<T>` replaces
  three hand-written `Debug` impls, and rustfmt uses `use_small_heuristics = "Max"` (A-17); `config.rs` is 917 -> 804 lines.
- Splunk is replaced by OpenSearch for Phase 5 (A-14).
### Fixed
- PF-0-02..07, PF-0-08..12 (security review): secret-safe parse errors, limit caps, HOME/ca_dir handling, admin token required,
  config size cap, redacted Debug, pentest/fuzz script exit codes, aws-lc ban, CI credentials, more gitignore patterns.
- PF-0-01: `.gitignore` now covers PFX/CRT/DER/JKS/token/.env.* files and fuzz/coverage artefacts.
### Decisions
- Addendum A-01..A-17. Resolved crate versions are in ENVIRONMENT.md.
