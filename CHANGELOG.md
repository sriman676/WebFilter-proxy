# Changelog

All notable changes per phase. Keep a Changelog format.

## [phase-1-complete] - 2026-10-31 - Phase 1: core library
### Added
- `normalize` (SPEC 4.5, dual-parser differential), `blocklist` (grammar, limits, hot reload), `filter` (rule order, monitor),
  `policy` (ports, destination, loop; injectable resolver), `logger` (schema, caps, rotation, drop counter, stats),
  `naming` (SPEC 5.3 + safe unique writes), `auth` (argon2id, constant-time path, lockout), `reason`.
- CLI: `blocklist test <url>`, `hash-password`. Fuzz targets F-01..F-03. `just pentest-p1`, per-module coverage gate.
- Tests: U-001..U-055, U-fn corpus, U-blocklist/policy/logger/auth, P-01..P-06, PT regressions (100 tests).
### Fixed
- PF-1-01 (regex DoS with large pattern lists) and PF-1-02..13 from the security review.
### Decisions
- A-18..A-28 (incl. regex-automata, raw-path naming oracle, parallel worktree, customization choices, up-front answers).

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
