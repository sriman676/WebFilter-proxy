# Changelog

All notable changes per phase. Keep a Changelog format.

## [phase-4-complete] - 2026-10-31 - Phase 4: TLS interception (pentest in the final run, A-29)
### Added
- `tls` module: CA store (`ca generate|export`, safe key loading A-33), P-256 leaf minting with cache, ClientHello
  peek (SNI/ALPN/ECH), intercepted tunnels serving filtered inner requests, passthrough domains, always-verified
  upstream TLS (502 `upstream_cert_invalid`), `block_non_tls_connect`. Fuzz F-10 `client_hello`. README CA steps (Firefox only).
### Fixed
- PF-0-13: CA key checks done on the opened handle (symlink/owner/mode, TOCTOU).

## [phase-3-complete] - 2026-10-31 - Phase 3: client (M1 complete; pentest in the final run, A-29)
### Added
- `webfilter-client` (hyper 1.x, D-25/D-26): explicit proxy, manual CONNECT with block detection, always-verified TLS
  (+ `--ca-cert`), per-hop redirect validation, caps, atomic no-clobber saves, `--json`, exit codes 0/1/2/3,
  proxy auth via env/file only. `scripts/demo.sh` (ACCEPTANCE Part B) and `just demo`. Fuzz F-05/F-06.
- Test harness: `TestPki` (CA, wrong-name, expired, foreign-CA leaves) and TLS origins.
### Fixed
- PF-3-01: origins could forge `X-WebFilter-*` block headers through the proxy.

## [phase-2-complete] - 2026-10-31 - Phase 2: proxy server (built + tested; pentest in the final run, A-29)
### Added
- `proxy::http1` strict HTTP/1 core (R1-R15, shared framing, chunked re-encoding, httparse cross-check), `compat` switch (A-25).
- Pipeline (SPEC 4.2): validation, auth (argon2 off-thread, cache, lockout), canonicalization, port/destination policy,
  pre-DNS filtering, resolve-once, rule 3, fresh upstream per request, 100-continue, response rule 6, keep-alive/pipelining.
- CONNECT passthrough, websocket relay, connection limits (503), panic isolation, stats, graceful shutdown and signals
  (SIGINT/SIGTERM drain, SIGHUP reload, SIGUSR1 reopen), CLI overrides `--listen/--mode/--log-dir`, default `run`.
- Customization: custom block page template (A-26); named blocklist categories with time schedules (A-27).
- Tests: 172 (http1 rules, X-01 vs hyper, integration I-01..I-28, PT-2 regressions, categories/schedules); fuzz F-04/F-08/F-09.
### Fixed
- Websocket `Upgrade` stripped when named in `Connection` (found by I-17).

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
