# Changelog

All notable changes per phase. Keep a Changelog format.

## [phase-14-complete] - 2026-11-10 - Phase 14: browser extension and WASM rule plugins (pentest in the final run, A-29)
### Added
- `extension/`: Chrome/Firefox MV3 extension (badge, recent blocks, request access, proxy toggle) using the
  admin API read-only; `just ext-lint`.
- `[admin] readonly_token_hash`: a token that can only read (O9).
- Rule plugins behind the `plugins` feature: wasmtime sandbox with fuel, memory limits and no imports, fresh
  instance per call, `on_error` fail closed by default, `/api/v1/plugins` and plugin metrics; example
  `plugins/examples/block_keyword.wat`; `just plugins-test`, fuzz target F-23, `just pentest-p14`.

## [phase-13-complete] - 2026-11-10 - Phase 13: final v1.1 regression (pentest in the final run, A-29)
### Added
- `tests/interaction_tests.rs` (E-83 feature interactions, PT-13.3 upgrade path) and an h2 x limits test.
- `just load-features` (L-06: 2.1 % max-throughput overhead with profiles, limits and metrics on).
- `just ui-e2e` (E-80: snapshot opened offline in headless Chromium, verified by screenshot pixels).
- `just pentest-p13`; `just acceptance` runs the v1.1 steps 18-24; `just e2e` covers the v1.1 suites.
### Changed
- `just audit` also checks the all-features dependency graph; two yara-x-only advisories accepted with
  reasons (A-45). Shared test helpers `eicar()` / `fake_clamd()` moved to `tests/common`.

## [phase-12-complete] - 2026-11-09 - Phase 12: client batches, retries, resume, snapshots, crawl (pentest in the final run, A-29)
### Added
- `--input-file` (with `-` for stdin), `--retries`/`--retry-max-delay` (Retry-After aware, never retrying blocks,
  TLS or usage errors), `--manifest` JSONL with a lock file and verified `--resume`, `--resume-partial` (If-Range).
- `--snapshot` (lol_html sanitizer, same-site assets with caps and media-type checks, CSP meta, report),
  `--snapshot-allow-scripts`, `--snapshot-extra-host`.
- `--crawl-depth`, `--max-pages`, `--crawl-subdomains`, `--crawl-delay-ms`, `--crawl-timeout`: BFS with an RFC 9309
  robots.txt parser, politeness, trap caps, link rewriting and `index.html`.
- `--json` fields `attempts`, `snapshot_report`, `crawl_depth`; summary line; fuzz targets F-19..F-22; `just pentest-p12`.
### Fixed
- PF-12-01 manifest after a crash; PF-12-02..04 snapshot sanitizer edge cases found by fuzzing.

## [phase-11-complete] - 2026-11-09 - Phase 11: operations, admin, dashboard, access requests (pentest in the final run, A-29)
### Added
- Admin listener (loopback, off by default): Host allowlist on every route, Bearer token with lockout, Origin
  checks, security headers, audit log; `/healthz`, `/readyz`, `/metrics` (promtool-clean), `/api/v1/*`.
- Rich web dashboard (`assets/admin/`, vanilla JS, strict CSP): overview with live charts, events with search,
  top blocked, clients, feeds, scans, access requests, temp allows, audit, and safeguarded editing of lists,
  categories/schedules, allowlist and mode with versions and one-click rollback (A-30).
- Access requests: block-page form with HMAC CSRF, reserved `webfilter.local` host, rate limits, temp allows
  scoped to client or profile (never over feeds, scans or safety policy).
- `webfilter-proxy tui` (ratatui) and `webfilter-proxy doctor`; `just promtool`, `just pentest-p11`.
### Fixed
- PF-11-01: Host with a trailing dot refused.

## [phase-10-complete] - 2026-11-09 - Phase 10: threat feeds, download hashing and scanning (pentest in the final run, A-29)
### Added
- `feeds` (D-52): verified HTTPS fetch with destination policy, caps, conditional GET, backoff; per-format
  parsers with poisoning guards; versioned store (5 kept), rollback, expiry; `feeds status|update|rollback|test`;
  matching in rules 2/3/4 per profile.
- `scan` (D-53/D-54): eligibility by extension/type/magic; detect and block modes on HTTP/1 and intercepted h2;
  0600 temp files with quota and concurrency caps; hash blocklist (hot reload); clamd INSTREAM; YARA via
  `yara-x` (feature `yara`); `scan_*`/`body_*`/`download_name` log fields; `malware_detected` events.
- `just scan-e2e` (pinned ClamAV container), `just feeds-test`, `just pentest-p10`; fuzz F-14/F-15/F-16.
- `just h2spec` now uses an h2 mode of the loadgen origin (147/147 strict); live `siem-e2e` passed.
### Fixed
- PF-10-01 feed `*.` form lost; PF-10-02 version-name reuse; PF-10-03 shipped config enabled v1.1 limits.

## [phase-9-complete] - 2026-10-31 - Phase 9: identity, profiles, rate limits, quotas (pentest in the final run, A-29)
### Added
- `[[users]]`, `[[clients]]`, `[[profiles]]` (D-50): per-request `client_id`, longest-prefix CIDR profiles,
  profile lists/allowlists/overrides that never touch safety policy, hot reload (SIGHUP/mtime) with rollback.
- `limiter` (D-51): requests/s + burst, in-flight, connections, tunnels, daily quota (429/503 + Retry-After),
  shared per-client bandwidth caps that delay bytes; enforced in monitor mode; per-profile stats.
- Multi-user auth with per-user lockout and equal-cost unknown users. Fuzz F-13 and `limiter`; `just pentest-p9`.
### Fixed
- PF-9-01: slow start delayed signal handling.

## [phase-8-complete] - 2026-10-31 - Phase 8: hardening, performance, release (pentest in the final run, A-29)
### Added
- `just load` (offline load generator, L-01..L-05; D-34 met with wide margins), `just compat` (C-01..C-09),
  `just release-audit` (feature/strings check, geiger, SBOM, gitleaks), `just e2e`, `just acceptance`.
- `deploy/` systemd unit (hardened) and non-root Dockerfile; README quick start, customization, deployment,
  architecture and limitations.
### Fixed
- PF-8-01: minted leaves lacked AKI/EKU and were rejected by strict validators.

## [phase-7-complete] - 2026-10-31 - Phase 7: transparent mode (Linux lab; pentest in the final run, A-29)
### Added
- Transparent HTTP and TLS listeners (SPEC 4.17): `OriginalDst` via `SO_ORIGINAL_DST` (`nix`, no unsafe), conntrack
  fallback, injectable for tests; host verification strict/relaxed; no-SNI/ECH actions; interception reusing the
  CONNECT path with inner Host bound to SNI; passthrough with ClientHello replay; direct/loop connections closed.
- `scripts/netns_lab.sh` (idempotent `up|down|status`, table `inet wf_lab`), `just e2e-netns`, `just pentest-p7`,
  fuzz F-12 `transparent_http_head`, README lab section. Shared test helpers (ClientHello builders, TLS client config).
### Fixed
- PF-7-01: transparent HTTP skipped the destination policy for the original IP.

## [phase-6-complete] - 2026-10-31 - Phase 6: HTTP/2 inside intercepted TLS (pentest in the final run, A-29)
### Added
- ALPN mirroring (D-40): h2 only when both client and origin chose it; never h1<->h2 translation, never h2c.
- `proxy::h2`: per-stream pipeline (H1-H11) over one upstream h2 connection per client connection; block pages,
  rule 6 and log fields (`http_version=2`, `alpn`, `h2_stream_id`) over h2.
- `proxy::h2guard` flood guard (D-45, A-36): rapid reset/ratio, MadeYouReset, control floods, CONTINUATION,
  stream budget, stall and idle timeouts; `h2_flood` events and stats counter. Fuzz F-10 `h2_frames`.
- `just pentest-p6`, `just h2spec` (h2spec via socat CONNECT forwarder; skip when tools are missing).
### Fixed
- PF-6-01: floods stopped by `h2`'s built-in limits were not logged as `h2_flood`.

## [phase-5-complete] - 2026-10-31 - Phase 5: observability, OpenSearch, detections (M2 complete; pentest in the final run, A-29)
### Added
- SIEM on OpenSearch instead of Splunk (A-14, A-35): `siem/opensearch/` (compose with security plugin, Fluent Bit,
  index templates, 16 detections in `detections.json`, DETECTIONS.md), `scripts/siem/` (evaluator, labelled dataset
  generator, offline `just siem-test` in `just test`, live `just siem-e2e`), `just pentest-p5`.
- System events: `config_loaded` with the config path; `insecure_permissions` for world-writable policy files (PT-5.4).
- Tests: E-25 rotation with 16 writers, PT-5.1 injection end to end, PT-5.4.
### Removed
- `splunk/` configs (superseded by A-14).

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
