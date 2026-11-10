# WebFilter Proxy - Project Report

**A multi-threaded, security-focused HTTP/HTTPS filtering proxy and fetch client, written in Rust.**

| | |
|---|---|
| Author | Sriman Rutvik |
| Version | 1.1.0 |
| Language | Rust 1.99.0 (edition 2024) |
| Size | about 18,000 lines of Rust in `src/`, 9,300 lines of tests, 15 build phases |
| Platforms | Linux (full feature set, incl. transparent mode); Windows (build host, explicit proxy) |

---

## 1. Problem and goals

The original assignment: *build a multi-threaded proxy server and client. The server accepts any URL from the
client, fetches it and returns the output; the client saves the output as an HTML page with an appropriate
name.*

The project keeps that core and grows it into a small but realistic **web-filtering gateway**, the kind of
component that sits between a school or company network and the internet:

1. **Proxy server** (`webfilter-proxy`): forwards HTTP and HTTPS for many clients at once, and decides for
   every request whether it may pass (blocklists, categories with schedules, threat feeds, malware scanning,
   per-user profiles and rate limits).
2. **Client** (`webfilter-client`): fetches URLs through the proxy and saves each one as a safely named HTML
   file; later extended with batches, retries, resume, offline snapshots and a polite crawler.
3. **Operations**: structured JSON logs for a SIEM (OpenSearch with 16 detections), a web dashboard, a
   terminal dashboard, a browser extension and WebAssembly rule plugins.

Security was a first-class goal: the proxy is an attacker-facing parser in the middle of every connection, so
the design follows "strict parsing, ambiguity is rejected, filter every request, never weaken TLS".

## 2. Architecture

```
            +---------------------------- webfilter-proxy (one process, tokio multi-thread runtime) ----------------------------+
 clients -->| listener -> HTTP/1 parser -> normalize URL -> identity/profile -> limits -> filter decision -> upstream (TLS verified) |--> origins
 (browser,  |              |  CONNECT -> passthrough tunnel | TLS interception (own CA) -> HTTP/1 or HTTP/2 (ALPN mirrored)        |
  curl,     |              |  transparent mode (Linux netns lab): original destination via SO_ORIGINAL_DST                       |
  client)   |  response path: content-type/extension rules -> download scanning (ClamAV/YARA, hashes) -> stream to client       |
            |  side services: JSON logger (4 streams) - admin API + dashboard - feeds updater - access requests - plugins     |
            +-------------------------------------------------------------------------------------------------------------------+
                  |                          |                                   |
          logs/*.jsonl --> OpenSearch    admin (loopback): dashboard, TUI,      threat feeds (https, guarded)
          (16 detections)                browser extension (read-only token)
```

Request life cycle (explicit proxy, plain HTTP):
1. Accept the TCP connection (per-IP and global connection caps).
2. Read the request head with strict limits (size, line count, timeouts) and parse it with the project's own
   HTTP/1 parser; anything ambiguous (duplicate `Content-Length`, `Transfer-Encoding` tricks, bad whitespace)
   is rejected, which defeats request smuggling.
3. Normalize the URL once (two independent parsers must agree; percent-decoding, dot segments, IDNA, IP
   forms), and from then on forward exactly what was checked.
4. Identify the client (proxy authentication with argon2id, or source address) and pick its profile; apply
   rate limits, concurrency limits, quotas and bandwidth shaping.
5. Decide: allowlist, threat feeds, temporary allows from approved access requests, local rules (domains,
   URL regexes, IP/CIDR, extensions, categories with time schedules), then WASM plugins. Blocked requests get a
   block page with an event id (and, if enabled, a "request access" form).
6. Resolve DNS once and connect to the validated IP (no DNS rebinding); private and metadata ranges are denied.
7. Stream the response, applying response rules and, for downloads, malware scanning before release.
8. Log one JSON event (never secrets, bodies or query values).

HTTPS: `CONNECT` is tunnelled byte-for-byte by default. With interception enabled (lab only, own CA), the proxy
terminates TLS with a per-host leaf certificate, applies the same filtering to each inner request, and opens its
own verified TLS connection upstream. HTTP/2 is supported only by mirroring the client's ALPN choice (never
translated between h1 and h2), with a frame-level flood guard.

## 3. Technologies used

| Area | Technology | Why |
|---|---|---|
| Language | **Rust 2024**, `unsafe_code = forbid`, no `unwrap`/`panic` on external input | memory safety for an attacker-facing network parser |
| Concurrency | **tokio** multi-thread runtime, one task per connection | thousands of concurrent connections on a few OS threads |
| HTTP/1 | **own parser** (validated against `httparse` in differential tests) | smuggling-resistant, strict rules we control |
| HTTP/2 | **h2** with a custom frame scanner (flood guard) | rapid-reset, CONTINUATION and ping floods detected |
| TLS | **rustls** (ring), **tokio-rustls**, **rcgen** for the lab CA, **webpki-roots** | memory-safe TLS; upstream certificates always verified |
| URLs | **url**, **idna**, **ipnet** | WHATWG parsing, IDN, CIDR matching |
| Matching | **regex** / **regex-automata** (DFA, size-limited) | linear-time URL patterns, no ReDoS |
| Hashing / crypto | **argon2** (passwords, tokens), **sha2**, **hmac** (CSRF), **subtle** (constant time), **zeroize** | safe credential handling |
| Config | **toml**, **serde**, **clap** | strict config (`deny_unknown_fields`), CLI |
| Hot reload | **arc-swap**, **moka** | lock-free policy swaps, bounded caches |
| Admin API | **hyper** server (loopback only) | dashboard, metrics, TUI, extension |
| Dashboard | vanilla **HTML/CSS/JavaScript**, strict CSP, canvas charts | no CDN, no frameworks, hostile data rendered as text |
| Terminal UI | **ratatui** + **crossterm** | live dashboard over SSH |
| Client HTML | **lol_html** (streaming rewriter) | snapshot sanitizing and link rewriting |
| Scanning | **ClamAV** (clamd INSTREAM), **YARA-X** (optional feature), SHA-256 hash lists | download malware checks |
| Plugins | **wasmtime** (optional feature): fuel, memory limits, no imports | safe operator-written rules |
| Browser | **WebExtension** Manifest V3 (Chrome and Firefox) | status badge, recent blocks, proxy toggle |
| Logging / SIEM | JSON lines, **OpenSearch** + security plugin, 16 detections, Docker Compose | SOC-style monitoring |
| Metrics | Prometheus text format, validated with **promtool** | standard monitoring |
| Testing | cargo **nextest**, **proptest**, **cargo-fuzz** (libFuzzer, 22 targets), **cargo-llvm-cov**, **h2spec**, **perf** | correctness, robustness, coverage, speed |
| Supply chain | **cargo-deny**, **cargo-audit**, **cargo-geiger**, CycloneDX SBOM | known-vulnerability and license gates |
| Lab | Linux network namespaces (transparent mode), Docker (ClamAV, OpenSearch) | realistic end-to-end tests |

## 4. Features

**Filtering (every request):** domain blocklists with suffix matching, URL regexes, IP/CIDR lists, blocked file
extensions and response content types, allowlist, named categories with weekly time schedules, enforce or
monitor mode, a custom block page with event id.

**Policies (v1.1):** users with argon2id passwords, client CIDR mapping, per-profile rules and modes; token-bucket
rate limits, connection/tunnel caps, daily quotas, bandwidth shaping; all reloadable at runtime.

**Threat feeds:** HTTPS-only fetching with TLS verification, size and sanity guards (refuses poisoned or
shrunken lists), versioned storage with rollback.

**Download scanning:** opt-in per profile; ClamAV and YARA verdicts and SHA-256 hash lists; detect or block
mode; explicit handling of unscannable content (encrypted, compressed, oversized).

**Admin and operations:** loopback-only admin API with Host allowlist (anti DNS-rebinding), Bearer token with
lockout, read-only token, no CORS; Prometheus metrics; a rich web dashboard with safe editing (validated,
versioned, audited, one-click rollback); a terminal dashboard; `doctor` self-check; access-request workflow
(users ask for a blocked site, admins approve a time-limited allow that never overrides feeds, scans or safety
policy).

**Client:** explicit proxy only, TLS always verified, redirects re-checked per hop, size and time limits,
no-clobber atomic saves with safe names; batches from a file, retries with backoff and `Retry-After`, JSONL
manifest with verified resume, partial-download resume, offline snapshots (scripts and handlers removed, CSP
injected, same-site assets only) and a crawler that always honors robots.txt.

**Extensions:** Chrome/Firefox extension (read-only); WebAssembly rule plugins that can only add blocks.

## 5. Concurrency model

One tokio task per client connection on a multi-thread runtime (`worker_threads` configurable). Shared state is
read-mostly and swapped atomically (`arc-swap`) on reload, so requests never wait for a reload. Every external
operation has a timeout (head read, body idle, connect, TLS, DNS, scanner, feeds), every buffer and map has a
size cap, and per-IP / per-profile limits bound what one client can consume. A panic in one connection is
isolated (release builds keep `panic = "unwind"`); poisoned locks are recovered.

## 6. Client naming scheme

`https://Example.COM./docs/a/../b.HTM?x=1` becomes `example.com_docs_b_q<hash8>.html`: lowercase host without
the trailing dot, default ports dropped (others as `_p8443`), path segments decoded once and joined with `_`,
`.html/.htm` stripped, the query replaced by a short hash, unsafe characters replaced, long names shortened with
a hash, reserved Windows names prefixed, then written atomically without overwriting (`-1`, `-2`, ...) and
without following symlinks.

## 7. Security design

The threat model (docs/THREAT_MODEL.md, STRIDE, 76 threats) maps every threat to a test. Highlights:
- **Request smuggling and parser differentials:** own strict HTTP/1 parser; dual URL parsers must agree.
- **SSRF and DNS rebinding:** resolve once, connect to the checked IP; private, loopback and metadata ranges
  denied; ports restricted.
- **TLS:** upstream certificates always verified, interception only with the lab's own CA; HTTP/2 never
  downgraded or translated.
- **Secrets and privacy:** never log credentials, bodies or query values; tokens hashed with argon2id;
  constant-time comparisons.
- **Admin surface:** loopback only, Host allowlist, Bearer token with lockout, no CORS, strict CSP, CSRF on the
  access-request form, all edits validated, versioned and audited.
- **Untrusted content:** dashboard, TUI and extension render data as text only; snapshots are sanitized; plugins
  run in a fuel- and memory-limited sandbox with no host access.
- **Fail closed:** unknown config keys, plugins in a binary without plugin support, scanner errors (in block
  mode) and plugin errors all refuse rather than allow.

## 8. Testing and quality evidence

| Kind | Evidence |
|---|---|
| Unit, integration and end-to-end tests | 340 tests (332 + 8 plugin tests) and 5 doc tests, all passing; end-to-end tests drive the real binaries |
| Coverage | 87.3 % line coverage (per-module gates pass) |
| Fuzzing | 22 libFuzzer targets (parsers, rewriters, robots, plugins); findings fixed with regression tests |
| Differential testing | own HTTP/1 parser vs `httparse`, URL normalizer vs WHATWG |
| HTTP/2 conformance | h2spec 147/147 |
| Real-tool interop | curl, wget, Python, git, HTTP/1.0, ranges, SSE; Firefox/Chrome; ClamAV; OpenSearch |
| SIEM | 2,163 events indexed, 56 alerts matching the offline evaluation, 0 canary leaks |
| Static gates | clippy `-D warnings` (incl. all features), rustfmt, cargo-deny, cargo-audit, SBOM, docs consistency |

## 9. Performance

Loopback measurements (WSL2, release build):

| Measurement | Result | Target (D-34) |
|---|---|---|
| Throughput, plain HTTP | 17,764 req/s, 0 errors | >= 2,000 req/s |
| Added p99 latency at 2,000 req/s | +0.33 ms | < 15 ms |
| Intercepted HTTPS (new TLS on both sides) | 13,741 req/s | >= 500 req/s |
| Memory at 1,000 concurrent connections | 36 MB | < 200 MB |
| Overhead with profiles, limits and metrics on | 0.2-2.1 % | <= 10 % |
| Stress test (A-40) | 42/42 checks: 1.88 M requests in 120 s with 0 errors, slowloris, 200 MiB bodies, HTTP/2 floods, 10,000 clients, chaos; RSS flat (55.7 -> 56.2 MB) | no crash, bounded memory, recovery |

Profiling (perf flamegraphs) shows time spread over socket I/O, the runtime and logging, and TLS handshake
cryptography for interception; no single hot spot.

## 10. Penetration testing

Every phase has a pentest plan (PT-x.y cases, 100+ cases across 14 phases) run in a consolidated final pentest,
plus three independent adversarial code reviews and one consolidated automated pentest of the whole codebase
(supply chain, static analysis, every test, release audit, UI checks, all 22 fuzz targets). Result: 45 findings
in total - 0 Critical, 0 High, 16 Medium, 29 Low - all fixed (`docs/pentest/final/FINAL_REPORT.md`). Every
finding received a regression test before its fix; reports are in `docs/pentest/`.

## 11. How to run

```bash
cp config/config.example.toml config/config.toml
cargo run --release --bin webfilter-proxy -- --config config/config.toml run      # 127.0.0.1:8080
cargo run --release --bin webfilter-client -- https://example.com                   # -> output/example.com.html
scripts/demo.sh                                                                     # offline assignment demo
just test        # full test suite (Linux/WSL)
```
Optional features: `--features yara` (YARA scanning), `--features plugins` (WASM rule plugins).

## 12. Limitations

- QUIC/HTTP/3 is not proxied (browsers fall back to TCP); ECH hides the real server name, so ECH-only traffic is
  blocked or passed by IP policy only.
- Certificate-pinned apps break under interception (by design: interception is opt-in, lab only).
- Transparent mode is Linux-only and meant for a lab network namespace.
- Scanning cannot see inside encrypted or compressed archives; such files follow the "unscannable" policy.

## 13. Repository map

`src/` proxy and client library, `src/bin/` the two binaries, `assets/admin/` dashboard, `extension/` browser
extension, `plugins/examples/` WASM example, `siem/` OpenSearch stack and detections, `scripts/` demo, tests,
pentest, load and stress tooling, `tests/` integration suites and corpora, `fuzz/` fuzz targets, `docs/`
specification, decisions, threat model, test and pentest plans and reports.

## 14. References

RFC 9110/9112 (HTTP semantics and HTTP/1.1), RFC 9113 (HTTP/2), RFC 8446 (TLS 1.3), RFC 9309 (robots.txt),
WHATWG URL Standard, OWASP request smuggling guidance, CVE-2023-44487 (HTTP/2 rapid reset), CycloneDX SBOM spec;
see docs/RESEARCH.md for the full list.
