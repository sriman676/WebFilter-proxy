# Test Plan (offline, deterministic, end-to-end)

## 1. Principles
- All tests run offline on loopback with generated PKI and local origins (D-29). No flaky sleeps:
  use readiness probes/channels with timeouts.
- Every bug found (by tests, fuzzing or pentest) gets a regression test BEFORE the fix.
- Pyramid: unit (U) > property (P) > fuzz (F) > integration (I) > end-to-end (E) > load (L) > SIEM (S).
- Coverage gate (cargo-llvm-cov): >= 85% lines for blocklist, normalize, policy, filter, logger, naming;
  >= 70% overall. Gate enforced in `just cov` and CI.
- `just test` = unit+property+integration; `just e2e` = E-suite; `just acceptance` = everything + all pentest automation.

## 2. Shared test harness (`tests/common/`, built in Phase 1-2, extended later)
| Helper | Capability |
|---|---|
| `TestPki` | generates a test root CA + leaf certs: valid, self-signed, expired, wrong-name, untrusted-CA, SHA-1 signed, TLS1.0-only config, mTLS-required (via rcgen/openssl scripts `scripts/gen_test_pki.sh`) |
| `Origin` | local HTTP/HTTPS server with programmable behavior: fixed body, chunked, slow drip, endless, huge declared CL, gzip when identity requested, redirects (to allowed/blocked/file:/loop), CRLF/response-splitting, websocket echo, records every received request (method/target/headers/raw bytes) so tests assert "origin never saw X" |
| `TestResolver` | implements `Resolver`: static map + scripted sequences (public then private for rebinding), counts lookups |
| `ProxyHarness` | `start(cfg)` on port 0 with temp log dir/blocklists; handle to edit lists, read parsed log lines, trigger reload/shutdown |
| `RawClient` | raw TCP sender for malformed/smuggling payloads (SM-xx), supports byte-at-a-time writes |
| `ClientRunner` | runs `webfilter-client` as a subprocess (assert_cmd) in a temp out-dir, returns exit code/stdout/files |
| `LogAssert` | validates every log line against LOG_SCHEMA (all keys present, types, enums, caps) |

## 3. Unit and property tests
Corpus-driven tests (table-driven, must pass): `url_bypass_cases.tsv`, `filename_cases.tsv`, `smuggling_cases.md`, `feed_cases.md` (FC-01..FC-30), `snapshot_html_cases.md` (SH-01..SH-22), `robots_cases.tsv` (RB-01..RB-15), `admin_host_cases.tsv` (AH-01..AH-20), `access_request_cases.tsv` (AR-01..AR-25).
- U-001..U-055: `tests/corpus/url_bypass_cases.tsv` through `canonicalize` + `evaluate` (table-driven).
- U-fn-001..: `tests/corpus/filename_cases.tsv` exact outputs; collision suffix; reserved names.
- U-cfg: valid/invalid configs (unknown key, bad port, non-loopback without auth, bad perms, relative paths).
- U-blocklist: grammar (apex/`*.`/`=`), IDN, limits, 50%-invalid rejection, dedup, hot reload swap, ReDoS timing.
- U-policy: private/metadata ranges, IPv4-mapped IPv6, port policy, loop detection.
- U-logger: all keys present, caps, control-char stripping, rotation without splitting lines, drop counter on full queue, never panics when disk errors.
- U-tls: leaf SAN/validity/key type/serial uniqueness, cache bounds, CA perms enforcement.
- U-auth: argon2 verify, constant-time path, lockout window.
- U-http: each rule R1-R15 with minimal inputs; response-side validation.
- P-01 canonicalize is idempotent and never panics on arbitrary strings (proptest). P-02 `output_filename`
  invariant regex always holds. P-03 normalized host matching equals reference suffix algorithm.
  P-04 blocklist parse(serialize(x)) == x. P-05 decision is invariant under case changes of host and
  under adding/removing the default port and trailing dot. P-07 token bucket never negative/overflows and refills monotonically; P-08 limiter keys fold IPv6 /64 and mapped addresses consistently; P-09 feed parser output is idempotent and order-independent; P-06 forwarded request line is derived only
  from `NormalizedTarget` (no raw substring survives).

## 4. Fuzz targets (`fuzz/`, nightly; smoke 60 s each in CI, 10 min each at pentest gates)
F-08 `response_head`, F-09 `chunked_codec` (round-trip + malformed), plus F-01 `normalize` (raw target strings), F-02 `blocklist_parse`, F-03 `naming`, F-04 `request_head`
(raw bytes into the HTTP head validator), F-05 `client_url`, F-06 `redirect_location`, F-07 `config_toml`.
F-13 `profiles_config`, F-14 `feed_parsers`, F-15 `clamd_reply`, F-16 `content_disposition`, F-17 `admin_router`, F-18 `form_body`, F-19 `html_rewrite`, F-20 `css_urls`, F-21 `robots`, F-22 `input_file`, plus F-10 `h2_frames` (frame sequences vs FloodGuard + validators), F-11 `client_hello` (TLS ClientHello/SNI/ECH parser), F-12 `transparent_http_head`.
Seed corpora from `tests/corpus/*`.

## 4b. Differential tests (X-xx, cross-parser)
X-01 generate/mutate request heads (from corpora + grammar-based + mutation of `smuggling_cases.md`); for each input compare our
validator+framer against `httparse` and hyper's server parser: if we ACCEPT, they must accept and agree on method, target,
headers and body length; if we reject while they accept, record as intentional strictness only if it maps to a rule R1-R15.
X-02 same for response heads vs hyper client. X-03 chunked codec vs hyper body decoder on random chunkings.
Optional X-04 (manual): replay `smuggling_cases.md` against Squid/nginx/mitmproxy in Docker to compare behavior and spot omissions.

## 5. Integration tests (I-xx; in-process proxy + harness)
I-01 allowed GET, I-02 blocked GET, I-03 POST body preserved (chunked and CL), I-04 HEAD/204/304,
I-05 100-continue, I-06 header stripping (4.4) both directions, I-07 `Proxy-*` never forwarded,
I-08 origin down 502, I-09 timeout 504, I-10 over-limit 503, I-11 block page headers/escaping,
I-12 monitor mode, I-13 allowlist precedence, I-14 hot reload, I-15 CONNECT passthrough,
I-16 CONNECT policy (ports, deny, passthrough rules 1-3 only), I-17 websocket handshake rule + relay,
I-18 auth flow, I-19 graceful shutdown, I-20..I-28 smuggling corpus SM-01..SM-25 via `RawClient`
(assert origin recorded 0 smuggled requests), I-ca-perms, I-panic (inject panic in a handler -> others
fine, `panic_isolated` event), I-block-page (XSS), I-client-tls (client TLS verification matrix).

I-h2-valid: each rule H1-H11 with a minimal violating and a minimal valid request (via `RawH2Client`).
I-h2-flood: rapid reset, MadeYouReset (server-caused resets), CONTINUATION flood, HPACK bomb, control-frame floods, flow-control stall - each yields GOAWAY and an `h2_flood` event while a parallel healthy connection keeps working.
I-transparent-http / I-transparent-tls: full transparent flows using `FixedOriginalDst` (no root needed): Host/SNI verification matrix, no-SNI, ECH, passthrough with ClientHello replay, direct-connect rejection, loop rejection.

## 6. End-to-end tests (E-xx) - real binaries as subprocesses (`webfilter-proxy` + `webfilter-client`)
| ID | Scenario | Expected |
|---|---|---|
| E-01 | client http://origin/ via proxy | exit 0; file named per SPEC 5.3; log `allowed` schema-valid |
| E-02 | https via CONNECT, intercept off | page saved; log `tls_intercepted=false`, domain-level |
| E-03 | https with interception: (a) client with `--ca-cert`, (b) without | (a) saved, inner URL/path logged; (b) exit 1 TLS verify failure |
| E-04 | blocked domain | client exit 3, prints BLOCKED + event_id; origin saw nothing; log `blocked` with same event_id |
| E-05 | subdomain of blocked vs `notevil` | subdomain blocked; notevil allowed |
| E-06 | URL pattern blocks one HTTPS path (intercept on) | that path blocked, rest of site allowed |
| E-07 | extension rule | blocked `.exe`, allowed `.html` |
| E-08 | content-type rule (response phase) | body never reaches client; log `ctype:` |
| E-09 | monitor mode | page delivered; `would_block=true`; exit 0 |
| E-10 | allowlist vs blocklist | allowlist wins |
| E-11 | hot reload: add entry / remove / write invalid file / delete file | enforced within interval; invalid keeps old + system event |
| E-12 | redirect chain allowed->blocked; loop; >max redirects | blocked at hop; loop & max error exit 1 |
| E-13 | redirect to `file://`, `ftp://` | client rejects; exit 1; nothing saved |
| E-14 | 200 concurrent fetches (client `--jobs 32`) | 200 distinct files, 200 valid log lines, no corruption |
| E-15 | origin slower than upstream timeout | 504 `timeout`; client exit 1 |
| E-16 | origin down | 502 `upstream_error` |
| E-17 | upstream bad cert (self-signed, expired, wrong-name, untrusted CA, SHA-1) | 502 `upstream_cert_invalid`; no origin data leaks to client |
| E-18 | passthrough domain with intercept on | not decrypted; `tls_intercepted=false` |
| E-19 | proxy auth: none/wrong/right; lockout | 407 / 407 / 200; 429 after 5 failures; password absent from logs |
| E-20 | port policy (CONNECT 25, GET :6379) | 403 `port_not_allowed`; no connection to those listeners |
| E-21 | `deny_private_ranges=true` vs loopback origin; metadata IP with flag false | 403 `private_range` |
| E-22 | DNS rebinding simulation | connection uses first validated IP; resolver lookups == 1 |
| E-23 | request to the proxy itself | 508 |
| E-24 | SIGTERM mid-transfer | in-flight completes <= 10 s; logs flushed; exit 0 |
| E-25 | rotation under 16 concurrent writers (small `max_bytes`) | no lost/partial/duplicated lines across files |
| E-26 | 200 MB streamed response | proxy RSS growth < 50 MB; client `--max-bytes` honoured |
| E-27 | websocket echo through proxy; URL rule on handshake | works; blocked handshake 403 |
| E-28 | OpenSearch ingest (Docker, `just siem-e2e`): proxy logs -> Fluent Bit -> indices; detections | every line indexed; detections equal the offline evaluation |
| E-29 | same URL fetched twice | `name.html` and `name-1.html`; no overwrite; symlink pre-planted not followed |
| E-30 | canary secrets in Cookie/Authorization/Proxy-Authorization/Set-Cookie/query value/body | canary absent from all logs |
| E-31 | chunked POST body 5 MB | origin receives identical bytes |
| E-32 | `Expect: 100-continue`, HEAD, 204, 304, 1xx | correct framing, no hang |
| E-33 | keep-alive: allowed then blocked host on same connection; pipelined pair | each request filtered independently |
| E-34 | intercepted tunnel with Host != CONNECT host; SNI != CONNECT host | `host_mismatch` / `sni_mismatch` blocks |
| E-35 | `check-config`, `hash-password`, `ca generate/export`, `blocklist test` subcommands | documented outputs/exit codes |
| E-36 | non-loopback bind without auth | process exits 2 with clear message |
| E-37 | curl `--http2` through the intercepting proxy to an h2 origin | negotiates h2; page OK; log `http_version=2`, `alpn=h2`, `h2_stream_id` set |
| E-38 | ALPN mirroring matrix: client {h1, h2} x origin {h1, h2} | client protocol == upstream protocol in all four cases (assert via origin-recorded protocol); no translation |
| E-39 | 50 concurrent h2 streams, 10 blocked | each stream correct; blocked get 403 block page over h2; allowed unaffected |
| E-40 | 8 parallel 100 MB h2 downloads (flow control) | SHA-256 matches; RSS growth < 100 MB |
| E-41 | `h2spec` (via socat CONNECT forwarder to the interception path) | 0 mandatory failures |
| E-42 | rapid reset 10k streams on one connection | GOAWAY ENHANCE_YOUR_CALM, `h2_flood` event, other connections fine |
| E-43 | h2 preface / `Upgrade: h2c` sent to the plain listener | rejected, logged `invalid_request`, origin sees nothing |
| E-44 | (netns, root) client without proxy settings fetches `http://name/` ; teardown | logged `transparent=true`, `orig_dst_*`; blocked domain 403; teardown restores host exactly |
| E-45 | (netns) transparent HTTPS with the test CA; path rule on inner URL | page OK; blocked path 403; SNI logged |
| E-46 | (netns) Host/SNI vs original IP mismatch, strict and relaxed | strict -> `host_mismatch` block; relaxed -> allowed with `host_verified=false`; upstream IP == original IP |
| E-47 | (netns) no-SNI and ECH-extension ClientHellos | behavior per `no_sni_action` / `ech_action` |
| E-48 | direct connection to transparent listeners (no redirect) | closed + `orig_dst_failed`; no upstream connection |
| E-49 | (netns) client targets the proxy's own IP; proxy's own outbound traffic | dropped as loop; no recursion; uid exemption works |
| E-50 | (netns) passthrough domain over transparent TLS | handshake with real origin completes; bytes intact (ClientHello replayed) |
| E-51 | non-root equivalents of E-44..E-50 using `FixedOriginalDst` | all pass in normal CI |
| E-52 | blocked domain/URL/extension (rules 1,2,4,5) | `TestResolver` lookup count == 0; 403 returned; same for blocked CONNECT host |
| E-53 | profile resolution matrix (user, CIDR overlap, default) with different lists | correct profile; safety policy unchanged; logs carry client_id/profile |
| E-54 | request-rate and concurrency limits | 429/503 with Retry-After; recovery after refill |
| E-55 | bandwidth cap (down and up) | throughput within 15 percent of cap; SHA-256 identical |
| E-56 | daily quota with injectable clock | 429 quota_exceeded until UTC midnight |
| E-57 | 200k distinct source keys incl. IPv6 /64 rotation | limiter memory bounded; /64 counted once |
| E-58 | monitor mode with limits | content rules log-only; limits enforced |
| E-59 | feed update from local HTTPS feed server (test CA) | list active; hit logged as feed:name; metrics updated |
| E-60 | poisoned feeds (TLD, protected domains, mass change, oversize) | rejected; last-good kept; feed_rejected event |
| E-61 | feed rollback and expiry | previous version restored; expired feed deactivated |
| E-62 | feed transport attacks (redirect to http/private IP, TLS failure, key on redirect) | refused; no key leak |
| E-63 | detect-mode scan with clamd (Docker) and EICAR | delivered; scan_status=infected logged; alert event |
| E-64 | block-mode scan | EICAR -> 403 malware_detected; clean file byte-identical (hash); temp files removed; no body in logs |
| E-65 | unscannable matrix (oversize, 206, gzip, clamd down, quota) x both actions | per unscannable_action |
| E-66 | hash blocklist hot reload | hit logged hash_blocklist |
| E-67 | YARA rule hit (feature yara) | verdict logged; timeout handled |
| E-68 | /healthz and /readyz states | 200/503 as specified; no info leak |
| E-69 | /metrics validated by promtool; cardinality test | valid; series count stable |
| E-70 | admin auth/Host/Origin/CORS matrix | per O1 |
| E-71 | admin API actions + audit log | actions work; every state change audited |
| E-72 | web UI smoke in headless browser with hostile data | renders inert text; no CSP violations; ui_lint passes |
| E-73 | TUI via test backend with escape-sequence data | sanitized; terminal restored |
| E-74 | access request happy path | form -> request -> approve -> allowed for requester only -> expires -> blocked |
| E-75 | access request negative matrix | rejected cases per O6; no upstream traffic to webfilter.local |
| E-76 | temp allows persist across restart; tampered file | loaded; invalid file rejected safely |
| E-77 | `doctor` outputs | PASS/WARN/FAIL correct; no secrets |
| E-78 | client --input-file, dedupe, retries against a flapping origin | backoff, caps, BLOCKED never retried |
| E-79 | client --manifest --resume after SIGKILL | only remaining URLs fetched; files identical |
| E-80 | snapshot opened offline in headless browser (Chromium and Firefox) | local images/CSS load (CSP not over-blocking); zero network requests; scripts absent; CSP present |
| E-81 | crawl depth/page caps, robots, traps | contained and reported |
| E-82 | snapshot/crawl through proxy with blocked assets and 429s | omitted and reported; backoff |
| E-83 | feature interaction pairs (profiles, scan, feeds, h2, transparent, access requests) | no safety bypass |

## 6b. Real-world compatibility (C-xx; Phase 8, local only)
C-01 curl (http, https tunnel, intercepted with CA) ; C-02 wget ; C-03 Python `requests` via `HTTPS_PROXY` ; C-04 `git ls-remote`
over proxy to a local test git-http server ; C-05 HTTP/1.0 client (`ab` or raw) ; C-06 Firefox and Chromium with a throwaway
profile, proxy set, CA imported (manual checklist: load local test sites, a large download, a websocket page, a site that
prefers HTTP/2 -> falls back to h1) ; C-07 large file resume (`Range`) ; C-08 `Transfer-Encoding: chunked` streaming (SSE) ;
C-09 IPv6 loopback listener ; C-10 admin web UI in Firefox and Chromium (manual checklist: CSP console clean, hostile data inert) ; C-11 TUI in xterm, tmux and a Linux console. Record results in `docs/COMPATIBILITY.md`.

## 7. Load / soak (L-xx; `just load`, Phase 8)
L-01 oha 2,000 rps plain HTTP 60 s: 0 errors, p99 added latency < 15 ms vs direct. L-02 1,000 concurrent
connections: RSS < 200 MB. L-03 slow-client mix (slowhttptest) while load runs: healthy clients unaffected.
L-04 intercepted HTTPS 500 rps, cache hit ratio reported. L-05 1 h soak: RSS slope ~0, fd count stable. L-06 repeat L-01/L-02 with limits, profiles and metrics on (overhead <= 10 percent). L-07 scanning throughput report (detect vs block).

## 8. SIEM tests (S-xx; OpenSearch, A-14)
S-01 the index templates map every schema field from a 1k-line sample; timestamps correct. S-02 each
detection returns expected rows on a generated dataset. S-03 detection replay from PT-5.5. S-04 no query
returns canary tokens. S-05 the v1.1 detections (rate limiting, malware, feeds, access requests, admin audit) return expected rows on a generated dataset.
Fallback when Docker is unavailable: `just siem-test` (offline S-01/S-02/S-03/S-05 with the same detection code);
record the limitation in the phase report (not a blocker).

## 9. CI matrix
Ubuntu + macOS: fmt, clippy (`-D warnings`), `cargo nextest`, coverage gate (Linux), e2e (Linux), `cargo deny`,
`cargo audit`, fuzz smoke (Linux nightly, 60 s/target), release build with `insecure-test` assertion.
Nightly schedule: fuzz 10 min/target, soak 20 min.
