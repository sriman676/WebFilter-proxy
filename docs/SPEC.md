# Specification v2 (complete)

Normative words: MUST / MUST NOT / SHOULD. Decisions in DECISIONS.md are final.

## 1. Overview
One Rust package, two programs sharing a library:
- **`webfilter-proxy`** - multi-threaded forward proxy (standard HTTP proxy protocol:
  absolute-form requests + `CONNECT`), blocklist filtering, optional full TLS interception,
  JSON logs for a SIEM (OpenSearch, A-14).
- **`webfilter-client`** - fetches URLs *through the proxy* and saves each response as an HTML
  file with a deterministic, safe name.

Non-goals: HTTP/3/QUIC, cleartext h2c, TPROXY, authentication beyond Basic proxy auth, DNS
filtering, Windows/macOS transparent mode. (v1.1 adds opt-in download scanning, admin UI/metrics, feeds, profiles and limits: SPEC_EXT_*.) (HTTP/2 inside intercepted TLS = Phase 6; transparent mode on Linux = Phase 7.)

## 2. Glossary
Target = the URL/authority the client asked the proxy to reach. Normalized target = canonical
form produced by 4.5. Intercepted = TLS terminated by the proxy with a minted leaf certificate.
Passthrough = CONNECT tunnel relayed without decryption.

## 3. Architecture
```
 client (browser/curl/webfilter-client)
    | TCP  (trust boundary B1: untrusted clients)
    v
 [accept + limits] -> [HTTP parse/validate] -> [auth] -> [target canonicalize] -> [dest policy]
    -> [filter: allow/block rules] -> [forward upstream]  ---- TCP/TLS ----> origin
                                         |                (boundary B2: untrusted origins)
                                         +-> [EventLogger] -> logs/*.jsonl -> Fluent Bit
 [CA store ~/.webfilter]  (boundary B3: secrets)      [config + blocklists] (boundary B4: operator files)
```
Modules: `config`, `blocklist`, `normalize`, `policy` (dest/port rules), `filter`, `logger`,
`stats`, `tls` (CA + leaf minting), `proxy` (`http1` core: head reader, validator, body framer, chunked codec, relay; plus handlers), `client`, `naming`.
Contracts: INTERFACES.md.

## 4. Proxy

### 4.1 Listener
Bind `listen` (default `127.0.0.1:8080`). Non-loopback bind requires `proxy_auth` (D-13).
At start-up warn (and `doctor` fails) if `RLIMIT_NOFILE` < 4 x `max_connections` (D-67). Enforce `max_connections` and `max_connections_per_ip`; over limit -> 503 + `Retry-After: 5`.

### 4.2 Request pipeline (every request, in this order; any failure stops the pipeline, returns the
mapped error in 4.12, and emits exactly one log event)
1. Accept, apply connection limits, start timers.
2. Read request head within limits (4.11). Validate per 4.3.
3. Proxy auth if enabled (407 on failure, lockout rules). 3b. (v1.1) Resolve `client_id`/profile and apply rate limits (SPEC_EXT_POLICY P1-P2).
4. Reject `TRACE`; reject unsupported targets (4.3 R9).
5. Canonicalize target (4.5). Dual-parser differential check.
6. Loop check: normalized target authority resolves to / equals the proxy's own listen address -> 508.
7. Port policy (D-12).
8. Pre-DNS filter: rules 1, 2, 4, 5 of 4.6 (allowlist, domain, URL, extension) on the normalized target. A block here
   happens BEFORE any DNS lookup (no resolver query is ever made for a blocked name).
9. Resolve DNS once; apply destination policy (D-11) to ALL resolved IPs and choose one validated IP; then rule 3 of 4.6
   (`ip_blocklist`, also for literal-IP hosts). `mode=monitor` logs but does not block.
10. Forward: rebuild the request from normalized fields, connect to the validated IP, stream body.
11. Response: validate framing, apply response-phase rule 6 (content-type), stream to client.
12. Log event (blocked or completed). Close/reuse connection per D-07 and D-37.
Pipeline MUST run for EVERY request on a keep-alive connection (D-10).

### 4.3 HTTP validation rules (violations -> 400 `invalid_request` unless noted)
| Rule | Requirement |
|---|---|
| R1 | Both `Content-Length` and `Transfer-Encoding` present -> reject. |
| R2 | More than one `Content-Length` header (even identical), or value not purely `[0-9]+`, or > 2^63-1 -> reject. |
| R3 | `Transfer-Encoding` value must be exactly `chunked` (case-insensitive, no spaces/tabs/lists/obfuscation) else reject. TE on HTTP/1.0 -> reject. |
| R4 | Whitespace between field-name and `:` -> reject. Obsolete line folding (line beginning SP/HT) -> reject. |
| R5 | Bare CR or bare LF in the head -> reject. NUL/control characters in names/values -> reject. Invalid token characters in field names/method -> reject. |
| R6 | Version must be `HTTP/1.0` or `HTTP/1.1` else 505. |
| R7 | At most one `Host`. Absolute-form: if `Host` present it MUST equal the target authority (case-insensitive, default port normalized) else reject. HTTP/1.1 origin-form inside an intercepted tunnel requires exactly one `Host` equal to the CONNECT authority (D-22 -> `host_mismatch`, 403 blocked). |
| R8 | `Connection` header listing `content-length`, `transfer-encoding` or `host` -> reject. Other tokens name hop-by-hop headers to strip (4.4). |
| R9 | Allowed request-target forms: absolute-form (`http://...`) for plain requests; authority-form for `CONNECT`; origin-form ONLY inside an intercepted tunnel. `https://` absolute-form on the plain listener, `*` form, and origin-form on the plain listener -> reject. |
| R10 | `Upgrade` allowed only with value `websocket` (+ `Connection: upgrade`); any other value (e.g. `h2c`) -> reject. |
| R11 | `TE` header: strip unless exactly `trailers`. |
| R12 | Request line + headers within limits (4.11): too large -> 431; URI too long -> 414. |
| R13 | `Expect: 100-continue`: forward; relay `100 Continue` only after upstream sends it (do not synthesize). |
| R14 | Methods: any valid token except `TRACE` (405). `CONNECT` must use authority-form `host:port`. |
| R15 | Request bodies: stream; chunked framing is re-generated by the engine, never copied raw. |
Response-side: upstream responses with both CL and TE, multiple/invalid CL, invalid chunk framing,
CR/LF/NUL in header values, or invalid status line -> 502 `upstream_error` (never forwarded raw).
`HEAD`, `204`, `304`, `1xx` carry no body regardless of headers. Close-delimited responses (no CL, not chunked) are streamed to EOF and the client connection is then closed (D-37). The proxy never caches.

### 4.4 Header handling
Strip before forwarding (request and response): `Connection` + any header it names, `Proxy-Connection`,
`Keep-Alive`, `TE` (per R11), `Trailer` (unless chunked trailers supported), `Transfer-Encoding`
(re-generated), `Upgrade` (except valid websocket), `Proxy-Authorization`, `Proxy-Authenticate`.
Do NOT add `Via` or `X-Forwarded-For` (D-32). Never forward `Proxy-*` headers upstream.
Preserve other headers byte-for-byte except normalizing case of names. Cap header count at 100.

### 4.5 Target canonicalization (normative algorithm)
Input: raw request-target (+ scheme context for CONNECT/intercepted).
1. Reject if it contains: bytes `<0x21` or `0x7F`, backslash, raw non-ASCII, fragment `#`,
   `%00`, or userinfo (`@` in authority) -> `userinfo_in_url` (blocked, 403) for userinfo, else 400.
2. Parse with `http::Uri` (parser A) and `url::Url` (parser B). Compare scheme, host, port, and
   path+query after B's normalization. Any mismatch -> 400 `parser_differential`.
3. Host: lowercase; remove exactly one trailing dot (two or more -> reject); IDNA->ASCII
   (UTS-46, non-transitional, strict) else reject; IPv4 must be canonical dotted-quad exactly as
   sent (decimal/octal/hex/short forms -> parser differential -> reject); IPv6 canonical lowercase
   compressed, zone-id rejected, IPv4-mapped IPv6 converted to IPv4 for policy checks.
4. Port: default (80/443) stripped for matching; port 0 or > 65535 rejected.
5. Path: decode percent-escapes of unreserved characters only; uppercase hex of remaining escapes;
   remove `.`/`..` segments (RFC 3986 5.2.4); do NOT collapse `//`.
6. Build `url_norm` = scheme://host[:port]path[?query].
7. Matching views for regex rules: (a) `url_norm`; (b) path decoded once; (c) path decoded twice
   (max two rounds). If decode-twice differs from decode-once, set `suspicious_encoding=true`.
8. The outgoing request is built ONLY from the normalized fields (D-09).
Test vectors: `tests/corpus/url_bypass_cases.tsv` (all MUST pass; add more as found).

### 4.6 Filtering (first match wins; evaluation phases: PreDns = rules 1,2,4,5; Resolved = rule 3; ResponseHeaders = rule 6)
The allowlist (rule 1) bypasses rules 2-6 only; it NEVER bypasses validation, auth, loop, port or destination policy (4.2 steps 2-7 and 9).
1. `allow_domains` match -> allow (`rule_id=allowlist`).
2. Blocked domains (`domains.txt`) -> block (`domain:<entry>`).
3. Destination IP in `ip_blocklist.txt` (after resolution, or literal IP host) -> block (`ip:<cidr>`).
4. URL regex set (`url_patterns.txt`) on the three views -> block (`url:<id>`).
5. Blocked extension (final path segment, case-insensitive, after stripping query) -> block (`ext:<ext>`).
6. (phase = response headers) `Content-Type` media type in `blocked_content_types` -> replace the
   response with the block page (headers already received are discarded; body never forwarded)
   -> block (`ctype:<type>`).
7. Default allow.
For passthrough CONNECT only rules 1-3 apply (domain/IP). For intercepted TLS all rules apply per
inner request. `monitor` mode: record `would_block=true`, `action=allowed`, forward.

v1.1 sources joining these rules (SPEC_EXT_*): profile lists, threat feeds (domain, URL digests, IP), temp allows from approved access requests, scan verdicts. Order with v1.1: rule 1 allowlist; feed domain/URL rules (cannot be overridden by temp allows); scoped temp allows (suppress ONLY local domain, url_pattern, extension and content_type rules); then rules 2-6 as listed.

**Blocklist file grammar** (`domains.txt`): UTF-8 (BOM stripped), one entry per line, blank lines
ignored, `#` starts a comment when at line start or preceded by whitespace. Entry forms:
`evil.com` (apex + all subdomains), `*.evil.com` (subdomains only), `=evil.com` (exact only).
Entries are IDNA-converted, lowercased; labels <= 63, total <= 253, chars `[a-z0-9-]`, no leading/trailing
hyphen; single-label entries rejected (except `localhost`). Matching: exact-or-subdomain by walking
label suffixes; `notevil.com` MUST NOT match `evil.com`.
`url_patterns.txt`: one Rust regex per line; comment lines start with `#`; optional prefix
`[id=rx-007] `; max 1,024 chars; invalid regex -> skip + warn. `ip_blocklist.txt`: IPv4/IPv6 address
or CIDR per line.
Limits: file <= 10 MiB, <= 1,000,000 entries. Duplicates deduped (count warned). Invalid lines
skipped and logged with line numbers (first 20). If > 50% of lines are invalid, reject the whole file
and keep the previous list. Hot reload: poll mtime+size every `reload_interval_secs`, parse into a new
structure, atomic swap (D-16); also on SIGHUP.

### 4.7 Block response
Status 403. Headers: `Content-Type: text/html; charset=utf-8`, `X-WebFilter-Action: blocked`,
`X-WebFilter-Event-Id`, `X-WebFilter-Reason`, `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`,
`Connection: close`. Body: static HTML showing host, reason, rule id, event id. ALL interpolated values
MUST be HTML-escaped (reflected-XSS defense); host/URL are truncated to 200 chars.

### 4.8 Upstream connections
Per D-07 and D-11. Connect timeout 10 s. Happy-eyeballs optional; try validated IPs in order.
Never follow redirects (the client sees them and re-requests through the proxy). On HTTPS-intercept,
upstream TLS follows D-20 with SNI = original hostname.

### 4.9 TLS interception
- `tls.intercept=false`: CONNECT -> after policy/filter rules 1-3, reply `200 Connection Established`
  then relay bytes; idle timeout `tunnel_idle_secs`. Log `tls_intercepted=false`.
- `tls.intercept=true` and host not in `passthrough_domains`: reply 200, peek the first bytes:
  - TLS ClientHello -> terminate TLS with a minted leaf, parse inner HTTP requests through the full
    pipeline (4.2). Mutual-TLS-requiring origins cannot be intercepted: add to passthrough.
  - Not TLS (e.g. plain HTTP, SSH banner) -> close with log `reason=non_tls_on_connect` and
    `action=blocked` when `block_non_tls_connect=true` (default true), else tunnel opaquely.
- CA: generated on first run in `ca_dir` (`ca.pem` public, `ca.key` 0600). `webfilter-proxy ca export`
  prints the public cert. CA key loaded into memory wrapped with `zeroize`.
- Leaf minting per D-19. Wildcards never minted; IP-literal hosts get an IP SAN; hostnames failing
  IDNA/length checks are refused (`reason=invalid_request`).
- TLS handshake timeout 10 s. Reject TLS < 1.2. Cipher suites: rustls defaults only.
- If the ClientHello has SNI and it differs from CONNECT host -> `sni_mismatch` block; ECH per D-21.
- ALPN: offered to the client per D-40 (Phase 6; before Phase 6 only `http/1.1`).
- Passthrough patterns: exact host or `*.suffix`; matched against the CONNECT host.

### 4.10 Proxy auth
Per D-14. Missing/invalid -> 407 with `Proxy-Authenticate: Basic realm="webfilter"`. Lockout after
5 failures/IP/60 s -> 429 `rate_limited`. Auth failures logged with the username truncated to 64
chars, never the password.

### 4.11 Limits and timeouts (defaults; all configurable)
| Item | Default |
|---|---|
| max request head (line+headers) | 65,536 bytes |
| max header count | 100 |
| max URI length | 8,192 bytes |
| client head read timeout | 15 s |
| client keep-alive idle | 60 s |
| upstream connect timeout | 10 s |
| upstream response-header timeout | 30 s |
| upstream/ body idle read timeout | 60 s |
| tunnel idle | 300 s |
| TLS handshake timeout | 10 s |
| max_connections / per IP | 1,024 / 128 |
| shutdown drain | 10 s |
Slow-client defense: head must complete within the head-read timeout; body idle > 60 s -> close.

### 4.12 Error response matrix (all also logged)
| Situation | Status | `reason` |
|---|---|---|
| Malformed/ambiguous request, parser differential | 400 | invalid_request / parser_differential |
| Host/SNI mismatch, userinfo, blocked by rule | 403 | host_mismatch / sni_mismatch / userinfo_in_url / rule reasons |
| Port not allowed, private/metadata destination | 403 | port_not_allowed / private_range |
| Auth missing/wrong | 407 | auth_required / auth_failed |
| TRACE | 405 | method_not_allowed |
| URI too long / headers too large | 414 / 431 | invalid_request |
| Too many auth failures | 429 | rate_limited |
| Version unsupported | 505 | invalid_request |
| Loop | 508 | loop_detected |
| Over connection limit | 503 | too_many_connections |
| DNS failure / refused / reset / bad upstream framing | 502 | upstream_error |
| Upstream cert invalid | 502 | upstream_cert_invalid |
| Upstream timeout | 504 | timeout |
| Internal error | 500 (or fail-open per `on_error`) | internal_error |
Error pages use the 4.7 escaping/headers and never reveal internal paths, versions, or stack traces.

### 4.13 Shutdown, signals, CLI
SIGUSR1 reopens log files (D-67). `webfilter-proxy [--config path] [--listen addr] [--mode enforce|monitor] [--log-dir dir] run` (default
subcommand); `hash-password`; `ca generate|export`; `check-config` (validate and exit 0/2);
`blocklist test <url>` (print the decision and matched rule); v1.1: `feeds ...`, `tui`, `doctor`. CLI overrides config file; env vars
are NOT used for secrets except `WEBFILTER_PROXY_PASSWORD` (client).

### 4.14 Stats
Every 60 s write one JSON line to `webfilter_stats.jsonl`: window start/end, requests, allowed, blocked,
errors, bytes in/out, active connections, dropped_log_events, top 5 blocked domains, blocklist counts.

### 4.15 HTTP/1 core requirements (`proxy::http1`, D-05)
MUST: (1) read heads byte-bounded and time-bounded, handling split/coalesced reads and pipelined bytes;
(2) run `httparse` then enforce every rule R1-R15 on the raw bytes (bare LF/CR, NUL, obs-fold, spacing, duplicates);
(3) body framing exactly one of: none, Content-Length, chunked, close-delimited (responses only), computed once by
one function used for both request and response sides; (4) chunked codec that re-encodes (never copies raw chunk
framing), enforces size/overflow limits, and rejects malformed extensions/trailers; (5) never forwards bytes it has not
framed; after any framing error close both connections; (6) keep-alive loop runs the full 4.2 pipeline per request;
(7) CONNECT/WebSocket switch to a plain bidirectional relay with idle timeouts only after the 200/101 is sent;
(8) every await is wrapped by a timeout; (9) no unbounded buffers; (10) panics isolated per connection.
Differential/fuzz hardening (TEST_PLAN F-04, F-08, F-09, X-01): the accepted-request set of our validator must be a
SUBSET of what `httparse` and hyper accept with identical framing; any input where our framing differs from either
parser (length, method, target, headers) is a bug.

### 4.16 HTTP/2 (Phase 6; intercepted TLS only; D-40/D-45)
**Negotiation (ALPN mirroring)**: (1) after CONNECT 200 read the ClientHello (SNI, ALPN, ECH flag) without completing the
handshake; (2) apply D-22 checks and filter rules 1-3; (3) connect upstream to the validated IP offering
`intersection(client ALPN, [h2, http/1.1])`; (4) upstream selects P; (5) complete the client handshake offering only P;
(6) run the HTTP/1 core (P=http/1.1) or the h2 core (P=h2). Cleartext h2 (h2c preface or `Upgrade: h2c`) is rejected on every
listener.
**Per-stream pipeline**: each h2 request stream runs SPEC 4.2 (framing steps replaced by rules H1-H11); streams are
independent (a blocked stream never affects others).
| Rule | Requirement (violation -> stream error PROTOCOL_ERROR unless noted; connection error where marked) |
|---|---|
| H1 | Exactly one each of `:method`, `:scheme` (=`https`), `:authority`, `:path`; pseudo-headers before regular headers; unknown/duplicate/response pseudo-headers rejected. |
| H2 | Header field names must be lowercase; empty names rejected. |
| H3 | Connection-specific headers (`connection`, `proxy-connection`, `keep-alive`, `transfer-encoding`, `upgrade`) rejected; `te` only `trailers`. |
| H4 | `:authority` host MUST equal the CONNECT authority host (D-22 -> `host_mismatch`, 403); if `host` present it must equal `:authority`. |
| H5 | `:path` origin-form only (starts `/`, or `*` for OPTIONS rejected), no spaces/control chars/backslash/fragment; canonicalized with 4.5 (`InterceptedOrigin`). |
| H6 | `content-length` (single, digits) must equal the total DATA bytes else RST_STREAM(PROTOCOL_ERROR) and discard the rest. |
| H7 | No CR/LF/NUL in any name/value. |
| H8 | `CONNECT` method, extended CONNECT (RFC 8441) and PUSH_PROMISE rejected; advertise `ENABLE_PUSH=0`, `ENABLE_CONNECT_PROTOCOL=0` (connection error for received PUSH_PROMISE). |
| H9 | Trailers allowed, validated like headers, pseudo-headers forbidden. |
| H10 | Upstream responses validated symmetrically (`:status`, no connection-specific headers, CL vs DATA); violation -> RST_STREAM to client + log `upstream_error`. |
| H11 | Blocked streams receive the 4.7 block response over h2 (same headers, lowercase names). |
**Flood and resource limits** (`[http2]`, defaults): `max_concurrent_streams=100`; `max_header_list_size=65536`;
`max_frame_size=16384`; `initial_stream_window=1 MiB`, connection window 4 MiB; HPACK table 4096; header block may span at most
16 CONTINUATION frames and `max_header_list_size` bytes; RST_STREAM received > 100 per 10 s (or resets > 50% of >= 50 opened
streams) -> GOAWAY(ENHANCE_YOUR_CALM); resets caused by OUR stream errors count against the client (MadeYouReset);
SETTINGS/PING/PRIORITY/empty-DATA/WINDOW_UPDATE(0) frames > 200 per 10 s -> GOAWAY; `max_streams_per_connection=10000` then
graceful GOAWAY; flow-control stall > 30 s -> close; idle 60 s. Every violation: GOAWAY + `h2_flood` system event + stats counter.
**Upstream**: one h2 connection per client connection, same validation/limits. WebSocket continues over HTTP/1.1 connections.
**Log**: `http_version="2"`, `alpn`, `h2_stream_id`.

### 4.17 Transparent mode (Phase 7; Linux; lab-only; D-41..D-44)
Config `[transparent]`: `enabled=false`, `acknowledge_lab_only=false` (required), `http_listen`, `tls_listen`,
`host_verify=strict|relaxed`, `no_sni_action=block|ip_only`, `ech_action=block|ip_only`, `orig_dst=so_original_dst|conntrack`.
Start-up validation: Linux only; refuse without acknowledgement; listeners must not collide with the explicit listener.
**Accept**: obtain original destination via `OriginalDst`. Failure, or destination equal to any proxy listener/own address
(direct un-redirected connection or loop) -> close + system event `orig_dst_failed` (never proxy such traffic).
**Transparent HTTP** (plain port): origin-form request with exactly one `Host` (rules R1-R8 apply; R9 allows origin-form here,
absolute-form rejected); authority = Host, port = original port; canonicalize (`TransparentHost` context); policy/port rules
apply to the ORIGINAL destination; connect to the original IP (no re-resolution); `host_verify` per D-42; then filter 4.6 and forward.
**Transparent TLS** (TLS port): read ClientHello via a lazy acceptor (SNI, ALPN, ECH). No SNI -> `no_sni_action`;
ECH present -> `ech_action` (`block` = close with log `ech_blocked`; `ip_only` = passthrough using IP rules only);
SNI canonicalized as a host; `host_verify` as above. Then either (a) intercept (D-19/D-40, upstream connects to the original IP
with SNI = SNI host; inner `Host`/`:authority` must equal the SNI host) or (b) passthrough when the SNI matches
`passthrough_domains` or `tls.intercept=false`: apply filter rules 1-3 (domain by SNI, ip by original IP) then relay with the
captured ClientHello replayed to the origin. Non-TLS bytes on the TLS port or non-HTTP on the HTTP port -> close + log.
**Lab network rules (documented in README and created only by `scripts/netns_lab.sh`)**: nft table `inet wf_lab`, PREROUTING
redirect of tcp/80 and tcp/443 from the lab veth to the listeners (IPv4 and IPv6), exemption for the proxy's own uid (prevents
loops), `udp dport 443 reject` (forces QUIC clients back to TCP). The script MUST be idempotent and its teardown MUST remove the
netns, veth and table; it MUST never touch rules outside `wf_lab`.
**Limitations (documented, tested)**: only redirected ports are seen; UDP/QUIC, DoH, apps with pinning, and non-standard ports bypass;
ECH hides the inner name (R-05/R-11); macOS/Windows unsupported.
**Log**: `transparent=true`, `orig_dst_ip`, `orig_dst_port`, `host_verified`.

## 5. Client

### 5.1 CLI
`webfilter-client [OPTIONS] <URL>...`
| Option | Default | Notes |
|---|---|---|
| `--proxy <url>` | `http://127.0.0.1:8080` (env `WEBFILTER_PROXY`) | explicit only; `HTTP(S)_PROXY` ignored |
| `--proxy-user <u>` | none | password from env `WEBFILTER_PROXY_PASSWORD` or `--proxy-password-file`; never as an argument |
| `--out-dir <dir>` | `output/` | created if missing (mode 0750) |
| `--name <file>` | generated | only with exactly one URL; sanitized with the same rules; must not contain separators |
| `--ca-cert <pem>` | none | repeatable extra trusted roots |
| `--jobs <n>` | 4 | max concurrent fetches |
| `--timeout <s>` / `--connect-timeout <s>` | 30 / 10 | |
| `--max-redirects <n>` | 10 | |
| `--max-bytes <n>` | 52,428,800 | abort + delete partial file if exceeded |
| `--save-blocked` | off | save the block page as `<name>.blocked.html` |
| `--json` | off | one JSON object per URL (below) |
| `-q/--quiet`, `-v/--verbose` | | |
| `--user-agent <s>` | `webfilter-client/<ver>` | |

### 5.2 Behavior
- URLs: trimmed; if no scheme, prepend `https://`; only `http`/`https` accepted (`file:`, `ftp:`, `data:`...
  -> usage error for that URL, counted as error). Arguments beginning with `-` are options, never URLs
  (use `--` to separate). Userinfo in a URL is stripped with a warning (never used in names/logs).
- Transport: plain `http://` -> absolute-form request to the proxy. `https://` -> manual `CONNECT host:443`
  (read the proxy's reply; a 403 with `X-WebFilter-Action: blocked` is a BLOCK, other non-200 -> error),
  then TLS (verify always, D-26), then HTTP/1.1. Send proxy credentials on CONNECT and plain requests.
- Redirects handled by the client (301/302/303/307/308 with `Location`): resolve relative locations,
  re-validate scheme (http/https only), re-run through the proxy, stop at `--max-redirects` and on loops.
  303 and 301/302-on-POST become GET; client only issues GET anyway.
- Headers sent: `Host`, `User-Agent`, `Accept: text/html,*/*;q=0.8`, `Accept-Encoding: identity`, `Connection: close`.
- Body read streaming with `--max-bytes`; response saved as received. If `Content-Type` is not `text/html`
  print a warning with the real type but still save as `.html`. If `Content-Encoding` is not identity,
  warn that the file is encoded. Never trust `Content-Disposition` for naming.
- Writes are atomic and no-clobber (5.3 step 11).

### 5.3 File naming algorithm (deterministic; the oracle is `tests/corpus/filename_cases.tsv`)
1. Name from the ORIGINAL requested URL (after adding a default `https://` scheme), not the redirect target.
2. `host` = IDNA ASCII, lowercase, with one trailing dot removed. IPv6 hosts: `ipv6-` + address with brackets removed and each `:` -> `-`.
3. If the port is non-default (not 80 for http / 443 for https) append `_p<port>`.
4. Path: non-empty segments, each percent-decoded once (invalid UTF-8 -> lossy), joined by `_`; if the
   last segment ends in `.html`/`.htm` (case-insensitive) strip that extension first.
5. If the query is non-empty append `_q` + first 8 hex chars of SHA-256(raw query string, UTF-8).
6. `stem = host + port_part + ("_" + path if path) + query_part`.
7. Replace every char not in `[A-Za-z0-9._-]` with `_`; collapse runs of `_`; replace any run of 2+ dots with
   `_` and collapse `_` again; trim leading/trailing `.`, `_`, `-`; if the result is empty or its first char is
   not alphanumeric prefix `h`.
8. If len(stem) > 120: `stem = stem[:110]` (then trim trailing `.`, `_`, `-`) + `_` + first 8 hex of
   SHA-256(untruncated sanitized stem).
9. Windows-reserved check: if any dot-separated part (case-insensitive) is CON, PRN, AUX, NUL, COM1-9 or
   LPT1-9, prefix `r_`.
10. Append `.html`.
11. Write: canonicalize `out_dir` once; create temp `.<name>.part` with `create_new`; on completion
    `hard_link(temp, final)`; on `AlreadyExists` try `<stem>-1.html`, `-2`, ... up to 999 (then error);
    remove temp. Never overwrite, never follow an existing symlink at the final component. Delete the temp file
    on any failure or when `--max-bytes` is exceeded.
Invariant (property test): result matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.html$` (collision suffix
included), contains no `..`, no separators, and no reserved Windows part.

### 5.4 Output and exit codes
Human line per URL: `OK|BLOCKED|ERROR <status> <bytes> <url> -> <path|reason>`. `--json` line:
`{"url","final_url","status","bytes","content_type","saved_path","blocked","event_id","reason","error","duration_ms"}`.
Exit codes: 0 all OK; 2 usage/config error (before any fetch); 1 any network/protocol/TLS/size error;
3 no errors but at least one BLOCKED. (Precedence 2 > 1 > 3 > 0.)

## 6. Configuration reference (TOML + CLI; CLI wins; unknown keys = error)
See `config/config.example.toml` for every key with defaults (including `[http2]` and `[transparent]`). Rules: missing keys take the documented defaults; `ports.*_allowed` accepts an array of ports or the string `"any"`; paths relative to the config file;
`~` expanded; durations in seconds; invalid values -> exit 2 with a precise message; `check-config`
validates without starting. `destination.deny_private_ranges`: code default false, shipped example true (D-36). Required validations: ports 1-65535; `worker_threads >= 1`;
non-loopback listen requires `proxy_auth`; CA dir perms; regex/blocklist paths readable; limits > 0.

## 7. Logging
See LOG_SCHEMA.md (authoritative).

## 8. SIEM (OpenSearch, A-14)
Files in `siem/opensearch/`: `docker-compose.yml`, `fluent-bit.conf`, `parsers.conf`, index templates and
`detections.json` (detections incl. attack-attempt rules that the Phase 5 pentest replays, A-35). Indices `webfilter-*`.
Scripts: `scripts/siem/` (`detect.py`, `gen_test_traffic.py`, `siem_test.py`, `siem_e2e.sh`); logic in siem/opensearch/DETECTIONS.md.

## 9. Non-functional
Performance targets D-34. `cargo fmt`/`clippy -D warnings` clean. Coverage >= 85% lines on `blocklist`,
`normalize`, `policy`, `filter`, `logger`, `naming`; >= 70% overall. No `unwrap`/`expect`/indexing panics on
external input (enforced by clippy lints `unwrap_used`, `expect_used`, `indexing_slicing` for non-test code).
Documented public items. `just test`/`just e2e` build with `--features insecure-test`; files under `tests/` and `fuzz/` start with `#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic, missing_docs)]`. Panic isolation: a panic in one connection task MUST NOT affect others (and is logged).

## 10. Repository conventions
`justfile` targets (create in Phase 0): `release` (builds WITHOUT `insecure-test` and fails if the binaries contain the strings `WEBFILTER_TEST_HOSTS`/`WEBFILTER_TEST_ORIG_DST`), `check-env`, `fmt`, `lint`, `test`, `e2e`, `cov`, `fuzz-smoke`,
`audit` (deny+audit+geiger), `sbom`, `load`, `pentest-p<N>` (N=1..13), `ui-lint`, `ui-e2e` (headless browser: E-72, E-80), `feeds-test`, `siem-test`, `siem-e2e`, `scan-e2e` (Docker clamd: E-63..E-67), `promtool`; plain `just e2e` runs only tests with no external services, `e2e-netns` (Linux, sudo), `h2spec`, `docs-check`, `acceptance`
(runs everything). CI (GitHub Actions; includes an Ubuntu job with sudo for `e2e-netns` once Phase 7 lands): fmt, clippy, test+nextest, e2e, coverage gate, deny, audit,
fuzz-smoke (60 s/target), build release with `insecure-test` OFF assertion. CI actions are pinned by commit SHA, builds use `--locked`, the toolchain comes from `rust-toolchain.toml` (D-46). Pre-commit hook: fmt +
clippy + gitleaks. Branching/tagging per D-28. `CHANGELOG.md` kept per phase.
