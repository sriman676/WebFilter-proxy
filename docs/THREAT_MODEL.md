# Threat Model (STRIDE) - proxy + client

Assets: filtering integrity (blocked stays blocked), CA private key, client confidentiality inside
the tunnel, log integrity/confidentiality, availability, the host running the proxy, the user's
filesystem (client output).
Actors: malicious/compromised LAN client; malicious origin server; network attacker between proxy
and origin; local unprivileged user on the proxy host; operator error; supply-chain attacker.
Trust boundaries: B1 clients->proxy, B2 proxy->origins, B3 CA store, B4 config/blocklist files,
B5 log files -> Splunk, B6 client program -> filesystem.

| ID | STRIDE | Threat | Mitigation (spec) | Verified by |
|---|---|---|---|---|
| T-01 | T | Request smuggling / desync via CL/TE ambiguity (R-01) | 4.3 R1-R5, R8, R15; D-07/D-08 | I-20..I-27, PT-2.1 |
| T-02 | T | Smuggling via upstream shared sockets | D-07 no cross-client upstream reuse | I-28, PT-2.2 |
| T-03 | E | Filter bypass using URL/host parsing differentials (R-03) | 4.5, D-09, corpus | U-001..U-055, F-01, PT-1.x, PT-2.3 |
| T-04 | E | Only first request on a keep-alive connection is filtered | D-10 | E-33, SM-14..16, PT-2.4 |
| T-05 | E | Host/absolute-URI ambiguity (R-04) | R7 | SM-11/12, PT-2.5 |
| T-06 | E | Domain fronting / SNI-Host-CONNECT mismatch | D-22 | E-34, PT-4.5 |
| T-07 | E | SSRF to localhost/RFC1918/metadata through the proxy | D-11, 4.8 | E-21, PT-2.6 |
| T-08 | E | DNS rebinding (resolve-validate-reresolve) | D-11 resolve once, connect to validated IP | E-22, PT-2.7 |
| T-09 | E | Cross-protocol abuse (CONNECT/GET to SMTP, Redis, SSH) | D-12 port policy | E-20, PT-2.8 |
| T-10 | S/E | Open proxy abuse from network | D-13 loopback default, auth off-loopback | E-19, PT-2.9, nmap check |
| T-11 | S | Proxy auth brute force / bypass | D-14 lockout, constant-time | E-19, PT-2.10 |
| T-12 | D | Slowloris / slow body / connection exhaustion | 4.11 timeouts + limits | L-03, PT-2.11 |
| T-13 | D | Oversized headers/URIs/bodies, chunk abuse | 4.11, R12 | SM-17, SM-24, PT-2.12 |
| T-14 | D | Regex ReDoS in url_patterns | D-15 linear-time engine + size limit | U-regex, F-02, PT-1.3 |
| T-15 | D | Memory blow-up (cert cache, logs queue, large bodies) | caps in D-17, D-19, D-24 | E-26, PT-4.4, PT-8.3 |
| T-16 | I | Reflected XSS in block/error pages | 4.7 escaping + CSP | I-block-page, PT-2.13 |
| T-17 | T | Header/response splitting/CRLF injection (request and response side) | 4.5.1, R5, response rules | SM-20, U-051, PT-2.14 |
| T-18 | R/T | Log injection / forging (CRLF, JSON, ANSI, SPL) | LOG_SCHEMA injection rules | U-logger, PT-5.1 |
| T-19 | I | Secrets in logs (cookies, auth, query values, bodies) | D-18 | E-30, PT-5.2 |
| T-20 | R | Log loss/tampering, disk fill | writer thread, rotation, 0640, drop counters | E-25, PT-5.3 |
| T-21 | I/E | CA private key theft or wide permissions | D-19 0600 check, zeroize, never logged/committed | I-ca-perms, PT-4.1, gitleaks |
| T-22 | S | Rogue leaf certs (SAN abuse, wildcard, IP, IDN, NUL) | 4.9 minting rules | U-tls, PT-4.2 |
| T-23 | I | Weakened TLS vs direct (R-02): no verification, old protocols, weak ciphers | D-20, TLS>=1.2, rustls defaults | E-17, PT-4.3, sslyze/testssl diff |
| T-24 | S | MITM of proxy->origin due to skipped cert validation | D-20 + CI check of `insecure-test` off | E-17, PT-4.3, PT-8.1 |
| T-25 | I | Interception of non-TLS or mTLS/pinned traffic breaking security | non_tls rule, passthrough list | E-18, PT-4.6 |
| T-26 | E | Proxy loop / self-request amplification | 4.2 step 5 | E-23, PT-2.15 |
| T-27 | E | Client writes outside out-dir (traversal, symlink, TOCTOU, reserved names) | 5.3 | P-naming, E-29, PT-3.1 |
| T-28 | D/E | Malicious origin vs client: huge/endless body, gzip bomb, redirect loop, file:// redirect | 5.2 caps, identity encoding | E-12, E-13, PT-3.2 |
| T-29 | S | Client trusts wrong cert / accepts invalid TLS | D-26 | I-client-tls, PT-3.3 |
| T-30 | I | Proxy credentials leaked via argv/env/logs | 5.1 password env/file only | PT-3.4 |
| T-31 | E | Blocklist/config tampering by local user | file perms checks, atomic reload, invalid file keeps old | E-11, PT-5.4 |
| T-32 | T | Hot-reload race / partial file read | arc-swap, parse-then-swap | E-11, PT-5.4 |
| T-33 | E | Supply chain (malicious/vulnerable crates) | D-27, deny/audit/geiger/SBOM | PT-1.4, PT-8.1 |
| T-34 | D | Panic in one task takes down proxy | panic isolation | I-panic, PT-8.3 |
| T-35 | R | Detections don't fire for real attacks | purple-team replay | S-xx, PT-5.5 |
| T-36 | E | QUIC/HTTP3 and ECH bypass of the proxy (R-05) | documented limitation + logs; D-21 | docs check, PT-4.7 |
| T-37 | D | HTTP/2 Rapid Reset and MadeYouReset (R-10) | 4.16 reset accounting incl. server-caused resets, D-45 | I-h2-flood, E-42, PT-6.1 |
| T-38 | D | HTTP/2 CONTINUATION flood, HPACK bomb | 4.16 header-block caps | I-h2-flood, E-42, PT-6.2 |
| T-39 | D | SETTINGS/PING/PRIORITY/empty-DATA/WINDOW_UPDATE floods, flow-control stalls | 4.16 control-frame limit, stall timeout | I-h2-flood, PT-6.3 |
| T-40 | T | h2 pseudo-header/header injection, CL-vs-DATA mismatch, forbidden headers | H1-H10 | I-h2-valid, F-10, PT-6.4 |
| T-41 | T | h1<->h2 downgrade smuggling and h2c upgrade smuggling (R-01) | D-40 ALPN mirroring, no h2c | E-38, E-43, PT-6.5 |
| T-42 | E | Filter bypass through concurrent/interleaved streams | H11 per-stream pipeline | E-39, PT-6.6 |
| T-43 | E | Transparent listener abused as open proxy by direct connections | 4.17 accept rules, D-41 | E-48, I-transparent-http, PT-7.1 |
| T-44 | E | Transparent Host/SNI vs original-IP mismatch (fronting) | D-42 host_verify | E-46, PT-7.2 |
| T-45 | E | Transparent evasion: no SNI, ECH, IP-literal HTTPS | no_sni_action/ech_action | E-47, PT-7.3 |
| T-46 | D/E | Transparent redirect loops / self-reference | dst==own check, uid exemption | E-49, PT-7.4 |
| T-47 | D | ClientHello fragmentation/size/slow abuse | lazy acceptor limits, timeouts | F-11, PT-7.5 |
| T-48 | I | Bypass via QUIC, other ports, IPv6, DoH (R-11) | documented limitations + lab reject rule + tests that state them | E-44, PT-7.6 |
| T-49 | E | Lab rules left behind on the host (firewall changes persist) | idempotent setup/teardown in dedicated table | E-44, PT-7.8 |
| T-50 | I | DNS lookups for blocked names leak intent and slow/skew errors | filter before DNS (4.2 step 8) | E-52, PT-2.3 |
| T-51 | S/E | Identity confusion: spoofed XFF, mid-connection credential switching, IPv6 aliasing | D-50 | E-53, PT-9.1 |
| T-52 | E | Profile overrides loosening safety policy | D-50 | E-53, PT-9.2 |
| T-53 | D | Limiter evasion or state exhaustion (IPv6 /64 rotation, spoofed users, key churn) | D-51 bounded LRU, /64 keys | E-57, PT-9.3 |
| T-54 | D/T | Throttling bugs: starvation, deadlock, byte corruption | D-51 | E-55, PT-9.4 |
| T-55 | T | Feed poisoning (compromised feed blocks critical names or exhausts memory) | D-52 guards, rollback | E-60, E-61, PT-10.1 |
| T-56 | E/I | Feed fetch SSRF, TLS downgrade, API-key leakage | D-52 | E-62, PT-10.2 |
| T-57 | E | Scan evasion (encoding, Range, MIME/extension lies, chunking) | D-53 | E-65, PT-10.4 |
| T-58 | D | Scanner DoS, temp-disk exhaustion, clamd hang | D-53, D-54 | E-65, PT-10.5 |
| T-59 | E | Temp-file attacks (symlink, permissions, TOCTOU, filename as path) | D-53 | E-64, PT-10.6 |
| T-60 | R/I | Log injection and secret leakage via filenames, signatures, hashes | LOG_SCHEMA rules | E-64, PT-10.7 |
| T-61 | E | DNS rebinding or Host attacks on the admin listener (R-14) | D-55 | E-70, PT-11.1 |
| T-62 | S/E | Admin authentication or authorization bypass, token leak | D-55 | E-70, PT-11.2 |
| T-63 | T | CSRF or CORS abuse against admin | D-55 | E-70, PT-11.3 |
| T-64 | E | XSS or terminal-escape injection through attacker-controlled data | D-57, D-58 | E-72, E-73, PT-11.4 |
| T-65 | I/D | Information exposure or metric cardinality bomb | D-56 | E-69, PT-11.5 |
| T-66 | E | Access-request abuse (forged/foreign event, CSRF, ineligible reasons, webfilter.local SSRF or loop) | D-59 | E-75, PT-11.6 |
| T-67 | E | Temp-allow scope escape, tampered state file, expiry races | D-59 | E-74, E-76, PT-11.7 |
| T-68 | R/D | Unaudited admin actions; admin flood affecting the data path | D-55 | E-71, PT-11.8 |
| T-69 | E/D | Client input-file or manifest path abuse; retry amplification | D-60 | E-78, E-79, PT-12.1 |
| T-70 | E | Snapshot HTML/CSS attacks (offline script execution, traversal, asset bombs) | D-61 | E-80, PT-12.4 |
| T-71 | D/E | Crawl traps, robots violations, scope escape | D-62 | E-81, PT-12.5 |
| T-72 | E | Feature interaction regressions | D-63 | E-83, PT-13.2 |
| T-73 | I | Privacy exposure: over-collection, interception of sensitive categories, long retention | D-68, passthrough defaults, no secrets in logs | E-30, PT-5.2 |
| T-74 | D | File-descriptor exhaustion or clock skew degrading service and certificates | D-67 | PT-8.3, E-24 |

