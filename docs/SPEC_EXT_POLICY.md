# Extension Spec A: Identity, Limits, Feeds, Download Inspection (Phases 9-10)

All features here are OFF by default. Core behavior: SPEC.md. Decisions: D-50..D-54, D-63.

## P1. Client identity and profiles (Phase 9)
- `client_id` per request: `user:<username>` if authenticated, else `ip:<addr>`. IPv4-mapped IPv6 -> IPv4; other IPv6 keyed by /64.
  `X-Forwarded-For` and similar are ignored. Tunnels/h2 streams inherit the CONNECT identity.
- Config: `[[users]]` (`username` `[A-Za-z0-9._-]{1,64}`, `password_hash` argon2id, `profile`), `[[clients]]` (`cidr`, `profile`),
  `[[profiles]]` (`name`, optional: `mode`, `allow_domains`, `extra_blocked_domains`, `extra_url_patterns`, `blocked_extensions`,
  `blocked_content_types`, `feeds` (names), `scan_downloads`, `access_requests`, `[profiles.rate]`). `default` profile always exists.
  The old single `[proxy_auth]` stays valid as one user in profile `default`. Limits: <= 100 profiles, <= 10,000 users+clients.
- Resolution order: user profile > longest-prefix CIDR match > `default`. Unknown profile names are config errors.
- Profiles NEVER override: request validation, port policy, destination policy, TLS verification, global limits maxima, auth
  requirement. A profile allowlist bypasses list rules (domain, url, ip, feed, extension, content-type) but never safety policy
  or scan verdicts (P4).
- Hot reload on SIGHUP or mtime change; parse-then-swap; invalid config keeps the old one and emits a system event.
- Every log event carries `client_id` and `profile`.

## P2. Rate limiting and bandwidth caps (Phase 9)
Pipeline position: after authentication/identity (SPEC 4.2 step 3b), before canonicalization.
| Key (`[profiles.rate]`) | Default | When exceeded |
|---|---|---|
| `requests_per_sec`, `burst` | 50, 100 | 429 `rate_limited` + `Retry-After` |
| `max_concurrent_connections` | 64 | 503 `too_many_connections` |
| `max_inflight_requests` | 128 | 429 `rate_limited` |
| `max_tunnels` | 32 | 429 `rate_limited` |
| `down_bytes_per_sec`, `up_bytes_per_sec` | 0 (unlimited) | bytes delayed, never dropped; `throttled=true` |
| `daily_quota_bytes` | 0 (off) | 429 `quota_exceeded`, `Retry-After` = seconds to UTC midnight |
Mechanics: token buckets on `Instant` (monotonic), saturating integer math; state in a bounded LRU (100,000 keys, idle eviction;
an evicted key restarts full); all connections of one client share one bandwidth bucket served in 10 ms quanta, round-robin;
waits reset idle timers; h2 streams share their connection's share. Quota and counters live in memory and reset on restart
(documented). Limits are enforced in `monitor` mode too. `Retry-After` is an integer number of seconds (RFC 9110).
Stats/metrics: counters per profile for each limit type.

## P3. Threat feeds (Phase 10)
`[[feeds]]` entries (all `enabled=false` by default): `name` `[a-z0-9_-]{1,32}`, `url` (https only), `format`
(`domains_text`, `hostfile`, `urls_text`, `csv_urlhaus`, `ips_text`), `refresh_secs` (>= 300, default 3600),
`max_bytes` (50 MiB), `max_entries` (2,000,000; global cap 5,000,000), `auth_header_file` (optional API key file; header
`Auth-Key`), `expire_after_secs` (604800). `[feeds_global] protected_domains` always includes `localhost`, the admin host, and
`webfilter.local`.
**Terms**: before enabling a feed the operator verifies its terms of use and recommended fetch rate (abuse.ch publishes both;
e.g. the URLhaus plain-text list is regenerated every 5 minutes and must not be fetched more often, R-12) and records them with
a date in `docs/DECISIONS_ADDENDUM.md`. Shipped example entries stay disabled.
**Fetch**: HTTPS with verification, redirects <= 3 and https only, feed host must resolve to public IPs (SPEC 4.8 policy,
resolve-once), conditional GET (ETag/Last-Modified), jitter +/-10%, exponential backoff up to 6 h, User-Agent
`webfilter-proxy/<ver>`, API key header never sent to a different host after a redirect, timeouts 30 s connect/120 s total.
**Test builds**: with the `insecure-test` feature a loopback feed host is allowed via `WEBFILTER_TEST_FEED_ALLOW_LOOPBACK=1` (test CA through `upstream_ca_bundle`); release builds cannot.
**Parse and guard**: same grammar/limits as SPEC 4.6; per-format parsers; unknown lines skipped and counted; domains IDNA-lowered;
URLs canonicalized with SPEC 4.5; reject single-label/TLD entries, protected domains, private/loopback IPs. Sanity guard:
reject a new version whose entry count is < 50% or > 200% of the active one (unless first load or `feeds update --force`).
**Apply**: write `feeds/<name>/candidate` -> validate -> write `v<unix>.list` -> atomically update `active` pointer -> swap in memory
-> system event `feed_updated` {entries, delta}. Keep 5 versions. Failure of any step keeps the last good list (`feed_failed`
or `feed_rejected`). No successful update for 3x `refresh_secs` -> `feed_stale` event + metric; after `expire_after_secs` the feed is
deactivated.
**Matching**: domain entries join SPEC 4.6 rule 2 (rule_id `feed:<name>:<entry>`, reason `feed_domain`; hostfile and URLhaus
host entries are exact-host); URL entries are an exact-match set of 128-bit truncated SHA-256 digests of the canonical URL (rule 4,
reason `feed_url`); IP entries join rule 3 (`feed_ip`). `rule_list` = feed name. Profiles choose feeds via `feeds = [...]`.
**CLI**: `feeds status`, `feeds update [name] [--force]`, `feeds rollback <name>`, `feeds test <url>`.

## P4. Download hashing and scanning (Phase 10)
`[scan]`: `enabled=false`, `mode` (`detect`/`block`), `max_bytes` (26,214,400), `max_concurrent` (8), `buffer_timeout_secs` (60; block mode: total time allowed to receive the body, else unscannable), `temp_dir` (`state/scan_tmp`,
0700), `temp_quota_bytes` (1 GiB), `unscannable_action` (`block`/`allow`; default `block` when mode=block, else `allow`),
`scanner_unavailable_action` (same default), `extensions`, `content_types`, `magic` (true), `hash_blocklist` path,
`[scan.clamd]` (`address` = `unix:/path` or `tcp:127.0.0.1:3310`, loopback only; `timeout_secs` 30; `chunk_bytes` 65536),
`[scan.yara]` (`rules_dir`, `timeout_secs` 10; requires cargo feature `yara`). A profile must set `scan_downloads=true`.
**Eligibility** (any): extension in `extensions`; response media type in `content_types`; magic bytes in the first 512 bytes: `MZ`,
`\x7fELF`, Mach-O (`feedface`/`feedfacf`/`cafebabe`), `PK\x03\x04`, OLE2 `D0CF11E0A1B11AE1`, `%PDF`, `Rar!`, 7z, gzip, `#!`.
Only 2xx responses to GET, plain HTTP and intercepted HTTPS, never passthrough.
**detect mode**: stream to the client unchanged while computing SHA-256 and feeding scanners incrementally (clamd INSTREAM tee; a temp
file tee only if YARA is enabled). Verdict is logged after delivery (`malware_detected` event, `action=allowed`).
**block mode**: buffer to a 0600 temp file with a random name (SHA-256 computed while writing), run hash blocklist, clamd, YARA; clean ->
serve exactly the stored bytes (Content-Length recomputed; file deleted after); infected/blocklisted -> 403 block page (`malware_detected`
or `hash_blocklist`), upstream headers discarded. Known oversize Content-Length is decided before buffering.
**Unscannable** = oversize, 206/Range, `Content-Encoding` other than identity, scanner down/timeout/protocol error, temp quota or
`max_concurrent` exhausted (queue <= 5 s): apply `unscannable_action` (`unscannable`/`scanner_unavailable`).
**clamd protocol (R-13)**: send `zINSTREAM\0`, then chunks of `<4-byte big-endian length><data>`, finish with a zero-length chunk;
read one reply line: `stream: OK`, `stream: <signature> FOUND`, or an error (e.g. `INSTREAM size limit exceeded` -> unscannable).
`max_bytes` must not exceed clamd `StreamMaxLength` (checked by `doctor` where possible, documented otherwise). One connection per scan.
**Hash blocklist**: SHA-256 hex per line, `#` comments, same limits/hot reload as other lists.
**Logging**: `scan_status` (`clean|infected|blocklisted|skipped|unscannable|error`), `scan_engine`, `scan_signature` (sanitized to
`[A-Za-z0-9._-]{1,64}`), `body_sha256`, `body_bytes`, `download_name` (from Content-Disposition or URL, control characters and
separators removed, <= 128 chars; never used as a file path).
**Limitations (documented)**: archives/encrypted files/content-encoding limit AV effectiveness; zero-days; false positives;
signature updates (freshclam) are the operator's job; this is defense in depth, not a guarantee.
