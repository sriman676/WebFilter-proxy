# Extension Spec B: Operations, Admin, Metrics, UI, TUI, Access Requests (Phase 11)

Off by default. Decisions: D-55..D-59, D-65. Research: R-14 (DNS rebinding), R-15 (metrics).

## O1. Admin listener
`[admin]`: `enabled=false`, `listen="127.0.0.1:9090"` (loopback only; non-loopback refused), `token_hash` (argon2id; required when
enabled), `allowed_hosts` (default: `127.0.0.1:9090`, `localhost:9090`, `[::1]:9090`; add the local forwarded port, e.g. `localhost:9999`, when using an SSH tunnel), `ui_enabled=true`, `metrics_public=false`,
`max_body_bytes=65536`, `request_timeout_secs=10`, `max_connections=64`.
Rules (every route, including health and UI): `Host` must exactly match `allowed_hosts` else 421; no CORS headers ever; reject non-GET
requests whose `Origin` is present and not an allowed origin; state-changing calls require `Content-Type: application/json` and a Bearer
token; no cookies; constant-time token compare; per-IP auth-failure lockout (5/60 s -> 429); token never in URL or logs. Response headers:
`Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Resource-Policy: same-origin`;
UI responses add `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. The admin server runs with its own task budget so floods cannot starve the
proxy data path. Every authenticated non-GET call and every auth failure is appended to `webfilter_admin.jsonl`
(`actor`, `remote_addr`, `action`, `target`, `result`).

## O2. Health and metrics
`/healthz`: 200 `{"status":"ok"}` while the process is responsive. `/readyz`: 200 only when config, blocklists, logger writer, and (if
intercepting) the CA are healthy; otherwise 503 listing failed check names only. Neither reveals versions, paths or hostnames.
`/metrics`: Prometheus text format; Bearer token unless `metrics_public=true`. Required series (labels bounded, D-56):
| Metric | Type | Labels |
|---|---|---|
| `webfilter_requests_total` | counter | action, reason, scheme |
| `webfilter_request_duration_seconds` | histogram | scheme |
| `webfilter_bytes_total` | counter | direction |
| `webfilter_active_connections` | gauge | - |
| `webfilter_rate_limited_total` | counter | profile, kind |
| `webfilter_throttled_seconds_total` | counter | profile |
| `webfilter_blocklist_entries` | gauge | list |
| `webfilter_feed_entries`, `webfilter_feed_last_success_timestamp_seconds` | gauge | feed |
| `webfilter_feed_updates_total` | counter | feed, result |
| `webfilter_scans_total` | counter | status, engine |
| `webfilter_access_requests` | gauge | state |
| `webfilter_h2_flood_total` | counter | type |
| `webfilter_log_dropped_total` | counter | - |
| `webfilter_up`, `webfilter_build_info` | gauge | version |
Series count is capped; label values are escaped per the exposition format. `promtool check metrics` must pass.

## O3. API (`/api/v1`, Bearer required)
GET `stats`, `events/recent?limit<=500&action&reason` (in-memory ring of the last 1,000 request events, same redaction as logs),
`top/blocked?window&n<=100` (space-saving heavy-hitter counters, 50,000 keys max), `clients` (top 50 active), `profiles` (read-only), `lists`, `feeds`,
`temp-allows`, `access-requests?status`, `audit?limit`. POST `feeds/update`, `reload` (blocklists + profiles), `temp-allows`
(host, scope, ttl <= 24 h), `access-requests/{id}/decide`. DELETE `temp-allows/{id}`. No endpoint can change mode, edit list/profile
files, read secrets or the CA, or execute anything. JSON bodies only, strict schemas, unknown fields rejected.

## O4. Web UI (`assets/admin/index.html`, `app.js`, `style.css`, embedded in the binary)
Tabs: Overview, Blocked, Clients, Feeds, Scans, Access requests, Temp allows, Audit. Vanilla JS; no framework, CDN, inline script or
inline style; all dynamic text via `textContent`/`createElement`; token kept in memory only; refresh every 5 s; 401 prompts for the token.
`scripts/ui_lint.py` (`just ui-lint`) fails on `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval(`, `new Function`,
string-argument `setTimeout/setInterval`, inline `on*=` attributes, `javascript:` URLs and external `http(s)://` references.

## O5. Terminal dashboard
`webfilter-proxy tui [--admin URL] [--token-file path]` (token also from `WEBFILTER_ADMIN_TOKEN_FILE`; never argv). Panels: Overview,
Recent events (filter), Top blocked, Clients, Feeds/Scans, Access requests (`a` approve, `d` deny, `t` TTL). Keys: `q`, `Tab`, `/`, `r`.
All strings are stripped of control characters and escape sequences before drawing; the terminal is restored on exit, SIGINT and panic;
admin unreachable shows a status line instead of crashing. Testable with the ratatui test backend.

## O6. Access-request workflow
Enabled when `[access_requests] enabled=true` AND the client's profile has `access_requests=true`.
- Block page (SPEC 4.7) shows a form only for eligible reasons: `domain_blocklist`, `url_pattern`, `extension`, `content_type`. Never for
  `feed_*`, `hash_blocklist`, `malware_detected`, `private_range`, `port_not_allowed`, `invalid_request`, `host_mismatch`, `sni_mismatch`,
  `auth_*`, `rate_limited`, `loop_detected` (those show "This block cannot be reviewed").
- Form fields: hidden `event_id`, hidden `csrf` = HMAC-SHA256(random in-memory 32-byte secret, event_id + client_id + expiry), 15 min
  validity, 128-bit truncated; `justification` (<= 500 chars), `contact` (<= 100). Posted to `<scheme>://webfilter.local/request`.
- Block-page CSP gains `form-action <scheme>://webfilter.local` when the form is shown (form-action does not fall back to default-src). For HTTPS blocks the page is
  only reachable with TLS interception enabled; the proxy then also answers `CONNECT webfilter.local:443` itself (minted certificate). When access requests are
  disabled the name is NOT special.
- The proxy answers reserved host `webfilter.local` itself (GET `/`, POST `/request`, GET `/status/<id>`) BEFORE DNS/destination
  policy; every other path/method gets 404; the host can never be forwarded upstream or appear in lists/feeds; `webfilter.local.`,
  other ports, userinfo or case variants are canonicalized first (SPEC 4.5) and treated identically.
- A `RecentBlocks` store (bounded: last 50 eligible blocked events per client, 15-minute TTL, 100,000 clients LRU) is filled when a request is blocked;
  it is independent of the 1,000-event admin ring so busy proxies do not lose events. Only real blocks qualify (`action=blocked`), never monitor-mode `would_block`.
- Accepted only if: CSRF valid and unexpired; `event_id` is in `RecentBlocks` for the SAME `client_id` with an eligible
  reason; <= 3 requests/hour and <= 20 pending per client; body <= 2 KiB `application/x-www-form-urlencoded`. Stored in
  `state/access_requests.jsonl` (0600); the SIEM log `webfilter_access.jsonl` stores ids, host, reason and justification length only.
- Decision via API/UI/TUI: approve creates a **temp allow** (scope `client` default or `profile`; host exact-only unless
  `include_subdomains`; TTL default 4 h, max 24 h) stored atomically in `state/temp_allows.json` (0600, schema-validated on load).
  Evaluation order: allowlist, then feed rules (never overridable), then scoped temp allows, then the remaining local rules. A temp allow applies only to its
  scoped client/profile and suppresses only local `domain_blocklist`, `url_pattern`, `extension` and `content_type` rules; expiry is checked at match time plus a
  sweeper. It never bypasses safety policy, feeds (including feed IPs after DNS), hash blocklist or scan verdicts.
- Events: `access_request_created`, `access_request_decided`, `temp_allow_added`, `temp_allow_expired`.

## O7. `doctor`
`webfilter-proxy doctor [--config]` prints PASS/WARN/FAIL and exits 0/1/2: config validity; permissions (CA key 0600, `state/` 0700,
token/key files); listen ports bindable; clamd `PING` and (if enabled) YARA compile; feed hosts resolve and answer HEAD; log dir writable
with >= 1 GiB free; transparent-mode prerequisites; tool versions vs `docs/ENVIRONMENT.md`. Never prints secrets.

## O8. State directory (`state/`, 0700)
`temp_allows.json`, `access_requests.jsonl`, `scan_tmp/`; `feeds/<name>/` holds versions. Backup/restore and drills: `docs/OPERATIONS.md`.
