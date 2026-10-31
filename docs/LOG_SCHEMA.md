# Log Schema v2 (authoritative)

Files (JSON Lines, UTF-8, one object per line, `\n` terminated, mode 0640):
- `webfilter.jsonl`        request events (below)
- `webfilter_system.jsonl` system/audit events
- `webfilter_stats.jsonl`  60 s summaries
Rotation (applies to ALL log files; SIGUSR1 reopens files): when `max_bytes` is reached rename `X` -> `X.1`, shifting `.1`->`.2` ... keep `backup_count`;
a line is never split across files. Writes are single `write_all` of a complete line.
Field names align with the CIM **Web** model (ECS-like names in OpenSearch). All keys are ALWAYS present (null when unknown).

## Request event
| Field | Type | Notes |
|---|---|---|
| `timestamp` | string | UTC ISO-8601 ms, `2026-10-28T14:03:22.114Z` |
| `event_id` | string | UUIDv7; also in block page/headers |
| `event_type` | string | always `request` |
| `src_ip` | string | client IP |
| `src_port` | int | |
| `http_method` | string | `CONNECT` for tunnels |
| `url` | string | `scheme://host[:port]/path` (no query), max 2048 chars (truncate + `…`) |
| `url_scheme` | string | `http`/`https` |
| `dest_host` | string | normalized host |
| `dest_ip` | string/null | validated IP actually connected to |
| `dest_port` | int | |
| `uri_path` | string | max 2048 |
| `uri_query_keys` | array[str] | names only (max 50 keys, each <= 64); values only if `log_query_values` |
| `status` | int | status returned to the client |
| `action` | string | `allowed` / `blocked` |
| `would_block` | bool | monitor mode |
| `reason` | string | enum from INTERFACES.md |
| `rule_id` | string/null | e.g. `domain:evil.com`, `url:rx-007`, `ip:10.0.0.0/8`, `ext:.exe`, `ctype:application/x-msdownload`, `allowlist` |
| `rule_list` | string/null | file name |
| `user_agent` | string/null | max 512 |
| `http_content_type` | string/null | response media type only |
| `http_version` | string | `1.0`/`1.1`/`2` |
| `bytes_in` | int | response bytes to client |
| `bytes_out` | int | request bytes from client |
| `duration_ms` | int | |
| `tls_intercepted` | bool | |
| `tls_sni` | string/null | |
| `ech_present` | bool | |
| `alpn` | string/null | negotiated ALPN (`h2`/`http/1.1`) on intercepted TLS |
| `h2_stream_id` | int/null | HTTP/2 stream id |
| `transparent` | bool | request arrived via transparent listener |
| `orig_dst_ip` / `orig_dst_port` | string/null, int/null | original destination (transparent) |
| `host_verified` | bool/null | transparent: Host/SNI matched original IP (null when not applicable) |
| `upgrade` | string/null | `websocket` or null |
| `suspicious_encoding` | bool | decode-twice differed |
| `client_id` / `profile` | string/null | identity and resolved profile (Phase 9) |
| `throttled` | bool | bandwidth cap delayed this request |
| `scan_status` / `scan_engine` / `scan_signature` | string/null | Phase 10: clean, infected, blocklisted, skipped, unscannable, error |
| `body_sha256` / `body_bytes` | string/null, int/null | SHA-256 and size of scanned downloads |
| `download_name` | string/null | sanitized, <= 128 chars, never a path |
| `proxy_user` | string/null | auth username (<= 64), never the password |
| `error` | string/null | short code/message, no stack traces, <= 256 |
| `proxy_mode` | string | `enforce`/`monitor` |

## System event (`webfilter_system.jsonl`)
`{"timestamp","event_type":"system","kind":<enum>,"detail":{...}}` with `kind` in:
`proxy_start`, `proxy_stop`, `config_loaded`, `blocklist_loaded`, `blocklist_reload_failed`,
`ca_generated`, `ca_loaded`, `ca_permission_error`, `log_dropped` (with count), `log_rotated`, `panic_isolated`,
`auth_lockout`, `listener_error`, `feed_updated`, `feed_failed`, `feed_rejected`, `feed_stale`, `malware_detected`, `scanner_down`, `access_request_created`, `access_request_decided`, `temp_allow_added`, `temp_allow_expired`, `policy_reloaded`, `h2_flood` (detail: violation type, counters), `orig_dst_failed`, `insecure_permissions` (detail: `files`, world-writable config/list/template paths). Never contains secrets.

## Stats event
`{"timestamp","event_type":"stats","window_secs":60,"requests","allowed","blocked","errors","bytes_in","bytes_out","active_connections","dropped_log_events","top_blocked":[{"host","count"}],"lists":{"domains","regexes","ips"}}`

## Injection & privacy rules
- Serialization is via serde_json only (no string concatenation) so control characters/quotes/newlines are
  escaped; additionally strip C0 control chars and ANSI escapes (`\x1b`) from free-text fields before logging.
- Never log: request/response bodies, `Cookie`, `Set-Cookie`, `Authorization`, `Proxy-Authorization`,
  query values (unless enabled), passwords, CA key material. Canary test E-30 enforces this.
- Truncation caps above are enforced in the logger, not by callers.

## Extra files (v1.1)
- `webfilter_admin.jsonl`: `{"timestamp","event_type":"admin","actor","remote_addr","action","target","result"}`.
- `webfilter_access.jsonl`: `{"timestamp","event_type":"access_request","request_id","event_id","client_id","host","reason","status","decided_by","ttl_secs","justification_len"}` (justification text lives only in `state/access_requests.jsonl`).
Shipper inputs (Fluent Bit, `siem/opensearch/fluent-bit.conf`): `webfilter.jsonl`, `webfilter_system/_stats/_admin/_access.jsonl`, one index each (`webfilter-requests`, `-system`, `-stats`, `-admin`, `-access`).

