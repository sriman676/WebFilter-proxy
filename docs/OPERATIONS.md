# Operations Runbook (v1.1)

## Install and run as a service (Linux)
Dedicated user `webfilter`; dirs: `/etc/webfilter` (config, 0750), `/var/lib/webfilter` (state, feeds, CA at `ca/`, 0700), `/var/log/webfilter`
(0750). systemd unit hardening: `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths=` for the
three dirs, `CapabilityBoundingSet=` empty (redirect-mode transparent needs no capability for the proxy itself), `Restart=on-failure`.
Run `webfilter-proxy doctor` before every start; fix every FAIL.

## What to back up
CA key and certificate, `config/`, `state/temp_allows.json`, `state/access_requests.jsonl`, `feeds/` (versions), `blocklists/`. Never back up
`scan_tmp/`. Restore: stop, restore files with original modes (CA key 0600), `doctor`, start.

## Monitoring (Prometheus) - suggested alerts
`webfilter_up == 0` for 1 m; `rate(webfilter_log_dropped_total[5m]) > 0`; `time() - webfilter_feed_last_success_timestamp_seconds > 3 * refresh`;
`rate(webfilter_requests_total{reason=~"invalid_request|parser_differential"}[5m])` above baseline; `webfilter_scans_total{status="infected"}`
increase > 0; `rate(webfilter_h2_flood_total[5m]) > 0`; `webfilter_active_connections` near `max_connections`.

## Drills (each must be exercised in Phase 13, PT-13.6)
1. **Feed poisoning or bad update**: `feeds status`; `feeds rollback <name>`; confirm `webfilter_feed_entries` returns to the prior value; disable the feed.
2. **clamd down**: expect `scanner_down` events and `unscannable_action` behavior; restart clamd; confirm recovery without restarting the proxy.
3. **CA key compromise or expiry**: stop interception (`tls.intercept=false`, restart); generate a new CA (`ca generate --force`); redistribute only to your own
   test devices; remove the old CA from every trust store; verify no old-CA leaf is served.
4. **Admin token rotation**: generate a token, store its argon2id hash in config (`hash-password`), reload, confirm the old token is rejected and the
   audit log shows the change.
5. **Disk full**: fill the log volume; confirm the proxy stays up, `log_dropped` events and metric appear, rotation resumes after space is freed.
6. **Blocklist/profile mistakes**: introduce an invalid list/profile; confirm the previous version stays active and a reload-failed event is logged.
7. **Access-request backlog**: flood requests as one client; confirm per-client limits, no memory growth, admin UI remains responsive.

## Upgrades
Read CHANGELOG; run `doctor`; deploy new binary; the old config/state must load unchanged (PT-13.3); features stay off until enabled.
Toolchain bumps follow `docs/ENVIRONMENT.md` rule 4.

## Capacity notes
Memory scales with list entries (about 100 bytes/domain entry; feed URL digests 16 bytes each), cached leaf certificates (<= 10,000), limiter keys
(<= 100,000), event ring (1,000). Scanning in block mode needs `temp_quota_bytes` of disk and delays first byte until the scan completes.

## Privacy and legal (D-68)
Interception reads personal data. Use it only on devices you own or whose users were informed and authorized it; show a notice; keep
banking, health and government names in `tls.passthrough_domains`; keep retention bounded (an OpenSearch ISM delete policy, default 90
days); restrict access to logs, `state/` and the admin token to the operator; query values, bodies and cookies are never logged;
access-request justifications live only in `state/access_requests.jsonl`. Check local law and your organization's policy before enabling.

## Misc operations
Keep the host clock NTP-synchronized (log timestamps, certificate validity). Raise the file-descriptor limit (`LimitNOFILE=`) above
4 x `max_connections`. Use SIGUSR1 (not copytruncate) with external log rotation. Remote admin access: SSH tunnel to loopback and add the forwarded
`host:port` to `admin.allowed_hosts`.

## Limitations to communicate to users
No QUIC/HTTP3 or DoH visibility; ECH hides inner names in transparent mode; certificate-pinned apps need passthrough; archives and encoded bodies
limit AV effectiveness; quotas reset on restart; the proxy is a lab/defense-in-depth tool, not a managed security product.
