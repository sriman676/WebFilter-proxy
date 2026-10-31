# Detections (Phase 5, A-14, A-35)

Source of truth: `siem/opensearch/detections.json`. Evaluator: `scripts/siem/detect.py` (JSONL or OpenSearch,
same code). Tests: `just siem-test` (offline, labelled dataset from `scripts/siem/gen_test_traffic.py`) and
`just siem-e2e` (Docker: real proxy logs + dataset shipped by Fluent Bit; OpenSearch results must equal the
offline ones; no canary is searchable). Field values are compared as data only, so log content cannot change
a rule (PT-5.1).

## How to run
```bash
python3 scripts/siem/detect.py --jsonl logs/                       # over local logs, "now" = newest event
OPENSEARCH_PASSWORD=... python3 scripts/siem/detect.py --opensearch https://localhost:9200 \
    --ca siem/opensearch/certs/root-ca.pem                         # after `just siem-e2e` style setup
```
Each alert is one JSON line: `{"id","group":{...},"count",...}`. Schedule it with cron/systemd timers
at the window size (e.g. every 10 min for the 1 h rules).

## Rules
| ID | Name | Logic (window) | Threshold | Known false positives / tuning |
|---|---|---|---|---|
| WF-01 | Top blocked domains | report: blocked requests by `dest_host`, `rule_id` (24 h) | any | report, not an alert |
| WF-02 | High block rate | per `src_ip`: blocked / total (1 h) | >= 10 blocked and >= 30 % | a kiosk or child device hitting one blocked app repeatedly; raise `min_hits` or allowlist that host |
| WF-03 | Possible beaconing | per `src_ip`+`dest_host`: interval mean and std-dev (4 h) | >= 21 requests, mean >= 5 s, std-dev < 10 % of mean | update checkers, NTP-like pollers, monitoring agents; add them to an exclusion list or raise `max_jitter` precision |
| WF-04 | DGA-like long hostnames | `dest_host` length >= 41 (24 h) | any | CDNs and cloud storage with long generated labels (`*.s3.amazonaws.com`, ad tracking); tune `min_len` or exclude known suffixes |
| WF-05 | Smuggling / malformed requests | reason `invalid_request`, `parser_differential` per `src_ip` (1 h) | >= 5 | broken clients or scanners on the LAN; investigate, rarely benign |
| WF-06 | SSRF / port abuse | reason `private_range`, `port_not_allowed`, `loop_detected` per `src_ip` (1 h) | >= 3 | misconfigured apps calling LAN services through the proxy |
| WF-07 | Proxy auth failures | reason `auth_failed`, `rate_limited` per `src_ip`+`proxy_user` (1 h) | >= 5 | a changed password still saved in a browser |
| WF-08 | TLS anomalies | reason `sni_mismatch`, `host_mismatch`, `upstream_cert_invalid`, `non_tls_on_connect` (24 h) | any | captive portals and expired origin certificates |
| WF-09 | Encoding evasion | `suspicious_encoding = true` per `src_ip`+`dest_host` (24 h) | any | sites that legitimately double-encode paths; review the rule_id first |
| WF-10 | Log pipeline / integrity health | system `log_dropped`, `blocklist_reload_failed`, `ca_permission_error`, `panic_isolated`, `insecure_permissions` (24 h) | any | none expected; every hit needs an operator action |
| WF-11 | Rate limited / over quota (v1.1) | reason `rate_limited`, `quota_exceeded`, `too_many_connections` per `client_id` (1 h) | >= 10 | streaming devices at a tight quota |
| WF-12 | Malware / unscannable downloads (v1.1) | `scan_status` `infected`, `blocklisted`, `unscannable`, `error` (24 h) | any | encrypted archives show as `unscannable` |
| WF-13 | Threat feed hits (v1.1) | reason `feed_domain`, `feed_url`, `feed_ip` (24 h) | any | stale feed entries; check feed age |
| WF-14 | Feed pipeline health (v1.1) | system `feed_failed`, `feed_rejected`, `feed_stale` (24 h) | any | upstream feed outages |
| WF-15 | Access requests (v1.1) | report of `access_request` events by id and status (24 h) | any | report |
| WF-16 | Admin auth failures (v1.1) | admin events with result `denied`/`auth_failed` per `remote_addr`+`action` (24 h) | >= 3 | an operator mistyping the token |

## Validation (PT-5.5)
The labelled dataset contains a 2 000-request benign baseline (40 clients, 30 sites, 2 % blocks, random
intervals) plus one replay per rule: a 30 s +/- 1 s beacon x 40, five 45-character hostnames, 50 blocks in a
minute, smuggling/SSRF/auth bursts, TLS anomalies, double encoding, pipeline events and the v1.1 events.
`siem_test.py` requires every expected alert and rejects any other alert, so a threshold change that adds
baseline false positives fails `just test`.
