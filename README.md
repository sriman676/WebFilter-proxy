# WebFilter Proxy (Rust)

Multi-threaded HTTP/HTTPS forward proxy with blocklists, optional TLS interception and SIEM-ready JSON
logs, plus a client that fetches URLs through the proxy and saves them as named HTML files.

> Security lab project. Bind to loopback (the default); intercept only your own devices (D-30).

## Features
- **Filtering on every request** (D-10): domain lists (suffix match), URL regexes, IP/CIDR lists, blocked
  extensions and response content types, allowlist, named categories with time schedules, monitor mode.
- **Strict HTTP/1 core** (own parser, D-05): smuggling-resistant framing, canonical URLs (dual parser),
  DNS resolved once and connected by validated IP (no rebinding), private ranges and metadata IPs denied.
- **HTTPS**: CONNECT passthrough, or opt-in interception with a local CA (upstream TLS always verified),
  HTTP/2 by ALPN mirroring (never translated) with a flood guard, websocket relay.
- **Transparent mode** (Linux netns lab only), proxy auth (argon2id), per-IP connection limits.
- **Logs**: JSON lines (request, system, stats), no secrets/bodies/query values, rotation; OpenSearch
  stack and 16 detections in `siem/opensearch/`.
- **Client**: fetches URLs through the proxy, verifies TLS, follows redirects safely, saves named HTML files;
  batch input files, retries with backoff, a JSONL manifest with verified resume, offline snapshots (sanitized,
  same-site assets only) and a polite crawler that always honors robots.txt.

## Quick start
```bash
cp config/config.example.toml config/config.toml   # hardened defaults; config/demo.toml for local origins
cargo run --release --bin webfilter-proxy -- --config config/config.toml check-config
cargo run --release --bin webfilter-proxy -- --config config/config.toml run      # 127.0.0.1:8080
cargo run --release --bin webfilter-client -- https://example.com https://rust-lang.org
# -> output/example.com.html, output/rust-lang.org.html; blocked URLs print BLOCKED and exit 3
curl -x http://127.0.0.1:8080 http://example.com/   # any proxy-aware client works
scripts/demo.sh                                    # the assignment demo, fully offline
```
Proxy CLI: `run` (default), `check-config`, `blocklist test <url>`, `hash-password` (stdin), `ca generate|export`;
global `--config`, `--listen`, `--mode enforce|monitor`, `--log-dir`. Signals: SIGHUP reloads lists,
SIGUSR1 reopens logs, SIGINT/SIGTERM drain and stop. Client: `webfilter-client --help` (`--proxy`,
`--out-dir`, `--name`, `--ca-cert`, `--jobs`, `--max-bytes`, `--save-blocked`, `--json`; exit 0 ok,
1 error, 2 usage, 3 blocked).

## Client: batches, snapshots, crawls (v1.1)
```bash
webfilter-client --input-file urls.txt --manifest run.jsonl          # one URL per line, # comments, deduplicated
webfilter-client --input-file urls.txt --manifest run.jsonl --resume # skips files still intact (size + SHA-256)
webfilter-client --retries 3 --retry-max-delay 30 https://example.com  # 408/429/502/503/504 and network errors only
webfilter-client --resume-partial https://example.com/big.html      # continues .part files (Range + If-Range)
webfilter-client --snapshot https://example.com                     # page + same-site images/CSS/fonts in <name>_files/
webfilter-client --crawl-depth 2 --max-pages 50 https://example.com # -> output/example.com_crawl/index.html
```
- Never retried: proxy blocks, TLS errors, usage errors, other 4xx, size limits. `Retry-After` is honored up to the cap.
- Snapshots remove scripts, event handlers, frames, plugins, `<base>` and meta refresh, add a CSP meta that allows
  only local files, and list every omitted asset (cross-site, blocked, wrong type, too big) in
  `<name>_snapshot_report.json`. `--snapshot-extra-host cdn.example` allows one CDN; `--snapshot-allow-scripts` is not recommended.
- Crawls stay on the start host (`--crawl-subdomains` widens it), wait at least 250 ms between requests to a host
  (`--crawl-delay-ms`, robots `Crawl-delay`), cap query variants, path depth and total time (`--crawl-timeout`),
  save only `text/html` pages and rewrite internal links to the saved files. robots.txt 4xx = allow, 5xx/timeout = stop.
- Every request still goes through the proxy, so filters, limits and scans apply; a summary line reports
  `pages`, `assets`, `blocked`, `skipped` and `retries`. `--json` adds `attempts`, `snapshot_report`, `crawl_depth`.

## Customization
- Lists: `blocklists/*.txt` (hot-reloaded); test a URL with `webfilter-proxy blocklist test <url>`.
- Categories with schedules: `[[blocklists.categories]]` with `active = ["Mon-Fri 09:00-17:00"]` (A-27).
- Block page: `[block_page] template = "..."` with `{url}`, `{host}`, `{reason}`, `{rule_id}`, `{category}`,
  `{event_id}`, `{timestamp}`, all HTML-escaped (A-26).
- Parser strictness: `[http] compat = true` tolerates a few legacy client quirks (A-25).
- Every key: `config/config.example.toml`; limits and timeouts have validated ranges.

## Deployment
`deploy/webfilter-proxy.service` (systemd, non-root, `NoNewPrivileges`, `ProtectSystem=strict`, ...) and
`deploy/Dockerfile` (non-root, read-only root). Listening beyond loopback requires `[proxy_auth]` (D-13).
Performance on loopback (`just load`): 2,000 req/s with +0.15 ms p99, ~18,000 req/s max, 1,000 connections
in ~32 MB RSS (D-34).

## Architecture
```
client -> listener (explicit | transparent http/tls) -> pipeline per request (src/proxy/pipeline.rs)
   validate (http1.rs) -> auth -> canonicalize (normalize.rs) -> port/destination policy (policy.rs)
   -> rules before DNS (filter.rs, blocklist.rs) -> resolve once -> IP rules -> fresh upstream
   -> response rules (content type) -> stream back            every request: one JSON event (logger.rs)
CONNECT -> passthrough relay | interception (connect.rs, tls.rs) -> same pipeline, or h2 core (h2.rs)
```
Facts live in `docs/` (start at `docs/INDEX.md`): behavior in SPEC, decisions in DECISIONS(+_ADDENDUM),
threats in THREAT_MODEL, tests in TEST_PLAN, pentests in `docs/pentest/`.

## Limitations (by design)
QUIC/HTTP3 is not proxied (disable it in the browser; the lab rejects udp/443). ECH hides the server name
(passthrough rules then see only IPs; transparent mode blocks ECH by default). Certificate-pinned apps and
mTLS client certificates fail under interception (add them to `tls.passthrough_domains`). No h2c, no
HTTP/1<->HTTP/2 translation. Transparent mode is Linux-only and sees only redirected ports.
## HTTPS interception (optional, lab only)
> **Ethics and scope (D-30, D-68):** interception decrypts other people's traffic. Only intercept your own
> devices or users who were told, on your own machine or lab. Never install the CA on machines you do not own.
> Banking/health/government sites should stay in `tls.passthrough_domains`.

1. In `config/config.toml` set `[tls] intercept = true` (default `ca_dir = "~/.webfilter"`).
2. `webfilter-proxy --config config/config.toml ca generate` creates `ca.pem` (public) and `ca.key` (0600,
   never share or commit it). The proxy refuses to start if the key is group/world-readable, a symlink,
   or owned by another user.
3. `webfilter-proxy --config config/config.toml ca export > webfilter-ca.pem`
4. **Firefox only (recommended, A-28):** Settings -> Privacy & Security -> Certificates -> View Certificates ->
   Authorities -> Import -> `webfilter-ca.pem` -> tick "Trust this CA to identify websites". Firefox keeps
   its own store, so no other application trusts the CA. Set Firefox's manual proxy to `127.0.0.1:8080`
   for HTTP and HTTPS, and disable HTTP/3 (`network.http.http3.enable = false`): QUIC/UDP bypasses a TCP proxy (D-21).
5. To undo: delete the CA in the same Firefox dialog, then delete `~/.webfilter/`.
6. Command-line check: `webfilter-client --ca-cert webfilter-ca.pem https://example.com`.

Upstream certificates are always verified (D-20); an invalid origin certificate gives `502 upstream_cert_invalid`.
For manual experiments, `scripts/gen_test_pki.sh <dir> <host...>` creates a throwaway test PKI.

## Transparent mode (optional, Linux lab only)
> Transparent mode intercepts traffic from devices that never configured a proxy. Use it only in the
> network-namespace lab on your own machine (D-41, D-43); it is off by default and refuses to start unless
> `[transparent] acknowledge_lab_only = true`.

1. Review `scripts/netns_lab.sh` first: it creates only netns `wf-client`, veth `wf-veth0/1`, dummy `wf-origin`
   (192.0.2.10-11) and the nft table `inet wf_lab`, and `down` removes exactly those.
2. `sudo -E just e2e-netns` builds the lab, runs E-44..E-50 with the proxy as your user, and checks that the host's
   ruleset, namespaces and links are identical afterwards.
3. Manual use: `sudo scripts/netns_lab.sh up`, run the proxy with `http_listen = "10.200.0.1:18880"` and
   `tls_listen = "10.200.0.1:18443"`, then `sudo ip netns exec wf-client curl http://...`; finish with
   `sudo scripts/netns_lab.sh down`.

Limitations (by design): only redirected tcp/80 and tcp/443 are seen; QUIC is rejected by the lab rule, other ports,
DoH and pinned apps bypass; ECH hides the name (blocked by default); transparent clients cannot do proxy auth.

## Documentation map
Start at `docs/INDEX.md` (it lists every document, its purpose and the reading order; docs load progressively, D-47). Gap history: `archive/GAPS_ANALYSIS.md`.

## Prompts for Claude Code
Tips: run `claude` in the repo root; use plan mode per phase; `/clear` after every gate (state lives in docs/STATE.md);
`/compact` if a phase runs long. Commands live in `.claude/commands/`.

### 1. Kickoff (paste once, first session)
```
Read CLAUDE.md, docs/INDEX.md, docs/STATE.md and docs/DECISIONS.md. Then read ONLY docs/phases/PHASE-0.md and the
sections it lists; do not load other docs. Rules: never ask me questions - follow DECISIONS.md and record any new choice
in docs/DECISIONS_ADDENDUM.md. Write tests first, run the phase pentest, fix findings with a regression test first,
run `just docs-check`, update docs/STATE.md and CHANGELOG.md, tag the gate, then stop with a summary of 15 lines or fewer.
Do Phase 0 now.
```

### 2. Each next phase
```
/build-phase 1
```
(then 2 ... 13; phases 9-13 are the v1.1 feature packs). Without slash commands: `Read docs/STATE.md and docs/phases/PHASE-N.md (only those plus the sections it lists), execute the phase including its pentest gate and gate checklist, update STATE.md, stop at the gate.`

### 3. Resume after a context reset, a new day, or a crash
```
/resume
```
Without slash commands: `Read CLAUDE.md, docs/INDEX.md, docs/STATE.md, docs/DECISIONS.md, then the current phase brief. Run git status, git log --oneline -15 and git tag; run just docs-check and just test; continue the phase loop from where it stopped. Do not redo finished work. Do not ask me questions.`

### 4. Gate failed / findings open
```
/phase-gate N
```

### 5. Independent adversarial review (before each milestone tag)
```
Use the security-reviewer subagent on the current phase diff and SPEC rules R1-R15, H1-H11. Return the findings table,
then fix every High/Critical with regression tests.
```

### 6. Docs drift check
```
/gap-check
```

### 7. New Rust stable released (e.g. 1.100)
```
/bump-toolchain 1.100.0
```

### 8. Final acceptance (after Phase 8 for v1.0; after Phase 13 for v1.1)
```
Run docs/ACCEPTANCE.md step by step, write docs/pentest/FINAL_REPORT.md with evidence, fix failures, tag m4-complete (v1.0) or m5-complete (v1.1) only when every step passes.
```
