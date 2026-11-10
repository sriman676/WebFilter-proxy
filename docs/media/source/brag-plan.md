# Brag plan - WebFilter Proxy

**What it is:** a multi-threaded HTTP/HTTPS filtering proxy and fetch client in Rust: every request is checked
(blocklists, categories, threat feeds, malware scanning, per-user limits) and logged for a SIEM.
**For:** a school/lab/small-org network admin (and the course reviewer) who wants control and evidence.
**Sets it apart:** security-first engineering you can see: own smuggling-resistant HTTP/1 parser, TLS always
verified, block pages that explain why, a live dashboard, and hard numbers.
**Most impressive claim:** 17,764 requests/s on loopback with 0 errors (target was 2,000).
**Visual hook:** a terminal firing fetches - `OK 200`, `OK 200`, then a red `BLOCKED 403` slams in.
**Real UI shown:** the client's real output format, the real default block page, the real dashboard
(assets/admin/style.css colors, tiles, events table, pills). Hosts/IDs are fictional stand-ins (`*.example`).
**Tone:** `polished` with punch - dark GitHub-style palette from the dashboard, clean type, confident cuts.
**Share caption:** "Every request gets a verdict. WebFilter Proxy: a Rust web filter with smuggling-proof
parsing, verified TLS and a live dashboard - 17.7k req/s."

## Identity
Background `#0d1117`, panel `#161b22`, line `#30363d`, text `#e6edf3`, muted `#8b949e`, accent `#58a6ff`,
ok `#3fb950`, bad `#f85149`, warn `#d29922`. Logo: the dashboard's 135deg accent->ok gradient square.
Fonts: Segoe UI / system-ui for type, Consolas for terminal.

## Music
120 BPM (beat 0.5 s), A minor, 4/4, counted from frame 0. Kick on beats, soft hats on off-beats, sub bass,
airy pad; SFX in key: muted low thud on BLOCKED, soft risers into cuts, gentle ticks while typing. Every cut on a
beat.

## Storyboard (20.0 s, 30 fps)
| # | Time | Beats | Scene | On screen |
|---|---|---|---|---|
| 1 | 0.0-3.0 | 6 | Hook | Terminal. `$ webfilter-client news.example docs.example ads.tracker.example` types fast; `OK 200` lines land green, then `BLOCKED 403 ... -> domain_blocklist (event 01J...)` slams in red with a thud. |
| 2 | 3.0-6.0 | 6 | Reveal | Logo square + **WebFilter Proxy**; line: "Every request gets a verdict." |
| 3 | 6.0-10.0 | 8 | Highlight 1 | The real block page slides in (Access blocked, host, reason, rule, event id). Caption: "Blocked pages say why." |
| 4 | 10.0-14.5 | 9 | Highlight 2 | Real dashboard: tiles count up (Requests, Blocked, Active, ENFORCE), events rows appear with allowed/blocked pills. Caption: "Live dashboard. Safe edits. One-click rollback." |
| 5 | 14.5-18.0 | 7 | Highlight 3 | Proof cards stack: "17,764 req/s", "13,741 req/s with TLS interception", "316 tests", "h2spec 147/147". |
| 6 | 18.0-20.0 | 4 | Outro | Logo + **WebFilter Proxy** + "Built in Rust. Filters every request." |

Transitions: dip through background (old content out, then new in), no muddy crossfades.
