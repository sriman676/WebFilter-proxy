# Gap Analysis of the v1 Instructions -> Where Each Is Fixed

| # | Gap in v1 | Resolution | Where |
|---|---|---|---|
| G-01 | Language/engine/crate left open ("ask me") | Final decisions D-02..D-05, approved dependency list | DECISIONS |
| G-02 | No environment/tooling prerequisites | Tool list, install commands, lab layout, check script | ENVIRONMENT |
| G-03 | Proxy and client treated as separate ideas | One package, shared lib, shared test harness | DECISIONS D-03, SPEC 1 |
| G-04 | No request-validation rules (smuggling/desync) | Strict rules R1-R15, one-shot upstream, per-request filtering | SPEC 4.3, D-07/08/10 |
| G-05 | No host/URL parsing-differential defense | Dual-parser check, forward-what-you-checked | SPEC 4.5, D-09 |
| G-06 | Normalization underspecified (IP forms, IDN, dots, userinfo, encodings, backslash) | Exact algorithm + bypass corpus | SPEC 4.5, tests/corpus |
| G-07 | SSRF / DNS rebinding / private ranges / metadata IP not addressed | Destination policy, resolve-once-connect-to-validated-IP | D-11, SPEC 4.8 |
| G-08 | Open-proxy risk, no auth, no port policy | Loopback default, mandatory auth off-loopback, port allowlists, loop detection | D-12..D-14 |
| G-09 | Blocklist file grammar/limits undefined | Full grammar, limits, failure behavior | SPEC 4.6 |
| G-10 | Content-type and extension rules vague | Phase-specific rules (request vs response) | SPEC 4.6 |
| G-11 | TLS interception details missing (CA params, leaf certs, upstream validation, ECH, non-TLS CONNECT, mTLS, pinning) | Full TLS section + decisions | SPEC 4.9, D-19..D-22 |
| G-12 | Domain fronting / SNI mismatch ignored | Host/SNI/CONNECT consistency rules | D-22 |
| G-13 | WebSocket/Upgrade/Expect/chunked/HEAD/1xx behaviors undefined | Behavior table | SPEC 4.3/4.4, D-23 |
| G-14 | Error handling/status codes undefined | Error response matrix | SPEC 4.12 |
| G-15 | Timeouts/limits undefined | Limits table | SPEC 4.11 |
| G-16 | Log schema lacked enums, caps, system events, injection defenses, drop policy | LOG_SCHEMA v2, D-17/18 | LOG_SCHEMA |
| G-17 | Log rotation/permissions/flush semantics undefined | Writer thread, rotation naming, 0640 | D-17, LOG_SCHEMA |
| G-18 | Config incomplete (precedence, validation, units, paths) | Full config reference | SPEC 6 |
| G-19 | Client behavior thin: naming edge cases, traversal, Windows names, collisions, atomic writes, redirects, size caps, TLS, exit codes | Precise client spec + filename algorithm | SPEC 5 |
| G-20 | Client could not report block/event id for HTTPS | Custom hyper-based client reads CONNECT replies | D-25 |
| G-21 | No block-page XSS/headers requirements | Escaping + CSP + nosniff + no-store | SPEC 4.7 |
| G-22 | No interfaces/types, so module boundaries were ambiguous | INTERFACES.md contracts | INTERFACES |
| G-23 | Testing was a short checklist | Test pyramid, E2E matrix (34), harness spec, fuzz/property/load/coverage | TEST_PLAN |
| G-24 | No pentesting | Per-phase pentest plan with IDs, tools, pass criteria, gate | PENTEST_PLAN |
| G-25 | No threat model tying risks to tests | STRIDE table T-01.. mapped to tests and pentests | THREAT_MODEL |
| G-26 | No research grounding | Annotated references and their design impact | RESEARCH |
| G-27 | Splunk detections not validated end-to-end | Purple-team replay (attack traffic -> alerts) | PENTEST P5, TEST E-28 |
| G-28 | Phases lacked deliverables/exit criteria/gates | Phase gates with checklists | BUILD_PLAN |
| G-29 | "Ask me questions" blocked autonomy | No-questions policy + addendum mechanism | CLAUDE.md, DECISIONS |
| G-30 | No dependency/supply-chain controls | cargo-deny/audit/geiger/cyclonedx, pinned toolchain | D-27, PENTEST P6 |
| G-31 | No reproducibility/rebuild path | justfile targets, acceptance script, final DoD | BUILD_PLAN, SPEC 10 |
| G-32 | No resource-exhaustion/DoS/chaos considerations | Limits, load/soak/chaos tests | SPEC 4.11, TEST L-*, PENTEST P2/P6 |
| G-33 | No secrets-in-logs guarantee | Canary test | TEST E-30 |
| G-34 | No CI definition | CI jobs list | SPEC 10 |

## Round 2 (second review)
| # | Gap / change | Resolution |
|---|---|---|
| G-35 | **Engine choice** (like Python->Rust): a third-party MITM crate cannot guarantee strict framing/parsing control | D-05 now a first-party HTTP/1 core on tokio + httparse, fuzzed and differential-tested; engine spike removed |
| G-36 | Scope risk: single huge plan, Phase 2 too big for one pass | D-35 milestones M1/M2/M3; Phase 2 split into 2a/2b/2c with mini-gates |
| G-37 | Original assignment not traceable to features | `docs/ASSIGNMENT_TRACE.md` + demo script requirement |
| G-38 | SPEC pipeline order bug: loop check ran before canonicalization | reordered (4.2 steps 5-6) |
| G-39 | Close-delimited responses, caching, HTTP/1.0 behavior unspecified | D-37, SPEC 4.3 |
| G-40 | Config default contradiction (`deny_private_ranges`) | D-36 |
| G-41 | Rust edition outdated (2021) | D-02: edition 2024 |
| G-42 | No real-world compatibility testing (browsers, curl, git, HTTP/1.0 clients) | TEST_PLAN C-01..C-09, COMPATIBILITY.md |
| G-43 | Own parser could diverge from reference parsers | differential tests X-01..X-04 |
| G-44 | Self-assessed pentest overstated | D-39 caveat + optional independent review |
| G-45 | Client/proxy scheme and IPv6 details | D-38 |

## Round 3 (HTTP/2, transparent mode, end-to-end proof)
| # | Gap / change | Resolution |
|---|---|---|
| G-46 | HTTP/2 was out of scope; browsers use h2 on intercepted TLS | Phase 6: D-40 ALPN mirroring (no downgrade), SPEC 4.16, flood limits (R-10), PT-6.x |
| G-47 | Transparent (non-explicit) mode was out of scope | Phase 7: D-41..D-44, SPEC 4.17, netns lab, PT-7.x |
| G-48 | Root-only tests could block autonomy | D-43 non-root `FixedOriginalDst` equivalents (E-51); limitation recorded, not asked |
| G-49 | Docs could drift or contain dangling IDs | `scripts/docs_check.py` + `just docs-check` at every gate |
| G-50 | No single end-to-end acceptance runbook | `docs/ACCEPTANCE.md` |
| G-51 | No ready prompts for the operator | `docs/PROMPTS.md` |
| G-52 | Final phase renumbered 6 -> 8; milestones redefined | D-35 and all references updated |

## Round 4 (versions, docs volume, repo hygiene)
| # | Gap / change | Resolution |
|---|---|---|
| G-53 | Language version vague ("latest stable") | Rust pinned to 1.99.0 (verified 2026-10-29), edition 2024; four-file consistency check; bump procedure (D-46, VERSIONS.md) |
| G-54 | Crate/tool versions unspecified; API drift risk | resolve at Phase 0, commit Cargo.lock, `--locked`, "read docs.rs for the resolved version" rule, minimum tool versions |
| G-55 | Too many docs (~27k tokens) loaded at once | progressive disclosure (D-47), INDEX tiers, per-phase briefs, STATE.md, `/clear` per gate |
| G-56 | Same facts could live in several docs and drift | single-source table (D-48), BUILD_PLAN now links to briefs only, size budgets in `docs-check` |
| G-57 | Resuming after a reset required git archaeology | `docs/STATE.md` + `/resume` |
| G-58 | Missing repo hygiene files | `rustfmt.toml`, `clippy.toml`, `deny.toml`, `.editorconfig`, `.gitattributes`, LICENSE, lint config in Cargo.toml, `panic = "unwind"` rule |
| G-59 | Untrusted fetched content / stale facts | D-49: data not instructions; dated facts |
| G-60 | Supply-chain drift in CI | actions pinned by SHA, images by tag/digest, `--locked` |

## Round 5 (defects found by audit)
| # | Defect | Fix |
|---|---|---|
| G-61 | Markdown table broken by an unescaped pipe character (PT-5.1) | escaped; `docs-check` now validates table columns |
| G-62 | Differential test IDs `D-01..D-04` collided with decision IDs | renamed `X-01..X-04` |
| G-63 | Example config wrote logs under `config/` | `dir = "../logs"`; missing keys take defaults |
| G-64 | Splunk monitored only `webfilter.jsonl`; system/stats events never ingested | directory monitor with whitelist |
| G-65 | Pipeline resolved DNS before filtering: blocked names leaked DNS queries and failed with 502 instead of 403 | pre-DNS filter step; E-52, T-50; allowlist never bypasses safety policy |
| G-66 | Demo would be refused by the hardened default config (private ranges, ports) | `config/demo.toml`, Phase 3 task |
| G-67 | `insecure-test` build/test split and test-lint exceptions unspecified | SPEC 9/10, `just release` string check, PT-8.2 |
| G-68 | Vague timing-oracle pass criterion (PT-2.10); ambiguous e2e scope in acceptance | statistical criterion; explicit step mapping |

## Round 6 (v1.1 feature packs requested: policies, limits, feeds, scanning, ops/admin, client)
| # | Addition / design risk handled | Resolution |
|---|---|---|
| G-69 | Per-client policies could weaken safety | D-50: profiles cannot override safety policy; IPv6 /64 and XFF rules |
| G-70 | Limiter could itself be exhausted or evaded | D-51: bounded LRU, /64 keys, saturating math, limits enforced in monitor mode |
| G-71 | Feed poisoning and fetch SSRF | D-52: guards, protected domains, rollback, expiry, destination policy, terms check |
| G-72 | Scanning contradicts "no body inspection" and creates TOCTOU/DoS risks | D-53/D-54: opt-in, deliver exactly the scanned bytes, temp quotas, unscannable policy |
| G-73 | Local admin UI exposed to DNS rebinding/CSRF/XSS | D-55..D-58, ui_lint, Host allowlist on every route |
| G-74 | Access requests could become an SSRF/bypass channel | D-59: virtual host before DNS, eligibility list, HMAC CSRF, scoped TTL temp allows |
| G-75 | Client snapshot/crawl security (offline script execution, traps, traversal) | D-60..D-62, SPEC_EXT_CLIENT |
| G-76 | Docs volume grows | new content in SPEC_EXT_* and PENTEST_PLAN_EXT (budgets kept), phase briefs 9-13 |
| G-77 | Operations knowledge missing | OPERATIONS.md runbook, `doctor`, drills in PT-13.6 |

## Round 7 (audit of the v1.1 design)
| # | Defect found | Fix |
|---|---|---|
| G-78 | Temp allows (from access requests) could override feed blocks because of rule order | explicit order: allowlist, feed rules, temp allows, local rules (SPEC 4.6, O6) |
| G-79 | "Recent blocked event" lookup relied on a 1,000-event ring that busy proxies overwrite | bounded per-client `RecentBlocks` store, 15-minute TTL; only real blocks qualify |
| G-80 | Access-request form could be blocked by the block-page CSP (form-action) and HTTPS needs interception | CSP `form-action` rule; HTTPS flow requires interception; name not special when disabled |
| G-81 | Feed tests need loopback feed hosts, which destination policy forbids | test-only `WEBFILTER_TEST_FEED_ALLOW_LOOPBACK` under `insecure-test` |
| G-82 | Scan block mode had no total-time bound for slow upstream bodies | `buffer_timeout_secs` |
| G-83 | Snapshot CSP used `'self'`, unreliable for file:// pages | scheme sources + browser verification in E-80 |
| G-84 | Unapproved dependencies implied by the design (CSPRNG, socket options, HTTP dates, form bodies, hex) | D-66 |
| G-85 | `just e2e` mixed tests needing Docker/browsers | separate `scan-e2e`, `ui-e2e`; acceptance steps updated |
| G-86 | No fd-limit, log-reopen, clock-sync, SSH-tunnel guidance | D-67, OPERATIONS |
| G-87 | Privacy and legal exposure of interception and logging not addressed | D-68, OPERATIONS section, T-73 |
| G-88 | No seed test data for v1.1 features | feed, snapshot, robots, admin-Host, access-request corpora |
| G-89 | Docs checker could not detect unassigned tests, missing corpora, undefined test IDs, undocumented just targets | four new checks in `docs-check` |

