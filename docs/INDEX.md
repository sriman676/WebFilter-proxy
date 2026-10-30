# Documentation Index and Reading Protocol (D-47, D-48)
Inventory is capped: 19 files in `docs/` (+14 phase briefs, 2 pentest templates, 8 corpora). Every file below exists for a distinct, required purpose; merge before adding.

## Reading protocol (start of every session)
1. Read `CLAUDE.md`, this index, `docs/STATE.md`, `docs/DECISIONS.md`.
2. Read ONLY the current phase brief `docs/phases/PHASE-N.md` and the sections/IDs it lists.
3. Open anything else only when blocked, and only the needed section. Never load all of `docs/`.
4. After each gate: update `docs/STATE.md`, then `/clear`.

## Tiers
| Tier | File | Purpose (single source of truth for) | ~words |
|---|---|---|---|
| 0 | CLAUDE.md | working rules, commands | 600 |
| 0 | docs/INDEX.md | this map | 700 |
| 0 | docs/STATE.md | progress/resume pointer | 100 |
| 0 | docs/DECISIONS.md | all final decisions (D-xx) | 3,000 |
| 0 | docs/phases/PHASE-N.md | the plan for one phase | 300-700 |
| 1 | docs/SPEC.md | behavior: sections 4.x proxy, 5 client, 6 config, 9-10 conventions | 4,500 |
| 1 | docs/INTERFACES.md | module/type contracts, reason enum | 1,300 |
| 1 | docs/LOG_SCHEMA.md | log fields, caps, system events | 700 |
| 1 | docs/SPEC_EXT_POLICY.md | v1.1 identity/profiles, rate limits, feeds, download scanning (Phases 9-10) | 1,100 |
| 1 | docs/SPEC_EXT_OPS.md | v1.1 admin, metrics, UI, TUI, access requests, doctor (Phase 11) | 950 |
| 1 | docs/SPEC_EXT_CLIENT.md | v1.1 client batch, snapshot, crawl (Phase 12) | 750 |
| 2 | docs/TEST_PLAN.md | all test IDs (U/P/F/D/I/E/L/C/S), harness | 2,500 |
| 2 | docs/PENTEST_PLAN.md | PT cases for Phases 1-8, severity rubric, gate rules | 3,300 |
| 2 | docs/PENTEST_PLAN_EXT.md | PT cases for Phases 9-13 | 1,900 |
| 2 | docs/OPERATIONS.md | runbook: service, backups, drills, alerts | 700 |
| 2 | docs/THREAT_MODEL.md | threats T-xx -> mitigations -> tests | 1,300 |
| 2 | docs/ENVIRONMENT.md | tools, lab layout, versions/pins, toolchain bump rules | 1,100 |
| 2 | docs/RESEARCH.md | papers/CVEs behind the design (R-xx) | 1,100 |
| 3 | docs/ACCEPTANCE.md | final end-to-end runbook (Part A) + assignment trace and demo (Part B) | 750 |
| - | archive/GAPS_ANALYSIS.md | history of gaps found and fixed (not read by agents) | 1,700 |
| - | docs/DECISIONS_ADDENDUM.md | decisions made during the build (append-only) | grows |
| - | docs/BUILD_PLAN.md | loop, milestones, phase table | 600 |
| - | README.md | human entry point: quick start, doc map, operator prompts (not an agent doc) | 650 |
| - | docs/pentest/** | per-phase reports and findings (written during the build) | grows |
| - | tests/corpus/* | test data: url bypass, smuggling, filename oracle, feed, snapshot HTML, robots, admin Host, access requests | data |

## Single source of truth (where to edit)
| Topic | Lives in | Everyone else |
|---|---|---|
| decisions/defaults | DECISIONS | cite D-xx |
| proxy/client behavior, limits, rules R1-R15, H1-H11 | SPEC | cite section/rule |
| v1.1 behavior (P1-P4, O1-O8, C1-C5) | SPEC_EXT_* | cite section |
| log fields and caps | LOG_SCHEMA | cite field |
| function/type names | INTERFACES | - |
| test cases | TEST_PLAN | cite ID |
| pentest cases | PENTEST_PLAN | cite PT-x.y |
| per-phase work | phases/PHASE-N | BUILD_PLAN links only |
| versions/pins | VERSIONS | CI and config files mirror it (checked) |

## SPEC section map
1 overview - 2 glossary - 3 architecture - 4.1 listener - 4.2 pipeline - 4.3 validation R1-R15 - 4.4 headers -
4.5 canonicalization - 4.6 filtering + blocklist grammar - 4.7 block page - 4.8 upstream - 4.9 TLS interception -
4.10 auth - 4.11 limits/timeouts - 4.12 error matrix - 4.13 CLI/signals - 4.14 stats - 4.15 HTTP/1 core -
4.16 HTTP/2 - 4.17 transparent - 5 client (5.1 CLI, 5.2 behavior, 5.3 naming, 5.4 output) - 6 config - 7 logging - 8 Splunk -
9 non-functional - 10 repo conventions. v1.1 sections live in SPEC_EXT_POLICY (P1-P4), SPEC_EXT_OPS (O1-O8), SPEC_EXT_CLIENT (C1-C5).

## ID prefixes
D decision, R research, T threat, U unit/URL corpus, P property, F fuzz, X cross-parser differential (TEST_PLAN 4b), I integration,
E end-to-end, L load, C compatibility, S Splunk, SM smuggling corpus, PT pentest, PF pentest finding, AR accepted risk, H/R rules in SPEC.
