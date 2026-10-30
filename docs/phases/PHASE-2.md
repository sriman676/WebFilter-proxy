# Phase 2 - Proxy server (HTTP + CONNECT tunnel, no interception) - split into 3 sub-phases
Milestone: M1 | Prerequisite: previous phase gate passed and tagged | Update `docs/STATE.md` at the gate.

## Read (only these; do not load other docs unless blocked)
2a: SPEC 4.3, 4.4, 4.15; INTERFACES http1; tests/corpus/smuggling_cases.md; T-01,T-02,T-13,T-17. 2b: SPEC 4.2, 4.6-4.8, 4.11, 4.12, 4.14; D-07,D-10,D-11,D-37. 2c: SPEC 4.1, 4.9 (CONNECT/passthrough part), 4.10, 4.13; D-12..D-14,D-23,D-31. TEST_PLAN sections 2,5,6 (harness, I-*, E-*)

## Plan
Each sub-phase has its own mini-gate (tests green + its PT subset); Phase 2 closes after 2c with the full PT-2.x list.
**2a - HTTP/1 core (`proxy::http1`, D-05, SPEC 4.15)**: head reader/limits, `httparse` + strict rules R1-R15, framing
functions (shared request/response rules), chunked codec, relay primitive; fuzz targets F-04, F-08, F-09; differential tests X-01.
Tests: U-http, SM-01..25 at parser level, F-04/08/09, X-01. Pentest subset: PT-2.1, 2.5, 2.12, 2.14, 2.16, 2.17.
**2b - Pipeline, policy, filtering, logging**: listener + per-connection loop, 4.2 pipeline, canonicalization hook,
port/dest policy with injectable resolver, filtering incl. response-phase content-type, block/error pages (4.7/4.12),
one-shot upstream (D-07, D-37), monitor mode, panic isolation, EventLogger/stats wiring, CLI (`run`, `check-config`,
`blocklist test`, `hash-password`). Tests: I-01..I-14, I-block-page, I-panic, E-04,05,07..11,15,16,21,22,25,31,32,33,52.
Pentest subset: PT-2.3, 2.4, 2.6, 2.7, 2.13, 2.18.
**2c - CONNECT, auth, limits, lifecycle**: CONNECT passthrough (rules 1-3), websocket relay, proxy auth + lockout,
connection limits/timeouts, loop detection, graceful shutdown/signals, non-loopback bind rule. Tests: I-15..I-19,
I-20..I-28 end-to-end via RawClient, E-19, E-20, E-23, E-24, E-35, E-36. Pentest subset: PT-2.8..2.11, 2.15, 2.19 + re-run all.
Milestone check: `curl -x` works for http and https tunnel; blocked domains 403; logs valid.

## Pentest gate
PT-2.1 .. PT-2.19 (definitions: docs/PENTEST_PLAN.md, section "Phase 2")

## Gate checklist
- [ ] `just fmt lint test` green (plus `just cov` where coverage gates are named in TEST_PLAN)
- [ ] Phase tests listed above pass; new bugs have regression tests
- [ ] `just pentest-p2` executed, manual PT cases done, `docs/pentest/phase-2/REPORT.md` + `FINDINGS.md` written
- [ ] `security-reviewer` subagent run on the phase diff; zero open Critical/High
- [ ] `just docs-check` passes; CHANGELOG.md and `docs/STATE.md` updated; new decisions in DECISIONS_ADDENDUM.md
- [ ] tag `phase-2-complete` (and `m1-complete` if this closes the milestone); then `/clear`
